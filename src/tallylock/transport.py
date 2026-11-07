"""Allowlisted calendar requests with one absolute retry budget."""
from __future__ import annotations

from email.utils import parsedate_to_datetime
import math
import re
import time
from urllib.parse import urlsplit

from opentimestamps.calendar import DEFAULT_AGGREGATORS

from . import _http, anchors
from .canonical import MAX_SAFE_INTEGER
from .errors import TallyLockError


class RetryDeferred(TallyLockError):
    def __init__(self, next_retry_at: int):
        super().__init__("calendar request deferred", code=5)
        self.next_retry_at = next_retry_at


def normalize_origin(origin: str, *, upgrade: bool = False) -> str:
    if (not isinstance(origin, str) or not origin.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in origin)
            or any(c in origin for c in "%@?#\\")):
        raise TallyLockError("calendar origin is not allowed")
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        valid = (parsed.scheme.lower() == "https" and host and parsed.path in {"", "/"}
                 and parsed.port in {None, 443} and parsed.netloc.lower() in {host, host+":443"})
    except ValueError:
        valid = False
    if not valid or len(host) > 253 or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) is None
                                         for p in host.split(".")):
        raise TallyLockError("calendar origin is not allowed")
    normalized = "https://" + host
    allowed = normalized in DEFAULT_AGGREGATORS
    if upgrade:
        allowed = allowed or any(host.endswith("." + suffix) for suffix in (
            "calendar.opentimestamps.org", "calendar.eternitywall.com", "calendar.catallaxy.com"))
    if not allowed:
        raise TallyLockError("calendar origin is not allowed")
    return normalized


def _retry_at(value):
    if not isinstance(value, str) or len(value) > 256:
        return None
    now = int(time.time())
    try:
        if re.fullmatch(r"[0-9]{1,16}", value):
            due = now + int(value)
        else:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                return None
            due = math.ceil(date.timestamp())
        return due if now < due <= MAX_SAFE_INTEGER else None
    except (ValueError, TypeError, OverflowError):
        return None


def _call(origin, commitment, *, upgrading, deadline):
    origin = normalize_origin(origin, upgrade=upgrading)
    if not isinstance(commitment, bytes) or not 1 <= len(commitment) <= 4096:
        raise TallyLockError("calendar commitment must be bounded bytes")
    if deadline is None:
        deadline = time.monotonic() + 120
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise TallyLockError("invalid calendar deadline")
    url = origin + ("/timestamp/" + commitment.hex() if upgrading else "/digest")
    for attempt in range(3):
        if time.monotonic() >= deadline:
            raise TallyLockError("calendar request deadline exceeded", code=5)
        try:
            response = _http.request("GET" if upgrading else "POST", url,
                body=None if upgrading else commitment,
                headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "tallylock"},
                response_limit=10000, deadline=deadline)
        except _http.NetworkError:
            response = None
        if response is not None:
            if response.status == 200:
                try:
                    stamp = anchors.parse_timestamp(response.body, commitment)
                    bitcoin, _, pending, _ = anchors._evidence(stamp)
                    if not bitcoin and not pending:
                        raise TallyLockError("calendar timestamp has no supported witness")
                except TallyLockError:
                    raise TallyLockError("calendar returned an invalid timestamp", code=5) from None
                return response.body
            if upgrading and response.status == 404:
                return None
            if response.status not in {403, 429} and not 500 <= response.status <= 599:
                raise TallyLockError("calendar returned an unsuccessful status", code=5)
            due = _retry_at(response.retry_after)
            if due is not None:
                raise RetryDeferred(due)
        if attempt == 2:
            raise TallyLockError("calendar request failed after bounded retries", code=5)
        delay = 2 ** attempt
        if time.monotonic() + delay >= deadline:
            raise TallyLockError("calendar retry exceeds the request deadline", code=5)
        time.sleep(delay)


def submit(origin: str, commitment: bytes, *, deadline: float | None = None) -> bytes:
    return _call(origin, commitment, upgrading=False, deadline=deadline)


def upgrade(origin: str, commitment: bytes, *, deadline: float | None = None) -> bytes | None:
    return _call(origin, commitment, upgrading=True, deadline=deadline)
