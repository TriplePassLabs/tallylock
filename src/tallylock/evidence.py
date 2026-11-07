"""Explicit read-only Bitcoin Core acquisition; source trust remains external."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from . import _http, canonical, chain
from .canonical import MAX_SAFE_INTEGER
from .errors import TallyLockError


_CONFIG_LIMIT = 16384
_COOKIE_LIMIT = 4096
_RESPONSE_LIMIT = 65536
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_HEADER = re.compile(r"[0-9a-f]{160}\Z")


def _read_regular(path: Path, limit: int) -> bytes:
    # O_NONBLOCK prevents a selected FIFO from blocking before fstat can reject it.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise TallyLockError("RPC local input must be a bounded regular file")
            value = stream.read(limit + 1)
            if len(value) > limit:
                raise TallyLockError("RPC local input exceeds its size limit")
            return value
    except (OSError, ValueError):
        raise TallyLockError("cannot read RPC local input") from None


def _config(path: Path):
    if not isinstance(path, Path):
        raise TallyLockError("RPC configuration path must be a Path")
    try:
        value = canonical.loads(_read_regular(path, _CONFIG_LIMIT))
    except TallyLockError:
        raise TallyLockError("invalid RPC local configuration") from None
    if (not isinstance(value, dict)
            or set(value) != {"format", "endpoint", "cookie_file", "source"}
            or value["format"] != "prove.bitcoin-rpc.v1"
            or any(not isinstance(value[key], str) or not value[key]
                   for key in ("endpoint", "cookie_file", "source"))):
        raise TallyLockError("invalid RPC local configuration")
    endpoint = value["endpoint"]
    try:
        parsed = urlsplit(endpoint)
        valid = (endpoint.isascii() and len(endpoint) <= 2048
                 and parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and parsed.path in {"", "/"} and parsed.port != 0
                 and not any(c in endpoint for c in "@?#%\\")
                 and not any(ord(c) <= 32 or ord(c) == 127 for c in endpoint))
        parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise TallyLockError("RPC endpoint must be an HTTP or HTTPS origin without credentials")
    cookie_path = Path(value["cookie_file"])
    if not cookie_path.is_absolute():
        cookie_path = path.parent / cookie_path
    cookie = _read_regular(cookie_path, _COOKIE_LIMIT)
    # Core writes a single user:password cookie, optionally followed by a newline.
    cookie = cookie.removesuffix(b"\n").removesuffix(b"\r")
    user, separator, password = cookie.partition(b":")
    if (not separator or not user or not password
            or any(byte <= 32 or byte == 127 for byte in cookie)):
        raise TallyLockError("invalid RPC authentication cookie")
    authorization = "Basic " + base64.b64encode(cookie).decode("ascii")
    return endpoint, authorization, value["source"]


def _decimal(token: str) -> Decimal:
    # Bound both the token and exponent before any plain-decimal expansion.
    if len(token) > 512:
        raise ValueError("number limit")
    value = Decimal(token)
    parts = value.as_tuple()
    if (not value.is_finite() or len(parts.digits) > 128
            or not isinstance(parts.exponent, int) or abs(parts.exponent) > 128):
        raise ValueError("number limit")
    return value


def _integer(token: str) -> int:
    if len(token) > 17:
        raise ValueError("integer limit")
    value = int(token)
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise ValueError("integer limit")
    return value


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _constant(token):
    raise ValueError("nonfinite JSON number")


def _json(body: bytes):
    try:
        if not isinstance(body, bytes) or len(body) > _RESPONSE_LIMIT:
            raise ValueError("response limit")
        value = json.loads(body.decode("utf-8"), parse_float=_decimal, parse_int=_integer,
                           parse_constant=_constant, object_pairs_hook=_object)
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            if depth > 64:
                raise ValueError("nesting limit")
            if isinstance(item, dict):
                stack.extend((part, depth + 1) for part in item.values())
                stack.extend((key, depth + 1) for key in item)
            elif isinstance(item, list):
                stack.extend((part, depth + 1) for part in item)
            elif isinstance(item, str):
                item.encode("utf-8")
        return value
    except (ValueError, TypeError, RecursionError, InvalidOperation, OverflowError):
        raise TallyLockError("RPC returned malformed JSON", code=5) from None


def _progress(value) -> str:
    if type(value) is int:
        value = Decimal(value)
    if not isinstance(value, Decimal) or not value.is_finite() or not 0 <= value <= 1:
        raise TallyLockError("RPC returned invalid verification progress", code=5)
    parts = value.as_tuple()
    if len(parts.digits) > 128 or abs(parts.exponent) > 128:
        raise TallyLockError("RPC verification progress exceeds numeric limits", code=5)
    if value.is_zero():
        return "0"
    # Avoid normalize(), which rounds through the caller's Decimal context.
    digits = list(parts.digits)
    exponent = parts.exponent
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    point = len(digits) + exponent
    length = (2 - point + len(digits) if point <= 0 else
              point if exponent >= 0 else len(digits) + 1)
    if length > 128:
        raise TallyLockError("RPC verification progress exceeds numeric limits", code=5)
    text = "".join(str(digit) for digit in digits)
    if point <= 0:
        return "0." + "0" * -point + text
    if exponent >= 0:
        return text + "0" * exponent
    return text[:point] + "." + text[point:]


def _retry_delay(value):
    if not isinstance(value, str) or len(value) > 256:
        return None
    try:
        if re.fullmatch(r"[0-9]{1,16}", value):
            return int(value)
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            return None
        return max(0, math.ceil(date.timestamp() - time.time()))
    except (ValueError, TypeError, OverflowError):
        return None


class _RPC:
    def __init__(self, endpoint, authorization, deadline):
        self.endpoint = endpoint
        self.headers = {"Content-Type": "application/json", "Accept": "application/json",
                        "Authorization": authorization}
        self.deadline = deadline
        self.sequence = 0

    def call(self, method, params):
        self.sequence += 1
        identifier = self.sequence
        body = json.dumps({"jsonrpc": "1.0", "id": identifier, "method": method,
                           "params": params}, separators=(",", ":")).encode()
        for attempt in range(3):
            if time.monotonic() >= self.deadline:
                raise TallyLockError("RPC network phase deadline exceeded", code=5)
            try:
                response = _http.request("POST", self.endpoint, body=body, headers=self.headers,
                    response_limit=_RESPONSE_LIMIT, timeout_seconds=10, deadline=self.deadline)
            except _http.NetworkError:
                response = None
            except TallyLockError:
                raise TallyLockError("RPC request failed", code=5) from None
            if response is not None:
                if response.status == 200:
                    value = _json(response.body)
                    if (not isinstance(value, dict) or not {"id", "result", "error"} <= value.keys()
                            or type(value["id"]) is not int or value["id"] != identifier):
                        raise TallyLockError("RPC returned an invalid response envelope", code=5)
                    if value["error"] is not None:
                        error = value["error"]
                        if (not isinstance(error, dict) or type(error.get("code")) is not int
                                or not isinstance(error.get("message"), str)
                                or value["result"] is not None):
                            raise TallyLockError("RPC returned a malformed error", code=5)
                        code = 4 if error["code"] == -32601 else 5
                        raise TallyLockError("RPC method unavailable" if code == 4 else "RPC returned an error", code=code)
                    return value["result"]
                if response.status in {404, 405}:
                    raise TallyLockError("RPC route is unsupported", code=4)
                if response.status not in {403, 429} and not 500 <= response.status <= 599:
                    raise TallyLockError("RPC returned an unsuccessful status", code=5)
                delay = _retry_delay(response.retry_after)
            else:
                delay = None
            if attempt == 2:
                code = 4 if response is not None and response.status == 501 else 5
                raise TallyLockError("RPC failed after bounded retries", code=code)
            delay = max(2**attempt, delay or 0)
            if time.monotonic() + delay >= self.deadline:
                raise TallyLockError("RPC retry deferred beyond network deadline", code=5)
            time.sleep(delay)
        raise TallyLockError("RPC request failed", code=5)


def _node(value):
    if (not isinstance(value, dict)
            or not {"chain", "initialblockdownload", "blocks", "headers", "bestblockhash",
                    "verificationprogress"} <= value.keys()
            or not isinstance(value["chain"], str) or not value["chain"]
            or type(value["initialblockdownload"]) is not bool
            or any(type(value[key]) is not int or not 0 <= value[key] <= MAX_SAFE_INTEGER
                   for key in ("blocks", "headers"))
            or not isinstance(value["bestblockhash"], str)
            or _HASH.fullmatch(value["bestblockhash"]) is None):
        raise TallyLockError("RPC returned malformed node state", code=5)
    progress = _progress(value["verificationprogress"])
    if value["chain"] != "main":
        raise TallyLockError("RPC node network is unsupported", code=4)
    if value["initialblockdownload"] or value["blocks"] != value["headers"]:
        raise TallyLockError("RPC node is still synchronizing", code=3)
    return {"chain": "main", "initialblockdownload": False, "blocks": value["blocks"],
            "headers": value["headers"], "verificationprogress": progress}, value["bestblockhash"]


def _hash(value):
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise TallyLockError("RPC returned an invalid block hash", code=5)
    return value


def export(config_path: Path, heights: list[int]) -> dict:
    """Acquire a bounded coherent cache, without publishing files or proving source trust."""
    if (not isinstance(heights, list) or not 1 <= len(heights) <= 128
            or any(type(height) is not int or not 0 <= height <= MAX_SAFE_INTEGER for height in heights)):
        raise TallyLockError("RPC heights must be a nonempty bounded list of nonnegative safe integers")
    selected = sorted(set(heights))
    endpoint, authorization, source = _config(config_path)
    rpc = _RPC(endpoint, authorization, time.monotonic() + 120)
    for _ in range(3):
        node, tip_hash = _node(rpc.call("getblockchaininfo", []))
        tip_height = node["blocks"]
        if selected[-1] > tip_height:
            raise TallyLockError("requested height is beyond the RPC node tip", code=3)
        blocks = {}
        for height in selected:
            block_hash = _hash(rpc.call("getblockhash", [height]))
            header = rpc.call("getblockheader", [block_hash, False])
            if not isinstance(header, str) or _HEADER.fullmatch(header) is None:
                raise TallyLockError("RPC returned an invalid raw block header", code=5)
            blocks[str(height)] = {"hash": block_hash, "header": header,
                                  "confirmations": tip_height - height + 1}
        stable = True
        for height in selected:
            if _hash(rpc.call("getblockhash", [height])) != blocks[str(height)]["hash"]:
                stable = False
        after_node, after_hash = _node(rpc.call("getblockchaininfo", []))
        if not stable or after_hash != tip_hash or after_node["blocks"] != tip_height:
            continue
        value = {"format": "prove.chain.v1",
                 "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "source": source, "tip": {"height": tip_height, "hash": tip_hash},
                 "node": after_node, "blocks": blocks}
        try:
            chain.prepare(value)
        except TallyLockError:
            raise TallyLockError("RPC snapshot failed cache binding validation", code=5) from None
        return value
    raise TallyLockError("RPC active-chain snapshot changed repeatedly", code=3)
