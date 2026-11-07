"""Bounded strict JSON reading for foreign files that may carry decimals."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path

from ..errors import TallyLockError


def _fail(message: str):
    raise TallyLockError(message)


def _decimal(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation:
        _fail("invalid JSON number")
    if not value.is_finite() or abs(value.adjusted()) > 60 or len(text) > 400:
        _fail("JSON number is out of range")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def loads(data: bytes):
    try:
        text = data.decode("utf-8")
        return json.loads(text, parse_float=_decimal, parse_constant=lambda name: _fail(f"JSON constant {name} is not permitted"),
                          object_pairs_hook=_object)
    except TallyLockError:
        raise
    except (UnicodeDecodeError, RecursionError, ValueError) as error:
        raise TallyLockError("invalid JSON") from error


def read_bounded(path, limit: int, what: str) -> bytes:
    path = Path(path)
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as error:
        raise TallyLockError(f"{what} could not be read: {path.name}") from error
    if len(data) > limit:
        _fail(f"{what} exceeds {limit} bytes")
    return data
