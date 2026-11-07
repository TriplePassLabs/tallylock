"""Strict parsing and RFC 8785 serialization for protocol metadata."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785

from .errors import TallyLockError


MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_SAFE_INTEGER = 2**53 - 1


def _fail(message: str) -> None:
    raise TallyLockError(message)


def _integer(value: str) -> int:
    number = int(value)
    if not -MAX_SAFE_INTEGER <= number <= MAX_SAFE_INTEGER:
        _fail("JSON integers must be within the safe integer range")
    return number


def _constant(value: str) -> None:
    _fail(f"JSON constant {value!r} is not permitted")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _validate(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        _fail("JSON nesting exceeds 64 levels")
    if isinstance(value, float):
        _fail("JSON floating-point values are not permitted")
    if isinstance(value, int) and not isinstance(value, bool):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            _fail("JSON integers must be within the safe integer range")
        return
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as error:
                raise TallyLockError("JSON strings must not contain surrogate code points") from error
        return
    if isinstance(value, list):
        for item in value:
            _validate(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("JSON object keys must be strings")
            _validate(key, depth + 1)
            _validate(item, depth + 1)
        return
    _fail(f"value of type {type(value).__name__} is not JSON")


def loads(data: bytes | str) -> Any:
    """Parse bounded strict JSON without executing metadata content."""
    if isinstance(data, bytes):
        if len(data) > MAX_JSON_BYTES:
            _fail("JSON input exceeds 8 MiB")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise TallyLockError("JSON input must be valid UTF-8") from error
    elif isinstance(data, str):
        try:
            encoded = data.encode("utf-8")
        except UnicodeEncodeError as error:
            raise TallyLockError("JSON input must not contain surrogate code points") from error
        if len(encoded) > MAX_JSON_BYTES:
            _fail("JSON input exceeds 8 MiB")
        text = data
    else:
        _fail("JSON input must be bytes or str")
    try:
        value = json.loads(
            text,
            parse_float=lambda _: _fail("JSON floating-point values are not permitted"),
            parse_int=_integer,
            parse_constant=_constant,
            object_pairs_hook=_object,
        )
    except TallyLockError:
        raise
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise TallyLockError("invalid JSON") from error
    _validate(value)
    return value


def dumps(value: Any) -> bytes:
    """Serialize a validated JSON value using RFC 8785 canonical JSON."""
    _validate(value)
    try:
        encoded = rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise TallyLockError("value cannot be serialized as canonical JSON") from error
    if len(encoded) > MAX_JSON_BYTES:
        _fail("canonical JSON exceeds 8 MiB")
    return encoded


def digest(value: Any) -> str:
    """Return the SHA-256 digest of the canonical JSON bytes for *value*."""
    return hashlib.sha256(dumps(value)).hexdigest()
