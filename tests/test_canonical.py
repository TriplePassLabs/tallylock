"""Behavioral tests for canonical JSON primitives."""

from __future__ import annotations

import hashlib

import pytest

from tallylock import canonical
from tallylock.errors import TallyLockError


def test_dumps_uses_rfc8785_key_order_and_digest_hashes_exact_bytes() -> None:
    value = {"b": 1, "a": 2}

    encoded = canonical.dumps(value)

    assert encoded == b'{"a":2,"b":1}'
    assert canonical.digest(value) == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b'{"value":1.5}',
        b'{"value":9007199254740992}',
        b'NaN',
        b'Infinity',
        b'\xef\xbb\xbf{}',
        b'\xff',
        b'"\xed\xa0\x80"',
    ],
)
def test_loads_rejects_noncanonical_or_unsafe_json(data: bytes) -> None:
    with pytest.raises(TallyLockError):
        canonical.loads(data)


def test_dumps_rejects_float_and_surrogate() -> None:
    with pytest.raises(TallyLockError):
        canonical.dumps({"value": 1.5})

    with pytest.raises(TallyLockError):
        canonical.dumps({"value": "\ud800"})


def test_loads_rejects_nesting_beyond_64_levels() -> None:
    data = ("[" * 65 + "0" + "]" * 65).encode("ascii")

    with pytest.raises(TallyLockError):
        canonical.loads(data)


def test_loads_normalizes_parser_recursion_errors_to_prove_error() -> None:
    data = ("[" * 2_000 + "0" + "]" * 2_000).encode("ascii")

    with pytest.raises(TallyLockError):
        canonical.loads(data)


@pytest.mark.parametrize("value", [-9007199254740991, 9007199254740991])
def test_safe_integer_boundaries_are_accepted(value: int) -> None:
    assert canonical.loads(str(value)) == value
    assert canonical.dumps(value) == str(value).encode("ascii")


def test_loads_rejects_input_larger_than_8_mib() -> None:
    with pytest.raises(TallyLockError):
        canonical.loads(b" " * (8 * 1024 * 1024 + 1))
