"""Behavioral tests for RFC 9162 Merkle primitives."""

from __future__ import annotations

import pytest

from tallylock.errors import TallyLockError
from tallylock.merkle import proof, root, verify


LEAVES = [b"alpha", b"bravo", b"charlie"]
# SHA-256 of the RFC 9162 construction for alpha, bravo, charlie:
# H(0x01 || H(0x01 || H(0x00 || alpha) || H(0x00 || bravo)) || H(0x00 || charlie))
EXPECTED_ROOT = "d4186e3c05a620ce61397e838bfbd76e6f27e6d7daa13c59eb82a8e094608e1c"
FIXED_VECTORS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    1: "305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7",
    2: "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc",
    3: "cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a",
    5: "00d21829a5503145348abcf712513eacf2a274211ad83e970202bb5b6d80b286",
    7: "0b007fb915eb9b2a146f54b1c86ec53b664f8e455b7660b0b6ee13edc0d921c0",
    8: "ca6b7b3e674ac86c1027b59c87c064fc3bc27b313294c75f83bd05fdd13f0dcf",
    9: "1374d3a5ecbef4cd7c109e5d0127955f4ef014756496d70a0f99f65aa0ac8a30",
}


@pytest.mark.parametrize("size", FIXED_VECTORS)
def test_root_matches_independent_rfc9162_vectors(size: int) -> None:
    leaves = [f"leaf-{index}".encode("ascii") for index in range(size)]

    assert root(leaves) == FIXED_VECTORS[size]


@pytest.mark.parametrize("index", range(len(LEAVES)))
def test_proof_verifies_each_leaf_in_odd_size_tree(index: int) -> None:
    siblings = proof(LEAVES, index)

    assert verify(LEAVES[index], index, len(LEAVES), siblings, EXPECTED_ROOT)


def test_verify_rejects_extra_or_malformed_proof_nodes() -> None:
    siblings = proof(LEAVES, 1)

    assert not verify(LEAVES[1], 1, len(LEAVES), siblings + ["00" * 32], EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), ["not-hex"], EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), siblings[:-1], EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), ["00 " * 32], EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), None, EXPECTED_ROOT)  # type: ignore[arg-type]
    assert not verify(LEAVES[1], 1, len(LEAVES), [None], EXPECTED_ROOT)  # type: ignore[list-item]
    assert not verify(LEAVES[1], 1, len(LEAVES), siblings, "not-hex")


def test_verify_requires_lowercase_compact_hex_encoding() -> None:
    siblings = proof(LEAVES, 1)
    uppercase_siblings = [siblings[0].upper(), *siblings[1:]]
    whitespace_siblings = [f" {siblings[0]}", *siblings[1:]]

    assert not verify(LEAVES[1], 1, len(LEAVES), uppercase_siblings, EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), whitespace_siblings, EXPECTED_ROOT)
    assert not verify(LEAVES[1], 1, len(LEAVES), siblings, EXPECTED_ROOT.upper())
    assert not verify(LEAVES[1], 1, len(LEAVES), siblings, f" {EXPECTED_ROOT}")


def test_verify_rejects_corrupted_leaf_or_index() -> None:
    siblings = proof(LEAVES, 1)

    assert not verify(b"corrupted", 1, len(LEAVES), siblings, EXPECTED_ROOT)
    assert not verify(LEAVES[1], 0, len(LEAVES), siblings, EXPECTED_ROOT)


@pytest.mark.parametrize(
    ("leaves", "index"),
    [([], 0), (LEAVES, -1), (LEAVES, len(LEAVES))],
)
def test_producers_reject_invalid_arguments(leaves: list[bytes], index: int) -> None:
    with pytest.raises(TallyLockError):
        proof(leaves, index)


def test_root_matches_rfc9162_empty_tree_hash() -> None:
    assert root([]) == FIXED_VECTORS[0]
