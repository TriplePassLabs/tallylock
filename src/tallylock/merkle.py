"""RFC 9162 ordered Merkle tree construction and inclusion proofs."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

from .errors import TallyLockError


def _validate_leaves(leaves: Sequence[bytes]) -> None:
    if any(not isinstance(leaf, bytes) for leaf in leaves):
        raise TallyLockError("Merkle leaves must be bytes")


def _leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def _root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return _leaf_hash(leaves[0])
    split = _split(len(leaves))
    return _node_hash(_root(leaves[:split]), _root(leaves[split:]))


def root(leaves: Sequence[bytes]) -> str:
    """Return the RFC 9162 Merkle Tree Hash for ordered leaves."""
    _validate_leaves(leaves)
    return _root(leaves).hex()


def _proof(leaves: Sequence[bytes], index: int) -> list[str]:
    if len(leaves) == 1:
        return []
    split = _split(len(leaves))
    if index < split:
        return _proof(leaves[:split], index) + [_root(leaves[split:]).hex()]
    return _proof(leaves[split:], index - split) + [_root(leaves[:split]).hex()]


def proof(leaves: Sequence[bytes], index: int) -> list[str]:
    """Return the ordered RFC 9162 inclusion proof for a leaf index."""
    _validate_leaves(leaves)
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(leaves):
        raise TallyLockError("Merkle proof index is out of range")
    return _proof(leaves, index)


def verify(leaf: bytes, index: int, size: int, siblings: Sequence[str], expected_root: str) -> bool:
    """Validate an RFC 9162 inclusion proof, including exact node consumption."""
    if (
        not isinstance(leaf, bytes)
        or not isinstance(index, int)
        or isinstance(index, bool)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 <= index < size
        or not isinstance(expected_root, str)
    ):
        return False
    try:
        if re.fullmatch(r"[0-9a-f]{64}", expected_root) is None:
            return False
        if any(
            not isinstance(sibling, str) or re.fullmatch(r"[0-9a-f]{64}", sibling) is None
            for sibling in siblings
        ):
            return False
        nodes = [bytes.fromhex(sibling) for sibling in siblings]
        expected = bytes.fromhex(expected_root)
    except (TypeError, ValueError):
        return False
    if any(len(node) != 32 for node in nodes) or len(expected) != 32:
        return False

    def rebuild(tree_size: int, tree_index: int, position: int) -> tuple[bytes, int]:
        if tree_size == 1:
            return _leaf_hash(leaf), position
        split = _split(tree_size)
        if tree_index < split:
            child, position = rebuild(split, tree_index, position)
            if position == len(nodes):
                raise ValueError
            return _node_hash(child, nodes[position]), position + 1
        child, position = rebuild(tree_size - split, tree_index - split, position)
        if position == len(nodes):
            raise ValueError
        return _node_hash(nodes[position], child), position + 1

    try:
        calculated, consumed = rebuild(size, index, 0)
    except (RecursionError, ValueError):
        return False
    return consumed == len(nodes) and calculated == expected
