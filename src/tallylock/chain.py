"""Explicit verifier-supplied cache, with internal bindings checked offline."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from bitcoin.core import CBlockHeader, b2lx

from . import canonical
from .canonical import MAX_SAFE_INTEGER
from .errors import TallyLockError
from .schema import validate_chain


@dataclass(frozen=True)
class CachedBlock:
    height: int
    hash: str
    header: bytes
    confirmations: int
    time: int
    merkle_root: bytes


@dataclass(frozen=True)
class ChainView:
    _blocks: Mapping[int, CachedBlock]
    _exported_at: str
    _source: str
    _tip_height: int
    _tip_hash: str

    def block(self, height: int) -> CachedBlock | None:
        """Look up a checked cached header without consulting any external source."""
        if type(height) is not int or not 0 <= height <= MAX_SAFE_INTEGER:
            raise TallyLockError("block height must be a nonnegative safe integer")
        return self._blocks.get(height)

    def summary(self) -> dict:
        return {
            "exported_at": self._exported_at,
            "source": self._source,
            "tip": {"height": self._tip_height, "hash": self._tip_hash},
            "trust": "external_explicit",
            "freshness": "cached_only",
        }


def prepare(value: dict) -> ChainView:
    """Snapshot a cache; consistency checks do not authenticate its provenance."""
    # Apply the existing bounded JSON profile before copying untrusted nesting.
    snapshot = canonical.loads(canonical.dumps(value))
    validate_chain(snapshot)
    blocks = {}
    for height_text, block in snapshot["blocks"].items():
        height = int(height_text)
        raw = bytes.fromhex(block["header"])
        # Schema checks exact length/encoding; upstream supplies parsing and hash.
        parsed = CBlockHeader.deserialize(raw)
        if b2lx(parsed.GetHash()) != block["hash"]:
            raise TallyLockError(f"cached block {height} hash differs from its header")
        blocks[height] = CachedBlock(
            height, block["hash"], raw, block["confirmations"],
            parsed.nTime, parsed.hashMerkleRoot,
        )
    return ChainView(
        MappingProxyType(blocks), snapshot["exported_at"], snapshot["source"],
        snapshot["tip"]["height"], snapshot["tip"]["hash"],
    )
