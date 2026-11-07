"""Bounded standard detached OTS inspection and explicit offline verification."""

from __future__ import annotations

import re

from bitcoin.core import CBlockHeader
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation, PendingAttestation, TimeAttestation,
    VerificationError,
)
from opentimestamps.core.op import CryptOp, Op, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, DeserializationError
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from .canonical import MAX_SAFE_INTEGER
from .chain import ChainView
from .errors import TallyLockError


MAX_PROOF_BYTES = 16 * 1024 * 1024
# Match the pinned upstream timestamp decoder's default recursion policy.
MAX_TIMESTAMP_DEPTH = 256
MAX_TIMESTAMP_ITEMS = 100000


def _expected_digest(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TallyLockError("expected SHA256 must be exactly 64 lowercase hex characters")


def _detached_header(ctx, expected_sha256: str) -> bytes:
    ctx.assert_magic(DetachedTimestampFile.HEADER_MAGIC)
    major = ctx.read_uint8()
    if major != DetachedTimestampFile.MAJOR_VERSION:
        raise TallyLockError(f"unsupported detached timestamp major version: {major}", code=4)
    file_hash_op = CryptOp.deserialize(ctx)
    if not isinstance(file_hash_op, OpSHA256):
        raise TallyLockError("unsupported detached file hash algorithm", code=4)
    digest = ctx.read_bytes(file_hash_op.DIGEST_LENGTH)
    if digest.hex() != expected_sha256:
        raise TallyLockError("detached timestamp digest differs from the expected core SHA256")
    return digest


def _preflight_timestamp(ctx) -> None:
    """Walk upstream framing and bounds, without invoking any proof operation."""
    items = 0

    def count_item():
        nonlocal items
        items += 1
        if items > MAX_TIMESTAMP_ITEMS:
            raise TallyLockError("timestamp exceeds the aggregate item limit")

    def node(depth):
        if depth > MAX_TIMESTAMP_DEPTH:
            raise TallyLockError("timestamp exceeds the depth limit")
        count_item()
        operations = set()

        def entry(tag):
            if tag == b"\x00":
                count_item()
                TimeAttestation.deserialize(ctx)
            else:
                operation = Op.deserialize_from_tag(ctx, tag)
                if operation in operations:
                    raise TallyLockError("timestamp repeats an operation at the same node")
                operations.add(operation)
                node(depth + 1)

        tag = ctx.read_bytes(1)
        while tag == b"\xff":
            entry(ctx.read_bytes(1))
            tag = ctx.read_bytes(1)
        entry(tag)

    node(1)


def _load(data: bytes, expected_sha256: str) -> Timestamp:
    _expected_digest(expected_sha256)
    if not isinstance(data, bytes):
        raise TallyLockError("detached timestamp must be bytes")
    if len(data) > MAX_PROOF_BYTES:
        raise TallyLockError("detached timestamp exceeds 16 MiB")
    try:
        ctx = BytesDeserializationContext(data)
        _detached_header(ctx, expected_sha256)
        _preflight_timestamp(ctx)
        ctx.assert_eof()
        # Only fully bounded framing reaches upstream operation evaluation.
        ctx = BytesDeserializationContext(data)
        digest = _detached_header(ctx, expected_sha256)
        stamp = Timestamp.deserialize(ctx, digest, _recursion_limit=MAX_TIMESTAMP_DEPTH)
        ctx.assert_eof()
        return stamp
    except (DeserializationError, ValueError) as error:
        raise TallyLockError(f"invalid detached timestamp: {error}") from error


def parse_timestamp(data: bytes, commitment: bytes) -> Timestamp:
    """Bound raw calendar framing before evaluating standard upstream operations."""
    if not isinstance(data, bytes) or len(data) > 10000:
        raise TallyLockError("calendar timestamp exceeds its byte limit")
    if not isinstance(commitment, bytes) or not 1 <= len(commitment) <= 4096:
        raise TallyLockError("invalid calendar commitment")
    try:
        ctx = BytesDeserializationContext(data)
        _preflight_timestamp(ctx)
        ctx.assert_eof()
        ctx = BytesDeserializationContext(data)
        stamp = Timestamp.deserialize(ctx, commitment, _recursion_limit=MAX_TIMESTAMP_DEPTH)
        ctx.assert_eof()
        return stamp
    except (DeserializationError, ValueError) as error:
        raise TallyLockError("invalid raw calendar timestamp") from error


def _evidence(stamp: Timestamp):
    bitcoin = []
    pending = unsupported = 0
    for message, attestation in stamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            bitcoin.append((message, attestation))
        elif isinstance(attestation, PendingAttestation):
            pending += 1
        else:
            unsupported += 1
    heights = sorted({attestation.height for _, attestation in bitcoin})
    return bitcoin, heights, pending, unsupported


def inspect(data: bytes, expected_sha256: str) -> dict:
    stamp = _load(data, expected_sha256)
    _, heights, pending, unsupported = _evidence(stamp)
    return {
        "format": "prove.ots-inspection.v1", "sha256": expected_sha256, "bytes": len(data),
        "bitcoin_heights": heights, "pending_count": pending,
        "unsupported_attestations": unsupported,
    }


def verify(
    data: bytes | None, expected_sha256: str, chain_view: ChainView | None,
    *, minimum_confirmations: int = 6,
) -> dict:
    _expected_digest(expected_sha256)
    if type(minimum_confirmations) is not int or not 1 <= minimum_confirmations <= MAX_SAFE_INTEGER:
        raise TallyLockError("minimum confirmations must be a positive safe integer")
    if chain_view is not None and not isinstance(chain_view, ChainView):
        raise TallyLockError("chain view must be an explicit prepared ChainView")
    result = {
        "state": "missing", "height": None, "hash": None, "time": None,
        "confirmations": None, "required_heights": [],
        "ignored_invalid_attestations": 0, "unsupported_attestations": 0,
    }
    if data is None:
        return result
    bitcoin, heights, pending, unsupported = _evidence(_load(data, expected_sha256))
    result["required_heights"] = heights
    result["unsupported_attestations"] = unsupported
    valid = []
    invalid = 0
    if chain_view is not None:
        for message, attestation in bitcoin:
            block = chain_view.block(attestation.height)
            if block is None:
                continue
            try:
                attestation.verify_against_blockheader(message, CBlockHeader.deserialize(block.header))
            except VerificationError:
                invalid += 1
            else:
                valid.append(block)
    if valid:
        qualifying = [block for block in valid if block.confirmations >= minimum_confirmations]
        selected = min(qualifying or valid, key=lambda block: block.height)
        result.update(
            state="anchored" if qualifying else "insufficient_confirmations",
            height=selected.height, hash=selected.hash, time=selected.time,
            confirmations=selected.confirmations, ignored_invalid_attestations=invalid,
        )
    elif invalid:
        raise TallyLockError("no valid cached Bitcoin witness; a cached header contradicts the proof")
    elif bitcoin:
        result["state"] = "insufficient_chain"
    elif pending:
        result["state"] = "pending"
    else:
        raise TallyLockError("proof contains no supported Bitcoin or pending witness", code=4)
    return result
