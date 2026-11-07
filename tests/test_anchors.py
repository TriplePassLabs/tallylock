"""Offline OTS interoperability and bounded untrusted-parser checks."""

from bitcoin.core import CBlockHeader
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation, LitecoinBlockHeaderAttestation,
    PendingAttestation, UnknownAttestation,
)
from opentimestamps.core.op import (
    Op, OpAppend, OpPrepend, OpReverse, OpHexlify,
    OpSHA1, OpSHA256, OpRIPEMD160, OpKECCAK256,
)
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
import pytest

from tallylock.errors import TallyLockError
from test_chain import HEADER, ModuleByName, cache_for


DIGEST = "12" * 32
MAGIC = DetachedTimestampFile.HEADER_MAGIC
PREFIX = MAGIC + b"\x01\x08" + bytes.fromhex(DIGEST)


def encode(value):
    ctx = BytesSerializationContext()
    value.serialize(ctx)
    return ctx.getbytes()


def test_raw_calendar_timestamp_preflight_before_operation_evaluation(monkeypatch):
    from tallylock import anchors
    stamp = Timestamp(bytes.fromhex(DIGEST))
    stamp.ops.add(OpSHA256()).attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
    encoded = encode(stamp)
    assert anchors.parse_timestamp(encoded, bytes.fromhex(DIGEST)).msg == bytes.fromhex(DIGEST)
    calls = []
    monkeypatch.setattr(OpSHA256, "__call__", lambda *a: calls.append(a))
    for data in (encoded+b"trailing", b"x"*10001, b"\x08"*65):
        with pytest.raises(TallyLockError):
            anchors.parse_timestamp(data, bytes.fromhex(DIGEST))
    assert calls == []


def detached(stamp):
    return encode(DetachedTimestampFile(OpSHA256(), stamp))


def pending():
    stamp = Timestamp(bytes.fromhex(DIGEST))
    stamp.attestations.add(PendingAttestation("https://example.invalid/calendar"))
    return detached(stamp)


def synthetic_witness(heights=(1,), operations=()):
    stamp = Timestamp(bytes.fromhex(DIGEST))
    end = stamp
    for op in operations:
        end = end.ops.add(op)
    for height in heights:
        end.attestations.add(BitcoinBlockHeaderAttestation(height))
    header = CBlockHeader(hashMerkleRoot=end.msg, nTime=1700000000).serialize()
    return stamp, header


@pytest.fixture
def modules():
    return ModuleByName("anchors"), ModuleByName("chain")


def assert_error(call, code=2):
    with pytest.raises(TallyLockError) as error:
        call()
    assert error.value.code == code


def test_pending_inspection_exact_shape_and_standard_interoperability(modules):
    anchors, _ = modules
    proof = pending()
    upstream = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    assert encode(upstream) == proof
    assert anchors.inspect(proof, DIGEST) == {
        "format": "prove.ots-inspection.v1", "sha256": DIGEST, "bytes": len(proof),
        "bitcoin_heights": [], "pending_count": 1, "unsupported_attestations": 0,
    }
    assert anchors.verify(proof, DIGEST, None) == {
        "state": "pending", "height": None, "hash": None, "time": None, "confirmations": None,
        "required_heights": [], "ignored_invalid_attestations": 0, "unsupported_attestations": 0,
    }
    assert anchors.verify(None, DIGEST, None)["state"] == "missing"


@pytest.mark.parametrize("ops", [(), (OpAppend(b"salt"), OpSHA256()),
    (OpPrepend(b"salt"), OpSHA256()), (OpReverse(),), (OpHexlify(), OpSHA256()),
    (OpSHA1(), OpRIPEMD160(), OpSHA256()), (OpKECCAK256(),)])
def test_standard_operations_and_qualifying_witness(modules, ops):
    anchors, chain = modules
    stamp, header = synthetic_witness((3, 1, 3), ops)
    proof = detached(stamp)
    view = chain.prepare(cache_for({1: header, 3: header}, 6))
    result = anchors.verify(proof, DIGEST, view)
    assert result == {
        "state": "anchored", "height": 1, "hash": view.block(1).hash,
        "time": 1700000000, "confirmations": 6, "required_heights": [1, 3],
        "ignored_invalid_attestations": 0, "unsupported_attestations": 0,
    }
    assert anchors.inspect(proof, DIGEST)["bitcoin_heights"] == [1, 3]


def test_historical_header_merkle_match_without_file_preimage_claim(modules):
    anchors, chain = modules
    root = CBlockHeader.deserialize(HEADER).hashMerkleRoot
    stamp = Timestamp(root)
    stamp.attestations.add(BitcoinBlockHeaderAttestation(1))
    result = anchors.verify(detached(stamp), root.hex(), chain.prepare(cache_for()))
    assert result["state"] == "anchored" and result["height"] == 1


def test_confirmation_edges_and_missing_header_fields(modules):
    anchors, chain = modules
    stamp, header = synthetic_witness()
    proof = detached(stamp)
    for confirmations, state in [(5, "insufficient_confirmations"), (6, "anchored"), (7, "anchored")]:
        result = anchors.verify(proof, DIGEST, chain.prepare(cache_for({1: header}, confirmations)))
        assert result["state"] == state and result["confirmations"] == confirmations
    for view in (None, chain.prepare(cache_for({}))):
        result = anchors.verify(proof, DIGEST, view)
        assert result["state"] == "insufficient_chain" and result["required_heights"] == [1]
        assert all(result[key] is None for key in ("height", "hash", "time", "confirmations"))


def test_existential_witness_policy_counts_invalid_extras(modules):
    anchors, chain = modules
    stamp, header = synthetic_witness((2,))
    bad = stamp.ops.add(OpSHA256())
    bad.attestations.add(BitcoinBlockHeaderAttestation(1))
    stamp.attestations.add(UnknownAttestation(b"unknown!", b"opaque"))
    stamp.attestations.add(PendingAttestation("https://example.invalid"))
    view = chain.prepare(cache_for({1: header, 2: header}, 7))
    result = anchors.verify(detached(stamp), DIGEST, view)
    assert result["state"] == "anchored" and result["height"] == 2
    assert result["ignored_invalid_attestations"] == 1 and result["unsupported_attestations"] == 1
    result = anchors.verify(detached(stamp), DIGEST, view, minimum_confirmations=7)
    assert result["state"] == "insufficient_confirmations" and result["height"] == 2
    assert_error(lambda: anchors.verify(detached(stamp), DIGEST, chain.prepare(cache_for({1: header}, 7))))


def test_wrong_cached_root_fails_and_pending_cannot_hide_it(modules):
    anchors, chain = modules
    stamp, _ = synthetic_witness()
    stamp.attestations.add(PendingAttestation("https://example.invalid"))
    assert_error(lambda: anchors.verify(detached(stamp), DIGEST, chain.prepare(cache_for())))


def test_unsupported_attestations_visible_and_fail_four_when_only_evidence(modules):
    anchors, _ = modules
    stamp = Timestamp(bytes.fromhex(DIGEST))
    stamp.attestations.update((UnknownAttestation(b"unknown!", b"anything"), LitecoinBlockHeaderAttestation(1)))
    proof = detached(stamp)
    assert anchors.inspect(proof, DIGEST)["unsupported_attestations"] == 2
    assert_error(lambda: anchors.verify(proof, DIGEST, None), 4)
    stamp.attestations.add(PendingAttestation("https://example.invalid"))
    assert anchors.verify(detached(stamp), DIGEST, None)["state"] == "pending"


@pytest.mark.parametrize("digest", ["ab", "AB" * 32, "12" * 32 + "\n", None, 123, "gg" * 32])
def test_expected_digest_is_exact_even_for_missing_proof(modules, digest):
    anchors, _ = modules
    assert_error(lambda: anchors.inspect(pending(), digest))
    assert_error(lambda: anchors.verify(None, digest, None))


@pytest.mark.parametrize("minimum", [0, -1, True, 1.0, "6", None, 2**53])
def test_minimum_confirmations_requires_positive_safe_integer(modules, minimum):
    anchors, _ = modules
    assert_error(lambda: anchors.verify(None, DIGEST, None, minimum_confirmations=minimum))


def test_chain_view_is_explicit_typed_input(modules):
    anchors, _ = modules
    assert_error(lambda: anchors.verify(pending(), DIGEST, cache_for()))


@pytest.mark.parametrize("data,code", [
    (b"", 2), (b"X" + PREFIX[1:], 2), (MAGIC + b"\x02", 4),
    (MAGIC + b"\x01\x02" + b"0" * 20, 4),
    (MAGIC + b"\x01\x03" + b"0" * 20, 4),
    (MAGIC + b"\x01\x09", 2), (PREFIX + b"\xfe", 2),
    (PREFIX + b"\xf0\x00", 2), (PREFIX + b"\xf0" + b"\x80" * 10, 2),
    (PREFIX + b"\x00unknown!" + b"\x80" * 10, 2),
    (PREFIX + b"\x00unknown!\x81\x40", 2),
    (PREFIX + b"\x00" + BitcoinBlockHeaderAttestation.TAG + b"\x05\x80\x80\x80\x80\x10", 2),
    (bytearray(PREFIX), 2), (None, 2),
])
def test_invalid_framing_and_unsupported_header(modules, data, code):
    anchors, _ = modules
    assert_error(lambda: anchors.inspect(data, DIGEST), code)


def test_digest_substitution_truncation_and_eof(modules):
    anchors, _ = modules
    proof = pending()
    assert_error(lambda: anchors.inspect(proof, "34" * 32))
    for offset in range(len(proof)):
        assert_error(lambda: anchors.inspect(proof[:offset], DIGEST))
    assert_error(lambda: anchors.inspect(proof + b"garbage", DIGEST))


def test_upstream_duplicate_ops_and_message_size_fail_closed(modules):
    anchors, _ = modules
    att = b"\x00" + encode(BitcoinBlockHeaderAttestation(1))
    assert_error(lambda: anchors.inspect(PREFIX + b"\xff\x08" + att + b"\x08" + att, DIGEST))
    body = b"\xf0" + b"\x80\x20" + b"x" * 4096 + att
    assert_error(lambda: anchors.inspect(PREFIX + body, DIGEST))


def test_depth_boundary_and_preflight_before_any_operation(modules, monkeypatch):
    anchors, _ = modules
    att = b"\x00" + encode(BitcoinBlockHeaderAttestation(1))
    assert anchors.inspect(PREFIX + b"\x08" * (anchors.MAX_TIMESTAMP_DEPTH - 1) + att, DIGEST)["bitcoin_heights"] == [1]
    def forbidden(*args):
        pytest.fail("Operation evaluated before full preflight accepted framing")
    monkeypatch.setattr(Op, "__call__", forbidden)
    for bad in (PREFIX + b"\x08" * anchors.MAX_TIMESTAMP_DEPTH + att,
                PREFIX + b"\x08" + att + b"trailing",
                PREFIX + b"\xff\x08" + att + b"\xfe"):
        assert_error(lambda: anchors.inspect(bad, DIGEST))


def test_aggregate_item_boundary_and_preflight_before_hashing(modules, monkeypatch):
    anchors, _ = modules
    att = b"\x00" + encode(UnknownAttestation(b"unknown!", b""))
    accepted = PREFIX + (b"\xff" + att) * 99998 + att
    assert anchors.inspect(accepted, DIGEST)["unsupported_attestations"] == 1
    def forbidden(*args):
        pytest.fail("Operation evaluated before aggregate bound accepted")
    monkeypatch.setattr(Op, "__call__", forbidden)
    too_wide = PREFIX + b"\xff\x08" + att + (b"\xff" + att) * 99998 + att
    assert_error(lambda: anchors.inspect(too_wide, DIGEST))


def test_byte_limit_rejected_before_hashing(modules, monkeypatch):
    anchors, _ = modules
    def forbidden(*args):
        pytest.fail("Operation evaluated on oversized proof")
    monkeypatch.setattr(Op, "__call__", forbidden)
    proof = pending()
    assert_error(lambda: anchors.inspect(proof + b"x" * (16 * 1024 * 1024), DIGEST))


def test_exact_byte_limit_is_accepted_with_bounded_standard_attestations(modules):
    anchors, _ = modules
    # Repeated attestations use upstream set semantics, but still consume preflight work.
    full = b"\xff\x00" + encode(UnknownAttestation(b"unknown!", b"x" * 8192))
    size = 16 * 1024 * 1024
    count = (size - len(PREFIX) - 12) // len(full)
    remaining = size - len(PREFIX) - count * len(full)
    # At this size, the last payload has a two-byte varuint framing length.
    last = b"\x00" + encode(UnknownAttestation(b"unknown!", b"y" * (remaining - 11)))
    proof = PREFIX + full * count + last
    assert len(proof) == size
    assert anchors.inspect(proof, DIGEST)["bytes"] == size
    assert_error(lambda: anchors.inspect(proof + b"x", DIGEST))


def test_attestation_payload_and_uri_bounds_preserved_before_hashing(modules, monkeypatch):
    anchors, _ = modules
    def uint(value):
        ctx = BytesSerializationContext()
        ctx.write_varuint(value)
        return ctx.getbytes()
    def forbidden(*args):
        pytest.fail("Operation evaluated before malformed attestation was rejected")
    monkeypatch.setattr(Op, "__call__", forbidden)
    uri = uint(1001) + b"x" * 1001
    for bad in (b"\x00unknown!" + uint(8193) + b"x" * 8193,
                b"\x00" + PendingAttestation.TAG + uint(len(uri)) + uri,
                b"\x00" + BitcoinBlockHeaderAttestation.TAG + b"\x02\x01\x00"):
        assert_error(lambda: anchors.inspect(PREFIX + b"\x08" + bad, DIGEST))


def test_non_sha256_intermediate_bitcoin_message_is_invalid(modules):
    anchors, chain = modules
    stamp = Timestamp(bytes.fromhex(DIGEST))
    stamp.ops.add(OpSHA1()).attestations.add(BitcoinBlockHeaderAttestation(1))
    assert_error(lambda: anchors.verify(detached(stamp), DIGEST, chain.prepare(cache_for())))
