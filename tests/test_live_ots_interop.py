"""OTS interoperability beyond short synthetic trees, without chain-trust claims."""

import hashlib
import json
from pathlib import Path

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
import pytest

from tallylock import anchors
from tallylock.errors import TallyLockError

LIVE_CASES = json.loads((Path(__file__).parent / "fixtures/ots/calendar-depth69.json").read_text())["cases"]


@pytest.mark.parametrize("case", LIVE_CASES, ids=lambda case: case["target"] + "-" + case["origin"].split("//")[1])
def test_captured_standard_calendar_reply(case):
    data = bytes.fromhex(case["raw_timestamp_hex"])
    assert len(data) == case["bytes"] == 1001
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    commitment = bytes.fromhex(case["commitment"])
    context = BytesDeserializationContext(data)
    reference = Timestamp.deserialize(context, commitment)
    context.assert_eof()
    stack = [(reference, 1)]
    maximum = 0
    while stack:
        node, depth = stack.pop()
        maximum = max(maximum, depth)
        stack.extend((child, depth + 1) for child in node.ops.values())
    assert maximum == case["depth"] == 69
    checked = anchors.parse_timestamp(data, commitment)
    assert checked.msg == reference.msg == commitment
    heights = sorted({attestation.height for _, attestation in checked.all_attestations()
                      if isinstance(attestation, BitcoinBlockHeaderAttestation)})
    assert heights == case["bitcoin_heights"]


def raw_chain(operations):
    context = BytesSerializationContext()
    BitcoinBlockHeaderAttestation(1).serialize(context)
    return b"\x08" * operations + b"\x00" + context.getbytes()


def test_standard_calendar_path_deeper_than_sixty_four_nodes():
    commitment = b"\x12" * 32
    data = raw_chain(70)
    upstream = BytesDeserializationContext(data)
    reference = Timestamp.deserialize(upstream, commitment)
    upstream.assert_eof()
    assert any(isinstance(attestation, BitcoinBlockHeaderAttestation)
               for _, attestation in reference.all_attestations())
    checked = anchors.parse_timestamp(data, commitment)
    context = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), checked).serialize(context)
    assert anchors.inspect(context.getbytes(), commitment.hex())["bitcoin_heights"] == [1]


def test_raw_and_detached_depth_policy_preflights_before_hashing(monkeypatch):
    assert anchors.MAX_TIMESTAMP_DEPTH == 256
    commitment = b"\x12" * 32
    accepted = anchors.parse_timestamp(raw_chain(255), commitment)
    context = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), accepted).serialize(context)
    assert anchors.inspect(context.getbytes(), commitment.hex())["bitcoin_heights"] == [1]

    def forbidden(*args):
        pytest.fail("Proof operation evaluated before rejecting over-depth framing")

    monkeypatch.setattr(OpSHA256, "__call__", forbidden)
    too_deep = raw_chain(256)
    with pytest.raises(TallyLockError, match="depth limit"):
        anchors.parse_timestamp(too_deep, commitment)
    prefix = DetachedTimestampFile.HEADER_MAGIC + b"\x01\x08" + commitment
    with pytest.raises(TallyLockError, match="depth limit"):
        anchors.inspect(prefix + too_deep, commitment.hex())
