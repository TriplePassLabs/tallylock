"""Main-owned cross-boundary observations; synthetic headers are never live evidence."""

import hashlib
import importlib
import shutil

from bitcoin.core import CBlockHeader, b2lx
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
import pytest

from tallylock import canonical, fixture, records, schema, store
from tallylock.filesystem import Directory, WriterLock


@pytest.fixture
def verifier():
    assert importlib.util.find_spec("tallylock.verify") is not None, "full verifier not implemented"
    return importlib.import_module("tallylock.verify")


def receipt_at(tmp_path, *, false_score=False):
    sample = fixture.example()
    aggregate = sample.aggregate
    if false_score:
        payload = canonical.loads(sample.artifacts["scores.json"])
        payload["aggregate"] = {"numerator": 2, "denominator": 2}
        sample.artifacts["scores.json"] = canonical.dumps(payload)
        aggregate = payload["aggregate"]
    source = tmp_path / "ordinary-outputs"
    source.mkdir()
    for path, data in sample.artifacts.items():
        (source / path).write_bytes(data)
    receipt = tmp_path / "receipt"
    receipt.mkdir()
    store.register(sample.manifest, receipt)
    result = store.seal(receipt, source, events=sample.events, roles=sample.roles,
                        score_path=sample.score_path, aggregate=aggregate)
    # All hashes, lengths and supplied trace bindings are actually correct.
    schema.validate_result(result, sample.manifest)
    records.check(sample.manifest, result, (receipt / "records.jsonl").read_bytes())
    for name, entry in result["inventory"].items():
        data = (receipt / "artifacts" / name).read_bytes()
        assert (hashlib.sha256(data).hexdigest(), len(data)) == (entry["sha256"], entry["bytes"])
    return receipt


def synthetic_anchors(receipt):
    (receipt / "proofs").mkdir()
    blocks = {}
    for height, name in enumerate(("manifest", "result"), 1):
        digest = hashlib.sha256((receipt / f"{name}.json").read_bytes()).digest()
        stamp = Timestamp(digest)
        stamp.attestations.add(BitcoinBlockHeaderAttestation(height))
        context = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), stamp).serialize(context)
        (receipt / "proofs" / f"{name}.ots").write_bytes(context.getbytes())
        header = CBlockHeader(hashMerkleRoot=digest, nTime=1700000000 + height)
        blocks[str(height)] = {"header": header.serialize().hex(), "hash": b2lx(header.GetHash()),
                               "confirmations": 8 - height}
    return {"format": "prove.chain.v1", "exported_at": "2026-11-06T00:00:00Z",
            "source": "Entirely fabricated coherent test cache; NOT node evidence",
            "tip": {"height": 7, "hash": "ab" * 32},
            "node": {"chain": "main", "initialblockdownload": False, "blocks": 7,
                     "headers": 7, "verificationprogress": "1"}, "blocks": blocks}


def test_full_math_failure_outranks_missing_both_anchors(verifier, tmp_path):
    receipt = receipt_at(tmp_path, false_score=True)
    answer = verifier.full(receipt)
    assert answer.code == answer.report["code"] == 2
    assert answer.report["artifact_integrity"]["state"] == "checked"
    assert answer.report["record_integrity"]["state"] == "checked"
    assert answer.report["score"]["state"] == "invalid"
    assert answer.report["manifest_anchor"]["state"] == "missing"
    assert answer.report["result_anchor"]["state"] == "missing"


def test_membership_of_false_score_receipt_has_honest_limited_scope(verifier, tmp_path):
    receipt = receipt_at(tmp_path, false_score=True)
    inclusion = verifier.make_inclusion(receipt, 0, include_proofs=False)
    shutil.rmtree(receipt)
    answer = verifier.inclusion(inclusion, policy="integrity-only")
    assert answer.code == 0
    report = answer.report
    assert report["scope"] == "inclusion"
    assert report["record_integrity"]["state"] == "membership_checked"
    for field in ("artifact_integrity", "score", "coverage", "budget", "resources"):
        assert report[field]["state"] == "not_checked"
    assert report["execution"] == report["issuer_identity"] == report["model"]["state"] == "unverified"


def test_coherent_forged_explicit_cache_shows_source_trust_boundary(verifier, tmp_path):
    receipt = receipt_at(tmp_path)
    cache = synthetic_anchors(receipt)
    # The exact same untrusted bytes hidden in local state must confer no trust.
    (receipt / ".prove" / "chain.json").write_bytes(canonical.dumps(cache))
    absent = verifier.full(receipt)
    assert absent.code == 3
    assert absent.report["chain_view"]["state"] == "unavailable"
    explicit = verifier.full(receipt, chain_cache=cache)
    assert explicit.code == 0
    assert explicit.report["minimum_confirmations"] == 6
    assert explicit.report["chain_view"]["trust"] == "external_explicit"
    assert explicit.report["chain_view"]["freshness"] == "cached_only"
    assert explicit.report["manifest_anchor"]["state"] == "anchored"
    assert explicit.report["result_anchor"]["state"] == "anchored"
    assert explicit.report["execution"] == explicit.report["model"]["state"] == "unverified"


def test_integrity_only_ignores_bad_proof_and_cache_without_writes(verifier, tmp_path, monkeypatch):
    receipt = receipt_at(tmp_path)
    shutil.rmtree(receipt / ".prove")
    (receipt / "proofs").mkdir()
    (receipt / "proofs" / "manifest.ots").write_bytes(b"not a timestamp")
    from tallylock import chain
    monkeypatch.setattr(chain, "prepare", lambda *a, **k: pytest.fail("integrity-only parsed cache"))
    monkeypatch.setattr(Directory, "atomic_write", lambda *a, **k: pytest.fail("verification wrote a file"))
    monkeypatch.setattr(WriterLock, "__enter__", lambda *a, **k: pytest.fail("verification acquired writer lock"))
    answer = verifier.full(receipt, policy="integrity-only", chain_cache={"format": "malformed"})
    assert answer.code == 0
    assert answer.report["manifest_anchor"]["state"] == "not_checked"
    assert answer.report["chain_view"]["state"] == "not_checked"
    assert not (receipt / ".prove").exists()


def test_bad_counterpart_proof_not_hidden_by_missing_proof_or_cache(verifier, tmp_path):
    receipt = receipt_at(tmp_path)
    (receipt / "proofs").mkdir()
    (receipt / "proofs" / "result.ots").write_bytes(b"bad detached proof")
    answer = verifier.full(receipt)
    assert answer.code == 2
    assert answer.report["manifest_anchor"]["state"] == "missing"
    assert answer.report["result_anchor"]["state"] == "invalid"


def test_valid_near_limit_cache_does_not_overflow_report(verifier, tmp_path):
    receipt = receipt_at(tmp_path)
    cache = synthetic_anchors(receipt)
    cache["source"] = "x" * (canonical.MAX_JSON_BYTES - 2048)
    assert len(canonical.dumps(cache)) < canonical.MAX_JSON_BYTES
    answer = verifier.full(receipt, chain_cache=cache)
    assert answer.code == 0
    view = answer.report["chain_view"]
    assert view["source"] is None and view["omitted_fields"] == ["source"]
    assert len(canonical.dumps(answer.report)) < 32 * 1024
    assert cache["source"].startswith("x") and len(cache["source"]) > 8_000_000
