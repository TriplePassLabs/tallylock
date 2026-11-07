"""Hub adapters: Inspect AI logs, proofbundle receipts and in-toto export."""
import base64
import copy
import hashlib
import io
import json
import shutil
import sys
import zipfile
from fractions import Fraction
from pathlib import Path

import pytest
import rfc8785
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import eddsa

from tallylock import canonical, ledger, merkle
from tallylock.adapters import import_inspect, to_intoto, verify_proofbundle
from tallylock.errors import TallyLockError

FIXTURES = Path(__file__).parent/"fixtures"/"adapters"
FORMATS_EVAL = FIXTURES/"inspect-log_formats.eval"
FORMATS_JSON = FIXTURES/"inspect-log_formats.json"
NO_SAMPLES = FIXTURES/"inspect-no-samples.json"
EXAMPLE = FIXTURES/"proofbundle-example_bundle.json"
FORGED = FIXTURES/"proofbundle-forged-anchor-own-frozen.bundle.json"
PREDICATE_TYPE = "https://triplepasslabs.com/tallylock/attempt-ledger/v1"


def frac(attempt):
    return Fraction(attempt["score"]["numerator"], attempt["score"]["denominator"])


def inspect_log(values, *, status="success", scorer="match", extra=None):
    samples = [{"id": n, "epoch": 1, "scores": {scorer: {"value": value}}} for n, value in enumerate(values, 1)]
    log = {"version": 2, "status": status,
           "eval": {"task": "t", "model": "m/x", "created": "2026-01-01T00:00:00+00:00"},
           "results": {"total_samples": len(values), "completed_samples": len(values),
                       "scores": [{"name": scorer, "scorer": scorer, "metrics": {}}]},
           "stats": {"started_at": "2026-01-01T00:00:01+00:00", "completed_at": "2026-01-01T00:00:09+00:00"},
           "samples": samples}
    log.update(extra or {})
    return log


def write_log(tmp_path, log, name="log.json"):
    path = tmp_path/name
    path.write_text(json.dumps(log, allow_nan=True))
    return path


def test_inspect_eval_zip_fixture():
    (attempt,) = import_inspect(FORMATS_EVAL)
    assert attempt["trust"] == "declared" and attempt["source"] == "inspect"
    assert attempt["task"] == "popularity" and attempt["model"] == "ollama/llama3.1"
    assert attempt["status"] == "success" and attempt["samples"] == 1
    assert attempt["score"] == {"numerator": 0, "denominator": 1} and attempt["scorer"] == "match"
    assert attempt["log_format"] == "eval"
    assert attempt["created"] == "2024-10-15T12:53:13-04:00"
    assert attempt["started_at"] == "2024-10-15T12:53:13-04:00"
    assert attempt["completed_at"] == "2024-10-15T12:53:13-04:00"


def test_inspect_json_fixture_matches_eval_fixture():
    (from_json,) = import_inspect(FORMATS_JSON)
    (from_eval,) = import_inspect(FORMATS_EVAL)
    assert from_json.pop("log_format") == "json" and from_eval.pop("log_format") == "eval"
    assert from_json == from_eval


def test_inspect_score_is_exact_fraction_from_reductions_when_samples_are_absent():
    (attempt,) = import_inspect(NO_SAMPLES)
    assert attempt["status"] == "cancelled" and attempt["samples"] == 3
    assert attempt["score"] == {"numerator": 2, "denominator": 3}
    assert attempt["model"] == "openai/gpt-4o-mini"


def test_inspect_floats_sum_exactly_and_letter_grades_map(tmp_path):
    (attempt,) = import_inspect(write_log(tmp_path, inspect_log([0.1, 0.2, 0.3])))
    assert frac(attempt) == Fraction(1, 5)
    (attempt,) = import_inspect(write_log(tmp_path, inspect_log(["C", "I", "P", "N"])))
    assert frac(attempt) == Fraction(3, 8)
    (attempt,) = import_inspect(write_log(tmp_path, inspect_log([True, False, 1, 0])))
    assert frac(attempt) == Fraction(1, 2)


def test_inspect_unscorable_values_give_no_score_with_reason(tmp_path):
    (attempt,) = import_inspect(write_log(tmp_path, inspect_log([{"a": 1}, 1])))
    assert attempt["score"] is None and "unsupported" in attempt["score_note"]
    (attempt,) = import_inspect(write_log(tmp_path, inspect_log([])))
    assert attempt["score"] is None and attempt["samples"] == 0


def test_inspect_scorer_choice(tmp_path):
    log = inspect_log([1, 0])
    for sample in log["samples"]:
        sample["scores"]["other"] = {"value": 1}
    path = write_log(tmp_path, log)
    assert frac(import_inspect(path)[0]) == Fraction(1, 2)
    assert frac(import_inspect(path, scorer="other")[0]) == 1
    with pytest.raises(TallyLockError, match="scorer"):
        import_inspect(path, scorer="missing")


def test_inspect_does_not_import_inspect_ai():
    import_inspect(FORMATS_EVAL)
    assert "inspect_ai" not in sys.modules


@pytest.mark.parametrize("text", ['{"version": 2, "version": 3}', '{"version": NaN}', "[1, 2]", "not json", "",
                                  '{"results": {"x": 1e99999999}}'])
def test_inspect_rejects_malformed_json(tmp_path, text):
    path = tmp_path/"bad.json"
    path.write_text(text)
    with pytest.raises(TallyLockError):
        import_inspect(path)


def test_inspect_rejects_missing_fields_and_files(tmp_path):
    bad = inspect_log([1])
    del bad["eval"]
    with pytest.raises(TallyLockError, match="eval"):
        import_inspect(write_log(tmp_path, bad))
    with pytest.raises(TallyLockError, match="not found|read"):
        import_inspect(tmp_path/"missing.json")


def test_inspect_size_bounds(tmp_path, monkeypatch):
    from tallylock.adapters import inspect_log as module
    monkeypatch.setattr(module, "MAX_JSON_BYTES", 100)
    with pytest.raises(TallyLockError, match="exceeds"):
        import_inspect(FORMATS_JSON)
    monkeypatch.setattr(module, "MAX_JSON_BYTES", 64*1024*1024)
    monkeypatch.setattr(module, "MAX_MEMBER_BYTES", 500)
    with pytest.raises(TallyLockError, match="exceeds"):
        import_inspect(FORMATS_EVAL)
    monkeypatch.setattr(module, "MAX_MEMBER_BYTES", 64*1024*1024)
    monkeypatch.setattr(module, "MAX_ARCHIVE_BYTES", 500)
    with pytest.raises(TallyLockError, match="exceeds"):
        import_inspect(FORMATS_EVAL)


def test_inspect_rejects_broken_archives(tmp_path):
    broken = tmp_path/"broken.eval"
    broken.write_bytes(FORMATS_EVAL.read_bytes()[:-30])
    with pytest.raises(TallyLockError):
        import_inspect(broken)
    empty = tmp_path/"empty.eval"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("other.json", "{}")
    with pytest.raises(TallyLockError, match="header.json"):
        import_inspect(empty)


def test_inspect_eval_without_summaries_reads_sample_members(tmp_path):
    source = zipfile.ZipFile(FORMATS_EVAL)
    path = tmp_path/"nosummary.eval"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in source.infolist():
            if info.filename not in ("summaries.json", "reductions.json") and not info.filename.startswith("_journal/summaries"):
                archive.writestr(info.filename, source.read(info.filename))
    (attempt,) = import_inspect(path)
    assert attempt["score"] == {"numerator": 0, "denominator": 1} and attempt["samples"] == 1


def test_inspect_archive_member_count_is_bounded(tmp_path, monkeypatch):
    from tallylock.adapters import inspect_log as module
    monkeypatch.setattr(module, "MAX_SAMPLES", 1)
    source = zipfile.ZipFile(FORMATS_EVAL)
    path = tmp_path/"many.eval"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("header.json", source.read("header.json"))
        archive.writestr("summaries.json", json.dumps([{"id": n, "epoch": 1, "scores": {"match": {"value": 1}}}
                                                      for n in range(3)]))
    with pytest.raises(TallyLockError, match="samples"):
        import_inspect(path)


KEY = eddsa.import_private_key(bytes(range(32)))


def raw_public():
    return KEY.public_key().export_key(format="raw")


def b64(data):
    return base64.b64encode(data).decode()


def make_bundle(payload=b'{"metric":"acc","prereg_sha256":"' + b"ab"*32 + b'"}', leaves=3, index=1, anchors=None):
    others = [bytes([n])*5 for n in range(leaves)]
    others[index] = payload
    bundle = {"schema": "proofbundle/v0.1", "payload_b64": b64(payload),
              "signature": {"alg": "ed25519", "public_key_b64": b64(raw_public()),
                            "sig_b64": b64(eddsa.new(KEY, "rfc8032").sign(payload))},
              "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": index, "tree_size": leaves,
                         "inclusion_proof_b64": [b64(bytes.fromhex(h)) for h in merkle.proof(others, index)],
                         "root_b64": b64(bytes.fromhex(merkle.root(others)))}}
    if anchors is not None:
        bundle["anchors"] = anchors
    return bundle


def save(tmp_path, bundle, name="b.json"):
    path = tmp_path/name
    path.write_text(json.dumps(bundle))
    return path


def test_proofbundle_real_example_verifies_as_signed():
    result = verify_proofbundle(EXAMPLE)
    assert result["ok"] is True and result["trust"] == "signed"
    assert result["public_key_b64"] == "Ts6DJw7AT4alPGqp9JVzh83VvXoMcRXVU0Lb7R2qB08="
    assert result["merkle"] == {"leaf_index": 1, "tree_size": 4,
                                "root_sha256": base64.b64decode("asb7ZKCZKBiZt/SOtrKbWmqEJW++IgVLpUHv14JWNAQ=").hex()}
    payload = base64.b64decode(json.loads(EXAMPLE.read_text())["payload_b64"])
    assert result["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["anchors"] == []
    assert any("SD-JWT" in item for item in result["not_checked"])


def test_proofbundle_tamper_detection(tmp_path):
    good = json.loads(EXAMPLE.read_text())
    def mutate(fn):
        bundle = copy.deepcopy(good)
        fn(bundle)
        return verify_proofbundle(save(tmp_path, bundle))
    payload = base64.b64decode(good["payload_b64"]).replace(b"0.83", b"0.99")
    result = mutate(lambda b: b.update(payload_b64=b64(payload)))
    assert result["ok"] is False and "signature" in result["reason"]
    sig = bytearray(base64.b64decode(good["signature"]["sig_b64"]))
    sig[0] ^= 1
    result = mutate(lambda b: b["signature"].update(sig_b64=b64(bytes(sig))))
    assert result["ok"] is False and "signature" in result["reason"]
    result = mutate(lambda b: b["merkle"].update(root_b64=b64(b"\x01"*32)))
    assert result["ok"] is False and "inclusion" in result["reason"]
    result = mutate(lambda b: b["merkle"].update(leaf_index=0))
    assert result["ok"] is False and "inclusion" in result["reason"]
    result = mutate(lambda b: b["merkle"]["inclusion_proof_b64"].pop())
    assert result["ok"] is False and "inclusion" in result["reason"]
    assert "trust" not in result or result["trust"] is None


@pytest.mark.parametrize("change", [
    lambda b: b.update(schema="proofbundle/v9"),
    lambda b: b.update(extra=1),
    lambda b: b["signature"].update(alg="rsa"),
    lambda b: b["merkle"].update(hash_alg="sha512"),
    lambda b: b["merkle"].pop("hash_alg"),
    lambda b: b["merkle"].update(tree_size=0),
    lambda b: b["signature"].update(public_key_b64="AAAA"),
    lambda b: b.update(payload_b64="not base64!"),
    lambda b: b["signature"].update(sig_b64=b["signature"]["sig_b64"].rstrip("=")),
    lambda b: b["merkle"].update(leaf_index=True),
    lambda b: b.pop("signature"),
    lambda b: b.update(anchors=[{"type": "opentimestamps", "target": "elsewhere"}]),
    lambda b: b.update(anchors={}),
])
def test_proofbundle_rejects_malformed(tmp_path, change):
    bundle = json.loads(EXAMPLE.read_text())
    change(bundle)
    result = verify_proofbundle(save(tmp_path, bundle))
    assert result["ok"] is False and result["reason"]


def test_proofbundle_rejects_bad_files(tmp_path, monkeypatch):
    for text in ['{"schema": "proofbundle/v0.1", "schema": "x"}', "[]", "nope", ""]:
        path = tmp_path/"x.json"
        path.write_text(text)
        assert verify_proofbundle(path)["ok"] is False
    assert verify_proofbundle(tmp_path/"missing.json")["ok"] is False
    from tallylock.adapters import proofbundle as module
    monkeypatch.setattr(module, "MAX_BUNDLE_BYTES", 100)
    assert "exceeds" in verify_proofbundle(EXAMPLE)["reason"]


def test_proofbundle_anchor_in_real_fixture_needs_relying_party_trust():
    result = verify_proofbundle(FORGED)
    assert result["ok"] is True and result["trust"] == "signed"
    (anchor,) = result["anchors"]
    assert anchor["type"] == "opentimestamps" and anchor["target"] == "preRegistration"
    assert anchor["state"] == "needs_relying_party_trust"


def test_proofbundle_confirmed_anchor_gives_anchored(tmp_path):
    prereg = bytes.fromhex("ab"*32)
    anchors = [{"type": "opentimestamps", "target": "preRegistration", "canonicalRoot": b64(prereg),
                "proof": b64(b"proof")}]
    path = save(tmp_path, make_bundle(anchors=anchors))
    assert verify_proofbundle(path)["trust"] == "signed"
    assert verify_proofbundle(path)["anchors"][0]["state"] == "needs_relying_party_trust"
    seen = []
    def confirm(entry, root):
        seen.append((entry["type"], root))
        return True
    result = verify_proofbundle(path, confirm_anchor=confirm)
    assert result["trust"] == "anchored" and result["anchors"][0]["state"] == "confirmed"
    assert seen == [("opentimestamps", prereg)]
    assert verify_proofbundle(path, confirm_anchor=lambda e, r: False)["trust"] == "signed"


def test_proofbundle_receipt_anchor_root_excludes_anchors(tmp_path):
    bundle = make_bundle()
    root = hashlib.sha256(rfc8785.dumps(bundle)).digest()
    bundle["anchors"] = [{"type": "rfc3161-tsa", "target": "receipt", "canonicalRoot": b64(root), "proof": b64(b"x")}]
    result = verify_proofbundle(save(tmp_path, bundle), confirm_anchor=lambda e, r: r == root)
    assert result["trust"] == "anchored"


def test_proofbundle_bad_anchors_never_confirm(tmp_path):
    base = {"type": "opentimestamps", "target": "preRegistration", "canonicalRoot": b64(bytes.fromhex("ab"*32)),
            "proof": b64(b"p")}
    cases = {"root_mismatch": {"canonicalRoot": b64(b"\x00"*32)},
             "unknown_type": {"type": "made-up"},
             "malformed_proof": {"proof": "***"}}
    for state, change in cases.items():
        path = save(tmp_path, make_bundle(anchors=[{**base, **change}]))
        result = verify_proofbundle(path, confirm_anchor=lambda e, r: True)
        assert result["trust"] == "signed" and result["anchors"][0]["state"] == state


def test_proofbundle_does_not_import_proofbundle():
    verify_proofbundle(EXAMPLE)
    assert "proofbundle" not in sys.modules


def worker_ledger(tmp_path, steps):
    import subprocess
    repo = tmp_path/"repo"
    repo.mkdir()
    tool = repo/"tool.py"
    tool.write_text("import sys, json, pathlib\n"
                    "state = pathlib.Path(sys.argv[1])\n"
                    "n = int((state/'n').read_text()) if (state/'n').exists() else 0\n"
                    "(state/'n').write_text(str(n + 1))\n"
                    "step = json.loads((state/'steps.json').read_text())[n]\n"
                    "sys.stdout.write(step['out'])\n"
                    "sys.exit(step.get('exit', 0))\n")
    state = tmp_path/"state"
    state.mkdir()
    (state/"steps.json").write_text(json.dumps(steps))
    head = "a1"*20
    def git(path, args):
        if args == ["rev-parse", "--is-inside-work-tree"]:
            return b"true\n"
        if args == ["rev-parse", "--verify", "HEAD"]:
            return (head + "\n").encode()
        if args[0] == "diff":
            return b""
        raise AssertionError(args)
    plan = ledger.start_plan(repo, [sys.executable, str(tool), str(state)], git=git)
    for _ in steps:
        ledger.run_attempt(plan, anchor=False, stdout=io.BytesIO(), stderr=io.BytesIO())
    return repo, plan


def test_to_intoto_statement_binds_every_attempt_receipt(tmp_path):
    repo, plan = worker_ledger(tmp_path, [{"out": "tallylock: score=1/2\n"},
                                          {"out": "tallylock: score=9/10\n", "exit": 1},
                                          {"out": "tallylock: score=3/4\n"}])
    statement = to_intoto(repo, plan.plan_id)
    assert set(statement) == {"_type", "subject", "predicateType", "predicate"}
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == PREDICATE_TYPE
    checked = ledger.verify_ledger(repo, plan.plan_id)
    assert [s["name"] for s in statement["subject"]] == ["attempt/run-1", "attempt/run-2", "attempt/run-3"]
    assert [s["digest"] for s in statement["subject"]] == [{"sha256": e["receipt_id"]} for e in checked["ledger"]]
    predicate = statement["predicate"]
    assert predicate["plan_id"] == plan.plan_id and predicate["ledger_head_sha256"] == checked["head_sha256"]
    assert predicate["counts"] == {"attempts": 3, "completed": 2, "failed": 1}
    assert [a["outcome"] for a in predicate["attempts"]] == ["completed", "failed", "completed"]
    assert predicate["attempts"][1]["score"] == {"numerator": 9, "denominator": 10}
    assert predicate["attempts"][0]["receipt_sha256"] == checked["ledger"][0]["receipt_id"]
    assert json.loads(json.dumps(statement)) == statement
    assert to_intoto(repo, plan.plan_id) == statement


def test_to_intoto_refuses_tampered_or_unknown_plans(tmp_path):
    repo, plan = worker_ledger(tmp_path, [{"out": "tallylock: score=1/2\n"}])
    with pytest.raises(TallyLockError):
        to_intoto(repo, "0"*64)
    line = (plan.directory/"ledger.jsonl").read_bytes()
    (plan.directory/"ledger.jsonl").write_bytes(line.replace(b'"outcome":"completed"', b'"outcome":"failed"  '))
    with pytest.raises(TallyLockError):
        to_intoto(repo, plan.plan_id)
