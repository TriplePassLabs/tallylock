"""Main-owned semantic probes, with all changed commitments honestly rebound."""

import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tallylock import canonical, merkle, verify


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "src/tallylock/data/conformance/cases"


def reference():
    spec = importlib.util.spec_from_file_location("main_reference_probe", ROOT / "tools/reference_verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loaded(name="run-fixture-exact.json"):
    case = json.loads((CORPUS / name).read_bytes())
    manifest = json.loads(base64.b64decode(case["manifest"]))
    result = json.loads(base64.b64decode(case["result"]))
    events = [json.loads(line) for line in base64.b64decode(case["records"]).splitlines()]
    artifacts = {path: base64.b64decode(raw) for path, raw in case["artifacts"].items()}
    return case, manifest, result, events, artifacts


def rebound(case, manifest, result, events, artifacts):
    """Production calls here only bind test inputs, never implement the reference."""
    manifest_raw = canonical.dumps(manifest)
    registration = hashlib.sha256(manifest_raw).hexdigest()
    result["registration_id"] = registration
    for index, event in enumerate(events):
        event.update(index=index, registration_id=registration)
    lines = [canonical.dumps(event) for event in events]
    raw = b"".join(line + b"\n" for line in lines)
    result["records"].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                              count=len(lines), root=merkle.root(lines))
    for path, entry in result["inventory"].items():
        data = artifacts[path]
        entry.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    if result["score"] is not None:
        entry = result["inventory"][result["score"]["path"]]
        result["score"].update(sha256=entry["sha256"], bytes=entry["bytes"])
    case.update(manifest=base64.b64encode(manifest_raw).decode(),
                result=base64.b64encode(canonical.dumps(result)).decode(),
                records=base64.b64encode(raw).decode(),
                artifacts={path: base64.b64encode(data).decode() for path, data in artifacts.items()})
    return case


def production(case, path):
    path.mkdir()
    for field, filename in (("manifest", "manifest.json"), ("result", "result.json"), ("records", "records.jsonl")):
        (path / filename).write_bytes(base64.b64decode(case[field]))
    for filename, encoded in case["artifacts"].items():
        target = path / "artifacts" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(encoded))
    return verify.full(path, policy="integrity-only")


@pytest.mark.parametrize("change,expected", [
    ("completed_reason", 2), ("second_score_role", 2), ("future_dataset", 4),
    ("future_scores", 4), ("future_score_profile", 4), ("future_event_kind", 4),
])
def test_reference_rejects_direct_semantics_and_versions(tmp_path, change, expected):
    case, manifest, result, events, artifacts = loaded()
    if change == "completed_reason":
        result["reason"] = "completed must have null reason"
        events[-1]["reason"] = result["reason"]
    elif change == "second_score_role":
        score_path = result["score"]["path"]
        artifacts["second-score.json"] = artifacts[score_path]
        result["inventory"]["second-score.json"] = deepcopy(result["inventory"][score_path])
    elif change in ("future_dataset", "future_scores"):
        filename = "dataset.json" if change == "future_dataset" else result["score"]["path"]
        payload = json.loads(artifacts[filename])
        payload["format"] = payload["format"].removesuffix("v1") + "v2"
        artifacts[filename] = canonical.dumps(payload)
        if change == "future_dataset":
            manifest["dataset"]["sha256"] = hashlib.sha256(artifacts[filename]).hexdigest()
    elif change == "future_score_profile":
        result["score"]["profile"] = "future-score-profile-v9"
    elif change == "future_event_kind":
        events[0]["kind"] = "future_event"
    case = rebound(case, manifest, result, events, artifacts)
    product = production(case, tmp_path / "receipt")
    assert product.code == expected, product.report
    answer = reference().verify_case(case)
    assert answer["code"] == expected, answer


def test_reference_inclusion_requires_score_pinned_dataset_binding():
    case, manifest, result, events, artifacts = loaded()
    del result["inventory"]["dataset.json"]
    del artifacts["dataset.json"]
    rebound(case, manifest, result, events, artifacts)
    leaves = [canonical.dumps(event) for event in events]
    inclusion = {"format": "prove.inclusion.v1", "registration_id": canonical.digest(manifest),
                 "receipt_id": canonical.digest(result), "manifest": manifest, "result": result,
                 "event": events[-1], "index": len(events) - 1, "size": len(events),
                 "siblings": merkle.proof(leaves, len(events) - 1),
                 "proofs": {"manifest": None, "result": None}}
    assert merkle.verify(leaves[-1], inclusion["index"], len(events), inclusion["siblings"], result["records"]["root"])
    assert verify.inclusion(inclusion, policy="integrity-only").code == 2
    answer = reference().verify_case({"format": "prove.conformance-case.v1", "kind": "inclusion",
                                      "inclusion": inclusion})
    assert answer["code"] == 2, answer


def test_reference_huge_integer_literal_returns_invalid_report():
    case, _, _, _, _ = loaded()
    case["manifest"] = base64.b64encode(b'{"huge":' + b"1" * 5000 + b"}").decode()
    answer = reference().verify_case(case)
    assert answer["code"] == 2


def test_reference_known_subtotal_overflow_not_hidden_by_null(tmp_path):
    case, manifest, result, events, artifacts = loaded("run-budget-unknown-total.json")
    calls = [event for event in events if event["kind"] == "call"]
    assert len(calls) >= 2
    extra = deepcopy(calls[0])
    extra["call_id"] = "extra-overflow-call"
    extra["retry_of"] = None
    first = events.index(calls[0])
    events.insert(first + 1, extra)
    calls = [event for event in events if event["kind"] == "call"]
    calls[0]["usage"]["input_tokens"] = canonical.MAX_SAFE_INTEGER
    calls[1]["usage"]["input_tokens"] = canonical.MAX_SAFE_INTEGER
    calls[-1]["usage"]["input_tokens"] = None
    manifest["budget"] = {name: None for name in manifest["budget"]}
    result["resources"] = {"calls": len(calls)}
    for key in calls[0]["usage"]:
        values = [event["usage"][key] for event in calls]
        result["resources"][key] = None if None in values else sum(values)
    case = rebound(case, manifest, result, events, artifacts)
    assert production(case, tmp_path / "receipt").code == 2
    answer = reference().verify_case(case)
    assert answer["code"] == 2, answer
