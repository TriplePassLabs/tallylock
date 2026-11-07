import copy
import hashlib

import pytest

from tallylock import fixture, scoring
from tallylock.errors import TallyLockError


def checked():
    value = fixture.example()
    result = {
        "format": "prove.result.v1", "registration_id": "0" * 64,
    }
    # The fixture is deliberately data-only; build the seal-shaped result here.
    from tallylock import canonical, merkle, records
    events = value.events
    data = records.encode(events)
    result = {
        "format": "prove.result.v1", "registration_id": canonical.digest(value.manifest),
        "attempt_id": "run-1", "profile": "trace-v1", "outcome": "completed", "reason": None,
        "inventory": {path: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                              "media_type": "application/json", "role": value.roles[path]}
                      for path, raw in value.artifacts.items()},
        "records": {"path": "records.jsonl", "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data), "count": len(events), "tree_algorithm": "rfc9162-sha256",
                    "root": merkle.root([canonical.dumps(event) for event in events])},
        "resources": {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                      "reasoning_tokens": 0, "cached_tokens": 0, "duration_ms": 0},
        "score": {"path": value.score_path, "sha256": hashlib.sha256(value.artifacts[value.score_path]).hexdigest(),
                  "bytes": len(value.artifacts[value.score_path]), "profile": "fixture-exact-v1",
                  "aggregate": copy.deepcopy(value.aggregate)}, "metadata": {},
    }
    return value, result


def reader(artifacts, reads):
    def read(path, limit):
        reads.append((path, limit))
        return artifacts[path]
    return read


def test_fixture_score_recomputes_exact_bytes_and_aggregate():
    value, result = checked()
    reads = []
    checked_score = scoring.check(value.manifest, result, reader(value.artifacts, reads))
    assert checked_score["state"] == "recomputed"
    assert checked_score["aggregate"] == {"numerator": 1, "denominator": 2}
    assert checked_score["recomputed"] == {"numerator": 1, "denominator": 2}
    assert [path for path, _ in reads] == ["dataset.json", "scores.json"]


def test_fixture_score_selects_utf8_first_matching_pinned_dataset_entry():
    value, result = checked()
    value.artifacts["0-dataset.json"] = value.artifacts["dataset.json"]
    result["inventory"]["0-dataset.json"] = copy.deepcopy(result["inventory"]["dataset.json"])
    reads = []
    assert scoring.check(value.manifest, result, reader(value.artifacts, reads))["state"] == "recomputed"
    assert [path for path, _ in reads] == ["0-dataset.json", "scores.json"]


def rebind_score(result, artifacts):
    digest = hashlib.sha256(artifacts["scores.json"]).hexdigest()
    size = len(artifacts["scores.json"])
    result["inventory"]["scores.json"].update(sha256=digest, bytes=size)
    result["score"].update(sha256=digest, bytes=size)


def test_fixture_score_rejects_honestly_rehashed_mathematically_wrong_score():
    value, result = checked()
    artifacts = copy.deepcopy(value.artifacts)
    artifacts["scores.json"] = artifacts["scores.json"].replace(b'"blue"', b'"green"')
    rebind_score(result, artifacts)
    from tallylock import schema
    assert schema.validate_result(result, value.manifest) is result
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(artifacts, []))


def test_fixture_score_rejects_actual_bytes_that_do_not_match_rebound_hash_fields():
    value, result = checked()
    result["inventory"]["scores.json"]["sha256"] = "f" * 64
    result["score"]["sha256"] = "f" * 64
    from tallylock import schema
    assert schema.validate_result(result, value.manifest) is result
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(value.artifacts, []))


@pytest.mark.parametrize("path,update", [
    ("scores.json", {"aggregate": {"numerator": 0, "denominator": 2}}),
    ("result", {"aggregate": {"numerator": 0, "denominator": 2}}),
])
def test_fixture_score_checks_score_and_result_aggregates(path, update):
    value, result = checked()
    if path == "scores.json":
        import json
        payload = json.loads(value.artifacts[path])
        payload.update(update)
        value.artifacts[path] = json.dumps(payload).encode()
        rebind_score(result, value.artifacts)
    else:
        result["score"].update(update)
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(value.artifacts, []))


@pytest.mark.parametrize("sample_ids,aggregate", [
    (["sample-1"], {"numerator": 0, "denominator": 1}),
    (["sample-1", "sample-1"], {"numerator": 0, "denominator": 2}),
    (["sample-1", "sample-2", "sample-3"], {"numerator": 1, "denominator": 3}),
])
def test_fixture_score_rejects_missing_duplicate_or_extra_selected_ids(sample_ids, aggregate):
    value, result = checked()
    from tallylock import canonical
    payload = canonical.loads(value.artifacts["scores.json"])
    payload["samples"] = [{"id": sample_id, "observed": "red"} for sample_id in sample_ids]
    payload["aggregate"] = aggregate
    value.artifacts["scores.json"] = canonical.dumps(payload)
    rebind_score(result, value.artifacts)
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(value.artifacts, []))


def test_fixture_score_accepts_shuffled_samples_but_not_unicode_or_case_changes():
    value, result = checked()
    from tallylock import canonical
    payload = canonical.loads(value.artifacts["scores.json"])
    payload["samples"].reverse()
    value.artifacts["scores.json"] = canonical.dumps(payload)
    rebind_score(result, value.artifacts)
    assert scoring.check(value.manifest, result, reader(value.artifacts, []))["state"] == "recomputed"
    payload["samples"][1]["observed"] = "BLUE"
    value.artifacts["scores.json"] = canonical.dumps(payload)
    rebind_score(result, value.artifacts)
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(value.artifacts, []))


def test_fixture_score_rejects_raw_artifact_over_8mib():
    value, result = checked()
    value.artifacts["scores.json"] = b"x" * (scoring.MAX_FIXTURE_BYTES + 1)
    rebind_score(result, value.artifacts)
    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, reader(value.artifacts, []))


def test_null_score_is_unavailable_without_artifact_reads():
    value, result = checked()
    result["outcome"] = "failed"
    result["reason"] = "before scoring"
    result["score"] = None
    result["inventory"] = {}
    result["records"].update(bytes=0, count=0)
    reads = []
    evidence = scoring.check(value.manifest, result, reader(value.artifacts, reads))
    assert evidence["state"] == "unavailable" and evidence["aggregate"] is None
    assert reads == []


def test_recorded_only_never_parses_arbitrary_score_bytes():
    value, result = checked()
    value.manifest["scorer"] = {"profile": "recorded-only-v1", "revision": "opaque"}
    from tallylock import canonical
    result["registration_id"] = canonical.digest(value.manifest)
    result["score"]["profile"] = "recorded-only-v1"
    value.artifacts["scores.json"] = b"not json at all"
    digest = hashlib.sha256(value.artifacts["scores.json"]).hexdigest()
    result["score"].update(sha256=digest, bytes=len(value.artifacts["scores.json"]))
    result["inventory"]["scores.json"].update(sha256=digest, bytes=len(value.artifacts["scores.json"]))
    reads = []
    evidence = scoring.check(value.manifest, result, reader(value.artifacts, reads))
    assert evidence["state"] == "recorded_only" and evidence["recomputed"] is None
    assert reads == []
    evidence["aggregate"]["numerator"] = 0
    assert result["score"]["aggregate"]["numerator"] == 1
