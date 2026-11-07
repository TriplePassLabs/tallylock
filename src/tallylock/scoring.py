"""Read-only score evidence checks for the reviewed built-in profiles."""

from __future__ import annotations

from copy import deepcopy
import hashlib

from . import canonical, schema
from .errors import TallyLockError


MAX_FIXTURE_BYTES = 8 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TallyLockError(message)


def _read(read_artifact, path: str, entry: dict) -> bytes:
    data = read_artifact(path, MAX_FIXTURE_BYTES)
    _require(isinstance(data, bytes), "artifact reader must return bytes")
    _require(len(data) <= MAX_FIXTURE_BYTES, "fixture artifact exceeds 8 MiB")
    _require(len(data) == entry["bytes"], "artifact byte length differs from inventory")
    _require(hashlib.sha256(data).hexdigest() == entry["sha256"], "artifact digest differs from inventory")
    return data


def _payload(data: bytes, validator, kind: str) -> dict:
    value = canonical.loads(data)
    _require(isinstance(value, dict), f"{kind} must be an object")
    return validator(value)


def check(manifest: dict, result: dict, read_artifact) -> dict:
    """Return declared or recomputed score evidence without executing producer code."""
    schema.validate_manifest(manifest)
    schema.validate_result(result, manifest)
    score = result["score"]
    profile = manifest["scorer"]["profile"]
    limitations = ["Producer-supplied labels and observations remain unverified.",
                   "Execution and output provenance remain unverified."]
    if score is None:
        return {"state": "unavailable", "profile": profile, "aggregate": None, "recomputed": None,
                "limitations": limitations}
    if profile == "recorded-only-v1":
        return {"state": "recorded_only", "profile": profile, "aggregate": deepcopy(score["aggregate"]), "recomputed": None,
                "limitations": limitations}

    score_entry = result["inventory"][score["path"]]
    dataset_entries = [(path, entry) for path, entry in result["inventory"].items()
                       if entry["role"] == "dataset" and entry["sha256"] == manifest["dataset"]["sha256"]]
    _require(dataset_entries, "fixture score requires a matching pinned dataset artifact")
    dataset_path, dataset_entry = min(dataset_entries, key=lambda item: item[0].encode("utf-8"))
    _require(score_entry["sha256"] == score["sha256"] and score_entry["bytes"] == score["bytes"],
             "score binding differs from inventory")
    artifacts = {dataset_path: dataset_entry, score["path"]: score_entry}
    loaded = {path: _read(read_artifact, path, entry) for path, entry in
              sorted(artifacts.items(), key=lambda item: item[0].encode("utf-8"))}
    dataset = _payload(loaded[dataset_path], schema.validate_fixture_dataset, "fixture dataset")
    scores = _payload(loaded[score["path"]], schema.validate_fixture_scores, "fixture scores")
    expected = {item["id"]: item["expected"] for item in dataset["samples"]}
    observed = {item["id"]: item["observed"] for item in scores["samples"]}
    selected = next(item["sample_ids"] for item in manifest["attempts"] if item["id"] == result["attempt_id"])
    _require(set(expected) == set(selected), "dataset samples differ from selected attempt")
    _require(set(observed) == set(selected), "score samples differ from selected attempt")
    aggregate = {"numerator": sum(expected[item] == observed[item] for item in selected),
                 "denominator": len(selected)}
    _require(scores["aggregate"] == aggregate, "score artifact aggregate differs from recomputation")
    _require(score["aggregate"] == aggregate, "declared score aggregate differs from recomputation")
    return {"state": "recomputed", "profile": profile, "aggregate": deepcopy(score["aggregate"]), "recomputed": aggregate,
            "limitations": limitations}
