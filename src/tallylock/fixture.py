"""Pure conformance data for the built-in deterministic fixture scorer."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import canonical, schema


@dataclass(frozen=True)
class Fixture:
    manifest: dict
    artifacts: dict[str, bytes]
    events: list[dict]
    roles: dict[str, str]
    score_path: str
    aggregate: dict


def example() -> Fixture:
    """Return fresh no-model data that exercises exact fixture-score bindings."""
    dataset = {"format": "prove.fixture-dataset.v1", "samples": [
        {"id": "sample-1", "expected": "blue"},
        {"id": "sample-2", "expected": "green"},
    ]}
    scores = {"format": "prove.fixture-scores.v1", "samples": [
        {"id": "sample-1", "observed": "blue"},
        {"id": "sample-2", "observed": "red"},
    ], "aggregate": {"numerator": 1, "denominator": 2}}
    dataset_data, scores_data = canonical.dumps(dataset), canonical.dumps(scores)
    manifest = schema.default_manifest("Deterministic fixture")
    manifest.update(profile="trace-v1", description="Local no-model conformance fixture.")
    manifest["attempts"] = [{"id": "run-1", "sample_ids": ["sample-1", "sample-2"]}]
    manifest["dataset"] = {"name": "fixture dataset", "sha256": hashlib.sha256(dataset_data).hexdigest()}
    manifest["model"] = {"id": "local-no-model-fixture", "evidence": "self_declared", "sha256": None}
    manifest["harness"] = {"name": "local no-model fixture", "revision": "fixture-v1", "config": {}}
    manifest["scorer"] = {"profile": "fixture-exact-v1", "revision": "fixture-exact-v1"}
    manifest["budget"] = {"max_calls": 0, "max_input_tokens": 0, "max_output_tokens": 0}
    schema.validate_manifest(manifest)
    registration_id = canonical.digest(manifest)
    events = []
    for sample_id in manifest["attempts"][0]["sample_ids"]:
        events.extend([
            {"format": "prove.event.v1", "registration_id": registration_id, "attempt_id": "run-1",
             "index": len(events), "kind": "sample_start", "sample_id": sample_id},
            {"format": "prove.event.v1", "registration_id": registration_id, "attempt_id": "run-1",
             "index": len(events) + 1, "kind": "sample_end", "sample_id": sample_id, "status": "completed"},
        ])
    events.append({"format": "prove.event.v1", "registration_id": registration_id, "attempt_id": "run-1",
                   "index": len(events), "kind": "attempt_end", "outcome": "completed", "reason": None})
    return Fixture(manifest, {"dataset.json": dataset_data, "scores.json": scores_data}, events,
                   {"dataset.json": "dataset", "scores.json": "score"}, "scores.json",
                   {"numerator": 1, "denominator": 2})
