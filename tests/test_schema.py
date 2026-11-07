"""Contract shapes and direct bindings, independent of receipt filesystem state."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tallylock import canonical
from tallylock.errors import TallyLockError
from tallylock import merkle


if importlib.util.find_spec("tallylock.schema") is not None:
    from tallylock import schema
else:
    schema = None

ROOT = Path(__file__).resolve().parents[1]
HEX = "ab" * 32


def api():
    assert schema is not None, "versioned contract validation is not implemented"
    return schema


def manifest(trace=False, fixture=False):
    value = json.loads((ROOT / "examples/basic/manifest.json").read_text())
    if trace:
        value["profile"] = "trace-v1"
        value["attempts"][0]["sample_ids"] = ["sample-1"]
    if fixture:
        value["scorer"]["profile"] = "fixture-exact-v1"
        value["dataset"]["sha256"] = HEX
    return value


def result(core=None):
    core = core or manifest()
    return {
        "format": "prove.result.v1",
        "registration_id": canonical.digest(core),
        "attempt_id": "run-1",
        "profile": core["profile"],
        "outcome": "completed",
        "reason": None,
        "inventory": {"Report Résumé.txt": {"sha256": HEX, "bytes": 7,
                                             "media_type": "text/plain", "role": "output"}},
        "records": {"path": "records.jsonl", "sha256": HEX, "bytes": 100,
                    "count": 2, "tree_algorithm": "rfc9162-sha256", "root": HEX},
        "resources": {key: (0 if key == "calls" and core["profile"] == "trace-v1" else None)
                      for key in ("calls", "input_tokens", "output_tokens",
                                  "reasoning_tokens", "cached_tokens", "duration_ms")},
        "score": None,
        "metadata": {},
    }


def event(core=None, kind="attempt_end"):
    core = core or manifest()
    value = {"format": "prove.event.v1", "registration_id": canonical.digest(core),
             "attempt_id": "run-1", "index": 0, "kind": kind}
    value.update({
        "attempt_end": {"outcome": "completed", "reason": None},
        "artifact": {"path": "Report Résumé.txt", "sha256": HEX, "bytes": 7},
        "sample_start": {"sample_id": "sample-1"},
        "sample_end": {"sample_id": "sample-1", "status": "completed"},
        "call": {"sample_id": "sample-1", "call_id": "call-1", "retry_of": None,
                 "source": "external", "status": "succeeded", "input": None,
                 "output": "Report Résumé.txt", "usage": {key: None for key in (
                     "input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")}},
    }[kind])
    return value


def inclusion():
    core = manifest()
    receipt = result(core)
    return {"format": "prove.inclusion.v1", "registration_id": canonical.digest(core),
            "receipt_id": canonical.digest(receipt), "manifest": core, "result": receipt,
            "event": event(core, "artifact"), "index": 0, "size": 2,
            "siblings": [HEX], "proofs": {"manifest": None, "result": None}}


def chain():
    return {"format": "prove.chain.v1", "exported_at": "2026-11-06T00:00:00Z",
            "source": "auditor-controlled export", "tip": {"height": 10, "hash": HEX},
            "node": {"chain": "main", "initialblockdownload": False, "blocks": 10,
                     "headers": 10, "verificationprogress": "0.9999"},
            "blocks": {"10": {"hash": HEX, "header": "00" * 80, "confirmations": 1}}}


def invalid(function, value, *args, code=2):
    with pytest.raises(TallyLockError) as caught:
        function(value, *args)
    assert caught.value.code == code


def test_example_and_generated_defaults_are_valid_without_mutation():
    validator = api()
    value = manifest()
    before = copy.deepcopy(value)
    assert validator.validate_manifest(value) is value
    assert value == before
    first, second = validator.default_manifest(), validator.default_manifest()
    assert first["nonce"] != second["nonce"]
    assert first["name"] == "Evaluation receipt"
    assert first["dataset"]["sha256"] is None
    assert all(item is None for item in first["budget"].values())
    assert validator.validate_manifest(first) is first


@pytest.mark.parametrize("field", list(manifest()))
def test_every_manifest_field_is_required(field):
    value = manifest()
    del value[field]
    invalid(api().validate_manifest, value)


@pytest.mark.parametrize("field,value,code", [
    ("format", "prove.manifest.v2", 4), ("format", None, 2), ("format", 1, 2),
    ("profile", "future", 4), ("profile", None, 2), ("nonce", "AB" * 16, 2),
    ("name", "", 2), ("name", "x" * 201, 2), ("description", "x" * 4001, 2),
    ("extra", True, 2), ("attempts", [], 2),
])
def test_manifest_boundary_fields(field, value, code):
    core = manifest()
    core[field] = value
    invalid(api().validate_manifest, core, code=code)


@pytest.mark.parametrize("change", [
    lambda m: m["attempts"].append(copy.deepcopy(m["attempts"][0])),
    lambda m: m["attempts"][0].update(sample_ids=["sample-1"]),
    lambda m: m["budget"].update(max_calls=True),
    lambda m: m["budget"].update(max_calls=-1),
    lambda m: m["model"].update(extra="untrusted"),
    lambda m: m["harness"]["config"].update(value=1.5),
    lambda m: m["metadata"].update(value=2**53),
    lambda m: m["model"].update(sha256="A" * 64),
    lambda m: m["scorer"].update(profile="fixture-exact-v1"),
])
def test_manifest_rejects_contradictions_and_noncanonical_values(change):
    value = manifest()
    change(value)
    invalid(api().validate_manifest, value)


def test_trace_and_fixture_constraints():
    validator = api()
    assert validator.validate_manifest(manifest(True, True))
    for value in (manifest(True), manifest(True, True)):
        value["attempts"][0]["sample_ids"] = []
        invalid(validator.validate_manifest, value)
    value = manifest(True, True)
    value["dataset"]["sha256"] = None
    invalid(validator.validate_manifest, value)
    value = manifest(True)
    value["attempts"][0]["sample_ids"] *= 2
    invalid(validator.validate_manifest, value)


@pytest.mark.parametrize("path", ["Report Résumé.txt", "A Folder/模型.JSON", "foo..bar", "a/.hidden"])
def test_paths_preserve_supported_names(path):
    assert api().validate_artifact_path(path) == path


def test_wire_path_bound_remains_1024_after_storage_path_refactor():
    path = "/".join(["a" * 255] * 3 + ["b" * 254, "x"])
    assert len(path.encode()) == 1024
    assert api().validate_artifact_path(path) == path
    invalid(api().validate_artifact_path, path + "x")


@pytest.mark.parametrize("path", ["", ".", "..", "a/../b", "a//b", "/a", "a/", "a\\b",
                                      "a\x00b", "a\x7fb", "a\x85b", "a./b", "a /b", "C:foo", "a:b/c",
                                      "Re\u0301sume\u0301.txt", "a" * 256, "😀" * 64,
                                      "/".join(["a" * 255] * 5), None, True])
def test_paths_reject_ambiguous_or_unsupported_names(path):
    invalid(api().validate_artifact_path, path)


@pytest.mark.parametrize("paths", [["A.txt", "a.txt"], ["Straße", "STRASSE"],
                                        ["folder", "FOLDER/a.txt"], ["a", "a/b"],
                                        ["A/x.txt", "a/y.txt"]])
def test_inventory_paths_reject_file_and_casefold_collisions(paths):
    invalid(api().validate_inventory_paths, paths)


def test_results_accept_explicit_unknowns_and_noncompleted_empty_inventory():
    validator = api()
    core = manifest()
    value = result(core)
    assert validator.validate_result(value, core) is value
    value.update(outcome="failed", reason="producer stopped", inventory={})
    value["records"].update(count=1)
    assert validator.validate_result(value, core) is value


@pytest.mark.parametrize("change,code", [
    (lambda r: r.update(registration_id="cd" * 32), 2),
    (lambda r: r.update(attempt_id="run-2"), 2),
    (lambda r: r.update(profile="trace-v1"), 2),
    (lambda r: r.update(profile="future"), 4),
    (lambda r: r.update(reason="unexpected reason"), 2),
    (lambda r: r.update(outcome="failed"), 2),
    (lambda r: r.update(inventory={}), 2),
    (lambda r: r["resources"].update(calls=0), 2),
    (lambda r: r["records"].update(count=True), 2),
    (lambda r: r["records"].update(tree_algorithm="future"), 4),
    (lambda r: r["records"].update(path="elsewhere"), 2),
    (lambda r: r["records"].update(count=0), 2),
    (lambda r: r.update(extra=1), 2),
])
def test_result_bindings_and_explicit_outcomes(change, code):
    core = manifest()
    value = result(core)
    change(value)
    invalid(api().validate_result, value, core, code=code)


def scored_result(core):
    value = result(core)
    value["inventory"]["score.json"] = {"sha256": HEX, "bytes": 12,
                                           "media_type": "application/json", "role": "score"}
    value["score"] = {"path": "score.json", "sha256": HEX, "bytes": 12,
                      "profile": core["scorer"]["profile"],
                      "aggregate": {"numerator": 1, "denominator": 1}}
    if core["profile"] == "artifacts-v1":
        value["records"]["count"] = len(value["inventory"]) + 1
    return value


@pytest.mark.parametrize("field,value", [("path", "missing.json"), ("sha256", "cd" * 32),
                                         ("bytes", 13), ("profile", "fixture-exact-v1"),
                                         ("aggregate", {"numerator": 1, "denominator": 0})])
def test_score_binds_inventory_and_manifest(field, value):
    core = manifest()
    receipt = scored_result(core)
    receipt["score"][field] = value
    invalid(api().validate_result, receipt, core)


def test_fixture_score_is_required_only_for_completed_outcomes():
    core = manifest(True, True)
    value = scored_result(core)
    value["inventory"]["dataset.json"] = {"sha256": HEX, "bytes": 10,
                                               "media_type": "application/json", "role": "dataset"}
    assert api().validate_result(value, core) is value
    value["score"] = None
    invalid(api().validate_result, value, core)
    value.update(outcome="aborted", reason="not enough samples")
    assert api().validate_result(value, core) is value


@pytest.mark.parametrize("kind", ["sample_start", "call", "sample_end", "attempt_end"])
def test_trace_event_shapes(kind):
    core = manifest(True)
    value = event(core, kind)
    assert api().validate_event(value, core, "run-1") is value


@pytest.mark.parametrize("change,code", [
    (lambda e: e.update(registration_id="cd" * 32), 2),
    (lambda e: e.update(attempt_id="run-2"), 2),
    (lambda e: e.update(index=True), 2),
    (lambda e: e.update(sample_id="unregistered"), 2),
    (lambda e: e.update(call_id="BAD"), 2),
    (lambda e: e.update(retry_of="call-1"), 2),
    (lambda e: e.update(input="../escape"), 2),
    (lambda e: e.update(extra=1), 2),
    (lambda e: e["usage"].update(input_tokens=True), 2),
    (lambda e: e.update(kind="future"), 4),
])
def test_event_shape_and_direct_bindings(change, code):
    core = manifest(True)
    value = event(core, "call")
    change(value)
    invalid(api().validate_event, value, core, "run-1", code=code)


def test_profile_event_kinds_and_event_size_limit():
    invalid(api().validate_event, event(manifest(True), "artifact"), manifest(True), "run-1")
    invalid(api().validate_event, event(manifest(), "call"), manifest(), "run-1")
    core = manifest(True)
    value = event(core, "call")
    value["source"] = "x" * (1024 * 1024)
    invalid(api().validate_event, value, core, "run-1")


def test_inclusion_embeds_bound_cores_without_claiming_crypto_membership():
    value = inclusion()
    value["proofs"]["manifest"] = base64.b64encode(b"opaque OTS bytes").decode()
    assert api().validate_inclusion(value) is value


@pytest.mark.parametrize("change,code", [
    (lambda p: p.update(receipt_id="cd" * 32), 2),
    (lambda p: p.update(registration_id="cd" * 32), 2),
    (lambda p: p.update(index=1), 2),
    (lambda p: p.update(size=3), 2),
    (lambda p: p.update(size=0), 2),
    (lambda p: p.update(siblings=["AB" * 32]), 2),
    (lambda p: p["event"].update(bytes=8), 2),
    (lambda p: p["proofs"].update(result="%%%"), 2),
    (lambda p: p["proofs"].update(result="ZE=="), 2),
    (lambda p: p.update(format="prove.inclusion.v2"), 4),
    (lambda p: p.update(extra=1), 2),
])
def test_inclusion_rejects_substitutions_and_malformed_data(change, code):
    value = inclusion()
    change(value)
    invalid(api().validate_inclusion, value, code=code)


def test_chain_shape_does_not_authenticate_header_or_source():
    value = chain()
    assert api().validate_chain(value) is value


@pytest.mark.parametrize("change,code", [
    (lambda c: c.update(format="prove.chain.v2"), 4),
    (lambda c: c.update(format=None), 2),
    (lambda c: c["blocks"].update({"010": c["blocks"].pop("10")}), 2),
    (lambda c: c["blocks"]["10"].update(header="00" * 79), 2),
    (lambda c: c["blocks"]["10"].update(confirmations=2), 2),
    (lambda c: c["tip"].update(height=9), 2),
    (lambda c: c["node"].update(blocks=True), 2),
    (lambda c: c["node"].update(verificationprogress=1), 2),
    (lambda c: c["node"].update(verificationprogress="1e0"), 2),
    (lambda c: c["node"].update(verificationprogress="0.50"), 2),
    (lambda c: c["node"].update(verificationprogress="1.1"), 2),
    (lambda c: c["node"].update(extra=1), 2),
])
def test_chain_cache_rejects_malformed_heights_progress_and_confirmations(change, code):
    value = chain()
    change(value)
    invalid(api().validate_chain, value, code=code)


@pytest.mark.parametrize("change", [
    lambda m: m.update(nonce=m["nonce"] + "\n"),
    lambda m: m["attempts"][0].update(id="run-1\n"),
    lambda m: m["dataset"].update(sha256=HEX + "\n"),
])
def test_pattern_fields_reject_final_newlines(change):
    core = manifest()
    change(core)
    invalid(api().validate_manifest, core)


@pytest.mark.parametrize("field", ["format", "registration_id", "attempt_id", "profile", "outcome",
                                   "reason", "inventory", "records", "resources", "score", "metadata"])
def test_every_result_field_is_required_even_when_nullable(field):
    core = manifest()
    receipt = result(core)
    del receipt[field]
    invalid(api().validate_result, receipt, core)


@pytest.mark.parametrize("field", list(event(manifest(True), "call")))
def test_every_call_field_is_required_even_when_nullable(field):
    core = manifest(True)
    value = event(core, "call")
    del value[field]
    invalid(api().validate_event, value, core, "run-1")


@pytest.mark.parametrize("kind", ["artifact", "sample_start", "sample_end", "attempt_end"])
def test_event_variants_are_closed(kind):
    core = manifest(kind not in ("artifact", "attempt_end"))
    value = event(core, kind)
    value["unrecognized"] = "not metadata"
    invalid(api().validate_event, value, core, "run-1")


def test_inventory_shared_directories_are_allowed_without_case_changes():
    paths = ["Reports/First.TXT", "Reports/Second.TXT", "Reports/子/Third.TXT"]
    assert api().validate_inventory_paths(paths) is None


def test_failing_fixture_can_omit_all_artifacts_and_score():
    core = manifest(True, True)
    receipt = result(core)
    receipt.update(outcome="failed", reason="failed before logging", inventory={}, score=None)
    receipt["records"].update(count=0, bytes=0)
    assert api().validate_result(receipt, core) is receipt


def test_fixture_payloads_are_closed_unique_and_keep_exact_unicode_strings():
    validator = api()
    dataset = {"format": "prove.fixture-dataset.v1", "samples": [
        {"id": "sample-1", "expected": "e\u0301"},
    ]}
    scores = {"format": "prove.fixture-scores.v1", "samples": [
        {"id": "sample-1", "observed": "é"},
    ], "aggregate": {"numerator": 0, "denominator": 1}}
    assert validator.validate_fixture_dataset(dataset) is dataset
    assert validator.validate_fixture_scores(scores) is scores
    for value in (dataset, scores):
        broken = copy.deepcopy(value)
        broken["samples"].append(copy.deepcopy(broken["samples"][0]))
        invalid(validator.validate_fixture_dataset if value is dataset else validator.validate_fixture_scores, broken)
    invalid(validator.validate_fixture_scores, {**scores, "unknown": True})
    invalid(validator.validate_fixture_scores, {**scores, "format": "prove.fixture-scores.v2"}, code=4)
    invalid(validator.validate_fixture_scores, {**scores, "aggregate": {"numerator": 0, "denominator": 2}})
    invalid(validator.validate_fixture_scores, {**scores, "aggregate": {"numerator": 2, "denominator": 1}})
    invalid(validator.validate_fixture_dataset, {"format": "prove.fixture-dataset.v1", "samples": [
        {"id": "sample-1", "expected": "x" * (8 * 1024 * 1024)},
    ]})


@pytest.mark.parametrize("function,value,code", [
    ("validate_fixture_dataset", {"format": "prove.fixture-dataset.v2", "samples": []}, 4),
    ("validate_fixture_scores", {"format": "prove.fixture-scores.v2", "samples": [], "aggregate": {"numerator": 0, "denominator": 1}}, 4),
    ("validate_fixture_dataset", {"samples": []}, 2),
    ("validate_fixture_scores", {"format": 1, "samples": [], "aggregate": {"numerator": 0, "denominator": 1}}, 2),
    ("validate_fixture_dataset", {"format": "prove.fixture-dataset.v1", "samples": []}, 2),
    ("validate_fixture_scores", {"format": "prove.fixture-scores.v1", "samples": [], "aggregate": {"numerator": 0, "denominator": 1}}, 2),
    ("validate_fixture_dataset", {"format": "prove.fixture-dataset.v1", "samples": [{"id": "sample-1", "expected": "x", "extra": True}]}, 2),
    ("validate_fixture_dataset", {"format": "prove.fixture-dataset.v1", "samples": [{"id": "sample-1"}]}, 2),
    ("validate_fixture_scores", {"format": "prove.fixture-scores.v1", "samples": [{"id": "sample-1", "observed": "x"}]}, 2),
    ("validate_fixture_dataset", {"format": "prove.fixture-dataset.v1", "samples": None}, 2),
    ("validate_fixture_scores", {"format": "prove.fixture-scores.v1", "samples": [{"id": "sample-1", "observed": 1}], "aggregate": {"numerator": False, "denominator": 1}}, 2),
])
def test_fixture_payload_discriminators_and_malformed_shapes(function, value, code):
    invalid(getattr(api(), function), value, code=code)


def test_supplied_fixture_score_requires_pinned_dataset_and_complete_aggregate():
    core = manifest(True, True)
    receipt = scored_result(core)
    receipt.update(outcome="failed", reason="failed after scoring")
    invalid(api().validate_result, receipt, core)
    receipt["inventory"]["dataset.json"] = {"sha256": HEX, "bytes": 10,
                                               "media_type": "application/json", "role": "dataset"}
    assert api().validate_result(receipt, core) is receipt
    receipt["score"]["aggregate"] = None
    invalid(api().validate_result, receipt, core)


def test_metadata_is_arbitrary_canonical_data_and_does_not_override_bindings():
    core = manifest()
    core["metadata"] = {"registration_id": "untrusted", "nested": {"value": [None, True, -1]}}
    assert api().validate_manifest(core) is core
    receipt = result(core)
    receipt["registration_id"] = "cd" * 32
    invalid(api().validate_result, receipt, core)


def test_static_packaged_schema_is_closed_at_root_and_uses_only_local_refs():
    from jsonschema import Draft202012Validator

    api()
    resource = ROOT / "src/tallylock/data/schemas/protocol-v1.json"
    document = json.loads(resource.read_text())
    Draft202012Validator.check_schema(document)
    validator = Draft202012Validator(document)
    validator.validate(manifest())
    assert not validator.is_valid({"format": "prove.manifest.v1", "producer_schema": "https://invalid/"})
    for change in (
        lambda m: m.update(nonce=m["nonce"] + "\n"),
        lambda m: m["attempts"][0].update(id="run-1\n"),
        lambda m: m["dataset"].update(sha256=HEX + "\n"),
    ):
        core = manifest()
        change(core)
        assert not validator.is_valid(core)

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref":
                    assert item.startswith("#/$defs/")
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)


def test_frozen_positive_contract_fixtures():
    directory = ROOT / "tests/fixtures/contracts"
    core = json.loads((directory / "trace-manifest.json").read_text())
    assert api().validate_manifest(core) is core
    cache = json.loads((directory / "chain.json").read_text())
    assert api().validate_chain(cache) is cache
    paths = json.loads((directory / "artifact-paths.json").read_text())
    assert api().validate_inventory_paths(paths) is None


def test_trace_call_count_is_known_even_when_other_usage_is_unknown():
    core = manifest(True)
    receipt = result(core)
    receipt["resources"]["calls"] = None
    invalid(api().validate_result, receipt, core)


@pytest.mark.parametrize("value", [None, [], True, "producer-controlled", 7])
def test_contract_roots_are_objects(value):
    validator = api()
    core = manifest()
    invalid(validator.validate_manifest, value)
    invalid(validator.validate_result, value, core)
    invalid(validator.validate_event, value, core, "run-1")
    invalid(validator.validate_inclusion, value)
    invalid(validator.validate_chain, value)


def test_inclusion_checks_terminal_outcome_and_call_artifact_references():
    value = inclusion()
    value["event"] = event(value["manifest"])
    value["event"].update(index=1, outcome="aborted", reason="stopped")
    value["index"] = 1
    invalid(api().validate_inclusion, value)
    core = manifest(True)
    receipt = result(core)
    value.update(manifest=core, result=receipt, registration_id=canonical.digest(core),
                 receipt_id=canonical.digest(receipt), event=event(core, "call"), index=0)
    value["event"]["input"] = "missing.txt"
    invalid(api().validate_inclusion, value)


def test_score_role_must_be_unique_and_copied_from_the_same_entry():
    core = manifest()
    receipt = scored_result(core)
    assert api().validate_result(receipt, core) is receipt
    receipt["inventory"]["extra-score.json"] = copy.deepcopy(receipt["inventory"]["score.json"])
    receipt["records"]["count"] = len(receipt["inventory"]) + 1
    invalid(api().validate_result, receipt, core)


def test_canonical_limits_apply_inside_non_normative_metadata():
    core = manifest()
    nested = {}
    core["metadata"] = nested
    for _ in range(64):
        nested["nested"] = {}
        nested = nested["nested"]
    invalid(api().validate_manifest, core)
    core["metadata"] = {"oversize": "x" * (8 * 1024 * 1024)}
    invalid(api().validate_manifest, core)


@pytest.mark.parametrize("change", [
    lambda c: c["node"].update(verificationprogress="0.9999\n"),
    lambda c: c["blocks"]["10"].update(header="00" * 80 + "\n"),
    lambda c: c["blocks"].update({"10\n": c["blocks"].pop("10")}),
])
def test_chain_pattern_fields_reject_final_newlines(change):
    value = chain()
    change(value)
    invalid(api().validate_chain, value)


def committed_inclusion(core, receipt, events, selected):
    leaves = [canonical.dumps(item) for item in events]
    raw_records = b"".join(leaf + b"\n" for leaf in leaves)
    receipt["records"].update(root=merkle.root(leaves), count=len(leaves),
                              sha256=hashlib.sha256(raw_records).hexdigest(), bytes=len(raw_records))
    value = {"format": "prove.inclusion.v1", "registration_id": canonical.digest(core),
             "receipt_id": canonical.digest(receipt), "manifest": core, "result": receipt,
             "event": events[selected], "index": selected, "size": len(leaves),
             "siblings": merkle.proof(leaves, selected), "proofs": {"manifest": None, "result": None}}
    assert merkle.verify(leaves[selected], selected, len(leaves), value["siblings"], receipt["records"]["root"])
    return value


def test_included_terminal_must_be_final_even_with_valid_merkle_membership():
    core = manifest()
    terminal = event(core)
    artifact = event(core, "artifact")
    artifact["index"] = 1
    value = committed_inclusion(core, result(core), [terminal, artifact], 0)
    invalid(api().validate_inclusion, value)


def test_included_final_terminal_accepts_valid_merkle_membership():
    core = manifest()
    terminal = event(core)
    terminal["index"] = 1
    value = committed_inclusion(core, result(core), [event(core, "artifact"), terminal], 1)
    assert api().validate_inclusion(value) is value


@pytest.mark.parametrize("embedded", ["manifest", "result", "event"])
@pytest.mark.parametrize("bad_format", [None, 1, True, ["prove.manifest.v1"]])
def test_embedded_malformed_format_precedes_unsupported_discriminators(embedded, bad_format):
    value = inclusion()
    value[embedded]["format"] = bad_format
    if embedded == "event":
        value[embedded]["kind"] = "future"
    else:
        value[embedded]["profile"] = "future"
    invalid(api().validate_inclusion, value)


@pytest.mark.parametrize("embedded", ["manifest", "result", "event"])
def test_missing_embedded_format_is_malformed_before_unknown_profile(embedded):
    value = inclusion()
    del value[embedded]["format"]
    if embedded == "event":
        value[embedded]["kind"] = "future"
    else:
        value[embedded]["profile"] = "future"
    invalid(api().validate_inclusion, value)


@pytest.mark.parametrize("embedded", ["manifest", "result", "event"])
def test_genuinely_future_embedded_formats_remain_unsupported(embedded):
    value = inclusion()
    value[embedded]["format"] = f"prove.{embedded}.v2"
    invalid(api().validate_inclusion, value, code=4)


@pytest.mark.parametrize("empty", [False, True])
def test_artifact_record_count_includes_one_terminal_per_inventory(empty):
    core = manifest()
    receipt = result(core)
    if empty:
        receipt.update(outcome="failed", reason="no source artifacts", inventory={})
    receipt["records"]["count"] = len(receipt["inventory"]) + 1
    assert api().validate_result(receipt, core) is receipt
    receipt["records"]["count"] += 1
    invalid(api().validate_result, receipt, core)
    receipt["records"]["count"] = 0
    invalid(api().validate_result, receipt, core)


@pytest.mark.parametrize("correct_order", [False, True])
def test_included_artifact_index_is_utf8_sorted_inventory_rank(correct_order):
    core = manifest()
    receipt = result(core)
    entry = next(iter(receipt["inventory"].values()))
    receipt["inventory"] = {name: copy.deepcopy(entry) for name in ["模型.JSON", "A.txt", "z.txt"]}
    paths = sorted(receipt["inventory"], key=lambda path: path.encode("utf-8"))
    if not correct_order:
        paths[0], paths[1] = paths[1], paths[0]
    events = []
    for index, path in enumerate(paths):
        item = event(core, "artifact")
        item.update(index=index, path=path)
        events.append(item)
    terminal = event(core)
    terminal["index"] = len(events)
    events.append(terminal)
    value = committed_inclusion(core, receipt, events, 0)
    if correct_order:
        assert api().validate_inclusion(value) is value
    else:
        invalid(api().validate_inclusion, value)


@pytest.mark.parametrize("aggregate", [{"numerator": 1, "denominator": 2},
                                        {"numerator": 2, "denominator": 1}])
def test_fixture_aggregate_counts_must_match_declared_samples(aggregate):
    core = manifest(True, True)
    receipt = scored_result(core)
    receipt["inventory"]["dataset.json"] = {"sha256": HEX, "bytes": 10,
                                               "media_type": "application/json", "role": "dataset"}
    receipt["score"]["aggregate"] = aggregate
    invalid(api().validate_result, receipt, core)


def test_recorded_only_aggregate_can_exceed_one():
    core = manifest()
    receipt = scored_result(core)
    receipt["score"]["aggregate"] = {"numerator": 20, "denominator": 3}
    assert api().validate_result(receipt, core) is receipt


def test_declared_weight_digest_evidence_requires_a_digest_without_authenticating_execution():
    core = manifest()
    core["model"]["evidence"] = "weight_digest_recorded"
    invalid(api().validate_manifest, core)
    core["model"]["sha256"] = HEX
    assert api().validate_manifest(core) is core


def test_prepared_event_validator_snapshots_manifest_and_validates_inventory_once():
    core = manifest(True)
    inventory = {"Report Résumé.txt": {"sha256": HEX, "bytes": 7,
                                        "media_type": "text/plain", "role": "output"}}
    assert api().validate_inventory(inventory) is inventory
    prepared = api().EventValidator(core, "run-1")
    core["attempts"][0]["sample_ids"] = ["other-sample"]
    value = event(manifest(True), "sample_start")
    assert prepared.validate(value) is value


def test_one_shot_event_validation_keeps_event_shape_error_precedence():
    core = manifest(True)
    core["profile"] = "future"
    value = event(manifest(True), "call")
    value["kind"] = "future"
    invalid(api().validate_event, value, core, "run-1", code=4)
