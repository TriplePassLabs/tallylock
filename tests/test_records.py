"""Normalized-record encoding and generic lifecycle checks."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tallylock import canonical, merkle, records
from tallylock.errors import TallyLockError


ROOT = Path(__file__).resolve().parents[1]
HEX = "ab" * 32
USAGE = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")


def manifest(trace=False):
    value = json.loads((ROOT / "examples/basic/manifest.json").read_text())
    if trace:
        value["profile"] = "trace-v1"
        value["attempts"][0]["sample_ids"] = ["sample-1"]
    return value


def inventory():
    return {"z.txt": {"sha256": HEX, "bytes": 7, "media_type": "text/plain", "role": "output"},
            "A.txt": {"sha256": "cd" * 32, "bytes": 3, "media_type": "text/plain", "role": "input"}}


def event(core, kind, index, **extra):
    value = {"format": "prove.event.v1", "registration_id": canonical.digest(core),
             "attempt_id": "run-1", "index": index, "kind": kind}
    values = {
        "sample_start": {"sample_id": "sample-1"},
        "sample_end": {"sample_id": "sample-1", "status": "completed"},
        "call": {"sample_id": "sample-1", "call_id": "call-1", "retry_of": None,
                 "source": "recorded", "status": "succeeded", "input": "A.txt", "output": "z.txt",
                 "usage": {name: 1 for name in USAGE}},
        "attempt_end": {"outcome": "completed", "reason": None},
    }
    value.update(values[kind])
    value.update(extra)
    return value


def result(core, event_set, outcome="completed", reason=None):
    data = records.encode(event_set)
    return {"format": "prove.result.v1", "registration_id": canonical.digest(core), "attempt_id": "run-1",
            "profile": core["profile"], "outcome": outcome, "reason": reason, "inventory": inventory(),
            "records": {"path": "records.jsonl", "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data), "count": len(event_set), "tree_algorithm": "rfc9162-sha256",
                        "root": merkle.root([canonical.dumps(item) for item in event_set])},
            "resources": {"calls": 1, **{name: 1 for name in USAGE}}, "score": None, "metadata": {}}


def invalid(callable_, *args):
    with pytest.raises(TallyLockError):
        callable_(*args)


def test_encode_decode_are_exact_canonical_records():
    core = manifest(True)
    events = [event(core, "sample_start", 0), event(core, "attempt_end", 1, outcome="failed", reason="stopped")]
    data = records.encode(events)
    assert data == b"".join(canonical.dumps(item) + b"\n" for item in events)
    assert records.decode(data) == events
    unordered = b'{"kind":"attempt_end","index":0,"attempt_id":"run-1","registration_id":"' + canonical.digest(core).encode() + b'","format":"prove.event.v1","outcome":"failed","reason":"stopped"}\n'
    invalid(records.decode, unordered)
    assert records.decode(unordered, require_canonical=False)[0]["kind"] == "attempt_end"


@pytest.mark.parametrize("data", [b'\xef\xbb\xbf{}\n', b'{}\r\n', b'\n', b'{}', b'{"x":1,"x":2}\n', b'\xff\n'])
def test_decode_rejects_malformed_or_ambiguous_jsonl(data):
    invalid(records.decode, data)


def test_artifacts_builds_utf8_sorted_inventory_events_and_terminal():
    core = manifest()
    built = records.build(core, "run-1", inventory(), "completed", None)
    assert [item["kind"] for item in built.events] == ["artifact", "artifact", "attempt_end"]
    assert [item.get("path") for item in built.events[:-1]] == ["A.txt", "z.txt"]
    assert built.metadata["count"] == 3
    assert built.resources == {"calls": None, **{name: None for name in USAGE}}
    assert built.coverage == {"state": "not_applicable", "expected": None, "started": None, "ended": None}
    with pytest.raises(TallyLockError):
        records.build(core, "run-1", {}, "completed", None)
    core["budget"]["max_calls"] = 1
    assert records.build(core, "run-1", inventory(), "completed", None).budget == "unknown"


def test_trace_lifecycle_and_resource_totals_are_checked_against_result():
    core = manifest(True)
    events = [event(core, "sample_start", 0), event(core, "call", 1),
              event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    data = records.encode(events)
    checked = records.check(core, result(core, events), data)
    assert checked.resources == {"calls": 1, **{name: 1 for name in USAGE}}
    assert checked.coverage == {"state": "complete", "expected": 1, "started": 1, "ended": 1}
    bad = copy.deepcopy(result(core, events))
    bad["resources"]["output_tokens"] = 2
    invalid(records.check, core, bad, data)


@pytest.mark.parametrize("mutate", [
    lambda items: items.__setitem__(1, event(manifest(True), "call", 1, retry_of="missing")),
    lambda items: items.__setitem__(2, event(manifest(True), "sample_end", 3)),
    lambda items: items.__setitem__(3, event(manifest(True), "attempt_end", 3, outcome="failed", reason="different")),
])
def test_trace_rejects_retry_index_and_terminal_contradictions(mutate):
    core = manifest(True)
    events = [event(core, "sample_start", 0), event(core, "call", 1),
              event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    mutate(events)
    data = records.encode(events)
    invalid(records.check, core, result(core, events), data)


def test_noncompleted_empty_trace_is_explicit_but_completed_empty_trace_is_not():
    core = manifest(True)
    built = records.build(core, "run-1", inventory(), "failed", "before logging", events=[])
    assert built.events == ()
    assert built.coverage["state"] == "incomplete"
    with pytest.raises(TallyLockError):
        records.build(core, "run-1", inventory(), "completed", None, events=[])


@pytest.mark.parametrize("field,value", [
    ("sha256", "00" * 32), ("bytes", 1), ("count", 3), ("root", "00" * 32),
    ("path", "other.jsonl"), ("tree_algorithm", "other-tree"),
])
def test_check_rejects_each_tampered_records_metadata_field(field, value):
    core = manifest(True)
    events = [event(core, "sample_start", 0), event(core, "call", 1),
              event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    data = records.encode(events)
    receipt = result(core, events)
    receipt["records"][field] = value
    invalid(records.check, core, receipt, data)


def test_artifact_trace_rejects_honestly_rehashed_wrong_order_and_entry_values():
    core = manifest()
    built = records.build(core, "run-1", inventory(), "completed", None)
    events = list(built.events)
    events[0], events[1] = events[1], events[0]
    events[0]["index"], events[1]["index"] = 0, 1
    receipt = result(core, events)
    receipt["resources"] = {"calls": None, **{name: None for name in USAGE}}
    invalid(records.check, core, receipt, records.encode(events))
    events = list(built.events)
    events[0]["bytes"] += 1
    receipt = result(core, events)
    receipt["resources"] = {"calls": None, **{name: None for name in USAGE}}
    invalid(records.check, core, receipt, records.encode(events))


@pytest.mark.parametrize("change", [
    lambda core, items: items.__setitem__(1, event(core, "sample_start", 1)),
    lambda core, items: items.__setitem__(1, event(core, "sample_end", 1)),
    lambda core, items: items.__setitem__(2, event(core, "call", 2)),
])
def test_trace_rejects_duplicate_and_closed_sample_lifecycle_states(change):
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    change(core, items)
    receipt = result(core, items)
    invalid(records.check, core, receipt, records.encode(items))


@pytest.mark.parametrize("mutate", [
    lambda core, items: items.__setitem__(1, event(core, "call", 1, retry_of="later")),
    lambda core, items: items.__setitem__(1, event(core, "call", 1, sample_id="other")),
    lambda core, items: items.__setitem__(1, event(core, "call", 1, input="missing.txt")),
])
def test_trace_rejects_forward_unknown_and_dangling_call_bindings(mutate):
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    mutate(core, items)
    invalid(records.check, core, result(core, items), records.encode(items))


def test_trace_rejects_duplicate_calls_and_cross_sample_retries():
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "call", 2), event(core, "sample_end", 3), event(core, "attempt_end", 4)]
    items[2]["call_id"] = "call-1"
    invalid(records.check, core, result(core, items), records.encode(items))
    core["attempts"][0]["sample_ids"].append("sample-2")
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "sample_start", 2, sample_id="sample-2"),
             event(core, "call", 3, sample_id="sample-2", call_id="call-2", retry_of="call-1"),
             event(core, "attempt_end", 4, outcome="failed", reason="stopped")]
    receipt = result(core, items, outcome="failed", reason="stopped")
    invalid(records.check, core, receipt, records.encode(items))


def test_trace_requires_a_final_terminal_and_completed_coverage():
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1), event(core, "sample_end", 2)]
    invalid(records.check, core, result(core, items), records.encode(items))
    items.append(event(core, "attempt_end", 3))
    items.append(event(core, "call", 4))
    invalid(records.check, core, result(core, items), records.encode(items))
    incomplete = [event(core, "sample_start", 0), event(core, "attempt_end", 1)]
    invalid(records.check, core, result(core, incomplete), records.encode(incomplete))
    failed = [event(core, "sample_start", 0), event(core, "attempt_end", 1, outcome="failed", reason="stopped")]
    receipt = result(core, failed, outcome="failed", reason="stopped")
    receipt["resources"] = {"calls": 0, **{name: 0 for name in USAGE}}
    assert records.check(core, receipt, records.encode(failed)).coverage["state"] == "incomplete"


@pytest.mark.parametrize("field", USAGE)
def test_trace_usage_zero_and_unknown_fields_have_exact_totals(field):
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    items[1]["usage"] = {name: 0 for name in USAGE}
    receipt = result(core, items)
    receipt["resources"] = {"calls": 1, **{name: 0 for name in USAGE}}
    assert records.check(core, receipt, records.encode(items)).resources[field] == 0
    items[1]["usage"][field] = None
    receipt = result(core, items)
    receipt["resources"] = {"calls": 1, **{name: (None if name == field else 0) for name in USAGE}}
    assert records.check(core, receipt, records.encode(items)).known_usage[field] == 0


def test_budget_uses_known_lower_bounds_and_exact_ceiling_edges():
    core = manifest(True)
    core["budget"].update(max_calls=1, max_input_tokens=1, max_output_tokens=1)
    items = [event(core, "sample_start", 0), event(core, "call", 1),
             event(core, "sample_end", 2), event(core, "attempt_end", 3)]
    receipt = result(core, items)
    assert records.check(core, receipt, records.encode(items)).budget == "recorded_within"
    items[1]["usage"]["reasoning_tokens"] = None
    receipt = result(core, items)
    receipt["resources"]["reasoning_tokens"] = None
    assert records.check(core, receipt, records.encode(items)).budget == "recorded_within"
    items[1]["usage"]["input_tokens"] = 2
    items[-1] = event(core, "attempt_end", 3, outcome="budget_exceeded", reason="limit")
    receipt = result(core, items, outcome="budget_exceeded", reason="limit")
    receipt["resources"] = {"calls": 1, **{name: (None if name == "reasoning_tokens" else items[1]["usage"][name]) for name in USAGE}}
    assert records.check(core, receipt, records.encode(items)).budget == "exceeded"
    items[-1] = event(core, "attempt_end", 3)
    receipt = result(core, items)
    receipt["resources"] = {"calls": 1, **{name: (None if name == "reasoning_tokens" else items[1]["usage"][name]) for name in USAGE}}
    invalid(records.check, core, receipt, records.encode(items))


def test_derived_usage_subtotals_reject_safe_integer_overflow():
    core = manifest(True)
    items = [event(core, "sample_start", 0), event(core, "call", 1), event(core, "call", 2),
             event(core, "sample_end", 3), event(core, "attempt_end", 4)]
    items[1]["usage"]["input_tokens"] = canonical.MAX_SAFE_INTEGER
    items[2]["call_id"] = "call-2"
    items[2]["usage"]["input_tokens"] = 1
    invalid(records.check, core, result(core, items), records.encode(items))


def test_encode_decode_limits_and_import_mode_are_bounded():
    oversized = {"value": "x" * records.MAX_EVENT_BYTES}
    with pytest.raises(TallyLockError):
        records.encode([oversized])
    with pytest.raises(TallyLockError):
        records.decode(b"x" * (records.MAX_RECORD_BYTES + 1))
    almost_maximum_event = {"value": "x" * (records.MAX_EVENT_BYTES - 20)}
    with pytest.raises(TallyLockError):
        records.encode([almost_maximum_event] * 65)
    line = b'{ "b" : 2 , "a" : 1 }\n'
    assert records.decode(line, require_canonical=False) == [{"b": 2, "a": 1}]


def test_build_hashes_the_manifest_once_and_normalizes_bad_attempt_ids():
    core = manifest()
    original = records.canonical.digest
    calls = 0

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    records.canonical.digest = counted
    try:
        records.build(core, "run-1", inventory(), "completed", None)
    finally:
        records.canonical.digest = original
    assert calls == 1
    with pytest.raises(TallyLockError):
        records.build(core, [], inventory(), "completed", None)
