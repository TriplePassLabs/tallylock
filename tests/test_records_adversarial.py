"""Independent semantic receipts with honest hashes and incomplete usage."""

import hashlib

import pytest

from tallylock import canonical, merkle, records, schema
from tallylock.errors import TallyLockError


def receipt(first, second, *, outcome="completed", ceiling=5, max_calls=None):
    manifest = schema.default_manifest()
    manifest["nonce"] = "00" * 16
    manifest["profile"] = "trace-v1"
    manifest["attempts"] = [{"id": "run-1", "sample_ids": ["sample"]}]
    manifest["budget"].update(max_input_tokens=ceiling, max_calls=max_calls)
    registration_id = canonical.digest(manifest)
    usage_fields = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")
    events = []

    def add(kind, **fields):
        events.append({"format": "prove.event.v1", "registration_id": registration_id,
                       "attempt_id": "run-1", "index": len(events), "kind": kind, **fields})

    add("sample_start", sample_id="sample")
    for index, amount in enumerate((first, second)):
        usage = dict.fromkeys(usage_fields, 0)
        usage["input_tokens"] = amount
        add("call", sample_id="sample", call_id=f"call-{index}", retry_of=None,
            source="external", status="succeeded", input=None, output=None, usage=usage)
    add("sample_end", sample_id="sample", status="completed")
    reason = None if outcome == "completed" else "recorded limit reached"
    add("attempt_end", outcome=outcome, reason=reason)
    data = b"".join(canonical.dumps(event) + b"\n" for event in events)
    resources = {"calls": 2, **dict.fromkeys(usage_fields, 0)}
    resources["input_tokens"] = None if None in (first, second) else first + second
    result = {"format": "prove.result.v1", "registration_id": registration_id,
              "attempt_id": "run-1", "profile": "trace-v1", "outcome": outcome,
              "reason": reason, "inventory": {}, "score": None, "metadata": {},
              "resources": resources,
              "records": {"path": "records.jsonl", "sha256": hashlib.sha256(data).hexdigest(),
                          "bytes": len(data), "count": len(events),
                          "tree_algorithm": "rfc9162-sha256",
                          "root": merkle.root([canonical.dumps(event) for event in events])}}
    return manifest, result, data


def test_unknown_usage_cannot_erase_a_known_budget_violation():
    manifest, result, data = receipt(6, None)
    # Closed schemas and every byte commitment are valid; only the semantic
    # lower bound contradicts the declared successful outcome.
    schema.validate_result(result, manifest)
    with pytest.raises(TallyLockError) as caught:
        records.check(manifest, result, data)
    assert caught.value.code == 2


def test_explicit_excess_retains_null_total_and_nonzero_lower_bound():
    checked = records.check(*receipt(6, None, outcome="budget_exceeded"))
    assert checked.resources["input_tokens"] is None
    assert checked.known_usage["input_tokens"] == 6
    assert checked.budget == "exceeded"
    assert checked.coverage == {"state": "complete", "expected": 1, "started": 1, "ended": 1}


@pytest.mark.parametrize("known", [0, 4, 5])
def test_unknown_constrained_total_never_claims_recorded_within(known):
    checked = records.check(*receipt(known, None))
    assert checked.budget == "unknown"


def test_known_call_limit_still_applies_with_unknown_token_totals():
    manifest, result, data = receipt(None, None, max_calls=1)
    schema.validate_result(result, manifest)
    with pytest.raises(TallyLockError) as caught:
        records.check(manifest, result, data)
    assert caught.value.code == 2


def test_exact_event_and_total_wire_limits_are_accepted():
    maximum = {"value": "x" * (records.MAX_EVENT_BYTES - 12)}
    assert len(canonical.dumps(maximum)) == records.MAX_EVENT_BYTES
    assert records.decode(records.encode([maximum])) == [maximum]
    tail = {"value": "x" * (records.MAX_EVENT_BYTES - 76)}
    events = [maximum] * 63 + [tail]
    data = records.encode(events)
    assert len(data) == records.MAX_RECORD_BYTES
    assert records.decode(data) == events
    with pytest.raises(TallyLockError):
        records.decode(data + b"\n")


@pytest.mark.parametrize("manifest_profile,event_field,event_value,code", [
    (None, "kind", "future", 4),
    ("future", "format", None, 2),
])
def test_one_shot_event_error_precedence_has_distinguishable_codes(
        manifest_profile, event_field, event_value, code):
    manifest, _, data = receipt(0, 0)
    event = records.decode(data)[0]
    manifest["profile"] = manifest_profile
    event[event_field] = event_value
    with pytest.raises(TallyLockError) as caught:
        schema.validate_event(event, manifest, "run-1")
    assert caught.value.code == code
