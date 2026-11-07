"""Pure normalized-record encoding and consistency checks."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from typing import Any

from . import canonical, merkle, schema
from .errors import TallyLockError


MAX_EVENT_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
_USAGE = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")
_SAFE = canonical.MAX_SAFE_INTEGER


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TallyLockError(message)


def _checked_add(left: int, right: int) -> int:
    total = left + right
    _require(total <= _SAFE, "derived counter exceeds the safe integer range")
    return total


def decode(data: bytes, *, require_canonical: bool = True) -> list[dict]:
    """Parse bounded strict JSONL, optionally allowing noncanonical import lines."""
    _require(isinstance(data, bytes), "records data must be bytes")
    _require(len(data) <= MAX_RECORD_BYTES, "records exceed 64 MiB")
    if not data:
        return []
    _require(not data.startswith(b"\xef\xbb\xbf"), "records must not have a BOM")
    _require(b"\r" not in data and data.endswith(b"\n"), "records must use final LF delimiters")
    lines = data[:-1].split(b"\n")
    _require(all(lines), "records must not contain blank lines")
    events: list[dict] = []
    for line in lines:
        _require(len(line) <= MAX_EVENT_BYTES, "record exceeds 1 MiB")
        value = canonical.loads(line)
        _require(isinstance(value, dict), "record must be an object")
        if require_canonical:
            _require(canonical.dumps(value) == line, "record is not canonical JSON")
        events.append(value)
    return events


def encode(events: list[dict]) -> bytes:
    """Encode object events as exact canonical JSONL without lifecycle claims."""
    _require(isinstance(events, list), "events must be a list")
    lines: list[bytes] = []
    size = 0
    for value in events:
        _require(isinstance(value, dict), "record must be an object")
        line = canonical.dumps(value)
        _require(len(line) <= MAX_EVENT_BYTES, "record exceeds 1 MiB")
        size += len(line) + 1
        _require(size <= MAX_RECORD_BYTES, "records exceed 64 MiB")
        lines.append(line)
    return b"".join(line + b"\n" for line in lines)


@dataclass(frozen=True)
class RecordSet:
    data: bytes
    events: tuple[dict, ...]
    metadata: dict
    resources: dict
    coverage: dict
    known_usage: dict
    budget: str


def _metadata(data: bytes, events: list[dict]) -> dict:
    leaves = [canonical.dumps(event) for event in events]
    return {"path": "records.jsonl", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "count": len(events), "tree_algorithm": "rfc9162-sha256", "root": merkle.root(leaves)}


def _record_set(events: list[dict], resources: dict, coverage: dict, known_usage: dict, budget: str,
                *, data: bytes | None = None, metadata: dict | None = None) -> RecordSet:
    data = encode(events) if data is None else data
    metadata = _metadata(data, events) if metadata is None else metadata
    return RecordSet(data, tuple(deepcopy(events)), deepcopy(metadata), deepcopy(resources),
                     deepcopy(coverage), deepcopy(known_usage), budget)


def _budget(manifest: dict, resources: dict, known: dict, outcome: str) -> str:
    ceilings = manifest["budget"]
    relevant = {"max_calls": "calls", "max_input_tokens": "input_tokens",
                "max_output_tokens": "output_tokens"}
    if all(ceilings[name] is None for name in relevant):
        return "not_declared"
    exceeded = any(ceilings[name] is not None and known[field] > ceilings[name]
                   for name, field in relevant.items())
    if exceeded:
        _require(outcome == "budget_exceeded", "known budget excess requires budget_exceeded outcome")
        return "exceeded"
    complete = all(ceilings[name] is None or resources[field] is not None
                   for name, field in relevant.items())
    return "recorded_within" if complete else "unknown"


def _analyze(manifest: dict, attempt_id: str, inventory: dict, events: list[dict], outcome: str, reason: str | None):
    prepared = schema.EventValidator(manifest, attempt_id)
    profile = manifest["profile"]
    if profile == "artifacts-v1":
        ordered = sorted(inventory, key=lambda path: path.encode("utf-8"))
        _require(len(events) == len(ordered) + 1, "artifact records require every inventory entry and terminal")
        for index, path in enumerate(ordered):
            value = events[index]
            prepared.validate(value)
            _require(value["index"] == index and value["kind"] == "artifact", "artifact record order is invalid")
            entry = inventory[path]
            _require(all(value[field] == entry[field] for field in ("sha256", "bytes")) and value["path"] == path,
                     "artifact record differs from inventory")
        terminal = events[-1]
        prepared.validate(terminal)
        _require(terminal["index"] == len(ordered) and terminal["kind"] == "attempt_end", "artifact terminal is invalid")
        _require(terminal["outcome"] == outcome and terminal["reason"] == reason, "terminal differs from result")
        resources = {"calls": None, **{field: None for field in _USAGE}}
        known = {"calls": None, **{field: None for field in _USAGE}}
        coverage = {"state": "not_applicable", "expected": None, "started": None, "ended": None}
        budget = "not_declared" if all(value is None for value in manifest["budget"].values()) else "unknown"
        return resources, coverage, known, budget

    if not events:
        _require(outcome != "completed" and isinstance(reason, str) and bool(reason),
                 "only explicit unsuccessful traces may be empty")
    open_samples: set[str] = set()
    started: set[str] = set()
    ended: set[str] = set()
    calls: dict[str, str] = {}
    totals = {field: 0 for field in _USAGE}
    complete = {field: True for field in _USAGE}
    terminal = None
    for index, value in enumerate(events):
        prepared.validate(value)
        _require(value["index"] == index, "record indices must be contiguous")
        _require(terminal is None, "records after attempt_end are not allowed")
        kind = value["kind"]
        if kind == "sample_start":
            sample = value["sample_id"]
            _require(sample not in started, "sample may start only once")
            started.add(sample); open_samples.add(sample)
        elif kind == "sample_end":
            sample = value["sample_id"]
            _require(sample in open_samples, "sample end requires an open sample")
            open_samples.remove(sample); ended.add(sample)
        elif kind == "call":
            sample = value["sample_id"]
            _require(sample in open_samples, "call requires an open sample")
            call_id = value["call_id"]
            _require(call_id not in calls, "call IDs must be unique")
            retry = value["retry_of"]
            _require(retry is None or (retry in calls and calls[retry] == sample),
                     "retry must reference an earlier call in the same sample")
            calls[call_id] = sample
            for field in ("input", "output"):
                _require(value[field] is None or value[field] in inventory, f"call has dangling {field} artifact")
            for field, amount in value["usage"].items():
                if amount is None:
                    complete[field] = False
                else:
                    totals[field] = _checked_add(totals[field], amount)
        elif kind == "attempt_end":
            terminal = value
            _require(index == len(events) - 1, "attempt_end must be final")
            _require(value["outcome"] == outcome and value["reason"] == reason, "terminal differs from result")
    if events:
        _require(terminal is not None, "nonempty trace requires attempt_end")
    expected = set(next(attempt for attempt in manifest["attempts"] if attempt["id"] == attempt_id)["sample_ids"])
    if outcome == "completed":
        _require(ended == expected and not open_samples, "completed trace requires every sample to end")
    resources = {"calls": len(calls)}
    resources.update({field: totals[field] if complete[field] else None for field in _USAGE})
    known = {"calls": len(calls), **totals}
    coverage = {"state": "complete" if ended == expected and not open_samples else "incomplete",
                "expected": len(expected), "started": len(started), "ended": len(ended)}
    return resources, coverage, known, _budget(manifest, resources, known, outcome)


def build(manifest: dict, attempt_id: str, inventory: dict, outcome: str, reason: str | None, *, events: list[dict] | None = None) -> RecordSet:
    """Create deterministic artifact records or validate a supplied trace."""
    schema.validate_manifest(manifest)
    schema.validate_inventory(inventory)
    _require(isinstance(attempt_id, str) and attempt_id in {item["id"] for item in manifest["attempts"]},
             "undeclared attempt")
    _require(outcome in ("completed", "failed", "aborted", "budget_exceeded"), "unsupported outcome")
    _require((outcome == "completed" and reason is None) or (outcome != "completed" and isinstance(reason, str) and bool(reason)),
             "outcome and reason conflict")
    if manifest["profile"] == "artifacts-v1":
        _require(events is None, "artifact profile generates its own events")
        _require(outcome != "completed" or bool(inventory),
                 "completed artifact receipt requires an artifact")
        generated = []
        registration_id = canonical.digest(manifest)
        for index, path in enumerate(sorted(inventory, key=lambda item: item.encode("utf-8"))):
            entry = inventory[path]
            generated.append({"format": "prove.event.v1", "registration_id": registration_id,
                              "attempt_id": attempt_id, "index": index, "kind": "artifact", "path": path,
                              "sha256": entry["sha256"], "bytes": entry["bytes"]})
        generated.append({"format": "prove.event.v1", "registration_id": registration_id,
                          "attempt_id": attempt_id, "index": len(generated), "kind": "attempt_end",
                          "outcome": outcome, "reason": reason})
    else:
        _require(events is not None and isinstance(events, list), "trace profile requires an explicit event list")
        generated = events
    resources, coverage, known, budget = _analyze(manifest, attempt_id, inventory, generated, outcome, reason)
    return _record_set(generated, resources, coverage, known, budget)


def check(manifest: dict, result: dict, data: bytes) -> RecordSet:
    """Validate canonical stored records against the declared core metadata."""
    schema.validate_manifest(manifest)
    schema.validate_result(result, manifest)
    events = decode(data)
    metadata = result["records"]
    computed = _metadata(data, events)
    _require(computed == metadata, "records metadata differs from stored records")
    resources, coverage, known, budget = _analyze(manifest, result["attempt_id"], result["inventory"], events,
                                                   result["outcome"], result["reason"])
    _require(resources == result["resources"], "declared resources differ from records")
    return _record_set(events, resources, coverage, known, budget, data=data, metadata=metadata)
