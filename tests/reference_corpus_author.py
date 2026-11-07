"""Offline corpus authoring worksheet, never imported by conformance tests.

Explicit regeneration: python -m pytest tests/reference_corpus_author.py -q
This writes reviewed source assets. It imports neither TallyLock nor the reference.
Wire fixtures use stdlib JSON with ASCII/BMP keys. Trees use a bottom-up node stack,
independently from the reference verifier's recursive split implementation.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path


DEST = Path(__file__).resolve().parents[1] / "src/tallylock/data/conformance"
FIELDS = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")


def packed(value):
    # Wire fixture keys are ASCII/BMP, where codepoint and UTF16 ordering agree.
    # Canonical-vector containers are ordinary JSON; their expected bytes are handwritten.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def tree(leaves):
    # Stack carries complete powers of two. Fold the remaining forest rightward.
    nodes = []
    for index, leaf in enumerate(leaves):
        current = hashlib.sha256(b"\x00" + leaf).digest()
        width = 1
        while nodes and nodes[-1][0] == width:
            _, left = nodes.pop()
            current = hashlib.sha256(b"\x01" + left + current).digest()
            width *= 2
        nodes.append((width, current))
    if not nodes:
        return hashlib.sha256(b"").digest()
    current = nodes.pop()[1]
    while nodes:
        current = hashlib.sha256(b"\x01" + nodes.pop()[1] + current).digest()
    return current


def path(leaves, position):
    # Find complete sibling intervals from the binary split geometry.
    result = []
    offset, width = 0, len(leaves)
    while width > 1:
        boundary = 2 ** ((width - 1).bit_length() - 1)
        if position < offset + boundary:
            result.insert(0, tree(leaves[offset + boundary:offset + width]).hex())
            width = boundary
        else:
            result.insert(0, tree(leaves[offset:offset + boundary]).hex())
            offset += boundary
            width -= boundary
    return result


def manifest(trace=False, fixture=False, samples=None):
    return {"format": "prove.manifest.v1", "nonce": "0123456789abcdef" * 2,
            "name": "Independent wire fixture", "description": "Fixed public synthetic bytes; no model run.",
            "profile": "trace-v1" if trace else "artifacts-v1",
            "attempts": [{"id": "run-1", "sample_ids": (samples or ["s1", "s2"]) if trace else []}],
            "dataset": {"name": "synthetic", "sha256": None},
            "model": {"id": "no-model", "evidence": "self_declared", "sha256": None},
            "harness": {"name": "public-bytes", "revision": "v1", "config": {}},
            "generation": {"prompt_sha256": None, "parameters": {}},
            "scorer": {"profile": "fixture-exact-v1" if fixture else "recorded-only-v1", "revision": "v1"},
            "analysis": {"revision": "v1", "plan_sha256": None},
            "budget": {"max_calls": None, "max_input_tokens": None, "max_output_tokens": None},
            "stopping_rule": "fixed synthetic fixture", "metadata": {}}


def end(outcome="completed", reason=None):
    return {"kind": "attempt_end", "outcome": outcome, "reason": reason}


def start(sample="s1"):
    return {"kind": "sample_start", "sample_id": sample}


def finish(sample="s1"):
    return {"kind": "sample_end", "sample_id": sample, "status": "completed"}


def call(sample="s1", identifier="c1", retry=None, tokens=3):
    return {"kind": "call", "sample_id": sample, "call_id": identifier, "retry_of": retry,
            "source": "synthetic", "status": "succeeded", "input": None, "output": None,
            "usage": {field: tokens if field == "input_tokens" else 0 for field in FIELDS}}


def run(m, artifacts, events=None, outcome="completed", reason=None, score_path=None, aggregate=None):
    inventory = {name: {"sha256": sha(raw), "bytes": len(raw), "media_type": "application/octet-stream", "role": role}
                 for name, (raw, role) in artifacts.items()}
    if events is None:
        events = [{"kind": "artifact", "path": name, "sha256": inventory[name]["sha256"], "bytes": inventory[name]["bytes"]}
                  for name in sorted(inventory, key=lambda value: value.encode("utf-8"))] + [end(outcome, reason)]
    document = {"format": "prove.result.v1", "registration_id": sha(packed(m)), "attempt_id": "run-1",
                "profile": m["profile"], "outcome": outcome, "reason": reason, "inventory": inventory,
                "records": {}, "resources": {field: None for field in ("calls", *FIELDS)}, "score": None, "metadata": {}}
    if m["profile"] == "trace-v1":
        calls = [event for event in events if event["kind"] == "call"]
        document["resources"] = {"calls": len(calls)}
        for field in FIELDS:
            values = [event["usage"][field] for event in calls]
            document["resources"][field] = None if None in values else sum(values)
    if score_path is not None:
        entry = inventory[score_path]
        document["score"] = {"path": score_path, "sha256": entry["sha256"], "bytes": entry["bytes"],
                             "profile": m["scorer"]["profile"], "aggregate": aggregate}
    return rebind({"format": "prove.conformance-case.v1", "kind": "run", "manifest": m, "result": document,
                   "events": copy.deepcopy(events), "artifacts": {name: raw for name, (raw, _) in artifacts.items()}})


def rebind(case):
    """Rebind every event, records digest/length/root, and both core commitments."""
    m, r = case["manifest"], case["result"]
    r["registration_id"] = sha(packed(m))
    for index, event in enumerate(case["events"]):
        event.update(format="prove.event.v1", registration_id=r["registration_id"], attempt_id=r["attempt_id"], index=index)
    return record_commit(case)


def record_commit(case):
    """Commit event bytes as supplied, preserving intentional event contradictions."""
    r = case["result"]
    leaves = [packed(event) for event in case["events"]]
    raw = b"".join(leaf + b"\n" for leaf in leaves)
    r["records"] = {"path": "records.jsonl", "sha256": sha(raw), "bytes": len(raw), "count": len(leaves),
                    "tree_algorithm": "rfc9162-sha256", "root": tree(leaves).hex()}
    return case


def envelope(case):
    return {"format": case["format"], "kind": "run", "manifest": b64(packed(case["manifest"])),
            "result": b64(packed(case["result"])), "records": b64(b"".join(packed(e) + b"\n" for e in case["events"])),
            "artifacts": {name: b64(raw) for name, raw in case["artifacts"].items()}}


def included(case, position):
    leaves = [packed(event) for event in case["events"]]
    r = case["result"]
    return {"format": "prove.conformance-case.v1", "kind": "inclusion", "inclusion": {
        "format": "prove.inclusion.v1", "registration_id": sha(packed(case["manifest"])), "receipt_id": sha(packed(r)),
        "manifest": copy.deepcopy(case["manifest"]), "result": copy.deepcopy(r),
        "event": copy.deepcopy(case["events"][position]), "index": position,
        "size": len(leaves), "siblings": path(leaves, position), "proofs": {"manifest": None, "result": None}}}


def test_author_fixed_corpus():
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST / "cases").mkdir(exist_ok=True)
    index = []

    def save(name, value, code, purpose, score=None, stage=None, production=True, raw=None):
        materialized = envelope(value) if "events" in value else value
        ids = {"registration_id": None, "receipt_id": None, "root": None}
        if stage not in ("canonical", "schema", "envelope") and raw is None:
            if "events" in value:
                m, r = value["manifest"], value["result"]
            elif value["kind"] == "run":
                m, r = json.loads(base64.b64decode(value["manifest"])), json.loads(base64.b64decode(value["result"]))
            else:
                m, r = value["inclusion"]["manifest"], value["inclusion"]["result"]
            ids = {"registration_id": sha(packed(m)), "receipt_id": sha(packed(r)), "root": r["records"]["root"]}
        (DEST / "cases" / f"{name}.json").write_bytes(raw if raw is not None else packed(materialized))
        index.append({"file": f"cases/{name}.json", "purpose": purpose, "expected": {
            "code": code, "kind": materialized.get("kind") if raw is None else None, **ids, "score": score},
            "production_overlap": production, "failure_stage": stage,
            "scope": "membership and finite visible contradictions" if materialized.get("kind") == "inclusion" else "materialized wire; filesystem and anchors excluded"})

    unavailable = {"state": "unavailable", "aggregate": None}
    generic = run(manifest(), {"Read Me.txt": (b"Public synthetic artifact.\n", "output"), "Données/東京.txt": ("café ☃\n".encode(), "input")})
    save("run-artifacts-unicode", generic, 0, "Generic artifacts with uppercase, space, NFC and Unicode paths", unavailable)
    opaque = run(manifest(), {"metrics.bin": (b"not JSON; never executed\x00", "score")}, score_path="metrics.bin", aggregate={"numerator": 17, "denominator": 3})
    save("run-opaque-score", opaque, 0, "Arbitrary recorded-only rational metric is never recomputed", {"state": "recorded_only", "aggregate": {"numerator": 17, "denominator": 3}})
    dataset = packed({"format": "prove.fixture-dataset.v1", "samples": [{"id": "s1", "expected": "YES"}, {"id": "s2", "expected": "é"}]})
    scores = packed({"format": "prove.fixture-scores.v1", "samples": [{"id": "s2", "observed": "e\u0301"}, {"id": "s1", "observed": "YES"}], "aggregate": {"numerator": 1, "denominator": 2}})
    fm = manifest(True, True)
    fm["dataset"]["sha256"] = sha(dataset)
    fixture = run(fm, {"dataset.json": (dataset, "dataset"), "score.json": (scores, "score")},
                  [start(), call(), finish(), start("s2"), finish("s2"), end()], score_path="score.json", aggregate={"numerator": 1, "denominator": 2})
    save("run-fixture-exact", fixture, 0, "No-model exact fixture; sample order irrelevant and strings not normalized", {"state": "recomputed", "aggregate": {"numerator": 1, "denominator": 2}})
    failed = run(fm, {}, [start(), end("failed", "stopped before scoring")], "failed", "stopped before scoring")
    save("run-fixture-null-failure", failed, 0, "Honest incomplete fixture has null score and no dataset artifact", unavailable)
    empty = run(fm, {}, [], "failed", "failed before logging")
    save("run-empty-failure", empty, 0, "Empty unsuccessful trace with explicit reason", unavailable)
    bm = manifest(True, samples=["s1"])
    bm["budget"]["max_input_tokens"] = 2
    unknown = call(identifier="c2", retry="c1", tokens=None)
    budget = run(bm, {}, [start(), call(), unknown, end("budget_exceeded", "known subtotal exceeds limit")], "budget_exceeded", "known subtotal exceeds limit")
    save("run-budget-unknown-total", budget, 0, "Known subtotal violation remains visible when full input total is unknown", unavailable)
    retry = run(manifest(True, samples=["s1"]), {}, [start(), call(), call(identifier="c2", retry="c1"), finish(), end()])
    save("run-retry", retry, 0, "Valid earlier same-sample retry", unavailable)
    save("inclusion-artifact-unavailable", included(generic, 0), 0, "Valid branch needs no artifacts on disk")
    save("inclusion-terminal", included(fixture, 5), 0, "Valid terminal membership does not recompute score")
    save("inclusion-call", included(fixture, 1), 0, "Valid call membership only")
    save("inclusion-open-failed", included(budget, 2), 0, "Unsuccessful retry may leave sample open")

    def changed(name, base, mutate, purpose, stage="records", code=2, production=True):
        value = copy.deepcopy(base)
        mutate(value)
        if "events" in value:
            rebind(value)
        save(name, value, code, purpose, stage=stage, production=production)

    changed("bad-false-math", fixture, lambda v: v["result"]["score"]["aggregate"].update(numerator=2), "Result score lies while artifact bytes and all trees/IDs remain correctly bound", "scoring")
    false_score = copy.deepcopy(fixture)
    payload = json.loads(false_score["artifacts"]["score.json"])
    payload["aggregate"]["numerator"] = 2
    false_score["artifacts"]["score.json"] = packed(payload)
    entry = false_score["result"]["inventory"]["score.json"]
    entry.update(sha256=sha(packed(payload)), bytes=len(packed(payload)))
    false_score["result"]["score"].update(sha256=entry["sha256"], bytes=entry["bytes"], aggregate=payload["aggregate"])
    save("bad-false-math-all-hashes", rebind(false_score), 2, "Artifact and result both lie about exact math; every digest/length/root rebound", stage="scoring")
    changed("bad-resources", fixture, lambda v: v["result"]["resources"].update(input_tokens=4), "False call resource total with correctly rebound core/record commitments")
    changed("bad-budget", budget, lambda v: (v["result"].update(outcome="failed"), v["events"][-1].update(outcome="failed")), "Unknown full total cannot erase known budget excess; all commitments rebound")
    changed("bad-retry-forward", retry, lambda v: v["events"][1].update(retry_of="c2"), "Retry references later call with genuinely matching record hashes/tree")
    changed("bad-retry-self", retry, lambda v: v["events"][1].update(retry_of="c1"), "Retry references itself")
    changed("bad-call-before-start", retry, lambda v: v["events"].__setitem__(slice(0, 2), [v["events"][1], v["events"][0]]), "Call precedes its start with all commitments rebound")
    changed("bad-call-after-end", retry, lambda v: v["events"].__setitem__(slice(2, 4), [v["events"][3], v["events"][2]]), "Call after closed sample with all commitments rebound")
    changed("bad-duplicate-start", fixture, lambda v: v["events"].insert(1, start()), "Duplicate sample start")
    changed("bad-duplicate-call", retry, lambda v: v["events"][2].update(call_id="c1", retry_of=None), "Duplicate call ID")
    changed("bad-missing-coverage", fixture, lambda v: v["events"].__delitem__(4), "Completed trace omits one sample_end with all hashes rebound")
    changed("bad-early-terminal", retry, lambda v: v["events"].insert(2, end()), "Record after an attempt_end, correctly hashed")
    changed("bad-terminal-reason", failed, lambda v: v["events"][-1].update(reason="different"), "Terminal reason differs from result")
    changed("bad-dangling-call", fixture, lambda v: v["events"][1].update(input="absent.txt"), "Call references absent inventory path")
    changed("bad-attempt", generic, lambda v: v["result"].update(attempt_id="other"), "Undeclared selected attempt", "bindings")
    changed("bad-profile", generic, lambda v: v["result"].update(profile="trace-v1", resources={"calls": 0, **{k: 0 for k in FIELDS}}), "Core profile binding differs", "bindings")
    changed("bad-score-binding", opaque, lambda v: v["result"]["score"].update(sha256="0" * 64), "Score copied digest differs from its inventory entry", "bindings")
    changed("bad-artifact-bytes", generic, lambda v: v["artifacts"].update({"Read Me.txt": b"changed"}), "Materialized artifact bytes differ from inventory", "artifacts")
    changed("bad-missing-artifact", generic, lambda v: v["artifacts"].pop("Read Me.txt"), "Materialized artifact is missing", "artifacts")
    changed("bad-extra-artifact", generic, lambda v: v["artifacts"].update({"extra": b"extra"}), "Unlisted materialized artifact", "artifacts")
    changed("bad-path-traversal", generic, lambda v: v["result"]["inventory"].update({"../escape": v["result"]["inventory"].pop("Read Me.txt")}), "Untrusted inventory traversal is data and never materialized", "bindings")
    collision = run(manifest(), {"A/x": (b"a", "output"), "a/y": (b"b", "output")})
    save("bad-prefix-collision", collision, 2, "Casefold collision includes directory prefixes", stage="bindings")
    for name, mutate, purpose in [
        ("bad-registration", lambda v: v["result"].update(registration_id="0" * 64), "Core manifest ID mismatch"),
        ("bad-event-binding", lambda v: v["events"][0].update(registration_id="0" * 64), "Record registration binding mismatch"),
        ("bad-record-root", lambda v: v["result"]["records"].update(root="0" * 64), "Committed record root mismatch"),
        ("bad-record-digest", lambda v: v["result"]["records"].update(sha256="0" * 64), "Committed records digest mismatch"),
    ]:
        value = copy.deepcopy(generic)
        mutate(value)  # Intentionally do not repair the targeted binding.
        if name == "bad-event-binding":
            record_commit(value)
        save(name, value, 2, purpose, stage="bindings" if name == "bad-registration" else "records")
    for name, mutator, code in [
        ("bad-manifest-future", lambda v: v["manifest"].update(format="prove.manifest.v2"), 4),
        ("bad-manifest-unknown-string", lambda v: v["manifest"].update(format="banana"), 4),
        ("bad-manifest-malformed", lambda v: v["manifest"].update(format=17), 2),
        ("bad-manifest-missing-format", lambda v: v["manifest"].pop("format"), 2),
        ("bad-event-future", lambda v: v["events"][0].update(format="prove.event.v2"), 4),
        ("bad-result-unknown-field", lambda v: v["result"].update(extra=True), 2),
    ]:
        value = copy.deepcopy(generic)
        if name == "bad-event-future":
            value["events"][0]["metadata_future"] = True
            rebind(value)
            value["events"][0].pop("metadata_future")
            mutator(value)
            leaves = [packed(event) for event in value["events"]]
            raw = b"".join(leaf + b"\n" for leaf in leaves)
            value["result"]["records"].update(root=tree(leaves).hex(), sha256=sha(raw), bytes=len(raw))
        else:
            mutator(value)
            rebind(value)
        save(name, value, code, "Unsupported future version distinguished from malformed closed schema", stage="records" if name == "bad-event-future" else "schema")
    for name, raw, purpose in [
        ("bad-json-duplicate", b'{"kind":"run","kind":"run"}', "Duplicate envelope key"),
        ("bad-json-float", b'{"x":1.0}', "Floating-point JSON"),
        ("bad-json-unsafe", b'{"x":9007199254740992}', "Unsafe integer"),
        ("bad-json-depth", b"[" * 65 + b"0" + b"]" * 65, "Depth above 64"),
        ("bad-json-utf8", b'{"x":"\xff"}', "Invalid UTF8"),
        ("bad-json-surrogate", b'{"x":"\\ud800"}', "Escaped lone surrogate"),
        ("bad-json-nonfinite", b'{"x":NaN}', "Nonfinite JSON number"),
    ]:
        save(name, {}, 2, purpose, stage="canonical", production=False, raw=raw)
    for name, replace, purpose in [
        ("bad-core-noncanonical", lambda raw: b" " + raw, "Core whitespace is not canonical"),
        ("bad-core-duplicate", lambda raw: raw[:-1] + b',"metadata":{}}', "Duplicate embedded core key"),
        ("bad-core-float", lambda raw: raw.replace(b'"metadata":{}', b'"metadata":{"x":1.0}'), "Embedded core float"),
        ("bad-core-unsafe", lambda raw: raw.replace(b'"metadata":{}', b'"metadata":{"x":9007199254740992}'), "Embedded unsafe integer"),
    ]:
        value = envelope(generic)
        value["manifest"] = b64(replace(base64.b64decode(value["manifest"])))
        save(name, value, 2, purpose, stage="canonical")
    value = envelope(generic)
    value["manifest"] += "\n"
    save("bad-base64", value, 2, "Strict canonical base64 rejects whitespace", stage="canonical", production=False)
    value = envelope(generic)
    value["extra"] = True
    save("bad-envelope-field", value, 2, "Envelope is closed", stage="envelope", production=False)

    # Recommit altered record framing so rejection exercises canonical JSONL.
    for name, transform, purpose in [
        ("bad-record-crlf", lambda raw: raw.replace(b"\n", b"\r\n"), "Canonical JSONL rejects CRLF"),
        ("bad-record-blank", lambda raw: raw + b"\n", "Canonical JSONL rejects blank lines"),
        ("bad-record-no-lf", lambda raw: raw[:-1], "Canonical JSONL requires final LF"),
        ("bad-record-whitespace", lambda raw: b" " + raw, "Every event leaf must be canonical"),
    ]:
        value = envelope(generic)
        raw = transform(base64.b64decode(value["records"]))
        r = json.loads(base64.b64decode(value["result"]))
        r["records"].update(sha256=sha(raw), bytes=len(raw))
        value.update(result=b64(packed(r)), records=b64(raw))
        # IDs are derived from the actual canonical cores, not the envelope.
        save(name, value, 2, purpose, stage="records")

    changed("bad-bool-counter", generic, lambda v: v["result"]["inventory"]["Read Me.txt"].update(bytes=True), "Boolean is not an integer byte counter", "schema")
    changed("bad-fixture-dataset-pin", fixture, lambda v: v["manifest"]["dataset"].update(sha256="0" * 64), "Correct artifact hash cannot satisfy another pinned dataset", "bindings")
    changed("bad-completed-null-score", fixture, lambda v: v["result"].update(score=None), "Completed exact fixture cannot omit its score", "bindings")
    changed("bad-fixture-denominator", fixture, lambda v: v["result"]["score"]["aggregate"].update(denominator=1), "Fixture counts are exact and not a reduced fraction", "bindings")
    for name, mutate, purpose in [
        ("bad-fixture-duplicate", lambda v: v["samples"].append(v["samples"][0]), "Duplicate fixture sample ID"),
        ("bad-fixture-observed-type", lambda v: v["samples"][0].update(observed=17), "Fixture observation must be a string"),
        ("bad-fixture-unknown-field", lambda v: v.update(ignored=True), "Fixture object is a closed shape"),
    ]:
        bad_fixture = copy.deepcopy(fixture)
        payload = json.loads(bad_fixture["artifacts"]["score.json"])
        mutate(payload)
        raw = packed(payload)
        bad_fixture["artifacts"]["score.json"] = raw
        bad_fixture["result"]["inventory"]["score.json"].update(sha256=sha(raw), bytes=len(raw))
        bad_fixture["result"]["score"].update(sha256=sha(raw), bytes=len(raw))
        save(name, rebind(bad_fixture), 2, purpose + "; all hashes and lengths rebound", stage="scoring")
    changed("bad-cross-sample-retry", fixture, lambda v: v["events"].insert(4, call(sample="s2", identifier="c2", retry="c1", tokens=0)), "Retry cannot reference another sample's earlier call")
    # Match resource totals in the cross-sample-retry case (the invalid retry
    # must be decisive rather than an unrelated stale resource declaration).
    cross = json.loads((DEST / "cases/bad-cross-sample-retry.json").read_bytes())
    cross_result = json.loads(base64.b64decode(cross["result"]))
    cross_result["resources"]["calls"] = 2
    cross["result"] = b64(packed(cross_result))
    (DEST / "cases/bad-cross-sample-retry.json").write_bytes(packed(cross))
    index[-1]["expected"]["receipt_id"] = sha(packed(cross_result))

    def inc_change(name, base, mutate, purpose):
        value = copy.deepcopy(base)
        mutate(value["inclusion"])
        save(name, value, 2, purpose, stage="membership")

    inc_change("bad-inclusion-sibling", included(generic, 0), lambda v: v["siblings"].__setitem__(0, "0" * 64), "Wrong sibling")
    inc_change("bad-inclusion-unused-sibling", included(generic, 0), lambda v: v["siblings"].append("0" * 64), "Unused sibling must fail")
    inc_change("bad-inclusion-size", included(generic, 0), lambda v: v.update(size=v["size"] + 1), "Size differs from committed count")
    inc_change("bad-inclusion-id", included(generic, 0), lambda v: v.update(receipt_id="0" * 64), "Supplied inclusion receipt ID mismatch")
    # These adversarial histories are freshly rebound before creating a REAL path.
    terminal_early = copy.deepcopy(retry)
    terminal_early["events"][0] = end()
    rebind(terminal_early)
    save("bad-inclusion-nonfinal-terminal", included(terminal_early, 0), 2, "Genuine membership for nonfinal terminal; static contradiction", stage="membership")
    final_call = copy.deepcopy(retry)
    final_call["events"][-1] = call(identifier="c3")
    rebind(final_call)
    final_call["result"]["resources"]["calls"] = 3
    save("bad-inclusion-final-call", included(final_call, 4), 2, "Genuine membership for final nonterminal; static contradiction", stage="membership")
    rank = copy.deepcopy(generic)
    rank["events"][0], rank["events"][1] = rank["events"][1], rank["events"][0]
    save("bad-inclusion-artifact-rank", included(rebind(rank), 0), 2, "Genuine membership for artifact at wrong UTF8 inventory rank", stage="membership")
    first_call = copy.deepcopy(retry)
    first_call["events"][0] = call(identifier="c0")
    save("bad-inclusion-first-call", included(rebind(first_call), 0), 2, "Genuine membership for first-position call", stage="membership")
    retry_early = copy.deepcopy(retry)
    retry_early["events"][1]["retry_of"] = "earlier"
    save("bad-inclusion-retry-position", included(rebind(retry_early), 1), 2, "Genuine membership: retry lacks two earlier positions", stage="membership")
    calls_zero = copy.deepcopy(retry)
    calls_zero["result"]["resources"]["calls"] = 0
    save("bad-inclusion-call-count", included(calls_zero, 1), 2, "Genuine membership: included call but declared zero calls", stage="membership")
    too_short = copy.deepcopy(retry)
    too_short["events"] = [start(), call(), end()]
    save("bad-inclusion-completed-size", included(rebind(too_short), 0), 2, "Genuine membership: completed trace cannot fit samples and calls", stage="membership")
    no_end_room = copy.deepcopy(retry)
    no_end_room["events"][3] = call(identifier="c3")
    # Declared calls retained at 2 to isolate the visible post-position bound.
    save("bad-inclusion-no-end-room", included(rebind(no_end_room), 3), 2, "Genuine membership: completed call leaves no sample_end slot", stage="membership")

    # Round-one main review: fixed counterexamples for each reported gap.
    changed("bad-completed-reason", fixture,
            lambda v: (v["result"].update(reason="completed reason"), v["events"][-1].update(reason="completed reason")),
            "Completed result and terminal must both have null reason", "bindings")
    second_score = copy.deepcopy(fixture)
    second_score["artifacts"]["second-score.json"] = second_score["artifacts"]["score.json"]
    second_score["result"]["inventory"]["second-score.json"] = copy.deepcopy(second_score["result"]["inventory"]["score.json"])
    save("bad-second-score-role", rebind(second_score), 2, "Supplied score requires exactly one score-role inventory entry", stage="bindings")
    missing_dataset = copy.deepcopy(fixture)
    del missing_dataset["artifacts"]["dataset.json"]
    del missing_dataset["result"]["inventory"]["dataset.json"]
    rebind(missing_dataset)
    save("bad-inclusion-no-pinned-dataset", included(missing_dataset, 5), 2,
         "Valid terminal membership cannot override absent pinned dataset inventory binding", stage="bindings")
    for name, filename, family in (("bad-future-fixture-dataset", "dataset.json", "fixture-dataset"),
                                   ("bad-future-fixture-scores", "score.json", "fixture-scores")):
        future = copy.deepcopy(fixture)
        payload = json.loads(future["artifacts"][filename])
        payload["format"] = f"prove.{family}.v2"
        raw = packed(payload)
        future["artifacts"][filename] = raw
        entry = future["result"]["inventory"][filename]
        entry.update(sha256=sha(raw), bytes=len(raw))
        if filename == "dataset.json":
            future["manifest"]["dataset"]["sha256"] = sha(raw)
        else:
            future["result"]["score"].update(sha256=sha(raw), bytes=len(raw))
        save(name, rebind(future), 4, "Future fixture payload format is unsupported; every artifact/core/record commitment rebound", stage="scoring")
    changed("bad-future-result-score-profile", fixture, lambda v: v["result"]["score"].update(profile="future-score-v9"),
            "Unknown string result score profile is unsupported rather than malformed", "schema", code=4)
    future_event = copy.deepcopy(fixture)
    future_event["events"][0]["kind"] = "future_event"
    save("bad-future-event-kind", record_commit(future_event), 4, "Unknown string event kind is unsupported with correctly rebound tree", stage="records")

    subtotal_manifest = manifest(True, samples=["s1"])
    safe = 9007199254740991
    below = run(subtotal_manifest, {}, [start(), call(tokens=safe // 2), call(identifier="c2", tokens=safe // 2),
                call(identifier="c3", tokens=None), end("aborted", "usage incomplete")], "aborted", "usage incomplete")
    save("run-null-total-safe-subtotal", below, 0, "Null full total retains a known safe subtotal at SAFE-1 without ceilings", unavailable)
    overflow = copy.deepcopy(below)
    overflow["events"][1]["usage"]["input_tokens"] = safe
    overflow["events"][2]["usage"]["input_tokens"] = safe
    save("bad-known-subtotal-overflow", rebind(overflow), 2, "Null full total cannot hide an unsafe derived known subtotal", stage="records")
    copies = copy.deepcopy(fixture)
    copies["artifacts"]["dataset-copy.json"] = copies["artifacts"]["dataset.json"]
    copies["result"]["inventory"]["dataset-copy.json"] = copy.deepcopy(copies["result"]["inventory"]["dataset.json"])
    rebind(copies)
    save("run-multiple-pinned-dataset-copies", copies, 0, "Multiple inventory dataset entries with the same pinned bytes are allowed",
         {"state": "recomputed", "aggregate": {"numerator": 1, "denominator": 2}})
    save("inclusion-multiple-pinned-dataset-copies", included(copies, 5), 0, "Inclusion requires a matching dataset binding, not dataset uniqueness or availability")

    # The event limit applies to a directly visible inclusion leaf as well as
    # full JSONL records. Keep the whole envelope below its separate 8MiB limit.
    sized = run(manifest(True, samples=["s1"]), {}, [start(), call(), finish(), end()])
    event = sized["events"][1]
    event["source"] = ""
    event["source"] = "x" * (1024 * 1024 - len(packed(event)))
    assert len(packed(event)) == 1024 * 1024
    rebind(sized)
    save("inclusion-event-exact-limit", included(sized, 1), 0, "A genuine call membership at the inclusive 1MiB event-byte boundary")
    oversized = copy.deepcopy(sized)
    oversized["events"][1]["source"] += "x"
    assert len(packed(oversized["events"][1])) == 1024 * 1024 + 1
    save("bad-inclusion-event-over-limit", included(rebind(oversized), 1), 2,
         "Genuine membership cannot bypass the 1MiB canonical event-byte limit", stage="membership")
    malformed_future = included(fixture, 5)
    malformed_future["inclusion"]["format"] = "prove.inclusion.v2"
    del malformed_future["inclusion"]["event"]["format"]
    save("bad-inclusion-future-and-missing-event-format", malformed_future, 2,
         "Missing nested format is malformed2 before future outer format unsupported4", stage="schema")
    for name, target, replacement in (("bad-inclusion-future-missing-manifest-format", "manifest", None),
                                      ("bad-inclusion-future-nonstring-result-format", "result", 17),
                                      ("bad-inclusion-future-nonstring-event-format", "event", False)):
        mixed = included(fixture, 5)
        mixed["inclusion"]["format"] = "prove.inclusion.v2"
        if replacement is None:
            del mixed["inclusion"][target]["format"]
        else:
            mixed["inclusion"][target]["format"] = replacement
        save(name, mixed, 2, "All visible discriminator shapes precede unsupported-string classification", stage="schema")
    changed("bad-future-manifest-missing-result-format", fixture,
            lambda v: (v["manifest"].update(format="prove.manifest.v2"), v["result"].pop("format")),
            "Full scope cannot interpret dependent result semantics under an unsupported manifest; returns4", "schema", code=4)
    # Round two: each full-run prerequisite is accepted before its dependent
    # core is interpreted; a core's format shape precedes its own profiles.
    changed("bad-missing-manifest-format-future-profile", fixture,
            lambda v: (v["manifest"].pop("format"), v["manifest"].update(profile="future-profile-v9")),
            "Missing prerequisite manifest format is malformed before its unsupported profile", "schema")
    changed("bad-missing-result-format-future-profile", fixture,
            lambda v: (v["result"].pop("format"), v["result"].update(profile="future-profile-v9")),
            "Missing result format is malformed before its unsupported profile", "schema")
    changed("bad-manifest-field-future-result", fixture,
            lambda v: (v["manifest"].update(extra=True), v["result"].update(format="prove.result.v2")),
            "Closed prerequisite manifest schema fails before dependent result version", "schema")
    changed("bad-manifest-semantics-future-result", fixture,
            lambda v: (v["manifest"]["attempts"].append(copy.deepcopy(v["manifest"]["attempts"][0])), v["result"].update(format="prove.result.v2")),
            "Duplicate manifest attempt semantics fail before dependent result version", "schema")
    changed("bad-future-result-valid-manifest", fixture,
            lambda v: v["result"].update(format="prove.result.v2"),
            "A fully accepted manifest allows dependent future result to report unsupported4", "schema", code=4)

    # Hand-specified canonical byte order, independent of both canonical writers.
    canonical = [
        {"name": "utf16-order", "value": {"\ue000": 1, "😀": 2, "a": 3},
         "hex": ('{"a":3,"😀":2,"\ue000":1}').encode().hex()},
        {"name": "controls", "value": "\x00\b\t\n\f\r\x1f\"\\/", "hex": b'"\\u0000\\b\\t\\n\\f\\r\\u001f\\"\\\\/"'.hex()},
        {"name": "unicode-preserved", "value": ["é", "e\u0301", "東京", "\u2028"], "hex": '["é","é","東京","\u2028"]'.encode().hex()},
        {"name": "safe-integers", "value": [-9007199254740991, 0, 9007199254740991], "hex": b'[-9007199254740991,0,9007199254740991]'.hex()},
    ]
    trees = []
    for size in (0, 1, 2, 3, 5, 7, 8, 9):
        leaves = [f"independent-wire-leaf:{n}".encode() for n in range(size)]
        trees.append({"size": size, "leaves": [b64(leaf) for leaf in leaves], "root": tree(leaves).hex(),
                      "paths": [{"index": position, "siblings": path(leaves, position)} for position in range(size)]})
    (DEST / "canonical.json").write_bytes(packed(canonical))
    (DEST / "trees.json").write_bytes(packed(trees))
    (DEST / "index.json").write_bytes(packed({"format": "prove.conformance-index.v1", "cases": index}))
    assert len(index) >= 60
