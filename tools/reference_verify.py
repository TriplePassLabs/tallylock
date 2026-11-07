#!/usr/bin/env python3
"""Independent, offline consumer of the published TallyLock v1 materialized wire.

Only protocol-v1.json is shared with the product. No producer code is imported.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata

from jsonschema import Draft202012Validator


LIMIT = 8 * 1024 * 1024
SAFE = 9007199254740991
USAGE = ("input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "duration_ms")
HEX = re.compile(r"[0-9a-f]{64}\Z")
LIMITATIONS = [
    "Checks materialized bytes only.",
    "No production-filesystem checks: paths are data, never opened.",
    "No anchors or chain authentication are checked.",
    "Execution, model identity and issuer identity are unverified.",
]


class Invalid(ValueError):
    pass


class Unsupported(Invalid):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def _profile(value, depth=0):
    require(depth <= 64, "JSON depth exceeds 64")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-SAFE <= value <= SAFE, "unsafe JSON integer")
    elif type(value) is str:
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "lone surrogate")
    elif type(value) is list:
        for item in value:
            _profile(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            require(type(key) is str, "object keys must be strings")
            _profile(key, depth + 1)
            _profile(item, depth + 1)
    else:
        raise Invalid("only integer-profile JSON values are supported")


def _quoted(value):
    # RFC8785 uses the JSON short escapes and lowercase control hex escapes.
    short = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r", 34: '\\"', 92: "\\\\"}
    return '"' + "".join(short.get(ord(c), f"\\u{ord(c):04x}" if ord(c) < 32 else c) for c in value) + '"'


def canonical_bytes(value):
    """Serialize the integer-only JCS profile, sorting UTF16 code units."""
    _profile(value)

    def emit(item):
        if item is None:
            return "null"
        if type(item) is bool:
            return "true" if item else "false"
        if type(item) is int:
            return str(item)
        if type(item) is str:
            return _quoted(item)
        if type(item) is list:
            return "[" + ",".join(map(emit, item)) + "]"
        keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_quoted(key) + ":" + emit(item[key]) for key in keys) + "}"

    result = emit(value).encode("utf-8")
    require(len(result) <= LIMIT, "canonical JSON exceeds 8MiB")
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _forbidden_number(value):
    raise Invalid("float or nonfinite JSON number")


def _integer(value):
    require(len(value.lstrip("-")) <= 16, "unsafe JSON integer")
    number = int(value)
    require(-SAFE <= number <= SAFE, "unsafe JSON integer")
    return number


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= LIMIT, "JSON exceeds 8MiB or is not bytes")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_int=_integer, parse_float=_forbidden_number, parse_constant=_forbidden_number)
        _profile(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("invalid strict UTF8 JSON") from exc


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _tree_hash(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + _tree_hash(leaves[:split]) + _tree_hash(leaves[split:])).digest()


def tree_root(leaves):
    require(type(leaves) is list and all(type(leaf) is bytes for leaf in leaves), "tree requires byte leaves")
    return _tree_hash(leaves).hex()


def membership(leaf, index, size, siblings, root):
    """Recover the branch geometry first, then fold leaf-to-root siblings."""
    if (type(leaf) is not bytes or type(index) is not int or type(size) is not int
            or not 0 <= index < size <= SAFE or type(siblings) is not list
            or type(root) is not str or HEX.fullmatch(root) is None):
        return False
    branch = []
    position, width = index, size
    while width > 1:
        split = 1 << ((width - 1).bit_length() - 1)
        right = position >= split
        branch.append(right)
        position, width = (position - split, width - split) if right else (position, split)
    if len(siblings) != len(branch):
        return False
    digest = hashlib.sha256(b"\x00" + leaf).digest()
    for right, sibling in zip(reversed(branch), siblings):
        if type(sibling) is not str or HEX.fullmatch(sibling) is None:
            return False
        other = bytes.fromhex(sibling)
        digest = hashlib.sha256(b"\x01" + (other + digest if right else digest + other)).digest()
    return digest.hex() == root


_VALIDATORS = None


def _schema(name, value):
    global _VALIDATORS
    if _VALIDATORS is None:
        source = Path(__file__).resolve().parents[1] / "src/tallylock/data/schemas/protocol-v1.json"
        document = strict_json(source.read_bytes())

        def local_refs(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    require(key != "$ref" or (type(item) is str and item.startswith("#/")), "nonlocal schema reference")
                    local_refs(item)
            elif isinstance(node, list):
                for item in node:
                    local_refs(item)

        local_refs(document)
        # Every ref was checked above; the validator can only traverse this
        # embedded document. No URI from a case is a schema reference.
        _VALIDATORS = {key: Draft202012Validator({"$ref": f"#/$defs/{key}", "$defs": document["$defs"]})
                       for key in document["$defs"]}
    error = next(_VALIDATORS[name].iter_errors(value), None)
    if error is not None:
        raise Invalid(f"{name} schema violation at {'/'.join(map(str, error.absolute_path))}: {error.message[:500]}")


def _format_shapes(*pairs):
    # Missing/nonstring discriminators are malformed even when a peer's
    # discriminator is a future string. Inspect visible shapes before versions.
    for family, value in pairs:
        require(type(value) is dict, f"{family} must be an object")
        require(type(value.get("format")) is str, f"{family} format must be a present string")


def _version(value, family):
    require(type(value) is dict, f"{family} must be an object")
    version = value.get("format")
    expected = f"prove.{family}.v1"
    if type(version) is str and version != expected:
        raise Unsupported(f"unsupported {family} format")


def _core_schema(manifest, result):
    for family, value in (("manifest", manifest), ("result", result)):
        _version(value, family)
        if type(value.get("profile")) is str and value["profile"] not in ("trace-v1", "artifacts-v1"):
            raise Unsupported("unsupported run profile")
    if type(manifest.get("scorer")) is dict:
        profile = manifest["scorer"].get("profile")
        if type(profile) is str and profile not in ("recorded-only-v1", "fixture-exact-v1"):
            raise Unsupported("unsupported scorer profile")
    if type(result.get("score")) is dict:
        profile = result["score"].get("profile")
        if type(profile) is str and profile not in ("recorded-only-v1", "fixture-exact-v1"):
            raise Unsupported("unsupported result score profile")
    if type(result.get("records")) is dict:
        algorithm = result["records"].get("tree_algorithm")
        if type(algorithm) is str and algorithm != "rfc9162-sha256":
            raise Unsupported("unsupported tree algorithm")
    _schema("manifest", manifest)
    _schema("result", result)


def _one_full_core(value, family):
    # A materialized run accepts each prerequisite before interpreting the next
    # core. Within a core, a missing/nonstring format is never a future profile.
    _format_shapes((family, value))
    _version(value, family)
    if type(value.get("profile")) is str and value["profile"] not in ("trace-v1", "artifacts-v1"):
        raise Unsupported("unsupported run profile")
    selector = value.get("scorer" if family == "manifest" else "score")
    if type(selector) is dict:
        profile = selector.get("profile")
        if type(profile) is str and profile not in ("recorded-only-v1", "fixture-exact-v1"):
            raise Unsupported("unsupported scorer profile")
    if family == "result" and type(value.get("records")) is dict:
        algorithm = value["records"].get("tree_algorithm")
        if type(algorithm) is str and algorithm != "rfc9162-sha256":
            raise Unsupported("unsupported tree algorithm")
    _schema(family, value)


def _manifest_semantics(manifest):
    attempts = {attempt["id"]: attempt["sample_ids"] for attempt in manifest["attempts"]}
    require(len(attempts) == len(manifest["attempts"]), "duplicate attempt ID")
    for samples in attempts.values():
        require((not samples) if manifest["profile"] == "artifacts-v1" else bool(samples), "attempt/profile sample mismatch")
    fixture = manifest["scorer"]["profile"] == "fixture-exact-v1"
    require(not fixture or (manifest["profile"] == "trace-v1" and manifest["dataset"]["sha256"] is not None), "fixture profile needs trace and pinned dataset")
    return attempts


def _base64(value):
    require(type(value) is str and len(value) <= 4 * ((LIMIT + 2) // 3), "invalid or oversized base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Invalid("invalid base64") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical base64")
    return raw


def _path(path):
    require(type(path) is str and path and unicodedata.normalize("NFC", path) == path, "artifact path must be nonempty NFC")
    require(len(path.encode("utf-8")) <= 1024, "artifact path exceeds 1024 bytes")
    require("\\" not in path and not any(unicodedata.category(c) == "Cc" for c in path), "control or backslash in artifact path")
    parts = path.split("/")
    for component in parts:
        require(component not in ("", ".", "..") and ":" not in component and not component.endswith((".", " ")),
                "ambiguous artifact path component")
        require(len(component.encode("utf-8")) <= 255, "artifact component exceeds 255 bytes")
    return parts


def _inventory(inventory):
    prefixes = {}
    files = set(inventory)
    for path in inventory:
        parts = _path(path)
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            folded = unicodedata.normalize("NFC", prefix.casefold())
            require(folded not in prefixes or prefixes[folded] == prefix, "casefold/NFC path collision")
            prefixes[folded] = prefix
            require(length == len(parts) or prefix not in files, "file is an artifact directory prefix")


def _bindings(manifest, result, registration):
    require(result["registration_id"] == registration, "registration ID does not bind manifest")
    attempts = _manifest_semantics(manifest)
    require(result["attempt_id"] in attempts, "undeclared selected attempt")
    require(result["profile"] == manifest["profile"], "profile binding mismatch")
    fixture = manifest["scorer"]["profile"] == "fixture-exact-v1"
    if result["outcome"] == "completed":
        require(result["reason"] is None, "completed result reason must be null")
    else:
        require(bool(result["reason"]), "unsuccessful result needs a reason")
    _inventory(result["inventory"])
    if manifest["profile"] == "artifacts-v1":
        require(all(value is None for value in result["resources"].values()), "artifact resources must be unknown")
        require(result["outcome"] != "completed" or bool(result["inventory"]), "completed artifacts need an artifact")
        require(result["records"]["count"] == len(result["inventory"]) + 1, "artifact record count mismatch")
    score = result["score"]
    if score is not None:
        require(sum(entry["role"] == "score" for entry in result["inventory"].values()) == 1,
                "supplied score needs exactly one score-role inventory entry")
        path = score["path"]
        require(path in result["inventory"], "score artifact missing from inventory")
        entry = result["inventory"][path]
        require(entry["role"] == "score" and entry["sha256"] == score["sha256"] and entry["bytes"] == score["bytes"], "score inventory binding mismatch")
        require(score["profile"] == manifest["scorer"]["profile"], "score profile mismatch")
        if fixture:
            require(any(entry["role"] == "dataset" and entry["sha256"] == manifest["dataset"]["sha256"]
                        for entry in result["inventory"].values()), "pinned fixture dataset inventory binding missing")
            aggregate = score["aggregate"]
            require(aggregate is not None and aggregate["denominator"] == len(attempts[result["attempt_id"]])
                    and aggregate["numerator"] <= aggregate["denominator"], "fixture aggregate bounds mismatch")
    require(not (fixture and result["outcome"] == "completed") or score is not None, "completed fixture score unavailable")
    return attempts[result["attempt_id"]]


def _event(event, registration, result):
    require(len(canonical_bytes(event)) <= 1024 * 1024, "event exceeds 1MiB")
    _format_shapes(("event", event))
    _version(event, "event")
    if type(event.get("kind")) is str and event["kind"] not in ("artifact", "sample_start", "call", "sample_end", "attempt_end"):
        raise Unsupported("unsupported event kind")
    _schema("event", event)
    require(event["registration_id"] == registration and event["attempt_id"] == result["attempt_id"], "event core binding mismatch")
    kind = event["kind"]
    if result["profile"] == "artifacts-v1":
        require(kind in ("artifact", "attempt_end"), "trace event in artifacts profile")
    else:
        require(kind != "artifact", "artifact event in trace profile")
    if kind == "attempt_end":
        require(event["outcome"] == result["outcome"] and event["reason"] == result["reason"], "terminal outcome/reason mismatch")
    elif kind == "artifact":
        entry = result["inventory"].get(event["path"])
        require(entry is not None and entry["sha256"] == event["sha256"] and entry["bytes"] == event["bytes"], "artifact event inventory binding mismatch")
        rank = sorted(result["inventory"], key=lambda path: path.encode("utf-8")).index(event["path"])
        require(event["index"] == rank, "artifact event rank mismatch")
    elif kind == "call":
        require(event["retry_of"] != event["call_id"], "call cannot retry itself")
        for field in ("input", "output"):
            require(event[field] is None or event[field] in result["inventory"], "dangling call artifact reference")


def _records(raw, manifest, result, registration, samples):
    require(len(raw) <= 64 * 1024 * 1024, "records exceed limit")
    binding = result["records"]
    require(len(raw) == binding["bytes"] and _sha(raw) == binding["sha256"], "records byte binding mismatch")
    require(not raw or raw.endswith(b"\n"), "records must end with LF")
    lines = raw[:-1].split(b"\n") if raw else []
    require(len(lines) == binding["count"], "record count mismatch")
    events = []
    for index, line in enumerate(lines):
        require(len(line) <= 1024 * 1024, "event exceeds 1MiB")
        event = strict_json(line)
        require(canonical_bytes(event) == line, "event is not canonical")
        _event(event, registration, result)
        require(event["index"] == index, "record index is not contiguous")
        events.append(event)
    require(tree_root(lines) == binding["root"], "record tree root mismatch")
    require(not events or events[-1]["kind"] == "attempt_end", "trace lacks final attempt_end")
    require(all(e["kind"] != "attempt_end" for e in events[:-1]), "records after attempt_end")
    if manifest["profile"] == "artifacts-v1":
        require(len(events) == len(result["inventory"]) + 1, "artifact event count mismatch")
        require(all(e["kind"] == "artifact" for e in events[:-1]), "missing artifact event")
        return
    require(bool(events) or result["outcome"] != "completed", "completed trace is empty")
    started, ended, calls = set(), set(), {}
    for event in events:
        kind = event["kind"]
        if kind == "attempt_end":
            continue
        sample = event["sample_id"]
        require(sample in samples, "undeclared sample")
        if kind == "sample_start":
            require(sample not in started, "duplicate sample_start")
            started.add(sample)
        else:
            require(sample in started and sample not in ended, "event outside open sample")
            if kind == "sample_end":
                ended.add(sample)
            else:
                call = event["call_id"]
                require(call not in calls, "duplicate call ID")
                retry = event["retry_of"]
                require(retry is None or (retry in calls and calls[retry]["sample_id"] == sample), "retry must name an earlier call in the same sample")
                calls[call] = event
    require(result["outcome"] != "completed" or ended == set(samples), "completed sample coverage incomplete")
    totals = {"calls": len(calls)}
    subtotals = {"calls": len(calls)}
    for field in USAGE:
        observed = [event["usage"][field] for event in calls.values()]
        subtotals[field] = sum(value for value in observed if value is not None)
        require(subtotals[field] <= SAFE, "derived known usage subtotal is not a safe integer")
        totals[field] = None if None in observed else subtotals[field]
    require(totals == result["resources"], "recorded resources do not equal call totals")
    exceeded = any(ceiling is not None and subtotals[field] > ceiling for field, ceiling in
                   (("calls", manifest["budget"]["max_calls"]), ("input_tokens", manifest["budget"]["max_input_tokens"]),
                    ("output_tokens", manifest["budget"]["max_output_tokens"])))
    require(not exceeded or result["outcome"] == "budget_exceeded", "known budget subtotal exceeds ceiling without budget_exceeded")


def _score(manifest, result, artifacts, samples):
    score = result["score"]
    if score is None:
        return {"state": "unavailable", "aggregate": None}
    if manifest["scorer"]["profile"] == "recorded-only-v1":
        return {"state": "recorded_only", "aggregate": score["aggregate"]}
    candidates = [path for path, entry in result["inventory"].items()
                  if entry["role"] == "dataset" and entry["sha256"] == manifest["dataset"]["sha256"]]
    require(bool(candidates), "pinned fixture dataset artifact missing")
    dataset = strict_json(artifacts[candidates[0]])
    observed = strict_json(artifacts[score["path"]])
    _version(dataset, "fixture-dataset")
    _version(observed, "fixture-scores")
    _schema("fixtureDataset", dataset)
    _schema("fixtureScores", observed)
    expected = {row["id"]: row["expected"] for row in dataset["samples"]}
    actual = {row["id"]: row["observed"] for row in observed["samples"]}
    require(len(expected) == len(dataset["samples"]) and len(actual) == len(observed["samples"]), "duplicate fixture sample")
    require(set(expected) == set(actual) == set(samples), "fixture sample coverage mismatch")
    aggregate = {"numerator": sum(expected[key] == actual[key] for key in samples), "denominator": len(samples)}
    require(score["aggregate"] == observed["aggregate"] == aggregate, "fixture exact math mismatch")
    return {"state": "recomputed", "aggregate": aggregate}


def _inclusion(value, manifest, result, registration, receipt, samples):
    _version(value, "inclusion")
    _event(value.get("event"), registration, result)
    _schema("inclusion", value)
    require(value["registration_id"] == registration and value["receipt_id"] == receipt, "inclusion ID mismatch")
    for proof in value["proofs"].values():
        if proof is not None:
            _base64(proof)
    event, index, size = value["event"], value["index"], value["size"]
    require(size == result["records"]["count"] and index == event["index"] and index < size, "inclusion position/count mismatch")
    require((event["kind"] == "attempt_end") == (index == size - 1), "visible terminal position contradiction")
    if result["profile"] == "trace-v1":
        calls = result["resources"]["calls"]
        minimum = (2 * len(samples) + calls + 1) if result["outcome"] == "completed" else (calls + 2 if calls else 1)
        require(size >= minimum, "trace record count cannot fit declared samples/calls/terminal")
        if event["kind"] != "attempt_end":
            require(event["sample_id"] in samples, "included undeclared sample")
            require(index != 0 or event["kind"] == "sample_start", "first trace record must be sample_start")
        if event["kind"] == "call":
            retry = event["retry_of"] is not None
            require(index >= (2 if retry else 1) and calls >= (2 if retry else 1), "included call has impossible position/count")
        if result["outcome"] == "completed" and event["kind"] in ("sample_start", "call"):
            require(index + 2 < size, "completed sample needs room for sample_end and terminal")
    require(membership(canonical_bytes(event), index, size, value["siblings"], result["records"]["root"]), "membership path mismatch or unused sibling")


def _report():
    return {"format": "prove.reference.v1", "code": 2, "kind": None, "registration_id": None,
            "receipt_id": None, "root": None, "score": None,
            "checks": {key: "not_checked" for key in ("canonical", "bindings", "artifacts", "records", "membership", "scoring")},
            "errors": [], "limitations": list(LIMITATIONS)}


def verify_case(value):
    report = _report()
    stage = "canonical"
    try:
        require(type(value) is dict, "case envelope must be an object")
        require(value.get("kind") in ("run", "inclusion"), "unknown case kind")
        report["kind"] = value["kind"]
        _version(value, "conformance-case")
        require(value.get("format") == "prove.conformance-case.v1", "invalid case format")
        canonical_bytes(value)
        expected = {"format", "kind", "manifest", "result", "records", "artifacts"} if value["kind"] == "run" else {"format", "kind", "inclusion"}
        require(set(value) == expected, "case envelope has missing or unknown fields")
        if value["kind"] == "run":
            manifest_raw, result_raw = _base64(value["manifest"]), _base64(value["result"])
            manifest, result = strict_json(manifest_raw), strict_json(result_raw)
            require(canonical_bytes(manifest) == manifest_raw and canonical_bytes(result) == result_raw, "core bytes are not canonical")
        else:
            inclusion = value["inclusion"]
            require(type(inclusion) is dict, "inclusion must be an object")
            manifest, result = inclusion.get("manifest"), inclusion.get("result")
            manifest_raw, result_raw = canonical_bytes(manifest), canonical_bytes(result)
        report["checks"]["canonical"] = "checked"
        stage = "bindings"
        if value["kind"] == "inclusion":
            _format_shapes(("inclusion", inclusion), ("manifest", manifest), ("result", result), ("event", inclusion.get("event")))
            _core_schema(manifest, result)
        else:
            _one_full_core(manifest, "manifest")
            _manifest_semantics(manifest)
            _one_full_core(result, "result")
        registration, receipt = _sha(manifest_raw), _sha(result_raw)
        report.update(registration_id=registration, receipt_id=receipt, root=result["records"]["root"])
        samples = _bindings(manifest, result, registration)
        report["checks"]["bindings"] = "checked"
        if value["kind"] == "inclusion":
            stage = "membership"
            _inclusion(inclusion, manifest, result, registration, receipt, samples)
            report["checks"]["membership"] = "checked"
            report["limitations"].append("Inclusion checks membership and finite visible contradictions only; full history, availability, totals, coverage, budgets and score math are not checked.")
        else:
            stage = "artifacts"
            require(type(value["artifacts"]) is dict, "materialized artifacts must be a mapping")
            _inventory(value["artifacts"])
            require(set(value["artifacts"]) == set(result["inventory"]), "materialized artifact set differs from inventory")
            artifacts = {path: _base64(encoded) for path, encoded in value["artifacts"].items()}
            for path, raw in artifacts.items():
                entry = result["inventory"][path]
                require(len(raw) == entry["bytes"] and _sha(raw) == entry["sha256"], "artifact byte binding mismatch")
            report["checks"]["artifacts"] = "checked"
            stage = "records"
            _records(_base64(value["records"]), manifest, result, registration, samples)
            report["checks"]["records"] = "checked"
            stage = "scoring"
            report["score"] = _score(manifest, result, artifacts, samples)
            report["checks"]["scoring"] = "checked"
        report["code"] = 0
    except Unsupported as exc:
        report["code"] = 4
        report["checks"][stage] = "unsupported"
        report["errors"] = [str(exc)[:1024]]
    except (Invalid, RecursionError, UnicodeError, TypeError, KeyError, OverflowError) as exc:
        report["checks"][stage] = "invalid"
        report["errors"] = [str(exc)[:1024] or "malformed materialized evidence"]
    return report


def _read_case(path):
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK")):
        raise OSError("regular no-follow file reading is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("case input must be a regular file")
        require(before.st_size <= LIMIT, "case input exceeds 8MiB")
        chunks, length = [], 0
        while True:
            block = os.read(descriptor, min(65536, LIMIT + 1 - length))
            if not block:
                break
            length += len(block)
            require(length <= LIMIT, "case input exceeds 8MiB")
            chunks.append(block)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise OSError("case changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path, help="bounded regular materialized-case JSON file")
    args = parser.parse_args(argv)
    try:
        report = verify_case(strict_json(_read_case(args.case)))
    except OSError as exc:
        report = _report()
        report["code"] = 5
        report["errors"] = [f"local case I/O: {str(exc)[:900]}"]
    except (Invalid, RecursionError) as exc:
        report = _report()
        report["checks"]["canonical"] = "invalid"
        report["errors"] = [str(exc)[:1024]]
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return report["code"]


if __name__ == "__main__":
    raise SystemExit(main())
