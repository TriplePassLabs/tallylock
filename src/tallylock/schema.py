"""Closed protocol contracts and deterministic bindings, without producer I/O."""

from __future__ import annotations

import base64
import binascii
import hashlib
from importlib.resources import files
import secrets

from jsonschema import Draft202012Validator

from . import canonical
from .paths import validate_path, validate_paths
from .errors import TallyLockError


_SCHEMA = canonical.loads(
    files("tallylock").joinpath("data/schemas/protocol-v1.json").read_bytes()
)
_VALIDATORS = {
    name: Draft202012Validator({"$defs": _SCHEMA["$defs"], "$ref": f"#/$defs/{name}"})
    for name in ("manifest", "result", "event", "inclusion", "chain", "inventoryEntry",
                 "fixtureDataset", "fixtureScores")
}
_PROFILES = ("artifacts-v1", "trace-v1")
_SCORERS = ("recorded-only-v1", "fixture-exact-v1")
_KINDS = ("artifact", "sample_start", "call", "sample_end", "attempt_end")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TallyLockError(message)


def _supported(value: dict, key: str, supported: tuple[str, ...]) -> None:
    candidate = value.get(key)
    if isinstance(candidate, str) and candidate not in supported:
        raise TallyLockError(f"unsupported {key}: {candidate!r}", code=4)


def _formats(value: dict, kind: str) -> None:
    _require(isinstance(value, dict), f"{kind} must be an object")
    _require(isinstance(value.get("format"), str), "format must be a string")
    if kind == "inclusion":
        for embedded in ("manifest", "result", "event"):
            _formats(value.get(embedded), embedded)


def _versions(value: dict, kind: str) -> None:
    _supported(value, "format", (f"prove.{kind}.v1",))
    if kind in ("manifest", "result"):
        _supported(value, "profile", _PROFILES)
    if kind == "manifest" and isinstance(value.get("scorer"), dict):
        _supported(value["scorer"], "profile", _SCORERS)
    if kind == "result":
        if isinstance(value.get("records"), dict):
            _supported(value["records"], "tree_algorithm", ("rfc9162-sha256",))
        if isinstance(value.get("score"), dict):
            _supported(value["score"], "profile", _SCORERS)
    if kind == "event":
        _supported(value, "kind", _KINDS)
    if kind == "inclusion":
        for embedded in ("manifest", "result", "event"):
            if isinstance(value.get(embedded), dict):
                _versions(value[embedded], embedded)


def _shape(value: dict, kind: str) -> None:
    encoded = canonical.dumps(value)
    if kind == "event":
        _require(len(encoded) <= 1024 * 1024, "event exceeds 1 MiB")
    # A missing or incorrectly typed discriminator is malformed, not unsupported.
    _formats(value, kind)
    _versions(value, kind)
    error = next(_VALIDATORS[kind].iter_errors(value), None)
    if error is not None:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise TallyLockError(f"invalid {kind} at {location}: {error.message}")


def _attempt(manifest: dict, attempt_id: str) -> dict:
    for attempt in manifest["attempts"]:
        if attempt["id"] == attempt_id:
            return attempt
    raise TallyLockError(f"undeclared attempt: {attempt_id!r}")


def _outcome(value: dict) -> None:
    if value["outcome"] == "completed":
        _require(value["reason"] is None, "completed outcome requires a null reason")
    else:
        _require(isinstance(value["reason"], str) and bool(value["reason"]),
                 "non-completed outcome requires a nonempty reason")


def validate_manifest(value: dict) -> dict:
    """Validate a registration's shape and declared profile constraints."""
    _shape(value, "manifest")
    attempts = value["attempts"]
    _require(len({item["id"] for item in attempts}) == len(attempts),
             "attempt IDs must be unique")
    if value["profile"] == "artifacts-v1":
        _require(all(not item["sample_ids"] for item in attempts),
                 "artifact attempts require empty sample_ids")
        _require(value["scorer"]["profile"] == "recorded-only-v1",
                 "artifact profile requires recorded-only scoring")
    else:
        _require(all(item["sample_ids"] for item in attempts),
                 "trace attempts require declared samples")
    if value["scorer"]["profile"] == "fixture-exact-v1":
        _require(value["profile"] == "trace-v1" and value["dataset"]["sha256"] is not None,
                 "fixture scoring requires a trace and pinned dataset")
    return value


def validate_artifact_path(path: str) -> str:
    """Validate a portable NFC path, preserving the producer's exact spelling."""
    return validate_path(path)


def validate_inventory_paths(paths) -> None:
    """Reject collisions in full paths and directory prefixes without renaming."""
    validate_paths(paths)


def validate_inventory(value: dict) -> dict:
    """Validate a complete inventory with the packaged entry contract."""
    _require(isinstance(value, dict), "inventory must be an object")
    canonical.dumps(value)
    validate_inventory_paths(value)
    for path, entry in value.items():
        error = next(_VALIDATORS["inventoryEntry"].iter_errors(entry), None)
        if error is not None:
            location = ".".join(str(part) for part in error.absolute_path) or path
            raise TallyLockError(f"invalid inventory entry at {location}: {error.message}")
    return value


def _fixture_payload(value: dict, kind: str) -> dict:
    """Validate one bounded, closed fixture payload without canonicalizing its source bytes."""
    _require(isinstance(value, dict), f"{kind} must be an object")
    encoded = canonical.dumps(value)
    _require(len(encoded) <= 8 * 1024 * 1024, f"{kind} exceeds 8 MiB")
    expected_format = {"fixtureDataset": "prove.fixture-dataset.v1",
                       "fixtureScores": "prove.fixture-scores.v1"}[kind]
    candidate = value.get("format")
    if isinstance(candidate, str) and candidate != expected_format:
        raise TallyLockError(f"unsupported format: {candidate!r}", code=4)
    error = next(_VALIDATORS[kind].iter_errors(value), None)
    if error is not None:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise TallyLockError(f"invalid {kind} at {location}: {error.message}")
    samples = value["samples"]
    _require(len({item["id"] for item in samples}) == len(samples), f"{kind} sample IDs must be unique")
    aggregate = value.get("aggregate")
    if aggregate is not None:
        _require(aggregate["denominator"] == len(samples),
                 "fixture aggregate denominator must count samples")
        _require(aggregate["numerator"] <= aggregate["denominator"],
                 "fixture aggregate numerator exceeds denominator")
    return value


def validate_fixture_dataset(value: dict) -> dict:
    """Validate a closed fixture dataset payload."""
    return _fixture_payload(value, "fixtureDataset")


def validate_fixture_scores(value: dict) -> dict:
    """Validate a closed fixture score payload."""
    return _fixture_payload(value, "fixtureScores")


def validate_result(value: dict, manifest: dict) -> dict:
    """Bind the result to a manifest without claiming to have read artifacts."""
    _shape(value, "result")
    validate_manifest(manifest)
    _require(value["registration_id"] == canonical.digest(manifest), "registration ID mismatch")
    attempt = _attempt(manifest, value["attempt_id"])
    _require(value["profile"] == manifest["profile"], "result profile differs from manifest")
    _outcome(value)
    validate_inventory(value["inventory"])
    if value["profile"] == "artifacts-v1":
        _require(value["records"]["count"] == len(value["inventory"]) + 1,
                 "artifact record count must include each artifact and one terminal")
        _require(all(item is None for item in value["resources"].values()),
                 "artifact profile resources must all be null")
        if value["outcome"] == "completed":
            _require(bool(value["inventory"]), "completed artifact receipt requires an artifact")
    if value["outcome"] == "completed":
        _require(value["records"]["count"] > 0, "completed result requires records")
    score = value["score"]
    fixture = manifest["scorer"]["profile"] == "fixture-exact-v1"
    if fixture and value["outcome"] == "completed":
        _require(score is not None, "completed fixture result requires a score")
    if score is not None:
        validate_artifact_path(score["path"])
        _require(score["profile"] == manifest["scorer"]["profile"], "score profile mismatch")
        entry = value["inventory"].get(score["path"])
        _require(entry is not None and entry["role"] == "score", "score must reference a score artifact")
        _require(sum(item["role"] == "score" for item in value["inventory"].values()) == 1,
                 "score must resolve to exactly one score artifact")
        _require(entry["sha256"] == score["sha256"] and entry["bytes"] == score["bytes"],
                 "score digest or byte length mismatch")
        if fixture:
            _require(score["aggregate"] is not None, "fixture score requires a complete aggregate")
            aggregate = score["aggregate"]
            _require(aggregate["denominator"] == len(attempt["sample_ids"])
                     and aggregate["numerator"] <= aggregate["denominator"],
                     "fixture aggregate must count the declared samples")
            _require(any(item["role"] == "dataset" and item["sha256"] == manifest["dataset"]["sha256"]
                         for item in value["inventory"].values()),
                     "fixture score requires the pinned dataset artifact")
    return value


class EventValidator:
    """Prepared direct-event validator that snapshots one validated manifest."""

    def __init__(self, manifest: dict, attempt_id: str) -> None:
        validate_manifest(manifest)
        frozen = canonical.loads(canonical.dumps(manifest))
        attempt = _attempt(frozen, attempt_id)
        self._profile = frozen["profile"]
        self._attempt_id = attempt_id
        self._registration_id = hashlib.sha256(canonical.dumps(frozen)).hexdigest()
        self._sample_ids = frozenset(attempt["sample_ids"])

    def validate(self, value: dict) -> dict:
        _shape(value, "event")
        _require(value["registration_id"] == self._registration_id, "event registration ID mismatch")
        _require(value["attempt_id"] == self._attempt_id, "event attempt ID mismatch")
        kind = value["kind"]
        allowed = ("artifact", "attempt_end") if self._profile == "artifacts-v1" else _KINDS[1:]
        _require(kind in allowed, "event kind is not allowed by the manifest profile")
        if kind == "artifact":
            validate_artifact_path(value["path"])
        if kind in ("sample_start", "call", "sample_end"):
            _require(value["sample_id"] in self._sample_ids, "event sample ID is undeclared")
        if kind == "call":
            _require(value["retry_of"] != value["call_id"], "call cannot retry itself")
            for field in ("input", "output"):
                if value[field] is not None:
                    validate_artifact_path(value[field])
        if kind == "attempt_end":
            _outcome(value)
        return value


def validate_event(value: dict, manifest: dict, attempt_id: str) -> dict:
    """Validate one event's direct bindings, leaving trace history to its consumer."""
    # Preserve one-shot historical precedence: malformed/unsupported event shape
    # is reported before any unrelated manifest error.
    _shape(value, "event")
    return EventValidator(manifest, attempt_id).validate(value)


def validate_inclusion(value: dict) -> dict:
    """Check embedded contracts and direct identities, not Merkle or OTS proofs."""
    _shape(value, "inclusion")
    manifest = validate_manifest(value["manifest"])
    result = validate_result(value["result"], manifest)
    event = validate_event(value["event"], manifest, result["attempt_id"])
    _require(value["registration_id"] == canonical.digest(manifest), "inclusion registration ID mismatch")
    _require(value["receipt_id"] == canonical.digest(result), "inclusion receipt ID mismatch")
    _require(value["size"] == result["records"]["count"], "inclusion tree size mismatch")
    _require(value["index"] == event["index"] and value["index"] < value["size"],
             "inclusion index is inconsistent or out of range")
    if event["kind"] == "artifact":
        entry = result["inventory"].get(event["path"])
        _require(entry is not None and all(event[field] == entry[field] for field in ("sha256", "bytes")),
                 "included artifact event differs from inventory")
        ordered_paths = sorted(result["inventory"], key=lambda path: path.encode("utf-8"))
        _require(event["index"] == ordered_paths.index(event["path"]),
                 "included artifact index differs from its inventory rank")
    if event["kind"] == "call":
        for field in ("input", "output"):
            _require(event[field] is None or event[field] in result["inventory"],
                     f"included call has a dangling {field} artifact")
    if event["kind"] == "attempt_end":
        _require(event["index"] == value["size"] - 1, "included attempt_end must be the final record")
        _require(all(event[field] == result[field] for field in ("outcome", "reason")),
                 "included attempt_end differs from result")
    for proof in value["proofs"].values():
        if proof is None:
            continue
        try:
            decoded = base64.b64decode(proof, validate=True)
        except (ValueError, binascii.Error) as error:
            raise TallyLockError("inclusion proof must be canonical base64") from error
        _require(base64.b64encode(decoded).decode("ascii") == proof,
                 "inclusion proof must be canonical base64")
    return value


def validate_chain(value: dict) -> dict:
    """Validate cache syntax and internal heights, without authenticating its source."""
    _shape(value, "chain")
    tip = value["tip"]
    node = value["node"]
    _require(node["blocks"] == tip["height"] and node["headers"] == tip["height"],
             "chain node heights differ from the cached tip")
    _require(not node["initialblockdownload"], "chain node is in initial block download")
    for height_text, block in value["blocks"].items():
        # Check length before int conversion to avoid unbounded integer conversion.
        _require(len(height_text) <= 16, "chain block height exceeds the safe integer range")
        height = int(height_text)
        _require(height <= tip["height"], "cached block height exceeds the tip")
        _require(block["confirmations"] == tip["height"] - height + 1,
                 "cached block confirmations differ from the cached tip")
        if height == tip["height"]:
            _require(block["hash"] == tip["hash"], "cached tip hash differs from its block")
    return value


def default_manifest(name: str = "Evaluation receipt") -> dict:
    """Create an editable domain-neutral manifest with explicit unknown evidence."""
    value = {
        "format": "prove.manifest.v1", "nonce": secrets.token_hex(16), "name": name,
        "description": "", "profile": "artifacts-v1", "attempts": [{"id": "run-1", "sample_ids": []}],
        "dataset": {"name": "unspecified", "sha256": None},
        "model": {"id": "unspecified", "evidence": "self_declared", "sha256": None},
        "harness": {"name": "external", "revision": "unspecified", "config": {}},
        "generation": {"prompt_sha256": None, "parameters": {}},
        "scorer": {"profile": "recorded-only-v1", "revision": "unspecified"},
        "analysis": {"revision": "unspecified", "plan_sha256": None},
        "budget": {"max_calls": None, "max_input_tokens": None, "max_output_tokens": None},
        "stopping_rule": "producer-controlled", "metadata": {},
    }
    return validate_manifest(value)
