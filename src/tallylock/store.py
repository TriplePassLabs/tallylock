"""Immutable receipt cores and recoverable descriptor-relative snapshots."""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

from . import canonical, records, schema
from .errors import TallyLockError
from .filesystem import Directory, WriterLock, _Descriptors, _contains_directory, _directory_names, _problem, _same
from .paths import validate_path, validate_paths


_ROOT_FILES = {"manifest.json", "result.json", "records.jsonl"}
_ROOT_DIRS = {"artifacts", "proofs", ".prove"}
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_JOURNAL = ".prove/seal.json"
_PENDING = ".prove/pending-write.json"
_PENDING_FORMAT = "prove.pending-write.v1"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TallyLockError(message)


def _optional_read(directory: Directory, path: str, *, limit: int = canonical.MAX_JSON_BYTES) -> bytes | None:
    parent, name, parents, identities = directory._parent(path)
    with _Descriptors() as owned:
        owned.add(parent, f"cannot close optional read parent for {path!r}")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            directory._verify_dirs(parents, identities, path)
            return None
        except OSError as error:
            raise _problem(error, f"cannot inspect optional file {path!r}") from error
        owned.add(fd, f"cannot close optional read probe for {path!r}")
        directory._verify_dirs(parents, identities, path)
    # Once the exact initial open succeeds, every stable-read failure propagates.
    return directory.read(path, limit=limit)


def _canonical_object(data: bytes, label: str) -> dict:
    value = canonical.loads(data)
    _require(isinstance(value, dict) and canonical.dumps(value) == data, f"{label} must be exact canonical JSON")
    return value


def _pending(directory: Directory) -> dict | None:
    data = _optional_read(directory, _PENDING, limit=4096)
    if data is None:
        return None
    value = _canonical_object(data, "pending publication")
    _require(set(value) == {"format", "parent", "temp", "final", "sha256", "bytes", "registration_id", "receipt_id"},
             "invalid pending publication fields")
    _require(isinstance(value["format"], str), "invalid pending publication format")
    if value["format"] != _PENDING_FORMAT:
        raise TallyLockError("unsupported pending publication format", code=4)
    for field in ("parent", "temp", "final", "sha256", "registration_id"):
        _require(isinstance(value[field], str), f"invalid pending publication {field}")
    _require(type(value["bytes"]) is int and 0 <= value["bytes"] <= canonical.MAX_SAFE_INTEGER,
             "invalid pending publication bytes")
    _require(_DIGEST.fullmatch(value["sha256"]) is not None and _DIGEST.fullmatch(value["registration_id"]) is not None,
             "invalid pending publication digest")
    _require(value["receipt_id"] is None or (isinstance(value["receipt_id"], str) and _DIGEST.fullmatch(value["receipt_id"]) is not None),
             "invalid pending publication receipt id")
    _require(len(value["temp"]) == 43 and value["temp"].startswith(".prove-tmp-")
             and all(char in "0123456789abcdef" for char in value["temp"][11:]) and value["temp"] != value["final"],
             "invalid pending publication temporary")
    if value["parent"]:
        validate_path(value["parent"], limit=2048)
    validate_path(value["final"], limit=2048)
    parent, _, leaf = value["final"].rpartition("/")
    _require(parent == value["parent"] and leaf and "/" not in value["temp"], "invalid pending publication path")
    return value


def _root(directory: Directory, *, allow_pending: bool = False) -> set[str]:
    try:
        names = set(_directory_names(directory.fd))
        pending = _pending(directory) if allow_pending and ".prove" in names else None
        for name in names:
            allowed = name in _ROOT_FILES | _ROOT_DIRS
            allowed = allowed or (pending is not None and pending["parent"] == "" and name == pending["temp"])
            _require(allowed, f"unknown receipt-root entry: {name!r}")
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            expected = stat.S_ISREG if name in _ROOT_FILES or (pending is not None and name == pending["temp"]) else stat.S_ISDIR
            _require(expected(info.st_mode), f"invalid receipt-root entry type: {name!r}")
        return names
    except OSError as error:
        raise _problem(error, "cannot inspect receipt root") from error


def _authorize_pending(pending: dict, manifest: dict, result: dict | None) -> None:
    manifest_data = canonical.dumps(manifest)
    _require(pending["registration_id"] == hashlib.sha256(manifest_data).hexdigest(), "pending publication registration mismatch")
    if result is None:
        _require(pending["receipt_id"] is None and pending["parent"] == "" and pending["final"] == "manifest.json",
                 "pending publication is not a registration write")
        _require(pending["sha256"] == hashlib.sha256(manifest_data).hexdigest() and pending["bytes"] == len(manifest_data),
                 "pending publication manifest bytes mismatch")
        return
    result_data = canonical.dumps(result)
    _require(pending["receipt_id"] == hashlib.sha256(result_data).hexdigest(), "pending publication receipt mismatch")
    target = pending["final"]
    _require(target in {"records.jsonl", "result.json"} or target.startswith("artifacts/"), "invalid pending publication target")
    if target == "records.jsonl":
        expected = result["records"]
        _require(pending["sha256"] == expected["sha256"] and pending["bytes"] == expected["bytes"],
                 "pending publication records bytes mismatch")
    elif target == "result.json":
        _require(pending["sha256"] == hashlib.sha256(result_data).hexdigest() and pending["bytes"] == len(result_data),
                 "pending publication result bytes mismatch")
    if target.startswith("artifacts/"):
        artifact = target[len("artifacts/"):]
        expected = result["inventory"].get(artifact)
        temporary_artifact = f"{pending['parent'][len('artifacts/'):]}/{pending['temp']}" if pending["parent"] != "artifacts" else pending["temp"]
        _require(expected is not None and temporary_artifact not in result["inventory"]
                 and pending["sha256"] == expected["sha256"] and pending["bytes"] == expected["bytes"],
                 "pending publication artifact is not authorized")


def _set_pending(directory: Directory, manifest: dict, result: dict | None, path: str, digest: str, size: int) -> dict:
    parent, _, final = path.rpartition("/")
    pending = {"format": _PENDING_FORMAT, "parent": parent, "temp": f".prove-tmp-{secrets.token_hex(16)}",
               "final": path, "sha256": digest, "bytes": size, "registration_id": canonical.digest(manifest),
               "receipt_id": None if result is None else hashlib.sha256(canonical.dumps(result)).hexdigest()}
    _authorize_pending(pending, manifest, result)
    directory.atomic_write(_PENDING, canonical.dumps(pending), replace=True)
    _persist_expected(directory, _PENDING, hashlib.sha256(canonical.dumps(pending)).hexdigest(), len(canonical.dumps(pending)))
    return pending


def _clear_pending(directory: Directory) -> None:
    directory.unlink_file(_PENDING)


def _reconcile_pending(directory: Directory, manifest: dict, result: dict | None) -> None:
    pending = _pending(directory)
    if pending is None:
        return
    _authorize_pending(pending, manifest, result)
    temporary = f"{pending['parent']}/{pending['temp']}" if pending["parent"] else pending["temp"]
    # The owned record is durable before destination-parent creation begins.
    # A valid journal authorizes these same directories during finalization.
    if pending["parent"]:
        directory.mkdirs(pending["parent"])
    directory.unlink_file(temporary, missing_ok=True)
    _clear_pending(directory)


def _publish_owned(directory: Directory, manifest: dict, result: dict | None, path: str, data: bytes,
                   *, limit: int = canonical.MAX_JSON_BYTES) -> None:
    existing = _optional_read(directory, path, limit=limit)
    if existing is not None:
        _require(existing == data, f"immutable file conflicts: {path!r}")
        _persist_expected(directory, path, hashlib.sha256(data).hexdigest(), len(data))
        return
    pending = _set_pending(directory, manifest, result, path, hashlib.sha256(data).hexdigest(), len(data))
    with directory.tracked_temporary(pending["temp"]):
        directory.atomic_write(path, data)
    _persist_expected(directory, path, pending["sha256"], pending["bytes"])
    _clear_pending(directory)


def _copy_owned(directory: Directory, source: str, manifest: dict, result: dict, path: str) -> tuple[str, int]:
    entry = result["inventory"][path[len("artifacts/"):]]
    pending = _set_pending(directory, manifest, result, path, entry["sha256"], entry["bytes"])
    with directory.tracked_temporary(pending["temp"]):
        copied = directory.copy_file_to(source, directory, path)
    _require(copied == (pending["sha256"], pending["bytes"]), f"staged artifact changed: {path!r}")
    _persist_expected(directory, path, pending["sha256"], pending["bytes"])
    _clear_pending(directory)
    return copied


def _manifest(directory: Directory) -> dict:
    value = _canonical_object(directory.read("manifest.json"), "manifest")
    schema.validate_manifest(value)
    return value


def load_manifest(receipt: Path) -> dict:
    with Directory(receipt) as directory:
        _root(directory)
        return _manifest(directory)


def _persist_expected(directory: Directory, path: str, digest: str, size: int) -> None:
    _require(directory.persist_file(path) == (digest, size), f"durable bytes differ at {path!r}")


def _publish_exact(directory: Directory, path: str, data: bytes, *, limit: int = canonical.MAX_JSON_BYTES) -> None:
    existing = _optional_read(directory, path, limit=limit)
    if existing is None:
        directory.atomic_write(path, data)
    else:
        _require(existing == data, f"immutable file conflicts: {path!r}")
    _persist_expected(directory, path, hashlib.sha256(data).hexdigest(), len(data))


def register(manifest: dict, receipt: Path) -> str:
    frozen = canonical.dumps(manifest)
    schema.validate_manifest(canonical.loads(frozen))
    registration_id = hashlib.sha256(frozen).hexdigest()
    with Directory(receipt) as directory:
        _root(directory, allow_pending=True)
        with WriterLock(directory):
            _reconcile_pending(directory, manifest, None)
            names = _root(directory)
            if _optional_read(directory, "manifest.json") is None:
                _require(names <= {".prove"}, "new registration requires an otherwise empty receipt root")
            _publish_owned(directory, manifest, None, "manifest.json", frozen)
            _require(directory.read("manifest.json") == frozen, "manifest changed during registration")
    return registration_id


def _ancestor(ancestor: Directory, descendant: Directory) -> bool:
    """Compare opened inodes and ascend descriptors, including pathname aliases."""
    try:
        wanted = os.fstat(ancestor.fd)
        with _Descriptors() as owned:
            current = owned.add(os.dup(descendant.fd), "cannot close ancestry descriptor")
            while True:
                here = os.fstat(current)
                if _same(wanted, here):
                    return True
                parent = owned.add(os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current),
                                   "cannot close ancestry descriptor")
                if _same(here, os.fstat(parent)):
                    return False
                owned.close(current)
                current = parent
    except OSError as error:
        raise _problem(error, "cannot establish source/receipt ancestry") from error


def _artifact_files(directory: Directory, prefix: str) -> dict[str, str]:
    entries = directory._list_entries(prefix, missing_ok=True)
    paths = [path for path, is_file in entries.items() if is_file]
    relative = {path[len(prefix) + 1:]: path for path in paths}
    schema.validate_inventory_paths(relative)
    return relative


def _final_entries(directory: Directory) -> dict[str, bool]:
    return directory._list_entries("artifacts", missing_ok=True)


def _check_data(directory: Directory, manifest: dict, result: dict, prefix: str) -> bytes:
    schema.validate_result(result, manifest)
    artifact_prefix = f"{prefix}/artifacts" if prefix else "artifacts"
    actual = _artifact_files(directory, artifact_prefix)
    inventory = result["inventory"]
    _require(actual.keys() == inventory.keys(), "snapshot artifact path set differs from inventory")
    for path, stored in actual.items():
        entry = inventory[path]
        _require(directory.digest(stored) == (entry["sha256"], entry["bytes"]), f"artifact differs: {path!r}")
    record_path = f"{prefix}/records.jsonl" if prefix else "records.jsonl"
    data = directory.read(record_path, limit=records.MAX_RECORD_BYTES)
    records.check(manifest, result, data)
    return data


def _check_stage(directory: Directory, manifest: dict, token: str) -> tuple[dict, bytes]:
    prefix = f".prove/staging/{token}"
    data = directory.read(f"{prefix}/result.json")
    result = _canonical_object(data, "staged result")
    _check_data(directory, manifest, result, prefix)
    expected = {f"{prefix}/result.json", f"{prefix}/records.jsonl"}
    expected.update(f"{prefix}/artifacts/{path}" for path in result["inventory"])
    _require(set(directory.list_files(prefix)) == expected, "unlisted staged snapshot files")
    return result, data


def _journal(directory: Directory, manifest: dict) -> tuple[dict, bytes, dict, bytes] | None:
    data = _optional_read(directory, _JOURNAL, limit=4096)
    if data is None:
        return None
    value = _canonical_object(data, "seal journal")
    _require(set(value) == {"format", "stage", "registration_id", "receipt_id"}, "invalid seal journal fields")
    _require(isinstance(value["format"], str), "invalid seal journal format")
    if value["format"] != "prove.seal-journal.v1":
        raise TallyLockError("unsupported seal journal format", code=4)
    _require(isinstance(value["stage"], str) and _TOKEN.fullmatch(value["stage"]) is not None,
             "invalid seal journal stage token")
    for field in ("registration_id", "receipt_id"):
        _require(isinstance(value[field], str) and _DIGEST.fullmatch(value[field]) is not None,
                 f"invalid seal journal {field}")
    _require(value["registration_id"] == canonical.digest(manifest), "journal registration mismatch")
    result, result_data = _check_stage(directory, manifest, value["stage"])
    _require(hashlib.sha256(result_data).hexdigest() == value["receipt_id"], "journal receipt mismatch")
    return value, data, result, result_data


def _unchanged(directory: Directory, manifest: dict, journal_data: bytes) -> None:
    _root(directory)
    _require(_manifest(directory) == manifest, "frozen manifest changed")
    _require(directory.read(_JOURNAL, limit=4096) == journal_data, "seal journal changed")


def _preflight(directory: Directory, manifest: dict, result: dict, result_data: bytes,
               record_data: bytes) -> dict[str, str]:
    _root(directory)
    _require(_manifest(directory) == manifest, "frozen manifest changed")
    existing = _optional_read(directory, "result.json")
    _require(existing is None or existing == result_data, "immutable result conflicts")
    existing_records = _optional_read(directory, "records.jsonl", limit=records.MAX_RECORD_BYTES)
    _require(existing_records is None or existing_records == record_data, "immutable records conflict")
    entries = _final_entries(directory)
    actual = {path[len("artifacts/"):]: path for path, is_file in entries.items() if is_file}
    schema.validate_inventory_paths(actual)
    _require(actual.keys() <= result["inventory"].keys(), "unlisted final artifacts")
    validate_paths([f"artifacts/{path}" for path in result["inventory"]], limit=2048,
                   directories=[path for path, is_file in entries.items() if not is_file])
    for path, stored in actual.items():
        entry = result["inventory"][path]
        _require(directory.digest(stored) == (entry["sha256"], entry["bytes"]), f"immutable artifact conflicts: {path!r}")
    return actual


def _persist_stage(directory: Directory, result: dict, prefix: str, data: bytes) -> None:
    for path, entry in result["inventory"].items():
        _persist_expected(directory, f"{prefix}/artifacts/{path}", entry["sha256"], entry["bytes"])
    metadata = result["records"]
    _persist_expected(directory, f"{prefix}/records.jsonl", metadata["sha256"], metadata["bytes"])
    _persist_expected(directory, f"{prefix}/result.json", hashlib.sha256(data).hexdigest(), len(data))


def _finalize(directory: Directory, manifest: dict, checkpoint: tuple[dict, bytes, dict, bytes]) -> dict:
    journal, journal_data, result, result_data = checkpoint
    prefix = f".prove/staging/{journal['stage']}"
    _unchanged(directory, manifest, journal_data)
    record_data = _check_data(directory, manifest, result, prefix)
    actual = _preflight(directory, manifest, result, result_data, record_data)
    manifest_data = canonical.dumps(manifest)
    _persist_expected(directory, "manifest.json", hashlib.sha256(manifest_data).hexdigest(), len(manifest_data))
    _persist_stage(directory, result, prefix, result_data)
    _persist_expected(directory, _JOURNAL, hashlib.sha256(journal_data).hexdigest(), len(journal_data))
    _unchanged(directory, manifest, journal_data)
    for path, entry in result["inventory"].items():
        target = f"artifacts/{path}"
        if path not in actual:
            copied = _copy_owned(directory, f"{prefix}/artifacts/{path}", manifest, result, target)
            _require(copied == (entry["sha256"], entry["bytes"]), f"staged artifact changed: {path!r}")
        _persist_expected(directory, target, entry["sha256"], entry["bytes"])
    _publish_owned(directory, manifest, result, "records.jsonl", record_data, limit=records.MAX_RECORD_BYTES)
    _check_data(directory, manifest, result, "")
    _unchanged(directory, manifest, journal_data)
    # A visible result is the last normative publication, including on retries.
    _publish_owned(directory, manifest, result, "result.json", result_data)
    _check_data(directory, manifest, result, "")
    _unchanged(directory, manifest, journal_data)
    _require(directory.read("result.json") == result_data, "final result changed")
    return canonical.loads(result_data)


def _options(manifest: dict, attempt_id, outcome, reason, events, roles, media_types,
             score_path, aggregate, metadata) -> dict:
    # Snapshot caller-owned options before streaming any source file.
    supplied = {"attempt_id": attempt_id, "outcome": outcome, "reason": reason, "roles": roles,
                "media_types": media_types, "score_path": score_path, "aggregate": aggregate, "metadata": metadata}
    options = {key: canonical.loads(canonical.dumps(value)) for key, value in supplied.items()}
    # Records have their own 64 MiB aggregate bound, independent of 8 MiB cores.
    options["events"] = None if events is None else records.decode(records.encode(events))
    if options["attempt_id"] is None:
        _require(len(manifest["attempts"]) == 1, "multiple attempts require explicit selection")
        options["attempt_id"] = manifest["attempts"][0]["id"]
    _require(isinstance(options["attempt_id"], str) and options["attempt_id"] in {a["id"] for a in manifest["attempts"]},
             "undeclared attempt")
    for field in ("roles", "media_types", "metadata"):
        if options[field] is None:
            options[field] = {}
        _require(isinstance(options[field], dict), f"{field} must be an object")
    for field in ("roles", "media_types"):
        schema.validate_inventory_paths(options[field])
        _require(all(isinstance(value, str) for value in options[field].values()), f"{field} values must be strings")
    if options["score_path"] is not None:
        schema.validate_artifact_path(options["score_path"])
        _require(options["roles"].get(options["score_path"], "score") == "score", "score role conflicts with explicit mapping")
    else:
        _require(options["aggregate"] is None, "aggregate requires an explicit score path")
    return options


def _stage(directory: Directory, manifest: dict, source: Directory | None, options: dict) -> tuple[str, dict, bytes]:
    names = [] if source is None else source.list_files()
    schema.validate_inventory_paths(names)
    for field in ("roles", "media_types"):
        _require(options[field].keys() <= set(names), f"{field} references missing source files")
    _require(options["score_path"] is None or options["score_path"] in names, "score artifact is missing")
    for _ in range(32):
        token = secrets.token_hex(16)
        try:
            directory.mkdir_exclusive(f".prove/staging/{token}")
        except TallyLockError as error:
            if isinstance(error.__cause__, OSError) and error.__cause__.errno == errno.EEXIST:
                continue
            raise
        break
    else:
        raise TallyLockError("cannot allocate exclusive snapshot stage", code=5)
    prefix = f".prove/staging/{token}"
    directory.mkdir_exclusive(f"{prefix}/artifacts")
    inventory = {}
    for path in names:
        digest, size = source.copy_file_to(path, directory, f"{prefix}/artifacts/{path}")
        role = "score" if path == options["score_path"] else options["roles"].get(path, "output")
        inventory[path] = {"sha256": digest, "bytes": size, "role": role,
                           "media_type": options["media_types"].get(path, "application/octet-stream")}
    _require(source is None or source.list_files() == names, "source artifact path set changed during snapshot")
    built = records.build(manifest, options["attempt_id"], inventory, options["outcome"], options["reason"], events=options["events"])
    score_path = options["score_path"]
    score = None if score_path is None else {"path": score_path, "sha256": inventory[score_path]["sha256"],
                                           "bytes": inventory[score_path]["bytes"], "profile": manifest["scorer"]["profile"],
                                           "aggregate": options["aggregate"]}
    result = {"format": "prove.result.v1", "registration_id": canonical.digest(manifest),
              "attempt_id": options["attempt_id"], "profile": manifest["profile"], "outcome": options["outcome"],
              "reason": options["reason"], "inventory": inventory, "records": built.metadata,
              "resources": built.resources, "score": score, "metadata": options["metadata"]}
    schema.validate_result(result, manifest)
    records.check(manifest, result, built.data)
    data = canonical.dumps(result)
    directory.atomic_write(f"{prefix}/records.jsonl", built.data)
    directory.atomic_write(f"{prefix}/result.json", data)
    _check_stage(directory, manifest, token)
    _persist_stage(directory, result, prefix, data)
    return token, result, data


def seal(receipt: Path, artifacts: Path | None = None, *, attempt_id: str | None = None,
         outcome: str = "completed", reason: str | None = None, events: list[dict] | None = None,
         roles: dict | None = None, media_types: dict | None = None, score_path: str | None = None,
         aggregate: dict | None = None, metadata: dict | None = None) -> dict:
    with Directory(receipt) as directory:
        _root(directory, allow_pending=True)
        with WriterLock(directory):
            _root(directory, allow_pending=True)
            manifest = _manifest(directory)
            pending = _pending(directory)
            _reconcile_pending(directory, manifest, None if pending is not None and pending["receipt_id"] is None else (_journal(directory, manifest) or (None, None, None, None))[2])
            _root(directory)
            options = _options(manifest, attempt_id, outcome, reason, events, roles, media_types, score_path, aggregate, metadata)
            previous = _journal(directory, manifest)
            if artifacts is None:
                token, result, data = _stage(directory, manifest, None, options)
            else:
                with Directory(artifacts) as source:
                    _require(not _ancestor(directory, source) and not _ancestor(source, directory),
                             "source and receipt trees overlap")
                    try:
                        _require(not _contains_directory(directory.fd, os.fstat(source.fd))
                                 and not _contains_directory(source.fd, os.fstat(directory.fd)),
                                 "source and receipt trees overlap through a directory alias")
                    except OSError as error:
                        raise _problem(error, "cannot inspect source/receipt root identities") from error
                    token, result, data = _stage(directory, manifest, source, options)
            record_data = directory.read(f".prove/staging/{token}/records.jsonl", limit=records.MAX_RECORD_BYTES)
            _preflight(directory, manifest, result, data, record_data)
            if previous is not None:
                _require(previous[3] == data, "seal candidate conflicts with existing journal")
                _require(directory.read(_JOURNAL, limit=4096) == previous[1], "seal journal changed")
                checkpoint = _journal(directory, manifest)
                _require(checkpoint is not None and checkpoint[1] == previous[1], "seal journal changed")
            else:
                journal = {"format": "prove.seal-journal.v1", "stage": token,
                           "registration_id": canonical.digest(manifest), "receipt_id": hashlib.sha256(data).hexdigest()}
                journal_data = canonical.dumps(journal)
                directory.atomic_write(_JOURNAL, journal_data)
                _persist_expected(directory, _JOURNAL, hashlib.sha256(journal_data).hexdigest(), len(journal_data))
                checkpoint = _journal(directory, manifest)
                _require(checkpoint is not None and checkpoint[1] == journal_data, "seal journal changed")
            return _finalize(directory, manifest, checkpoint)


def recover_seal(receipt: Path) -> dict:
    with Directory(receipt) as directory:
        _root(directory, allow_pending=True)
        with WriterLock(directory):
            _root(directory, allow_pending=True)
            manifest = _manifest(directory)
            pending = _pending(directory)
            _reconcile_pending(directory, manifest, None if pending is not None and pending["receipt_id"] is None else (_journal(directory, manifest) or (None, None, None, None))[2])
            _root(directory)
            checkpoint = _journal(directory, manifest)
            _require(checkpoint is not None, "no complete seal journal is available")
            return _finalize(directory, manifest, checkpoint)
