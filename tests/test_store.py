"""Durable generic receipt snapshots and interrupted publication."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tallylock import canonical, filesystem, records
from tallylock.errors import TallyLockError


ROOT = Path(__file__).resolve().parents[1]


def api():
    from tallylock import store
    return store


def manifest(trace=False):
    value = json.loads((ROOT / "examples/basic/manifest.json").read_text())
    if trace:
        value["profile"] = "trace-v1"
        value["attempts"][0]["sample_ids"] = ["sample-1"]
    return value


def roots(tmp_path):
    receipt, source = tmp_path / "receipt", tmp_path / "source"
    receipt.mkdir(); source.mkdir()
    (source / "Résumé.txt").write_bytes(b"snapshot")
    api().register(manifest(), receipt)
    return receipt, source


def trace(core):
    common = {"format": "prove.event.v1", "registration_id": canonical.digest(core), "attempt_id": "run-1"}
    return [{**common, "index": 0, "kind": "sample_start", "sample_id": "sample-1"},
            {**common, "index": 1, "kind": "sample_end", "sample_id": "sample-1", "status": "completed"},
            {**common, "index": 2, "kind": "attempt_end", "outcome": "completed", "reason": None}]


def call(core, index, *, source="recorded", **extra):
    return {"format": "prove.event.v1", "registration_id": canonical.digest(core), "attempt_id": "run-1",
            "index": index, "kind": "call", "sample_id": "sample-1", "call_id": f"call-{index}",
            "retry_of": None, "source": source, "status": "succeeded", "input": None, "output": None,
            "usage": {"input_tokens": None, "output_tokens": None, "reasoning_tokens": None,
                      "cached_tokens": None, "duration_ms": None}, **extra}


def test_registration_freezes_canonical_bytes_and_rejects_conflict(tmp_path):
    core = manifest()
    expected = canonical.dumps(core)
    assert api().register(core, tmp_path) == hashlib.sha256(expected).hexdigest()
    core["metadata"]["changed"] = True
    assert (tmp_path / "manifest.json").read_bytes() == expected
    loaded = api().load_manifest(tmp_path)
    assert api().register(loaded, tmp_path) == hashlib.sha256(expected).hexdigest()
    loaded["metadata"]["later"] = True
    assert api().load_manifest(tmp_path)["metadata"] == canonical.loads(expected)["metadata"]
    with pytest.raises(TallyLockError):
        api().register(core, tmp_path)
    (tmp_path / "manifest.json").write_bytes(expected + b"\n")
    with pytest.raises(TallyLockError):
        api().load_manifest(tmp_path)


def test_generic_seal_snapshots_nested_unicode_and_repeats(tmp_path):
    receipt, source = roots(tmp_path)
    (source / "nested").mkdir()
    (source / "nested" / "model.bin").write_bytes(b"model" * 300_000)
    core = api().seal(receipt, source, roles={"nested/model.bin": "input"}, media_types={"Résumé.txt": "text/plain"})
    assert core["inventory"]["Résumé.txt"]["media_type"] == "text/plain"
    assert core["inventory"]["nested/model.bin"]["role"] == "input"
    records.check(api().load_manifest(receipt), core, (receipt / "records.jsonl").read_bytes())
    assert (receipt / "artifacts" / "nested" / "model.bin").read_bytes() == (source / "nested" / "model.bin").read_bytes()
    assert api().seal(receipt, source, roles={"nested/model.bin": "input"}, media_types={"Résumé.txt": "text/plain"}) == core
    core["metadata"]["caller"] = True
    assert "caller" not in api().recover_seal(receipt)["metadata"]


def test_completed_trace_can_have_zero_artifacts_and_attempt_selection_is_explicit(tmp_path):
    core = manifest(True)
    api().register(core, tmp_path)
    result = api().seal(tmp_path, events=trace(core))
    assert result["inventory"] == {} and result["resources"]["calls"] == 0
    assert api().recover_seal(tmp_path) == result


def test_multiple_attempts_and_bad_options_do_not_publish(tmp_path):
    core = manifest()
    core["attempts"].append({"id": "run-2", "sample_ids": []})
    api().register(core, tmp_path)
    with pytest.raises(TallyLockError):
        api().seal(tmp_path, outcome="failed", reason="stopped")
    with pytest.raises(TallyLockError):
        api().seal(tmp_path, attempt_id="run-2", outcome="failed", reason="stopped", aggregate={"numerator": 1, "denominator": 1})
    assert not (tmp_path / "result.json").exists()
    result = api().seal(tmp_path, attempt_id="run-2", outcome="failed", reason="stopped")
    assert result["attempt_id"] == "run-2"


def test_score_is_explicit_and_binds_exact_copied_bytes(tmp_path):
    receipt, source = roots(tmp_path)
    result = api().seal(receipt, source, score_path="Résumé.txt", aggregate={"numerator": 1, "denominator": 3})
    score = result["score"]
    assert score["path"] == "Résumé.txt" and score["profile"] == "recorded-only-v1"
    assert score["sha256"] == hashlib.sha256(b"snapshot").hexdigest()
    assert result["inventory"]["Résumé.txt"]["role"] == "score"


def test_conflicting_completed_candidate_cannot_add_new_artifact(tmp_path):
    receipt, source = roots(tmp_path)
    first = api().seal(receipt, source)
    final = (receipt / "result.json").read_bytes()
    journal = (receipt / ".prove" / "seal.json").read_bytes()
    (source / "NEW.txt").write_bytes(b"new")
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert (receipt / "result.json").read_bytes() == final
    assert (receipt / ".prove" / "seal.json").read_bytes() == journal
    assert not (receipt / "artifacts" / "NEW.txt").exists()
    assert api().recover_seal(receipt) == first


@pytest.mark.parametrize("point", ["stage_artifact", "stage_records", "stage_result", "journal", "artifact", "records", "result"])
def test_interruption_retains_candidate_and_recovery_ignores_live_source(tmp_path, monkeypatch, point):
    receipt, source = roots(tmp_path)
    write = filesystem.Directory.atomic_write
    copy = filesystem.Directory.copy_file_to
    fired = False

    def interrupt_write(self, path, data, replace=False):
        nonlocal fired
        selected = ((point == "stage_records" and path.startswith(".prove/staging/") and path.endswith("/records.jsonl"))
                    or (point == "stage_result" and path.startswith(".prove/staging/") and path.endswith("/result.json"))
                    or (point == "journal" and path == ".prove/seal.json")
                    or (point == "records" and path == "records.jsonl")
                    or (point == "result" and path == "result.json"))
        if selected and not fired:
            fired = True
            raise TallyLockError("injected interruption", code=5)
        return write(self, path, data, replace)

    def interrupt_copy(self, path, destination, destination_path):
        nonlocal fired
        selected = ((point == "stage_artifact" and destination_path.startswith(".prove/staging/"))
                    or (point == "artifact" and destination_path.startswith("artifacts/")))
        if selected and not fired:
            fired = True
            raise TallyLockError("injected interruption", code=5)
        return copy(self, path, destination, destination_path)

    monkeypatch.setattr(filesystem.Directory, "atomic_write", interrupt_write)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", interrupt_copy)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert fired and not (receipt / "result.json").exists()
    monkeypatch.setattr(filesystem.Directory, "atomic_write", write)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", copy)
    if point.startswith("stage_") or point == "journal":
        with pytest.raises(TallyLockError):
            api().recover_seal(receipt)
        result = api().seal(receipt, source)
    else:
        (source / "Résumé.txt").unlink()
        source.rmdir()
        result = api().recover_seal(receipt)
    assert result["inventory"]["Résumé.txt"]["sha256"] == hashlib.sha256(b"snapshot").hexdigest()


def test_pending_journal_conflict_is_preserved(tmp_path, monkeypatch):
    receipt, source = roots(tmp_path)
    original = filesystem.Directory.copy_file_to
    def stop(self, path, destination, destination_path):
        if destination_path.startswith("artifacts/"):
            raise TallyLockError("interrupted", code=5)
        return original(self, path, destination, destination_path)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", stop)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    journal = (receipt / ".prove" / "seal.json").read_bytes()
    (source / "Résumé.txt").write_bytes(b"changed")
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert (receipt / ".prove" / "seal.json").read_bytes() == journal
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", original)
    assert api().recover_seal(receipt)["inventory"]["Résumé.txt"]["bytes"] == 8


@pytest.mark.parametrize("change", ["stage", "registration_id", "receipt_id", "extra", "format"])
def test_journal_substitution_fails_closed(tmp_path, change):
    receipt, source = roots(tmp_path)
    api().seal(receipt, source)
    journal_path = receipt / ".prove" / "seal.json"
    value = canonical.loads(journal_path.read_bytes())
    value[change] = "../outside" if change == "stage" else "00" * 32
    journal_path.write_bytes(canonical.dumps(value))
    with pytest.raises(TallyLockError):
        api().recover_seal(receipt)


@pytest.mark.parametrize("kind", ["extra", "link", "source_same", "source_parent", "source_child", "source_alias", "parent_alias"])
def test_root_allowlist_and_source_overlap(tmp_path, kind):
    receipt, source = roots(tmp_path)
    if kind == "extra":
        (receipt / "unknown").write_bytes(b"bad")
    elif kind == "link":
        (receipt / "proofs").symlink_to(source, target_is_directory=True)
    elif kind == "source_same":
        source = receipt
    elif kind == "source_parent":
        source = tmp_path
    elif kind == "source_child":
        source = receipt / "artifacts"; source.mkdir()
    elif kind == "source_alias":
        source = tmp_path / "alias"; source.symlink_to(receipt, target_is_directory=True)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        source = alias / "receipt"
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert not (receipt / "result.json").exists()


def test_wire_1024_byte_path_survives_stage_final_and_recovery(tmp_path):
    receipt, source = roots(tmp_path)
    (source / "Résumé.txt").unlink()
    path = "/".join(["a" * 255] * 3 + ["b" * 255, "x"])
    assert len(path.encode()) == 1025
    path = "/".join(["a" * 255] * 3 + ["b" * 254, "x"])
    assert len(path.encode()) == 1024
    target = source / path
    target.parent.mkdir(parents=True)
    target.write_bytes(b"edge")
    result = api().seal(receipt, source)
    assert path in result["inventory"]
    assert api().recover_seal(receipt) == result


def test_fsync_failed_visible_artifact_requires_repair_on_retry(tmp_path, monkeypatch):
    receipt, source = roots(tmp_path)
    publish = filesystem.Directory._publish
    def fail_after_publish(self, parent, temp, final, replace):
        publish(self, parent, temp, final, replace)
        if final == "Résumé.txt" and (receipt / "artifacts" / "Résumé.txt").exists():
            raise OSError(errno.EIO, "injected directory fsync failure")
    monkeypatch.setattr(filesystem.Directory, "_publish", fail_after_publish)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert (receipt / "artifacts" / "Résumé.txt").exists()
    monkeypatch.setattr(filesystem.Directory, "_publish", publish)
    persist = filesystem.Directory.persist_file
    seen = []
    def observe(self, path):
        seen.append(path)
        return persist(self, path)
    monkeypatch.setattr(filesystem.Directory, "persist_file", observe)
    api().recover_seal(receipt)
    assert "artifacts/Résumé.txt" in seen


def test_missing_io_and_live_writer_are_not_ignored(tmp_path, monkeypatch):
    receipt, source = roots(tmp_path)
    with filesystem.Directory(receipt) as directory, filesystem.WriterLock(directory):
        with pytest.raises(TallyLockError) as caught:
            api().seal(receipt, source)
        assert caught.value.code == 5
    original = os.open
    identity = receipt.stat()
    def broken(path, flags, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        if path == "result.json" and parent is not None and os.fstat(parent).st_ino == identity.st_ino:
            raise OSError(errno.EIO, "injected bad disk")
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", broken)
    with pytest.raises(TallyLockError) as caught:
        api().seal(receipt, source)
    assert caught.value.code == 5 and not (receipt / "result.json").exists()


@pytest.mark.parametrize("existing,candidate", [("z", "z"), ("Z/empty", "z/file")])
def test_empty_final_directory_conflicts_are_preflighted_before_any_normative_copy(tmp_path, existing, candidate):
    receipt, source = roots(tmp_path)
    (source / "a").write_bytes(b"must not be copied")
    target = source / candidate
    target.parent.mkdir(exist_ok=True, parents=True)
    target.write_bytes(b"conflict")
    (receipt / "artifacts" / existing).mkdir(parents=True)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert not (receipt / "artifacts" / "a").exists()
    assert not (receipt / "records.jsonl").exists()


def test_trace_records_can_exceed_the_core_json_limit(tmp_path):
    core = manifest(True)
    api().register(core, tmp_path)
    events = trace(core)
    events = events[:1] + [call(core, index, source="r" * 950_000) for index in range(1, 10)] + events[1:]
    for index, event in enumerate(events):
        event["index"] = index
    result = api().seal(tmp_path, events=events)
    assert canonical.MAX_JSON_BYTES < result["records"]["bytes"] < records.MAX_RECORD_BYTES
    assert result["resources"]["calls"] == 9


@pytest.mark.parametrize("options", [
    {"roles": {"missing": "input"}}, {"roles": {"Résumé.txt": 1}},
    {"media_types": []}, {"metadata": []}, {"score_path": "missing"},
    {"score_path": "Résumé.txt", "roles": {"Résumé.txt": "input"}},
    {"score_path": "Résumé.txt", "aggregate": {"numerator": True, "denominator": 1}},
    {"outcome": "failed"}, {"attempt_id": "undeclared"},
])
def test_invalid_data_options_never_publish_normative_files(tmp_path, options):
    receipt, source = roots(tmp_path)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source, **options)
    assert not (receipt / "artifacts").exists()
    assert not (receipt / "records.jsonl").exists()
    assert not (receipt / "result.json").exists()


def test_snapshot_freezes_caller_options_before_copy_and_rejects_source_set_changes(tmp_path, monkeypatch):
    receipt, source = roots(tmp_path)
    options = {"nested": {"value": "frozen"}}
    original = filesystem.Directory.copy_file_to
    def mutate_options(self, path, destination, destination_path):
        options["nested"]["value"] = "changed"
        return original(self, path, destination, destination_path)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", mutate_options)
    assert api().seal(receipt, source, metadata=options)["metadata"] == {"nested": {"value": "frozen"}}
    other = tmp_path / "other"
    other.mkdir()
    api().register(manifest(), other)
    def change_source_set(self, path, destination, destination_path):
        copied = original(self, path, destination, destination_path)
        (source / "new").write_bytes(b"new")
        return copied
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", change_source_set)
    assert not (source / "new").exists()
    with pytest.raises(TallyLockError):
        api().seal(other, source)
    assert not (other / ".prove" / "seal.json").exists()
    assert not (other / "result.json").exists()


def test_wire_over_limit_source_name_is_rejected_without_renaming(tmp_path):
    receipt, source = roots(tmp_path)
    name = "/".join(["a" * 255] * 4 + ["x"])
    target = source / name
    target.parent.mkdir(parents=True)
    target.write_bytes(b"too long")
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    assert target.read_bytes() == b"too long"
    assert not (receipt / "result.json").exists()


@pytest.mark.parametrize("part", ["artifact", "artifact_missing", "records", "result", "stage_link", "extra", "journal_link"])
def test_recovery_revalidates_every_staged_binding(tmp_path, part):
    receipt, source = roots(tmp_path)
    api().seal(receipt, source)
    journal_path = receipt / ".prove" / "seal.json"
    journal = canonical.loads(journal_path.read_bytes())
    stage = receipt / ".prove" / "staging" / journal["stage"]
    if part == "artifact":
        (stage / "artifacts" / "Résumé.txt").write_bytes(b"tampered")
    elif part == "artifact_missing":
        (stage / "artifacts" / "Résumé.txt").unlink()
    elif part == "records":
        (stage / "records.jsonl").write_bytes(b"\n")
    elif part == "result":
        value = canonical.loads((stage / "result.json").read_bytes())
        value["metadata"]["tampered"] = True
        (stage / "result.json").write_bytes(canonical.dumps(value))
    elif part == "stage_link":
        moved = stage.with_name("moved")
        stage.rename(moved)
        stage.symlink_to(moved, target_is_directory=True)
    elif part == "extra":
        (stage / "extra").write_bytes(b"extra")
    else:
        moved = journal_path.with_name("moved-journal")
        journal_path.rename(moved)
        journal_path.symlink_to(moved)
    final = (receipt / "result.json").read_bytes()
    with pytest.raises(TallyLockError):
        api().recover_seal(receipt)
    assert (receipt / "result.json").read_bytes() == final


@pytest.mark.parametrize("point", ["journal", "artifact", "records", "result"])
def test_interruption_after_visible_publication_requires_explicit_revalidation(tmp_path, monkeypatch, point):
    receipt, source = roots(tmp_path)
    write, copy = filesystem.Directory.atomic_write, filesystem.Directory.copy_file_to
    def broken_write(self, path, data, replace=False):
        write(self, path, data, replace)
        if path == {"journal": ".prove/seal.json", "records": "records.jsonl", "result": "result.json"}.get(point):
            raise TallyLockError("injected post-publication fsync/close error", code=5)
    def broken_copy(self, path, destination, destination_path):
        copied = copy(self, path, destination, destination_path)
        if point == "artifact" and destination_path.startswith("artifacts/"):
            raise TallyLockError("injected post-publication fsync/close error", code=5)
        return copied
    monkeypatch.setattr(filesystem.Directory, "atomic_write", broken_write)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", broken_copy)
    with pytest.raises(TallyLockError):
        api().seal(receipt, source)
    monkeypatch.setattr(filesystem.Directory, "atomic_write", write)
    monkeypatch.setattr(filesystem.Directory, "copy_file_to", copy)
    assert api().recover_seal(receipt)["inventory"]["Résumé.txt"]["bytes"] == 8


def test_retry_cannot_succeed_while_matching_artifact_fsync_still_fails(tmp_path, monkeypatch):
    receipt, source = roots(tmp_path)
    sync = os.fsync
    final_artifact = receipt / "artifacts" / "Résumé.txt"
    def broken_sync(fd):
        if final_artifact.exists() and os.fstat(fd).st_ino == final_artifact.stat().st_ino:
            raise OSError(errno.EIO, "file fsync still fails")
        return sync(fd)
    monkeypatch.setattr(os, "fsync", broken_sync)
    for operation in (lambda: api().seal(receipt, source), lambda: api().recover_seal(receipt)):
        with pytest.raises(TallyLockError) as caught:
            operation()
        assert caught.value.code == 5
        assert not (receipt / "result.json").exists()
    monkeypatch.setattr(os, "fsync", sync)
    assert api().recover_seal(receipt)["outcome"] == "completed"


def test_trace_known_budget_excess_is_never_silently_rewritten(tmp_path):
    core = manifest(True)
    core["budget"]["max_input_tokens"] = 1
    api().register(core, tmp_path)
    events = trace(core)
    usage = {"input_tokens": 2, "output_tokens": None, "reasoning_tokens": None,
             "cached_tokens": None, "duration_ms": None}
    events = events[:1] + [call(core, 1, usage=usage), call(core, 2)] + events[1:]
    for index, value in enumerate(events):
        value["index"] = index
    with pytest.raises(TallyLockError):
        api().seal(tmp_path, events=events)
    assert not (tmp_path / "result.json").exists()
    events[-1].update(outcome="budget_exceeded", reason="known excess")
    result = api().seal(tmp_path, outcome="budget_exceeded", reason="known excess", events=events)
    assert result["resources"]["input_tokens"] is None
    assert records.check(core, result, (tmp_path / "records.jsonl").read_bytes()).budget == "exceeded"


def test_empty_staged_artifact_directory_is_itself_persisted(tmp_path, monkeypatch):
    core = manifest(True)
    api().register(core, tmp_path)
    sync = os.fsync
    seen = []
    def observe(fd):
        seen.append(os.fstat(fd).st_ino)
        return sync(fd)
    monkeypatch.setattr(os, "fsync", observe)
    api().seal(tmp_path, events=trace(core))
    journal = canonical.loads((tmp_path / ".prove" / "seal.json").read_bytes())
    empty_directory = tmp_path / ".prove" / "staging" / journal["stage"] / "artifacts"
    assert empty_directory.stat().st_ino in seen


@pytest.mark.parametrize("entry", ["result.json", "records.jsonl", "artifacts", "proofs"])
def test_new_registration_refuses_to_adopt_foreign_normative_contents(tmp_path, entry):
    target = tmp_path / entry
    if entry.endswith("json") or entry.endswith("jsonl"):
        target.write_bytes(b"foreign")
    else:
        target.mkdir()
    with pytest.raises(TallyLockError):
        api().register(manifest(), tmp_path)
    assert not (tmp_path / "manifest.json").exists()


@pytest.mark.parametrize("recover", [False, True])
def test_seal_and_recovery_require_manifest_file_durability(tmp_path, monkeypatch, recover):
    receipt, source = roots(tmp_path)
    if recover:
        api().seal(receipt, source)
    original = filesystem.Directory.persist_file
    def fail_manifest(self, path):
        if path == "manifest.json":
            raise TallyLockError("manifest file fsync failed", code=5)
        return original(self, path)
    monkeypatch.setattr(filesystem.Directory, "persist_file", fail_manifest)
    with pytest.raises(TallyLockError) as caught:
        api().recover_seal(receipt) if recover else api().seal(receipt, source)
    assert caught.value.code == 5


def test_stale_lock_is_not_implicitly_removed_or_treated_as_pid_evidence(tmp_path):
    receipt, source = roots(tmp_path)
    lock = receipt / ".prove" / "lock"
    stale = b'{"pid":999999999,"token":"stale"}'
    lock.write_bytes(stale)
    for operation in (lambda: api().seal(receipt, source), lambda: api().recover_seal(receipt)):
        with pytest.raises(TallyLockError) as caught:
            operation()
        assert caught.value.code == 5
        assert lock.read_bytes() == stale


def test_real_process_exit_after_checkpoint_requires_observed_lock_recovery(tmp_path):
    receipt, source = roots(tmp_path)
    # This child stays inside the capped pytest worker. os._exit bypasses every
    # context manager to exercise an actual stale lock and durable checkpoint.
    child = """
import os
from pathlib import Path
import sys
from tallylock import filesystem, store
write = filesystem.Directory.atomic_write
def checkpoint_exit(self, path, data, replace=False):
    write(self, path, data, replace)
    if path == '.prove/seal.json':
        os._exit(77)
filesystem.Directory.atomic_write = checkpoint_exit
store.seal(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    exited = subprocess.run([sys.executable, "-c", child, str(receipt), str(source)],
                            capture_output=True, timeout=30)
    assert exited.returncode == 77, exited.stderr.decode()
    lock = receipt / ".prove" / "lock"
    assert lock.is_file()
    with pytest.raises(TallyLockError) as caught:
        api().recover_seal(receipt)
    assert caught.value.code == 5
    observed = hashlib.sha256(lock.read_bytes()).hexdigest()
    with filesystem.Directory(receipt) as directory:
        filesystem.recover_lock(directory, observed)
    (source / "Résumé.txt").unlink()
    source.rmdir()
    result = api().recover_seal(receipt)
    assert result["inventory"]["Résumé.txt"]["sha256"] == hashlib.sha256(b"snapshot").hexdigest()


@pytest.mark.parametrize("helper", ["_artifact_files", "_final_entries"])
def test_missing_descendant_is_not_an_absent_artifact_root(tmp_path, monkeypatch, helper):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "keep").write_bytes(b"keep")
    (artifact_root / "gone").write_bytes(b"gone")
    original = os.open
    def vanished(path, flags, *args, **kwargs):
        if path == "gone":
            raise FileNotFoundError(errno.ENOENT, "injected disappearing descendant")
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", vanished)
    with filesystem.Directory(tmp_path) as directory:
        call_helper = getattr(api(), helper)
        with pytest.raises(TallyLockError) as caught:
            call_helper(directory, "artifacts") if helper == "_artifact_files" else call_helper(directory)
        assert caught.value.code == 5


def test_optional_artifact_root_does_not_hide_missing_ancestors(tmp_path):
    with filesystem.Directory(tmp_path) as directory:
        assert api()._artifact_files(directory, "artifacts") == {}
        with pytest.raises(TallyLockError):
            api()._artifact_files(directory, ".prove/staging/" + "ab" * 16 + "/artifacts")


def test_optional_core_read_does_not_hide_disappearance_after_initial_open(tmp_path, monkeypatch):
    (tmp_path / "result.json").write_bytes(b"existing")
    def vanished_read(self, path, limit=8_388_608):
        raise TallyLockError("file disappeared during stable read", code=5) from FileNotFoundError(errno.ENOENT, "gone")
    monkeypatch.setattr(filesystem.Directory, "read", vanished_read)
    with filesystem.Directory(tmp_path) as directory:
        with pytest.raises(TallyLockError) as caught:
            api()._optional_read(directory, "result.json")
        assert caught.value.code == 5
