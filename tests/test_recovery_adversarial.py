"""Main-owned recovery probes for process-loss windows and durable retries."""

import hashlib
import subprocess
import sys

import pytest

from tallylock import canonical, filesystem, schema, store, verify
from tallylock.errors import TallyLockError


@pytest.mark.parametrize("phase", ["registration", "records", "result", "nested-artifact", "before-parent"])
def test_real_process_loss_at_link_or_before_parent_creation(tmp_path, phase):
    receipt, source = tmp_path / "receipt", tmp_path / "outputs"
    receipt.mkdir()
    source.mkdir()
    (source / "a/b").mkdir(parents=True)
    (source / "a/b/output.txt").write_bytes(b"unaltered source")
    manifest = schema.default_manifest()
    manifest_file = tmp_path / "input.json"
    manifest_file.write_bytes(canonical.dumps(manifest))
    if phase != "registration":
        store.register(manifest, receipt)
    program = r'''
import os, sys
from pathlib import Path
from tallylock import canonical, filesystem, store
receipt, source, manifest_file = map(Path, sys.argv[1:4])
phase = sys.argv[4]
original_link = os.link
def terminate_after_link(src, dst, *args, **kwargs):
    answer = original_link(src, dst, *args, **kwargs)
    wanted = {'registration': 'manifest.json', 'records': 'records.jsonl',
              'result': 'result.json', 'nested-artifact': 'output.txt'}
    parent = os.readlink('/proc/self/fd/' + str(kwargs['dst_dir_fd']))
    expected = str(receipt / 'artifacts/a/b') if phase == 'nested-artifact' else str(receipt)
    if phase in wanted and dst == wanted[phase] and parent == expected:
        os._exit(92)
    return answer
os.link = terminate_after_link
original_write = filesystem.Directory._write_private
def terminate_before_parent(self, path, *args, **kwargs):
    if phase == 'before-parent' and path == 'artifacts/a/b/output.txt':
        os._exit(93)
    return original_write(self, path, *args, **kwargs)
filesystem.Directory._write_private = terminate_before_parent
if phase == 'registration':
    store.register(canonical.loads(manifest_file.read_bytes()), receipt)
else:
    store.seal(receipt, source)
'''
    child = subprocess.run([sys.executable, "-I", "-c", program, str(receipt), str(source),
                            str(manifest_file), phase], capture_output=True, timeout=20)
    assert child.returncode == (93 if phase == "before-parent" else 92), (child.stdout, child.stderr)
    owner = canonical.loads((receipt / ".prove/pending-write.json").read_bytes())
    saved_stage = None if phase == "registration" else (receipt / ".prove/seal.json").read_bytes()
    observed = hashlib.sha256((receipt / ".prove/lock").read_bytes()).hexdigest()
    with filesystem.Directory(receipt) as directory:
        filesystem.recover_lock(directory, observed)
    if phase == "registration":
        assert store.register(manifest, receipt) == canonical.digest(manifest)
    else:
        result = store.recover_seal(receipt)
        assert (receipt / ".prove/seal.json").read_bytes() == saved_stage
        assert canonical.digest(result) == owner["receipt_id"]
        assert verify.full(receipt, policy="integrity-only").code == 0
    assert (source / "a/b/output.txt").read_bytes() == b"unaltered source"
    assert not (receipt / ".prove/pending-write.json").exists()


def test_identical_registration_retry_repairs_durability(tmp_path, monkeypatch):
    manifest = schema.default_manifest()
    store.register(manifest, tmp_path)
    original = filesystem.Directory.persist_file

    def fail_manifest_sync(self, path):
        if path == "manifest.json":
            raise TallyLockError("injected durable-file failure", code=5)
        return original(self, path)

    monkeypatch.setattr(filesystem.Directory, "persist_file", fail_manifest_sync)
    with pytest.raises(TallyLockError, match="durable-file failure"):
        store.register(manifest, tmp_path)
    assert (tmp_path / "manifest.json").read_bytes() == canonical.dumps(manifest)


@pytest.mark.parametrize("mutation", ["inventory-temp", "bytes-bool", "wrong-size", "wrong-hash", "traversal", "symlink"])
def test_recovery_preserves_files_when_owner_record_is_not_authorized(tmp_path, mutation):
    receipt, source = tmp_path / "receipt", tmp_path / "outputs"
    receipt.mkdir()
    source.mkdir()
    (source / "nested").mkdir()
    temporary = ".prove-tmp-" + "ab" * 16
    original_bytes = b"legitimate named artifact"
    (source / "nested" / temporary).write_bytes(original_bytes)
    (source / "nested/output.txt").write_bytes(b"other output")
    manifest = schema.default_manifest()
    store.register(manifest, receipt)
    result = store.seal(receipt, source)
    target = "nested/output.txt"
    entry = result["inventory"][target]
    owner = {"format": "prove.pending-write.v1", "parent": "artifacts/nested",
             "temp": temporary, "final": "artifacts/" + target,
             "sha256": entry["sha256"], "bytes": entry["bytes"],
             "registration_id": canonical.digest(manifest), "receipt_id": canonical.digest(result)}
    if mutation != "inventory-temp":
        owner["temp"] = ".prove-tmp-" + "cd" * 16
        candidate = receipt / "artifacts/nested" / owner["temp"]
        if mutation == "symlink":
            candidate.symlink_to(source / "nested" / temporary)
        else:
            candidate.write_bytes(b"unrelated preserved file")
    if mutation == "bytes-bool":
        owner["bytes"] = True
    elif mutation == "wrong-size":
        owner["bytes"] += 1
    elif mutation == "wrong-hash":
        owner["sha256"] = "00" * 32
    elif mutation == "traversal":
        owner["parent"] = "../outputs/nested"
        owner["final"] = "../outputs/nested/output.txt"
    encoded = canonical.dumps(owner)
    (receipt / ".prove/pending-write.json").write_bytes(encoded)
    with pytest.raises(TallyLockError):
        store.recover_seal(receipt)
    assert (receipt / ".prove/pending-write.json").read_bytes() == encoded
    assert (receipt / "artifacts/nested" / temporary).read_bytes() == original_bytes
    assert (source / "nested" / temporary).read_bytes() == original_bytes
    if mutation not in {"inventory-temp", "symlink"}:
        assert candidate.read_bytes() == b"unrelated preserved file"
