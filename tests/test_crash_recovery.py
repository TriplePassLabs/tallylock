"""Crash recovery for store-owned same-parent private publications."""
import hashlib
import subprocess
import sys

import pytest

from tallylock import canonical, filesystem, schema, store, verify
from tallylock.errors import TallyLockError


@pytest.mark.parametrize("phase", ["registration", "final-core", "final-artifact"])
def test_explicit_lock_recovery_removes_only_crashed_owned_publication(tmp_path, phase):
    """Deleting pending ownership/reconciliation must make this process crash fail again."""
    receipt = tmp_path / "receipt"
    source = tmp_path / "source"
    receipt.mkdir()
    source.mkdir()
    original_output = b"preserved output"
    (source / "output.txt").write_bytes(original_output)
    manifest = schema.default_manifest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical.dumps(manifest))
    if phase != "registration":
        store.register(manifest, receipt)

    child = r'''
import os
import sys
from pathlib import Path
from tallylock import canonical, filesystem, store

receipt, source, manifest_path = map(Path, sys.argv[1:4])
phase = sys.argv[4]
root = receipt.stat()
original = filesystem.Directory._temporary

def crash_after_private_create(self, parent):
    answer = original(self, parent)
    current = os.fstat(parent)
    root_match = (current.st_dev, current.st_ino) == (root.st_dev, root.st_ino)
    artifact_match = os.readlink('/proc/self/fd/' + str(parent)) == str(receipt / 'artifacts')
    if (phase == 'final-artifact' and artifact_match) or (phase != 'final-artifact' and root_match):
        os._exit(91)
    return answer

filesystem.Directory._temporary = crash_after_private_create
if phase == 'registration':
    store.register(canonical.loads(manifest_path.read_bytes()), receipt)
else:
    store.seal(receipt, source)
'''
    run = subprocess.run(
        [sys.executable, "-I", "-c", child, str(receipt), str(source), str(manifest_path), phase],
        capture_output=True,
        timeout=15,
    )
    assert run.returncode == 91, (run.stdout, run.stderr)
    if phase != "registration":
        assert (receipt / ".prove/seal.json").is_file()
    residue_parent = receipt / "artifacts" if phase == "final-artifact" else receipt
    assert list(residue_parent.glob(".prove-tmp-*"))

    observed = hashlib.sha256((receipt / ".prove/lock").read_bytes()).hexdigest()
    with filesystem.Directory(receipt) as directory:
        filesystem.recover_lock(directory, observed)
    if phase == "registration":
        assert store.register(manifest, receipt) == canonical.digest(manifest)
    else:
        result = store.recover_seal(receipt)
        assert result["outcome"] == "completed"
        assert verify.full(receipt, policy="integrity-only").code == 0
    assert (source / "output.txt").read_bytes() == original_output


@pytest.mark.parametrize("pending", [b"{}", b'{"bytes":true}'])
def test_recovery_rejects_malformed_private_ownership_state(tmp_path, pending):
    """Removing closed/bounded private-state validation must make this accept bad recovery state."""
    receipt = tmp_path / "receipt"
    receipt.mkdir()
    manifest = schema.default_manifest()
    store.register(manifest, receipt)
    with filesystem.Directory(receipt) as directory:
        directory.atomic_write(".prove/pending-write.json", pending, replace=True)
    with pytest.raises(TallyLockError):
        store.recover_seal(receipt)


def test_recovery_rejects_symlinked_private_ownership_state(tmp_path):
    """Removing nofollow handling must make a symlinked owner record reach recovery."""
    receipt = tmp_path / "receipt"
    receipt.mkdir()
    store.register(schema.default_manifest(), receipt)
    target = tmp_path / "outside.json"
    target.write_bytes(canonical.dumps({}))
    (receipt / ".prove/pending-write.json").symlink_to(target)
    with pytest.raises(TallyLockError):
        store.recover_seal(receipt)


def test_legitimate_prefix_named_artifact_is_retained(tmp_path):
    """Prefix-based orphan cleanup would incorrectly delete this normative artifact."""
    receipt = tmp_path / "receipt"
    source = tmp_path / "source"
    receipt.mkdir()
    source.mkdir()
    name = ".prove-tmp-0123456789abcdef0123456789abcdef"
    (source / name).write_bytes(b"normative artifact")
    manifest = schema.default_manifest()
    store.register(manifest, receipt)
    store.seal(receipt, source)
    assert (receipt / "artifacts" / name).read_bytes() == b"normative artifact"
    assert verify.full(receipt, policy="integrity-only").code == 0
