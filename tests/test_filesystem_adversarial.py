"""Independent acceptance regressions for filesystem namespace and error boundaries."""

import errno
import hashlib
import multiprocessing
import os
import stat

import pytest

from tallylock.errors import TallyLockError
from tallylock.filesystem import Directory, WriterLock
import tallylock.filesystem as filesystem


@pytest.mark.parametrize("operation", ["read", "digest", "copy"])
def test_read_detects_replaced_ancestor_from_receipt_root(tmp_path, monkeypatch, operation):
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "output.txt").write_bytes(b"original")
    original_read = os.read
    swapped = False

    def swap_parent(fd, amount):
        nonlocal swapped
        data = original_read(fd, amount)
        if data == b"original" and not swapped:
            swapped = True
            folder.rename(tmp_path / "retired")
            folder.mkdir()
            (folder / "output.txt").write_bytes(b"replacement")
        return data

    with Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "read", swap_parent)
        with pytest.raises(TallyLockError):
            if operation == "copy":
                destination_path = tmp_path / "destination"
                destination_path.mkdir()
                with Directory(destination_path) as destination:
                    directory.copy_file_to("folder/output.txt", destination, "copied.txt")
            else:
                getattr(directory, operation)("folder/output.txt")
    assert swapped


@pytest.mark.parametrize("operation", ["write", "copy"])
def test_publication_rejects_replaced_destination_ancestor(tmp_path, monkeypatch, operation):
    root = tmp_path / "destination"
    root.mkdir()
    target = root / "folder"
    target.mkdir()
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "input.txt").write_bytes(b"payload")
    original_temporary = Directory._temporary
    swapped = False

    def swap_destination(self, parent):
        nonlocal swapped
        result = original_temporary(self, parent)
        if self.root == root and not swapped:
            swapped = True
            target.rename(root / "retired")
            target.mkdir()
        return result

    monkeypatch.setattr(Directory, "_temporary", swap_destination)
    with Directory(root) as directory, Directory(source_root) as source:
        with pytest.raises(TallyLockError):
            if operation == "write":
                directory.atomic_write("folder/output.txt", b"payload")
            else:
                source.copy_file_to("input.txt", directory, "folder/output.txt")
    assert swapped
    assert not (root / "folder/output.txt").exists()


@pytest.mark.parametrize("paths", [("A.txt", "a.txt"), ("A/x.txt", "a/y.txt")])
def test_enumeration_rejects_casefold_namespace_collisions(tmp_path, paths):
    for name in paths:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"output")
    with Directory(tmp_path) as directory:
        with pytest.raises(TallyLockError):
            directory.list_files()


def test_enumeration_io_failure_is_a_structured_operational_error(tmp_path, monkeypatch):
    original_listdir = os.listdir

    def broken_listdir(path):
        if isinstance(path, int):
            raise OSError(errno.EIO, "injected enumeration error")
        return original_listdir(path)

    with Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "listdir", broken_listdir)
        with pytest.raises(TallyLockError) as caught:
            directory.list_files()
    assert caught.value.code == 5


def test_new_parent_fsync_failure_prevents_successful_publication(tmp_path, monkeypatch):
    original_fsync = os.fsync
    root_identity = tmp_path.stat()

    def fail_parent_sync(fd):
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) == (root_identity.st_dev, root_identity.st_ino):
            raise OSError(errno.EIO, "injected root-directory sync failure")
        return original_fsync(fd)

    with Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "fsync", fail_parent_sync)
        with pytest.raises(TallyLockError) as caught:
            directory.atomic_write("new/child/output.txt", b"result")
    assert caught.value.code == 5
    assert not (tmp_path / "new/child/output.txt").exists()


def test_writer_acquisition_does_not_wait_on_competing_flock(tmp_path, monkeypatch):
    original_flock = filesystem.fcntl.flock

    def contended_flock(fd, operation):
        if operation & filesystem.fcntl.LOCK_EX:
            if not operation & filesystem.fcntl.LOCK_NB:
                raise TimeoutError("a blocking call would wait indefinitely")
            raise BlockingIOError(errno.EWOULDBLOCK, "another process won the acquisition race")
        return original_flock(fd, operation)

    with Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.fcntl, "flock", contended_flock)
        with pytest.raises(TallyLockError) as caught:
            with WriterLock(directory):
                pytest.fail("contended writer entered the critical section")
    assert caught.value.code == 5


def test_cleanup_error_preserves_primary_failure_and_closes_descriptors(tmp_path, monkeypatch):
    original_unlink = os.unlink
    descriptors_before = len(os.listdir("/proc/self/fd"))

    def failed_write(fd, data):
        raise OSError(errno.EIO, "primary write failure")

    def failed_cleanup(path, *args, **kwargs):
        if str(path).startswith(".prove-tmp-"):
            raise OSError(errno.EACCES, "secondary cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(filesystem, "_write_all", failed_write)
    monkeypatch.setattr(filesystem.os, "unlink", failed_cleanup)
    with Directory(tmp_path) as directory:
        with pytest.raises(TallyLockError) as caught:
            directory.atomic_write("output.txt", b"payload")
    assert caught.value.code == 5
    assert "primary write failure" in str(caught.value)
    assert len(os.listdir("/proc/self/fd")) == descriptors_before


@pytest.mark.parametrize("failure_point", ["file", "publication"])
def test_file_and_publication_sync_failures_are_structured(tmp_path, monkeypatch, failure_point):
    original_fsync = os.fsync

    def failed_sync(fd):
        info = os.fstat(fd)
        target = stat.S_ISREG(info.st_mode) if failure_point == "file" else stat.S_ISDIR(info.st_mode)
        if target:
            raise OSError(errno.EIO, f"injected {failure_point} sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(filesystem.os, "fsync", failed_sync)
    with Directory(tmp_path) as directory:
        with pytest.raises(TallyLockError) as caught:
            directory.atomic_write("output.txt", b"complete data")
    assert caught.value.code == 5
    if (tmp_path / "output.txt").exists():
        assert (tmp_path / "output.txt").read_bytes() == b"complete data"


def _hold_writer(root, acquired, release):
    with Directory(root) as directory, WriterLock(directory):
        acquired.set()
        if not release.wait(5):
            raise RuntimeError("parent did not release test writer")


def test_live_process_writer_cannot_be_recovered_or_displaced(tmp_path):
    context = multiprocessing.get_context("fork")
    acquired, release = context.Event(), context.Event()
    process = context.Process(target=_hold_writer, args=(tmp_path, acquired, release))
    process.start()
    try:
        assert acquired.wait(5), "child failed to acquire writer lock"
        with Directory(tmp_path) as directory:
            observed = hashlib.sha256(directory.read(".prove/lock")).hexdigest()
            with pytest.raises(TallyLockError) as caught:
                filesystem.recover_lock(directory, observed)
            assert caught.value.code == 5
            with pytest.raises(TallyLockError):
                with WriterLock(directory):
                    pytest.fail("second process displaced the writer")
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(5)
    assert process.exitcode == 0
    with Directory(tmp_path) as directory, WriterLock(directory):
        assert (tmp_path / ".prove/lock").is_file()


def test_recovery_winning_empty_file_window_prevents_displaced_writer_entry(tmp_path, monkeypatch):
    original_flock = filesystem.fcntl.flock
    won_recovery = False
    with Directory(tmp_path) as directory:
        def recover_before_acquire(fd, operation):
            nonlocal won_recovery
            if operation & filesystem.fcntl.LOCK_EX and not won_recovery:
                won_recovery = True
                filesystem.recover_lock(directory, hashlib.sha256(b"").hexdigest())
            return original_flock(fd, operation)

        monkeypatch.setattr(filesystem.fcntl, "flock", recover_before_acquire)
        with pytest.raises(TallyLockError) as caught:
            with WriterLock(directory):
                pytest.fail("writer entered after its lock was recovered")
    assert won_recovery
    assert caught.value.code == 5
