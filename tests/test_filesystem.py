"""Descriptor-relative storage boundaries for untrusted receipt paths."""

from __future__ import annotations

import hashlib
import errno
import os
from contextlib import contextmanager
from pathlib import Path
import socket

import pytest

from tallylock.errors import TallyLockError


def api():
    from tallylock import filesystem

    return filesystem


def test_mkdir_exclusive_rejects_existing_and_persist_repairs_full_chain(tmp_path, monkeypatch):
    with api().Directory(tmp_path) as directory:
        directory.mkdir_exclusive("parent/new")
        failure(lambda: directory.mkdir_exclusive("parent/new"))
        directory.atomic_write("parent/new/file", b"durable")
        real_sync = os.fsync
        seen = []
        def sync(fd):
            seen.append(os.fstat(fd))
            return real_sync(fd)
        monkeypatch.setattr(os, "fsync", sync)
        assert directory.persist_file("parent/new/file") == (hashlib.sha256(b"durable").hexdigest(), 7)
        assert len(seen) == 4  # file, new, parent, opened root


def test_internal_storage_prefix_does_not_consume_wire_path_allowance(tmp_path):
    path = "/".join(["a" * 255] * 3 + ["b" * 254, "x"])
    full = ".prove/staging/" + "ab" * 16 + "/artifacts/" + path
    with api().Directory(tmp_path) as directory:
        directory.atomic_write(full, b"boundary")
        assert directory.digest(full) == (hashlib.sha256(b"boundary").hexdigest(), 8)
        assert directory.list_files(".prove/staging/" + "ab" * 16 + "/artifacts") == [full]


def test_enumeration_rejects_colliding_empty_directory_prefixes(tmp_path):
    (tmp_path / "A").mkdir()
    (tmp_path / "a").mkdir()
    with api().Directory(tmp_path) as directory:
        failure(directory.list_files)


def test_repeated_descriptor_enumeration_sees_new_entries(tmp_path):
    (tmp_path / "first").write_bytes(b"first")
    with api().Directory(tmp_path) as directory:
        assert directory.list_files() == ["first"]
        (tmp_path / "new").write_bytes(b"new")
        assert directory.list_files() == ["first", "new"]


@pytest.mark.parametrize("change", ["file", "parent"])
def test_persist_file_rejects_changes_during_fsync(tmp_path, monkeypatch, change):
    directory_path = tmp_path / "parent"
    directory_path.mkdir()
    file_path = directory_path / "file"
    file_path.write_bytes(b"old")
    real_sync = os.fsync
    changed = False
    def mutate(fd):
        nonlocal changed
        real_sync(fd)
        if not changed and os.fstat(fd).st_ino == file_path.stat().st_ino:
            changed = True
            if change == "file":
                file_path.write_bytes(b"new")
            else:
                directory_path.rename(tmp_path / "moved")
                directory_path.mkdir()
                file_path.write_bytes(b"old")
    monkeypatch.setattr(os, "fsync", mutate)
    with api().Directory(tmp_path) as directory:
        failure(lambda: directory.persist_file("parent/file"), code=5)
    assert changed


@pytest.mark.parametrize("operation", ["persist", "mkdir"])
def test_new_primitives_drain_descriptors_after_sync_failure(tmp_path, monkeypatch, operation):
    (tmp_path / "file").write_bytes(b"data")
    before = set(os.listdir("/proc/self/fd"))
    real_sync = os.fsync
    def broken(fd):
        raise OSError(errno.EIO, "injected fsync failure")
    monkeypatch.setattr(os, "fsync", broken)
    with api().Directory(tmp_path) as directory:
        call = (lambda: directory.persist_file("file")) if operation == "persist" else (lambda: directory.mkdir_exclusive("new"))
        failure(call, code=5)
    monkeypatch.setattr(os, "fsync", real_sync)
    assert set(os.listdir("/proc/self/fd")) == before


def test_persist_never_retries_ambiguously_failed_close(tmp_path, monkeypatch):
    (tmp_path / "file").write_bytes(b"data")
    real_close = os.close
    calls = []
    target = None
    def close(fd):
        calls.append(fd)
        real_close(fd)
        if fd == target:
            raise OSError(errno.EIO, "close consumed the descriptor before failing")
    with api().Directory(tmp_path) as directory:
        original_open = os.open
        def observe(path, flags, *args, **kwargs):
            nonlocal target
            fd = original_open(path, flags, *args, **kwargs)
            if path == "file" and target is None:
                target = fd
            return fd
        monkeypatch.setattr(os, "open", observe)
        monkeypatch.setattr(os, "close", close)
        failure(lambda: directory.persist_file("file"), code=5)
        assert calls.count(target) == 1
        monkeypatch.setattr(os, "close", real_close)


def test_enumeration_rechecks_prefix_identity_after_directory_substitution(tmp_path, monkeypatch):
    subtree = tmp_path / "artifacts"
    subtree.mkdir()
    (subtree / "file").write_bytes(b"old")
    inode = subtree.stat().st_ino
    original = os.listdir
    changed = False
    def substitute(fd):
        nonlocal changed
        names = original(fd)
        if isinstance(fd, int) and os.fstat(fd).st_ino == inode and not changed:
            changed = True
            subtree.rename(tmp_path / "detached")
            subtree.mkdir()
            (subtree / "new").write_bytes(b"new")
        return names
    monkeypatch.setattr(os, "listdir", substitute)
    with api().Directory(tmp_path) as directory:
        failure(lambda: directory.list_files("artifacts"), code=5)
    assert changed


def test_descendant_identity_scan_finds_nested_directories_without_following_links(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "nested" / "target").mkdir(parents=True)
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with api().Directory(root) as directory:
        assert api()._contains_directory(directory.fd, (root / "nested" / "target").stat())
        assert not api()._contains_directory(directory.fd, outside.stat())


def test_descendant_identity_scan_bounds_repeated_directory_inodes(tmp_path, monkeypatch):
    (tmp_path / "back").mkdir()
    outside = tmp_path.parent / "unrelated"
    outside.mkdir()
    with api().Directory(tmp_path) as directory:
        original_stat, original_open = os.stat, os.open
        calls = []
        def bind_stat(path, *args, **kwargs):
            if path == "back" and kwargs.get("dir_fd") is not None:
                return os.fstat(directory.fd)
            return original_stat(path, *args, **kwargs)
        def bind_open(path, flags, *args, **kwargs):
            if path == "back" and kwargs.get("dir_fd") is not None:
                calls.append(path)
                return os.dup(directory.fd)
            return original_open(path, flags, *args, **kwargs)
        monkeypatch.setattr(os, "stat", bind_stat)
        monkeypatch.setattr(os, "open", bind_open)
        assert not api()._contains_directory(directory.fd, outside.stat())
        assert calls == ["back"]


def failure(call, code=2):
    with pytest.raises(TallyLockError) as caught:
        call()
    assert caught.value.code == code


def test_directory_reads_unicode_files_and_sorts_utf8_bytes(tmp_path):
    (tmp_path / "z.txt").write_bytes(b"z")
    (tmp_path / "\u6a21\u578b.txt").write_bytes(b"model")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "R\u00e9sum\u00e9.txt").write_bytes(b"cv")

    with api().Directory(tmp_path) as directory:
        assert directory.read("\u6a21\u578b.txt") == b"model"
        assert directory.digest("nested/R\u00e9sum\u00e9.txt") == (
            hashlib.sha256(b"cv").hexdigest(), 2
        )
        assert directory.list_files() == sorted(
            ["z.txt", "\u6a21\u578b.txt", "nested/R\u00e9sum\u00e9.txt"], key=lambda path: path.encode()
        )


def test_directory_rejects_ancestor_and_final_symlinks(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    outside.write_bytes(b"outside")
    (tmp_path / "file-link").symlink_to(outside)
    (tmp_path / "dir-link").symlink_to(tmp_path.parent, target_is_directory=True)

    with api().Directory(tmp_path) as directory:
        failure(lambda: directory.read("file-link"))
        failure(lambda: directory.read("dir-link/outside.txt"))


def test_directory_rejects_nonregular_files_without_fifo_blocking(tmp_path):
    os.mkfifo(tmp_path / "waiting")
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(tmp_path / "socket"))

    try:
        with api().Directory(tmp_path) as directory:
            failure(lambda: directory.read("waiting"))
            failure(lambda: directory.digest("waiting"))
            failure(lambda: directory.read("socket"))
    finally:
        listener.close()


def test_read_has_a_hard_limit_and_empty_files_are_valid(tmp_path):
    (tmp_path / "empty").write_bytes(b"")
    (tmp_path / "large").write_bytes(b"12345")

    with api().Directory(tmp_path) as directory:
        assert directory.read("empty") == b""
        failure(lambda: directory.read("large", limit=4))


def test_mkdirs_and_atomic_write_are_no_clobber_by_default(tmp_path):
    with api().Directory(tmp_path) as directory:
        directory.mkdirs("proofs/inner")
        directory.atomic_write("proofs/inner/state", b"first")
        failure(lambda: directory.atomic_write("proofs/inner/state", b"second"))
        assert directory.read("proofs/inner/state") == b"first"
        directory.atomic_write("proofs/inner/state", b"second", replace=True)
        assert directory.read("proofs/inner/state") == b"second"


def test_writer_does_not_create_partial_destination_or_leave_temps_after_error(tmp_path, monkeypatch):
    with api().Directory(tmp_path) as directory:
        real_write = os.write

        def broken_write(fd, data):
            raise OSError("injected write failure")

        monkeypatch.setattr(os, "write", broken_write)
        failure(lambda: directory.atomic_write("state", b"data"), code=5)
        monkeypatch.setattr(os, "write", real_write)
        assert not (tmp_path / "state").exists()
        assert not list(tmp_path.glob(".prove-tmp-*"))


def test_copy_streams_file_and_preserves_immutable_destination(tmp_path):
    source_root, destination_root = tmp_path / "source", tmp_path / "destination"
    source_root.mkdir()
    destination_root.mkdir()
    payload = b"streamed-content" * 100_000
    (source_root / "source.bin").write_bytes(payload)

    with api().Directory(source_root) as source, api().Directory(destination_root) as destination:
        assert source.copy_file_to("source.bin", destination, "nested/copy.bin") == (
            hashlib.sha256(payload).hexdigest(), len(payload)
        )
        assert destination.read("nested/copy.bin") == payload
        failure(lambda: source.copy_file_to("source.bin", destination, "nested/copy.bin"))
        assert destination.read("nested/copy.bin") == payload


def test_mkdirs_rejects_file_collision(tmp_path):
    (tmp_path / "not-directory").write_bytes(b"file")
    with api().Directory(tmp_path) as directory:
        failure(lambda: directory.mkdirs("not-directory/child"))


def test_recover_lock_requires_observed_digest_and_never_evicts_live_writer(tmp_path):
    filesystem = api()
    with filesystem.Directory(tmp_path) as directory:
        directory.mkdirs(".prove")
        lock_path = tmp_path / ".prove" / "lock"
        lock_path.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        failure(lambda: filesystem.recover_lock(directory, "00" * 32))
        filesystem.recover_lock(directory, expected)
        assert not lock_path.exists()

        with filesystem.WriterLock(directory):
            live_digest, _ = directory.digest(".prove/lock")
            failure(lambda: filesystem.recover_lock(directory, live_digest), code=5)
            assert lock_path.exists()


def test_recovery_of_a_missing_lock_does_not_create_the_prove_directory(tmp_path):
    filesystem = api()
    with filesystem.Directory(tmp_path) as directory:
        failure(lambda: filesystem.recover_lock(directory, "00" * 32), code=5)
    assert not (tmp_path / ".prove").exists()


def test_writer_lock_does_not_unlink_a_replaced_lock(tmp_path):
    filesystem = api()
    with filesystem.Directory(tmp_path) as directory:
        with filesystem.WriterLock(directory):
            lock_path = tmp_path / ".prove" / "lock"
            lock_path.unlink()
            lock_path.write_bytes(b"replacement")
        assert lock_path.read_bytes() == b"replacement"


def test_second_writer_reports_lock_contention_as_operational(tmp_path):
    filesystem = api()
    with filesystem.Directory(tmp_path) as directory:
        with filesystem.WriterLock(directory):
            failure(lambda: filesystem.WriterLock(directory).__enter__(), code=5)


def test_digest_rejects_in_place_final_file_mutation(tmp_path, monkeypatch):
    filesystem = api()
    target = tmp_path / "output.txt"
    target.write_bytes(b"original")
    real_read = os.read
    changed = False

    def mutate_after_read(fd, count):
        nonlocal changed
        value = real_read(fd, count)
        if value and not changed:
            changed = True
            target.write_bytes(b"changed!")
        return value

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "read", mutate_after_read)
        failure(lambda: directory.digest("output.txt"), code=5)
    assert changed


@pytest.mark.parametrize("failure", ["write", "fsync", "release"])
def test_lock_failures_are_structured(tmp_path, monkeypatch, failure):
    filesystem = api()
    original_write, original_sync, original_unlink = os.write, os.fsync, os.unlink

    def broken_write(fd, data):
        raise OSError("injected lock write failure")

    def broken_sync(fd):
        raise OSError("injected lock sync failure")

    def broken_unlink(path, *args, **kwargs):
        if path == "lock":
            raise OSError("injected lock release failure")
        return original_unlink(path, *args, **kwargs)

    if failure == "write":
        monkeypatch.setattr(filesystem.os, "write", broken_write)
    elif failure == "fsync":
        monkeypatch.setattr(filesystem.os, "fsync", broken_sync)
    else:
        monkeypatch.setattr(filesystem.os, "unlink", broken_unlink)
    with filesystem.Directory(tmp_path) as directory:
        with pytest.raises(TallyLockError) as caught:
            with filesystem.WriterLock(directory):
                pass
    assert caught.value.code == 5


def test_no_clobber_preserves_destination_created_during_copy(tmp_path, monkeypatch):
    filesystem = api()
    source_root, destination_root = tmp_path / "source", tmp_path / "destination"
    source_root.mkdir()
    destination_root.mkdir()
    (source_root / "input.txt").write_bytes(b"source")
    real_temporary = filesystem.Directory._temporary

    def competing_destination(self, parent):
        fd, name = real_temporary(self, parent)
        if self.root == destination_root:
            os.close(fd)
            os.unlink(name, dir_fd=parent)
            (destination_root / "output.txt").write_bytes(b"winner")
            return real_temporary(self, parent)
        return fd, name

    monkeypatch.setattr(filesystem.Directory, "_temporary", competing_destination)
    with filesystem.Directory(source_root) as source, filesystem.Directory(destination_root) as destination:
        failure(lambda: source.copy_file_to("input.txt", destination, "output.txt"))
    assert (destination_root / "output.txt").read_bytes() == b"winner"


def test_writer_rejects_prove_directory_replaced_during_metadata_write(tmp_path, monkeypatch):
    filesystem = api()
    original_write = filesystem._write_all
    swapped = False

    def replace_prove_directory(fd, data):
        nonlocal swapped
        original_write(fd, data)
        if not swapped:
            swapped = True
            (tmp_path / ".prove").rename(tmp_path / "retired-prove")
            (tmp_path / ".prove").mkdir()

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem, "_write_all", replace_prove_directory)
        failure(lambda: filesystem.WriterLock(directory).__enter__(), code=5)
    assert swapped


def test_enumeration_fstat_failure_is_structured_and_closes_child_fd(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "output.txt").write_bytes(b"output")
    original_fstat = os.fstat
    before = len(os.listdir("/proc/self/fd"))

    def broken_fstat(fd):
        raise OSError("injected child stat failure")

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "fstat", broken_fstat)
        failure(lambda: directory.list_files(), code=5)
    assert len(os.listdir("/proc/self/fd")) == before
    monkeypatch.setattr(filesystem.os, "fstat", original_fstat)


def test_recovery_hashes_full_lock_despite_short_initial_read(tmp_path, monkeypatch):
    filesystem = api()
    lock_bytes = b"abcdef"
    (tmp_path / ".prove").mkdir()
    (tmp_path / ".prove" / "lock").write_bytes(lock_bytes)
    original_read = os.read
    first = True

    def short_first_read(fd, count):
        nonlocal first
        if first:
            first = False
            return original_read(fd, 3)
        return original_read(fd, count)

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "read", short_first_read)
        parent, _, _, _ = directory._parent(".prove/lock")
        fd = os.open("lock", os.O_RDONLY, dir_fd=parent)
        try:
            assert filesystem._lock_bytes(fd) == lock_bytes
        finally:
            os.close(fd)
            os.close(parent)


def test_transition_close_error_is_structured_and_closes_transferred_descriptor(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "file.txt").write_bytes(b"data")
    original_close = os.close
    before = len(os.listdir("/proc/self/fd"))
    first = True

    def close_then_fail(fd):
        nonlocal first
        original_close(fd)
        if first:
            first = False
            raise OSError("injected close failure after close")

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "close", close_then_fail)
        failure(lambda: directory.read("nested/file.txt"), code=5)
        monkeypatch.setattr(filesystem.os, "close", original_close)
    assert len(os.listdir("/proc/self/fd")) == before


def test_stream_final_close_error_preserves_primary_and_closes_parent(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "file.txt").write_bytes(b"data")
    original_close = os.close
    before = len(os.listdir("/proc/self/fd"))
    first = True

    def close_then_fail(fd):
        nonlocal first
        original_close(fd)
        if first:
            first = False
            raise OSError("injected close failure after close")

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(filesystem.os, "close", close_then_fail)
        with pytest.raises(TallyLockError) as caught:
            directory._stream("file.txt", lambda chunk: (_ for _ in ()).throw(OSError("primary stream failure")))
        monkeypatch.setattr(filesystem.os, "close", original_close)
    assert caught.value.code == 5
    assert "primary stream failure" in str(caught.value)
    assert len(os.listdir("/proc/self/fd")) == before


@contextmanager
def close_faults(monkeypatch, *, fail_at=None, close_error=None):
    """Exercise real fd ownership while close reports failure after releasing it."""
    real_open, real_dup, real_close = os.open, os.dup, os.close
    baseline = len(os.listdir("/proc/self/fd"))
    live, retries, closes = set(), [], []

    def opened(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        live.add(fd)
        return fd

    def duplicated(fd):
        result = real_dup(fd)
        live.add(result)
        return result

    def closed(fd):
        closes.append(fd)
        if fd not in live:
            retries.append(fd)
        live.discard(fd)
        real_close(fd)
        if fail_at is None or len(closes) == fail_at:
            raise close_error or OSError(errno.EIO, "secondary close failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opened)
        patch.setattr(os, "dup", duplicated)
        patch.setattr(os, "close", closed)
        try:
            yield closes
        finally:
            leaked = set(live)
            for fd in leaked:
                real_close(fd)
            assert not leaked, f"leaked descriptors: {leaked}"
            assert not retries, f"retried released descriptors: {retries}"
            assert len(os.listdir("/proc/self/fd")) == baseline


@pytest.mark.parametrize("fail_at", [1, 2, None])
def test_identity_rewalk_close_ownership(tmp_path, monkeypatch, fail_at):
    (tmp_path / "nested").mkdir()
    with api().Directory(tmp_path) as directory:
        fd, identities = directory._walk_dirs(["nested"])
        os.close(fd)
        with close_faults(monkeypatch, fail_at=fail_at):
            failure(lambda: directory._verify_dirs(["nested"], identities, "nested/file"), code=5)


@pytest.mark.parametrize("layout,fail_at", [("empty", 1), ("file", 1), ("file", 2), ("nested", None)])
def test_enumeration_close_ownership(tmp_path, monkeypatch, layout, fail_at):
    if layout == "nested":
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "file").write_bytes(b"data")
    elif layout == "file":
        (tmp_path / "file").write_bytes(b"data")
    with api().Directory(tmp_path) as directory:
        with close_faults(monkeypatch, fail_at=fail_at):
            failure(directory.list_files, code=5)


def test_failed_file_open_preserves_primary_when_parent_close_fails(tmp_path, monkeypatch):
    with api().Directory(tmp_path) as directory:
        with close_faults(monkeypatch):
            with pytest.raises(TallyLockError) as caught:
                directory.read("missing")
            assert caught.value.code == 5
            assert "cannot open file" in str(caught.value)
            assert "secondary close" not in str(caught.value)


@pytest.mark.parametrize("operation", ["walk", "rewalk", "enumerate"])
@pytest.mark.parametrize("interruption", [False, True])
def test_inspection_failure_survives_all_close_failures(tmp_path, monkeypatch, operation, interruption):
    filesystem = api()
    (tmp_path / "nested").mkdir()
    (tmp_path / "file").write_bytes(b"data")
    primary = KeyboardInterrupt("primary inspection") if interruption else OSError(errno.EIO, "primary inspection")
    with filesystem.Directory(tmp_path) as directory:
        fd, identities = directory._walk_dirs(["nested"])
        os.close(fd)

        def broken_stat(fd):
            raise primary

        calls = {
            "walk": lambda: directory._walk_dirs(["nested"]),
            "rewalk": lambda: directory._verify_dirs(["nested"], identities, "nested/file"),
            "enumerate": directory.list_files,
        }
        with monkeypatch.context() as patch:
            patch.setattr(os, "fstat", broken_stat)
            with close_faults(patch):
                with pytest.raises(KeyboardInterrupt if interruption else TallyLockError) as caught:
                    calls[operation]()
                assert "primary inspection" in str(caught.value)
                if interruption:
                    assert caught.value is primary


@pytest.mark.parametrize("operation", ["stream", "write", "acquire"])
@pytest.mark.parametrize("interruption", [False, True])
def test_operation_primary_survives_all_close_failures(tmp_path, monkeypatch, operation, interruption):
    filesystem = api()
    (tmp_path / "file").write_bytes(b"data")
    (tmp_path / ".prove").mkdir()
    primary = KeyboardInterrupt("primary operation") if interruption else OSError(errno.EIO, "primary operation")

    def broken(*args):
        raise primary

    with filesystem.Directory(tmp_path) as directory:
        if operation == "acquire":
            # Fail before a descriptor transition can short circuit acquisition.
            monkeypatch.setattr(directory, "_verify_dirs", broken)
        with close_faults(monkeypatch):
            with pytest.raises(KeyboardInterrupt if interruption else TallyLockError) as caught:
                if operation == "stream":
                    directory._stream("file", broken)
                elif operation == "write":
                    directory._write_private("new", broken, False)
                else:
                    # Root-level acquisition parent avoids an earlier close failure.
                    monkeypatch.setattr(filesystem, "_lock_parent", lambda *args, **kwargs: (os.dup(directory.fd), ()))
                    filesystem.WriterLock(directory).__enter__()
            assert "primary operation" in str(caught.value)
            if interruption:
                assert caught.value is primary
        assert not list(tmp_path.glob(".prove-tmp-*"))


def test_reopened_file_inspection_preserves_primary(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "file").write_bytes(b"data")
    real_stat = os.fstat
    count = 0

    def broken_reopened_stat(fd):
        nonlocal count
        count += 1
        if count == 3:
            raise OSError(errno.EIO, "primary reopened inspection")
        return real_stat(fd)

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(os, "fstat", broken_reopened_stat)
        with close_faults(monkeypatch, fail_at=2):
            with pytest.raises(TallyLockError) as caught:
                directory.read("file")
            assert "primary reopened inspection" in str(caught.value)


def test_mkdirs_final_close_is_structured(tmp_path, monkeypatch):
    with api().Directory(tmp_path) as directory:
        with close_faults(monkeypatch, fail_at=2):
            failure(lambda: directory.mkdirs("nested"), code=5)


@pytest.mark.parametrize("operation", ["write", "lock", "recover"])
@pytest.mark.parametrize("fail_at", range(1, 14))
def test_each_persistence_close_boundary_is_structured(tmp_path, monkeypatch, operation, fail_at):
    filesystem = api()
    (tmp_path / ".prove").mkdir()
    if operation == "recover":
        (tmp_path / ".prove" / "lock").write_bytes(b"stale")
    with filesystem.Directory(tmp_path) as directory:
        with close_faults(monkeypatch, fail_at=fail_at) as closes:
            try:
                if operation == "write":
                    directory.atomic_write("new", b"data")
                elif operation == "lock":
                    with filesystem.WriterLock(directory):
                        pass
                else:
                    filesystem.recover_lock(directory, hashlib.sha256(b"stale").hexdigest())
            except TallyLockError as error:
                assert error.code == 5
                assert len(closes) >= fail_at
            else:
                assert len(closes) < fail_at, "close failure was silently ignored"


def test_recovery_preserves_mismatch_when_cleanup_fails(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / ".prove").mkdir()
    (tmp_path / ".prove" / "lock").write_bytes(b"stale")
    with filesystem.Directory(tmp_path) as directory:
        with close_faults(monkeypatch, fail_at=4):
            with pytest.raises(TallyLockError) as caught:
                filesystem.recover_lock(directory, "00" * 32)
            assert caught.value.code == 2
            assert "SHA256 does not match" in str(caught.value)


def test_lock_reopen_inspection_failure_survives_close_error(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "lock").write_bytes(b"lock")
    with filesystem.Directory(tmp_path) as directory:
        identity = (tmp_path / "lock").stat()

        def broken_stat(fd):
            raise OSError(errno.EIO, "primary lock inspection")

        with monkeypatch.context() as patch:
            patch.setattr(os, "fstat", broken_stat)
            with close_faults(patch):
                with pytest.raises(TallyLockError) as caught:
                    filesystem._reachable_lock(directory.fd, identity)
                assert "primary lock inspection" in str(caught.value)


@pytest.mark.parametrize("has_primary", [False, True])
def test_stream_cleanup_interruption_drains_remaining_fds(tmp_path, monkeypatch, has_primary):
    filesystem = api()
    (tmp_path / "file").write_bytes(b"data")
    primary = RuntimeError("primary callback")
    interrupted = KeyboardInterrupt("secondary close interruption")

    def consume(chunk):
        if has_primary:
            raise primary

    with filesystem.Directory(tmp_path) as directory:
        with close_faults(monkeypatch, close_error=interrupted):
            with pytest.raises(RuntimeError if has_primary else KeyboardInterrupt) as caught:
                directory._stream("file", consume)
            assert caught.value is (primary if has_primary else interrupted)


@pytest.mark.parametrize("operation", ["write", "recover"])
def test_unlock_and_temp_cleanup_preserve_interrupted_primary(tmp_path, monkeypatch, operation):
    filesystem = api()
    (tmp_path / ".prove").mkdir()
    (tmp_path / ".prove" / "lock").write_bytes(b"stale")
    real_unlink, real_flock = os.unlink, filesystem.fcntl.flock
    primary = KeyboardInterrupt("primary persistence interruption")

    def fail_unlink(path, *args, **kwargs):
        if path == "lock":
            raise primary
        if str(path).startswith(".prove-tmp-"):
            real_unlink(path, *args, **kwargs)
            raise OSError(errno.EIO, "secondary temp cleanup")
        return real_unlink(path, *args, **kwargs)

    def fail_unlock(fd, operation):
        if operation == filesystem.fcntl.LOCK_UN:
            raise OSError(errno.EIO, "secondary unlock")
        return real_flock(fd, operation)

    def fail_write(fd):
        raise primary

    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(os, "unlink", fail_unlink)
        monkeypatch.setattr(filesystem.fcntl, "flock", fail_unlock)
        # Recovery reaches unlink after six closes. Writing reaches its callback directly.
        with close_faults(monkeypatch, fail_at=7 if operation == "recover" else 1):
            with pytest.raises(KeyboardInterrupt) as caught:
                if operation == "write":
                    directory._write_private("new", fail_write, False)
                else:
                    filesystem.recover_lock(directory, hashlib.sha256(b"stale").hexdigest())
            assert caught.value is primary
        assert not list(tmp_path.glob(".prove-tmp-*"))


def test_directory_reentry_preserves_owned_root(tmp_path, monkeypatch):
    filesystem = api()
    (tmp_path / "file").write_bytes(b"data")
    with filesystem.Directory(tmp_path) as directory:
        original_fd = directory.fd
        try:
            with close_faults(monkeypatch, fail_at=100):
                failure(directory.__enter__, code=5)
                assert directory.fd == original_fd
                assert directory.read("file") == b"data"
        finally:
            # Keep a broken reentry implementation from leaking the original root.
            directory._fd = original_fd


def test_writer_lock_reentry_preserves_original_lock(tmp_path, monkeypatch):
    filesystem = api()
    with filesystem.Directory(tmp_path) as directory:
        with filesystem.WriterLock(directory) as lock:
            original_fd, original_parent = lock._fd, lock._parent
            before = (tmp_path / ".prove" / "lock").read_bytes()
            with close_faults(monkeypatch, fail_at=100):
                failure(lock.__enter__, code=5)
                assert lock._fd == original_fd
                assert lock._parent == original_parent
                assert (tmp_path / ".prove" / "lock").read_bytes() == before
                failure(lambda: filesystem.recover_lock(directory, hashlib.sha256(before).hexdigest()), code=5)
        assert not (tmp_path / ".prove" / "lock").exists()
