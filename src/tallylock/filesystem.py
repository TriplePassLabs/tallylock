"""Descriptor-relative filesystem primitives for receipt storage."""
from __future__ import annotations
import errno
import hashlib
import json
import os
import secrets
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from .errors import TallyLockError
from .canonical import MAX_SAFE_INTEGER
from .paths import validate_path, validate_paths

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on platforms without flock.
    fcntl = None

_CHUNK = 1024 * 1024
_LOCK_MAX = 64 * 1024


def _require_lock_primitives() -> None:
    if fcntl is None or not all(hasattr(fcntl, name) for name in ("flock", "LOCK_EX", "LOCK_NB", "LOCK_UN")):
        raise TallyLockError("required advisory locking primitives are unsupported", code=4)


def _problem(error: OSError, message: str, *, conflict: bool = False) -> TallyLockError:
    if conflict or error.errno in (errno.EEXIST, errno.ENOTDIR, errno.ELOOP, errno.ENXIO):
        return TallyLockError(message)
    return TallyLockError(f"{message}: {error.strerror or error}", code=5)


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode)) == (
        right.st_dev, right.st_ino, stat.S_IFMT(right.st_mode))


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return _same(left, right) and (left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
        right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def _regular(info: os.stat_result, path: str) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise TallyLockError(f"path is not a regular file: {path!r}")


def _parts(path: str) -> list[str]:
    validate_path(path, limit=2048)
    return path.split("/")


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        offset += written


def _close_owned(fd: int, message: str) -> BaseException | None:
    """Close exactly once; callers decide whether a cleanup error is primary."""
    try:
        os.close(fd)
    except OSError as error:
        return TallyLockError(f"{message}: {error.strerror or error}", code=5)
    except BaseException as error:
        return error
    return None


class _Descriptors:
    """Own fds until transfer; consume ownership before an ambiguous close."""
    def __init__(self):
        self._owned: dict[int, str] = {}

    def __enter__(self) -> "_Descriptors":
        return self

    def add(self, fd: int, message: str) -> int:
        self._owned[fd] = message
        return fd

    def take(self, fd: int) -> int:
        del self._owned[fd]
        return fd

    def close(self, fd: int) -> None:
        message = self._owned[fd]
        error = _close_owned(self.take(fd), message)
        if error is not None:
            raise error

    def __exit__(self, exc_type, exc, traceback) -> None:
        failure: BaseException | None = None
        while self._owned:
            fd, message = self._owned.popitem()
            error = _close_owned(fd, message)
            failure = failure or error
        if exc_type is None and failure is not None:
            raise failure


def _directory_names(fd: int) -> list[str]:
    """Use a fresh open description so overlay readdir caches cannot hide changes."""
    with _Descriptors() as owned:
        fresh = owned.add(os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd),
                          "cannot close directory enumeration descriptor")
        if not _same(os.fstat(fd), os.fstat(fresh)):
            raise TallyLockError("directory changed before enumeration", code=5)
        return os.listdir(fresh)


def _contains_directory(root_fd: int, wanted: os.stat_result) -> bool:
    """Find a directory inode through descendants, including bind-mount aliases."""
    try:
        with _Descriptors() as owned:
            start = owned.add(os.dup(root_fd), "cannot close overlap traversal root")
            root_info = os.fstat(start)
            if _same(root_info, wanted):
                return True
            visited = {(root_info.st_dev, root_info.st_ino)}
            stack = [(start, iter(_directory_names(start)))]
            while stack:
                current, names = stack[-1]
                try:
                    name = next(names)
                except StopIteration:
                    stack.pop()
                    owned.close(current)
                    continue
                before = os.stat(name, dir_fd=current, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    continue
                child = owned.add(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current),
                                  "cannot close overlap traversal directory")
                info = os.fstat(child)
                if not _same(before, info):
                    raise TallyLockError("directory changed during overlap traversal", code=5)
                if _same(info, wanted):
                    return True
                identity = (info.st_dev, info.st_ino)
                if identity in visited:
                    owned.close(child)
                    continue
                visited.add(identity)
                stack.append((child, iter(_directory_names(child))))
            return False
    except OSError as error:
        raise _problem(error, "cannot inspect source/receipt directory identities") from error


class Directory:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._fd: int | None = None
        self._tracked_temporary: str | None = None

    def __enter__(self) -> "Directory":
        if self._fd is not None:
            raise TallyLockError("directory is already open", code=5)
        if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
            raise TallyLockError("TallyLock writes files only on Linux. On Windows, use WSL or a Linux container", code=4)
        try:
            self._fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise _problem(error, f"cannot open directory root {self.root}") from error
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            failure = _close_owned(fd, "cannot close directory root")
            if exc_type is None and failure is not None:
                raise failure

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise TallyLockError("directory is not open", code=5)
        return self._fd

    def _walk_dirs(self, parts: list[str], *, create: bool = False) -> tuple[int, tuple[os.stat_result, ...]]:
        try:
            current = os.dup(self.fd)
        except OSError as error:
            raise _problem(error, "cannot duplicate directory descriptor") from error
        identities: list[os.stat_result] = []
        with _Descriptors() as owned:
            owned.add(current, "cannot close directory after traversal")
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    except OSError as error:
                        raise _problem(error, f"cannot create directory {part!r}") from error
                    else:
                        try:
                            os.fsync(current)
                        except OSError as error:
                            raise _problem(error, f"cannot persist new directory {part!r}") from error
                try:
                    following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                except OSError as error:
                    raise _problem(error, f"invalid directory path component {part!r}") from error
                owned.add(following, f"cannot close directory {part!r}")
                try:
                    identities.append(os.fstat(following))
                except OSError as error:
                    raise _problem(error, f"cannot inspect directory {part!r}") from error
                owned.close(current)
                current = following
            return owned.take(current), tuple(identities)

    def _parent(self, path: str, *, create: bool = False) -> tuple[int, str, list[str], tuple[os.stat_result, ...]]:
        parts = _parts(path)
        parent, identities = self._walk_dirs(parts[:-1], create=create)
        return parent, parts[-1], parts[:-1], identities

    def _verify_dirs(self, parts: list[str], expected: tuple[os.stat_result, ...], path: str) -> None:
        try:
            current = os.dup(self.fd)
        except OSError as error:
            raise _problem(error, f"cannot rewalk directory for {path!r}") from error
        with _Descriptors() as owned:
            owned.add(current, f"cannot close directory while rewalking {path!r}")
            if len(parts) != len(expected):
                raise TallyLockError(f"directory identity bookkeeping failed for {path!r}", code=5)
            for part, wanted in zip(parts, expected):
                try:
                    following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                except OSError as error:
                    raise _problem(error, f"directory changed while operating on {path!r}") from error
                owned.add(following, f"cannot close directory while rewalking {path!r}")
                try:
                    if not _same(wanted, os.fstat(following)):
                        raise TallyLockError(f"directory changed while operating on {path!r}", code=5)
                except OSError as error:
                    raise _problem(error, f"cannot inspect directory while operating on {path!r}") from error
                owned.close(current)
                current = following

    def _open_file(self, path: str) -> tuple[int, int, str, list[str], tuple[os.stat_result, ...]]:
        parent, name, parents, identities = self._parent(path)
        with _Descriptors() as owned:
            owned.add(parent, f"cannot close parent for {path!r}")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
            except OSError as error:
                raise _problem(error, f"cannot open file {path!r}") from error
            return owned.take(parent), fd, name, parents, identities

    def _stream(self, path: str, consume: Callable[[bytes], None], limit: int | None = None,
                *, persist: bool = False, expected_bytes: int | None = None) -> tuple[str, int]:
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
            raise TallyLockError("read limit must be a nonnegative integer")
        if expected_bytes is not None and (type(expected_bytes) is not int or not 0 <= expected_bytes <= MAX_SAFE_INTEGER):
            raise TallyLockError("expected bytes must be a nonnegative safe integer")
        parent, fd, name, parents, parent_ids = self._open_file(path)
        with _Descriptors() as owned:
            owned.add(parent, f"cannot close parent for {path!r}")
            owned.add(fd, f"cannot close file {path!r}")
            try:
                before = os.fstat(fd)
                _regular(before, path)
                if expected_bytes is not None and before.st_size != expected_bytes:
                    raise TallyLockError(f"file byte length differs from inventory: {path!r}")
                if limit is not None and before.st_size > limit:
                    raise TallyLockError(f"file exceeds read limit: {path!r}")
                digest, total = hashlib.sha256(), 0
                while True:
                    chunk = os.read(fd, _CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if limit is not None and total > limit:
                        raise TallyLockError(f"file exceeds read limit: {path!r}")
                    digest.update(chunk)
                    consume(chunk)
                after = os.fstat(fd)
                if not _same_file_state(before, after) or total != before.st_size:
                    raise TallyLockError(f"file changed while reading {path!r}", code=5)
                if persist:
                    os.fsync(fd)
                    if not _same_file_state(after, os.fstat(fd)):
                        raise TallyLockError(f"file changed while persisting {path!r}", code=5)
                self._verify_dirs(parents, parent_ids, path)
                try:
                    reopened = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
                except OSError as error:
                    raise _problem(error, f"file changed while reading {path!r}") from error
                with _Descriptors() as recheck:
                    recheck.add(reopened, f"cannot close reopened file {path!r}")
                    if not _same_file_state(after, os.fstat(reopened)):
                        raise TallyLockError(f"file changed while reading {path!r}", code=5)
                if persist:
                    self._persist_dirs(parents, parent_ids, path)
                    if not _same_file_state(after, os.fstat(fd)):
                        raise TallyLockError(f"file changed while persisting {path!r}", code=5)
                    self._verify_dirs(parents, parent_ids, path)
                    if not _same_file_state(after, os.stat(name, dir_fd=parent, follow_symlinks=False)):
                        raise TallyLockError(f"file changed while persisting {path!r}", code=5)
                return digest.hexdigest(), total
            except OSError as error:
                raise _problem(error, f"cannot read file {path!r}") from error

    def read(self, path: str, limit: int = 8_388_608) -> bytes:
        chunks: list[bytes] = []
        self._stream(path, chunks.append, limit)
        return b"".join(chunks)

    def digest(self, path: str, *, expected_bytes: int | None = None) -> tuple[str, int]:
        return self._stream(path, lambda _: None, expected_bytes=expected_bytes)

    def _persist_dirs(self, parts: list[str], expected: tuple[os.stat_result, ...], path: str) -> None:
        """Sync child-to-root through a verified owned chain, including reused dirs."""
        try:
            with _Descriptors() as owned:
                current = owned.add(os.dup(self.fd), f"cannot close persistence root for {path!r}")
                chain = [current]
                if len(parts) != len(expected):
                    raise TallyLockError("directory identity bookkeeping failed", code=5)
                for part, wanted in zip(parts, expected):
                    current = owned.add(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                                dir_fd=current), f"cannot close persistence directory for {path!r}")
                    if not _same(wanted, os.fstat(current)):
                        raise TallyLockError(f"directory changed while persisting {path!r}", code=5)
                    chain.append(current)
                for fd in reversed(chain):
                    os.fsync(fd)
        except OSError as error:
            raise _problem(error, f"cannot persist directory chain for {path!r}") from error

    def persist_file(self, path: str) -> tuple[str, int]:
        return self._stream(path, lambda _: None, persist=True)

    def list_files(self, prefix: str = "") -> list[str]:
        entries = self._list_entries(prefix)
        return sorted((path for path, is_file in entries.items() if is_file), key=lambda value: value.encode("utf-8"))

    def _list_entries(self, prefix: str = "", *, missing_ok: bool = False) -> dict[str, bool]:
        """Inspect the namespace including empty directories for collision preflight."""
        if not isinstance(prefix, str):
            raise TallyLockError("list prefix must be a string")
        parts = [] if not prefix else _parts(prefix)
        results: dict[str, bool] = {}
        with _Descriptors() as owned:
            if parts and missing_ok:
                parent, final, parents, ancestor_ids = self._parent(prefix)
                owned.add(parent, "cannot close optional enumeration parent")
                try:
                    start = os.open(final, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                except FileNotFoundError:
                    # Only absence at this exact final open is optional. A failed
                    # ancestor walk or any later descendant read must propagate.
                    self._verify_dirs(parents, ancestor_ids, prefix)
                    return {}
                except OSError as error:
                    raise _problem(error, f"cannot open enumeration prefix {prefix!r}") from error
                owned.add(start, "cannot close enumeration directory")
                try:
                    identities = ancestor_ids + (os.fstat(start),)
                except OSError as error:
                    raise _problem(error, f"cannot inspect enumeration prefix {prefix!r}") from error
                owned.close(parent)
            else:
                start, identities = self._walk_dirs(parts)
                owned.add(start, "cannot close enumeration directory")
            try:
                root_info = os.fstat(start)
                active = {(root_info.st_dev, root_info.st_ino)}
                stack = [(start, prefix, iter(_directory_names(start)), (root_info.st_dev, root_info.st_ino))]
                while stack:
                    fd, relative, names, identity = stack[-1]
                    try:
                        name = next(names)
                    except StopIteration:
                        stack.pop()
                        active.remove(identity)
                        owned.close(fd)
                        continue
                    candidate = f"{relative}/{name}" if relative else name
                    validate_path(candidate, limit=2048)
                    child = owned.add(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd),
                                      f"cannot close enumerated path {candidate!r}")
                    info = os.fstat(child)
                    if stat.S_ISDIR(info.st_mode):
                        child_identity = (info.st_dev, info.st_ino)
                        if child_identity in active:
                            raise TallyLockError(f"cyclic directory namespace at {candidate!r}")
                        results[candidate] = False
                        active.add(child_identity)
                        stack.append((child, candidate, iter(_directory_names(child)), child_identity))
                    elif stat.S_ISREG(info.st_mode):
                        results[candidate] = True
                        owned.close(child)
                    else:
                        raise TallyLockError(f"path is not a regular file: {candidate!r}")
            except OSError as error:
                raise _problem(error, f"cannot enumerate {prefix or '.'!r}") from error
            self._verify_dirs(parts, identities, prefix or ".")
            validate_paths([path for path, is_file in results.items() if is_file], limit=2048,
                           directories=[path for path, is_file in results.items() if not is_file])
            return results

    def mkdirs(self, path: str) -> None:
        fd, _ = self._walk_dirs(_parts(path), create=True)
        with _Descriptors() as owned:
            owned.add(fd, f"cannot close created directory {path!r}")

    def mkdir_exclusive(self, path: str) -> None:
        parent, name, parents, parent_ids = self._parent(path, create=True)
        with _Descriptors() as owned:
            owned.add(parent, f"cannot close parent for {path!r}")
            try:
                self._verify_dirs(parents, parent_ids, path)
                os.mkdir(name, 0o700, dir_fd=parent)
                created = os.stat(name, dir_fd=parent, follow_symlinks=False)
                child = owned.add(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent),
                                  f"cannot close new directory {path!r}")
                if not _same(created, os.fstat(child)):
                    raise TallyLockError(f"new directory changed: {path!r}", code=5)
                os.fsync(child)
                self._persist_dirs(parents, parent_ids, path)
                self._verify_dirs(parents, parent_ids, path)
                if not _same(created, os.stat(name, dir_fd=parent, follow_symlinks=False)):
                    raise TallyLockError(f"new directory changed: {path!r}", code=5)
            except OSError as error:
                raise _problem(error, f"cannot exclusively create directory {path!r}") from error

    def _temporary(self, parent: int) -> tuple[int, str]:
        names = ([self._tracked_temporary] if self._tracked_temporary is not None
                 else [f".prove-tmp-{secrets.token_hex(16)}" for _ in range(32)])
        for name in names:
            assert name is not None
            try:
                return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent), name
            except FileExistsError:
                continue
            except OSError as error:
                raise _problem(error, "cannot create private temporary file") from error
        raise TallyLockError("cannot allocate private temporary file", code=5)

    def _publish(self, parent: int, temp: str, final: str, replace: bool) -> None:
        try:
            if replace:
                os.replace(temp, final, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                os.link(temp, final, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.unlink(temp, dir_fd=parent)
            os.fsync(parent)
        except OSError as error:
            raise _problem(error, f"cannot publish destination {final!r}") from error

    def _cleanup_temp(self, parent: int, temp: str | None) -> TallyLockError | None:
        if temp is None:
            return None
        try:
            os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            return None
        except OSError as error:
            return _problem(error, "cannot clean private temporary file")
        return None

    @contextmanager
    def tracked_temporary(self, temporary: str):
        if (not isinstance(temporary, str) or len(temporary) != 43
                                      or not temporary.startswith(".prove-tmp-") or "/" in temporary
                                      or any(char not in "0123456789abcdef" for char in temporary[11:])):
            raise TallyLockError("invalid tracked temporary name")
        if self._tracked_temporary is not None:
            raise TallyLockError("tracked temporary is already active", code=5)
        self._tracked_temporary = temporary
        try:
            yield
        finally:
            self._tracked_temporary = None

    def _write_private(self, path: str, write: Callable[[int], tuple[str, int] | None], replace: bool) -> tuple[str, int] | None:
        parent, final, parents, parent_ids = self._parent(path, create=True)
        with _Descriptors() as owned:
            owned.add(parent, "cannot close destination directory")
            temp: str | None = None
            primary: BaseException | None = None
            try:
                output, temp = self._temporary(parent)
                with _Descriptors() as outputs:
                    outputs.add(output, f"cannot close private file for {path!r}")
                    result = write(output)
                    os.fsync(output)
                self._verify_dirs(parents, parent_ids, path)
                self._publish(parent, temp, final, replace)
                temp = None
                self._verify_dirs(parents, parent_ids, path)
                return result
            except BaseException as error:
                primary = error
                if isinstance(error, OSError):
                    raise _problem(error, f"cannot write {path!r}") from error
                raise
            finally:
                try:
                    cleanup_error = self._cleanup_temp(parent, temp)
                except BaseException:
                    if primary is None:
                        raise
                else:
                    if primary is None and cleanup_error is not None:
                        raise cleanup_error

    def atomic_write(self, path: str, data: bytes, replace: bool = False) -> None:
        if not isinstance(data, bytes) or not isinstance(replace, bool):
            raise TallyLockError("atomic writes require bytes and a boolean replace flag")
        self._write_private(path, lambda fd: (_write_all(fd, data), None)[1], replace)

    def copy_file_to(self, path: str, destination: "Directory", destination_path: str) -> tuple[str, int]:
        if not isinstance(destination, Directory):
            raise TallyLockError("destination must be a Directory")
        result = destination._write_private(destination_path, lambda fd: self._stream(path, lambda chunk: _write_all(fd, chunk)), False)
        assert isinstance(result, tuple)
        return result

    def unlink_file(self, path: str, *, missing_ok: bool = False) -> None:
        parent, name, parents, identities = self._parent(path)
        with _Descriptors() as owned:
            owned.add(parent, f"cannot close parent for {path!r}")
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                self._verify_dirs(parents, identities, path)
                if missing_ok:
                    return
                raise TallyLockError(f"missing file: {path!r}")
            except OSError as error:
                raise _problem(error, f"cannot inspect file {path!r}") from error
            _regular(info, path)
            try:
                self._verify_dirs(parents, identities, path)
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
                self._verify_dirs(parents, identities, path)
            except OSError as error:
                raise _problem(error, f"cannot remove file {path!r}") from error


def _lock_parent(directory: Directory, *, create: bool) -> tuple[int, tuple[os.stat_result, ...]]:
    return directory._walk_dirs([".prove"], create=create)


def _lock_bytes(fd: int) -> bytes:
    try:
        info = os.fstat(fd)
        _regular(info, ".prove/lock")
        if info.st_size > _LOCK_MAX:
            raise TallyLockError("lock metadata exceeds 64 KiB", code=5)
        before = info
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(_CHUNK, _LOCK_MAX + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _LOCK_MAX:
                raise TallyLockError("lock metadata exceeds 64 KiB", code=5)
        after = os.fstat(fd)
    except TallyLockError:
        raise
    except OSError as error:
        raise _problem(error, "cannot read lock metadata") from error
    if total > _LOCK_MAX:
        raise TallyLockError("lock metadata exceeds 64 KiB", code=5)
    if not _same_file_state(before, after) or total != before.st_size:
        raise TallyLockError("lock changed while reading metadata", code=5)
    return b"".join(chunks)


def _reachable_lock(parent: int, expected: os.stat_result) -> bool:
    try:
        reopened = os.open("lock", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    except OSError:
        return False
    with _Descriptors() as owned:
        owned.add(reopened, "cannot close reopened writer lock")
        try:
            return _same(expected, os.fstat(reopened))
        except OSError as error:
            raise _problem(error, "cannot inspect reopened writer lock") from error


class WriterLock:
    def __init__(self, directory: Directory):
        self.directory = directory
        self._parent: int | None = None
        self._parent_ids: tuple[os.stat_result, ...] | None = None
        self._fd: int | None = None
        self._metadata: bytes | None = None
        self._identity: os.stat_result | None = None

    def __enter__(self) -> "WriterLock":
        if self._fd is not None or self._parent is not None:
            raise TallyLockError("writer lock is already open", code=5)
        _require_lock_primitives()
        self._parent, self._parent_ids = _lock_parent(self.directory, create=True)
        try:
            self.directory._verify_dirs([".prove"], self._parent_ids, ".prove/lock")
            try:
                self._fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._parent)
            except FileExistsError as error:
                raise TallyLockError("writer lock already exists", code=5) from error
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise TallyLockError("writer lock is held by a live process", code=5) from error
            self._metadata = json.dumps({"token": secrets.token_hex(32), "pid": os.getpid(), "time": time.time()}, sort_keys=True, separators=(",", ":")).encode()
            _write_all(self._fd, self._metadata)
            os.fsync(self._fd)
            os.fsync(self._parent)
            self._identity = os.fstat(self._fd)
            self.directory._verify_dirs([".prove"], self._parent_ids, ".prove/lock")
            if not _reachable_lock(self._parent, self._identity):
                raise TallyLockError("writer lock was replaced before acquisition completed", code=5)
            return self
        except BaseException as error:
            self.__exit__(type(error), error, error.__traceback__)
            if isinstance(error, OSError):
                raise _problem(error, "cannot acquire writer lock") from error
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:
        fd, parent = self._fd, self._parent
        parent_ids, identity, metadata = self._parent_ids, self._identity, self._metadata
        self._fd = self._parent = None
        self._parent_ids = self._identity = self._metadata = None
        try:
            with _Descriptors() as owned:
                if parent is not None:
                    owned.add(parent, "cannot close writer-lock directory")
                if fd is not None:
                    owned.add(fd, "cannot close writer lock")
                if fd is None or parent is None:
                    return
                failure: BaseException | None = None
                try:
                    current = os.fstat(fd)
                    unchanged = identity is not None and _same(identity, current)
                    if parent_ids is None:
                        raise TallyLockError("writer-lock parent identity is missing", code=5)
                    self.directory._verify_dirs([".prove"], parent_ids, ".prove/lock")
                    if unchanged and _reachable_lock(parent, current) and _lock_bytes(fd) == metadata:
                        os.unlink("lock", dir_fd=parent)
                        os.fsync(parent)
                except OSError as error:
                    failure = _problem(error, "cannot release writer lock")
                except BaseException as error:
                    failure = error
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError as error:
                    failure = failure or _problem(error, "cannot unlock writer lock")
                except BaseException as error:
                    failure = failure or error
                if failure is not None:
                    raise failure
        except BaseException:
            if exc_type is None:
                raise


def recover_lock(directory: Directory, expected_sha256: str) -> None:
    _require_lock_primitives()
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or expected_sha256 != expected_sha256.lower():
        raise TallyLockError("expected lock SHA256 must be lowercase hexadecimal")
    try:
        int(expected_sha256, 16)
    except ValueError as error:
        raise TallyLockError("expected lock SHA256 must be lowercase hexadecimal") from error
    parent, parent_ids = _lock_parent(directory, create=False)
    with _Descriptors() as owned:
        owned.add(parent, "cannot close recovery directory")
        try:
            directory._verify_dirs([".prove"], parent_ids, ".prove/lock")
            fd = owned.add(os.open("lock", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent), "cannot close recovered lock")
            identity = os.fstat(fd)
            if hashlib.sha256(_lock_bytes(fd)).hexdigest() != expected_sha256:
                raise TallyLockError("lock SHA256 does not match the explicitly observed value")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise TallyLockError("writer lock is held by a live process", code=5) from error
            primary: BaseException | None = None
            try:
                directory._verify_dirs([".prove"], parent_ids, ".prove/lock")
                if not _same(identity, os.fstat(fd)) or not _reachable_lock(parent, identity):
                    raise TallyLockError("lock changed during recovery", code=5)
                if hashlib.sha256(_lock_bytes(fd)).hexdigest() != expected_sha256:
                    raise TallyLockError("lock changed during recovery", code=5)
                os.unlink("lock", dir_fd=parent)
                os.fsync(parent)
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except BaseException:
                    if primary is None:
                        raise
        except OSError as error:
            raise _problem(error, "cannot recover writer lock") from error
