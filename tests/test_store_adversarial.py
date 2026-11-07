"""Independent receipt persistence acceptance regressions."""

import errno
import os
from pathlib import Path

import pytest

from tallylock import canonical, filesystem, schema, store
from tallylock.errors import TallyLockError
from tallylock.filesystem import Directory


def test_descendant_enoent_never_hides_unlisted_final_artifacts(tmp_path, monkeypatch):
    receipt = tmp_path / 'receipt'
    receipt.mkdir()
    manifest = schema.default_manifest()
    manifest['profile'] = 'trace-v1'
    manifest['attempts'] = [{'id': 'run-1', 'sample_ids': ['sample']}]
    store.register(manifest, receipt)
    artifacts = receipt / 'artifacts'
    artifacts.mkdir()
    (artifacts / 'keep.txt').write_bytes(b'keep')
    (artifacts / 'gone.txt').write_bytes(b'gone')
    identity = artifacts.stat()
    original_open = os.open

    def disappearing_child(path, flags, *args, **kwargs):
        parent = kwargs.get('dir_fd')
        if path == 'gone.txt' and parent is not None:
            current = os.fstat(parent)
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                raise FileNotFoundError(errno.ENOENT, 'injected disappearing child')
        return original_open(path, flags, *args, **kwargs)

    registration_id = canonical.digest(manifest)
    events = []
    for index, (kind, extra) in enumerate([
        ('sample_start', {'sample_id': 'sample'}),
        ('sample_end', {'sample_id': 'sample', 'status': 'completed'}),
        ('attempt_end', {'outcome': 'completed', 'reason': None}),
    ]):
        events.append({'format': 'prove.event.v1', 'registration_id': registration_id,
                       'attempt_id': 'run-1', 'index': index, 'kind': kind, **extra})
    monkeypatch.setattr(filesystem.os, 'open', disappearing_child)
    with pytest.raises(TallyLockError):
        store.seal(receipt, events=events)
    assert not (receipt / 'result.json').exists()
    assert (artifacts / 'keep.txt').read_bytes() == b'keep'
    assert (artifacts / 'gone.txt').read_bytes() == b'gone'


def test_deep_storage_tree_never_leaks_python_recursion_error(tmp_path):
    current = tmp_path
    created = []
    try:
        for _ in range(1010):
            current = current / 'd'
            current.mkdir()
            created.append(current)
        with Directory(tmp_path) as directory:
            try:
                assert directory.list_files() == []
            except TallyLockError as error:
                assert error.code in (2, 5)
    finally:
        # Avoid recursive test cleanup of the deliberately deep namespace.
        for directory in reversed(created):
            directory.rmdir()


@pytest.mark.skipif('TALLYLOCK_ALIAS_RECEIPT' not in os.environ,
                    reason='requires test-owned second bind mount worker')
def test_bind_alias_of_receipt_descendant_is_rejected_before_staging():
    receipt = Path(os.environ['TALLYLOCK_ALIAS_RECEIPT'])
    source = Path('/tallylock-source-alias')
    source_id, receipt_id = source.stat(), (receipt / 'artifacts').stat()
    assert (source_id.st_dev, source_id.st_ino) == (receipt_id.st_dev, receipt_id.st_ino)
    assert (source / 'input.txt').read_bytes() == b'alias regression only'
    with pytest.raises(TallyLockError) as caught:
        store.seal(receipt, source)
    assert caught.value.code == 2
    assert not (receipt / 'result.json').exists()
    assert not (receipt / '.prove/staging').exists()
