import os

import pytest

from tallylock import cli, doctor
from tallylock.errors import TallyLockError
from tallylock.filesystem import Directory


def test_windows_like_system_gets_a_plain_write_error(tmp_path, monkeypatch):
    monkeypatch.delattr(os, 'O_NOFOLLOW')
    with pytest.raises(TallyLockError) as caught:
        Directory(tmp_path).__enter__()
    assert caught.value.code == 4
    assert cli._diagnostic(caught.value, 'output') == ('TallyLock writes files only on Linux. '
                                                       'On Windows, use WSL or a Linux container')


def test_doctor_reports_the_platform():
    assert doctor.check_platform()['id'] == 'TL-DOC-PLATFORM-OK'
    windows = doctor.check_platform(['O_RDONLY', 'O_BINARY'])
    assert windows['id'] == 'TL-DOC-PLATFORM' and windows['state'] == 'fail'
    assert 'WSL' in windows['next']
