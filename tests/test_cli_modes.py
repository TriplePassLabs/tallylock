"""Output modes, friendly default verify, doctor and release packaging contracts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pty
import re
import subprocess
import sys

import pytest

from tallylock import doctor, render

ROOT = Path(__file__).resolve().parents[1]
BANNED = re.compile(r'bitcoin|merkle|opentimestamps|—', re.I)


def launch(*args, code=0, tty=False, cwd=None, env=None, patch=None):
    base = [sys.executable, '-m', 'tallylock']
    if patch is not None:
        base = [sys.executable, '-c', patch + '\nfrom tallylock.cli import main\nraise SystemExit(main())']
    command = base + [str(a) for a in args]
    if tty:
        master, slave = pty.openpty()
        try:
            result = subprocess.run(command, stdout=slave, stderr=subprocess.PIPE, cwd=cwd, env=env,
                                    timeout=30)
            os.close(slave)
            slave = None
            chunks = []
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)
        stdout = b''.join(chunks).decode().replace('\r\n', '\n')
        stderr = result.stderr.decode()
    else:
        result = subprocess.run(command, capture_output=True, text=True, cwd=cwd, env=env, timeout=30)
        stdout, stderr = result.stdout, result.stderr
    assert code is None or result.returncode == code, (result.returncode, stdout, stderr)
    assert stderr == '', stderr
    return stdout


def made(tmp_path):
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / 'a.txt').write_bytes(b'ordinary output\n')
    launch('init', '--out', tmp_path / 'manifest.json', cwd=tmp_path)
    launch('pre-register', tmp_path / 'manifest.json', '--receipt', tmp_path / 'receipt', cwd=tmp_path)
    launch('seal', tmp_path / 'receipt', '--artifacts', outputs, cwd=tmp_path)
    return tmp_path / 'receipt', outputs


def test_default_is_json_on_a_pipe_and_human_on_a_tty(tmp_path):
    piped = launch('init', '--out', tmp_path / 'm1.json')
    assert json.loads(piped)['command'] == 'init'
    on_tty = launch('init', '--out', tmp_path / 'm2.json', tty=True)
    with pytest.raises(ValueError):
        json.loads(on_tty)
    assert 'm2.json' in on_tty and 'pre-register' in on_tty


def test_flags_override_the_default_in_both_directions(tmp_path):
    human = launch('init', '--out', tmp_path / 'm1.json', '--human')
    with pytest.raises(ValueError):
        json.loads(human)
    assert 'pre-register' in human
    forced = launch('init', '--out', tmp_path / 'm2.json', '--json', tty=True)
    assert json.loads(forced)['command'] == 'init'


def test_json_and_human_together_exit_2_before_any_work(tmp_path):
    out = tmp_path / 'never.json'
    launch('init', '--out', out, '--json', '--human', code=2)
    assert not out.exists()
    launch('verify', tmp_path / 'nothing', '--json', '--human', code=2)


def test_json_shape_is_unchanged_by_the_flag(tmp_path):
    first = json.loads(launch('init', '--out', tmp_path / 'a.json'))
    second = json.loads(launch('init', '--out', tmp_path / 'b.json', '--json'))
    first['output'], second['output'] = None, None
    assert first == second


def test_help_and_version_are_unchanged(tmp_path):
    assert 'usage:' in launch('--help', tty=True)
    assert launch('--version', tty=True).strip() == '0.1.0a5'
    assert 'usage:' in launch('verify', '--help')


def test_default_verify_passes_with_timestamp_not_checked(tmp_path):
    receipt, _ = made(tmp_path)
    value = json.loads(launch('verify', receipt))
    assert value['code'] == 0
    assert value['timestamp_checked'] is False
    assert value['effective_policy'] == 'integrity-only'
    assert value['policy'] == 'integrity-only'
    assert value['format'] == 'prove.verification.v1'


def test_default_verify_human_says_not_checked_and_names_next_command(tmp_path):
    receipt, _ = made(tmp_path)
    text = launch('verify', receipt, '--human')
    assert 'not checked' in text.lower()
    assert 'passed' in text.lower()
    assert f'tallylock verify {receipt} --online' in text
    assert 'who ran it' in text
    assert not BANNED.search(text)
    assert '{' not in text


def test_explicit_anchored_policy_stays_strict(tmp_path):
    receipt, _ = made(tmp_path)
    value = json.loads(launch('verify', receipt, '--policy', 'anchored', code=3))
    assert value['policy'] == 'anchored'
    assert 'timestamp_checked' not in value and 'effective_policy' not in value
    text = launch('verify', receipt, '--policy', 'anchored', '--human', code=3)
    assert 'incomplete' in text.lower()
    assert not BANNED.search(text)


def test_explicit_integrity_only_keeps_its_old_shape(tmp_path):
    receipt, _ = made(tmp_path)
    value = json.loads(launch('verify', receipt, '--policy', 'integrity-only'))
    assert 'timestamp_checked' not in value and 'effective_policy' not in value


def test_default_verify_with_a_cache_runs_the_anchored_check(tmp_path):
    receipt, _ = made(tmp_path)
    cache = tmp_path / 'cache.json'
    cache.write_text('{}')
    value = json.loads(launch('verify', receipt, '--chain-cache', cache, code=2))
    assert value['policy'] == value['effective_policy'] == 'anchored'
    patch = ("from tallylock import verify\n"
             "seen = []\n"
             "def fake(*a, **kw):\n"
             "    seen.append(kw['policy'])\n"
             "    return verify.Verification(0, {'format': 'prove.verification.v1', 'code': 0, 'policy': kw['policy']})\n"
             "verify.full = fake\n"
             "import atexit; atexit.register(lambda: print(seen))\n")
    from tallylock import canonical
    cache.write_bytes(canonical.dumps({'format': 'prove.chain.v1'}))
    out = launch('verify', receipt, '--chain-cache', cache, patch=patch)
    assert "['anchored']" in out
    assert json.loads(out.splitlines()[0])['effective_policy'] == 'anchored'
    assert json.loads(out.splitlines()[0])['timestamp_checked'] is True


def test_exit_codes_match_across_modes(tmp_path):
    receipt, _ = made(tmp_path)
    (receipt / 'artifacts' / 'a.txt').write_bytes(b'changed')
    json.loads(launch('verify', receipt, code=2))
    text = launch('verify', receipt, '--human', code=2)
    assert 'failed' in text.lower()
    missing = launch('verify', tmp_path / 'absent', '--human', code=5)
    assert 'could not' in missing.lower() or 'failed' in missing.lower()


@pytest.mark.parametrize('command', ['inspect'])
def test_inspect_human_is_a_short_readable_paragraph(tmp_path, command):
    receipt, _ = made(tmp_path)
    text = launch(command, receipt, '--human')
    assert 'sealed' in text and 'a.txt' in text and 'not verified' in text.lower()
    assert 'tallylock verify' in text
    assert not BANNED.search(text)
    assert len(text.splitlines()) <= 12


def test_command_reports_render_as_plain_paragraphs(tmp_path):
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / 'a.txt').write_bytes(b'x\n')
    manifest, receipt = tmp_path / 'manifest.json', tmp_path / 'receipt'
    texts = [launch('init', '--out', manifest, '--human'),
             launch('pre-register', manifest, '--receipt', receipt, '--human'),
             launch('seal', receipt, '--artifacts', outputs, '--human')]
    assert 'tallylock pre-register' in texts[0]
    assert 'Registration ID' in texts[1] and f'tallylock seal {receipt}' in texts[1]
    assert 'Receipt ID' in texts[2] and f'tallylock verify {receipt}' in texts[2]
    for text in texts:
        assert not BANNED.search(text) and not text.lstrip().startswith('{')


def test_anchor_and_upgrade_render_without_network():
    base = {'format': 'prove.command.v1', 'command': 'anchor', 'code': 0, 'registration_id': 'a' * 64,
            'receipt_id': 'b' * 64, 'local_state': 'sealed', 'output': None,
            'anchor_action': {'state': 'returned', 'report': {'format': 'prove.anchor-action.v1'}},
            'data': None, 'errors': [], 'limitations': []}
    text = render.human(base, {'receipt': 'rcpt'})
    assert 'timestamp' in text.lower() and 'tallylock upgrade rcpt' in text
    base['command'] = 'upgrade'
    assert 'tallylock verify rcpt' in render.human(base, {'receipt': 'rcpt'})
    failed = dict(base, code=5, errors=[{'stage': 'anchor', 'code': 5, 'message': 'Timestamp action failed'}],
                  anchor_action={'state': 'failed', 'report': None})
    assert 'Timestamp action failed' in render.human(failed, {'receipt': 'rcpt'})
    for text in (render.human(base, {'receipt': 'rcpt'}), render.human(failed, {'receipt': 'rcpt'})):
        assert not BANNED.search(text)


def test_python_range_diagnostics():
    assert doctor.check_python((3, 12, 1))['state'] == 'ok'
    assert doctor.check_python((3, 11, 0))['state'] == 'ok'
    low = doctor.check_python((3, 10, 9))
    high = doctor.check_python((3, 15, 0))
    assert low['id'] == high['id'] == 'TL-DOC-PYTHON-RANGE'
    assert low['state'] == high['state'] == 'fail'
    assert doctor.check_python((3, 12, 1))['id'] == 'TL-DOC-PYTHON-OK'
    assert doctor.check_python((3, 14, 0))['state'] == 'ok'


def test_data_diagnostics(tmp_path):
    assert doctor.check_data()['id'] == 'TL-DOC-DATA-OK'
    empty = doctor.check_data(tmp_path)
    assert empty['id'] == 'TL-DOC-DATA-UNREADABLE' and empty['state'] == 'fail'


def test_path_diagnostics(tmp_path):
    mine = tmp_path / 'mine' / 'tallylock'
    other = tmp_path / 'other' / 'tallylock'
    for item in (mine, other):
        item.parent.mkdir()
        item.write_text('#!/bin/sh\n')
    assert doctor.check_path(str(mine), [mine])['id'] == 'TL-DOC-PATH-OK'
    shadow = doctor.check_path(str(other), [mine])
    assert shadow['id'] == 'TL-DOC-PATH-SHADOWED' and shadow['state'] == 'warn'
    assert str(other) in shadow['message'] and str(mine) in shadow['message']
    missing = doctor.check_path(None, [mine])
    assert missing['id'] == 'TL-DOC-PATH-MISSING' and missing['state'] == 'warn'


def test_doctor_detects_a_shadowing_tallylock_on_path(tmp_path):
    fake = tmp_path / 'bin'
    fake.mkdir()
    script = fake / 'tallylock'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o755)
    env = dict(os.environ, PATH=f'{fake}{os.pathsep}{Path(sys.executable).parent}')
    value = json.loads(launch('doctor', env=env))
    ids = {item['id'] for item in value['checks']}
    assert 'TL-DOC-PATH-SHADOWED' in ids
    clean = dict(os.environ, PATH=str(Path(sys.executable).parent))
    ids = {item['id'] for item in json.loads(launch('doctor', env=clean))['checks']}
    assert 'TL-DOC-PATH-OK' in ids


def test_doctor_json_and_human_without_receipt(tmp_path):
    env = dict(os.environ, PATH=str(Path(sys.executable).parent))
    value = json.loads(launch('doctor', env=env))
    assert value['format'] == 'tallylock.doctor.v1' and value['code'] == 0
    assert all({'id', 'state', 'message', 'next'} <= set(item) for item in value['checks'])
    assert {item['id'] for item in value['checks']} >= {'TL-DOC-PYTHON-OK', 'TL-DOC-DATA-OK'}
    text = launch('doctor', '--human', env=env)
    assert 'TL-DOC-PYTHON-OK' in text and not BANNED.search(text)


def test_doctor_is_read_only_and_never_opens_a_socket(tmp_path):
    receipt, _ = made(tmp_path)
    before = sorted(str(p.relative_to(receipt)) for p in receipt.rglob('*'))
    patch = ("import sys\n"
             "def deny(event, args):\n"
             "    if event.startswith('socket.'):\n"
             "        raise AssertionError('network')\n"
             "sys.addaudithook(deny)\n")
    value = json.loads(launch('doctor', receipt, patch=patch))
    assert value['code'] == 0
    assert sorted(str(p.relative_to(receipt)) for p in receipt.rglob('*')) == before


def test_doctor_receipt_timestamp_states_and_exact_next_command(tmp_path):
    receipt, _ = made(tmp_path)
    value = json.loads(launch('doctor', receipt))
    stamp = [c for c in value['checks'] if c['id'].startswith('TL-DOC-TS')]
    assert [c['id'] for c in stamp] == ['TL-DOC-TS-MISSING']
    assert stamp[0]['next'] == f'tallylock anchor {receipt}'
    (receipt / 'proofs').mkdir()
    for name in ('manifest', 'result'):
        (receipt / 'proofs' / f'{name}.ots').write_bytes(b'garbage')
    value = json.loads(launch('doctor', receipt, code=None))
    ids = [c['id'] for c in value['checks'] if c['id'].startswith(('TL-DOC-TS', 'TL-DOC-RECEIPT'))]
    assert ids and ids[0] in {'TL-DOC-RECEIPT-UNREADABLE', 'TL-DOC-TS-UNSUPPORTED'}
    text = launch('doctor', receipt, '--human', code=None)
    assert 'Next:' in text


def test_doctor_unsealed_and_unreadable_receipts(tmp_path):
    manifest, receipt = tmp_path / 'm.json', tmp_path / 'r'
    launch('init', '--out', manifest)
    launch('pre-register', manifest, '--receipt', receipt)
    value = json.loads(launch('doctor', receipt))
    ids = [c['id'] for c in value['checks']]
    assert 'TL-DOC-RECEIPT-UNSEALED' in ids
    unsealed = [c for c in value['checks'] if c['id'] == 'TL-DOC-RECEIPT-UNSEALED'][0]
    assert unsealed['next'].startswith(f'tallylock seal {receipt}')
    gone = json.loads(launch('doctor', tmp_path / 'absent', code=3))
    assert 'TL-DOC-RECEIPT-UNREADABLE' in [c['id'] for c in gone['checks']]


def test_timestamp_state_mapping():
    assert doctor.timestamp_check('R', {'manifest': 'pending', 'result': 'pending'}, True)['id'] == 'TL-DOC-TS-PENDING'
    assert doctor.timestamp_check('R', {'manifest': 'pending', 'result': 'pending'}, True)['next'] == 'tallylock upgrade R'
    present = doctor.timestamp_check('R', {'manifest': 'attestation_present', 'result': 'attestation_present'}, True)
    assert present['id'] == 'TL-DOC-TS-PRESENT' and 'tallylock verify R --online' in present['next']
    assert doctor.timestamp_check('R', {'manifest': 'unsupported', 'result': 'missing'}, True)['id'] == 'TL-DOC-TS-UNSUPPORTED'
    assert doctor.timestamp_check('R', {'manifest': 'missing', 'result': 'core_missing'}, False)['id'] == 'TL-DOC-RECEIPT-UNSEALED'


def test_requires_python_range():
    text = (ROOT / 'pyproject.toml').read_text()
    assert 'requires-python = ">=3.11,<3.15"' in text


def test_release_workflow_uses_trusted_publishing():
    text = (ROOT / '.github/workflows/release.yml').read_text()
    assert re.search(r"tags:\s*\n\s*- 'v\*'", text) or re.search(r'tags:\s*\n\s*- "v\*"', text)
    assert re.search(r'pypa/gh-action-pypi-publish@[0-9a-f]{40}\b', text)
    assert 'environment: pypi' in text or re.search(r'environment:\s*\n\s*name: pypi', text)
    assert text.count('id-token: write') == 1
    assert 'permissions: {}' in text or 'permissions:\n  contents: read' in text
    publish = text.split('publish:', 1)[1]
    assert 'id-token: write' in publish
    assert 'id-token' not in text.split('publish:', 1)[0]
    assert 'password' not in text.lower() and 'secrets.' not in text


def test_security_policy_points_to_private_advisories():
    text = (ROOT / 'SECURITY.md').read_text()
    assert 'security advisor' in text.lower() and 'private' in text.lower()
    assert '—' not in text


def test_docs_show_the_pypi_install_and_keep_the_wheel_path():
    for name in ('README.md', 'docs/QUICKSTART.md'):
        text = (ROOT / name).read_text()
        assert 'pipx install tallylock' in text
        assert 'after the first PyPI release' not in text
        assert 'wheel' in text.lower()


def test_check_install_does_not_assume_the_old_default():
    text = (ROOT / 'tools/check_install.py').read_text()
    assert '["verify", "receipt", "--offline"], expected=3' not in text
    assert '"--policy", "anchored"' in text
