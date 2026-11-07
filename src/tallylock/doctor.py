"""Read-only installation and receipt diagnostics with stable IDs."""
from __future__ import annotations

from importlib import resources
import os
from pathlib import Path
import shutil
import sys
import sysconfig

SUPPORTED = ((3, 11), (3, 14))
REQUIRED_DATA = ('data/schemas/protocol-v1.json', 'data/conformance/index.json',
                 'data/examples/basic/manifest.json')


def _check(identifier, state, message, next_step=None):
    return {'id': identifier, 'state': state, 'message': message, 'next': next_step}


def check_python(version=None):
    version = tuple(sys.version_info[:3] if version is None else version)
    text = '.'.join(str(part) for part in version[:3])
    if SUPPORTED[0] <= version[:2] < SUPPORTED[1]:
        return _check('TL-DOC-PYTHON-OK', 'ok', f'Python {text} is in the tested range (3.11 to 3.13).')
    return _check('TL-DOC-PYTHON-RANGE', 'fail', f'Python {text} is outside the tested range (3.11 to 3.13).',
                  'Install TallyLock with Python 3.11, 3.12 or 3.13.')


def console_candidates():
    names = {Path(sys.executable).parent, Path(sysconfig.get_path('scripts'))}
    return [directory / 'tallylock' for directory in sorted(names)]


def check_path(found, candidates):
    if found is None:
        return _check('TL-DOC-PATH-MISSING', 'warn', 'No tallylock command was found on PATH.',
                      f'Run it as: {sys.executable} -m tallylock')
    real = os.path.realpath(found)
    if any(os.path.realpath(candidate) == real for candidate in candidates):
        return _check('TL-DOC-PATH-OK', 'ok', f'The tallylock on PATH is this installation: {found}')
    expected = ', '.join(str(candidate) for candidate in candidates)
    return _check('TL-DOC-PATH-SHADOWED', 'warn',
                  f'The tallylock on PATH is {found}, not this installation ({expected}).',
                  f'Run it as: {sys.executable} -m tallylock')


def check_data(root=None):
    base = resources.files('tallylock') if root is None else Path(root)
    bad = []
    for name in REQUIRED_DATA:
        try:
            if not base.joinpath(name).read_bytes():
                bad.append(name)
        except OSError:
            bad.append(name)
    if bad:
        return _check('TL-DOC-DATA-UNREADABLE', 'fail', 'Packaged data is missing or unreadable: ' + ', '.join(bad),
                      'Reinstall TallyLock from a fresh wheel.')
    return _check('TL-DOC-DATA-OK', 'ok', 'Packaged schemas and examples are readable.')


def timestamp_check(receipt, states, sealed):
    if not sealed:
        return _check('TL-DOC-RECEIPT-UNSEALED', 'warn', 'The receipt is registered but not sealed yet.',
                      f'tallylock seal {receipt} --artifacts OUTPUT_DIR')
    values = set(states.values())
    if 'unsupported' in values:
        return _check('TL-DOC-TS-UNSUPPORTED', 'warn', 'A timestamp proof is present but not in a supported form.',
                      f'tallylock inspect {receipt}')
    if values & {'missing', 'core_missing'}:
        return _check('TL-DOC-TS-MISSING', 'warn', 'No timestamp has been requested for this receipt.',
                      f'tallylock anchor {receipt}')
    if 'pending' in values:
        return _check('TL-DOC-TS-PENDING', 'warn', 'The timestamp was requested and is not complete yet.',
                      f'tallylock upgrade {receipt}')
    return _check('TL-DOC-TS-PRESENT', 'ok', 'Timestamp proofs are present. They are not checked until you supply evidence.',
                  f'tallylock verify {receipt} --chain-cache CACHE_FILE')


def unreadable(receipt):
    return _check('TL-DOC-RECEIPT-UNREADABLE', 'fail', 'The receipt could not be read.',
                  f'tallylock inspect {receipt}')


def install_checks():
    return [check_python(), check_path(shutil.which('tallylock'), console_candidates()), check_data()]


def report(checks):
    failed = any(item['state'] == 'fail' for item in checks)
    return {'format': 'tallylock.doctor.v1', 'code': 3 if failed else 0, 'checks': checks, 'errors': []}
