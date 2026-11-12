"""Offline, read-only receipt integrity and scoped membership verification."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from . import anchors, canonical, chain, merkle, records, schema, scoring
from .errors import TallyLockError
from .filesystem import Directory, _Descriptors, _directory_names, _problem, _same
from .paths import validate_paths


_ROOT_FILES = {'manifest.json', 'result.json', 'records.jsonl'}
_ROOT_DIRS = {'artifacts', 'proofs', '.prove'}
_PRIORITY = {0: 0, 3: 1, 4: 2, 5: 3, 2: 4}
_LIMITATIONS = [
    'Issuer identity, model identity and execution are unsigned and unverified.',
    'Supplied logs do not establish logging completeness or parity with actual activity.',
    'Explicit chain evidence is cached only; freshness and external provenance remain unverified.',
    'Header time is not trusted execution time or independent preregistration chronology.',
    'No trusted execution-time or no-hidden-attempt guarantee is established.',
    'Safely read bytes do not establish future filesystem immutability against same-UID writers.',
]
_PROVIDER_LIMITATION = ('Provider headers are checked for proof-of-work and links only; '
                        'full consensus is not validated and two providers can still agree on a false chain.')


@dataclass(frozen=True)
class Verification:
    code: int
    report: dict
    evidence: dict | None = None


def _anchor(state='not_checked') -> dict:
    return {'state': state, 'height': None, 'hash': None, 'time': None, 'confirmations': None,
            'required_heights': [], 'ignored_invalid_attestations': 0, 'unsupported_attestations': 0}


def _state(error: TallyLockError) -> str:
    return {2: 'invalid', 4: 'unsupported', 3: 'unavailable', 5: 'unavailable'}[error.code]


class _Report:
    def __init__(self, scope: str):
        self.value = {
            'format': 'prove.verification.v1', 'code': 0, 'scope': scope, 'policy': None,
            'minimum_confirmations': None, 'registration_id': None, 'receipt_id': None,
            'attempt_id': None, 'outcome': None,
            'artifact_integrity': {'state': 'not_checked', 'files': None, 'bytes': None},
            'record_integrity': {'state': 'not_checked', 'count': None, 'root': None},
            'score': {'state': 'not_checked', 'profile': None, 'aggregate': None, 'recomputed': None, 'limitations': []},
            'manifest_anchor': _anchor(), 'result_anchor': _anchor(), 'chain_view': {'state': 'not_checked'},
            'model': {'state': 'unverified', 'evidence': None, 'sha256': None},
            'issuer_identity': 'unverified', 'execution': 'unverified',
            'coverage': {'state': 'not_checked', 'expected': None, 'started': None, 'ended': None},
            'budget': {'state': 'not_checked', 'declared': None},
            'resources': {'state': 'not_checked', 'totals': None, 'known_lower_bounds': None},
            'errors': [], 'limitations': list(_LIMITATIONS),
        }
        self.evidence = None
        if scope == 'inclusion':
            self.value['limitations'].append(
                'Inclusion does not check artifacts, full record history, resources, coverage or scoring.')

    def error(self, stage: str, error: TallyLockError) -> None:
        # Schema, version and JSON diagnostics put hostile values after a colon.
        # Preserve the descriptive prefix while bounding and removing controls.
        code = error.code
        if _PRIORITY[code] > _PRIORITY[self.value['code']]:
            self.value['code'] = code
        if len(self.value['errors']) < 32:
            prefix = error.message.split(':', 1)[0]
            message = ''.join(char if char.isprintable() else ' ' for char in prefix[:2048]).strip()
            if not message:
                message = f'{stage}: {_state(error)} evidence or prerequisites.'
            self.value['errors'].append({'stage': stage, 'code': code, 'message': message})

    def options(self, policy, minimum, evidence=None) -> bool:
        if isinstance(policy, str) and policy in ('anchored', 'integrity-only', 'provider-pow'):
            self.value['policy'] = policy
        else:
            self.error('options', TallyLockError('unsupported verification policy'))
        if policy == 'provider-pow':
            self.value['provider_pow'] = {'state': 'not_checked'}
            self.value['limitations'].append(_PROVIDER_LIMITATION)
        elif evidence is not None:
            self.error('options', TallyLockError('provider evidence requires the provider-pow policy'))
        if type(minimum) is int and 1 <= minimum <= canonical.MAX_SAFE_INTEGER:
            self.value['minimum_confirmations'] = minimum
        else:
            self.error('options', TallyLockError('invalid minimum confirmations'))
        return not self.value['errors']

    def finish(self) -> Verification:
        return Verification(self.value['code'], self.value, self.evidence)

    def manifest(self, manifest: dict) -> None:
        self.value['registration_id'] = canonical.digest(manifest)
        self.value['model'].update(evidence=manifest['model']['evidence'], sha256=manifest['model']['sha256'])
        self.value['budget']['declared'] = dict(manifest['budget'])
        self.value['score']['profile'] = manifest['scorer']['profile']

    def result(self, result: dict) -> None:
        self.value.update(receipt_id=canonical.digest(result), attempt_id=result['attempt_id'], outcome=result['outcome'])


def _require(condition: bool, message: str, *, code: int = 2) -> None:
    if not condition:
        raise TallyLockError(message, code=code)


def _receipt_path(value) -> Path:
    _require(isinstance(value, (str, os.PathLike)), 'receipt must be a filesystem path')
    try:
        path = Path(value)
    except (TypeError, ValueError) as error:
        raise TallyLockError('receipt must be a filesystem path') from error
    _require('\x00' not in str(path), 'receipt path must not contain NUL')
    return path


def _optional_read(directory: Directory, path: str, *, limit=canonical.MAX_JSON_BYTES) -> bytes | None:
    parent, name, parents, identities = directory._parent(path)
    with _Descriptors() as owned:
        owned.add(parent, 'cannot close optional read parent')
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            directory._verify_dirs(parents, identities, path)
            return None
        except OSError as error:
            raise _problem(error, 'cannot open optional receipt file') from error
        owned.add(fd, 'cannot close optional read probe')
        directory._verify_dirs(parents, identities, path)
    return directory.read(path, limit=limit)


def _optional_directory(directory: Directory, path: str) -> bool:
    with _Descriptors() as owned:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory.fd)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise _problem(error, 'cannot open optional receipt directory') from error
        owned.add(fd, 'cannot close optional directory probe')
        try:
            directory._verify_dirs([path], (os.fstat(fd),), path)
        except OSError as error:
            raise _problem(error, 'cannot inspect optional receipt directory') from error
    return True


def _root(directory: Directory) -> set[str]:
    try:
        names = set(_directory_names(directory.fd))
        for name in names:
            _require(name in _ROOT_FILES | _ROOT_DIRS, 'unknown receipt-root entry')
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            predicate = stat.S_ISREG if name in _ROOT_FILES else stat.S_ISDIR
            _require(predicate(info.st_mode), 'invalid receipt-root entry type')
        return names
    except OSError as error:
        raise _problem(error, 'cannot inspect receipt root') from error


def _core(data: bytes, kind: str, manifest: dict | None = None) -> dict:
    value = canonical.loads(data)
    _require(isinstance(value, dict) and canonical.dumps(value) == data, 'core must be exact canonical JSON')
    if kind == 'manifest':
        schema.validate_manifest(value)
    else:
        schema.validate_result(value, manifest)
    return value


def _chain(report: _Report, cache) -> chain.ChainView | None:
    if report.value['policy'] in ('integrity-only', 'provider-pow'):
        return None
    if cache is None:
        report.value['chain_view'] = {'state': 'unavailable'}
        report.error('chain', TallyLockError('explicit chain cache is absent', code=3))
        return None
    try:
        view = chain.prepare(cache)
    except TallyLockError as error:
        report.value['chain_view'] = {'state': _state(error)}
        report.error('chain', error)
        return None
    summary = view.summary()
    omitted = []
    for field in ('exported_at', 'source'):
        if len(summary[field]) > 2048:
            summary[field] = None
            omitted.append(field)
    report.value['chain_view'] = {'state': 'checked', **summary, 'omitted_fields': omitted}
    return view


def _verify_anchor(report: _Report, kind: str, data: bytes | None, view: chain.ChainView | None) -> None:
    field = f'{kind}_anchor'
    digest = report.value['registration_id' if kind == 'manifest' else 'receipt_id']
    if digest is None:
        return
    try:
        evidence = anchors.verify(data, digest, view, minimum_confirmations=report.value['minimum_confirmations'])
    except TallyLockError as error:
        report.value[field] = _anchor(_state(error))
        report.error(field, error)
    else:
        report.value[field] = evidence
        if evidence['state'] != 'anchored':
            report.error(field, TallyLockError('insufficient anchored evidence', code=3))


def _provider_anchors(report: _Report, proofs: dict, evidence: dict | None, fetch) -> None:
    from . import headers
    offline = evidence is not None
    heights = set()
    for kind, data in list(proofs.items()):
        digest = report.value['registration_id' if kind == 'manifest' else 'receipt_id']
        try:
            if data is not None:
                heights.update(anchors.inspect(data, digest)['bitcoin_heights'])
        except TallyLockError as error:
            report.value[f'{kind}_anchor'] = _anchor(_state(error))
            report.error(f'{kind}_anchor', error)
            del proofs[kind]
    view = None
    try:
        if not offline and heights:
            evidence = headers.observe(sorted(heights), **({} if fetch is None else {'fetch': fetch}))
        if evidence is not None:
            checked = headers.check(evidence, saved=offline)
            view = checked.view
            report.value['provider_pow'] = dict(checked.summary)
            report.evidence = evidence
    except TallyLockError as error:
        report.value['provider_pow'] = {'state': _state(error)}
        report.error('providers', error)
        for kind in proofs:
            report.value[f'{kind}_anchor'] = _anchor(_state(error))
        return
    for kind, data in proofs.items():
        _verify_anchor(report, kind, data, view)
    if view is not None:
        counts = [report.value[f'{kind}_anchor']['confirmations'] for kind in proofs]
        counts = [count for count in counts if count is not None]
        report.value['provider_pow']['freshness'] = headers.freshness(
            report.value['provider_pow']['observed_at'], min(counts) if counts else None,
            report.value['minimum_confirmations'], offline=offline)


def _full_anchors(report: _Report, directory: Directory, view: chain.ChainView | None,
                  evidence: dict | None = None, fetch=None) -> None:
    if report.value['policy'] == 'integrity-only':
        return
    try:
        exists = _optional_directory(directory, 'proofs')
    except TallyLockError as error:
        for kind in ('manifest', 'result'):
            field = f'{kind}_anchor'
            if report.value['registration_id' if kind == 'manifest' else 'receipt_id'] is not None:
                report.value[field] = _anchor(_state(error))
                report.error(field, error)
        return
    proofs = {}
    for kind in ('manifest', 'result'):
        if report.value['registration_id' if kind == 'manifest' else 'receipt_id'] is None:
            continue
        try:
            data = _optional_read(directory, f'proofs/{kind}.ots', limit=anchors.MAX_PROOF_BYTES) if exists else None
        except TallyLockError as error:
            report.value[f'{kind}_anchor'] = _anchor(_state(error))
            report.error(f'{kind}_anchor', error)
        else:
            if report.value['policy'] == 'provider-pow':
                proofs[kind] = data
            else:
                _verify_anchor(report, kind, data, view)
    if proofs:
        _provider_anchors(report, proofs, evidence, fetch)


def _artifact_check(report: _Report, directory: Directory, result: dict) -> None:
    failure = 0
    entries = None
    files = []
    total = 0

    def failed(error):
        nonlocal failure
        if _PRIORITY[error.code] > _PRIORITY[failure]:
            failure = error.code
        report.error('artifacts', error)

    try:
        entries = directory._list_entries('artifacts', missing_ok=True)
        # Directory's storage prefix has a larger bound than portable wire paths.
        files = [path[len('artifacts/'):] for path, is_file in entries.items() if is_file]
        dirs = [path[len('artifacts/'):] for path, is_file in entries.items() if not is_file]
        validate_paths(files, directories=dirs)
        _require(set(files) == set(result['inventory']), 'artifact inventory differs from disk')
    except TallyLockError as error:
        failed(error)
    # A read error for one committed file must not hide invalidity of another.
    for path, entry in result['inventory'].items():
        if entries is not None and f'artifacts/{path}' not in entries:
            continue  # The exact initial namespace comparison already reported absence.
        try:
            digest, size = directory.digest(f'artifacts/{path}', expected_bytes=entry['bytes'])
            _require(digest == entry['sha256'], 'artifact SHA256 differs from inventory')
            total += size
            _require(total <= canonical.MAX_SAFE_INTEGER, 'aggregate artifact bytes exceed safe integer range')
        except TallyLockError as error:
            failed(error)
    try:
        current = directory._list_entries('artifacts', missing_ok=True)
        if entries is not None:
            _require(current == entries, 'artifact namespace changed while checking', code=5)
    except TallyLockError as error:
        failed(error)
    if failure:
        report.value['artifact_integrity']['state'] = _state(TallyLockError('artifact check failed', code=failure))
    else:
        report.value['artifact_integrity'] = {'state': 'checked', 'files': len(files), 'bytes': total}


def _records_check(report: _Report, directory: Directory, manifest: dict, result: dict) -> None:
    try:
        data = _optional_read(directory, 'records.jsonl', limit=records.MAX_RECORD_BYTES)
        _require(data is not None, 'committed records are missing')
        checked = records.check(manifest, result, data)
    except TallyLockError as error:
        report.value['record_integrity']['state'] = _state(error)
        report.error('records', error)
    else:
        report.value['record_integrity'] = {'state': 'checked', 'count': checked.metadata['count'], 'root': checked.metadata['root']}
        report.value['coverage'] = checked.coverage
        report.value['budget']['state'] = checked.budget
        report.value['resources'] = {'state': 'recorded', 'totals': checked.resources, 'known_lower_bounds': checked.known_usage}


def _score_check(report: _Report, directory: Directory, manifest: dict, result: dict) -> None:
    try:
        def read(path, limit):
            data = _optional_read(directory, f'artifacts/{path}', limit=limit)
            _require(data is not None, 'committed score input is missing')
            return data
        checked = scoring.check(manifest, result, read)
    except TallyLockError as error:
        report.value['score']['state'] = _state(error)
        report.error('score', error)
    else:
        report.value['score'] = checked


def _stability(directory: Directory, before: set[str] | None, cores: dict[str, bytes]) -> None:
    current = _root(directory)
    if before is not None:
        _require(current == before, 'receipt root changed while checking', code=5)
    for path, expected in cores.items():
        _require(directory.read(path) == expected, 'core bytes changed while checking', code=5)
    # Verify that the caller-selected root still names the directory we opened.
    try:
        with Directory(directory.root) as reopened:
            _require(_same(os.fstat(directory.fd), os.fstat(reopened.fd)), 'receipt root changed', code=5)
    except OSError as error:
        raise _problem(error, 'cannot recheck receipt root') from error


def full(receipt: Path, *, policy='anchored', chain_cache: dict | None = None,
         minimum_confirmations: int = 6, provider_evidence: dict | None = None, fetch=None) -> Verification:
    """Check all available receipt integrity evidence without writes; provider-pow may fetch headers."""
    report = _Report('full')
    if not report.options(policy, minimum_confirmations, provider_evidence):
        return report.finish()
    try:
        receipt = _receipt_path(receipt)
    except TallyLockError as error:
        report.error('options', error)
        return report.finish()
    view = _chain(report, chain_cache)
    try:
        with Directory(receipt) as directory:
            before = None
            try:
                before = _root(directory)
            except TallyLockError as error:
                report.error('receipt', error)
            cores = {}
            manifest = result = None
            try:
                data = _optional_read(directory, 'manifest.json')
                _require(data is not None, 'manifest is missing')
                cores['manifest.json'] = data
                manifest = _core(data, 'manifest')
                report.manifest(manifest)
            except TallyLockError as error:
                report.error('manifest', error)
            if manifest is not None:
                try:
                    data = _optional_read(directory, 'result.json')
                    _require(data is not None, 'result is not available', code=3)
                    cores['result.json'] = data
                    result = _core(data, 'result', manifest)
                    report.result(result)
                except TallyLockError as error:
                    report.error('result', error)
            if result is not None:
                _artifact_check(report, directory, result)
                _records_check(report, directory, manifest, result)
                _score_check(report, directory, manifest, result)
            _full_anchors(report, directory, view, provider_evidence, fetch)
            try:
                _stability(directory, before, cores)
            except TallyLockError as error:
                report.error('stability', error)
    except TallyLockError as error:
        report.error('receipt', error)
    return report.finish()


def _trace_plausibility(value: dict) -> None:
    """Reject visible impossible slots without checking unseen trace history."""
    result, event = value['result'], value['event']
    if result['profile'] != 'trace-v1':
        return
    index, size, kind = value['index'], value['size'], event['kind']
    _require(index != 0 or kind in ('sample_start', 'attempt_end'),
             'first nonterminal trace record must be sample_start')
    calls = result['resources']['calls']
    if kind == 'call':
        retry = event['retry_of'] is not None
        _require(not retry or index >= 2, 'retry requires positions for sample_start and a prior call')
        _require(calls >= (2 if retry else 1), 'declared calls cannot accommodate included call or retry')
    completed = result['outcome'] == 'completed'
    selected = next(attempt for attempt in value['manifest']['attempts'] if attempt['id'] == result['attempt_id'])
    # Python integer arithmetic preserves impossible bounds above the wire's safe range.
    minimum = 1 + calls + (2 * len(selected['sample_ids']) if completed else (1 if calls else 0))
    _require(size >= minimum, 'trace record count cannot accommodate declared calls and samples')
    if completed and kind in ('sample_start', 'call'):
        _require(size - index - 1 >= 2, 'completed trace event needs following sample_end and attempt_end positions')


def inclusion(value: dict | bytes, *, policy='anchored', chain_cache: dict | None = None,
              minimum_confirmations: int = 6, provider_evidence: dict | None = None, fetch=None) -> Verification:
    """Check one event's committed membership with explicitly partial scope."""
    report = _Report('inclusion')
    if not report.options(policy, minimum_confirmations, provider_evidence):
        return report.finish()
    view = _chain(report, chain_cache)
    snapshot = None
    try:
        if isinstance(value, bytes):
            snapshot = canonical.loads(value)
        else:
            _require(isinstance(value, dict), 'inclusion must be a dict or bytes')
            snapshot = canonical.loads(canonical.dumps(value))
        schema.validate_inclusion(snapshot)
    except TallyLockError as error:
        report.value['record_integrity']['state'] = _state(error)
        report.error('inclusion', error)
        return report.finish()
    report.manifest(snapshot['manifest'])
    report.result(snapshot['result'])
    try:
        _require(snapshot['index'] != snapshot['size'] - 1 or snapshot['event']['kind'] == 'attempt_end',
                 'final included record must be attempt_end')
        _trace_plausibility(snapshot)
        _require(merkle.verify(canonical.dumps(snapshot['event']), snapshot['index'], snapshot['size'],
                               snapshot['siblings'], snapshot['result']['records']['root']),
                 'invalid Merkle membership')
    except TallyLockError as error:
        report.value['record_integrity']['state'] = _state(error)
        report.error('inclusion', error)
    else:
        report.value['record_integrity'] = {'state': 'membership_checked', 'count': snapshot['size'],
                                            'root': snapshot['result']['records']['root']}
    if report.value['policy'] in ('anchored', 'provider-pow'):
        proofs = {}
        for kind in ('manifest', 'result'):
            encoded = snapshot['proofs'][kind]
            proofs[kind] = None if encoded is None else base64.b64decode(encoded, validate=True)
            if report.value['policy'] == 'anchored':
                _verify_anchor(report, kind, proofs[kind], view)
        if report.value['policy'] == 'provider-pow':
            _provider_anchors(report, proofs, provider_evidence, fetch)
    return report.finish()


def make_inclusion(receipt: Path, index: int, *, include_proofs: bool = True) -> dict:
    """Build a bounded membership package from safely read complete records."""
    _require(type(include_proofs) is bool, 'include_proofs must be a boolean')
    _require(type(index) is int and 0 <= index <= canonical.MAX_SAFE_INTEGER, 'invalid inclusion index')
    receipt = _receipt_path(receipt)
    with Directory(receipt) as directory:
        before = _root(directory)
        manifest_data = _optional_read(directory, 'manifest.json')
        _require(manifest_data is not None, 'manifest is missing')
        manifest = _core(manifest_data, 'manifest')
        result_data = _optional_read(directory, 'result.json')
        _require(result_data is not None, 'result is not available', code=3)
        result = _core(result_data, 'result', manifest)
        record_data = _optional_read(directory, 'records.jsonl', limit=records.MAX_RECORD_BYTES)
        _require(record_data is not None, 'committed records are missing')
        checked = records.check(manifest, result, record_data)
        _require(index < len(checked.events), 'inclusion index is out of range')
        leaves = [canonical.dumps(event) for event in checked.events]
        proofs = {'manifest': None, 'result': None}
        if include_proofs and _optional_directory(directory, 'proofs'):
            for kind, core in (('manifest', manifest), ('result', result)):
                data = _optional_read(directory, f'proofs/{kind}.ots', limit=anchors.MAX_PROOF_BYTES)
                if data is not None:
                    anchors.inspect(data, canonical.digest(core))
                    proofs[kind] = base64.b64encode(data).decode('ascii')
        package = {'format': 'prove.inclusion.v1', 'registration_id': canonical.digest(manifest),
                   'receipt_id': canonical.digest(result), 'manifest': manifest, 'result': result,
                   'event': checked.events[index], 'index': index, 'size': len(leaves),
                   'siblings': merkle.proof(leaves, index), 'proofs': proofs}
        schema.validate_inclusion(package)
        canonical.dumps(package)
        _stability(directory, before, {'manifest.json': manifest_data, 'result.json': result_data})
        return package
