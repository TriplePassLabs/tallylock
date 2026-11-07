"""Offline verifier contracts using synthetic receipt bytes and real consumers."""
from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import json
import os

from bitcoin.core import CBlockHeader
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
import pytest

from tallylock import canonical, fixture, filesystem, records, schema
from tallylock.errors import TallyLockError
from test_chain import cache_for


def api():
    assert importlib.util.find_spec('tallylock.verify') is not None, 'Task5a verifier module absent'
    return importlib.import_module('tallylock.verify')


def receipt(tmp_path, *, generic=False, empty=False):
    value = fixture.example()
    manifest = schema.default_manifest('Synthetic') if generic else value.manifest
    artifacts = {'Résumé.TXT': b'snapshot'} if generic else value.artifacts
    if empty:
        manifest = schema.default_manifest('Empty unsuccessful')
        manifest['profile'] = 'trace-v1'
        manifest['attempts'][0]['sample_ids'] = ['sample-1']
        artifacts = {}
    inventory = {path: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                        'role': 'output' if generic else value.roles[path], 'media_type': 'application/octet-stream'}
                 for path, data in artifacts.items()}
    outcome, reason = ('failed', 'synthetic unsuccessful') if empty else ('completed', None)
    events = [] if empty else (None if generic else value.events)
    checked = records.build(manifest, 'run-1', inventory, outcome, reason, events=events)
    score = None if generic or empty else {'path': 'scores.json', **{k: inventory['scores.json'][k] for k in ('sha256', 'bytes')},
                                          'profile': 'fixture-exact-v1', 'aggregate': value.aggregate}
    result = {'format': 'prove.result.v1', 'registration_id': canonical.digest(manifest), 'attempt_id': 'run-1',
              'profile': manifest['profile'], 'outcome': outcome, 'reason': reason, 'inventory': inventory,
              'records': checked.metadata, 'resources': checked.resources, 'score': score, 'metadata': {}}
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / 'manifest.json').write_bytes(canonical.dumps(manifest))
    (tmp_path / 'result.json').write_bytes(canonical.dumps(result))
    (tmp_path / 'records.jsonl').write_bytes(checked.data)
    for path, data in artifacts.items():
        target = tmp_path / 'artifacts' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return manifest, result


def write_result(root, result):
    (root / 'result.json').write_bytes(canonical.dumps(result))


def anchored(root, manifest, result, *, tip=7):
    headers = {}
    (root / 'proofs').mkdir(exist_ok=True)
    for height, (name, core) in enumerate((('manifest', manifest), ('result', result)), 1):
        stamp = Timestamp(bytes.fromhex(canonical.digest(core)))
        stamp.attestations.add(BitcoinBlockHeaderAttestation(height))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
        (root / 'proofs' / f'{name}.ots').write_bytes(ctx.getbytes())
        headers[height] = CBlockHeader(hashMerkleRoot=stamp.msg, nTime=1700000000 + height).serialize()
    return cache_for(headers, tip)


FIELDS = {'format', 'code', 'scope', 'policy', 'minimum_confirmations', 'registration_id', 'receipt_id', 'attempt_id',
          'outcome', 'artifact_integrity', 'record_integrity', 'score', 'manifest_anchor', 'result_anchor', 'chain_view',
          'model', 'issuer_identity', 'execution', 'coverage', 'budget', 'resources', 'errors', 'limitations'}


def test_full_exact_report_and_fixture(tmp_path):
    manifest, result = receipt(tmp_path)
    verification = api().full(tmp_path, policy='integrity-only', chain_cache={'poison': object()})
    report = verification.report
    assert verification.code == 0 and report['code'] == 0 and set(report) == FIELDS
    assert report['scope'] == 'full' and report['minimum_confirmations'] == 6
    assert report['registration_id'] == canonical.digest(manifest) and report['receipt_id'] == canonical.digest(result)
    assert report['artifact_integrity'] == {'state': 'checked', 'files': 2, 'bytes': sum(x['bytes'] for x in result['inventory'].values())}
    assert report['record_integrity'] == {'state': 'checked', 'count': 5, 'root': result['records']['root']}
    assert report['score']['state'] == 'recomputed' and report['score']['aggregate'] == {'numerator': 1, 'denominator': 2}
    assert report['coverage'] == {'state': 'complete', 'expected': 2, 'started': 2, 'ended': 2}
    assert report['resources']['state'] == 'recorded' and report['budget']['state'] == 'recorded_within'
    assert report['chain_view'] == {'state': 'not_checked'} and report['manifest_anchor']['state'] == 'not_checked'
    assert report['model'] == {'state': 'unverified', 'evidence': 'self_declared', 'sha256': None}
    assert report['issuer_identity'] == report['execution'] == 'unverified'
    assert not (tmp_path / '.prove').exists() and report['errors'] == []
    with pytest.raises(FrozenInstanceError):
        verification.code = 9


@pytest.mark.parametrize('options,policy,minimum', [({'policy': []}, None, 6), ({'policy': 'future'}, None, 6),
    ({'minimum_confirmations': True}, 'anchored', None), ({'minimum_confirmations': 0}, 'anchored', None),
    ({'minimum_confirmations': 2**53}, 'anchored', None)])
def test_bad_options_return_sanitized_reports(tmp_path, options, policy, minimum):
    for check in (lambda: api().full(tmp_path, **options), lambda: api().inclusion({}, **options)):
        output = check()
        assert output.code == 2 and set(output.report) == FIELDS
        assert output.report['policy'] == policy and output.report['minimum_confirmations'] == minimum
        assert output.report['errors'][0]['stage'] == 'options'


@pytest.mark.parametrize('generic,empty', [(True, False), (False, True)])
def test_generic_and_unsuccessful_empty_receipts(tmp_path, generic, empty):
    receipt(tmp_path, generic=generic, empty=empty)
    report = api().full(tmp_path, policy='integrity-only')
    assert report.code == 0 and report.report['record_integrity']['state'] == 'checked'
    if empty:
        assert report.report['record_integrity']['count'] == 0
        with pytest.raises(TallyLockError):
            api().make_inclusion(tmp_path, 0)


@pytest.mark.parametrize('change', ['missing', 'extra', 'hash', 'length', 'empty_collision', 'symlink', 'fifo'])
def test_artifact_integrity_negative_namespaces(tmp_path, change):
    _, result = receipt(tmp_path, generic=True)
    file = tmp_path / 'artifacts' / 'Résumé.TXT'
    if change == 'missing': file.unlink()
    elif change == 'extra': (file.parent / 'extra').write_bytes(b'extra')
    elif change == 'hash': file.write_bytes(b'SNAPSHOT')
    elif change == 'length': file.write_bytes(b'short')
    elif change == 'empty_collision': (file.parent / 'résumé.txt').mkdir()
    elif change == 'symlink': file.unlink(); file.symlink_to('/etc/passwd')
    elif change == 'fifo': file.unlink(); os.mkfifo(file)
    output = api().full(tmp_path, policy='integrity-only')
    assert output.code == 2 and output.report['artifact_integrity'] == {'state': 'invalid', 'files': None, 'bytes': None}


def test_independent_false_score_and_resources_even_without_anchors(tmp_path):
    _, result = receipt(tmp_path)
    result['resources']['calls'] = 1
    result['score']['aggregate']['numerator'] = 0
    write_result(tmp_path, result)
    output = api().full(tmp_path)
    assert output.code == 2
    assert {'records', 'score', 'manifest_anchor', 'result_anchor', 'chain'} <= {e['stage'] for e in output.report['errors']}
    assert output.report['score']['state'] == output.report['record_integrity']['state'] == 'invalid'


@pytest.mark.parametrize('change,code', [('missing_root', 5), ('no_manifest', 2), ('no_result', 3), ('noncanonical', 2),
    ('future_manifest', 4), ('extra_root', 2), ('missing_records', 2)])
def test_core_and_root_failures(tmp_path, change, code):
    receipt(tmp_path, generic=True)
    root = tmp_path
    if change == 'missing_root': root = tmp_path / 'absent'
    elif change == 'no_manifest': (root / 'manifest.json').unlink()
    elif change == 'no_result': (root / 'result.json').unlink()
    elif change == 'noncanonical': (root / 'manifest.json').write_bytes((root / 'manifest.json').read_bytes() + b'\n')
    elif change == 'future_manifest':
        core = canonical.loads((root / 'manifest.json').read_bytes()); core['format'] = 'prove.manifest.v2'
        (root / 'manifest.json').write_bytes(canonical.dumps(core))
    elif change == 'extra_root': (root / 'extra').write_bytes(b'unknown')
    elif change == 'missing_records': (root / 'records.jsonl').unlink()
    assert api().full(root, policy='integrity-only').code == code


def test_make_and_verify_inclusion_scope_odd_tree_and_strict_bytes(tmp_path):
    _, result = receipt(tmp_path)
    for index in range(5):
        proof = api().make_inclusion(tmp_path, index)
        output = api().inclusion(json.dumps(proof).encode(), policy='integrity-only')
        assert output.code == 0 and output.report['scope'] == 'inclusion'
        assert output.report['record_integrity'] == {'state': 'membership_checked', 'count': 5, 'root': result['records']['root']}
        for field in ('artifact_integrity', 'score', 'coverage', 'budget', 'resources'):
            assert output.report[field]['state'] == 'not_checked'
        proof['siblings'].append('00' * 32)
        assert api().inclusion(proof, policy='integrity-only').code == 2
    for index in (True, -1, 5):
        with pytest.raises(TallyLockError): api().make_inclusion(tmp_path, index)
    with pytest.raises(TallyLockError): api().make_inclusion(tmp_path / 'absent', 0, include_proofs=1)


def test_completed_anchors_explicit_cache_thresholds_and_bounded_summary(tmp_path):
    manifest, result = receipt(tmp_path)
    cache = anchored(tmp_path, manifest, result)
    output = api().full(tmp_path, chain_cache=cache)
    assert output.code == 0 and output.report['result_anchor']['state'] == 'anchored'
    assert output.report['chain_view']['state'] == 'checked'
    proof = api().make_inclusion(tmp_path, 2)
    assert api().inclusion(proof, chain_cache=cache).code == 0
    assert api().full(tmp_path, chain_cache=cache, minimum_confirmations=7).code == 3
    cache['source'] = 's' * (canonical.MAX_JSON_BYTES - 4000)
    bounded = api().full(tmp_path, chain_cache=cache)
    assert bounded.code == 0 and bounded.report['chain_view']['source'] is None
    assert bounded.report['chain_view']['omitted_fields'] == ['source']
    assert len(canonical.dumps(bounded.report)) < 20000 and len(cache['source']) > 8_000_000


def test_malformed_proofs_still_parsed_without_cache_and_integrity_policy_skips(tmp_path):
    receipt(tmp_path)
    (tmp_path / 'proofs').mkdir()
    (tmp_path / 'proofs/manifest.ots').write_bytes(b'malformed')
    output = api().full(tmp_path, chain_cache={'format': 'prove.chain.v2'})
    assert output.code == 2 and output.report['manifest_anchor']['state'] == 'invalid'
    assert output.report['result_anchor']['state'] == 'missing'
    assert api().full(tmp_path, policy='integrity-only').code == 0
    proof = api().make_inclusion(tmp_path, 0, include_proofs=False)
    assert proof['proofs'] == {'manifest': None, 'result': None}
    with pytest.raises(TallyLockError): api().make_inclusion(tmp_path, 0)
    proof['proofs']['manifest'] = 'not base64!'
    assert api().inclusion(proof, policy='integrity-only').code == 2


def test_expected_bytes_rejects_sparse_size_before_reads(tmp_path, monkeypatch):
    path = tmp_path / 'sparse'
    with path.open('wb') as stream: stream.truncate(1024 * 1024)
    def trap(*args): raise AssertionError('size mismatch must not read')
    with filesystem.Directory(tmp_path) as directory:
        monkeypatch.setattr(os, 'read', trap)
        with pytest.raises(TallyLockError): directory.digest('sparse', expected_bytes=2)
        for expected in (True, -1, 2**53, 1.0):
            with pytest.raises(TallyLockError): directory.digest('sparse', expected_bytes=expected)


def package_for(manifest, result, event, siblings=None):
    return {'format': 'prove.inclusion.v1', 'registration_id': canonical.digest(manifest),
            'receipt_id': canonical.digest(result), 'manifest': manifest, 'result': result,
            'event': event, 'index': event['index'], 'size': result['records']['count'],
            'siblings': [] if siblings is None else siblings, 'proofs': {'manifest': None, 'result': None}}


def test_inclusion_rejects_nonterminal_at_known_final_position(tmp_path):
    from tallylock import merkle
    manifest, result = receipt(tmp_path)
    event = {'format': 'prove.event.v1', 'registration_id': canonical.digest(manifest), 'attempt_id': 'run-1',
             'index': 0, 'kind': 'sample_start', 'sample_id': 'sample-1'}
    result['records'].update(count=1, root=merkle.root([canonical.dumps(event)]))
    package = package_for(manifest, result, event)
    schema.validate_inclusion(package)  # Direct schema does not claim terminal/history validation.
    assert api().inclusion(package, policy='integrity-only').code == 2


def test_artifact_checks_collect_later_invalidity_after_read_failure(tmp_path, monkeypatch):
    receipt(tmp_path)
    original = filesystem.Directory.digest
    calls = []
    def digest(self, path, **kwargs):
        calls.append(path)
        if path.endswith('dataset.json'):
            raise TallyLockError('synthetic read failure', code=5)
        if path.endswith('scores.json'):
            return '0' * 64, kwargs['expected_bytes']
        return original(self, path, **kwargs)
    monkeypatch.setattr(filesystem.Directory, 'digest', digest)
    output = api().full(tmp_path, policy='integrity-only')
    assert output.code == 2 and len(calls) == 2
    assert {e['code'] for e in output.report['errors'] if e['stage'] == 'artifacts'} == {2, 5}


def test_error_cap_keeps_severity_after_thirty_two_presented_errors(tmp_path, monkeypatch):
    manifest, result = receipt(tmp_path, generic=True)
    inventory = {}
    for index in range(40):
        path = f'{index:02}.bin'
        (tmp_path / 'artifacts' / path).write_bytes(b'')
        inventory[path] = {'sha256': hashlib.sha256(b'').hexdigest(), 'bytes': 0, 'role': 'output',
                           'media_type': 'application/octet-stream'}
    (tmp_path / 'artifacts' / 'Résumé.TXT').unlink()
    result['inventory'] = inventory
    checked = records.build(manifest, 'run-1', inventory, 'completed', None)
    result['records'] = checked.metadata
    (tmp_path / 'records.jsonl').write_bytes(checked.data)
    write_result(tmp_path, result)
    calls = []
    def digest(self, path, **kwargs):
        calls.append(path)
        raise TallyLockError('synthetic read failure: sensitive arbitrary payload must not appear', code=2 if path.endswith('39.bin') else 5)
    monkeypatch.setattr(filesystem.Directory, 'digest', digest)
    output = api().full(tmp_path, policy='integrity-only')
    assert output.code == 2 and len(calls) == 40 and len(output.report['errors']) == 32
    assert all(e['code'] == 5 for e in output.report['errors'])
    assert 'sensitive arbitrary payload' not in json.dumps(output.report)


def test_errors_preserve_safe_actionable_reasons_without_raw_payloads(tmp_path):
    _, result = receipt(tmp_path)
    result['score']['aggregate']['numerator'] = 0
    write_result(tmp_path, result)
    output = api().full(tmp_path, policy='integrity-only')
    assert any('aggregate' in e['message'] for e in output.report['errors'] if e['stage'] == 'score')
    secret_marker = 'ARBITRARY-UNTRUSTED-VALUE'
    manifest = canonical.loads((tmp_path / 'manifest.json').read_bytes())
    manifest['model']['evidence'] = secret_marker
    (tmp_path / 'manifest.json').write_bytes(canonical.dumps(manifest))
    bad = api().full(tmp_path, policy='integrity-only')
    assert bad.code == 2 and secret_marker not in json.dumps(bad.report)
    bad_policy = api().full(tmp_path, policy=secret_marker * 3000)
    assert bad_policy.code == 2 and secret_marker not in json.dumps(bad_policy.report)


@pytest.mark.parametrize('path', [None, 3, {}, b'bytes-path', 'bad\x00path'])
def test_bad_receipt_type_is_reported_before_any_filesystem_or_cache_work(path, monkeypatch):
    def trap(*args, **kwargs): raise AssertionError('invalid path must precede IO and cache work')
    monkeypatch.setattr(api().chain, 'prepare', trap)
    monkeypatch.setattr(filesystem.Directory, '__enter__', trap)
    output = api().full(path, chain_cache={})
    assert output.code == 2 and output.report['registration_id'] is None
    assert output.report['chain_view'] == {'state': 'not_checked'}


@pytest.mark.parametrize('change', ['parent', 'file'])
def test_full_detects_actual_descriptor_read_races(tmp_path, monkeypatch, change):
    receipt(tmp_path, generic=True)
    target = tmp_path / 'artifacts' / 'Résumé.TXT'
    identity = target.stat().st_ino
    original = os.read
    changed = False
    def read(fd, size):
        nonlocal changed
        data = original(fd, size)
        if not changed and os.fstat(fd).st_ino == identity and data:
            changed = True
            if change == 'file':
                target.write_bytes(b'SNAPSHOT')
            else:
                (tmp_path / 'artifacts').rename(tmp_path.parent / (tmp_path.name + '-old-artifacts'))
                target.parent.mkdir()
                target.write_bytes(b'snapshot')
        return data
    monkeypatch.setattr(os, 'read', read)
    output = api().full(tmp_path, policy='integrity-only')
    assert changed and output.code == 5 and output.report['artifact_integrity']['state'] == 'unavailable'


def test_full_rechecks_canonical_core_bytes_after_other_checks(tmp_path, monkeypatch):
    from tallylock import scoring
    receipt(tmp_path, generic=True)
    original = scoring.check
    def score(*args, **kwargs):
        checked = original(*args, **kwargs)
        core = canonical.loads((tmp_path / 'manifest.json').read_bytes())
        core['metadata']['changed'] = True
        (tmp_path / 'manifest.json').write_bytes(canonical.dumps(core))
        return checked
    monkeypatch.setattr(scoring, 'check', score)
    output = api().full(tmp_path, policy='integrity-only')
    assert output.code == 5 and any(e['stage'] == 'stability' for e in output.report['errors'])


def test_honestly_rehashed_budget_excess_cannot_claim_completed(tmp_path):
    from tallylock import merkle
    manifest, result = receipt(tmp_path)
    events = records.decode((tmp_path / 'records.jsonl').read_bytes())
    call = {'format': 'prove.event.v1', 'registration_id': canonical.digest(manifest), 'attempt_id': 'run-1',
            'index': 1, 'kind': 'call', 'sample_id': 'sample-1', 'call_id': 'call-1', 'retry_of': None,
            'source': 'recorded', 'status': 'succeeded', 'input': None, 'output': None,
            'usage': {field: 0 for field in ('input_tokens', 'output_tokens', 'reasoning_tokens', 'cached_tokens', 'duration_ms')}}
    events.insert(1, call)
    for index, event in enumerate(events): event['index'] = index
    data = records.encode(events)
    result['records'].update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), count=len(events),
                             root=merkle.root([canonical.dumps(event) for event in events]))
    result['resources']['calls'] = 1
    schema.validate_result(result, manifest)
    (tmp_path / 'records.jsonl').write_bytes(data)
    write_result(tmp_path, result)
    output = api().full(tmp_path)
    assert output.code == 2 and output.report['budget']['state'] == 'not_checked'
    assert any('budget' in e['message'] for e in output.report['errors'] if e['stage'] == 'records')
    assert output.report['score']['state'] == 'recomputed'


def test_single_terminal_tree_and_absent_artifacts_are_valid_unsuccessful(tmp_path):
    manifest = schema.default_manifest('Synthetic single leaf')
    checked = records.build(manifest, 'run-1', {}, 'failed', 'No artifacts produced')
    result = {'format': 'prove.result.v1', 'registration_id': canonical.digest(manifest), 'attempt_id': 'run-1',
              'profile': 'artifacts-v1', 'outcome': 'failed', 'reason': 'No artifacts produced', 'inventory': {},
              'records': checked.metadata, 'resources': checked.resources, 'score': None, 'metadata': {}}
    (tmp_path / 'manifest.json').write_bytes(canonical.dumps(manifest))
    write_result(tmp_path, result)
    (tmp_path / 'records.jsonl').write_bytes(checked.data)
    assert api().full(tmp_path, policy='integrity-only').code == 0
    package = api().make_inclusion(tmp_path, 0)
    assert package['siblings'] == [] and api().inclusion(package, policy='integrity-only').code == 0


@pytest.mark.parametrize('value', [b'{}' + b' ' * canonical.MAX_JSON_BYTES, {'untrusted': object()}, {'untrusted': 2**53}])
def test_inclusion_bounded_profile_invalid_inputs_return_two(value):
    output = api().inclusion(value, policy='integrity-only')
    assert output.code == 2 and output.report['record_integrity']['state'] == 'invalid'


def test_inclusion_never_borrows_mutable_input_and_rejects_tampered_event(tmp_path):
    receipt(tmp_path)
    package = api().make_inclusion(tmp_path, 1)
    output = api().inclusion(package, policy='integrity-only')
    package['manifest']['budget']['max_calls'] = 1234
    assert output.report['budget']['declared']['max_calls'] == 0
    package = api().make_inclusion(tmp_path, 1)
    package['event']['status'] = 'failed'
    assert api().inclusion(package, policy='integrity-only').code == 2


def test_expected_bytes_keeps_default_and_exact_read_behavior(tmp_path):
    (tmp_path / 'empty').write_bytes(b'')
    (tmp_path / 'data').write_bytes(b'payload')
    with filesystem.Directory(tmp_path) as directory:
        assert directory.digest('empty', expected_bytes=0) == (hashlib.sha256(b'').hexdigest(), 0)
        assert directory.digest('data', expected_bytes=7) == directory.digest('data')


def test_programming_errors_and_base_exceptions_propagate(tmp_path, monkeypatch):
    receipt(tmp_path)
    def fail(*args, **kwargs): raise RuntimeError('programming failure')
    monkeypatch.setattr(api().scoring, 'check', fail)
    with pytest.raises(RuntimeError, match='programming failure'):
        api().full(tmp_path, policy='integrity-only')
    def stop(*args, **kwargs): raise KeyboardInterrupt()
    monkeypatch.setattr(api().scoring, 'check', stop)
    with pytest.raises(KeyboardInterrupt): api().full(tmp_path, policy='integrity-only')


def trace_package(kinds, index, *, calls=0, samples=1, outcome='failed', other_samples=0):
    """Commit exact synthetic records, including deliberately impossible histories."""
    from tallylock import merkle
    manifest = schema.default_manifest('Synthetic trace slot bounds')
    manifest['profile'] = 'trace-v1'
    selected = [f'sample-{number + 1}' for number in range(samples)]
    manifest['attempts'] = [{'id': 'run-1', 'sample_ids': selected}]
    if other_samples:
        manifest['attempts'].append({'id': 'run-other',
                                     'sample_ids': [f'other-{number + 1}' for number in range(other_samples)]})
    registration_id = canonical.digest(manifest)
    reason = None if outcome == 'completed' else 'Synthetic unsuccessful trace'
    events = []
    previous_call = None
    for position, entry in enumerate(kinds):
        kind, sample = entry if isinstance(entry, tuple) else (entry, 'sample-1')
        event = {'format': 'prove.event.v1', 'registration_id': registration_id, 'attempt_id': 'run-1',
                 'index': position}
        if kind == 'terminal':
            event.update(kind='attempt_end', outcome=outcome, reason=reason)
        elif kind in ('start', 'end'):
            event.update(kind='sample_start' if kind == 'start' else 'sample_end', sample_id=sample)
            if kind == 'end': event['status'] = 'completed'
        else:
            assert kind in ('call', 'retry')
            event.update(kind='call', sample_id=sample, call_id=f'call-{position}',
                         retry_of=(previous_call or 'call-prior') if kind == 'retry' else None,
                         source='recorded', status='succeeded', input=None, output=None,
                         usage={field: 0 for field in ('input_tokens', 'output_tokens', 'reasoning_tokens',
                                                       'cached_tokens', 'duration_ms')})
            previous_call = event['call_id']
        events.append(event)
    data = records.encode(events)
    leaves = [canonical.dumps(event) for event in events]
    result = {'format': 'prove.result.v1', 'registration_id': registration_id, 'attempt_id': 'run-1',
              'profile': 'trace-v1', 'outcome': outcome, 'reason': reason, 'inventory': {},
              'records': {'path': 'records.jsonl', 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                          'count': len(events), 'tree_algorithm': 'rfc9162-sha256', 'root': merkle.root(leaves)},
              'resources': {'calls': calls, **{field: 0 for field in ('input_tokens', 'output_tokens',
                  'reasoning_tokens', 'cached_tokens', 'duration_ms')}}, 'score': None, 'metadata': {}}
    package = package_for(manifest, result, events[index], merkle.proof(leaves, index))
    schema.validate_inclusion(package)
    assert hashlib.sha256(data).hexdigest() == result['records']['sha256']
    assert len(data) == result['records']['bytes'] and len(events) == package['size']
    assert merkle.verify(canonical.dumps(package['event']), index, len(events), package['siblings'],
                         result['records']['root'])
    return package, data


@pytest.mark.parametrize('kinds,index,options', [
    (['call', 'end', 'terminal'], 0, {'calls': 1}),
    (['end', 'start', 'terminal'], 0, {}),
    (['start', 'retry', 'end', 'terminal'], 1, {'calls': 2}),
    (['start', 'terminal'], 1, {'samples': 2, 'outcome': 'completed'}),
    (['start', 'end', 'terminal'], 2, {'calls': 5}),
    (['start', 'call', 'terminal'], 1, {'calls': 0}),
    (['start', 'call', 'retry', 'end', 'terminal'], 2, {'calls': 1}),
    (['end', 'start', 'terminal'], 1, {'outcome': 'completed'}),
    (['start', 'end', 'call', 'terminal'], 2, {'calls': 1, 'outcome': 'completed'}),
    (['start', 'end', 'terminal'], 2, {'calls': canonical.MAX_SAFE_INTEGER}),
])
def test_inclusion_rejects_visible_trace_slot_contradictions_with_valid_membership(kinds, index, options):
    package, _ = trace_package(kinds, index, **options)
    output = api().inclusion(package, policy='integrity-only')
    assert output.code == 2 and output.report['record_integrity']['state'] == 'invalid'
    for field in ('resources', 'coverage', 'budget', 'score'):
        assert output.report[field]['state'] == 'not_checked'
    assert any(error['stage'] == 'inclusion' for error in output.report['errors'])


@pytest.mark.parametrize('kinds,calls,outcome,samples', [
    (['start', 'end', 'terminal'], 0, 'completed', 1),
    (['start', 'call', 'end', 'terminal'], 1, 'completed', 1),
    (['start', 'call', 'retry', 'end', 'terminal'], 2, 'completed', 1),
    ([('start', 'sample-1'), ('end', 'sample-1'), ('start', 'sample-2'), ('end', 'sample-2'), 'terminal'],
     0, 'completed', 2),
    (['terminal'], 0, 'failed', 1),
    (['start', 'terminal'], 0, 'failed', 1),
    (['start', 'call', 'terminal'], 1, 'failed', 1),
    (['start', 'call', 'retry', 'terminal'], 2, 'failed', 1),
])
def test_inclusion_accepts_actual_valid_trace_boundaries_without_full_claims(kinds, calls, outcome, samples):
    for index in range(len(kinds)):
        package, data = trace_package(kinds, index, calls=calls, samples=samples, outcome=outcome,
                                      other_samples=3)
        # Positive examples pass actual full lifecycle/resources checks as well.
        checked = records.check(package['manifest'], package['result'], data)
        assert checked.metadata['count'] == len(kinds)
        output = api().inclusion(package, policy='integrity-only')
        assert output.code == 0 and output.report['record_integrity']['state'] == 'membership_checked'
        for field in ('resources', 'coverage', 'budget', 'score'):
            assert output.report[field]['state'] == 'not_checked'


def test_inclusion_slot_bounds_do_not_assert_unseen_call_history():
    package, data = trace_package(['start', 'end', 'terminal'], 2, calls=1)
    # The visible terminal and declarations allow an unseen call in the middle.
    # This actual full log contains an end instead, which membership cannot reveal.
    with pytest.raises(TallyLockError): records.check(package['manifest'], package['result'], data)
    output = api().inclusion(package, policy='integrity-only')
    assert output.code == 0 and output.report['resources']['state'] == 'not_checked'
