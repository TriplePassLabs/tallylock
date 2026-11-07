"""Installed subprocess command contracts; synthetic inputs and offline backends only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tallylock import canonical, fixture, schema, store


FIELDS = {'format', 'command', 'code', 'registration_id', 'receipt_id', 'local_state',
          'output', 'anchor_action', 'data', 'errors', 'limitations'}


def run(*args, patch=None, code=0, cwd=None, entry=False):
    if patch is None:
        cmd = [str(Path(sys.executable).parent / 'tallylock')] if entry else [sys.executable, '-m', 'tallylock']
    else:
        cmd = [sys.executable, '-c', patch + '\nfrom tallylock.cli import main\nraise SystemExit(main())']
    result = subprocess.run(cmd + [str(a) for a in args], capture_output=True, text=True,
                            cwd=cwd, timeout=20)
    assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
    assert result.stderr == '', result.stderr
    return result.stdout


def report(*args, code=0, **kwargs):
    output = run(*args, code=code, **kwargs)
    assert output.endswith('\n') and output.count('\n') == 1
    value = json.loads(output)
    assert value['code'] == code
    if value['format'] == 'prove.command.v1':
        assert set(value) == FIELDS
        assert len(value['errors']) <= 16
        assert all(len(e['message']) <= 2048 and e['message'].isprintable() for e in value['errors'])
    return value


def generic(tmp_path):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / 'Résumé.TXT').write_bytes(b'ordinary external output\n')
    report('init', '--out', manifest, cwd=tmp_path)
    registered = report('pre-register', manifest, '--receipt', receipt, cwd=tmp_path)
    sealed = report('seal', receipt, '--artifacts', outputs, cwd=tmp_path)
    return manifest, receipt, outputs, registered, sealed


@pytest.mark.parametrize('args', [(), ('--help',), ('seal', '--help'), ('proof', 'create', '--help')])
def test_help(args, tmp_path):
    assert 'usage:' in run(*args, cwd=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_version_entrypoints_and_passive_import(tmp_path):
    assert run('--version').strip() == '0.1.0a1'
    assert run('--version', entry=True).strip() == '0.1.0a1'
    result = subprocess.run([sys.executable, '-c',
        "import tallylock,sys; from importlib.metadata import version; "
        "assert tallylock.__version__ == version('tallylock'); "
        "assert not any(n in sys.modules for n in ('tallylock.cli','tallylock.fixture','tallylock.timestamping'))"],
        capture_output=True, text=True, timeout=10, cwd=tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('args,command', [
    (('secret-unknown-token',), None), (('proof', 'secret-unknown-token'), None),
    (('init', '--o', 'secret-unknown-token'), 'init'),
    (('seal', 'x', '--outcome', 'secret-unknown-token'), 'seal'),
    (('verify',), 'verify'), (('verify', 'x', '--inclusion', 'y'), 'verify'),
    (('verify', 'x', '--min-confirmations', 'secret-unknown-token'), 'verify'),
    (('verify', 'x', '--min-confirmations', '0'), 'verify'),
])
def test_argument_reports_scrub_unknown_values(args, command):
    value = report(*args, code=2)
    assert value['command'] == command
    assert 'secret-unknown-token' not in json.dumps(value)
    assert value['errors'][0]['stage'] == 'arguments'


def test_generic_source_free_workflow_inclusion_and_no_clobber(tmp_path):
    manifest, receipt, outputs, registered, sealed = generic(tmp_path)
    assert registered['local_state'] == 'registered'
    assert sealed['local_state'] == 'sealed'
    assert registered['registration_id'] == sealed['registration_id']
    assert sealed['receipt_id'] == hashlib.sha256((receipt / 'result.json').read_bytes()).hexdigest()
    assert not manifest.read_bytes().endswith(b'\n')
    assert (outputs / 'Résumé.TXT').read_bytes() == b'ordinary external output\n'
    verified = report('verify', receipt, '--offline', '--policy', 'integrity-only',
                      '--chain-cache', tmp_path / 'does-not-exist')
    assert verified['score']['state'] == 'unavailable'
    report('verify', receipt, code=3)
    inclusion = tmp_path / 'inclusion.json'
    created = report('proof', 'create', receipt, '--index', '0', '--out', inclusion, '--without-proofs')
    assert created['data'] == {'index': 0, 'size': 2}
    before = inclusion.read_bytes()
    report('proof', 'create', receipt, '--index', '0', '--out', inclusion, code=2)
    assert inclusion.read_bytes() == before
    prior = manifest.read_bytes()
    report('init', '--out', manifest, code=2)
    assert manifest.read_bytes() == prior
    shutil.rmtree(receipt)
    assert report('verify', '--inclusion', inclusion, '--policy', 'integrity-only')['scope'] == 'inclusion'


@pytest.mark.parametrize('destination', ['poison.json', 'artifacts/poison.json', 'proofs/poison.json', '.prove/poison.json'])
def test_proof_output_cannot_poison_receipt(tmp_path, destination):
    _, receipt, _, _, sealed = generic(tmp_path)
    (receipt / 'proofs').mkdir(exist_ok=True)
    cores = [(receipt / p).read_bytes() for p in ('manifest.json', 'result.json', 'records.jsonl')]
    report('proof', 'create', receipt, '--index', '0', '--out', receipt / destination, code=2)
    assert not (receipt / destination).exists()
    assert cores == [(receipt / p).read_bytes() for p in ('manifest.json', 'result.json', 'records.jsonl')]
    report('verify', receipt, '--policy', 'integrity-only')


def test_proof_output_alias_and_missing_parents(tmp_path):
    _, receipt, _, _, _ = generic(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(receipt, target_is_directory=True)
    report('proof', 'create', receipt, '--index', '0', '--out', alias / 'artifacts' / 'bad.json', code=2)
    report('init', '--out', tmp_path / 'absent' / 'manifest.json', code=5)
    assert not (tmp_path / 'absent').exists()


@pytest.mark.parametrize('kind', ['invalid', 'unsupported', 'pending', 'completed'])
def test_inspection_proof_states_and_anchored_verification(tmp_path, kind):
    from bitcoin.core import CBlockHeader
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation, UnknownAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    from test_chain import cache_for
    _, receipt, _, _, _ = generic(tmp_path)
    (receipt / 'proofs').mkdir()
    headers = {}
    for height, target in enumerate(('manifest', 'result'), 1):
        digest = hashlib.sha256((receipt / f'{target}.json').read_bytes()).digest()
        stamp = Timestamp(digest)
        witness = (BitcoinBlockHeaderAttestation(height) if kind == 'completed' else
                   PendingAttestation('https://example.invalid') if kind == 'pending' else
                   UnknownAttestation(b'12345678', b''))
        stamp.attestations.add(witness)
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
        (receipt / 'proofs' / f'{target}.ots').write_bytes(b'invalid' if kind == 'invalid' else ctx.getbytes())
        headers[height] = CBlockHeader(hashMerkleRoot=digest, nTime=1700000000 + height).serialize()
    if kind == 'invalid':
        assert report('inspect', receipt, code=2)['format'] == 'prove.command.v1'
    else:
        inspected = report('inspect', receipt)
        state = {'completed': 'attestation_present', 'pending': 'pending', 'unsupported': 'unsupported'}[kind]
        assert inspected['proofs']['manifest']['state'] == state
        assert inspected['verification'] == 'not_performed'
    cache = tmp_path / 'cache.json'
    cache.write_bytes(canonical.dumps(cache_for(headers, 7)))
    report('verify', receipt, '--chain-cache', cache,
           code={'completed': 0, 'invalid': 2, 'unsupported': 4, 'pending': 3}[kind])


def test_unsealed_inspection_and_input_failures_are_command_reports(tmp_path):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    report('init', '--out', manifest)
    report('pre-register', manifest, '--receipt', receipt)
    value = report('inspect', receipt)
    assert value['receipt_id'] is value['attempt_id'] is value['outcome'] is None
    assert value['proofs']['result']['state'] == 'core_missing'
    assert report('verify', receipt, '--chain-cache', tmp_path / 'absent', code=5)['format'] == 'prove.command.v1'
    manifest.write_text('{"duplicate":1,"duplicate":2}')
    selected = tmp_path / 'should-not-exist'
    report('pre-register', manifest, '--receipt', selected, code=2)
    assert not selected.exists()


@pytest.mark.parametrize('command', ['pre-register', 'seal'])
@pytest.mark.parametrize('failure,code,state', [('tallylock', 4, 'failed'), ('interrupt', 130, 'interrupted'), ('unexpected', 5, 'failed')])
def test_optional_anchor_failure_retains_local_completion(tmp_path, command, failure, code, state):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / 'output.txt').write_text('frozen')
    report('init', '--out', manifest)
    if command == 'seal':
        report('pre-register', manifest, '--receipt', receipt)
    raised = {'tallylock': "TallyLockError('SECRET backend data',4)", 'interrupt': 'KeyboardInterrupt()',
              'unexpected': "RuntimeError('SECRET backend data')"}[failure]
    patch = ("from tallylock import timestamping\nfrom tallylock.errors import TallyLockError\n"
             f"def fail(*a,**kw): raise {raised}\ntimestamping.submit=fail\n")
    args = ('pre-register', manifest, '--receipt', receipt) if command == 'pre-register' else ('seal', receipt, '--artifacts', outputs)
    value = report(*args, '--anchor', 'ots', patch=patch, code=code)
    assert value['local_state'] == ('registered' if command == 'pre-register' else 'sealed')
    assert value['registration_id'] == hashlib.sha256((receipt / 'manifest.json').read_bytes()).hexdigest()
    if command == 'seal':
        assert value['receipt_id'] == hashlib.sha256((receipt / 'result.json').read_bytes()).hexdigest()
        report('verify', receipt, '--policy', 'integrity-only')
    assert value['anchor_action'] == {'state': state, 'report': None}
    assert 'SECRET' not in json.dumps(value)
    assert not (receipt / '.prove' / 'lock').exists()


@pytest.mark.parametrize('action', ['anchor', 'upgrade'])
def test_explicit_timestamp_actions_dispatch_without_source(tmp_path, action):
    _, receipt, outputs, _, _ = generic(tmp_path)
    shutil.rmtree(outputs)
    patch = ("from tallylock import timestamping\n"
             "def fake(receipt,*,targets): return {'targets':list(targets),'state':'pending'}\n"
             f"timestamping.{ 'submit' if action == 'anchor' else 'upgrade'}=fake\n")
    value = report(action, receipt, '--target', 'manifest', patch=patch)
    assert value['anchor_action'] == {'state': 'returned', 'report': {'targets': ['manifest'], 'state': 'pending'}}


def test_recovery_commands_and_export_dispatch(tmp_path):
    _, receipt, outputs, _, sealed = generic(tmp_path)
    (receipt / 'result.json').unlink()
    shutil.rmtree(outputs)
    assert report('recover-seal', receipt)['receipt_id'] == sealed['receipt_id']
    report('verify', receipt, '--policy', 'integrity-only')
    lock = receipt / '.prove' / 'lock'
    lock.write_bytes(b'')
    report('recover-lock', receipt, '--observed-sha256', '00' * 32, code=2)
    assert lock.exists()
    value = report('recover-lock', receipt, '--observed-sha256', hashlib.sha256(b'').hexdigest())
    assert value['local_state'] == 'lock_recovered'
    assert value['receipt_id'] is None
    patch = "from tallylock import evidence\nevidence.export=lambda *a: {'tip':{'height':8,'hash':'12'*32},'blocks':{'3':{},'2':{}}}\n"
    output = tmp_path / 'chain.json'
    value = report('evidence', 'export', '--bitcoin-rpc', tmp_path / 'trusted-config.json',
                   '--height', '3', '--height', '2', '--out', output, patch=patch)
    assert value['data']['heights'] == [2, 3]
    assert value['data']['trust'] == 'external_explicit'
    assert not output.read_bytes().endswith(b'\n')


def test_fixture_false_math_is_not_repaired(tmp_path):
    value = fixture.example()
    root, outputs = tmp_path / 'fixture', tmp_path / 'outputs'
    root.mkdir()
    outputs.mkdir()
    for path, data in value.artifacts.items():
        (outputs / path).write_bytes(data)
    store.register(value.manifest, root)
    scores = canonical.loads((outputs / value.score_path).read_bytes())
    scores['aggregate']['numerator'] = 2
    (outputs / value.score_path).write_bytes(canonical.dumps(scores))
    # Freeze a consistent but mathematically false reported score.
    store.seal(root, outputs, events=value.events, roles=value.roles,
               score_path=value.score_path, aggregate={'numerator': 2, 'denominator': 2})
    verified = report('verify', root, '--policy', 'integrity-only', code=2)
    assert verified['score']['state'] == 'invalid'


def test_inspect_bounded_preview_does_not_scan_artifacts_or_local_state(tmp_path):
    _, receipt, _, _, _ = generic(tmp_path)
    shutil.rmtree(receipt / 'artifacts')
    os.mkfifo(receipt / '.prove' / 'opaque-fifo')
    inspected = report('inspect', receipt)
    assert inspected['inventory_count'] == 1
    assert inspected['inventory_preview'][0]['path'] == 'Résumé.TXT'
    assert len(inspected['inventory_preview'][0]) == 3


def test_bind_output_alias_rejection_when_worker_mount_available():
    receipt = os.environ.get('TALLYLOCK_ALIAS_RECEIPT')
    if not receipt:
        pytest.skip('main-owned bind alias worker mounts required')
    report('proof', 'create', receipt, '--index', '0', '--out', '/tallylock-source-alias/bad.json', code=2)


@pytest.mark.parametrize('operation', ['register', 'proof'])
def test_selected_receipt_rename_never_writes_replacement_decoy(tmp_path, operation):
    manifest, receipt, _, _, _ = generic(tmp_path)
    moved = tmp_path / 'moved'
    output = tmp_path / 'inclusion.json'
    module, name = ('store', 'register') if operation == 'register' else ('verify', 'make_inclusion')
    patch = (f"from tallylock import {module}\nfrom pathlib import Path\n"
             f"real={module}.{name}\n"
             "def swap(*a,**kw):\n"
             f"    Path({str(receipt)!r}).rename({str(moved)!r})\n"
             f"    Path({str(receipt)!r}).mkdir()\n"
             "    return real(*a,**kw)\n"
             f"{module}.{name}=swap\n")
    args = (('pre-register', manifest, '--receipt', receipt) if operation == 'register' else
            ('proof', 'create', receipt, '--index', '0', '--out', output))
    report(*args, patch=patch, code=5)
    assert list(receipt.iterdir()) == []
    assert not output.exists()
    assert (moved / 'manifest.json').exists()


@pytest.mark.parametrize('failure,code', [('os', 5), ('interrupt', 130)])
def test_main_restores_cwd_after_backend_failure(tmp_path, failure, code):
    _, receipt, outputs, _, _ = generic(tmp_path)
    raised = "OSError('SECRET')" if failure == 'os' else 'KeyboardInterrupt()'
    patch = ("import os\nfrom tallylock import store\n"
             "initial=os.getcwd()\n"
             f"def fail(*a,**kw): raise {raised}\nstore.seal=fail\n"
             "from tallylock.cli import main\n"
             "real_main=main\n"
             "def check(argv=None):\n"
             "    result=real_main(argv)\n"
             "    assert os.getcwd()==initial\n"
             "    return result\n"
             "import tallylock.cli\ntallylock.cli.main=check\n")
    report('seal', receipt, '--artifacts', outputs, patch=patch, code=code)


@pytest.mark.parametrize('mode,code', [('all-fail', 5), ('partial-core', 5), ('partial-calendar', 0), ('interrupt', 130)])
def test_real_timestamp_backend_partial_progress_and_cleanup(tmp_path, mode, code):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / 'output.txt').write_bytes(b'frozen')
    report('init', '--out', manifest)
    report('pre-register', manifest, '--receipt', receipt)
    patch = ("from tallylock import transport,timestamping\nfrom tallylock.errors import TallyLockError\n"
             "from opentimestamps.core.timestamp import Timestamp\n"
             "from opentimestamps.core.notary import PendingAttestation\n"
             "from opentimestamps.core.serialize import BytesSerializationContext\n"
             "timestamping.DEFAULT_AGGREGATORS=['https://a.pool.opentimestamps.org','https://b.pool.opentimestamps.org']\n"
             "calls=0\n"
             "def submit(origin,commitment,**kw):\n"
             "    global calls\n    calls+=1\n"
             f"    mode={mode!r}\n"
             "    if mode=='interrupt' and calls==2: raise KeyboardInterrupt()\n"
             "    if mode=='all-fail' or (mode=='partial-core' and calls%2==0) or (mode=='partial-calendar' and calls>2):\n"
             "        raise TallyLockError('SECRET network response',5)\n"
             "    stamp=Timestamp(commitment)\n"
             "    stamp.attestations.add(PendingAttestation(origin))\n"
             "    ctx=BytesSerializationContext()\n    stamp.serialize(ctx)\n    return ctx.getbytes()\n"
             "transport.submit=submit\n")
    value = report('seal', receipt, '--artifacts', outputs, '--anchor', 'ots', patch=patch, code=code)
    assert value['local_state'] == 'sealed'
    assert value['receipt_id'] == hashlib.sha256((receipt / 'result.json').read_bytes()).hexdigest()
    assert 'SECRET' not in json.dumps(value)
    assert not (receipt / '.prove' / 'lock').exists()
    if mode != 'all-fail':
        assert (receipt / 'proofs' / 'manifest.ots').exists()
    report('verify', receipt, '--policy', 'integrity-only')
    if mode == 'partial-calendar':
        assert value['anchor_action']['state'] == 'returned'
        assert value['anchor_action']['report']['targets']['manifest']['state'] == 'pending'
    elif mode != 'interrupt':
        assert value['anchor_action'] == {'state': 'failed', 'report': None}
        # An explicit retry uses saved state, never the original output source.
        shutil.rmtree(outputs)
        retry_patch = ("from tallylock import timestamping,transport\n"
                       "timestamping.DEFAULT_AGGREGATORS=['https://a.pool.opentimestamps.org','https://b.pool.opentimestamps.org']\n"
                       "def forbidden(*a,**kw): raise AssertionError('unexpected online request')\n"
                       "transport.submit=forbidden\ntransport.upgrade=forbidden\n")
        retried = report('upgrade', receipt, patch=retry_patch)
        assert any(t['state'] == 'retry_wait' for t in retried['anchor_action']['report']['targets'].values())


def test_cli_explicit_trace_and_score_data_options(tmp_path):
    value = fixture.example()
    manifest = tmp_path / 'manifest.json'
    manifest.write_bytes(canonical.dumps(value.manifest))
    receipt = tmp_path / 'receipt'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    for path, data in value.artifacts.items():
        (outputs / path).write_bytes(data)
    options = {'roles': value.roles, 'media-types': {p: 'application/json' for p in value.artifacts},
               'aggregate': value.aggregate, 'metadata': {'source': 'external ordinary data'}}
    args = []
    for name, payload in options.items():
        path = tmp_path / f'{name}.json'
        path.write_bytes(canonical.dumps(payload))
        args.extend(['--' + name, path])
    events = tmp_path / 'events.jsonl'
    events.write_text(''.join(json.dumps(event) + '\n' for event in value.events))
    report('pre-register', manifest, '--receipt', receipt)
    report('seal', receipt, '--artifacts', outputs, '--attempt', 'run-1', '--events', events,
           '--score-path', value.score_path, *args)
    assert report('verify', receipt, '--policy', 'integrity-only')['score']['recomputed'] == value.aggregate
    assert all((outputs / p).read_bytes() == data for p, data in value.artifacts.items())


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'oversize', 'duplicate'])
def test_manifest_inputs_are_bounded_regular_strict_data(tmp_path, kind):
    manifest = tmp_path / 'manifest.json'
    if kind == 'symlink':
        source = tmp_path / 'source.json'
        source.write_bytes(canonical.dumps(schema.default_manifest()))
        manifest.symlink_to(source)
    elif kind == 'fifo':
        os.mkfifo(manifest)
    elif kind == 'oversize':
        with manifest.open('wb') as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
    else:
        manifest.write_bytes(b'{"format":1,"format":2}')
    receipt = tmp_path / 'receipt'
    report('pre-register', manifest, '--receipt', receipt, code=2)
    assert not receipt.exists()


def test_minimum_confirmation_argument_and_verifier_report_passthrough(tmp_path):
    _, receipt, _, _, _ = generic(tmp_path)
    value = report('verify', receipt, '--min-confirmations', '9', code=3)
    assert value['minimum_confirmations'] == 9
    # A called verifier owns its exact shape/code, including unsupported evidence.
    patch = ("from tallylock import verify\n"
             "verify.full=lambda *a,**kw: verify.Verification(4,{'format':'test.verifier','code':4,'marker':'exact'})\n")
    assert report('verify', receipt, patch=patch, code=4) == {'format': 'test.verifier', 'code': 4, 'marker': 'exact'}


def test_no_producer_import_or_metadata_execution(tmp_path):
    marker = tmp_path / 'must-not-execute'
    manifest = schema.default_manifest()
    manifest['metadata'] = {'command': f'touch {marker}', 'module': 'tallylock.fixture'}
    path = tmp_path / 'manifest.json'
    path.write_bytes(canonical.dumps(manifest))
    patch = ("import builtins\nreal_import=builtins.__import__\n"
             "def checked(name,*a,**kw):\n"
             "    assert name not in ('tallylock.fixture','inspect_ai','openai','anthropic','torch')\n"
             "    return real_import(name,*a,**kw)\n"
             "builtins.__import__=checked\n")
    report('pre-register', path, '--receipt', tmp_path / 'receipt', patch=patch)
    assert not marker.exists()


def test_inspection_preview_is_utf8_sorted_and_capped_at_100(tmp_path):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    for index in range(102):
        (outputs / f'{index:03}.txt').write_bytes(b'x')
    report('init', '--out', manifest)
    report('pre-register', manifest, '--receipt', receipt)
    report('seal', receipt, '--artifacts', outputs)
    before = {p.relative_to(receipt): p.read_bytes() for p in receipt.rglob('*') if p.is_file()}
    value = report('inspect', receipt)
    assert value['inventory_count'] == 102 and value['preview_truncated'] is True
    assert [entry['path'] for entry in value['inventory_preview']] == [f'{i:03}.txt' for i in range(100)]
    assert before == {p.relative_to(receipt): p.read_bytes() for p in receipt.rglob('*') if p.is_file()}


def test_closed_stdout_has_no_traceback_or_retry_loop(tmp_path):
    manifest = tmp_path / 'manifest.json'
    child = subprocess.Popen([sys.executable, '-m', 'tallylock', 'init', '--out', str(manifest)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.stdout.close()
    assert child.wait(timeout=10) == 5
    assert child.stderr.read() == b''
    assert manifest.exists()


def test_explicit_unsuccessful_empty_receipt(tmp_path):
    manifest = tmp_path / 'manifest.json'
    receipt = tmp_path / 'receipt'
    report('init', '--out', manifest)
    report('pre-register', manifest, '--receipt', receipt)
    sealed = report('seal', receipt, '--outcome', 'aborted', '--reason', 'Producer stopped before output')
    assert sealed['local_state'] == 'sealed'
    verified = report('verify', receipt, '--policy', 'integrity-only')
    assert verified['outcome'] == 'aborted'


@pytest.mark.parametrize('name', ['forbidden:name.txt', 'bad\\name.txt', 'trailing-dot.'])
def test_path_rejections_preserve_actionable_explicit_filename(tmp_path, name):
    manifest = tmp_path / 'manifest.json'
    receipt, outputs = tmp_path / 'receipt', tmp_path / 'outputs'
    outputs.mkdir()
    (outputs / name).write_bytes(b'unchanged')
    report('init', '--out', manifest)
    report('pre-register', manifest, '--receipt', receipt)
    value = report('seal', receipt, '--artifacts', outputs, code=2)
    assert repr(name) in value['errors'][0]['message']
    assert (outputs / name).read_bytes() == b'unchanged'
    assert not (receipt / 'result.json').exists()


@pytest.mark.parametrize('field', ['max_calls', 'max_input_tokens', 'max_output_tokens'])
def test_schema_diagnostics_keep_field_location_and_redact_large_instance_values(tmp_path, field):
    path = tmp_path / 'manifest.json'
    value = schema.default_manifest()
    marker = 'PRIVATE_INSTANCE_PAYLOAD_VALUE'
    value['budget'][field] = marker * 300
    path.write_bytes(canonical.dumps(value))
    answer = report('pre-register', path, '--receipt', tmp_path / 'receipt', code=2)
    assert f'budget.{field}' in answer['errors'][0]['message']
    assert marker not in json.dumps(answer)
    assert not (tmp_path / 'receipt').exists()


def test_duplicate_key_and_unsupported_format_diagnostics_hide_values(tmp_path):
    path = tmp_path / 'manifest.json'
    marker = 'PRIVATE_INPUT_BODY_KEY'
    path.write_text(json.dumps({marker: 1})[:-1] + f',"{marker}":2}}')
    answer = report('pre-register', path, '--receipt', tmp_path / 'receipt', code=2)
    assert 'duplicate JSON key' in answer['errors'][0]['message']
    assert marker not in json.dumps(answer)
    value = schema.default_manifest()
    value['format'] = marker
    path.write_bytes(canonical.dumps(value))
    answer = report('pre-register', path, '--receipt', tmp_path / 'receipt', code=4)
    assert 'unsupported format' in answer['errors'][0]['message']
    assert marker not in json.dumps(answer)


@pytest.mark.parametrize('action', ['anchor', 'upgrade'])
@pytest.mark.parametrize('sealed', [False, True])
@pytest.mark.parametrize('interrupted', [False, True])
def test_explicit_timestamp_actions_retain_validated_existing_state(tmp_path, action, sealed, interrupted):
    path, receipt = tmp_path / 'manifest.json', tmp_path / 'receipt'
    report('init', '--out', path)
    report('pre-register', path, '--receipt', receipt)
    if sealed:
        report('seal', receipt, '--outcome', 'failed', '--reason', 'Synthetic external failure')
    raised = "KeyboardInterrupt()" if interrupted else "TallyLockError('PRIVATE_CALENDAR_AUTH_BODY',5)"
    patch = ("from tallylock import timestamping\nfrom tallylock.errors import TallyLockError\n"
             f"def fail(*a,**kw): raise {raised}\n"
             f"timestamping.{'submit' if action == 'anchor' else 'upgrade'}=fail\n")
    answer = report(action, receipt, '--target', 'manifest', patch=patch, code=130 if interrupted else 5)
    assert answer['local_state'] == ('sealed' if sealed else 'registered')
    assert answer['registration_id']
    assert bool(answer['receipt_id']) is sealed
    assert answer['anchor_action'] == {'state': 'interrupted' if interrupted else 'failed', 'report': None}
    assert 'PRIVATE_CALENDAR_AUTH_BODY' not in json.dumps(answer)


def test_full_stdout_device_returns_operational_failure_with_local_bytes_preserved(tmp_path):
    manifest = tmp_path / 'manifest.json'
    with open('/dev/full', 'wb') as sink:
        child = subprocess.run([sys.executable, '-m', 'tallylock', 'init', '--out', str(manifest)],
                               stdout=sink, stderr=subprocess.PIPE, timeout=10)
    assert child.returncode == 5, child.stderr
    assert child.stderr == b''
    schema.validate_manifest(canonical.loads(manifest.read_bytes()))


@pytest.mark.parametrize('number', [5, 28])
def test_injected_terminal_stdout_io_error_is_not_retried(tmp_path, number):
    manifest = tmp_path / 'manifest.json'
    patch = ("import os,sys\nfrom pathlib import Path\n"
             "real_stdout=sys.stdout\n"
             "class FailedSink:\n"
             "    attempts=0\n"
             "    def write(self,data):\n"
             "        self.attempts+=1\n"
             f"        raise OSError({number},'PRIVATE_SINK_MESSAGE')\n"
             "    def flush(self): return None\n"
             "    def fileno(self): return real_stdout.fileno()\n"
             "sink=FailedSink()\nsys.stdout=sink\n"
             "from tallylock.cli import main\nreal_main=main\n"
             "def checked(argv=None):\n"
             "    result=real_main(argv)\n"
             "    assert sink.attempts==1\n"
             "    return result\n"
             "import tallylock.cli\ntallylock.cli.main=checked\n")
    assert run('init', '--out', manifest, patch=patch, code=5) == ''
    assert manifest.exists()


def test_stdout_descriptor_closed_after_startup_transfers_devnull_ownership(tmp_path):
    manifest = tmp_path / 'manifest.json'
    assert run('init', '--out', manifest, patch='import os\nos.close(1)', code=5) == ''
    schema.validate_manifest(canonical.loads(manifest.read_bytes()))


def test_stdout_absent_from_interpreter_startup_preserves_local_work(tmp_path):
    manifest = tmp_path / 'manifest.json'
    child = subprocess.run(['sh', '-c', 'exec "$@" 1>&-', 'prove-stdout-test',
                            sys.executable, '-m', 'tallylock', 'init', '--out', str(manifest)],
                           capture_output=True, timeout=10)
    assert child.returncode == 5, child.stderr
    assert child.stdout == child.stderr == b''
    schema.validate_manifest(canonical.loads(manifest.read_bytes()))


def test_closed_stdout_stream_preserves_local_work_without_reporting_retry(tmp_path):
    manifest = tmp_path / 'manifest.json'
    assert run('init', '--out', manifest, patch='import sys\nsys.stdout.close()', code=5) == ''
    schema.validate_manifest(canonical.loads(manifest.read_bytes()))

