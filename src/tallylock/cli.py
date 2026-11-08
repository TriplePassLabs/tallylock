"""Explicit data-only commands over the accepted receipt and evidence APIs."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys

from . import __version__
from .errors import TallyLockError


LIMITATIONS = [
    "Receipt integrity does not prove honest execution or model identity.",
    "Timestamp submission is not completed anchoring; presence is unverified without independently selected chain evidence.",
]
COMMANDS = {'init', 'pre-register', 'seal', 'anchor', 'upgrade', 'verify', 'inspect',
            'recover-seal', 'recover-lock', 'doctor', 'run', 'score', 'check', 'refresh', 'export',
            'board', 'compare', 'capabilities', 'agent-guide'}


class _Formatter(argparse.HelpFormatter):
    # Python 3.14 probes stdout for color on every formatter, which fails once stdout is closed.
    def _set_color(self, color, **kwargs):
        super()._set_color(False, **kwargs)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['allow_abbrev'] = False
        kwargs.setdefault('formatter_class', _Formatter)
        super().__init__(*args, **kwargs)

    def error(self, message):
        # argparse includes arbitrary option values in its diagnostics.
        raise TallyLockError("Invalid command arguments", code=2)


class _Commands:
    # Every command takes --json/--human, including the nested proof and evidence actions.
    def __init__(self, subparsers, common):
        self._subparsers, self._common = subparsers, common

    def add_parser(self, name, **kwargs):
        return self._subparsers.add_parser(name, parents=[self._common], **kwargs)


def _integer(value):
    from .canonical import MAX_SAFE_INTEGER
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('Expected an integer') from None
    if not 0 <= number <= MAX_SAFE_INTEGER:
        raise argparse.ArgumentTypeError('Expected a nonnegative safe integer')
    return number


def _positive(value):
    number = _integer(value)
    if number == 0:
        raise argparse.ArgumentTypeError('Expected a positive integer')
    return number


def _parser():
    parser = _Parser(prog='tallylock', description='Freeze external outputs and verify receipts offline.')
    parser.add_argument('--version', action='version', version=__version__)
    common = _Parser(add_help=False)
    common.add_argument('--json', action='store_true', help='Print one JSON report line')
    common.add_argument('--human', action='store_true', help='Print a short plain-language summary')
    commands = _Commands(parser.add_subparsers(dest='command', required=True), common)
    init = commands.add_parser('init', help='Create a fresh editable manifest')
    init.add_argument('--out', required=True, type=_path)
    init.add_argument('--name', default='Evaluation receipt')
    register = commands.add_parser('pre-register', help='Freeze a data-only manifest')
    register.add_argument('manifest', type=_path)
    register.add_argument('--receipt', required=True, type=_path)
    register.add_argument('--anchor', choices=['ots'])
    seal = commands.add_parser('seal', help='Snapshot ordinary external output files')
    seal.add_argument('receipt', type=_path)
    seal.add_argument('--artifacts', type=_path)
    seal.add_argument('--attempt')
    seal.add_argument('--outcome', default='completed', choices=['completed', 'failed', 'aborted', 'budget_exceeded'])
    seal.add_argument('--reason')
    for option in ('events', 'roles', 'media-types', 'score-path', 'aggregate', 'metadata'):
        seal.add_argument('--' + option, type=None if option == 'score-path' else _path)
    seal.add_argument('--anchor', choices=['ots'])
    for name in ('anchor', 'upgrade'):
        action = commands.add_parser(name, help='Explicit timestamp action on frozen cores')
        action.add_argument('receipt', type=_path)
        action.add_argument('--target', choices=['all', 'manifest', 'result'], default='all')
    verify = commands.add_parser('verify', help='Read-only verification, offline unless --online')
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument('receipt', nargs='?', type=_path)
    source.add_argument('--inclusion', type=_path)
    verify.add_argument('--offline', action='store_true', help='Accepted explicitly; verification is always offline')
    verify.add_argument('--policy', choices=['anchored', 'integrity-only', 'provider-pow'],
                        help='Default: provider-pow with --online or --evidence, anchored with --chain-cache, '
                             'otherwise integrity-only')
    verify.add_argument('--online', action='store_true', help='Check timestamps against two public providers')
    verify.add_argument('--evidence', type=_path, help='Saved provider evidence to re-check offline')
    verify.add_argument('--save-evidence', type=_path, help='Write the provider evidence used to this file')
    verify.add_argument('--chain-cache', type=_path)
    verify.add_argument('--min-confirmations', type=_positive, default=6)
    inspect = commands.add_parser('inspect', help='Bounded local presentation without verification')
    inspect.add_argument('receipt', type=_path)
    proof = commands.add_parser('proof', help='Record inclusion packages')
    create = proof.add_subparsers(dest='action', required=True).add_parser('create', parents=[common])
    create.add_argument('receipt', type=_path)
    create.add_argument('--index', type=_integer, required=True)
    create.add_argument('--out', required=True, type=_path)
    create.add_argument('--without-proofs', action='store_true')
    evidence = commands.add_parser('evidence', help='Explicit external chain evidence')
    export = evidence.add_subparsers(dest='action', required=True).add_parser('export', parents=[common])
    export.add_argument('--bitcoin-rpc', required=True, metavar='CONFIG', type=_path)
    export.add_argument('--height', type=_integer, action='append', required=True)
    export.add_argument('--out', required=True, type=_path)
    recover = commands.add_parser('recover-seal', help='Resume an explicit durable seal checkpoint')
    recover.add_argument('receipt', type=_path)
    lock = commands.add_parser('recover-lock', help='Recover only the explicitly observed abandoned lock')
    lock.add_argument('receipt', type=_path)
    lock.add_argument('--observed-sha256', required=True)
    doctor = commands.add_parser('doctor', help='Read-only installation and receipt diagnostics')
    doctor.add_argument('receipt', nargs='?', type=_path)
    run = commands.add_parser('run', help='Run your command once and record the attempt: tallylock run -- CMD')
    run.add_argument('--outputs', type=_path)
    run.add_argument('--score-file', type=_path)
    run.add_argument('--config', type=_path, action='append', default=[])
    run.add_argument('--max-attempts', type=_positive, default=100)
    run.add_argument('--no-anchor', action='store_true')
    run.add_argument('--repeat', type=_positive, default=1)
    run.add_argument('--setup', type=_path)
    run.add_argument('--no-tsa', action='store_true')
    run.add_argument('--tsa', action='append', default=[])
    run.add_argument('argv', nargs=argparse.REMAINDER)
    score = commands.add_parser('score', help='Show the real score and claim line for a plan')
    score.add_argument('--plan')
    score.add_argument('--online', action='store_true', help='Check Bitcoin proofs of ledger heads against two public providers')
    check = commands.add_parser('check', help='Check a pasted claim line against this repository')
    check.add_argument('claim')
    check.add_argument('--online', action='store_true', help='Check Bitcoin proofs of ledger heads against two public providers')
    refresh = commands.add_parser('refresh', help='Recover, re-stamp and upgrade ledger timestamps')
    refresh.add_argument('--plan')
    export = commands.add_parser('export', help='Copy one plan into a bundle, or write an in-toto statement')
    export.add_argument('plan')
    export.add_argument('--out', required=True, type=_path)
    export.add_argument('--format', choices=['bundle', 'intoto'], default='bundle')
    registry = commands.add_parser('registry', help='Add plans to a registry folder and re-verify it')
    registry_actions = registry.add_subparsers(dest='action', required=True)
    registry_add = registry_actions.add_parser('add', parents=[common])
    registry_add.add_argument('registry', type=_path)
    registry_add.add_argument('source', type=_path)
    registry_add.add_argument('plan')
    registry_add.add_argument('--title', required=True)
    registry_add.add_argument('--trust', required=True, choices=['anchored', 'signed', 'declared'])
    registry_add.add_argument('--submitted-by', required=True)
    registry_verify = registry_actions.add_parser('verify', parents=[common])
    registry_verify.add_argument('registry', type=_path)
    board = commands.add_parser('board', help='Build the static Receipts Board from a registry')
    board.add_argument('registry', type=_path)
    board.add_argument('--out', required=True, type=_path)
    compare = commands.add_parser('compare', help='Compare two plans: same setup, and is the gap just noise?')
    compare.add_argument('left')
    compare.add_argument('right')
    adapters = commands.add_parser('adapters', help="Read another tool's records")
    adapter_import = adapters.add_subparsers(dest='action', required=True).add_parser('import', parents=[common])
    adapter_import.add_argument('kind', choices=['inspect', 'proofbundle'])
    adapter_import.add_argument('path', type=_path)
    commands.add_parser('capabilities', help='Print every command as machine-readable JSON')
    commands.add_parser('agent-guide', help='Print the guide for AI assistants')
    return parser


def _recognized(argv):
    if argv and argv[0] in COMMANDS:
        return argv[0]
    if len(argv) >= 2 and (argv[0], argv[1]) in {('proof', 'create'), ('evidence', 'export'), ('registry', 'add'),
                                                  ('registry', 'verify'), ('adapters', 'import')}:
        return '.'.join(argv[:2])
    return None


def _report(command):
    return {'format': 'prove.command.v1', 'command': command, 'code': 0,
            'registration_id': None, 'receipt_id': None, 'local_state': None, 'output': None,
            'anchor_action': {'state': 'not_requested', 'report': None}, 'data': None,
            'errors': [], 'limitations': list(LIMITATIONS)}


def _path(value):
    # Do not resolve symlinks. The parent is the selected trusted opened root;
    # its final component is always traversed through no-follow primitives.
    return Path(value).absolute()


def _read(value, limit=8_388_608):
    from .filesystem import Directory
    selected = _path(value)
    with Directory(selected.parent) as parent:
        return parent.read(selected.name, limit=limit)


def _json_file(value):
    from . import canonical
    return canonical.loads(_read(value))


@contextmanager
def _receipt(value, *, create=False):
    from .filesystem import Directory
    selected = _path(value)
    with Directory(selected.parent) as parent:
        from .paths import validate_path
        validate_path(selected.name)
        if create:
            try:
                os.stat(selected.name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                # A single final component: mkdir_exclusive cannot create ancestors.
                parent.mkdir_exclusive(selected.name)
        # The selected root remains open across every backend phase.
        with Directory(Path(f'/proc/self/fd/{parent.fd}') / selected.name) as directory:
            previous = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
            primary_error = False
            try:
                _check_selected(directory, selected)
                # Backend APIs take Paths, and O_NOFOLLOW forbids a final proc
                # descriptor symlink. A descriptor-selected cwd preserves the
                # actual selected inode even if its external name is replaced.
                # All CLI path arguments were made absolute before this scope.
                os.fchdir(directory.fd)
                yield directory, Path('.')
                _check_selected(directory, selected)
            except BaseException:
                primary_error = True
                raise
            finally:
                cleanup_error = None
                try:
                    os.fchdir(previous)
                except OSError as error:
                    cleanup_error = error
                try:
                    os.close(previous)
                except OSError as error:
                    if cleanup_error is None:
                        cleanup_error = error
                if cleanup_error is not None and not primary_error:
                    raise cleanup_error


def _check_selected(directory, selected):
    from .filesystem import Directory, _same
    try:
        with Directory(selected) as visible:
            if not _same(os.fstat(directory.fd), os.fstat(visible.fd)):
                raise TallyLockError('Selected receipt identity changed', code=5)
    except TallyLockError:
        raise TallyLockError('Selected receipt identity could not be preserved', code=5) from None


def _outside(directory, parent):
    from .filesystem import _contains_directory
    from .store import _ancestor
    if _ancestor(directory, parent) or _contains_directory(directory.fd, os.fstat(parent.fd)):
        raise TallyLockError('Output must be outside the operated receipt')


def _write(value, data, *, receipt=None, selected_receipt=None):
    from .filesystem import Directory
    selected = _path(value)
    with Directory(selected.parent) as parent:
        if receipt is not None:
            _check_selected(receipt, selected_receipt)
            _outside(receipt, parent)
        parent.atomic_write(selected.name, data)
        if receipt is not None:
            _check_selected(receipt, selected_receipt)


def _ids(report, directory, *, result=True):
    from . import canonical
    from .store import _manifest, _optional_read, _canonical_object
    from .schema import validate_result
    manifest = _manifest(directory)
    report['registration_id'] = canonical.digest(manifest)
    if result:
        data = _optional_read(directory, 'result.json')
        if data is not None:
            core = _canonical_object(data, 'result')
            validate_result(core, manifest)
            report['receipt_id'] = canonical.digest(core)


def _inspect(directory):
    from . import anchors, canonical, schema
    from .store import _root, _manifest, _optional_read, _canonical_object
    names = _root(directory)
    manifest = _manifest(directory)
    result = None
    if 'result.json' in names:
        result = _canonical_object(directory.read('result.json'), 'result')
        schema.validate_result(result, manifest)
    inventory = {} if result is None else result['inventory']
    selected = sorted(inventory, key=lambda path: path.encode('utf-8'))[:100]
    proofs = {}
    for target, core in (('manifest', manifest), ('result', result)):
        info = None
        if core is None:
            state = 'core_missing'
        elif 'proofs' not in names:
            state = 'missing'
        else:
            data = _optional_read(directory, f'proofs/{target}.ots', limit=anchors.MAX_PROOF_BYTES)
            if data is None:
                state = 'missing'
            else:
                info = anchors.inspect(data, canonical.digest(core))
                state = ('attestation_present' if info['bitcoin_heights'] else
                         'pending' if info['pending_count'] else 'unsupported')
        proofs[target] = {'state': state, 'inspection': info}
    return {'format': 'prove.inspection.v1', 'code': 0, 'verification': 'not_performed',
            'registration_id': canonical.digest(manifest),
            'receipt_id': None if result is None else canonical.digest(result),
            'local_state': 'registered' if result is None else 'sealed',
            'name': manifest['name'], 'profile': manifest['profile'],
            'attempt_id': None if result is None else result['attempt_id'],
            'outcome': None if result is None else result['outcome'],
            'inventory_count': len(inventory),
            'inventory_preview': [{'path': path, 'sha256': inventory[path]['sha256'],
                                   'bytes': inventory[path]['bytes']} for path in selected],
            'preview_truncated': len(inventory) > 100, 'proofs': proofs,
            'limitations': list(LIMITATIONS)}


def _dispatch(args, report, phase):
    from . import canonical
    command = report['command']
    if command == 'init':
        from .schema import default_manifest
        report['output'] = str(_path(args.out))
        value = default_manifest(args.name)
        phase[0] = 'output'
        _write(args.out, canonical.dumps(value))
        report['local_state'] = 'initialized'
        return report
    if command == 'pre-register':
        from . import schema, store
        if args.anchor:
            from . import timestamping
        report['output'] = str(_path(args.receipt))
        manifest = _json_file(args.manifest)
        schema.validate_manifest(manifest)
        phase[0] = 'local'
        with _receipt(args.receipt, create=True) as (directory, pinned):
            report['registration_id'] = store.register(manifest, pinned)
            report['local_state'] = 'registered'
            _check_selected(directory, args.receipt)
            if args.anchor:
                _anchor(pinned, ('manifest',), 'submit', report, phase)
        return report
    if command == 'verify':
        from . import verify
        if args.online and args.offline:
            raise _Shown("Choose --online or --offline, not both", code=2)
        policy = args.policy or ('provider-pow' if args.online or args.evidence else
                                 'anchored' if args.chain_cache else 'integrity-only')
        cache = None
        if policy == 'anchored' and args.chain_cache:
            cache = _json_file(args.chain_cache)
        options = {'policy': policy, 'chain_cache': cache, 'minimum_confirmations': args.min_confirmations}
        if policy == 'provider-pow':
            options['provider_evidence'] = _json_file(args.evidence) if args.evidence else None
        phase[0] = 'local'
        if args.inclusion:
            checked = verify.inclusion(_json_file(args.inclusion), **options)
        else:
            # Verifier owns opening/validating its receipt so all invoked failures
            # retain the exact Verification.report rather than a CLI envelope.
            checked = verify.full(_path(args.receipt), **options)
        result = checked.report
        if args.save_evidence and checked.evidence is not None:
            phase[0] = 'output'
            _write(args.save_evidence, canonical.dumps(checked.evidence))
        if args.policy is None and result.get('format') == 'prove.verification.v1':
            result['effective_policy'] = policy
            result['timestamp_checked'] = policy in ('anchored', 'provider-pow')
        return result
    if command == 'doctor':
        from . import doctor
        checks = doctor.install_checks()
        if args.receipt is not None:
            phase[0] = 'local'
            try:
                with _receipt(args.receipt) as (directory, pinned):
                    inspection = _inspect(directory)
            except (TallyLockError, OSError):
                checks.append(doctor.unreadable(args.receipt))
            else:
                states = {target: value['state'] for target, value in inspection['proofs'].items()}
                checks.append(doctor.timestamp_check(args.receipt, states, inspection['receipt_id'] is not None))
        return doctor.report(checks)
    if command in ('run', 'score', 'check', 'refresh', 'export', 'compare'):
        return _tally_command(command, args, phase)
    if command in ('registry.add', 'registry.verify', 'board', 'adapters.import', 'capabilities', 'agent-guide'):
        return _hub_command(command, args, phase)
    if command == 'evidence.export':
        from . import evidence
        report['output'] = str(_path(args.out))
        phase[0] = 'local'
        value = evidence.export(_path(args.bitcoin_rpc), args.height)
        phase[0] = 'output'
        _write(args.out, canonical.dumps(value))
        report['data'] = {'tip': value['tip'], 'heights': sorted(int(h) for h in value['blocks']),
                          'trust': 'external_explicit', 'freshness': 'cached_only'}
        return report
    # Parse all seal data before any local writes. Paths and JSON are data only.
    # Trusted code and dependencies load before entering a data-controlled cwd.
    from . import anchors, schema, store
    if command in ('anchor', 'upgrade') or (command == 'seal' and args.anchor):
        from . import timestamping
    if command == 'proof.create':
        from .verify import make_inclusion
    options = {}
    if command == 'seal':
        from . import records
        options = {'attempt_id': args.attempt, 'outcome': args.outcome, 'reason': args.reason,
                   'score_path': args.score_path}
        options['events'] = None if args.events is None else records.decode(_read(args.events, 64 * 1024 * 1024), require_canonical=False)
        for name in ('roles', 'media_types', 'aggregate', 'metadata'):
            selected = getattr(args, name)
            options[name] = None if selected is None else _json_file(selected)
    phase[0] = 'local'
    with _receipt(args.receipt) as (directory, pinned):
        if command == 'inspect':
            return _inspect(directory)
        if command == 'seal' or command == 'recover-seal':
            from . import store
            value = (store.seal(pinned, None if args.artifacts is None else _path(args.artifacts), **options)
                     if command == 'seal' else store.recover_seal(pinned))
            report['registration_id'] = value['registration_id']
            report['receipt_id'] = canonical.digest(value)
            report['local_state'] = 'sealed'
            _check_selected(directory, args.receipt)
            if command == 'seal' and args.anchor:
                _anchor(pinned, ('manifest', 'result'), 'submit', report, phase)
        elif command in ('anchor', 'upgrade'):
            _ids(report, directory)
            report['local_state'] = 'sealed' if report['receipt_id'] is not None else 'registered'
            targets = ('manifest', 'result') if args.target == 'all' else (args.target,)
            _anchor(pinned, targets, 'submit' if command == 'anchor' else 'upgrade', report, phase)
        elif command == 'recover-lock':
            from .filesystem import recover_lock
            recover_lock(directory, args.observed_sha256)
            report['local_state'] = 'lock_recovered'
            # Lock recovery says nothing about whether a seal completed.
        elif command == 'proof.create':
            report['output'] = str(_path(args.out))
            value = make_inclusion(pinned, args.index, include_proofs=not args.without_proofs)
            report['registration_id'] = value['registration_id']
            report['receipt_id'] = value['receipt_id']
            phase[0] = 'output'
            _write(args.out, canonical.dumps(value), receipt=directory, selected_receipt=args.receipt)
            report['data'] = {'index': value['index'], 'size': value['size']}
    return report


def _anchor(receipt, targets, action, report, phase):
    from . import timestamping
    phase[0] = 'anchor'
    report['anchor_action'] = {'state': 'failed', 'report': None}
    value = getattr(timestamping, action)(receipt, targets=targets)
    report['anchor_action'] = {'state': 'returned', 'report': value}
    phase[0] = 'local'


def _repo():
    import subprocess
    try:
        top = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, timeout=30)
    except OSError:
        raise TallyLockError("git is required for run, score and check", code=2) from None
    if top.returncode:
        raise TallyLockError("Run this inside a git repository", code=2)
    return Path(top.stdout.decode().strip())


class _Shown(TallyLockError):
    # Messages written by the run/score/check commands themselves; safe to show as-is.
    pass


def _tally_command(command, args, phase):
    try:
        return _tally(command, args, phase)
    except _Shown:
        raise
    except TallyLockError as error:
        raise _Shown(error.message, code=error.code) from None


def _tally(command, args, phase):
    from . import ledger, tally
    repo = _repo()
    phase[0] = 'local'
    if command == 'run':
        argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
        if not argv:
            raise TallyLockError("Give the command to run after --", code=2)
        configs = []
        for config in args.config:
            try:
                configs.append(config.resolve().relative_to(repo.resolve()))
            except ValueError:
                raise TallyLockError(f"Config file must be inside the repository: {config}", code=2) from None
        plan = ledger.start_plan(repo, argv, configs=tuple(configs), max_attempts=args.max_attempts,
                                 setup=args.setup)
        stdout = None if args.human_mode else sys.stderr.buffer
        tsa = False if args.no_tsa else None
        results = [ledger.run_attempt(plan, outputs=args.outputs, score_file=args.score_file, stdout=stdout,
                                      anchor=not args.no_anchor, tsa=tsa, tsas=args.tsa or None)
                   for _ in range(args.repeat)]
        # Like time or uv run: pass on the first failing exit code, 128 plus the signal for a killed command.
        failed = [item['exit_code'] for item in results if item['exit_code']]
        code = 0 if not failed else 128 - failed[0] if failed[0] < 0 else failed[0]
        report = {**results[-1], 'code': code}
        if args.repeat > 1:
            report['repeat'] = [{key: item[key] for key in ('seq', 'outcome', 'exit_code', 'score')} for item in results]
        return report
    if command == 'score':
        plans = ledger.list_plans(repo)
        if args.plan:
            plans = [plan for plan in plans if plan.startswith(args.plan)]
            if len(plans) != 1:
                raise TallyLockError("No single plan matches that ID", code=3)
        if not plans:
            raise TallyLockError("No runs recorded yet. Start with: tallylock run -- YOUR_COMMAND", code=3)
        plan_id = max(plans, key=lambda item: (repo/'.tallylock'/'plans'/item/'ledger.jsonl').stat().st_mtime_ns
                      if (repo/'.tallylock'/'plans'/item/'ledger.jsonl').exists() else 0)
        summary = tally.plan_summary(repo, plan_id)
        overview = tally.repo_summary(repo)
        claim = tally.format_claim(summary, overview) if summary['attempts'] else None
        half = tally._fields(summary, overview['count'])['half'] if summary['attempts'] else None
        report = {'format': 'tallylock.score.v1', 'code': 0, 'plan': summary, 'half_display': half,
                  'plans_in_repo': overview['count'], 'claim': claim}
        if args.online:
            _online(report, repo, plan_id)
        return report
    if command == 'refresh':
        plans = [_plan_id(repo, args.plan)] if args.plan else ledger.list_plans(repo)
        results = []
        for plan_id in plans:
            results.append({'plan_id': plan_id, 'recovered': ledger.recover(repo, plan_id),
                            'instant': ledger.timestamp_head(repo, plan_id),
                            'upgraded': ledger.upgrade_heads(repo, plan_id)})
        return {'format': 'tallylock.refresh.v1', 'code': 0, 'plans': results}
    if command == 'export':
        plan_id = _plan_id(repo, args.plan)
        if args.format == 'intoto':
            from .adapters import intoto
            from . import canonical
            phase[0] = 'output'
            _write(args.out, canonical.dumps(intoto.to_intoto(repo, plan_id)))
        else:
            from . import registry
            registry.export(repo, plan_id, args.out)
        return {'format': 'tallylock.export.v1', 'code': 0, 'plan_id': plan_id, 'kind': args.format,
                'out': str(args.out), 'note': 'Bundles include the full stdout and stderr of every run. '
                                              'Read them before you publish.' if args.format == 'bundle' else None}
    if command == 'compare':
        from . import compare
        result = compare.compare((repo, _plan_id(repo, args.left)), (repo, _plan_id(repo, args.right)))
        return {**result, 'code': 0}
    verdict = tally.check_claim(repo, args.claim)
    report = {**verdict, 'code': 0 if verdict['verdict'] == 'match' else 3}
    if args.online and verdict['verdict'] == 'match':
        _online(report, repo, verdict['plan_id'])
    return report


def _online(report, repo, plan_id):
    from . import ledger
    report['timestamps'] = ledger.check_heads_online(repo, plan_id)
    if any(item['state'] in ('failed', 'too_few_confirmations') for item in report['timestamps']['heads']):
        report['code'] = 3


def _plan_id(repo, prefix):
    from . import ledger
    matches = [plan for plan in ledger.list_plans(repo) if plan.startswith(prefix)]
    if len(matches) != 1:
        raise TallyLockError(f"No single plan matches {prefix!r}", code=3)
    return matches[0]


def _hub_command(command, args, phase):
    try:
        return _hub(command, args, phase)
    except _Shown:
        raise
    except TallyLockError as error:
        raise _Shown(error.message, code=error.code) from None


def _hub(command, args, phase):
    phase[0] = 'local'
    if command == 'registry.add':
        from . import registry
        plan_id = _plan_id(args.source, args.plan)
        entry = registry.add_entry(args.registry, args.source, plan_id,
                                   {'source': 'tallylock', 'trust': args.trust, 'title': args.title,
                                    'submitted_by': args.submitted_by})
        return {**entry, 'code': 0}
    if command == 'registry.verify':
        from . import registry
        result = registry.verify_registry(args.registry)
        failed = [item for item in result.get('entries', []) if not item.get('ok')]
        return {**result, 'code': 3 if failed else 0}
    if command == 'board':
        from . import board
        return {**board.build(args.registry, args.out), 'code': 0}
    if command == 'adapters.import':
        from .adapters import import_inspect, verify_proofbundle
        if args.kind == 'inspect':
            records = import_inspect(args.path)
            return {'format': 'tallylock.adapter-import.v1', 'code': 0, 'kind': 'inspect', 'trust': 'declared',
                    'records': records}
        result = verify_proofbundle(args.path)
        return {'format': 'tallylock.adapter-import.v1', 'code': 0 if result['ok'] else 3, 'kind': 'proofbundle',
                'trust': result.get('trust'), 'result': result}
    if command == 'capabilities':
        from . import capabilities
        return {**capabilities.capabilities(), 'code': 0}
    from importlib.resources import files
    return {'format': 'tallylock.agent-guide.v1', 'code': 0,
            'markdown': files('tallylock').joinpath('data/agent-guide.md').read_text(encoding='utf-8')}


def _human_mode(argv):
    argv = argv[:argv.index('--')] if '--' in argv else argv
    flags = {'--json', '--human'} & set(argv)
    if len(flags) == 1:
        return flags == {'--human'}
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _emit(report, human=False, context=None):
    if sys.stdout is None or getattr(sys.stdout, 'closed', False):
        return 5
    try:
        if human:
            from . import render
            sys.stdout.write(render.human(report, context))
        else:
            sys.stdout.write(json.dumps(report, ensure_ascii=True, separators=(',', ':')) + '\n')
        sys.stdout.flush()
        return report['code']
    except OSError:
        # Backend scopes (including isolated HTTP children) are already closed.
        # A terminal sink error, including ENOSPC/EIO, must never trigger a
        # second report or another failed flush at interpreter shutdown.
        try:
            target = sys.stdout.fileno()
            fd = os.open(os.devnull, os.O_WRONLY)
            if fd != target:
                try:
                    os.dup2(fd, target)
                finally:
                    os.close(fd)
            # When open reused stdout's closed descriptor, ownership already
            # belongs to the stdout stream; leave it open for its final flush.
        except (OSError, ValueError, AttributeError):
            pass
        return 5


def _diagnostic(error, stage):
    fallback = {'arguments': 'Invalid command arguments',
                'input': 'Input could not be read or validated',
                'local': 'Local operation failed',
                'anchor': 'Timestamp action failed; completed local work is retained',
                'output': 'Output could not be published'}[stage]
    if isinstance(error, _Shown) and isinstance(error.message, str):
        return error.message
    if not isinstance(error, TallyLockError) or stage in ('arguments', 'anchor'):
        return fallback
    text = error.message
    if not isinstance(text, str):
        return fallback
    # Portable-path diagnostics intentionally identify the rejected explicit
    # filename. Their repr-encoded paths may themselves contain colons.
    path_prefixes = ('invalid artifact path: ', 'artifact path is not NFC: ',
                     'control character in artifact path: ', 'artifact path collision: ',
                     'artifact path exceeds 1024 bytes: ', 'artifact path exceeds 2048 bytes: ',
                     'invalid artifact component in ', 'artifact component exceeds 255 bytes in ')
    if text.startswith(path_prefixes):
        message = text
    else:
        prefix = text.split(':', 1)[0]
        if prefix in {'duplicate JSON key', 'unsupported format', 'unsupported profile',
                      'unsupported tree_algorithm', 'unsupported kind', 'undeclared attempt',
                      'invalid JSON', 'format must be a string', 'JSON floating-point values are not permitted',
                      'JSON integers must be within the safe integer range', 'JSON nesting exceeds 64 levels',
                      'TallyLock writes files only on Linux. On Windows, use WSL or a Linux container'}:
            message = prefix
        else:
            match = re.fullmatch(r'invalid (?:manifest|result|event|inclusion|chain|fixtureDataset|fixtureScores|inventory entry) at (.+)', prefix)
            if match is None:
                return fallback
            # Schema values appear only after the diagnostic delimiter. Permit
            # property locations from the trusted packaged schema, never
            # arbitrary instance keys or a jsonschema instance/body rendering.
            from .schema import _SCHEMA

            def properties(value):
                if isinstance(value, dict):
                    names = set(value.get('properties', {}))
                    for child in value.values():
                        names.update(properties(child))
                    return names
                if isinstance(value, list):
                    return set().union(*(properties(child) for child in value))
                return set()

            location = match.group(1)
            known = properties(_SCHEMA)
            if location != '<root>' and not all(
                    part in known or re.fullmatch(r'[0-9]{1,16}', part)
                    for part in location.split('.')):
                return fallback
            message = prefix
    return ''.join(char if char.isprintable() else ' ' for char in message[:2048]).strip() or fallback


def main(argv=None) -> int:
    """Run one explicit command and return its process status."""
    argv = list(sys.argv[1:] if argv is None else argv)
    report = _report(_recognized(argv))
    phase = ['arguments']
    human = _human_mode(argv)
    context = {}
    try:
        parser = _parser()
        if not argv:
            parser.print_help()
            return 0
        try:
            args = parser.parse_args(argv)
        except SystemExit as error:
            return int(error.code)
        if args.json and args.human:
            raise TallyLockError("Invalid command arguments", code=2)
        human = args.human or (not args.json and human)
        args.human_mode = human
        selected = getattr(args, 'receipt', None)
        context = {'receipt': None if selected is None else str(selected)}
        phase[0] = 'input'
        return _emit(_dispatch(args, report, phase), human, context)
    except KeyboardInterrupt:
        report['code'] = 130
        if phase[0] == 'anchor':
            report['anchor_action'] = {'state': 'interrupted', 'report': None}
        report['errors'] = [{'stage': 'interrupt', 'code': 130, 'message': 'Command interrupted'}]
    except (TallyLockError, OSError) as error:
        report['code'] = error.code if isinstance(error, TallyLockError) else 5
        report['errors'] = [{'stage': phase[0], 'code': report['code'],
                             'message': _diagnostic(error, phase[0])}]
    except Exception:
        report['code'] = 5
        report['errors'] = [{'stage': phase[0], 'code': 5, 'message': 'Internal command failure'}]
    return _emit(report, human, context)
