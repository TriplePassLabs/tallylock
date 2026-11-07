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
            'recover-seal', 'recover-lock'}


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['allow_abbrev'] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        # argparse includes arbitrary option values in its diagnostics.
        raise TallyLockError("Invalid command arguments", code=2)


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
    commands = parser.add_subparsers(dest='command', required=True)
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
    verify = commands.add_parser('verify', help='Read-only offline verification')
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument('receipt', nargs='?', type=_path)
    source.add_argument('--inclusion', type=_path)
    verify.add_argument('--offline', action='store_true', help='Accepted explicitly; verification is always offline')
    verify.add_argument('--policy', choices=['anchored', 'integrity-only'], default='anchored')
    verify.add_argument('--chain-cache', type=_path)
    verify.add_argument('--min-confirmations', type=_positive, default=6)
    inspect = commands.add_parser('inspect', help='Bounded local presentation without verification')
    inspect.add_argument('receipt', type=_path)
    proof = commands.add_parser('proof', help='Record inclusion packages')
    create = proof.add_subparsers(dest='action', required=True).add_parser('create')
    create.add_argument('receipt', type=_path)
    create.add_argument('--index', type=_integer, required=True)
    create.add_argument('--out', required=True, type=_path)
    create.add_argument('--without-proofs', action='store_true')
    evidence = commands.add_parser('evidence', help='Explicit external chain evidence')
    export = evidence.add_subparsers(dest='action', required=True).add_parser('export')
    export.add_argument('--bitcoin-rpc', required=True, metavar='CONFIG', type=_path)
    export.add_argument('--height', type=_integer, action='append', required=True)
    export.add_argument('--out', required=True, type=_path)
    recover = commands.add_parser('recover-seal', help='Resume an explicit durable seal checkpoint')
    recover.add_argument('receipt', type=_path)
    lock = commands.add_parser('recover-lock', help='Recover only the explicitly observed abandoned lock')
    lock.add_argument('receipt', type=_path)
    lock.add_argument('--observed-sha256', required=True)
    return parser


def _recognized(argv):
    if argv and argv[0] in COMMANDS:
        return argv[0]
    if len(argv) >= 2 and (argv[0], argv[1]) in {('proof', 'create'), ('evidence', 'export')}:
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
        cache = None
        if args.policy == 'anchored' and args.chain_cache:
            cache = _json_file(args.chain_cache)
        options = {'policy': args.policy, 'chain_cache': cache, 'minimum_confirmations': args.min_confirmations}
        if args.inclusion:
            value = _json_file(args.inclusion)
            phase[0] = 'local'
            return verify.inclusion(value, **options).report
        phase[0] = 'local'
        # Verifier owns opening/validating its receipt so all invoked failures
        # retain the exact Verification.report rather than a CLI envelope.
        return verify.full(_path(args.receipt), **options).report
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


def _emit(report):
    if sys.stdout is None or getattr(sys.stdout, 'closed', False):
        return 5
    try:
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
                      'JSON integers must be within the safe integer range', 'JSON nesting exceeds 64 levels'}:
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
    try:
        parser = _parser()
        if not argv:
            parser.print_help()
            return 0
        try:
            args = parser.parse_args(argv)
        except SystemExit as error:
            return int(error.code)
        phase[0] = 'input'
        return _emit(_dispatch(args, report, phase))
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
    return _emit(report)
