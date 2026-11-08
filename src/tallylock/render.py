"""Plain-language rendering of command reports. Exit codes never depend on this module."""
from __future__ import annotations

_CODES = {2: 'The input was invalid.', 3: 'Some needed evidence is missing.',
          4: 'The evidence uses an unsupported form.', 5: 'The command could not finish.',
          130: 'The command was interrupted.'}


def _failure(report):
    lines = [f"Failed (exit {report['code']}). {_CODES.get(report['code'], 'The command failed.')}"]
    lines += [f"Detail: {error['message']}" for error in report.get('errors', [])]
    return lines


def _verify(report, context):
    receipt = context.get('receipt') or 'RECEIPT'
    code = report['code']
    if code == 2:
        head = 'Result: failed. The receipt does not match its recorded contents.'
    elif code == 3:
        head = 'Result: incomplete. Some needed evidence is missing.'
    elif code == 4:
        head = 'Result: incomplete. Some evidence uses an unsupported form.'
    elif code != 0:
        head = 'Result: the check could not run.'
    else:
        head = 'Result: passed. The receipt contents are intact.'
    lines = [head]
    artifacts = report.get('artifact_integrity') or {}
    records = report.get('record_integrity') or {}
    score = (report.get('score') or {}).get('state')
    if artifacts.get('files') is not None:
        lines.append(f"Checked: {artifacts['files']} files, {artifacts.get('bytes')} bytes, "
                     f"records {records.get('state')}, score {score}.")
    lines += [f"Detail: {error['message']}" for error in report.get('errors', [])]
    pow_check = report.get('provider_pow') or {}
    if pow_check.get('state') == 'checked':
        tip = pow_check['tip']['height']
        confirmations = min(tip - int(height) + 1 for height in pow_check['blocks_on_top'])
        agreed = 'both public services agreed' if pow_check.get('providers_agreed') else 'the services disagreed'
        lines.append(f"Timestamp: checked. {confirmations} later blocks confirm it, {agreed}, "
                     f"and the work was checked on this computer ({pow_check['freshness']['label']}).")
        lines.append('Not checked: full network consensus. Run your own node for that.')
    elif 'timestamp_checked' in report and not report['timestamp_checked']:
        lines.append('Timestamp: not checked.')
        lines.append(f'Next: tallylock verify {receipt} --online')
    elif report.get('policy') == 'integrity-only':
        lines.append('Timestamp: not checked (integrity-only policy).')
    else:
        lines.append(f"Timestamp: manifest {report['manifest_anchor']['state']}, "
                     f"result {report['result_anchor']['state']}.")
    lines.append('Not verified: who ran it, which model was used, or whether the run was honest.')
    return lines


def _inspect(report, context):
    receipt = context.get('receipt') or 'RECEIPT'
    lines = [f"Receipt {report['name']!r} is {report['local_state']}. Registration ID {report['registration_id']}."]
    if report['receipt_id'] is not None:
        names = ', '.join(item['path'] for item in report['inventory_preview'][:5])
        more = ' and more' if report['inventory_count'] > 5 else ''
        lines.append(f"Attempt {report['attempt_id']} ended {report['outcome']} with "
                     f"{report['inventory_count']} files: {names}{more}.")
        lines.append(f"Receipt ID {report['receipt_id']}.")
    states = [f"{target} {value['state']}" for target, value in report['proofs'].items()]
    lines.append('Timestamps: ' + ', '.join(states) + '.')
    lines.append('Not verified: this view only reads the receipt.')
    lines.append(f'Next: tallylock verify {receipt}')
    return lines


def _command(report, context):
    command = report['command']
    receipt = context.get('receipt') or report.get('output') or 'RECEIPT'
    if command == 'init':
        out = report['output']
        return [f'Created a new manifest at {out}.',
                f'Edit it, then freeze it with: tallylock pre-register {out} --receipt RECEIPT_DIR']
    if command == 'pre-register':
        lines = [f"Froze the plan. Registration ID {report['registration_id']}. Receipt folder: {report['output']}."]
        lines += _anchor_lines(report, receipt)
        lines.append(f'Next: tallylock seal {report["output"]} --artifacts OUTPUT_DIR')
        return lines
    if command in ('seal', 'recover-seal'):
        lines = [f"Sealed the outputs. Registration ID {report['registration_id']}. Receipt ID {report['receipt_id']}."]
        lines += _anchor_lines(report, receipt)
        lines.append(f'Next: tallylock verify {receipt}')
        return lines
    if command in ('anchor', 'upgrade'):
        lines = [f"Timestamp {command} finished for {receipt} (local state {report['local_state']})."]
        lines += _anchor_lines(report, receipt, force=True)
        lines.append(f'Next: tallylock upgrade {receipt}' if command == 'anchor' else f'Next: tallylock verify {receipt}')
        return lines
    if command == 'proof.create':
        return [f"Wrote an inclusion package to {report['output']}.",
                f'Next: tallylock verify --inclusion {report["output"]}']
    if command == 'evidence.export':
        return [f"Wrote chain evidence to {report['output']}.",
                f'Next: tallylock verify RECEIPT --chain-cache {report["output"]}']
    return [f'{command} finished with local state {report["local_state"]}.']


def _anchor_lines(report, receipt, force=False):
    state = report['anchor_action']['state']
    if state == 'not_requested' and not force:
        return []
    if state == 'returned':
        return ['Timestamp request sent. It may stay pending for a while.']
    return [f'Timestamp state: {state}.']


def _doctor(report, context):
    lines = []
    for item in report['checks']:
        lines.append(f"{item['id']} [{item['state']}] {item['message']}")
        if item['next']:
            lines.append(f"Next: {item['next']}")
    return lines


def _run(report):
    how = 'finished' if report['outcome'] == 'completed' else f"failed ({report['reason']})"
    if report['exit_code'] < 0:
        how = f"was stopped by signal {-report['exit_code']}"
    score = report['score']
    passed = [f"Exit code {report['code']}, from your command."] if report['code'] else []
    if report.get('repeat'):
        done = sum(item['outcome'] == 'completed' for item in report['repeat'])
        return [f"Ran {len(report['repeat'])} times: {done} finished, {len(report['repeat']) - done} failed.",
                f"This plan now has {report['seq']} recorded attempts.", *passed, 'Next: tallylock score']
    lines = [f"Run {report['seq']} {how}. Recorded as attempt {report['seq']} of this plan.",
             f"Score: {score['numerator']}/{score['denominator']}." if score else
             "Score: none found. Print a line like 'tallylock: score=0.74' to record one."]
    state = report['anchor']['state']
    lines.append('Timestamp: requested.' if report['anchor'].get('submitted') else
                 'Timestamp: not requested.' if state == 'not_requested' else
                 'Timestamp: could not be requested now. The run is still recorded.')
    lines += passed
    lines.append('Next: tallylock score')
    return lines


def _timestamps(report):
    if 'timestamps' not in report:
        return []
    checked = report['timestamps']
    if not checked['heads']:
        return ['Timestamps: this plan has no Bitcoin proofs to check.']
    lines = []
    for item in checked['heads']:
        seq = item['seq']
        if item['state'] == 'checked':
            lines.append(f"Head {seq}: checked. {item['confirmations']} later blocks confirm it.")
        elif item['state'] == 'pending':
            lines.append(f"Head {seq}: Bitcoin proof pending, run tallylock refresh.")
        elif item['state'] == 'too_few_confirmations':
            lines.append(f"Head {seq}: only {item['confirmations']} blocks confirm it so far, "
                         f"{checked['minimum_confirmations']} needed. Check again later.")
        elif item['state'] == 'skipped':
            lines.append(f"Head {seq}: not checked, {item['reason']}.")
        else:
            lines.append(f"Head {seq}: timestamp check failed. {item['reason']}")
    if checked['providers'] is not None:
        lines.append('Checked against two public block services. Full network consensus was not checked.')
    return lines


def _score(report):
    plan = report['plan']
    lines = [f"Plan {plan['plan_id'][:8]}: {plan['attempts']} runs, {plan['completed']} completed, "
             f"{plan['failed']} failed."]
    if plan['best'] is not None:
        spread = f" ± {report['half_display']}" if plan['interval'] else ' (one scored run, no range yet)'
        lines.append(f"Best {plan['best_display']}. Real score {plan['mean_display']}{spread}.")
    if report['plans_in_repo'] > 1:
        lines.append(f"This repository has {report['plans_in_repo']} plans. Each config change starts a new one.")
    if report['claim']:
        lines += ['Claim line to paste:', report['claim']]
    return lines + _timestamps(report)


def _check(report):
    if report['verdict'] == 'match':
        return ['Claim checked: every number matches the recorded runs.'] + _timestamps(report)
    if report['verdict'] == 'not_found':
        return ['Claim not found in this repository. It cannot be checked here.']
    lines = ['Claim does not match the recorded runs:']
    lines += [f"- {item['field']}: claimed {item['claimed']}, recorded {item['actual']}" for item in report['reasons']]
    return lines


def _refresh(report):
    lines = [f"Checked {len(report['plans'])} plans."]
    for plan in report['plans']:
        lines.append(f"- Plan {plan['plan_id'][:8]}: timestamps refreshed.")
    return lines


def _export(report):
    lines = [f"Wrote the plan {report['plan_id'][:8]} {'bundle' if report['kind'] == 'bundle' else 'in-toto statement'} to {report['out']}."]
    if report.get('note'):
        lines.append(report['note'])
    return lines


def _registry_entry(report):
    return [f"Added '{report['title']}' to the registry.", f"Claim: {report['claim']}"]


def _registry_check(report):
    lines = [f"Registry: {report['verified']} entries checked, {report['failed']} failed."]
    lines += [f"- {item['plan_id'][:8]}: {item.get('reason', 'failed')}" for item in report['entries'] if not item['ok']]
    return lines


def _board(report):
    return [f"Board written to {report['out']}: {report['rows']} entries, {report['excluded']} could not be checked."]


def _compare(report):
    return list(report.get('plain') or [f"Verdict: {report.get('verdict')}."])


def _adapter(report):
    if report['kind'] == 'inspect':
        return [f"Read {len(report['records'])} attempts from the Inspect log. They are declared, not signed."]
    result = report['result']
    if result['ok']:
        return [f"proofbundle checked: {result['trust']}."]
    return [f"proofbundle rejected: {result['reason']}."]


def _capabilities(report):
    names = [item['name'] for item in report['commands'] if item['status'] == 'available']
    return [f"{len(names)} commands: " + ', '.join(names) + '.', 'Use --json for the full machine-readable list.']


_HUB = {'tallylock.refresh.v1': _refresh, 'tallylock.export.v1': _export,
        'tallylock.registry-entry.v1': _registry_entry, 'tallylock.registry-verification.v1': _registry_check,
        'tallylock.board.v1': _board, 'tallylock.compare.v1': _compare, 'tallylock.adapter-import.v1': _adapter,
        'tallylock.capabilities.v1': _capabilities, 'tallylock.agent-guide.v1': lambda report: [report['markdown'].rstrip()]}


def human(report, context=None):
    context = context or {}
    kind = report.get('format')
    if kind == 'tallylock.doctor.v1':
        lines = _doctor(report, context)
    elif kind == 'prove.verification.v1':
        lines = _verify(report, context)
    elif kind == 'prove.inspection.v1':
        lines = _inspect(report, context)
    elif kind == 'tallylock.run.v1':
        lines = _run(report)
    elif kind == 'tallylock.score.v1':
        lines = _score(report)
    elif kind == 'tallylock.claim-check.v1':
        lines = _check(report)
    elif kind in _HUB:
        lines = _HUB[kind](report)
    elif kind == 'prove.command.v1' and report['code'] == 0:
        lines = _command(report, context)
    elif kind == 'prove.command.v1':
        lines = _failure(report)
    else:
        lines = [f"Finished with exit {report.get('code')}."]
    return '\n'.join(lines) + '\n'
