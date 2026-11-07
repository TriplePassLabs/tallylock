# How TallyLock compares

Checked 2026-11-07 against each project's own repository, package page or documentation. Star counts and versions change fast. Where a claim comes from a project's own words, it is quoted or tied to a file. Anything we could not read is marked as unread.

The short version: several small projects now cover parts of "lock the claim, seal the result". TallyLock's own piece is the complete record of attempts. It locks one plan before the first run, records every attempt (failed ones too) in an append-only ledger, and anchors the ledger head to an outside clock. It is meant to sit beside these tools, and to read their records, not to replace them.

## At a glance

| Tool | Strong at | Records every attempt? | Time evidence | Who you must trust |
|---|---|---|---|---|
| TallyLock | One plan locked before the run; attempt ledger with failures; offline check | Yes, by design | OpenTimestamps on the ledger head, plus instant RFC 3161 timestamps from two time authorities | Nobody's server. Your own git history and the outside clocks |
| K-Veritas | One-command sealed runs, hardware and energy measurement, signed report | Yes, but through its server | The server's own clock | The K-Veritas server holds the signing key |
| proofbundle | Signed offline receipts with an inclusion proof, many optional layers | Not claimed | Optional anchors (RFC 3161, OpenTimestamps) | The signer's key. You supply the time-authority trust |
| falsify (PRML) | Fix the pass bar before a test, then check it later | Not claimed | RFC 3161 plus a public transparency log | The time authority and the log |
| NoCherry | Sealed test items with a public random beacon choosing what to reveal | No | Multi-operator timestamp servers | The operators and the beacon |
| Sigstore | Signing any file or statement with an identity and a public log | No | Public log time | Sigstore, the identity provider, the log |
| OSF, AsPredicted | Human pre-registration of a study plan | Partly (withdrawals show) | Their own records | The service |
| W&B, MLflow | Tracking runs day to day | No, runs can be deleted | None | Whoever runs the server |

## K-Veritas

What it does well: `kveritas run --seal -- <command>` is a very short path from a run to a signed report. It measures time, CPU, memory, GPU and energy. Its README says "every run is recorded, failed ones too, so an attempt shows" and "Every run anchored at the server when it ends." Link: https://github.com/27-GROUP/kveritas-go (Apache-2.0 CLI, 13 stars when checked).

What TallyLock adds: a plan frozen before any run, and no vendor in the trust path. In K-Veritas a report signed by a trusted K-Veritas key is `VERIFIED`, any other key is `SELF-ATTESTED`, and `verify --offline` skips the server audit, so the completeness check needs the server. TallyLock's ledger is checked on your own machine. We found no outside timestamp in K-Veritas. We did not read all of its server code.

## proofbundle

What it does well: portable receipts that verify offline, with an Ed25519 signature, an RFC 6962 inclusion proof, optional selective disclosure, optional time anchors, and plugins for Inspect AI and pytest. It states its limits plainly: a bundle does not attest "the absence of cherry-picking in an eval it carries" (SPEC.md, section 7a). Link: https://github.com/b7n0de/proofbundle (MIT, 3 stars; PyPI 6.4.0 and a 6.5.0 README on the main branch when checked).

What TallyLock adds: the attempt ledger. That is the missing piece proofbundle says it leaves open. TallyLock can read a proofbundle receipt with `verify_proofbundle`. That checks the signature and the inclusion proof only, and reports the receipt as "signed". A receipt only counts as "anchored" when you confirm its time anchor yourself, because proofbundle's own rule is that anchor trust must come from the relying party, never from the bundle.

## falsify (PRML)

What it does well: it hashes the pass bar (metric, comparator, threshold, dataset hash, seed) before a test, gets an RFC 3161 timestamp and a public log entry, and checks the receipt offline. It has Inspect and MLflow integrations. Its README says what it does not show: "that the run happened after that time, or that any reported result is true." Link: https://github.com/falsify-dev/falsify (MIT, 8 stars, version 0.5.3 on PyPI).

What TallyLock adds: every attempt of a run, not one claim. A pre-registered bar with ten tries behind it looks the same as one with a single try. The ledger makes the number of tries visible.

## NoCherry

What it does well: it commits to hashes of all test items, then a public random beacon (drand) chosen after the commit picks which items must be revealed, so the test set can stay private and still be audited. Link: https://github.com/peerbench/nocherry (MIT, 0 stars).

What TallyLock adds: it does not do sealed test sets. It covers the other half, how many times the model was tried. The two ideas fit together. We did not read its spec in full.

## Sigstore (cosign, Rekor)

What it does well: signs any file or statement with a short-lived identity or your own key and records it in a public log. It is the standard way to attach a signed statement to a build. Link: https://github.com/sigstore/cosign (Apache-2.0, release v3.1.4 when checked).

What TallyLock adds: the content of the statement. Sigstore proves who signed something and when it was logged. It has no idea what an attempt is. TallyLock exports its ledger as an in-toto Statement so Sigstore can sign it. See the next section.

### Signing a TallyLock ledger with cosign

`tallylock.adapters.to_intoto(repo, plan_id)` returns an in-toto Statement v1. It re-verifies the ledger first and refuses to export a ledger that fails. Each attempt receipt is a subject, named `attempt/<id>`, with its SHA-256 digest. The predicate type is `https://triplepasslabs.com/tallylock/attempt-ledger/v1`.

```
python -c "import json,sys; from tallylock.adapters import to_intoto; print(json.dumps(to_intoto('.', sys.argv[1])))" PLAN_ID > statement.json
cosign attest-blob --statement statement.json --key cosign.key --bundle ledger.sigstore.json
```

Leave out `--key` and `cosign` signs with your identity through its browser sign-in. `--statement` is how cosign takes a ready-made statement. Without it cosign builds its own statement around one blob, which cannot hold one subject per attempt. We checked that flag in the cosign v3.1.4 source and docs. To check the result against one receipt:

```
cosign verify-blob-attestation --bundle ledger.sigstore.json --key cosign.pub --type https://triplepasslabs.com/tallylock/attempt-ledger/v1 --check-claims .tallylock/plans/PLAN_ID/attempts/run-1/result.json
```

The statement is checked by cosign against the receipt's digest. We have not run this command against a live cosign here. The flags come from the cosign docs.

## OSF and AsPredicted

What they do well: they are the accepted home of human pre-registration. AsPredicted says "All pre-registrations PDFs at AsPredicted are permanent, authors may not delete them or hide them after they are created," and a registration stays private to its authors until one makes a PDF. OSF says a withdrawn registration keeps its title and justification while the form and files are removed. Links: https://aspredicted.org/help and https://help.osf.io/article/330-welcome-to-registrations.

What TallyLock adds: a machine-checkable link between the plan and the actual runs. A private AsPredicted registration can stay private, so a lab can register several plans and publish one. A TallyLock plan is named by its own hash, and each plan's ledger shows its attempts. You can paste a TallyLock plan hash into an OSF registration as a public mirror.

## W&B and MLflow

What they do well: they are where runs actually get tracked, with good tables and charts. W&B's own docs say a deleted run with its artifacts is permanently removed. MLflow's `delete_run` leaves the run readable with its stage set to deleted, and its `delete_experiment` docs call that a soft delete. Links: https://docs.coreweave.com/products/wandb/runs/delete-runs and https://mlflow.org/docs/latest/api_reference/python_api/mlflow.client.html.

What TallyLock adds: tamper evidence. A tracker can be edited by whoever runs it. TallyLock does not replace a tracker. A later release may read a tracker's run list to find gaps.

## What we import and export today

| Direction | Function | What it gives you |
|---|---|---|
| In | `import_inspect(log_path)` | Attempts from an Inspect AI `.json` or `.eval` log, labeled "declared". These are unsigned logs, so TallyLock records what they say and nothing more |
| In | `verify_proofbundle(path)` | A proofbundle receipt checked for signature and inclusion. Result is "signed", or "anchored" once you confirm an anchor |
| Out | `to_intoto(repo, plan_id)` | An in-toto Statement for cosign |

Formats were read from these upstream versions: inspect_ai commit da64cc6 (release 0.3.288), proofbundle commit 65bd4b7 (release 6.5.0 notes), in-toto attestation commit 50bf017, cosign v3.1.4. Full commit IDs are in the source headers under `src/tallylock/adapters/` and in `tests/fixtures/adapters/README.md`.
