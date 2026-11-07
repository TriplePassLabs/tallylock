# External testing procedure

TallyLock is a standalone tool. Test it as an ordinary downstream user. Colony Zero, Ouroboros and other research projects may supply inputs and outputs, but TallyLock must install and work without their code, models, credentials or services.

This procedure is prepared ahead of candidate freeze. It does not declare the candidate ready. Consult [READINESS.md](READINESS.md) for the observed gates. A testing delivery must include a separate candidate manifest identifying the exact Git commit, version, distribution names and SHA256 digests, test observations and unresolved gates. Do not substitute an unpinned branch for that candidate.

## Prompt for the external session

> Test the identified TallyLock candidate as an independent CLI consumer. Read its candidate manifest and readiness limitations first. Verify the supplied distribution's SHA256, create a new virtual environment outside both the TallyLock checkout and your research project, install that wheel with its dependencies, and record Python, operating system, architecture and `python -m pip freeze --all`. Use the documented Linux/Python support range. Run `tallylock --version`, `tallylock --help` and `python -m pip check`. Do not edit TallyLock to make a test pass.
>
> First complete the offline quickstart using a fresh directory, a new manifest and tiny ordinary output files. Save exact commands, exit codes and JSON reports outside the receipt. Test full integrity verification, default anchored insufficiency, inclusion verification after moving the original receipt away, an altered artifact, and refusal to overwrite an existing proof output. Block networking during the offline checks where your environment supports it, recording how it was blocked. An OS-level block and a Python audit hook are different evidence.
>
> Then use a small already authorized evaluation from your research project as a separate producer. Review declarations before preregistration, run the producer independently, and seal its ordinary output directory using only installed `tallylock` commands. Preserve the original output bytes. Do not add project-specific behavior to TallyLock. Record any awkward input mapping or unsupported semantics. Start with a generic artifact receipt; trace/scoring integration is optional and must follow the published protocol rather than inventing events or silently converting metrics.
>
> Treat local preregistration, pending timestamps, completed timestamps and independent chain evidence separately. If live anchoring is part of the approved test, wait for the plan proof to complete before the separately launched evaluation, then anchor the result after sealing. Preserve observations without claiming they independently prove execution order. Obtain a chain cache from an independently selected validated source, record provenance without credentials, and verify offline. Never replace missing real evidence with a synthetic header or explorer response while marking the gate passed. If prerequisites are absent, record `not_run` and the reason.
>
> Explain what passed: byte integrity, record consistency, independently recomputed fixture score if selected, membership only, or timestamp/header consistency against the explicit cached chain view. State that model identity, honest execution, complete disclosure of attempts and scientific validity remain unverified. In particular, an inclusion proof does not check all artifacts or the entire trace.
>
> Return a concise Markdown report plus a completed `testing-feedback.template.json`, matching `testing-feedback.schema.json`. Include reproducible defects, expected versus observed behavior, minimal inputs, exact commands/exit codes and relevant report files. Distinguish defects from requests for new features. Keep research artifacts under their existing sharing authorization. Do not publish private outputs, raw credentials or RPC configuration. Put proposed TallyLock changes in the feedback, leaving the tested candidate intact.

## Required observations

| Check ID | Expected observation |
| --- | --- |
| install | Candidate digest and version match; wheel installation and `pip check` succeed outside either checkout |
| generic-offline | Fresh generic preregistration/seal/full integrity check succeeds without model or network access |
| insufficient-anchor | Default anchored verification of a receipt without qualifying evidence returns 3 |
| inclusion | Verification succeeds after hiding the original receipt, reporting membership only |
| tamper | Changing one committed artifact causes full verification to return 2 |
| no-clobber | Existing proof output remains byte-identical after a rejected second publication |
| external-producer | An ordinary producer's outputs are sealed without importing or modifying that project |
| live-anchor | Real fresh proofs and independently obtained chain evidence are checked, or explicitly `not_run` |
| claims | Tester correctly distinguishes integrity, scoring, timestamp and execution/model claims |

For negative checks, preserve the expected nonzero exit code rather than aborting a shell script and losing the observation. Copy the receipt before destructive tests. No paid model run or infrastructure deployment is required by this procedure.

Candidate testing is a feedback boundary before a stable release. A passing downstream smoke test does not establish universal production readiness or replace unresolved acceptance gates.

The unfinished JSON template uses `not_assessed` and permits unknown candidate identifiers. An assessed recommendation requires exact candidate identifiers and all nine check IDs once each. Any `not_run` check then needs an explanation. Schema validity checks completeness and shape; it does not establish that the reported observations are true.
