# TallyLock

TallyLock was named Prove until 2026-11-07. The command is `tallylock` and the package is `tallylock`. Protocol v1 wire identifiers keep their original `prove.` prefix (for example `prove.manifest.v1`), and receipts keep their `.prove/` state directory, so existing receipt IDs and anchored timestamps stay valid.

TallyLock freezes evaluation plans and ordinary output files into standalone receipts. Its Python CLI verifies byte integrity offline and separates that evidence from reported scores, model identity and execution claims. Developed by [TriplePass Labs](https://github.com/TriplePassLabs). Created and maintained by [Christopher Ayers](https://github.com/BrianBoitano).

[Lab website](https://triplepasslabs.com) · [GitHub organization](https://github.com/TriplePassLabs) · [Founder profile](https://github.com/BrianBoitano)

It binds an evaluation plan, recorded artifacts and reported results to commitments with optional OpenTimestamps evidence. Verification distinguishes artifact integrity from claims about execution, model identity, timing and scientific validity.

Version `0.1.0a1` is an unreleased implementation candidate for Linux with Python 3.11 through 3.13. Use a supported interpreter and install the reviewed wheel in its own environment. The example below selects Python 3.12; substitute your supported interpreter when needed.

On Ubuntu or Debian, that interpreter needs its matching venv package before environment creation. Ubuntu 24.04 users selecting Python 3.12 need `python3.12-venv`. The [offline quickstart](docs/QUICKSTART.md) gives the prerequisite and an optional fallback when `uv` is already installed. See the [Ubuntu Python setup guide](https://ubuntu.com/developers/docs/howto/python-setup/) and [package record](https://packages.ubuntu.com/noble/python3.12-venv).

```sh
python3.12 -m venv .venv-tallylock
. .venv-tallylock/bin/activate
python -m pip install /absolute/path/to/tallylock-0.1.0a1-py3-none-any.whl
tallylock --version
```

From a reviewed source checkout, `python -m pip install .` works in the same environment. Installation may fetch dependencies.

Install from PyPI: `pipx install tallylock` or `uv tool install tallylock`. Version 0.1.0a1 is published with trusted publishing and signed provenance. The wheel and source steps above still work for offline or reviewed installs. Distribution acceptance and release status are recorded in [the readiness audit](docs/READINESS.md).

The [offline quickstart](docs/QUICKSTART.md) uses only the installed CLI, a fresh manifest and an ordinary output directory. It needs no model, provider account, research checkout or hosted service. `python -m tallylock` can replace `tallylock` in every command.

```sh
tallylock init --out manifest.json --name "My evaluation"
tallylock pre-register manifest.json --receipt receipt
mkdir outputs
printf 'ordinary external output\n' > outputs/result.txt
tallylock seal receipt --artifacts outputs
tallylock verify receipt
```

Edit the manifest before preregistration. Run your external evaluation program yourself and pass its output directory to `seal`. TallyLock never launches a model or executes a scorer named in metadata. See [generic integration](docs/INTEGRATION.md) for explicit score/trace options, bounded reports and recovery.

Anchoring is explicit: `tallylock anchor receipt`, then `tallylock upgrade receipt` as calendars gain attestations. Submission and pending proofs are not completed anchoring. Plain `tallylock verify receipt` checks integrity and reports the timestamp as not checked, exiting 0 when integrity passes. With `--chain-cache FILE` it also runs the anchored check. `--policy anchored` is the strict form: it requires qualifying Bitcoin attestations and an explicitly selected local chain cache, and exits 3 without them. Verification never contacts a node or calendar. Independently assess the cache's provenance and freshness.

Output is one JSON object per stdout line when piped and a short plain-language summary on a terminal. Force either with `--json` or `--human` (not both). `tallylock doctor [RECEIPT]` checks the installation and a receipt's timestamp state without writing or using the network. Statuses are 0 for the requested action/check, 2 invalid input, 3 insufficient evidence, 4 unsupported evidence, 5 operational failure and 130 interruption. A returned timestamp action can still be pending or retry-wait. After optional anchoring fails, completed local state and IDs remain in the report. Resume with `anchor`/`upgrade` without the original outputs.

Static examples and canonical conformance assets ship under `tallylock/data/examples/basic` and `tallylock/data/conformance`, accessible through `importlib.resources`. Basic use requires no optional harness importer.

- [Project plan](PLAN.md): scope, protocol decisions, milestones and release gates.
- [Threat model](docs/THREAT_MODEL.md): attacks, defenses and remaining trust.
- [Acceptance tests](docs/ACCEPTANCE.md): tests required before implementation claims.
- [Sources and alternatives](docs/SOURCES.md): primary references and reuse decisions.
- [Review log](docs/reviews/REVIEW_LOG.md): critiques and their disposition.
- [Proposed flagship roadmap](docs/roadmap/README.md): setup choices, AI instructions and twenty staged features. Design for review; proposed commands are not implemented.

## License

Licensed under [Apache-2.0](LICENSE). Copyright 2026 Christopher Ayers.

## Record every run

```sh
tallylock run --repeat 5 -- python eval.py --seed {seed}
tallylock score
```

Every attempt is recorded, including failures. `score` reports the best result, the real score with its range, and a claim line others can check with `tallylock check`. See [the quickstart](docs/QUICKSTART.md#record-every-run-and-get-the-real-score) and [the method](docs/METHODS.md).

## What a receipt means

A valid completed timestamp establishes that a commitment existed by a Bitcoin block. Artifact hashes reveal changes to committed bytes. Neither establishes that an evaluator ran honestly, used the claimed model, disclosed all attempts, or produced a scientifically sound result.

TallyLock works alongside evaluation harnesses. A preregistration ID alone establishes no independently witnessed chronology. External research experiments remain separate from the protocol's cryptographic checks.
