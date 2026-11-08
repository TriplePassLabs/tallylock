# TallyLock

**Lock the plan. Tally every run. See the real score.**

When someone shares an AI evaluation result, readers ask three things. How many tries did it take? Is the difference just noise? Is it comparable to the other numbers? TallyLock records every attempt, including failures, and answers all three in one claim line that anyone can recheck:

```text
0.742 best of 14 runs; adjusted 0.712 ± 0.011 (95% CI, 12 completed, 2 failed); plan 3f2a9c1d (1 of 3 in repo); ledger 9b1e04aa; tallylock check
```

Free and open source (Apache-2.0). Built by [TriplePass Labs](https://triplepasslabs.com/tallylock/). Created and maintained by [Christopher Ayers](https://github.com/BrianBoitano).

[Product page](https://triplepasslabs.com/tallylock/) · [PyPI](https://pypi.org/project/tallylock/) · [Releases](https://github.com/TriplePassLabs/tallylock/releases) · [GitHub organization](https://github.com/TriplePassLabs)

## Install

```sh
pipx install tallylock        # or: uv tool install tallylock
tallylock --version
```

Version `0.1.0a4` is an alpha for Linux with Python 3.11 through 3.14, published with trusted publishing and signed provenance. On Windows, use WSL or a Linux container: commands that write files need Linux, and `tallylock doctor` says so. For offline installs from a reviewed wheel or source checkout, see the [quickstart](docs/QUICKSTART.md). On Ubuntu or Debian, a plain venv needs the matching venv package, for example `python3.12-venv`.

## Record every run

Run it inside a git repository. Your eval prints a line such as `tallylock: score=0.74` so TallyLock can read the score.

```sh
tallylock run --repeat 5 -- python eval.py --seed {seed}   # records every attempt, failures included
tallylock score                                            # best score, real score with its 95% interval, claim line
tallylock check "<claim line>"                             # anyone recomputes it from the ledger
```

The first run locks the plan: the commit, the command and the config files. Changing any of them starts a new plan, and the old one stays visible. The ledger lives in `.tallylock/`. Commit it when you want others to check your claim. `run` exits with your command's own exit code, so a failing eval still fails your CI.

Each ledger update gets an instant RFC 3161 timestamp from two public services and a Bitcoin timestamp through OpenTimestamps a few hours later. `tallylock refresh` finishes pending proofs. See [the quickstart](docs/QUICKSTART.md#record-every-run-and-get-the-real-score) and [the method](docs/METHODS.md).

## More commands

- `tallylock compare A B` says whether two results used the same dataset, harness, prompt and decoding settings, and whether the gap is just noise. It never ranks across a mismatch.
- `tallylock verify RECEIPT --online` and `tallylock check --online` check Bitcoin timestamps without running a node. The block and the blocks after it are checked against Bitcoin's real difficulty, and two public services must agree.
- `tallylock export`, `registry` and `board` publish a static Receipts Board where every entry is rechecked.
- `tallylock adapters import` reads Inspect AI logs and proofbundle files. `tallylock export --format intoto` writes statements cosign can sign.
- `tallylock capabilities --json` and `tallylock agent-guide` let AI assistants drive the CLI safely.

Output is plain language on a terminal and one JSON object per line when piped. Force either with `--human` or `--json`. Exit codes: 0 success, 2 invalid input, 3 insufficient evidence, 4 unsupported evidence, 5 operational failure, 130 interrupted. See [how it compares](docs/COMPARISON.md) to other tools and the [receipt request](docs/RECEIPT_REQUEST.md) paragraph for reviewers.

## Receipts for any output files

TallyLock can also freeze a plan and ordinary output files into a standalone receipt that verifies offline:

```sh
tallylock init --out manifest.json --name "My evaluation"
tallylock pre-register manifest.json --receipt receipt
mkdir outputs
printf 'ordinary external output\n' > outputs/result.txt
tallylock seal receipt --artifacts outputs
tallylock verify receipt
```

Run your evaluation yourself and pass its output directory to `seal`. TallyLock never launches a model or runs a scorer named in a receipt. Anchoring is explicit: `tallylock anchor receipt`, then `tallylock upgrade receipt` as calendars confirm. Plain `verify` checks integrity offline and reports the timestamp as not checked. Add `--online` to check it against public block headers, or `--policy anchored --chain-cache FILE` to check against your own node's data. See [generic integration](docs/INTEGRATION.md) for score and trace options, reports and recovery.

## What a result proves

It proves that the plan, the attempts and their outputs existed by a stated time and were not changed later, and that the score counts every recorded attempt. It does not prove that the evaluation ran honestly, which model was used, or that no attempts happened outside the tool. TallyLock records evidence. It does not certify results.

## Documentation

- [Quickstart](docs/QUICKSTART.md) and [method](docs/METHODS.md)
- [Protocol](docs/PROTOCOL.md), [threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md)
- [Comparison with other tools](docs/COMPARISON.md) and [sources](docs/SOURCES.md)
- [Roadmap](docs/roadmap/README.md): Phase 1 is built ([Phase 1 plan](docs/roadmap/PHASE1_RECUT.md)). Later phases are proposals.
- [Readiness audit](docs/READINESS.md), [acceptance tests](docs/ACCEPTANCE.md), [project plan](PLAN.md) and [review log](docs/reviews/REVIEW_LOG.md)

## Name and license

TallyLock was named Prove until 2026-11-07. Protocol v1 wire identifiers keep their original `prove.` prefix (for example `prove.manifest.v1`), and receipts keep their `.prove/` state directory, so existing receipt IDs and timestamps stay valid.

Licensed under [Apache-2.0](LICENSE). Copyright 2026 Christopher Ayers.
