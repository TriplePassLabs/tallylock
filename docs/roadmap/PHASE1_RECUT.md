# Phase 1: the neutral scoreboard (revised 2026-11-07)

Status: planning draft, not implemented. This replaces the eight-feature Phase 1 in ROADMAP.md. It was rewritten after competitor validation showed that run wrappers, pre-registration and Merkle-plus-timestamp receipts already exist in small open-source tools, then revised the same day for simplicity and three reader questions. Product: TallyLock. Package and command: `tallylock`.

## Positioning

Every reader of an AI result asks three questions:
1. How many tries did it take?
2. Is the difference just noise?
3. Is it comparable to the other numbers?

TallyLock answers all three in one line, for example: **"74.0 best of 14 runs, adjusted 71.2 ± 1.1, tied with model B, same benchmark version."** That line is the product. TallyLock is the neutral scoreboard that produces it. It checks receipts from any tool, counts every attempt, corrects best-of-N scores, flags noise and mismatched setups, and publishes a board where only checkable results appear.

One line: **Lock the plan. Tally every run. See the real score.**

Why this position is open (checked 2026-11-07): K-Veritas, proofbundle, falsify (PRML) and NoCherry each ship part of the receipt layer, and none has more than 15 GitHub stars. None corrects scores for attempts, none runs a receipts-only leaderboard, and none verifies other tools' receipts. Each depends on its own key, server or format.

Who drives adoption: the people checking results, not the authors. Authors who cherry-pick gain nothing from adopting this. Reviewers, journalists, model buyers and leaderboard maintainers do gain, so TallyLock serves them directly, and their demand pulls authors in.

What a result proves: the declared plan, attempts and outputs existed by a stated time and have not changed, and the score shown accounts for every recorded attempt. What it does not prove: honest execution, the model used, or that no attempts happened outside any recording tool. Every result states this once, plainly.

## Simplicity rules

- One command to start: `tallylock run -- python eval.py`. No plan file is required. On the first run, the git commit plus the eval config files become the locked plan. A changed config starts a new plan automatically, and the old ledger stays visible.
- The ledger lives in the repo, in a `.tallylock/` folder. An optional GitHub Action timestamps it on each push.
- Every result prints a paste-ready claim line for papers, model cards and READMEs, with the receipt link built in. The honest number is the easiest one to copy.
- Users only see "timestamped" and "checked". Bitcoin, Merkle trees and OpenTimestamps stay in the docs and `--json` output.

## Phase 1 scope

Seven items in build order. Each has a check that must pass before it counts as done.

1. **Install in one line, verify in plain words.** Publish to PyPI with trusted publishing (signed provenance included). Bare `tallylock verify RECEIPT` reports what it checked in plain language, exits 0 on integrity success and says "timestamp: not checked" with the next command. `tallylock doctor` catches the wrong interpreter, PATH shadowing and pending proofs. JSON is the default when output is piped or `--json` is given.
   Verify: on a clean Linux machine, `pipx install tallylock` and `uvx tallylock --version` work. A new user's first `verify` never exits 3. Human output contains no Bitcoin or Merkle vocabulary. Agent-contract tests pin JSON fields and exit codes.

2. **One-command attempt ledger.** `tallylock run -- <command>` runs the user's own command and records exit code, duration, seed when declared, environment summary and outputs. It appends the attempt, including failures, to the git-native ledger. Each ledger update gets an RFC 3161 timestamp (seconds) and an OpenTimestamps submission (Bitcoin, hours). After a ledger state is anchored, dropping or editing an earlier attempt is detectable. TallyLock never runs a model or scorer named inside a receipt.
   Verify: in a fresh git repo with no plan file, three runs with one failure give "3 of 3 attempts". Changing a config file starts a new plan and keeps the old one visible. Removing an anchored attempt fails verification with a distinct message. Two TSAs are supported with no silent fallback.

3. **Timestamp checks without a Bitcoin node.** `verify --online` fetches the anchoring block header plus the next 100 headers (about 8 KB), checks proof-of-work and chain links locally, and cross-checks the tip with two providers (Blockstream Esplora and mempool.space). Freshness only matters below the confirmation threshold.
   Verify: real receipts pass. A forged header, a broken link, disagreeing providers and malformed replies each fail with a distinct message. `--offline` makes no network calls.

4. **The real score: adjustment, noise and the claim line.** `tallylock score` reports the best score, the mean, a corrected estimate with an interval that accounts for the number of attempts, and the spread across seeds. It prints the claim line. The correction method is fixed in the plan before any run and documented in a short methods note, intended as a Colony Zero companion paper.
   Verify: a simulation study with known true scores shows the 95% interval covers the truth at least 90% of the time for 1 to 50 attempts. The corrected score never exceeds the best observed score. The claim line round-trips: `tallylock check` on a pasted line finds and verifies its receipt.

5. **Compare: is it apples to apples?** `tallylock compare A B` reports whether two results used the same dataset version (by content hash), prompt template, decoding settings, harness version and attempt count. It also says whether the gap is larger than the combined noise. Mismatches are listed in plain words, and results are never ranked across a mismatch.
   Verify: fixtures that differ in exactly one setting are each flagged with the right reason. A gap inside the noise is reported as "statistically tied". Identical setups compare clean.

6. **The hub and the checker.** TallyLock reads and labels evidence from other tools, and serves the people checking results.
   - Adapters: Inspect AI eval logs imported as attempts (unsigned, labeled "declared"); proofbundle bundles, checked and labeled by what they prove; in-toto/DSSE export of TallyLock receipts, so cosign and `gh attestation verify` can check the signature layer. falsify (PRML) and K-Veritas adapters follow in Phase 2, after reading their specs in full.
   - `tallylock check <repo, receipt or claim line>` returns a plain verdict for reviewers, journalists and buyers, including "unverifiable: no attempt record" when nothing is found.
   - A short "receipt request" paragraph that a reviewer can paste into a review.
   Verify: real sample files from each upstream release round-trip. Tampered inputs are rejected. Trust labels (anchored, signed, declared only) match what each source can prove. No adapter imports its upstream package at verify time. `check` gives a correct verdict on each fixture class.

7. **Receipts Board v1 and agent access.** `tallylock board build REGISTRY` turns a public git registry of receipts into a static page on the existing site at triplepasslabs.com/tallylock. Each entry shows the claim line, trust label and a re-check command. Entries within noise are grouped as ties, and entries with mismatched setups carry a warning instead of a rank. `tallylock capabilities --json` and a packaged agent guide let any AI assistant drive the CLI and add entries.
   Verify: the board builds offline. Every entry re-verifies from the registry alone. Ties and mismatch warnings match `compare`. Hostile strings are escaped. A headless screenshot passes visual review before the page goes live. Deployment to the site needs Chris's approval at that time.

Also required in Phase 1: SECURITY.md with a private reporting address, a `requires-python` upper bound matching tested versions, and a public comparison page covering K-Veritas, proofbundle, falsify and NoCherry fairly.

## Build order and demand gate

Decision, Chris, 2026-11-07: the slice (items 1, 2 and 4) shipped as tallylock 0.1.0a1 on PyPI. Chris chose to build all of Phase 1 now without waiting on the demand test. The gate below is kept for the record and is waived. The 60-day kill rule in the exit test still applies after the Phase 1 release.

Original recommendation:

1. **Two-week slice:** items 1, 2 and 4 (install, one-command ledger, the real score and claim line). Then run the next Colony Zero experiment through it. This gives the lab checkable results and a publishable methods note on its own.
2. **Demand test during the slice:** contact 10 eval researchers, the proofbundle and falsify maintainers, and at least one benchmark or leaderboard maintainer. Before claiming novelty, check whether `compare` and noise-floor ties already exist in eval harnesses (lm-eval, for example, already reports standard errors).
3. **Gate:** if at least 3 contacts say they would use it, or one leaderboard or venue shows interest, build items 3, 5, 6 and 7. If not, stop at the lab tool and the paper.

## Moved out of Phase 1

- Existing-node attachment (F04), named multi-profile management (F02 beyond one config file), managed Bitcoin node (F19), bundles, HTML reports and lifecycle tooling move to later phases.
- Sealed test sets and beacon-chosen seeds become adapters or later features, since NoCherry and others already cover them.
- Before 1.0, only receipt IDs and canonical core bytes are frozen. Report, config and evidence formats may change.

## Phase 1 exit test

1. Five people who publish evals, none from TriplePass, each go from a clean Linux machine to a timestamped, verified result with a claim line in under five minutes, install included, with no help. At least 4 of 5 succeed and can say what the result does and does not prove.
2. Two people who check results (a reviewer, journalist, buyer or leaderboard maintainer) use `check` and `compare` on real claims and say the verdicts were useful.
3. The Receipts Board shows at least 10 entries from at least 3 sources, including one from outside TriplePass and one imported from another tool.
4. The 2026-11-02 kill rule still applies: within 60 days of the Phase 1 release, at least 10 outside repositories use TallyLock and at least 1 organization asks for witness runs. Otherwise TallyLock stays a credibility tool for the lab.

## Running alongside the build

- Read the proofbundle and falsify specs and code in full before building adapters, and contact both maintainers about interoperability.
- Land one design partner from the demand test.
- Dogfood: the next Colony Zero experiment becomes the board's first entry. The episode shows the lock, the runs and the real score.
- Draft the methods note for attempt-adjusted scores and noise ties.

## Rough size

The two-week slice is about 2 weeks of agent-assisted build time. The full Phase 1 is about 7 to 9 weeks. Items 4, 5 and 6 carry the most uncertainty. These are estimates, not measurements.
