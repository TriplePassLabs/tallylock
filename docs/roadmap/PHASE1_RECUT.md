# Phase 1: the neutral scoreboard (rewrite, 2026-11-07)

Status: planning draft, not implemented. This replaces the eight-feature Phase 1 in ROADMAP.md. It was rewritten after the competitor validation (.planning, summarized below) showed that run wrappers, pre-registration and Merkle-plus-timestamp receipts already exist in small open-source tools. Product: TallyLock. Package and command: `tallylock`.

## Positioning

TallyLock is the neutral scoreboard for AI evaluation claims. It checks receipts from any tool, counts every attempt, corrects "best of N" scores, and publishes a board where only checkable results appear. It also makes its own receipts, but that is the entry point, not the pitch.

One line: **Lock the plan. Tally every run. See the real score.**

Why this position is open (checked 2026-11-07): K-Veritas, proofbundle, falsify (PRML) and NoCherry each ship part of the receipt layer, and none has more than 15 GitHub stars. None corrects scores for attempts, none runs a receipts-only leaderboard, and none verifies other tools' receipts. Each depends on its own key, server or format. A neutral lab can sit above all of them.

What a TallyLock result proves: the declared plan, attempts and outputs existed by a stated time and have not changed, and the score shown accounts for every recorded attempt. What it does not prove: honest execution, the model used, or that no attempts happened outside any recording tool. Every result states this once, plainly.

## Phase 1 scope

Six items in build order. Each has a check that must pass before it counts as done.

1. **Install in one line, verify in plain words.** Publish to PyPI with trusted publishing (signed provenance included). Bare `tallylock verify RECEIPT` reports what it checked in plain language, exits 0 on integrity success and says "timestamp: not checked" with the next command. `tallylock doctor` catches the wrong interpreter, PATH shadowing and pending proofs. JSON is the default when output is piped or `--json` is given.
   Verify: on a clean Linux machine, `pipx install tallylock` and `uvx tallylock --version` work. A new user's first `verify` never exits 3. Agent-contract tests pin JSON fields and exit codes.

2. **Attempt ledger with fast and permanent timestamps.** `tallylock run --plan PLAN -- <command>` runs the user's own command, records exit code, duration, environment summary and outputs, and appends the attempt, including failures, to the plan's ledger. Each ledger update gets an RFC 3161 timestamp (seconds) and an OpenTimestamps submission (Bitcoin, hours). After a ledger state is anchored, dropping or editing an earlier attempt is detectable. TallyLock never runs a model or scorer named inside a receipt.
   Verify: three runs with one failure give "3 of 3 attempts". Removing an anchored attempt fails verification with a distinct message. Two TSAs are supported with no silent fallback.

3. **Timestamp checks without a Bitcoin node.** `verify --online` fetches the anchoring block header plus the next 100 headers (about 8 KB), checks proof-of-work and chain links locally, and cross-checks the tip with two providers (Blockstream Esplora and mempool.space). Freshness only matters below the confirmation threshold.
   Verify: real receipts pass. A forged header, a broken link, disagreeing providers and malformed replies each fail with a distinct message. `--offline` makes no network calls.

4. **Attempt-adjusted scores.** `tallylock score LEDGER` reports the best score, the mean, and a corrected estimate with an interval that accounts for the number of attempts. The correction method is fixed in the plan before any run. It is documented in a short methods note, intended as a Colony Zero companion paper.
   Verify: a simulation study with known true scores shows the 95% interval covers the truth at least 90% of the time for 1 to 50 attempts. The corrected score never exceeds the best observed score. The method and code are pinned in the receipt.

5. **The hub, first adapters.** TallyLock reads and labels evidence from other tools instead of replacing them. Phase 1 ships three adapters:
   - Inspect AI eval logs, imported as attempts. They are unsigned, so they are labeled "declared".
   - proofbundle bundles, checked and labeled by what they actually prove.
   - in-toto/DSSE export of TallyLock receipts, so cosign and `gh attestation verify` can check the signature layer.
   Every imported item carries a trust label: anchored, signed, or declared only. falsify (PRML) and K-Veritas adapters follow in Phase 2, after reading their specs in full.
   Verify: real sample files from each upstream release round-trip. Tampered inputs are rejected. Trust labels match what each source can prove. No adapter imports its upstream package at verify time.

6. **Receipts Board v1 and agent access.** `tallylock board build REGISTRY` turns a public git registry of receipts into a static page for the existing site at triplepasslabs.com/tallylock. Each entry shows the claim, best score, attempts, adjusted score, trust label and a re-check command. `tallylock capabilities --json` and a packaged agent guide let any AI assistant drive the CLI and add entries.
   Verify: the board builds offline. Every entry re-verifies from the registry alone. Hostile strings are escaped. A headless screenshot passes visual review before the page goes live. Deployment to the site needs Chris's approval at that time.

Also required in Phase 1: SECURITY.md with a private reporting address, a `requires-python` upper bound matching tested versions, and a public comparison page covering K-Veritas, proofbundle, falsify and NoCherry fairly.

## Moved out of Phase 1

- Existing-node attachment (F04), named multi-profile management (F02 beyond one config file), managed Bitcoin node (F19), bundles, HTML reports and lifecycle tooling move to later phases.
- Sealed test sets and beacon-chosen seeds become adapters or features after Phase 1, since NoCherry and others already cover them.
- Before 1.0, only receipt IDs and canonical core bytes are frozen. Report, config and evidence formats may change.

## Phase 1 exit test

1. Five people who publish evals, none from TriplePass, each go from a clean Linux machine to a run, timestamped and verified receipt with an adjusted score in under five minutes, install included, with no help. At least 4 of 5 succeed and can say what the result does and does not prove.
2. The Receipts Board shows at least 10 entries from at least 3 sources, including at least one entry from outside TriplePass and at least one imported from another tool.
3. The 2026-11-02 kill rule still applies: within 60 days of the Phase 1 release, at least 10 outside repositories use TallyLock and at least 1 organization asks for witness runs. Otherwise TallyLock stays a credibility tool for the lab rather than a product bet.

## Running alongside the build

- Read the proofbundle and falsify specs and code in full before building adapters, and contact both maintainers about interoperability.
- Ten conversations with eval researchers and benchmark maintainers. Land one design partner.
- Dogfood: the next Colony Zero experiment runs through TallyLock and becomes the board's first entry. The episode shows the lock, the runs and the adjusted score.
- Draft the methods note for attempt-adjusted scores.

## Rough size

6 to 8 weeks of agent-assisted build time. Item 4 (the statistics and simulation study) and item 5 (adapters against real upstream files) carry the most uncertainty. This is an estimate, not a measurement.
