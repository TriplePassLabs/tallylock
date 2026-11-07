# Phase 1 re-cut (draft, 2026-11-07)

Status: planning draft. Chris approved the critique's recommendations on 2026-11-07. This replaces the eight-feature Phase 1 in ROADMAP.md now that the name is chosen: TallyLock (Chris, 2026-11-07). Package and command: `tallylock`. Nothing here is implemented yet.

## Product thesis

TallyLock is for anyone who publishes AI evaluation or benchmark results. The pain: nobody trusts a single best number, because nobody can see how many runs were tried or whether the plan changed after the results came in. The promise: lock the plan before the run, count every attempt automatically, and hand readers a receipt they can check themselves in seconds, with no account and no trust in TriplePass Labs.

One line: **Lock the plan. Count every run. Let anyone check.**

What a receipt proves: the plan and outputs existed by a certain time and have not changed since, and the receipt shows every declared run. What it does not prove: that the code ran honestly, which model was used, or that no runs happened outside the tool. That limit appears once, plainly, in every human-readable result.

## Phase 1 scope

Six items, in build order. Each has a check that must pass before it counts as done.

1. **Rename and publish.** Rename the package, the command and the repository. Publish to PyPI with trusted publishing, which brings signed provenance attestations.
   Verify: on a clean Linux machine, `pipx install tallylock` and `uvx tallylock --version` work with no wheel path. The command name does not collide with any Debian, Ubuntu or Homebrew command. The PyPI page shows attestations.

2. **Friendly default verify.** Bare `tallylock verify RECEIPT` checks what it can and says so in plain words. Integrity success exits 0, and the output says "timestamp: not checked" with the exact next command. The strict anchored policy moves behind an explicit flag. Human-readable output is the default in a terminal. JSON is the default when output is piped or `--json` is given.
   Verify: a new user's first `verify` on a fresh receipt never exits 3. Agent-contract tests confirm the JSON fields and exit codes for every policy.

3. **`tallylock run` plus the attempt ledger.** `tallylock run --plan PLAN -- <command>` locks the plan (if it is not already locked), runs the user's own command the way `time` does, and captures the command line, environment summary, exit code, duration and output directory. It then seals the result and appends the run to the plan's attempt ledger. Failed and abandoned runs are recorded too. TallyLock still never runs a model or scorer named inside a receipt. It only runs the command the user typed.
   Verify: three runs, one of them failing, produce a ledger showing 3 of 3 attempts. Deleting or editing any run's receipt breaks verification. Hidden runs outside the tool are listed as a stated limit.

4. **Instant timestamp, then Bitcoin.** At seal time, request an RFC 3161 timestamp from a free public timestamp authority (seconds) and an OpenTimestamps submission (Bitcoin, hours). Verification reports both. The Bitcoin proof upgrades on the next `verify --online` or `upgrade`.
   Verify: a receipt shows a checkable timestamp within 10 seconds of sealing. Two different TSAs are supported, with no automatic silent fallback. Offline verification of the RFC 3161 token works against a bundled or user-selected certificate chain.

5. **Provider verify with proof-of-work.** `verify --online` fetches the anchoring block header and the next N headers (default 100, about 8 KB). It checks proof-of-work and the chain links locally, and cross-checks the tip with two independent providers (initially Blockstream Esplora and mempool.space). The result states: proof-of-work checked, N blocks on top, two providers agreed, full consensus not validated. Freshness matters only below the confirmation threshold.
   Verify: real receipts pass. Tests reject a forged header with invalid proof-of-work, a broken chain link, disagreeing providers and malformed replies, and each rejection has a distinct message. Offline mode makes no network calls.

6. **Agent guide and doctor, minimum version.** `tallylock doctor` diagnoses install problems, wrong interpreter, PATH shadowing and pending proofs. `tallylock capabilities --json` and a packaged agent guide let any AI assistant drive the CLI.
   Verify: a scripted consumer completes lock, run, verify using only `capabilities` output. `doctor` detects a shadowed command on PATH.

Also in Phase 1, small but required: SECURITY.md with a private reporting address, `requires-python` upper bound matching the tested versions, and a status banner instead of repeated disclaimers in public docs.

## Moved out of Phase 1

- F04 existing-node attachment moves to Phase 2. The existing RPC export path stays as an advanced option.
- F16 adversarial corpus shrinks to the existing conformance vectors plus the new forged-header cases in item 5.
- F17 release provenance is covered mostly by PyPI trusted publishing.
- Profiles (F02) shrink to a single optional config file. Named multi-profile management waits for real demand.
- Compatibility promises: before 1.0, only receipt IDs and canonical core bytes are frozen. Report, config and evidence formats may change.

## Phase 1 exit test

Five people who publish evals, none of them TriplePass, each go from a clean Linux machine to a locked, run, timestamped and verified receipt in under five minutes, install included, with no help. Each can then say in their own words what the receipt does and does not prove. At least 4 of 5 must succeed.

## Running alongside the build

- Ten conversations with eval researchers and benchmark maintainers, with notes saved, and one design partner by the end of Phase 1.
- Dogfood: the next Colony Zero experiment is locked and run through TallyLock, and the episode ends on its verify badge (the badge itself is Phase 2).
- A one-page comparison with OSF/AsPredicted, the OpenTimestamps CLI, Sigstore Rekor and git signing.

## Phase 2 preview

Verify page and README badge, browser verifier on the product site, eval-tool plugins (pytest, lm-evaluation-harness, Inspect AI, GitHub Action), the public git registry of locked plans, resumable jobs, portable bundles and existing-node attachment.

## Rough size

3 to 5 weeks of agent-assisted build time for items 1 to 6. This is an estimate, not a measurement.

## Website

No separate website or domain (Chris, 2026-11-07). TallyLock gets a page on the existing site at https://triplepasslabs.com/tallylock, with GitHub as the canonical docs and release source.
