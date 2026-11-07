# TallyLock flagship roadmap proposal

Status: proposed design for review. Chris requested design and roadmap only at this stage. These documents do not implement new commands, authorize a Bitcoin download or mark the existing stronger audit complete.

Recommendation: install one small CLI, then choose a verification profile. Use a public service for convenient timestamp checks, attach an existing Bitcoin node for stronger independently selected evidence, or stay offline. Creating a new node is a separate advanced option with a resource plan and explicit start. Setup shows the chosen paths and offers customization; the package manager owns the program's installation location.

Public-source checks trust the named service's Bitcoin view. Running a node has substantial synchronization and maintenance costs. Both preserve the same receipt format and remain explicit choices. Ordinary installation never requires a Bitcoin-history download.

Start with the [short user overview](NOVICE_OVERVIEW.md), then read the [full design](DESIGN.md), [phased roadmap](ROADMAP.md) and [20-feature catalog](FEATURES.json). The [agent operating guide](AGENT_GUIDE.md) distinguishes commands available today from proposed discovery/setup commands. It is not an active root AGENTS.md instruction file.

The [website plan](WEBSITE_PLAN.md) recommends a proposed `triplepasslabs.com/tallylock` product page and reciprocal GitHub links. GitHub remains the canonical technical documentation and release source. The website helps people discover TallyLock; the CLI never requires that website to run.

| Phase | User outcome | Feature count |
| --- | --- | --- |
| 1 | Easy setup, clear trust choices, online checks, readable results and AI instructions | 8 |
| 2 | Resume work, share receipts and manage evidence safely | 6 |
| 3 | Compare results, disclose declared attempts and integrate with pipelines | 5 |
| 4 | Optional managed Bitcoin node and additional OS qualification | 1, plus platform follow-through |

## Feature portfolio

Each catalog entry records existing foundations, new behavior, user value, acceptance checks, dependencies, risks and a release cutline. Existing Merkle proofs and JSON output are not counted as new features by themselves.

| ID | Feature | Phase |
| --- | --- | --- |
| F01 | Qualified installation and setup wizard | 1 |
| F02 | Named verification profiles and typed configuration | 1 |
| F03 | Public-provider timestamp verification | 1 |
| F04 | Guided existing-node attachment | 1 |
| F05 | Trust-aware doctor and actionable status | 1 |
| F06 | Agent discovery and operating contract | 1 |
| F07 | Resumable timestamp jobs | 2 |
| F08 | Safe portable receipt bundles | 2 |
| F09 | Rich shareable local evidence reports | 2 |
| F10 | Evidence refresh and audit export | 2 |
| F11 | Local project registry and bounded batch work | 2 |
| F12 | Receipt comparison with semantic limits | 3 |
| F13 | Declared attempt and disclosure accounting | 3 |
| F14 | Generic reproducibility templates and preflight | 3 |
| F15 | Optional issuer signatures | 3 |
| F16 | Independent compatibility and adversarial corpus | 1 |
| F17 | Verifiable releases and dependency provenance | 1 |
| F18 | Bounded CI workflow integration | 3 |
| F19 | Optional managed pruned Bitcoin Core | 4 |
| F20 | Transparent data lifecycle and recovery | 2 |

The five-minute setup and pilot-completion measures are targets, not measured results. Linux/Python3.11-3.13 is the currently qualified platform. The first useful alpha does not wait for all twenty features or managed-node installation.

Current implementation instructions remain in the [quickstart](https://github.com/TriplePassLabs/tallylock/blob/02f7c642ea17748e0cb8637b2e7a56a59f0959bd/docs/QUICKSTART.md). The [current protocol](https://github.com/TriplePassLabs/tallylock/blob/02f7c642ea17748e0cb8637b2e7a56a59f0959bd/docs/PROTOCOL.md) remains in force until an explicitly approved revision replaces a contract. Proposed commands and public-provider verification in these design documents are not available in the frozen0.1.0a1 runtime.

Design reviewed with GPT-6 Astra and the main session on2026-11-07. The proposal retains immutable receipts and the offline verifier; implementation requires the agreed next phase's detailed contracts and tests.
