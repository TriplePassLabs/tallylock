# TallyLock roadmap proposal

Status: reviewable product roadmap, not an implementation plan or approval to deploy. Feature details and dependencies are in FEATURES.json. Every phase ends in a usable vertical slice; later phases are optional expansion, not prerequisites for the first public alpha.

| Phase | What the user gains | Features |
| --- | --- | --- |
| 1 | Install, choose a trust profile and check a receipt without a Bitcoin download | F01–F06, F16, F17 |
| 2 | Finish pending work, share readable receipts and recover/manage local evidence | F07–F11, F20 |
| 3 | Compare results, account for declared attempts and integrate with existing pipelines | F12–F15, F18 |
| 4 | Choose managed Bitcoin independence and use additionally qualified operating systems | F19, with F01/F20 platform follow-through |

The catalog has exactly twenty distinct features. Existing hashes, Merkle proofs and JSON output are foundations, not new entries by themselves.

Website discovery and reciprocal lab/GitHub links are cross-cutting distribution work under F01/F17, not another feature. See [WEBSITE_PLAN.md](WEBSITE_PLAN.md) for the proposed `/tallylock` landing page, canonical documentation ownership and release-link checks. Offline verification never depends on that website.

## Phase 1: A normal user can install and check a receipt

Features F01–F06, F16 and F17. Deliver the supported Linux wheel/source distribution, tested pipx/uv/venv instructions, setup profiles, explicit public-provider checking, existing-node attachment, local diagnostics, versioned agent interface and release provenance. F05 includes short plain-language verification summaries in phase 1 through proposed `--human`; legacy commands retain default JSON. Proposed `--human` and `--json` are mutually exclusive, with unchanged policy and exit semantics.

Sequence:

1. Freeze provider evidence, report, configuration and effective-policy contracts -> verify: adversarial review distinguishes provider trust from independently selected node evidence and preserves every offline invariant.
2. Build explicit acquisition plus pure-engine integration -> verify: real OTS proof/header round trip with recorded provider source; malformed/contradictory/orphan/stale evidence and network failures do not pass the selected policy.
3. Add setup and installation journeys -> verify: fresh capped Linux workers install a release artifact without source checkout and finish ordinary local/provider workflows; offline commands run with blocked network and no writes.
4. Add agent discovery, guides and diagnostics -> verify: a model-independent scripted consumer completes the same flow with no prompts, clean JSON, exact exit behavior and no secret leakage; novice `--human` output expresses the same policy/result/limits, and conflicting output flags fail before work.
5. Produce release assets and external-test packet -> verify: hashes, dependency inventory, provenance, installed vectors and reproducible feedback instructions correspond to the actual released bytes.

First-alpha cut line: the above works, real provider-backed evidence passes its declared lane, and limits are honest. No managed Bitcoin installer, bundle extraction, dashboard, scheduling daemon, new model integration or native Windows claim. The existing immutable receipt engine and manual anchor/upgrade flow suffice. Basic cancellation and bounded retry are required now; rich durable timestamp jobs are phase 2.

Strict G2 disposition must be explicit: retain the original validated-node experiment as open, while approving a separate provider-backed external-testing lane. Do not relabel it passed. Reuse frozen receipt data for compatibility tests, but any fresh experiment claiming a weaker launch rule needs a newly declared plan. Maintainer audit prerequisites are not ordinary-user setup tasks.

Acceptance targets, not observations: first local receipt within five active minutes after installation; no Bitcoin vocabulary needed for recommended setup; at least 4/5 unfamiliar pilot users complete it without intervention and explain what remains unverified. Collect elapsed setup/download/anchor-wait separately and fix concrete friction before broader release.

## Phase 2: Receipts are easy to finish, share and recover

Features F07–F11 and F20. Deliver durable timestamp work, safe portable bundles, explicit evidence refresh/export, rich shareable HTML/detailed local reports, a local project registry and data lifecycle controls. Basic plain-language CLI results already ship in phase 1; F09 expands presentation rather than postponing that essential experience.

1. Timestamp job journal and registry -> verify: restart and cancellation preserve cores and recover the last durable step without duplicate mutation or unbounded polling.
2. Bundle export/import -> verify: round-trip receipt IDs; zip-slip, symlink, duplicate path, case collision, decompression limits and oversized metadata are rejected before unsafe extraction. Chain evidence remains separately selected trust material.
3. HTML/text reports and evidence export -> verify: rendered report accurately reflects machine output; hostile HTML/scripts are escaped; no remote assets, tracking or embedded credentials; offline rendering needs no network.
4. Registry/batch/lifecycle -> verify: registry is reconstructible convenience, never verification authority; bounded workers preserve per-receipt outcomes; cleanup cannot remove durable evidence or receipts; uninstall/reinstall preserves user data.

Cut line: no web account, cloud hosting, automatic public upload or continually running service. Shareable HTML is a local artifact that the user chooses to publish. No browser automation is needed to verify a receipt, though visual acceptance tests inspect generated reports.

## Phase 3: Researchers and teams can compare and automate honestly

Features F12–F15 and F18. Deliver change comparison, declared attempt accounting, generic reproducibility templates, optional issuer signatures and bounded CI integration.

1. Comparison and attempt disclosure -> verify: compare compatible declared fields/artifact changes without inventing score equivalence; missing declared attempts are visible, while hidden off-schedule work remains unprovable.
2. Templates -> verify: examples cover ordinary files, tests, benchmarks and model-output artifacts without provider SDK imports; budget claims remain declared or derived only from supplied records.
3. Optional signatures -> verify: signing does not change sealed-core IDs; key possession is distinct from verified human identity; revoked/expired/untrusted signer states are explicit. Choose an established signature format in a separate reviewed design.
4. CI -> verify: untrusted fork inputs cannot access signing keys or execute receipt instructions; network and secrets are explicit; artifact outputs work independently of GitHub. No mandatory hosted action.

Cut line: no arbitrary scorer execution, model runner, research dashboard, automatic scientific conclusions or identity-verification business. An MCP adapter is deferred until real users show that the stable CLI is insufficient.

## Phase 4: Optional independence and broader platform support

Features F19 and the staged platform work in F01/F20. Deliver carefully bounded managed Core only after it earns a separate lifecycle/security review. Qualify macOS before advertising it; qualify native Windows only when filesystem guarantees can be implemented honestly. Do not treat successful Python import or WSL execution as native Windows support.

1. Managed-node planning without installation -> verify: exact version/provenance, resources, selected data path, bandwidth uncertainty and no automatic start are visible; unsupported hard caps fail explicitly.
2. Opt-in install/start/stop/resume -> verify: signature failure stops installation, disk pressure stops safely, interruption resumes, wallet is disabled, node listens only as configured, no attached service is touched.
3. Update/remove -> verify: no silent database downgrade; binary removal retains data; purge requires a separate explicit selection and cannot reach receipts or attached-node directories.
4. Platform qualification -> verify: the same adversarial filesystem, persistence, offline and machine-contract tests pass on actual OS workers before release labels change.

Cut line: no embedded custom Bitcoin consensus implementation, header/SPV subsystem or paid node reseller. Users can always choose the public profile or attach a node they already maintain.

## Architecture ownership and implementation boundaries

| Area | Existing surfaces retained | Proposed change boundary |
| --- | --- | --- |
| Receipt cores | canonical.py, merkle.py, store.py, current manifest/result schemas | No provider/setup-driven core format change |
| Verification | verify.py, anchors.py, chain.py | Pure checks stay offline/read-only; new typed external evidence and report versions |
| Acquisition | evidence.py, existing bounded HTTP/transport modules | Provider adapter and orchestration; no writer imports into pure verifier |
| CLI | cli.py | Setup/profiles/diagnostics/discovery and explicit online flags; avoid unnecessary broad refactor |
| Schemas | schema.py, data/schemas/protocol-v1.json | Separate config/evidence/report contracts; keep old wire readers |
| Agent documentation | New root AGENTS.md and packaged runtime guide | Contributor instructions separate from operational instructions; examples generated/tested from contracts |
| Optional node | New optional component after phase-4 review | No import/install/service dependency for core CLI |

Exact module filenames beyond current surfaces are design suggestions, to be frozen in each phase's implementation plan. Each feature's acceptance tests must exercise behavior rather than merely mirror implementation.

## Compatibility and rollback gates

- Preserve existing receipt IDs, core canonical bytes, inclusion semantics and OTS interoperability across every phase.
- Introduce separately versioned config/report/evidence/bundle/job envelopes. An unknown version returns unsupported, not guessed interpretation.
- Keep frozen-runtime test fixtures and installed-artifact compatibility checks. New reports require explicit format selection/version communication; existing JSON consumers get a migration path.
- Config migration is transactional with a readable backup; dry-run lists changes. Rollback reinstalls the previous package environment without deleting user data.
- A node database is not a Python package: rollback follows that exact Bitcoin Core version's compatibility guidance and is never automatic.
- Release only observed platform support. Pin dependencies and supported external tool versions in the release evidence; newer upstream versions are candidates for testing, not automatic upgrades.

## Success and stop rules

Track setup completion, time to first local receipt, correct trust comprehension, recovery success, provider outage behavior, agent contract compatibility and external-user defects. Record denominators and platform/version for every claim. Do not substitute downloads, feature count or green unit tests for observed user success.

Pause expansion if phase-1 users cannot explain TallyLock's extra value over hashes plus OTS, or if setup remains confusing. Simplify wording and workflow before adding node management or integrations. No subscriptions, dashboards, model runners or provider accounts are required to make a receipt useful.

Ready for review now: DESIGN.md, this roadmap and twenty-feature catalog. No implementation, deployment, node download or old-gate completion is implied by writing these documents.
