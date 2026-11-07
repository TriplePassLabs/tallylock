# TallyLock website and distribution plan

Status: proposed, 2026-11-07. Planning only; no website changes, deployment, website publication or new service is authorized. This is a distribution/documentation extension of F01 and F17, not feature 21.

## Recommendation

Link in both directions. Create a branded product landing page at **https://triplepasslabs.com/tallylock**, with GitHub as the canonical technical documentation and release source. Keep TallyLock a recognizable standalone open-source project, described as “TallyLock, maintained by TriplePass Labs,” with Christopher Ayers's founder/maintainer credit and personal GitHub link preserved.

Use `/tallylock` rather than `tallylock.triplepasslabs.com` initially: one existing website, deployment and navigation system, without extra DNS/certificate/site operations. Reconsider a subdomain only if a substantial documentation site needs independent deployment. Neither option justifies a dashboard, account system or hosted verification API.

The lab benefits from a concrete public tool demonstrating its evidence philosophy. Users benefit from a clear explanation, a trustworthy route to the actual release and a short path to first use. Open-source participation must remain possible without becoming a lab customer. No nonprofit status, commercial support promise or pricing model is implied.

## Observed public state

The [current lab homepage](https://triplepasslabs.com/) already has a “TallyLock” principle section and links its research programs to GitHub. Separate the future product page from that broad principle. The [public repository view](https://github.com/TriplePassLabs/tallylock) already links back to the lab and credits the founder; the fetched view still describes a planned CLI. That may lag the local candidate, so release owners must reconcile public status before promoting installation.

On 2026-11-07, a direct HTTP HEAD request to the then-proposed `https://triplepasslabs.com/prove` returned HTTP 404 with no redirect. The product was renamed TallyLock the same day; its page will be `/tallylock`. The proposed route is currently absent; recheck routing before deployment. Do not link users to it as a live product page yet. PyPI publication and publicly downloadable candidate assets have not been established here.

## Visitor journey and page content

**Lab visitor → TallyLock landing page → GitHub quickstart/release → package-manager installation → `tallylock setup` → first local receipt → optional explicit online timestamp check.**

The page should contain:

1. Plain purpose: package a declared plan, outputs and results into a receipt that others can check. State that integrity/timestamps do not prove honest execution.
2. Current status and qualified platforms. Before a release, primary action is “View project and roadmap.” After assets are verified, use “Install TallyLock,” linking to the exact current release/quickstart. Never show a working-looking PyPI command before that package exists.
3. A short example and expected plain-language result, generated or imported from the matching repository documentation. Proposed commands remain visibly proposed until implemented.
4. Three trust choices: public service recommended, existing node optional, offline checks. New-node planning sits under advanced usage and explains large initial transfer, pruning limits and resource approval. No 600 GB prerequisite on the normal download path.
5. “Use with your AI assistant,” linking to the version-matched runtime agent guide and a copyable handoff prompt. This supplies instructions; it cannot guarantee assistants automatically load or execute them.
6. Links to source, verified release assets, docs, Apache-2.0 license and support. Add contributing/security-report links only after those documents and channels exist. Security reports must not be directed to public issues by default.

Add a product call to action beneath the homepage's existing TallyLock principle, plus a tools/products location when the site's information architecture supports one. Preserve the current Ouroboros and Colony Zero research links; this task does not migrate those programs. GitHub's README/About and later PyPI project metadata link back to the product page, with a separate lab link. Existing lab/org/founder links are partial foundations, not a new feature. Preserve founder credit at https://github.com/BrianBoitano.

## One source of truth and no runtime dependency

GitHub owns versioned installation instructions, command reference, trust model, compatibility, agent guide and release notes. The website owns the short product introduction and navigation. Avoid maintaining two independent quickstarts: link to the canonical one initially; later render a pinned repository excerpt with its version and source link. Distribution remains real GitHub release assets and, once published and verified, PyPI. Release badges must derive from actual releases/tests, never imply audited security, trustless execution or unsupported platform readiness.

CLI help may display the project URL locally. Proposed `about`, `docs` or `support` actions can print the relevant links; browser opening requires an explicit user action. No launch-time website request, update check, telemetry, account, website availability test or remote documentation dependency is required to verify offline. Public Bitcoin providers are named third parties, not disguised lab infrastructure. Local HTML reports contain no tracking or remote assets by default.

Use accessible semantic HTML, keyboard-visible links, descriptive titles, canonical URL, Open Graph metadata and a simple product image. Publish only accurate structured metadata and status. No analytics is added by this plan. Existing website analytics remain unassessed; any new analytics needs an explicit privacy/cost decision. Optional later sponsorship or support links cannot gate the Apache-2.0 CLI or promise a paid service before one is approved.

## Phased delivery and handoff

| Stage | Deliverable | Acceptance |
| --- | --- | --- |
| Planning now | This page specification and ownership decisions | Six proposed roadmap documents remain coherent; feature count stays twenty |
| Product alpha, F01/F17 | Landing page, reciprocal navigation, accurate status and installation links | Follow visitor journey from public page to actual installed artifact; verify all destinations and unsupported-platform wording |
| After release | Version-aware docs excerpts, release metadata and agent-guide link | Website instructions match released CLI; no fabricated downloads/badges; offline tests remain independent of website |
| Optional later | Sponsorship/support or separate docs site if justified | Explicit owner, maintenance plan, privacy/cost review and no core dependency |

Implementation handoff: inspect the existing website repository and `/tallylock` route; identify its deployment workflow; verify public repository/release/PyPI state; then propose the smallest website change using these requirements. Review an accessible rendered preview and link-check the actual release journey before deployment. No new paid software or hosting is planned; confirm the existing hosting arrangement before claiming zero incremental cost. This document does not authorize deployment or completion of TallyLock's still-open acceptance gates.
