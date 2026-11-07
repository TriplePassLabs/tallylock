# TallyLock receipt protocol v1

Naming note (2026-11-07): the product is now TallyLock. Protocol v1 format identifiers keep the historical `prove.` namespace and receipts keep the `.prove/` directory. These are wire names, not product names, and changing them would change receipt bytes and IDs.

Draft frozen for implementation review, 2026-11-06. Normative core version identifiers below are independent of package release numbers. The standalone CLI supports any producer of files and optional structured traces. No lab project or hosted TriplePass Labs service is part of this contract.

## Canonical data and identities

Protocol JSON is strict UTF-8 without a BOM, duplicate keys or lone surrogates. RFC8785 canonical bytes are used for core files and event leaves. Floats are rejected; safe integers are -9007199254740991 through 9007199254740991 inclusive, and counters/byte lengths are nonnegative. Decimal quantities belong in explicitly named decimal-string metadata fields. Boolean values are never accepted as integer counters. Maximum JSON depth is 64, core size 8MiB, one event 1MiB and total normalized records 64MiB. Proof parser input is capped at 16MiB with separate operation/depth limits. Exact limits are local parser policy; changing them does not change committed bytes.

The OTS timestamp-tree depth limit is 256 nodes, matching the pinned upstream decoder's default. Aggregate framing work is limited to100000 timestamp-node/attestation items. Framing, depth, work, byte and EOF checks precede operation evaluation. Calendar responses have a separate10000-byte cap. These timestamp-tree limits apply independently of JSON depth. The earlier64-node timestamp policy rejected standard live calendar replies and was corrected during interoperability testing.

Registration ID = lowercase SHA256 hex of canonical `manifest.json`. Receipt ID = lowercase SHA256 hex of canonical `result.json`. Cores must be stored in exact canonical bytes with no trailing newline. Detached OTS proofs timestamp those exact file bytes. Mutable proofs, local state, chain caches and verifier reports are excluded from receipt identity.

Unknown fields are rejected in every normative object. The explicitly non-normative `metadata` object may contain arbitrary values within the canonical profile. It is still hashed, but does not override protocol semantics. Required nullable fields must appear with JSON null when unknown; optional top-level normative fields are not used in v1.

## Manifest

All fields are required:

| Field | Type and meaning |
|---|---|
| `format` | Literal `prove.manifest.v1` |
| `nonce` | 16 random bytes as 32 lowercase hex characters; explicit fixed nonce is allowed only for conformance fixtures |
| `name` | Nonempty string, maximum 200 characters |
| `description` | String, maximum 4000 characters |
| `profile` | `artifacts-v1` or `trace-v1` |
| `attempts` | Nonempty array of `{id, sample_ids}`; unique attempt IDs and unique per-attempt sample IDs |
| `dataset` | `{name, sha256}`: string and nullable lowercase SHA256; digest pins exact bytes, not a remote URL |
| `model` | `{id, evidence, sha256}`: string identifier, one of self_declared/provider_metadata_recorded/weight_digest_recorded, nullable weight digest |
| `harness` | `{name, revision, config}`: two strings and canonical JSON object binding effective configuration |
| `generation` | `{prompt_sha256, parameters}`: nullable SHA256 and canonical JSON object |
| `scorer` | `{profile, revision}`: profile `recorded-only-v1` or `fixture-exact-v1`, revision string |
| `analysis` | `{revision, plan_sha256}`: string and nullable SHA256 |
| `budget` | `{max_calls, max_input_tokens, max_output_tokens}`: nonnegative safe integers or null |
| `stopping_rule` | String describing the declared rule, not independent evidence of enforcement |
| `metadata` | Explicit non-normative object |

Attempt, sample and call IDs match `[a-z0-9][a-z0-9_-]{0,63}`. Artifacts profile uses empty sample_ids. Trace profile requires at least one declared sample. The producer chooses whether to preregister multiple attempts; undeclared attempt IDs cannot be sealed against this manifest. This cannot reveal hidden evaluations. Model names and weight digests identify recorded claims/artifacts, not executed-model attestation.

Each selected attempt is sealed in its own receipt directory. Reuse the same frozen manifest bytes in separate directories to share a registration ID across attempts; do not overwrite one attempt's result with another. `pre-register MANIFEST --receipt RECEIPT` freezes one copy, and `seal RECEIPT --attempt ID` selects one of its declared attempts (the single declared ID may be the default). Directory names are user-chosen, not security identities. The CLI does not claim to enumerate every receipt issued for a registration.

`fixture-exact-v1` scoring is allowed only with trace-v1 and a non-null dataset digest. Artifacts-v1 uses recorded-only-v1. These are generic profile constraints, not a dependency on a named evaluation harness.

`weight_digest_recorded` requires a non-null model.sha256. All model evidence types remain operator-declared descriptions: a recorded digest does not prove execution with those weights, and a provider-metadata label does not authenticate a provider response.

`tallylock init` creates a domain-neutral manifest with one `run-1` attempt, artifacts-v1, recorded-only scoring, explicit unknown model/dataset digests and unknown budgets. The user edits/pins relevant evidence before `pre-register`. Defaults do not imply strong scientific preregistration; the report keeps unknowns visible.

## Layout and artifact inventory

Fixed normative files: `manifest.json`, `result.json` after sealing, and `records.jsonl` after sealing. Detached proofs live at `proofs/manifest.ots` and `proofs/result.ots`. Local non-normative state is confined to `.prove/`; that directory never supplies implicit trusted chain data or overrides core checks. Unknown receipt-root entries are rejected. Proof revision backups may exist only under `.prove/proof-history/`.

`artifacts/` holds exact input bytes under their original relative names. Result inventory keys are NFC-normalized Unicode POSIX paths; uppercase letters, interior spaces and Unicode names are supported, never silently lowercased or renamed. Reject empty/dot/parent components, repeated slashes, leading slash, backslash, NUL/control characters, trailing dot/space components, non-NFC input names, links, nonregular files and casefold/NFC collisions, including colliding directory prefixes such as A/x.txt versus a/y.txt. Reject ambiguous Windows drive-like colon components even on Linux. Maximum encoded path length is 1024 UTF8 bytes, with 255 bytes per component. Report rejected names explicitly so producers can choose an intentional export mapping; do not invent one. Each entry is `{sha256, bytes, media_type, role}`; strings for type/role, nonnegative byte count. The canonical mapping itself is embedded in the result. Full verification rejects unlisted or missing files beneath artifacts/. Inclusion verification never claims full availability.

Source artifacts are copied into a new immutable snapshot before finalization, not modified in place. Descriptor-relative no-follow access applies during both snapshot and verification, including parent directories. Compare file type/device/inode/size/time metadata before and after streaming and check exact count and digest. Core and proof reads have the same race protection. Fail closed on unsupported OS primitives; Linux is the initial supported runtime.

## Records and tree

records.jsonl consists of canonical event JSON followed by LF for each record. No blank lines, BOM, CRLF or trailing data. Its raw SHA256 and byte count are in result.json. Every record contains `{format, registration_id, attempt_id, index, kind}`; format is `prove.event.v1`, indices are contiguous from zero. Each record's canonical bytes excluding LF are a leaf. The RFC9162 SHA256 construction uses 0x00 leaf/0x01 internal prefixes, largest-power-of-two split rule and SHA256(empty) for the empty tree. Do not duplicate odd leaves. Tree size, root, proof index and exact sibling consumption are checked.

### Artifacts profile

For every inventory entry sorted by its UTF8 path bytes, generate one event with kind `artifact` and additional required `{path, sha256, bytes}` matching that entry. Finish with one `attempt_end` event. Artifacts-profile records.count is exactly inventory entry count plus one; an artifact event's index is its sorted inventory rank. This is an artifact inventory record, not an execution trace. Completed attempts require at least one artifact. Failed/aborted/budget-exceeded attempts may have no artifacts, with a reason. The generated final event ensures a normal seal still has a nonempty tree.

### Optional trace profile

The producer supplies normalized events through a local JSONL file; the CLI validates them and copies canonical records. Four kinds are supported:

- `sample_start`: additional `{sample_id}`. Exactly one start per started sample, declared in the attempt.
- `call`: additional `{sample_id, call_id, retry_of, source, status, input, output, usage}`. IDs are unique per attempt; retry_of is null or an earlier call in the same sample. Source is a descriptive string. Status is succeeded/failed/timeout/refused. Input/output are nullable inventory paths. Usage is `{input_tokens, output_tokens, reasoning_tokens, cached_tokens, duration_ms}` with nullable nonnegative safe integers. Missing provider data is null, never zero by default.
- `sample_end`: additional `{sample_id, status}` where status is completed/failed/skipped; requires its prior start and closes the sample. No calls after its end.
- `attempt_end`: additional `{outcome, reason}` where outcome is completed/failed/aborted/budget_exceeded, reason is nullable string. It is the final event. Completed requires every expected sample to have a terminal event. Other outcomes allow incomplete coverage with a nonempty reason.

Every record's registration_id and attempt_id must match the selected manifest/result binding. Calls require a previously started sample that remains open. No unknown fields, kinds, dangling artifact references, duplicate starts/ends, cross-attempt events or records after attempt_end. The terminal attempt_end outcome and reason must equal result.json exactly. A completed trace closes every expected sample; failed/aborted/budget-exceeded traces may leave samples open but must report incomplete coverage explicitly. Every nonempty trace ends with attempt_end, including unsuccessful attempts. Zero records are allowed only for a declared non-completed outcome with a reason, representing failure before normalized logging began. These checks establish consistency of supplied records, not completeness of actual execution history.

## Result

Required fields: `format` literal prove.result.v1; `registration_id`; `attempt_id`; `profile` matching manifest; `outcome`; nullable `reason`; `inventory`; `records` object `{path, sha256, bytes, count, tree_algorithm, root}` with fixed path records.jsonl and tree_algorithm rfc9162-sha256; `resources`; `score`; and `metadata` object. No operator clock is treated as trusted timing evidence; optional reported times belong in metadata.

Resources is `{calls, input_tokens, output_tokens, reasoning_tokens, cached_tokens, duration_ms}`. Artifacts-only resources are all null: hashing arbitrary files does not measure a model run. Trace call count equals supplied call records. Each other total is the sum if every call has that usage field, otherwise null. Empty call sets yield zero in trace mode. Also derive known subtotal lower bounds for each usage field, even when its full total is null. A known count/lower bound above a declared ceiling establishes exceeded: the producer must explicitly select budget_exceeded as the terminal and result outcome. Sealing rejects contradictory outcomes instead of silently rewriting them; verification reports invalid evidence (exit 2) for those contradictions. A correctly declared budget_exceeded receipt remains structurally valid and reports exceeded. Unknown usage never erases a known violation. If incomplete usage stays below a ceiling, compliance is unknown; complete recorded usage within every declared ceiling is recorded_within, never proof of actual call completeness. Artifacts-only budgets are unknown when any ceiling is declared; no ceilings yields not_declared.

Score is null when unavailable, otherwise `{path, sha256, bytes, profile, aggregate}`. It resolves to exactly one inventory entry with role score; copied digest/length match, and its profile equals manifest.scorer.profile. Aggregate is null or `{numerator, denominator}` using nonnegative safe integers and positive denominator. A score can be honestly sealed and mathematically false. Recorded-only scores are not recomputed. Completed fixture-exact attempts require a non-null complete score. Failed/aborted/budget-exceeded fixture attempts may omit the score and report unavailable; a supplied fixture score still must cover every declared sample and pass recomputation. Incomplete fixture results use null score rather than claiming a denominator over unobserved samples.

When a fixture score is supplied, the deterministic fixture scoring profile requires an inventory dataset entry whose bytes match the non-null manifest dataset digest. An unsuccessful null-score receipt may contain no artifacts at all if work failed before logging; do not require a missing dataset artifact merely to seal that honest failure. Dataset JSON is `{format:"prove.fixture-dataset.v1", samples:[{id, expected}]}`, with expected a UTF8 string and sample IDs equal the declared attempt. Score artifact JSON is `{format:"prove.fixture-scores.v1", samples:[{id, observed}], aggregate:{numerator, denominator}}`, observed a UTF8 string. Recompute exact string equality, count every declared sample once, compare both declared aggregates to correct/total. Fixture denominator equals the declared sample count and numerator cannot exceed it; store exact counts rather than a reduced fraction. This restriction is specific to fixture accuracy, not arbitrary recorded-only rational metrics. This checks the declared deterministic rule and pinned dataset, not the real-world correctness of labels or honest model execution. Generic production scorers stay recorded-only until separately reviewed.

Both fixture JSON objects and their sample entries are closed shapes: no unknown or missing fields, duplicate IDs or non-string expected/observed values. Each payload is bounded at8MiB and uses the strict JSON value rules, but artifact whitespace/key order need not be canonical because the original bytes are hashed. Sample array order may differ; identity is the unique declared sample ID. Compare strings exactly without Unicode normalization or case conversion. These fixture-only restrictions do not limit arbitrary recorded-only score artifacts. Recomputed fixture labels/observations remain producer-supplied claims and need not establish a link to actual model outputs.

## Policy and report

Report format prove.verification.v1 includes receipt/registration IDs, scope full|inclusion, policy anchored|integrity-only, selected attempt and outcome, artifact_integrity, record_integrity, score evidence, manifest_anchor, result_anchor, chain_view, model evidence, issuer_identity unverified, execution unverified, coverage and budget-compliance state, errors and limitations. No bare verified evaluation badge. Full integrity checks score recomputation when fixture-exact-v1 is selected; failures cannot disappear behind an anchor status.

Reports include the selected minimum_confirmations threshold. A rejected policy/threshold is null in the report rather than reflecting an arbitrary invalid input. Independent failures use deterministic precedence invalid2, operational5, unsupported4, insufficient3, success0; the presentation cap on error messages never changes that precedence. Reports omit oversized cache source/exported_at strings (over2048 characters) as null and identify them in chain_view.omitted_fields. This affects presentation only, never cache validation or proof checking. Integrity-only leaves proofs and chain data not_checked. Inclusion success is membership_checked, never a full record-consistency verdict.

| Evidence and selected policy | Exit |
|---|---|
| Required hashes/structure/membership and optional built-in score checks pass; both completed anchors meet selected chain policy | 0 anchored |
| Same local checks pass under explicit integrity-only; anchors reported unchecked | 0 integrity-only |
| Malformed core, wrong binding/hash/membership, wrong recomputed fixture score or contradictory declared data | 2 invalid |
| Valid local evidence but required proof pending/missing, or no explicit trusted chain cache | 3 insufficient |
| Unsupported format/profile/algorithm | 4 unsupported |
| I/O, lock, network or other operational failure | 5 operational |

Failure of an evaluation does not itself invalidate its receipt. Inclusions bind a supplied event, index, tree size/root and result/manifest commitments; they report artifacts and coverage not_checked. Invalid evidence outranks insufficient anchors. Verifier code performs no network requests, artifact fetching, imports of producer code or scorer execution. `inspect` is inventory/status presentation, not verification.

## Inclusion interchange

`tallylock proof create RECEIPT --index N --out FILE` emits canonical JSON with closed fields `{format, registration_id, receipt_id, manifest, result, event, index, size, siblings, proofs}`. Format is prove.inclusion.v1. Manifest/result are embedded parsed core objects whose canonical bytes reproduce the declared IDs; event is the complete canonical leaf object. Index/size are nonnegative safe integers, size equals result.records.count, index equals event.index, and both event bindings match the cores. Siblings is an array of lowercase 32-byte SHA256 hex strings consumed exactly by the RFC9162 verifier. Proofs is `{manifest, result}`, each null or base64 detached OTS bytes for the corresponding canonical core. The default JSON operation limit is 8MiB including embedded material; unusually large cores/proofs may require a future explicitly bounded larger inclusion policy, not an unbounded parse.

`tallylock verify --inclusion FILE` checks closed core/event schemas, IDs, selected attempt/profile, inventory and score binding shapes, membership and requested anchor policy. Included attempt_end must have index size-1; an included artifacts-profile artifact must occupy its inventory rank and match its entry. These contradictions are checkable from embedded data even without the full trace. It does not need records.jsonl or artifact files. It must report full-tree, trace-state-machine, actual resource totals, coverage and score recomputation not_checked. Even when a single artifact event matches its inventory entry, availability and whole-run consistency are not established. An inclusion check never emits a full record-validation verdict. Embedded OTS bytes are untrusted bounded data and cannot supply chain trust.

Conversely, an inclusion for the final position of a nonempty tree must contain attempt_end. This directly visible terminal contradiction is rejected even when its membership path and all supplied commitments are correct.

For trace inclusions, reject impossible visible positions and record-count declarations. The first nonterminal record must be sample_start; a retry call needs at least two earlier positions (sample_start and a prior call). A supplied call requires declared calls at least one, or at least two when retry_of is non-null. A completed trace needs at least one terminal, one position per declared call, and two positions per declared sample; an unsuccessful trace with calls needs at least one sample_start as well as its calls and terminal. A completed trace's included sample_start or call needs room afterward for sample_end and attempt_end. These are necessary plausibility bounds only. They do not validate unseen history, actual totals, budget compliance or coverage; those report dimensions remain not_checked.

## Persistence and anchors

Each selected attempt has a new receipt directory; multiple copies of the same frozen manifest may share a registration ID. Finalization is single-writer under `.prove/lock`, created exclusively with an OS advisory lock held for the writer's lifetime. Recovery requires the caller's explicit expected SHA256 of the stale lock bytes and acquires the same OS lock nonblockingly; a live writer cannot be displaced by ordinary recovery. No automatic PID-based stale-lock deletion. Atomically write fsynced temporary files, fsync parent directories, and only publish complete state. Immutable destination publication is no-clobber even if another process creates the destination after an existence check. Retrying identical registration/seal operations may reuse identical bytes; conflicting immutable input requires a new receipt, never overwrite. Interrupted sealing is recoverable from local journal/staging. Partial result.json or records.jsonl must never look finalized. Reject overlapping source-artifact and receipt directory trees to prevent recursively ingesting receipt staging or overwriting source data.

Before publishing any normative files for a seal candidate, check an existing final result. A conflicting result rejects without adding candidate artifacts or changing the finalized tree. A pending local journal binds exactly one complete staged candidate; fresh sealing cannot replace its recovery pointer with another candidate. Identical reuse and explicit recovery revalidate staged/final bindings. Reusing visible hash-identical files after interruption also requires successful file and directory-chain fsyncs before finalization; a previous failed fsync is not repaired by hashing or syncing result.json alone. Publish result.json last. Local stage/journal fields never override actual core, artifact or record validation.

OTS submits exact frozen core file digests, with nonces and standard upstream proof operations. Upgrades atomically replace proof files and preserve old proof bytes; core identities stay fixed. Online calendar endpoints are explicit allowlisted HTTPS origins with request timeouts, backoff for 429/403/5xx, bounded retries and one active request per receipt. URLs embedded in untrusted proofs are not arbitrary outbound authority. Pending, failed submission and malformed proof are distinct.

Detached proofs are limited to16MiB, timestamp-tree depth256 and100000 structural timestamp-node/attestation items before operation evaluation. Use standard upstream SHA256 detached-file semantics and proof operations, with upstream framing/argument/height bounds. A checked Bitcoin witness is sufficient when its message matches an explicitly trusted cached header and its confirmations meet the selected threshold. Choose the earliest qualifying valid witness. Extra contradictory attestations do not erase a valid checked path; report their ignored count without calling those paths valid. If no cached witness is valid and a supplied cached witness contradicts its header, reject invalid evidence. No available header yields insufficient-chain status; checked witnesses below threshold yield insufficient-confirmation status. Pending and unsupported attestations never establish a completed anchor.

Offline anchoring requires an explicitly supplied verifier-controlled prove.chain.v1 cache. Its required fields are `{format, exported_at, source, tip, node, blocks}`, source a provenance string, tip `{height, hash}`, node `{chain, initialblockdownload, blocks, headers, verificationprogress}`, and blocks a mapping of decimal-string heights to `{hash, header, confirmations}`. Header is 80 bytes of lowercase hex; hash matches double-SHA256 reversed header hash; confirmations must equal tip.height-height+1. Source flags cannot authenticate the cache. A coherently fabricated explicitly trusted cache can pass internal checks; independent acquisition remains the auditor's responsibility. No implicit bundle cache is used. Default minimum confirmations six. Output reports the cached tip and never current-chain freshness.

The separate Bitcoin Core exporter uses local configuration/cookie credentials, rejects credentials in endpoint URLs, requires main chain, no IBD and synchronized blocks/headers, reads active-chain headers and tip before/after, and retries bounded snapshot attempts if the view changes. Its `verificationprogress` field is serialized as a canonical decimal string, not a JSON float. Height-map keys have canonical decimal spelling with no leading zeros. It does not deploy a node, validate new consensus or equate explorer data with a locally validated source.

## Compatibility and integration boundary

Package versions may change while protocol v1 stays stable. Unknown normative versions fail explicitly. Generic CLI defaults, examples and installed conformance vectors have no research-project dependency. Optional adapters preserve original logs and account for source semantics; unsupported mappings cannot acquire strict trace claims. External Colony/Ouroboros testing happens against installed versioned artifacts and produces documented feedback before public stable release.
