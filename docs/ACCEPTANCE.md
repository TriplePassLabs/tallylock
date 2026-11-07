# TallyLock acceptance matrix

Planned checks, not test results. Each row must become an executable test or a recorded integration procedure. G1 and G2 are separate acceptance gates.

| ID | Gate | Check and expected observation |
|---|---|---|
| C01 | G1 | Known manifest/result bytes produce published digests; a second minimal verifier reproduces them without calling the production functions |
| C02 | G1 | Reordered object keys canonicalize identically; floats, duplicate keys, non-finite values, out-of-range integers, unknown normative fields and bad Unicode fail |
| C03 | G1 | Cross-check tree roots and membership for 0, 1, 2, 3, 5, 7, 8 and 9 leaves against independent fixed vectors |
| C04 | G1 | Wrong sibling order, wrong tree size/index, unused proof nodes, duplicate or reordered event indices fail |
| C05 | G1 | Alter manifest, registration binding, attempt ID, one artifact byte, file size or score inventory; each mutation fails the relevant check |
| C06 | G1 | Duplicate/unexpected sample terminals and dangling artifact references fail; completed attempts require full coverage; failed, aborted and budget-exceeded attempts permit explicitly reasoned incomplete coverage |
| C07 | G1 | Valid zero-event failed/aborted/budget-exceeded receipts with explicit reasons pass structural checks; zero-event completed evaluation fails |
| C08 | G1 | Inclusion-only verification never emits full-artifact or full-history success |
| C09 | G1 | Deterministic fixture scores recompute from raw disclosed records; intentionally wrong sealed score has valid hashes but fails score recomputation |
| C10 | G1 | A fabricated but internally consistent fixture can pass integrity; report still labels execution and model identity unverified |
| C11 | G1 | Symlinks, traversal, absolute paths, case collisions, oversized metadata/proofs, invalid encodings and unsupported versions fail safely; descriptor-read mutation/symlink-swap attempts fail closed |
| C12 | G1 | Interrupt each write/rename boundary and rerun; cores stay intact, IDs stable and incomplete work recoverable |
| C13 | G1 | Two writers cannot finalize conflicting cores; changed input after freeze requires a new receipt |
| C14 | G1 | Verification never executes scorer/harness code or fetches an artifact URL; full check uses streamed artifact hashing |
| C15 | G1 | Integers at both safe-range boundaries pass canonicalization; adjacent out-of-range values and negative counters fail |
| C16 | G1 | A separately authored reference implementation sharing no canonicalization/tree/scoring code reproduces IDs, roots, membership and fixture scores; record its vector outputs |
| C17 | G1 | Unsupported secret-inventory/reveal fields cannot imply verified holdout membership; reject unsupported normative schema features |
| C18 | G1 | Frozen policy/exit matrix covers valid unsuccessful evaluations, invalid recomputed fixture scores, pending anchors with integrity-only policy, and inclusion-only scope with unavailable artifacts |
| T01 | G2 | Network-disabled verification succeeds for valid completed OTS proofs and independently prepared chain cache; process-level egress prohibition is exercised |
| T02 | G2 | Missing cache, implicit bundle-supplied cache and inconsistent/mismatched block hash/root/height or confirmation data fail; a coherently fabricated explicitly trusted cache may pass internal checks, demonstrating that independent acquisition stays an auditor responsibility |
| T03 | G2 | Pending proof is insufficient evidence; malformed or wrong-file proof is invalid; unsupported attestation is explicit |
| T04 | G2 | Block sequence and cache source are reported; stale-cache verification never claims current-chain freshness |
| T05 | G2 | Simulated 429/403/5xx, timeout and lost response leave durable core bytes unchanged; retries respect configured caps and backoff |
| T06 | G2 | Proof upgrade changes proof data but not core digests or receipt ID; interruption preserves a usable prior proof |
| T07 | G2 | Fresh real plan anchor completes before the fixture's locally enforced launch; separate result anchor completes after finalization; audit records are preserved without claiming independent chronology |
| T08 | G2 | Clean offline verifier, with separately acquired chain evidence, checks the fresh receipt; mock-only or historical-only evidence cannot pass this milestone |
| T09 | G2 | Standard upstream OTS tooling checks the core-file proofs, and TallyLock reports the same anchor hashes against the same chain view |
| U01 | G3 | Import one pinned existing-harness log with retries and failures; raw log hash preserved and mapping report accounts for every record, explicitly reporting unsupported semantics |
| U02 | G3 | Two unfamiliar users can verify a real pilot and correctly explain that timestamps do not prove model identity, honest execution or no hidden attempts |
| U03 | G3 | Pinned exported Inspect JSON is parsed only as data; task/plugin paths, attachment URLs and malformed references cannot trigger execution, reads outside the input or network fetches |
| R01 | G4 | Clean wheel installation and quickstart run on the documented Python/OS matrix; vectors are packaged and compatibility retained |
| R02 | G5 | Three unaffiliated adopters publish real receipts that a separate environment verifies; active setup time and evidence preparation costs are recorded; adoption does not block package release |
| S01 | G5 | Null/stationary fixture simulations calibrate the preregistered drift procedure, including repeated looks and multiple endpoints |
| S02 | G5 | Audit all scheduled observatory run IDs against complete, aborted, failed and missing dispositions; count 100 unique completed anchored executions |
| S03 | G5 | Recompute report headline results independently and reconcile all routing/retry/judging usage against the declared parity track |

Performance claims require separate measured reports with CPU, OS, versions, sizes, sample counts and distribution of elapsed times. Measure hashing a whole run separately from verifying a single membership path. No universal millisecond claim is an acceptance requirement.

Observed core conformance evidence: C01/C03/C16 are exercised by tests/test_conformance.py, tests/test_reference_verify.py and main-owned tests/test_reference_adversarial.py against fixed packaged data under src/tallylock/data/conformance/. The independent tool shares the published wire schema and SHA256 primitive, but no production canonicalization, tree, record or scoring functions. Its authoring worksheet uses a separate tree construction. Final corpus:103 cases,94 production comparisons, four canonical vectors and eight tree sizes with all35 paths. Main's final affected run passed142 checks in22.15s after two scoped repair rounds and independent approval. This covers materialized bytes and declared overlap, not production filesystem races, installed CLI behavior, Bitcoin provenance or the fresh-anchor gates.
