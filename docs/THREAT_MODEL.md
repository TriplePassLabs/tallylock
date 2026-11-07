# TallyLock threat model

Design review, 2026-11-05. This is a protocol threat analysis, not an implementation audit.

The receipt author, harness, model endpoint, network transport, artifacts, proof files and any embedded metadata can be malicious. The auditor's chosen verifier implementation, independent local trust store and validated chain acquisition are trusted. Cryptographic assumptions include SHA-256 collision and preimage resistance. The verifier reports its cached view instead of assuming Bitcoin is permanently final.

| Attack | Required defense | Remaining limit |
|---|---|---|
| Fabricate an impressive run, then timestamp it | Label execution and model identity as assertions | OTS does not attest execution |
| Run privately before preregistering | Never infer chronology or no rehearsal from anchor ordering | Independent witnesses or task-release mechanisms are separate work |
| Register many plans and publish the best | Publish declared schedule and all scheduled dispositions | Hidden registrations/runs remain undetectable |
| Modify prompt, scorer or dataset after freeze | Bind effective configuration and content digests in manifest | Incorrect initial declarations may still be committed |
| Seal a wrong score | Separate score integrity from independent recomputation | Opaque judges or private labels may prevent recomputation |
| Substitute another result or registration | Typed cores, explicit manifest digest and attempt IDs | Author can deliberately issue another honest-looking receipt |
| Delete/reorder/duplicate visible records | Ordered domain-separated tree, contiguous indices, bound tree size and sample reconciliation | Never-observed calls cannot be recovered |
| Show one passing record as a complete evaluation | Scope labeled inclusion; no full-integrity verdict | Inclusion establishes only the selected leaf |
| Supply fake matching header and Merkle root | Use verifier-owned independently validated chain cache | Compromising local trust data compromises assurance |
| Present pending calendar acknowledgement as confirmed | Separate submission and completed Bitcoin checks | Calendar availability affects completion |
| Present a stale/reorganized anchor | Cached tip/provenance and confirmation policy in output; refresh separately | Offline verifier cannot learn new chain state |
| Replace local artifacts during finalization | Immutable snapshot, one writer, atomic commit, consistency checks | A hostile host can fabricate all writer inputs |
| Crash after sealing but before timestamp request | Durable core before network I/O, idempotent resume | Remote submission may have happened even if response was lost |
| Trigger requests to attacker-selected servers | Offline network prohibition; no artifact URL fetch; online calendar allowlist | Configured calendars still see submission metadata |
| Execute code from a scorer or imported log | Verify data only; rescore only in an explicit isolated action | Receipt integrity says nothing about scorer safety |
| Read files outside bundle | Reject traversal, links, absolute and colliding paths; regular files only | Local OS and verifier permissions remain trusted |
| Exhaust parser memory/CPU | Documented limits, bounded proof parsing and streamed artifacts | Operational policy may reject unusually large valid receipts |
| Recover private tasks from guessable digests | Randomized commitment preimages and deliberate reveal policy | A public disclosure cannot later be revoked |
| Misattribute a receipt to a person or institution | Label unsigned authorship as unverified | Signatures/identity systems are deferred |
| Treat a service change as model-weight drift | Fixed protocol, uncertainty, calibration and attribution limits | Provider internals remain unknown |

Required verifier invariants and their test cases are listed in [acceptance tests](ACCEPTANCE.md). These defenses become implementation claims only after their tests and independent review pass.
