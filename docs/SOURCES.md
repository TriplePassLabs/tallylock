# Sources and reuse decisions

Primary references checked 2026-11-05. Dependencies and interfaces will be pinned when implementation begins; these links do not claim that TallyLock already integrates with them.

| Source | What we reuse or learn | Boundary |
|---|---|---|
| [OpenTimestamps](https://opentimestamps.org/) | Public timestamp format and existing calendars | Prior existence is not execution attestation |
| [OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client) | Stamping, proof completion and upstream verification | Independent verification needs appropriate Bitcoin chain evidence |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | JSON canonicalization basis | TallyLock proposes a narrower schema profile |
| [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1) | Ordered domain-separated Merkle construction | We reuse the construction, not Certificate Transparency's entire service protocol |
| [Bitcoin block headers](https://developer.bitcoin.org/reference/block_chain.html) | Header layout, Merkle root and timestamp semantics | Header possession alone does not authenticate the active chain |
| [Inspect evaluation logs](https://inspect.aisi.org.uk/eval-logs.html) | Existing structured evaluations and log reading APIs | Candidate import adapter, not a new runtime dependency for verification |
| [lm-evaluation-harness interface](https://github.com/EleutherAI/lm-evaluation-harness/blob/main/docs/interface.md) | Existing result and sample-log export | Candidate alternative adapter; support one first |
| [in-toto Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) | Digest-addressed subjects and typed claims | Evaluate a mapping after the minimal receipt stabilizes; do not invent signature assurance |
| [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) | Existing artifact verification and explicit trust policies | Existing alternative worth testing with pilots; not a Bitcoin-anchoring substitute |
| [Sequential multiple hypothesis testing](https://proceedings.mlr.press/v54/malek17a.html) | Primary research on sequential error control | Supports the need for a specified testing procedure; does not select or validate our future study design |
| [Colony Zero public commitments](https://github.com/colony-zero/colony-zero-research/tree/main/public-commitments) | Real commitments, reveals and timing disclosures | Historical limitations remain; verify redistribution permission before copying implementation |

## Why a separate tool might be useful

A plain checksum establishes byte identity against a supplied expected value. A signed log can add identity under a key policy. Existing attestations describe artifact claims. TallyLock's proposed value is a constrained evaluation-specific binding and inspection workflow, including plan/result linkage, incomplete attempts, ordered records, evidence scope and optional Bitcoin anchoring. The pilot must establish whether that added structure justifies another tool.

If an adapter plus an existing attestation format provides the same useful assurance with less maintenance, prefer that design. There is no claim that this field is empty or that Bitcoin alone fixes benchmark science.
