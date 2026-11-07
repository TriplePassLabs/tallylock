# Adapter fixtures

Every file below is a byte-for-byte copy of a published upstream file, fetched on 2026-11-07 over HTTPS from raw.githubusercontent.com. None is synthetic. Nothing here was edited.

## Inspect AI (MIT)

Repository https://github.com/UKGovernmentBEIS/inspect_ai, commit `da64cc6475734b3b4873de6c1957d727c86ba192` (main on 2026-11-07, latest release 0.3.288). Format read from `src/inspect_ai/log/_log.py` at that commit.

| Fixture | Upstream path | SHA-256 |
|---|---|---|
| inspect-log_formats.eval | tests/log/test_eval_log/log_formats.eval | 13274e1d67440bdbd8d88e9400d0dd1e19d9b3b39128e3d9fee91618f116baff |
| inspect-log_formats.json | tests/log/test_eval_log/log_formats.json | b36b887e44701701d87a7bd8bac7f9fafb2804731491b3125b3917fb7968a825 |
| inspect-no-samples.json | tests/analysis/test_logs/2025-05-12T20-28-13-04-00_no-samples.json | b5e483498324b2d18beda512660a61a2858b659f1ef4c0e726c23f41979fdc63 |

The two `log_formats` files are the same one-sample run in both formats. `no-samples` has an empty `samples` list and per-sample scores only in `reductions`.

## proofbundle (MIT)

Repository https://github.com/b7n0de/proofbundle, commit `65bd4b7a34b84724298961254eaba5d67bb3fc3b` (main on 2026-11-07; README names release 6.5.0, PyPI showed 6.4.0). Format read from `SPEC.md` sections 2 to 6 and 7i.

| Fixture | Upstream path |
|---|---|
| proofbundle-example_bundle.json | examples/example_bundle.json |
| proofbundle-forged-anchor-own-frozen.bundle.json | conformance/bundle/forged-anchor-own-frozen/bundle.json |

The second one carries an OpenTimestamps anchor whose block header the producer supplied itself. Upstream expects a verifier to refuse to trust it without the relying party's own header. TallyLock reports it as "signed" with the anchor state `needs_relying_party_trust`.

## in-toto and cosign (no fixture)

in-toto attestation commit `50bf01716982189898823e90586075f37cd9bb7d` (spec/v1/statement.md, spec/v1/envelope.md). cosign v3.1.4, commit of main read for docs: `92514f9fedfabaf562f4946469a29b18c1ea68e7`.
