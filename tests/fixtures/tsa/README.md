# Recorded RFC 3161 replies

Real replies recorded once on 2026-11-07 at 21:32 UTC by POSTing the
`.tsq` request beside each `.tsr` reply. Nothing here is synthetic.

- Message imprint: SHA-256 of the 27 bytes `TallyLock RFC 3161 fixture\n`,
  3a4230a4dee322d76b3fa58b94e9cd4baa912c77d19bb044e78c95993d965740.
- Requests ask for certificates (certReq true) and carry a nonce.

| File | Service | Nonce | Signer |
| --- | --- | --- | --- |
| freetsa.tsr | https://freetsa.org/tsr | 37777802110563428264632080986 | ECDSA P-384, ecdsa-with-SHA512, under the FreeTSA root |
| digicert.tsr | http://timestamp.digicert.com | 37777802110563709739608810917 | RSA 4096 PKCS#1 v1.5 SHA-256, under DigiCert Trusted Root G4 |

Both replies passed `openssl ts -verify -queryfile <name>.tsq` against the
roots in src/tallylock/data/tsa/ when recorded. Negative cases in
tests/test_rfc3161.py either alter these bytes or build an explicitly
synthetic test CA in memory.
