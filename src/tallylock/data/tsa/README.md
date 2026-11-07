# Bundled RFC 3161 timestamp roots

TallyLock checks every stored ledger-head timestamp token offline against these
roots. Each file is stored exactly as downloaded on 2026-11-07. `File SHA-256`
is the digest of the file bytes; `Certificate SHA-256` is the digest of the DER
certificate (the usual certificate fingerprint).

| File | Source URL | File SHA-256 | Certificate SHA-256 | Valid until |
| --- | --- | --- | --- | --- |
| freetsa-root.pem | https://freetsa.org/files/cacert.pem | 2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438 | a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc | 2041-03-07 |
| digicert-trusted-root-g4.crt | https://cacerts.digicert.com/DigiCertTrustedRootG4.crt | 552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988 | 552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988 | 2038-01-15 |

freetsa-root.pem is the FreeTSA root CA ("O=Free TSA, OU=Root CA") that signs
the https://freetsa.org/tsr responder certificate. digicert-trusted-root-g4.crt
is DigiCert Trusted Root G4, the root above "DigiCert Trusted G4 TimeStamping
RSA4096 SHA256 2025 CA1", which issues the http://timestamp.digicert.com
responder certificate. Recorded replies from both services verified with
`openssl ts -verify` against these files before they were bundled.

To add a root for another service, add its PEM or DER certificate here, add a
row to this table, and add the file to the package data.
