Real Bitcoin mainnet replies, recorded once on 2026-11-07T21:31:50Z through the
capped worker from https://blockstream.info/api and https://mempool.space/api
(endpoints /blocks/tip/height, /blocks/tip/hash, /block-height/H and
/block/HASH/header). Both providers returned identical bytes for every height.
Recorded heights: 0..3 (genesis and the first blocks), 358391..358401 (the block
attested by the hello-world proof and ten blocks on top) and 840000..840010
(modern difficulty). The recorded tip was 974990 at both providers.

hello-world.txt and hello-world.txt.ots are the public example proof from
https://github.com/opentimestamps/opentimestamps-client/tree/master/examples
(fetched from the master branch on 2026-11-07). The proof carries one Bitcoin
attestation at height 358391. Upstream identifies its source license as
LGPL-3.0-or-later; these files are factual test data, not copied source code.

SHA-256:
03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340  hello-world.txt
be61ecb940db2e4a6f89fbed59c8d4f7f74fa756cbc1fad1ad7aabcb2bf59c30  hello-world.txt.ots

Forged, disagreeing, malformed and timed-out replies in tests/test_headers.py
are synthetic edits of these recordings. Headers mined at regtest difficulty in
the verifier tests are synthetic and only pass with a test-raised work limit.
