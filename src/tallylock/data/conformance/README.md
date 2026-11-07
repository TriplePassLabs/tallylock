# Fixed v1 materialized wire corpus

All content is synthetic public test data. There are no model executions, private
datasets, credentials, authentic issuers, blockchain witnesses or network inputs.
The reviewed input bytes and expected outputs are checked in once, here. Tests
read these files; they never generate cases or expected values with production code.

* [index.json](index.json) is the case index. Every case lists its purpose, code,
  reference-known registration/receipt IDs and root, score, failure stage and scope.
  Null IDs on parser/schema failures mean the consumer has not accepted the cores.
* [canonical.json](canonical.json) fixes UTF16 key order, JSON control escapes,
  Unicode preservation and both safe-integer limits. Expected byte strings were
  written explicitly, rather than obtained from either canonicalizer.
* [trees.json](trees.json) fixes roots and every branch for 0, 1, 2, 3, 5, 7, 8 and
  9 leaves. Empty trees have no membership paths. The leaf bytes are
  `independent-wire-leaf:N`, starting at zero. Every hash uses SHA256, RFC9162
  `00` leaf / `01` inner prefixes, without odd-leaf duplication.
* [cases/](cases/) holds raw closed envelopes, including deliberately malformed
  JSON bytes. Artifact and core bytes use canonical base64.

Authorship and independence: `tests/reference_corpus_author.py` is the retained
offline authoring worksheet. It imports neither TallyLock nor the reference tool.
Its wire fixture keys are ASCII/BMP, where stdlib key ordering agrees with UTF16.
Canonical-vector containers are ordinary JSON with handwritten expected JCS bytes.
Its tree builder merges equal-sized completed subtrees on a bottom-up
stack, then folds the remaining forest from the right. The independently authored
reference instead writes JCS strings and UTF16 key ordering directly and computes
roots with recursive largest-power-of-two splits. Both use SHA256 from the Python
standard library. The reference intentionally shares the static published closed
JSON schema, but no production Python functions or canonicalization dependency.

Explicit reauthoring, only when reviewing corpus changes:

```sh
python -m pytest tests/reference_corpus_author.py -q
```

This is an authoring operation that writes source assets. Ordinary tests never
import or invoke it. Review both the new bytes and the resulting fixed index.
See the [source-checkout runbook](https://github.com/TriplePassLabs/tallylock/blob/build/integration-candidate/RUNBOOK.md)
for isolated environment guidance.
Math, lifecycle, resource and budget counterexamples rebind their record bytes,
digest, length, root and IDs. The genuinely valid membership paths on impossible
visible positions isolate inclusion scope checks from path verification.

`production_overlap: false` marks envelope-only/parser-only cases that have no
production materialized-case interface. For shared inputs the tests compare fixed
exit codes. Successful cases also compare fixed IDs, roots and score state/counts.
Failure reports can expose different partial IDs because each consumer accepts
independent stages in a different order; fixed failure IDs describe the reference.
Inclusions compare membership scope only, and leave artifact availability, full
history, coverage, actual totals, budgets and score math unchecked.

The subprocess tests run Python isolated from project import paths and explicitly
deny imports of `tallylock` and `rfc8785`, including transitive imports. They also trap
Python socket connections. Installed-CLI process-level blocked-network acceptance
belongs to Task 7; this is not that gate. No filesystem race, chain authentication,
hidden-attempt completeness or executed-model claim follows from this corpus.

Review additions include a1MiB exact-limit event, a1MiB+1 event with genuine
membership, safe and overflowing known usage subtotals despite null full totals,
multiple valid copies of the pinned dataset, and malformed embedded discriminator
shapes paired with a future inclusion version. Inclusion preflights every visible
format shape. Full scope interprets result semantics only after accepting the
manifest, so an unsupported manifest remains unsupported4 even if its dependent
result has a missing format. The index states that boundary explicitly.
