# Public wire conformance

The single canonical corpus lives in [package data](../src/tallylock/data/conformance/README.md).
The [case index](../src/tallylock/data/conformance/index.json) records each input's
purpose, expected code, registration ID, receipt ID, root, score and scope.
The intentionally malformed JSON cases are raw byte files, not valid JSON documents.

Run `python tools/reference_verify.py src/tallylock/data/conformance/cases/run-fixture-exact.json`
from the repository with `jsonschema` installed. This prints a reference report,
not a production verification report. `--help` describes the one-file interface.

For contributor checks, use:

```sh
python -m pytest tests/test_conformance.py tests/test_reference_verify.py
```

See [RUNBOOK.md](../RUNBOOK.md) for isolated environment guidance.

The reference reads only its caller-selected case and the fixed published schema.
Envelope artifact paths stay data. Only the production-side test harness creates
tiny files in a fresh temporary receipt. Inclusion vectors require no artifact
availability and cannot establish full record history, resource totals, budget
compliance, score math, execution or issuer authenticity. These observations do
not satisfy real-node, real-anchor or installed-CLI network-isolation gates.
