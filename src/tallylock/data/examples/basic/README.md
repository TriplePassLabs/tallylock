# Generic artifact receipt example

This example represents outputs from any evaluation program. It needs no model, API account, hosted service or research-project checkout. The fixed manifest nonce is a conformance fixture, not a recommendation for real registrations.

The source files and installed copies under `tallylock/data/examples/basic` are byte-identical. Access installed copies with `importlib.resources.files("tallylock").joinpath("data/examples/basic")`. The primary quickstart generates its own inputs and needs no example files.

After copying these files into a fresh working directory:

```sh
tallylock pre-register manifest.json --receipt receipt
tallylock seal receipt --artifacts outputs
tallylock verify receipt --offline --policy integrity-only
tallylock proof create receipt --index 0 --out inclusion.json --without-proofs
tallylock verify --inclusion inclusion.json --offline --policy integrity-only
```

No score is inferred from metrics.json: without explicit selection scoring is unavailable. To record the supplied metric, use a fresh receipt and `--score-path metrics.json --aggregate aggregate.json`, where aggregate.json contains `{"numerator":3,"denominator":4}`. This remains recorded-only, without a claim that its math or observations are correct. Passing a receipt check does not establish honest execution or model identity.

Generate a fresh manifest with `tallylock init`, edit evidence/budgets, then use this generic workflow for real output directories. `tallylock verify receipt` defaults to anchored verification and returns insufficient evidence until qualifying timestamp proofs and independently selected chain evidence are supplied. Calendar submission is not completed anchoring.
