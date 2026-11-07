# Offline quickstart

The supported runtime target is Linux with Python 3.11 through 3.13. This is an unreleased candidate; see the readiness audit for observed gates. Select one of those interpreters explicitly; a distro default may be newer and unsupported. On Ubuntu or Debian, install the matching venv package before the primary setup path. For example, Ubuntu 24.04 users selecting Python 3.12 need `python3.12-venv`:

```sh
sudo apt install python3.12-venv
```

This installs venv support for that interpreter. It does not replace the system Python or install TallyLock into it. See the [Ubuntu Python setup guide](https://ubuntu.com/developers/docs/howto/python-setup/) and the [Ubuntu `python3.12-venv` package record](https://packages.ubuntu.com/noble/python3.12-venv) for the matching-package relationship.

With a supported interpreter and its venv support, create an isolated environment and install the reviewed wheel:

```sh
/usr/bin/python3.12 -m venv .venv-tallylock
. .venv-tallylock/bin/activate
python -m pip install /absolute/path/to/tallylock-0.1.0a1-py3-none-any.whl
tallylock --version
```

If [`uv`](https://docs.astral.sh/uv/pip/environments/) is already installed, it is an optional fallback, not a TallyLock runtime dependency. It can create an environment without `ensurepip`, then install the wheel without needing `pip` inside that environment:

```sh
uv venv --python /absolute/path/to/supported/python .venv-tallylock
uv pip install --python .venv-tallylock/bin/python /absolute/path/to/tallylock-0.1.0a1-py3-none-any.whl
uv pip check --python .venv-tallylock/bin/python
. .venv-tallylock/bin/activate
tallylock --version
```

The console command works after activation even if the environment has no `pip` command. Do not use `sudo pip`.

Alternatively install a reviewed source checkout with `python -m pip install /absolute/path/to/tallylock`. Installation may fetch dependencies. A fully offline installation needs a separately prepared wheelhouse containing TallyLock and all dependencies, then `python -m pip install --no-index --find-links /absolute/path/to/wheelhouse tallylock==0.1.0a1`. No unpublished PyPI release is assumed.

Once installed, this workflow runs in a fresh directory unrelated to any repository. It uses no model, API key or private service. `python -m tallylock` can replace `tallylock` in every command.

```sh
mkdir my-receipt-demo
cd my-receipt-demo
tallylock --version
tallylock init --out manifest.json --name "Ordinary output demo"
```

`init` writes a fresh nonce and editable manifest. Review and edit its model, dataset, harness, attempts and budgets before freezing it. This demo keeps the explicit unspecified/self-declared values. `init` does not preregister anything or execute an evaluation.

```sh
tallylock pre-register manifest.json --receipt receipt
mkdir outputs
printf 'ordinary external output\n' > outputs/result.txt
tallylock seal receipt --artifacts outputs
tallylock inspect receipt
tallylock verify receipt --offline --policy integrity-only
```

`receipt` is created as a single final directory in its existing parent. Output parents must already exist. `seal` snapshots the external outputs without rewriting them. Reports contain `registration_id` and, after sealing, `receipt_id`. `inspect` is a bounded local presentation and explicitly performs no verification.

Verification checks the copied files under `receipt/artifacts`, not the original `outputs` directory. Editing the original outputs after sealing does not invalidate the receipt; editing its frozen copy does. The retained root `.prove/staging` files are producer recovery checkpoints. They are unnecessary in a read-only sharing copy. See [integration guidance](INTEGRATION.md) for disk usage, portable contents and retrospective sealing of existing results.

Integrity-only verification returns 0 here, checking frozen artifacts and records without timestamps. No score was selected, so scoring is `unavailable`. Explicit recorded-only scores remain `recorded_only`; their meaning or accuracy is not recomputed. Verification does not establish honest execution or model identity.

```sh
tallylock proof create receipt --index 0 --out inclusion.json --without-proofs
tallylock verify --inclusion inclusion.json --offline --policy integrity-only
```

The inclusion package is self-contained, including after the original receipt disappears. It proves only the selected record's membership in the ordered tree. It does not scan artifacts or verify the entire history or scoring. Keep outputs outside the receipt. TallyLock rejects destinations within the operated receipt, including aliases. Immutable output files never overwrite an existing file; choose a fresh filename for another package.

```sh
tallylock verify receipt --offline
```

This intentionally returns 3, insufficient evidence: default verification requires anchored evidence. No timestamp was requested. `--offline` makes the existing policy explicit; verification always stays offline. Under integrity-only, even an explicitly named chain cache is ignored without opening it.

Optional timestamping is a separate network action:

```sh
tallylock anchor receipt
tallylock upgrade receipt
tallylock verify receipt --chain-cache independently-selected-chain.json --offline
```

The last command requires an independently selected local `prove.chain.v1` cache with matching headers and at least six confirmations by default. `--min-confirmations N` selects a positive threshold. TallyLock never obtains that cache implicitly. Pending proofs, submission and an attestation's presence do not establish completed anchoring. Header time is not trusted execution time. Cache freshness and external provenance remain your responsibility.

`pre-register ... --anchor ots` and `seal ... --anchor ots` finish locally before timestamping. If that phase fails or is interrupted, reports retain completed local state and IDs with `anchor_action` failed/interrupted. Retry with `anchor`/`upgrade`; no reseal or original outputs are required. `recover-seal` is for an interrupted local checkpoint. `recover-lock --observed-sha256 SHA` requires the exact observed abandoned lock digest. Neither runs automatically.

Read static generic examples from the installed package without repository files:

```python
from importlib.resources import files

basic = files("tallylock").joinpath("data/examples/basic")
manifest_bytes = basic.joinpath("manifest.json").read_bytes()
metrics_bytes = basic.joinpath("outputs/metrics.json").read_bytes()
```

The static manifest has a fixed demonstration nonce. Use `tallylock init` for real registrations.
