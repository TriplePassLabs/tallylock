# Integrating ordinary evaluation programs

TallyLock consumes data files from external programs. It does not import a model SDK, execute a scorer supplied by metadata or require a research checkout. Freeze the plan, run your program separately, then seal its output directory.

1. Run `tallylock init --out manifest.json`, edit declarations and attempts, then `tallylock pre-register manifest.json --receipt receipt`.
2. Run your external program and write ordinary output files. Record failures and selected attempts honestly.
3. Run `tallylock seal receipt --artifacts outputs`, with explicit data options where applicable.
4. Share the receipt. Verify with an explicit policy and independently selected chain evidence.

For outputs that already exist, describe the operation as retrospective sealing. Before freezing the manifest, set `manifest.metadata.evaluation_timing` to `"retrospective"`. For example, the metadata object may include:

```json
{"evaluation_timing": "retrospective"}
```

This is a structured, hashed self-declaration using the existing non-normative metadata field. Preserve any other metadata entries. It does not establish when the outputs were created or turn retrospective sealing into pre-execution preregistration. Version 0.1.0a4 has no dedicated `--retrospective` flag or report field. Read the frozen manifest for this declaration; `inspect` does not dump arbitrary metadata.

`seal` maps data-only options directly to the store API: `--attempt ID`, `--outcome completed|failed|aborted|budget_exceeded`, `--reason TEXT`, `--events FILE`, `--roles FILE`, `--media-types FILE`, `--score-path REL`, `--aggregate FILE`, and `--metadata FILE`. Outcome defaults to completed and reason to absent. Unsuccessful outcomes require the reason and evidence expected by the protocol. See `prove COMMAND --help` for exact arguments.

JSON options are strict data limited to 8 MiB, rejecting duplicate keys, floating-point numbers and unsupported values. Role/media-type maps contain artifact-relative paths and string values. Events are JSONL up to 64 MiB, with a final LF for nonempty input; import mode accepts ordinary JSON whitespace with strict value rules. Trace lifecycle and bindings must already be correct. TallyLock never invents terminal events or infers scores/roles from filenames.

To select an external recorded-only score explicitly:

```sh
printf '{"numerator":3,"denominator":4}' > aggregate.json
tallylock seal receipt --artifacts outputs --score-path metrics.json --aggregate aggregate.json
```

The manifest's scorer profile controls interpretation. With `recorded-only-v1`, the aggregate is recorded without recomputing the metric. Omitting `--score-path` yields an unavailable score even when a file is named metrics.json. The separate `fixture-exact-v1` rule recomputes only its closed deterministic fixture format. It does not verify a model ran or authenticate producer labels/observations.

Keep raw output files and complex producer-specific semantics in the frozen artifacts unless a supported scorer explicitly recomputes them. For example, an external program may preserve per-condition metrics and select one ratio as a recorded-only aggregate:

```json
{"selected_ratio":{"numerator":3,"denominator":4},"selection_rule":"highest eligible condition"}
```

That object is an example metrics artifact, not the `--aggregate` input. Write the selected ratio alone as `{"numerator":3,"denominator":4}` in the separate aggregate file shown above. TallyLock does not extract `selected_ratio` or check the selection rule automatically. The selection rule and per-condition values remain preserved declarations. Likewise, ledger roots, weight-digest strings, and model declarations are not automatically authenticated as trace, model-identity, or score evidence. Do not invent trace events or map arbitrary producer data to `fixture-exact-v1`; project-specific parsing and adapters remain outside this generic core.

`seal --artifacts outputs` copies those files into `receipt/artifacts`. Full verification checks that frozen copy. Moving, editing or deleting the original `outputs` directory afterward does not change the receipt's validity. Changing `receipt/artifacts` does. There is no `verify --artifacts` option to compare an external working directory. Use a new registration/receipt for a new experiment, or a separate receipt for each already declared attempt; do not overwrite sealed artifacts.

The producer retains `.prove/staging` and its journal after a successful seal. These are durable recovery checkpoints, not a sign that the seal failed. Staging can contain another complete artifact copy, and retries can retain additional candidate stages, so account for their disk usage. Version 0.1.0a4 has no automatic staging cleanup command. Keep the original producer state for retry and recovery.

For a read-only portable receipt, include `manifest.json`, `result.json`, `records.jsonl`, the entire `artifacts/` tree and `proofs/` when present. The root `.prove/` directory is not needed for verification and is excluded from receipt identity. Omitting private state from a sharing copy is distinct from deleting recovery state in the producer's original receipt. Preserve any committed artifact directory named `.prove` inside `artifacts/`; only the receipt's root `.prove` is private state.

Receipt reads use bounded stable regular files and no-follow traversal beneath selected opened roots. Absolute root ancestors are selected trusted paths, not a sandbox. Receipt creation creates only the selected final directory in an existing parent. Output files publish canonical bytes atomically without a trailing LF, never overwriting an existing file. Stdout machine reports have one LF. Proof outputs must be outside the operated receipt, including artifacts, proofs and local-state directories; identity checks include bind aliases. Do not redirect reports into the receipt either.

`verify DIR` and `verify --inclusion FILE` are always offline/read-only. Exactly one source is required. Default policy is anchored, requiring a positive confirmation minimum (default 6), suitable proofs and explicit local chain evidence. Integrity-only checks integrity without reading even an explicitly named chain cache. After invocation, the CLI returns the verifier's exact report; earlier argument/input-file errors use command-error reports. Inclusion is partial, without full receipt validity claims.

`inspect DIR` emits `prove.inspection.v1`: core schemas/direct bindings, IDs, declared name/profile/attempt/outcome, inventory count and at most 100 UTF8-path-sorted path/hash/byte entries. It never scans artifacts, runs scoring, traverses `.prove`, consults caches or makes chain claims. Proof states distinguish missing, pending, unverified attestation presence, unsupported witnesses and missing cores.

`anchor DIR --target all|manifest|result` and `upgrade DIR --target all|manifest|result` act on frozen cores. Default target is all. Returned actions may remain pending/retry-wait/unverified. Local preregistration and sealing finish before optional `--anchor ots`; errors/interruption retain completed local state and IDs. Resume timestamping without original artifacts. `recover-seal DIR` resumes an explicit valid durable checkpoint. `recover-lock DIR --observed-sha256 SHA` only recovers an observed abandoned lock, without asserting seal completion.

`evidence export --bitcoin-rpc CONFIG --height N [--height N ...] --out FILE` asks an explicitly configured Bitcoin Core node for a bounded coherent snapshot. Endpoint/authentication stay in trusted configuration/cookie files, never command arguments. Those files retain the export API's bounded regular trusted-path semantics. TallyLock deploys no node and implements no consensus. Caches are external_explicit/cached_only; internal consistency does not authenticate the source or current freshness.

The configuration has exactly these fields. Set the endpoint and cookie path for the node you independently selected; the values below are examples, without credentials:

```json
{
  "format": "prove.bitcoin-rpc.v1",
  "endpoint": "http://127.0.0.1:8332",
  "cookie_file": "/absolute/path/to/bitcoin/.cookie",
  "source": "My independently selected validated Bitcoin Core node"
}
```

A relative cookie path resolves against the configuration file's directory. Keep the configuration/cookie outside the receipt and any shared feedback. The source text records your description; it does not authenticate the node. `tallylock inspect receipt` shows required heights under `proofs.manifest.inspection.bitcoin_heights` and `proofs.result.inspection.bitcoin_heights` when attestations are present. Export each required height using repeated `--height`, write the cache outside the receipt, then pass that file explicitly to `tallylock verify receipt --offline --chain-cache chain.json`. Preserve the source/provenance record separately. A cached view never establishes current-chain freshness.

Action reports contain exactly `format`, `command`, `code`, `registration_id`, `receipt_id`, `local_state`, `output`, `anchor_action`, `data`, `errors`, and `limitations`. Nested paths use `proof.create`/`evidence.export`; unknown command paths use null. IDs remain null until known. Local states are null, initialized, registered, sealed or lock_recovered. Explicit anchor/upgrade commands report the existing registered/sealed state after validating their cores, retaining it if timestamping fails or is interrupted. Output is the selected absolute file destination or preregistration receipt directory; commands with no new destination use null. Anchor states are not_requested, returned, failed or interrupted. Data is non-null only for proof index/size and export tip/heights/trust/freshness. Diagnostics preserve safe schema field locations and explicitly rejected artifact filenames, including colons. Other arbitrary values, schema instance renderings, unknown arguments and authentication/response bodies are omitted. Each diagnostic is bounded to 2048 printable characters.

Statuses: 0 successful requested action/check, 2 invalid input, 3 insufficient evidence, 4 unsupported evidence, 5 operational/internal failure, 130 interruption. Help/version return 0. `run` records a failing command and then exits with that command's own exit code (128 plus the signal number for a signal); with `--repeat` it exits with the first failing attempt's code. Local work is not rolled back after optional anchoring failure. A closed stdout may prevent reporting but retains no HTTP child or retry loop.

Installed static resources live under `tallylock/data/examples/basic` and `tallylock/data/conformance`, accessible with `importlib.resources.files("tallylock")`. Optional harness importers are outside this generic workflow.
