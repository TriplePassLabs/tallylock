"""Machine-readable list of every TallyLock command, kept in step with the real parser by a test."""
from __future__ import annotations

import json


FORMAT = "tallylock.capabilities.v1"

_EXIT_CODES = [
    {"code": 0, "meaning": "The requested action or check succeeded."},
    {"code": 2, "meaning": "Invalid input or arguments."},
    {"code": 3, "meaning": "Not enough evidence, no matching plan, or a claim that does not match."},
    {"code": 4, "meaning": "Evidence of a kind this version does not support."},
    {"code": 5, "meaning": "Operational failure, such as a file or network error."},
    {"code": 130, "meaning": "Interrupted."},
]


def _opt(flag, summary, *, required=False, choices=None, value=True):
    option = {"flags": [flag], "required": required, "takes_value": value, "summary": summary}
    if choices:
        option["choices"] = list(choices)
    return option


def _arg(name, summary, *, required=True):
    return {"name": name, "required": required, "summary": summary}


def _command(name, summary, outputs, effects, *, arguments=(), options=(), status="available", note=None):
    command = {"name": name, "status": status, "summary": summary, "arguments": list(arguments),
               "options": list(options), "effects": effects, "outputs": outputs}
    if note:
        command["note"] = note
    return command


_RECEIPT = _arg("receipt", "Receipt directory")
_ANCHOR = _opt("--anchor", "Submit to OpenTimestamps calendars after writing", choices=["ots"])
_TARGET = _opt("--target", "Which frozen core to act on", choices=["all", "manifest", "result"])
_COMMANDS = [
    _command("init", "Create a fresh editable manifest.", {"stdout": ["prove.command.v1"], "files": ["manifest JSON at --out"]},
             {"writes": "The file named by --out."}, options=[_opt("--out", "Manifest file to create", required=True),
                                                           _opt("--name", "Name for the evaluation")]),
    _command("pre-register", "Freeze a data-only manifest into a receipt before any results exist.",
             {"stdout": ["prove.command.v1"], "files": ["receipt directory"]},
             {"reads": "The manifest file.", "writes": "The receipt directory.",
              "network": "Only with --anchor: OpenTimestamps calendars."},
             arguments=[_arg("manifest", "Manifest file to freeze")],
             options=[_opt("--receipt", "Receipt directory to create", required=True), _ANCHOR]),
    _command("seal", "Snapshot ordinary output files into a receipt.",
             {"stdout": ["prove.command.v1"], "files": ["sealed result inside the receipt directory"]},
             {"reads": "The receipt and the artifacts folder.", "writes": "The receipt directory.",
              "network": "Only with --anchor: OpenTimestamps calendars."},
             arguments=[_RECEIPT],
             options=[_opt("--artifacts", "Folder of output files"), _opt("--attempt", "Attempt name"),
                      _opt("--outcome", "How the attempt ended", choices=["completed", "failed", "aborted", "budget_exceeded"]),
                      _opt("--reason", "Why the attempt did not complete"), _opt("--events", "Events JSON file"),
                      _opt("--roles", "Roles JSON file"), _opt("--media-types", "Media types JSON file"),
                      _opt("--score-path", "Path of the score inside the artifacts"),
                      _opt("--aggregate", "Aggregate score JSON file"), _opt("--metadata", "Metadata JSON file"), _ANCHOR]),
    _command("anchor", "Submit frozen cores to timestamp calendars.", {"stdout": ["prove.command.v1"]},
             {"reads": "The receipt.", "writes": "Timestamp proof files in the receipt.",
              "network": "OpenTimestamps calendars."}, arguments=[_RECEIPT], options=[_TARGET]),
    _command("upgrade", "Fetch completed timestamp proofs for frozen cores.", {"stdout": ["prove.command.v1"]},
             {"reads": "The receipt.", "writes": "Updated timestamp proof files in the receipt.",
              "network": "OpenTimestamps calendars."}, arguments=[_RECEIPT], options=[_TARGET]),
    _command("verify", "Read-only offline verification of a receipt or inclusion package.",
             {"stdout": ["prove.verification.v1"]}, {"reads": "The receipt or package, and an optional chain cache."},
             arguments=[_arg("receipt", "Receipt directory", required=False)],
             options=[_opt("--inclusion", "Inclusion package file to verify instead"),
                      _opt("--offline", "Accepted explicitly; verification is always offline", value=False),
                      _opt("--policy", "Evidence policy", choices=["anchored", "integrity-only", "provider-pow"]),
                      _opt("--online", "Check timestamps against two public providers", value=False),
                      _opt("--evidence", "Saved provider evidence to re-check offline"),
                      _opt("--save-evidence", "Write the provider evidence used to this file"),
                      _opt("--chain-cache", "Saved chain evidence file"),
                      _opt("--min-confirmations", "Confirmations needed")],
             note="Give exactly one of the receipt argument or --inclusion."),
    _command("inspect", "Bounded local presentation of a receipt without verifying it.",
             {"stdout": ["prove.inspection.v1"]}, {"reads": "The receipt."}, arguments=[_RECEIPT]),
    _command("proof create", "Record an inclusion package for one attempt.",
             {"stdout": ["prove.command.v1"], "files": ["prove.inclusion.v1 at --out"]},
             {"reads": "The receipt.", "writes": "The file named by --out."}, arguments=[_RECEIPT],
             options=[_opt("--index", "Index of the item to include", required=True),
                      _opt("--out", "Package file to create", required=True),
                      _opt("--without-proofs", "Leave timestamp proofs out", value=False)]),
    _command("evidence export", "Save chain evidence from a Bitcoin node you control.",
             {"stdout": ["prove.command.v1"], "files": ["prove.chain.v1 at --out"]},
             {"reads": "The node config file.", "writes": "The file named by --out.",
              "network": "The Bitcoin RPC endpoint in the config."},
             options=[_opt("--bitcoin-rpc", "Node config file", required=True),
                      _opt("--height", "Block height to save; repeat for more", required=True),
                      _opt("--out", "Evidence file to create", required=True)]),
    _command("recover-seal", "Resume an interrupted seal.", {"stdout": ["prove.command.v1"]},
             {"reads": "The receipt.", "writes": "The receipt directory."}, arguments=[_RECEIPT]),
    _command("recover-lock", "Clear one abandoned lock you have looked at.", {"stdout": ["prove.command.v1"]},
             {"reads": "The receipt.", "writes": "Removes the lock file in the receipt."}, arguments=[_RECEIPT],
             options=[_opt("--observed-sha256", "Hash of the lock you inspected", required=True)]),
    _command("doctor", "Read-only installation and receipt diagnostics.", {"stdout": ["tallylock.doctor.v1"]},
             {"reads": "The installation and the optional receipt."},
             arguments=[_arg("receipt", "Receipt directory", required=False)]),
    _command("run", "Run your command once and record the attempt in the plan ledger.",
             {"stdout": ["tallylock.run.v1"], "files": [".tallylock/plans/<id>/ledger.jsonl", ".tallylock/plans/<id>/attempts/<n>/"]},
             {"reads": "The git repository, config files and score file.",
              "writes": ".tallylock/plans in the repository, plus whatever your command writes.",
              "network": "OpenTimestamps calendars unless --no-anchor is given; your command may use the network."},
             arguments=[_arg("argv", "The command to run, after --", required=False)],
             options=[_opt("--outputs", "Folder of output files to record"), _opt("--score-file", "File holding the score"),
                      _opt("--config", "Config file to include in the plan; repeat for more"),
                      _opt("--max-attempts", "Plan attempt limit"),
                      _opt("--no-anchor", "Skip the timestamp request", value=False),
                      _opt("--repeat", "Number of attempts to run"),
                      _opt("--setup", "Setup file: dataset, harness, model and decoding settings"),
                      _opt("--no-tsa", "Skip the instant timestamp services", value=False),
                      _opt("--tsa", "Timestamp service URL; repeat for more")],
             note="This runs the command you give it. Run only commands you trust."),
    _command("score", "Show the real score and claim line for a plan.", {"stdout": ["tallylock.score.v1"]},
             {"reads": "The git repository's plans."}, options=[_opt("--plan", "Plan ID prefix")]),
    _command("check", "Check a pasted claim line against this repository.", {"stdout": ["tallylock.claim-check.v1"]},
             {"reads": "The git repository's plans."}, arguments=[_arg("claim", "The claim line, in quotes")],
             note="Exit code 3 means the claim did not match or the plan was not found."),
    _command("refresh", "Recover, re-stamp and upgrade the timestamps of ledger heads.", {"stdout": ["tallylock.refresh.v1"]},
             {"reads": "The repository's plans.", "writes": "Timestamp files in .tallylock/plans.",
              "network": "Timestamp services and OpenTimestamps calendars."}, options=[_opt("--plan", "Plan ID prefix")]),
    _command("export", "Copy one plan into a bundle that verifies on its own, or write an in-toto statement.",
             {"stdout": ["tallylock.export.v1"], "files": ["bundle folder with .tallylock/plans/<id>", "in-toto Statement v1 JSON"]},
             {"reads": "The repository's plan folder.", "writes": "The bundle folder or statement file at --out."},
             arguments=[_arg("plan", "Plan ID prefix")],
             options=[_opt("--out", "Bundle folder or statement file to create", required=True),
                      _opt("--format", "What to write", choices=["bundle", "intoto"])],
             note="Bundles include the full stdout and stderr of every run. Read them before you publish."),
    _command("registry add", "Verify a plan and add it to a registry folder.",
             {"stdout": ["tallylock.registry-entry.v1"]},
             {"reads": "The bundle or repository.", "writes": "entries/<plan_id> in the registry."},
             arguments=[_arg("registry", "Registry folder"), _arg("source", "Bundle or repository"), _arg("plan", "Plan ID prefix")],
             options=[_opt("--title", "Entry title", required=True), _opt("--trust", "Trust level", required=True,
                                                                       choices=["anchored", "signed", "declared"]),
                      _opt("--submitted-by", "Who submitted it", required=True)]),
    _command("registry verify", "Re-verify every entry in a registry.", {"stdout": ["tallylock.registry-verification.v1"]},
             {"reads": "The registry folder."}, arguments=[_arg("registry", "Registry folder")],
             note="Exit code 3 means at least one entry failed."),
    _command("board", "Build a static board from a registry.", {"stdout": ["tallylock.board.v1"],
                                                               "files": ["index.html", "entries.json"]},
             {"reads": "The registry folder.", "writes": "index.html and entries.json in --out."},
             arguments=[_arg("registry", "Registry folder")], options=[_opt("--out", "Folder for the site", required=True)]),
    _command("compare", "Compare two plans: same setup, and is the gap just noise?", {"stdout": ["tallylock.compare.v1"]},
             {"reads": "The repository's plans."},
             arguments=[_arg("left", "First plan ID prefix"), _arg("right", "Second plan ID prefix")]),
    _command("adapters import", "Read another tool's records and label what they prove.",
             {"stdout": ["tallylock.adapter-import.v1"]}, {"reads": "The log or bundle file."},
             arguments=[_arg("kind", "inspect or proofbundle"), _arg("path", "Log or bundle file")],
             note="Inspect logs are declared records. proofbundle files are checked for signatures and anchors."),
    _command("capabilities", "Print every command as machine-readable JSON.", {"stdout": ["tallylock.capabilities.v1"]},
             {"reads": "Nothing."}),
    _command("agent-guide", "Print the guide for AI assistants.", {"stdout": ["tallylock.agent-guide.v1"]},
             {"reads": "The packaged guide."}),
]
_DATA = {"format": FORMAT, "tool": "tallylock",
         "common_options": [_opt("--json", "Print one JSON report line", value=False),
                            _opt("--human", "Print a short plain-language summary", value=False)],
         "exit_codes": _EXIT_CODES, "commands": _COMMANDS,
         "notes": ["Give at most one of --json and --human. Without either, output is JSON when piped.",
                   "Every listed command is available in this version."]}


def capabilities() -> dict:
    return json.loads(capabilities_json())


def capabilities_json() -> str:
    return json.dumps(_DATA, indent=2, ensure_ascii=True) + "\n"
