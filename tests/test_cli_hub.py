"""CLI wiring for export, registry, board, adapters, refresh, capabilities and the agent guide."""
import json
import sys
from pathlib import Path

import pytest

from tallylock import cli, ledger
from test_ledger import FakeGit

FIXTURES = Path(__file__).parent/"fixtures"/"adapters"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path/"repo"
    root.mkdir()
    monkeypatch.setattr(cli, "_repo", lambda: root)
    monkeypatch.setattr(ledger, "_git", FakeGit())
    return root


def call(capsys, *argv):
    code = cli.main(list(argv))
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1, lines
    return code, json.loads(lines[0])


def recorded(capsys, runs=3):
    code, report = call(capsys, "run", "--json", "--no-anchor", "--repeat", str(runs), "--",
                        sys.executable, "-c", "import sys; print(f'tallylock: score=0.{sys.argv[1]}')", "{seed}")
    assert code == 0
    return report["plan_id"]


def test_export_bundle_registry_and_board(repo, tmp_path, capsys):
    plan = recorded(capsys)
    code, exported = call(capsys, "export", "--json", plan[:8], "--out", str(tmp_path/"bundle"))
    assert code == 0 and exported["kind"] == "bundle" and "stdout and stderr" in exported["note"]
    registry = tmp_path/"registry"
    code, entry = call(capsys, "registry", "add", "--json", str(registry), str(tmp_path/"bundle"), plan[:8],
                       "--title", "Demo <eval>", "--trust", "declared", "--submitted-by", "tests")
    assert code == 0 and entry["plan_id"] == plan
    code, checked = call(capsys, "registry", "verify", "--json", str(registry))
    assert code == 0 and checked["verified"] == 1 and checked["failed"] == 0
    code, built = call(capsys, "board", "--json", str(registry), "--out", str(tmp_path/"site"))
    assert code == 0 and built["rows"] == 1
    page = (tmp_path/"site"/"index.html").read_text()
    assert "Demo &lt;eval&gt;" in page and "<script" not in page


def test_registry_verify_fails_on_tampered_entry(repo, tmp_path, capsys):
    plan = recorded(capsys)
    registry = tmp_path/"registry"
    call(capsys, "registry", "add", "--json", str(registry), str(repo), plan[:8],
         "--title", "Demo", "--trust", "declared", "--submitted-by", "tests")
    ledger_file = next((registry/"entries"/plan).rglob("ledger.jsonl"))
    lines = ledger_file.read_bytes().splitlines(keepends=True)
    ledger_file.write_bytes(lines[0] + lines[1].replace(b'"exit_code":0', b'"exit_code":1') + b"".join(lines[2:]))
    code, checked = call(capsys, "registry", "verify", "--json", str(registry))
    assert code == 3 and checked["failed"] == 1


def test_export_intoto_statement(repo, tmp_path, capsys):
    plan = recorded(capsys, runs=2)
    out = tmp_path/"statement.json"
    code, exported = call(capsys, "export", "--json", plan[:8], "--out", str(out), "--format", "intoto")
    statement = json.loads(out.read_text())
    assert code == 0 and exported["note"] is None
    assert statement["_type"] == "https://in-toto.io/Statement/v1" and len(statement["subject"]) == 2


def test_adapters_import_inspect_and_proofbundle(capsys):
    inspect_log = next(p for p in FIXTURES.iterdir() if p.suffix in (".eval", ".json") and "inspect" in p.name.lower())
    code, report = call(capsys, "adapters", "import", "--json", "inspect", str(inspect_log))
    assert code == 0 and report["trust"] == "declared" and report["records"]
    bundles = [p for p in FIXTURES.iterdir() if "proofbundle" in p.name.lower() or p.suffix == ".pb"]
    if bundles:
        code, report = call(capsys, "adapters", "import", "--json", "proofbundle", str(bundles[0]))
        assert report["kind"] == "proofbundle" and code in (0, 3)


def test_refresh_calls_recover_stamp_and_upgrade(repo, capsys, monkeypatch):
    plan = recorded(capsys, runs=1)
    calls = []
    for name in ("recover", "timestamp_head", "upgrade_heads"):
        monkeypatch.setattr(ledger, name, lambda repo, plan_id, _n=name, **kw: calls.append(_n) or {"state": "ok"})
    code, report = call(capsys, "refresh", "--json")
    assert code == 0 and [p["plan_id"] for p in report["plans"]] == [plan]
    assert calls == ["recover", "timestamp_head", "upgrade_heads"]


def test_capabilities_and_agent_guide(capsys):
    code, caps = call(capsys, "capabilities", "--json")
    assert code == 0 and all(item["status"] == "available" for item in caps["commands"])
    code = cli.main(["agent-guide", "--human"])
    text = capsys.readouterr().out
    assert code == 0 and "tallylock" in text.lower()


def test_verify_rejects_online_with_offline(capsys, tmp_path):
    code, report = call(capsys, "verify", "--json", str(tmp_path), "--online", "--offline")
    assert code == 2 and "--online or --offline" in report["errors"][0]["message"]


def test_compare_two_plans(repo, capsys):
    left = recorded(capsys, runs=3)
    code, report = call(capsys, "run", "--json", "--no-anchor", "--repeat", "3", "--",
                        sys.executable, "-c", "import sys; print(f'tallylock: score=0.{sys.argv[1]}'); print('v2')", "{seed}")
    right = report["plan_id"]
    code, compared = call(capsys, "compare", "--json", left[:8], right[:8])
    assert code == 0 and compared["format"] == "tallylock.compare.v1"
    assert compared["verdict"] == "statistically tied" and compared["plain"]
