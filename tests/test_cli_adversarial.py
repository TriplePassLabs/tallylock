"""Main-owned consumer tests and the real second-bind output-placement check."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def command(cwd, *arguments, code=0):
    result = subprocess.run([sys.executable, "-I", "-m", "tallylock", *map(str, arguments)],
                            cwd=cwd, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == code, (result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    value = json.loads(result.stdout)
    assert value["code"] == code
    return value


def registration(tmp_path):
    command(tmp_path, "init", "--out", "manifest.json")
    command(tmp_path, "pre-register", "manifest.json", "--receipt", "receipt")
    return tmp_path / "receipt"


def test_rejected_source_filename_is_actionable_without_source_changes(tmp_path):
    receipt = registration(tmp_path)
    manifest = (receipt / "manifest.json").read_bytes()
    source = tmp_path / "outputs"
    source.mkdir()
    name = "forbidden:name.txt"
    (source / name).write_bytes(b"unchanged external data")
    answer = command(tmp_path, "seal", "receipt", "--artifacts", "outputs", code=2)
    assert name in " ".join(error["message"] for error in answer["errors"])
    assert (source / name).read_bytes() == b"unchanged external data"
    assert (receipt / "manifest.json").read_bytes() == manifest
    assert not (receipt / "result.json").exists()


def test_bad_manifest_reports_field_without_reflecting_its_value(tmp_path):
    command(tmp_path, "init", "--out", "manifest.json")
    path = tmp_path / "manifest.json"
    manifest = json.loads(path.read_bytes())
    marker = "PRIVATE_PAYLOAD_VALUE_DO_NOT_REFLECT"
    manifest["budget"]["max_calls"] = marker
    path.write_text(json.dumps(manifest))
    answer = command(tmp_path, "pre-register", "manifest.json", "--receipt", "receipt", code=2)
    messages = " ".join(error["message"] for error in answer["errors"])
    assert "budget.max_calls" in messages
    assert marker not in json.dumps(answer)
    assert not (tmp_path / "receipt").exists()


def test_verify_cli_does_not_import_producer_or_use_sockets(tmp_path):
    registration(tmp_path)
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    (outputs / "plain.txt").write_text("ordinary output")
    command(tmp_path, "seal", "receipt", "--artifacts", "outputs")
    bootstrap = r'''
import importlib.abc, sys
class DenyProducer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'tallylock.store', 'tallylock.timestamping', 'tallylock.transport', 'tallylock.evidence'}:
            raise AssertionError('verification imported producer/online code')
sys.meta_path.insert(0, DenyProducer())
def no_socket(event, arguments):
    if event.startswith('socket.'):
        raise AssertionError('verification attempted a socket operation')
sys.addaudithook(no_socket)
from tallylock.cli import main
raise SystemExit(main(['verify', 'receipt', '--policy', 'integrity-only', '--chain-cache', 'absent.json']))
'''
    result = subprocess.run([sys.executable, "-I", "-c", bootstrap], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not result.stderr
    assert json.loads(result.stdout)["record_integrity"]["state"] == "checked"


@pytest.mark.parametrize("sealed", [False, True])
def test_explicit_anchor_failure_reports_known_existing_local_state(tmp_path, sealed):
    registration(tmp_path)
    if sealed:
        outputs = tmp_path / "outputs"
        outputs.mkdir()
        (outputs / "plain.txt").write_bytes(b"ordinary output")
        command(tmp_path, "seal", "receipt", "--artifacts", "outputs")
    bootstrap = r'''
from tallylock import timestamping
from tallylock.errors import TallyLockError
def fail(*args, **kwargs):
    raise TallyLockError('Synthetic calendar failure', code=5)
timestamping.submit = fail
from tallylock.cli import main
raise SystemExit(main(['anchor', 'receipt', '--target', 'manifest']))
'''
    result = subprocess.run([sys.executable, "-I", "-c", bootstrap], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 5, (result.stdout, result.stderr)
    answer = json.loads(result.stdout)
    assert answer["registration_id"]
    assert bool(answer["receipt_id"]) is sealed
    assert answer["local_state"] == ("sealed" if sealed else "registered")
    assert answer["anchor_action"] == {"state": "failed", "report": None}


def test_bind_alias_output_is_rejected_without_invalidating_receipt(tmp_path):
    selected = os.environ.get("TALLYLOCK_ALIAS_RECEIPT")
    if not selected:
        pytest.skip("requires main-owned second-bind worker")
    receipt = Path(selected)
    source = tmp_path / "independent-outputs"
    source.mkdir()
    (source / "input.txt").write_bytes(b"alias regression only")
    command(tmp_path, "seal", receipt, "--artifacts", source)
    valid = command(tmp_path, "verify", receipt, "--policy", "integrity-only")
    cores = {name: (receipt / name).read_bytes() for name in ("manifest.json", "result.json", "records.jsonl")}
    output = Path("/tallylock-source-alias/main-membership.json")
    command(tmp_path, "proof", "create", receipt, "--index", "0", "--out", output, code=2)
    assert not output.exists()
    for name, data in cores.items():
        assert (receipt / name).read_bytes() == data
    after = command(tmp_path, "verify", receipt, "--policy", "integrity-only")
    assert after["receipt_id"] == valid["receipt_id"]


def test_stdout_enospc_returns_operational_without_retry_or_traceback(tmp_path):
    with Path("/dev/full").open("wb") as full:
        result = subprocess.run([sys.executable, "-I", "-m", "tallylock", "init", "--out", "manifest.json"],
                                cwd=tmp_path, stdout=full, stderr=subprocess.PIPE, timeout=30, check=False)
    assert (tmp_path / "manifest.json").is_file()
    assert result.returncode == 5, result.stderr
    assert not result.stderr


def test_stdout_closed_fd_returns_operational_without_final_flush_failure(tmp_path):
    bootstrap = r'''
import os
from tallylock.cli import main
os.close(1)
raise SystemExit(main(['init', '--out', 'manifest.json']))
'''
    result = subprocess.run([sys.executable, "-I", "-c", bootstrap], cwd=tmp_path,
                            capture_output=True, timeout=30, check=False)
    assert (tmp_path / "manifest.json").is_file()
    assert result.returncode == 5, result.stderr
    assert not result.stderr


def test_stdout_absent_at_interpreter_startup_returns_operational(tmp_path):
    result = subprocess.run(["/bin/sh", "-c", 'exec "$1" -I -m tallylock init --out manifest.json 1>&-',
                             "prove-closed-stdout", sys.executable], cwd=tmp_path,
                            capture_output=True, timeout=30, check=False)
    assert (tmp_path / "manifest.json").is_file()
    assert result.returncode == 5, result.stderr
    assert not result.stderr
