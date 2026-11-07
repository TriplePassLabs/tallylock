"""Reference-only public contract tests; no production algorithms imported."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def reference():
    path = ROOT / "tools/reference_verify.py"
    assert path.is_file(), "independent materialized-wire verifier is missing"
    spec = importlib.util.spec_from_file_location("independent_reference", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_reference_contract():
    ref = reference()
    assert ref.canonical_bytes({"z": 1, "a": "\n"}) == b'{"a":"\\n","z":1}'
    assert ref.tree_root([]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert not ref.membership(b"x", 0, 0, [], "0" * 64)
    report = ref.verify_case({})
    assert report["code"] == 2
    assert set(report) == {"format", "code", "kind", "registration_id", "receipt_id", "root", "score", "checks", "errors", "limitations"}


@pytest.mark.parametrize("value", [1.0, float("nan"), 9007199254740992, "\ud800", {1: "key"}])
def test_canonical_profile_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        reference().canonical_bytes(value)


@pytest.mark.parametrize("raw", [b"1" * 5000, b"{" + b'"x":0,' * 2 + b'"x":0}', b"\xef\xbb\xbf{}",
                                 b"[" * 65 + b"0" + b"]" * 65, b" " * (8 * 1024 * 1024 + 1)])
def test_strict_parser_bounded_failures(raw):
    with pytest.raises(ValueError):
        reference().strict_json(raw)


def cli(path):
    result = subprocess.run([sys.executable, "-I", str(ROOT / "tools/reference_verify.py"), str(path)],
                            capture_output=True, timeout=10, check=False)
    assert not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert result.returncode == report["code"]
    return report


def test_cli_no_follow_regular_file_and_local_io_failures(tmp_path):
    path = tmp_path / "case.json"
    path.write_text("{}")
    assert cli(path)["code"] == 2
    assert cli(tmp_path / "absent")["code"] == 5
    link = tmp_path / "link"
    link.symlink_to(path)
    assert cli(link)["code"] == 5
    assert cli(tmp_path)["code"] == 5


def test_cli_fifo_fails_without_blocking_and_reports_io(tmp_path):
    import os
    path = tmp_path / "fifo"
    os.mkfifo(path)
    assert cli(path)["code"] == 5


def test_cli_size_limit_depth_and_conventional_help(tmp_path):
    path = tmp_path / "oversized"
    with path.open("wb") as stream:
        stream.truncate(8 * 1024 * 1024 + 1)
    assert cli(path)["code"] == 2
    result = subprocess.run([sys.executable, "-I", str(ROOT / "tools/reference_verify.py"), "--help"],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0 and b"usage:" in result.stdout


def test_materialized_path_never_becomes_a_filesystem_read(monkeypatch):
    import base64
    ref = reference()
    path = ROOT / "src/tallylock/data/conformance/cases/run-artifacts-unicode.json"
    value = json.loads(path.read_bytes())
    # The schemas are the only shared, fixed filesystem input to verify_case.
    ref._schema("manifest", json.loads(base64.b64decode(value["manifest"])))
    def forbidden(*args, **kwargs):
        raise AssertionError("materialized case attempted a filesystem operation")
    monkeypatch.setattr(ref.os, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    value["artifacts"]["../../outside"] = ""
    report = ref.verify_case(value)
    assert report["code"] == 2
    assert report["checks"]["artifacts"] == "invalid"


def test_reference_source_dependency_boundary():
    import ast
    tree = ast.parse((ROOT / "tools/reference_verify.py").read_text())
    dependencies = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            dependencies.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            dependencies.add(node.module.split(".")[0])
    assert "tallylock" not in dependencies and "rfc8785" not in dependencies
    assert dependencies <= set(sys.stdlib_module_names) | {"jsonschema"}
