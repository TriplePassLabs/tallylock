"""Both independent consumers against committed, fixed public wire examples."""
import base64
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

import pytest

from tallylock import canonical, merkle, verify


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "src/tallylock/data/conformance"
INDEX = json.loads((CORPUS / "index.json").read_bytes())["cases"]
CANONICAL = json.loads((CORPUS / "canonical.json").read_bytes())
TREES = json.loads((CORPUS / "trees.json").read_bytes())

# -I removes project PYTHONPATH. The importer also makes the installed producer
# and its canonicalization dependency unavailable, including transitive imports.
ISOLATED = r'''
import importlib.abc, runpy, socket, sys
class Unavailable(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('tallylock', 'rfc8785'):
            raise ModuleNotFoundError('production imports unavailable in reference')
sys.meta_path.insert(0, Unavailable())
def offline(*args, **kwargs):
    raise AssertionError('reference attempted network access')
socket.socket.connect = offline
socket.socket.connect_ex = offline
socket.create_connection = offline
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''


def reference_module():
    spec = importlib.util.spec_from_file_location("wire_reference", ROOT / "tools/reference_verify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def invoke(path):
    result = subprocess.run([sys.executable, "-I", "-c", ISOLATED, str(ROOT / "tools/reference_verify.py"), str(path)],
                            capture_output=True, check=False, timeout=15, cwd=path.parent,
                            env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert result.returncode == report["code"]
    return report


def materialize(value, directory):
    """Only the production test side creates files, in a fresh private root."""
    directory.mkdir()
    for field, name in (("manifest", "manifest.json"), ("result", "result.json"), ("records", "records.jsonl")):
        raw = base64.b64decode(value[field], validate=True)
        assert len(raw) < 1024 * 1024
        (directory / name).write_bytes(raw)
    artifact_root = directory / "artifacts"
    artifact_root.mkdir()
    assert len(value["artifacts"]) <= 32
    for name, encoded in value["artifacts"].items():
        # This guard is intentionally separate from both protocol validators.
        path = PurePosixPath(name)
        assert name == path.as_posix() and not path.is_absolute()
        assert all(part not in ("", ".", "..") and "\\" not in part and ":" not in part for part in name.split("/"))
        assert all(ord(character) >= 32 and ord(character) != 127 for character in name)
        raw = base64.b64decode(encoded, validate=True)
        assert len(raw) <= 65536
        target = artifact_root.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


@pytest.mark.parametrize("vector", CANONICAL, ids=lambda row: row["name"])
def test_fixed_canonical_bytes_in_both_consumers(vector):
    expected = bytes.fromhex(vector["hex"])
    assert reference_module().canonical_bytes(vector["value"]) == expected
    assert canonical.dumps(vector["value"]) == expected


@pytest.mark.parametrize("vector", TREES, ids=lambda row: str(row["size"]))
def test_fixed_tree_roots_and_every_branch_in_both_consumers(vector):
    leaves = [base64.b64decode(value) for value in vector["leaves"]]
    ref = reference_module()
    assert ref.tree_root(leaves) == merkle.root(leaves) == vector["root"]
    assert len(vector["paths"]) == vector["size"]
    for branch in vector["paths"]:
        position, siblings = branch["index"], branch["siblings"]
        assert merkle.proof(leaves, position) == siblings
        assert ref.membership(leaves[position], position, len(leaves), siblings, vector["root"])
        assert merkle.verify(leaves[position], position, len(leaves), siblings, vector["root"])
        assert not ref.membership(leaves[position], position, len(leaves), siblings + ["0" * 64], vector["root"])


@pytest.mark.parametrize("case", INDEX, ids=lambda row: row["file"])
def test_fixed_corpus_isolated_reference_and_production_overlap(case, tmp_path):
    path = CORPUS / case["file"]
    report = invoke(path)
    assert {key: report[key] for key in case["expected"]} == case["expected"], report
    assert set(report) == {"format", "code", "kind", "registration_id", "receipt_id", "root", "score", "checks", "errors", "limitations"}
    assert set(report["checks"].values()) <= {"checked", "not_checked", "invalid", "unsupported"}
    assert len(report["errors"]) <= 16 and all(len(error) <= 1024 for error in report["errors"])
    stage = case["failure_stage"]
    if stage in report["checks"]:
        assert report["checks"][stage] in ("invalid", "unsupported"), report
    if report["kind"] == "inclusion":
        assert all(report["checks"][key] == "not_checked" for key in ("artifacts", "records", "scoring"))
        assert report["score"] is None
    if not case["production_overlap"]:
        return
    value = json.loads(path.read_bytes())
    if value["kind"] == "inclusion":
        product = verify.inclusion(value["inclusion"], policy="integrity-only")
    else:
        materialize(value, tmp_path / "receipt")
        product = verify.full(tmp_path / "receipt", policy="integrity-only")
    assert product.code == case["expected"]["code"], product.report
    if product.code == 0:
        for key in ("registration_id", "receipt_id"):
            assert product.report[key] == case["expected"][key]
        assert product.report["record_integrity"]["root"] == case["expected"]["root"]
        if value["kind"] == "inclusion":
            assert product.report["record_integrity"]["state"] == "membership_checked"
            assert product.report["score"]["state"] == "not_checked"
            assert product.report["resources"]["state"] == "not_checked"
            assert product.report["coverage"]["state"] == "not_checked"
        else:
            assert product.report["score"]["state"] == report["score"]["state"]
            assert product.report["score"]["aggregate"] == report["score"]["aggregate"]


def test_corpus_rebound_math_state_and_inclusion_negatives_target_the_declared_checks():
    ref = reference_module()
    names = {Path(case["file"]).stem: case for case in INDEX}
    for name in ("bad-false-math", "bad-false-math-all-hashes", "bad-resources", "bad-budget", "bad-retry-forward",
                 "bad-call-before-start", "bad-call-after-end", "bad-missing-coverage", "bad-early-terminal", "bad-event-binding",
                 "bad-completed-reason", "bad-second-score-role", "bad-future-fixture-dataset", "bad-future-fixture-scores",
                 "bad-future-result-score-profile", "bad-future-event-kind", "bad-known-subtotal-overflow"):
        value = json.loads((CORPUS / names[name]["file"]).read_bytes())
        result = json.loads(base64.b64decode(value["result"]))
        raw = base64.b64decode(value["records"])
        import hashlib
        assert len(raw) == result["records"]["bytes"]
        assert hashlib.sha256(raw).hexdigest() == result["records"]["sha256"]
        leaves = raw[:-1].split(b"\n")
        assert ref.tree_root(leaves) == result["records"]["root"]
    for name in ("bad-inclusion-nonfinal-terminal", "bad-inclusion-final-call", "bad-inclusion-artifact-rank",
                 "bad-inclusion-first-call", "bad-inclusion-retry-position", "bad-inclusion-call-count",
                 "bad-inclusion-completed-size", "bad-inclusion-no-end-room", "bad-inclusion-no-pinned-dataset",
                 "inclusion-event-exact-limit", "bad-inclusion-event-over-limit"):
        value = json.loads((CORPUS / names[name]["file"]).read_bytes())["inclusion"]
        assert ref.membership(ref.canonical_bytes(value["event"]), value["index"], value["size"], value["siblings"], value["result"]["records"]["root"])


def test_mixed_inclusion_discriminators_isolate_one_malformed_shape():
    for filename, malformed in (("bad-inclusion-future-and-missing-event-format.json", "event"),
                                ("bad-inclusion-future-missing-manifest-format.json", "manifest"),
                                ("bad-inclusion-future-nonstring-result-format.json", "result"),
                                ("bad-inclusion-future-nonstring-event-format.json", "event")):
        value = json.loads((CORPUS / "cases" / filename).read_bytes())["inclusion"]
        assert value["format"] == "prove.inclusion.v2"
        for field in ("manifest", "result", "event"):
            assert (type(value[field].get("format")) is not str) == (field == malformed)
