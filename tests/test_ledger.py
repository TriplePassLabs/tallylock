"""Plan identity, attempt runs, the append-only ledger and its head anchors."""
import fcntl
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import time
from pathlib import Path

import pytest
from bitcoin.core import CBlockHeader
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

from tallylock import canonical, rfc3161, store, transport, verify
from tallylock.errors import TallyLockError
from test_chain import cache_for
from test_rfc3161 import Forge, recorded
from test_transport import reply, attested_reply


HEAD = "a1" * 20
TOOL = r'''
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
count = int((state/"count").read_text()) if (state/"count").exists() else 0
(state/"count").write_text(str(count + 1))
step = json.loads((state/"steps.json").read_text())[count]
sys.stdout.write(step.get("stdout", ""))
sys.stderr.write(step.get("stderr", ""))
for name, text in step.get("files", {}).items():
    path = pathlib.Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
sys.exit(step.get("exit", 0))
'''


def api():
    assert importlib.util.find_spec("tallylock.ledger") is not None, "run ledger missing"
    from tallylock import ledger
    return ledger


class FakeGit:
    def __init__(self, head=HEAD, diff=b""):
        self.head, self.diff, self.calls = head, diff, []

    def __call__(self, repo, args):
        self.calls.append(list(args))
        if args == ["rev-parse", "--is-inside-work-tree"]:
            return b"true\n"
        if args == ["rev-parse", "--verify", "HEAD"]:
            return (self.head + "\n").encode()
        if args[0] == "diff":
            return self.diff
        raise AssertionError(args)


class Project:
    """A temporary work tree with a scripted fake command and a fake git."""

    def __init__(self, root: Path, steps):
        self.repo, self.state = root/"repo", root/"state"
        self.repo.mkdir()
        self.state.mkdir()
        (self.repo/"tool.py").write_text(TOOL)
        (self.repo/"config.toml").write_text("seed = 1\n")
        (self.state/"steps.json").write_text(json.dumps(steps))
        self.argv = [sys.executable, str(self.repo/"tool.py"), str(self.state)]
        self.git = FakeGit()

    def plan(self, **options):
        options.setdefault("configs", ["config.toml"])
        return api().start_plan(self.repo, self.argv, git=self.git, **options)

    def run(self, plan, **options):
        options.setdefault("anchor", False)
        options.setdefault("tsa", False)
        options.setdefault("stdout", io.BytesIO())
        options.setdefault("stderr", io.BytesIO())
        return api().run_attempt(plan, **options)


def three_runs(tmp_path):
    project = Project(tmp_path, [
        {"stdout": "warming up\ntallylock: score=0.5\ntallylock: score=0.742\n"},
        {"stdout": "tallylock: score=0.9\n", "stderr": "boom\n", "exit": 1},
        {"stdout": "tallylock: score=74/100\n"},
    ])
    plan = project.plan()
    reports = [project.run(plan) for _ in range(3)]
    return project, plan, reports


def ledger_lines(plan):
    return (plan.directory/"ledger.jsonl").read_bytes().splitlines(keepends=True)


def test_plan_requires_git_work_tree(tmp_path):
    ledger = api()
    def not_a_tree(repo, args):
        raise TallyLockError("fatal: not a git repository", code=5)
    with pytest.raises(TallyLockError) as error:
        ledger.start_plan(tmp_path, ["true"], git=not_a_tree)
    assert "git work tree" in error.value.message
    with pytest.raises(TallyLockError) as error:
        ledger.start_plan(tmp_path, ["true"], git=lambda repo, args: b"false\n")
    assert "git work tree" in error.value.message
    # The real runner fails the same clear way, whether or not git is installed.
    with pytest.raises(TallyLockError) as error:
        ledger.start_plan(tmp_path, ["true"])
    assert "git work tree" in error.value.message
    assert not (tmp_path/".tallylock").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="worker image has no git binary")
def test_real_git_identity(tmp_path):
    import subprocess
    ledger = api()
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path/"a.txt").write_text("one\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "a.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@e",
                    "commit", "-qm", "init"], check=True)
    first = ledger.plan_identity(tmp_path, ["true"])
    (tmp_path/".tallylock").mkdir()
    (tmp_path/".tallylock/x").write_text("ignored")
    assert ledger.plan_identity(tmp_path, ["true"]) == first
    (tmp_path/"a.txt").write_text("two\n")
    assert ledger.plan_identity(tmp_path, ["true"])["key"] != first["key"]


def test_plan_key_binds_every_input_and_excludes_ledger_state(tmp_path):
    ledger = api()
    (tmp_path/"cfg.json").write_text("{}")
    git = FakeGit()
    base = ledger.plan_identity(tmp_path, ["python", "x.py"], configs=["cfg.json"], git=git)
    assert base["head"] == HEAD
    assert base["diff_sha256"] == hashlib.sha256(b"").hexdigest()
    assert base["argv"] == ["python", "x.py"]
    assert base["configs"] == {"cfg.json": hashlib.sha256(b"{}").hexdigest()}
    assert base["max_attempts"] == 100
    assert base["key"] == canonical.digest({k: v for k, v in base.items() if k != "key"})
    diff = next(call for call in git.calls if call[0] == "diff")
    assert "HEAD" in diff and ":(exclude).tallylock" in diff
    variants = [
        ledger.plan_identity(tmp_path, ["python", "x.py"], configs=["cfg.json"], git=FakeGit(head="b2" * 20)),
        ledger.plan_identity(tmp_path, ["python", "x.py"], configs=["cfg.json"], git=FakeGit(diff=b"+x\n")),
        ledger.plan_identity(tmp_path, ["python", "y.py"], configs=["cfg.json"], git=FakeGit()),
        ledger.plan_identity(tmp_path, ["python", "x.py"], configs=["cfg.json"], max_attempts=5, git=FakeGit()),
        ledger.plan_identity(tmp_path, ["python", "x.py"], git=FakeGit()),
    ]
    (tmp_path/"cfg.json").write_text('{"a": 1}')
    variants.append(ledger.plan_identity(tmp_path, ["python", "x.py"], configs=["cfg.json"], git=FakeGit()))
    keys = {base["key"]} | {value["key"] for value in variants}
    assert len(keys) == 7
    with pytest.raises(TallyLockError):
        ledger.plan_identity(tmp_path, [], git=FakeGit())
    with pytest.raises(TallyLockError):
        ledger.plan_identity(tmp_path, ["x"], configs=["missing.toml"], git=FakeGit())
    with pytest.raises(TallyLockError):
        ledger.plan_identity(tmp_path, ["x"], max_attempts=0, git=FakeGit())


def test_plan_manifest_is_frozen_with_pre_register_and_named_by_registration(tmp_path):
    ledger = api()
    project = Project(tmp_path, [])
    plan = project.plan(max_attempts=4)
    assert plan.created is True
    assert plan.directory == project.repo/".tallylock/plans"/plan.plan_id
    frozen = (plan.directory/"manifest.json").read_bytes()
    assert hashlib.sha256(frozen).hexdigest() == plan.plan_id
    manifest = canonical.loads(frozen)
    assert [a["id"] for a in manifest["attempts"]] == ["run-1", "run-2", "run-3", "run-4"]
    assert all(a["sample_ids"] == [] for a in manifest["attempts"])
    info = manifest["metadata"]["tallylock_plan"]
    assert info["format"] == "tallylock.plan.v1"
    assert info["key"] == plan.key == ledger.plan_identity(
        project.repo, project.argv, configs=["config.toml"], max_attempts=4, git=FakeGit())["key"]
    assert info["plan_number"] == 1
    assert store.load_manifest(plan.directory/"attempts/run-1") == manifest
    assert (plan.directory/"attempts/run-1/manifest.json").read_bytes() == frozen
    default = api().start_plan(project.repo, project.argv, git=project.git)
    assert len(canonical.loads((default.directory/"manifest.json").read_bytes())["attempts"]) == 100


def test_same_key_reuses_plan_and_changed_config_starts_new_one(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1/2\n"}] * 3)
    first = project.plan()
    project.run(first)
    again = project.plan()
    assert again.plan_id == first.plan_id and again.created is False
    (project.repo/"config.toml").write_text("seed = 2\n")
    second = project.plan()
    assert second.created is True and second.plan_id != first.plan_id
    assert canonical.loads((second.directory/"manifest.json").read_bytes())["metadata"]["tallylock_plan"]["plan_number"] == 2
    assert sorted(ledger.list_plans(project.repo)) == sorted([first.plan_id, second.plan_id])
    assert len(ledger_lines(first)) == 1
    assert ledger.verify_ledger(project.repo, first.plan_id)["entries"] == 1
    assert ledger.verify_ledger(project.repo, second.plan_id)["entries"] == 0


def test_three_runs_one_failing_give_three_of_three(tmp_path):
    ledger = api()
    project, plan, reports = three_runs(tmp_path)
    assert [r["outcome"] for r in reports] == ["completed", "failed", "completed"]
    assert [r["exit_code"] for r in reports] == [0, 1, 0]
    assert [r["attempt_id"] for r in reports] == ["run-1", "run-2", "run-3"]
    assert all(r["anchor"] == {"state": "not_requested"} for r in reports)
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert checked["entries"] == 3 and checked["receipts_verified"] == 3
    lines = ledger_lines(plan)
    assert checked["head_sha256"] == ledger.ledger_head(project.repo, plan.plan_id) \
        == hashlib.sha256(lines[-1][:-1]).hexdigest()
    previous = None
    for seq, line in enumerate(lines, 1):
        assert line.endswith(b"\n")
        entry = canonical.loads(line[:-1])
        assert canonical.dumps(entry) == line[:-1]
        assert set(entry) == {"format", "plan_id", "seq", "attempt_id", "receipt_id", "outcome",
                              "exit_code", "duration_ms", "score", "argv", "prev_sha256"}
        assert entry["format"] == "tallylock.ledger-entry.v1"
        assert entry["plan_id"] == plan.plan_id and entry["seq"] == seq
        assert entry["argv"] == project.argv and entry["prev_sha256"] == previous
        assert type(entry["duration_ms"]) is int and entry["duration_ms"] >= 0
        receipt = plan.directory/"attempts"/entry["attempt_id"]
        assert hashlib.sha256((receipt/"result.json").read_bytes()).hexdigest() == entry["receipt_id"]
        assert verify.full(receipt, policy="integrity-only").code == 0
        previous = hashlib.sha256(line[:-1]).hexdigest()
    entries = [canonical.loads(line[:-1]) for line in lines]
    assert [e["score"] for e in entries] == [{"numerator": 742, "denominator": 1000},
                                             {"numerator": 9, "denominator": 10},
                                             {"numerator": 74, "denominator": 100}]
    failed = canonical.loads((plan.directory/"attempts/run-2/result.json").read_bytes())
    assert failed["outcome"] == "failed" and failed["reason"] == "exit code 1"
    completed = canonical.loads((plan.directory/"attempts/run-1/result.json").read_bytes())
    assert completed["outcome"] == "completed" and completed["reason"] is None
    assert completed["score"]["aggregate"] == {"numerator": 742, "denominator": 1000}
    assert completed["inventory"]["stdout.log"]["role"] == "stdout"
    assert (plan.directory/"attempts/run-2/artifacts/stderr.log").read_bytes() == b"boom\n"


def test_output_streams_to_terminal_and_capture_is_bounded(tmp_path, monkeypatch):
    ledger = api()
    monkeypatch.setattr(ledger, "STREAM_LIMIT", 100)
    project = Project(tmp_path, [{"stdout": "x" * 1000 + "\ntallylock: score=3/4\n", "stderr": "e" * 150}])
    plan = project.plan()
    out, err = io.BytesIO(), io.BytesIO()
    report = project.run(plan, stdout=out, stderr=err)
    assert out.getvalue() == b"x" * 1000 + b"\ntallylock: score=3/4\n"
    assert err.getvalue() == b"e" * 150
    artifacts = plan.directory/"attempts/run-1/artifacts"
    assert (artifacts/"stdout.log").read_bytes() == b"x" * 100
    assert (artifacts/"stderr.log").read_bytes() == b"e" * 100
    assert report["score"] == {"numerator": 3, "denominator": 4}
    result = canonical.loads((plan.directory/"attempts/run-1/result.json").read_bytes())
    streams = result["metadata"]["tallylock_attempt"]["streams"]
    assert streams["stdout"] == {"bytes": 1022, "captured": 100, "truncated": True}
    assert streams["stderr"] == {"bytes": 150, "captured": 100, "truncated": True}


def test_argv_runs_without_shell(tmp_path):
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}])
    project.argv = [sys.executable, "-c", "import sys; print(sys.argv[1])", "$HOME; echo hacked"]
    plan = project.plan()
    out = io.BytesIO()
    project.run(plan, stdout=out)
    assert out.getvalue().strip() == b"$HOME; echo hacked"


@pytest.mark.parametrize("text, expected", [
    ("tallylock: score=0.742\n", {"numerator": 742, "denominator": 1000}),
    ("tallylock: score=74/100\n", {"numerator": 74, "denominator": 100}),
    ("tallylock: score=1\n", {"numerator": 1, "denominator": 1}),
    ("tallylock: score=0.1\nnoise\ntallylock: score=2/3\nmore noise\n", {"numerator": 2, "denominator": 3}),
    ("tallylock: score=2/3\r\ntallylock: score=0.25", {"numerator": 25, "denominator": 100}),
    ("no score here\n", None),
    ("", None),
    ("tallylock: score=1/0\n", None),
    ("tallylock: score=-0.5\n", None),
    ("tallylock: score=1e3\n", None),
    ("tallylock: score=0.5 extra\n", None),
    ("  tallylock: score=0.5\n", None),
    ("tallylock: score=0.5\ntallylock: score=bad\n", {"numerator": 5, "denominator": 10}),
    ("tallylock: score=99999999999999999999\n", None),
])
def test_score_parsing(text, expected):
    assert api().parse_score(text.encode()) == expected


def test_score_file_and_absent_score(tmp_path):
    project = Project(tmp_path, [
        {"stdout": "tallylock: score=0.1\n", "files": {"out/score.json": '{"numerator": 7, "denominator": 8}'}},
        {"stdout": "nothing\n"},
        {"files": {"out/score.json": '{"numerator": 1.5, "denominator": 8}'}},
    ])
    plan = project.plan()
    score_file = project.repo/"out/score.json"
    first = project.run(plan, score_file=score_file)
    assert first["score"] == {"numerator": 7, "denominator": 8}
    receipt = canonical.loads((plan.directory/"attempts/run-1/result.json").read_bytes())
    assert receipt["score"]["path"] == "score.json"
    assert receipt["metadata"]["tallylock_attempt"]["score_source"] == "score_file"
    score_file.unlink()
    assert project.run(plan)["score"] is None
    third = project.run(plan, score_file=score_file)
    assert third["score"] is None
    entries = api().verify_ledger(project.repo, plan.plan_id)
    assert entries["entries"] == 3


def test_declared_outputs_are_sealed(tmp_path):
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n", "files": {"results/a.txt": "A", "results/sub/b.txt": "B"}}])
    plan = project.plan()
    project.run(plan, outputs=project.repo/"results")
    inventory = canonical.loads((plan.directory/"attempts/run-1/result.json").read_bytes())["inventory"]
    assert set(inventory) == {"stdout.log", "stderr.log", "score.json", "outputs/a.txt", "outputs/sub/b.txt"}


def test_attempt_budget_and_single_writer(tmp_path):
    project = Project(tmp_path, [{}] * 3)
    plan = project.plan(max_attempts=2)
    project.run(plan)
    with open(plan.directory/"run.lock", "a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(TallyLockError) as error:
            project.run(plan)
        assert error.value.code == 5
    project.run(plan)
    with pytest.raises(TallyLockError) as error:
        project.run(plan)
    assert "all 2 attempts" in error.value.message
    assert len(ledger_lines(plan)) == 2


def rewrite(plan, lines):
    (plan.directory/"ledger.jsonl").write_bytes(b"".join(lines))


def edit_line(line, **changes):
    entry = canonical.loads(line[:-1])
    entry.update(changes)
    return canonical.dumps(entry) + b"\n"


@pytest.mark.parametrize("tamper, kind", [
    (lambda lines: [lines[0], edit_line(lines[1], exit_code=0), lines[2]], "edited"),
    (lambda lines: [lines[0], lines[1], edit_line(lines[2], score={"numerator": 99, "denominator": 100})], "edited"),
    (lambda lines: [lines[0], lines[1], edit_line(lines[2], outcome="failed")], "edited"),
    (lambda lines: [lines[0], lines[2]], "removed"),
    (lambda lines: [lines[1], lines[2]], "removed"),
    (lambda lines: [lines[0], lines[1]], "removed"),
    (lambda lines: [lines[0], lines[2], lines[1]], "reordered"),
    (lambda lines: [lines[1], lines[0], lines[2]], "reordered"),
    (lambda lines: [lines[0], lines[1], lines[1], lines[2]], "duplicated"),
    (lambda lines: [lines[0], lines[1], lines[2][:-1]], "malformed"),
    (lambda lines: [lines[0], b"{not json}\n", lines[2]], "malformed"),
])
def test_ledger_tampering_fails_distinctly(tmp_path, tamper, kind):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    rewrite(plan, tamper(ledger_lines(plan)))
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == kind
    assert error.value.code == 2


def test_rechained_edit_is_caught_by_receipt_check(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    lines = ledger_lines(plan)
    forged, previous = [], None
    for line in lines:
        entry = canonical.loads(line[:-1])
        if entry["seq"] == 2:
            entry["outcome"], entry["exit_code"] = "completed", 0
        entry["prev_sha256"] = previous
        data = canonical.dumps(entry)
        forged.append(data + b"\n")
        previous = hashlib.sha256(data).hexdigest()
    rewrite(plan, forged)
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "edited"


def test_damaged_attempt_receipt_fails_ledger(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    (plan.directory/"attempts/run-1/artifacts/stdout.log").write_bytes(b"changed")
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "receipt_invalid"


def bitcoin_submit(headers):
    def submit(origin, commitment, **kwargs):
        headers.append(CBlockHeader(hashMerkleRoot=commitment, nTime=1700000000).serialize())
        return attested_reply(commitment, BitcoinBlockHeaderAttestation(1))
    return submit


def test_anchor_head_stores_proof_and_verifies_offline(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    calls = []
    def submit(origin, commitment, **kwargs):
        calls.append(origin)
        return reply(commitment, origin)
    report = ledger.anchor_head(project.repo, plan.plan_id, submit=submit)
    assert report["seq"] == 3 and report["state"] == "pending"
    assert report["head_sha256"] == ledger.ledger_head(project.repo, plan.plan_id)
    assert len(calls) == 4
    proof = plan.directory/"ledger-head-3.ots"
    assert proof.is_file()
    assert ledger.verify_anchor(project.repo, plan.plan_id, 3)["state"] == "pending"
    again = ledger.anchor_head(project.repo, plan.plan_id, submit=submit)
    assert again["state"] == "unchanged" and len(calls) == 4
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert checked["anchors"] == [{"seq": 3, "state": "pending"}]


def test_anchored_head_with_cached_header_and_anchor_contradiction(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    headers = []
    ledger.anchor_head(project.repo, plan.plan_id, submit=bitcoin_submit(headers))
    cache = cache_for({1: headers[0]}, tip_height=6)
    assert ledger.verify_anchor(project.repo, plan.plan_id, 3, chain_cache=cache)["state"] == "anchored"
    assert ledger.verify_anchor(project.repo, plan.plan_id, 3)["state"] == "insufficient_chain"
    checked = ledger.verify_ledger(project.repo, plan.plan_id, chain_cache=cache)
    assert checked["anchors"] == [{"seq": 3, "state": "anchored"}]
    # Moving an anchored proof onto a different head is caught offline.
    (plan.directory/"ledger-head-3.ots").rename(plan.directory/"ledger-head-2.ots")
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "anchor_mismatch"
    (plan.directory/"ledger-head-2.ots").rename(plan.directory/"ledger-head-9.ots")
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "removed"


def test_run_anchors_by_default_and_failures_stay_pending(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}] * 2)
    plan = project.plan()
    def down(origin, commitment, **kwargs):
        raise TallyLockError("calendar request failed after bounded retries", code=5)
    report = project.run(plan, anchor=True, calendar_submit=down)
    assert report["outcome"] == "completed"
    assert report["anchor"]["state"] == "pending" and report["anchor"]["submitted"] is False
    assert not (plan.directory/"ledger-head-1.ots").exists()
    report = project.run(plan, anchor=True, calendar_submit=lambda origin, commitment, **kw: reply(commitment, origin))
    assert report["anchor"] == {"state": "pending", "submitted": True, "seq": 2,
                                "proof": ".tallylock/plans/" + plan.plan_id + "/ledger-head-2.ots"}
    assert ledger.verify_ledger(project.repo, plan.plan_id)["anchors"] == [{"seq": 2, "state": "pending"}]


def test_seed_placeholder_keeps_one_plan(tmp_path):
    ledger = api()
    project = Project(tmp_path, [])
    argv = [sys.executable, "-c", "import os, sys; print('seed', sys.argv[1], os.environ['TALLYLOCK_SEED'])", "{seed}"]
    plan = ledger.start_plan(project.repo, argv, git=project.git)
    outputs = [io.BytesIO(), io.BytesIO()]
    reports = [project.run(plan, stdout=out) for out in outputs]
    assert [out.getvalue() for out in outputs] == [b"seed 1 1\n", b"seed 2 2\n"]
    assert [r["executed_argv"][-1] for r in reports] == ["1", "2"]
    assert ledger.start_plan(project.repo, argv, git=project.git).plan_id == plan.plan_id
    entries = [json.loads(line) for line in ledger_lines(plan)]
    assert [entry["argv"] for entry in entries] == [argv, argv]
    assert ledger.verify_ledger(project.repo, plan.plan_id)["entries"] == 2


SETUP = {"dataset": {"name": "gsm8k", "version": "1.0", "sha256": "ab" * 32},
         "harness": {"name": "lm-eval", "version": "0.4.2"}, "prompt_template_sha256": "cd" * 32,
         "decoding": {"temperature": "0.7", "max_tokens": 512, "greedy": False},
         "model": {"name": "qwen", "revision": "main"}, "notes": "first pass"}


def write_setup(project, value, name="setup.json"):
    path = project.repo/name
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    return path


def plan_info(plan):
    return canonical.loads((plan.directory/"manifest.json").read_bytes())["metadata"]["tallylock_plan"]


def test_setup_file_is_frozen_into_the_plan_and_its_identity(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}])
    plain = project.plan()
    assert "setup" not in plan_info(plain)
    assert "setup" not in ledger.plan_identity(project.repo, project.argv, configs=["config.toml"], git=FakeGit())
    path = write_setup(project, SETUP)
    plan = project.plan(setup=path)
    assert plan.created and plan.plan_id != plain.plan_id
    assert plan_info(plan)["setup"] == {"format": "tallylock.setup.v1", **SETUP}
    assert plan.key == ledger.plan_identity(project.repo, project.argv, configs=["config.toml"],
                                            setup=ledger.read_setup(path), git=FakeGit())["key"]
    # Reformatting the file or naming its format keeps the plan; changing a value starts a new one.
    path.write_text(json.dumps(SETUP, indent=2, sort_keys=True))
    assert project.plan(setup=path).plan_id == plan.plan_id
    write_setup(project, {"format": "tallylock.setup.v1", **SETUP})
    assert project.plan(setup=path).plan_id == plan.plan_id
    write_setup(project, {**SETUP, "notes": "second pass"})
    assert project.plan(setup=path).created is True
    write_setup(project, {})
    assert plan_info(project.plan(setup=path))["setup"] == {"format": "tallylock.setup.v1"}
    project.run(plan)
    assert ledger.verify_ledger(project.repo, plan.plan_id)["entries"] == 1


@pytest.mark.parametrize("text, words", [
    ('{"decoding": {"temperature": 0.7}}', "decimals as strings"),
    ('{"seed": 1}', "seed"),
    ('{"dataset": {"name": "x", "size": "3"}}', "size"),
    ('{"dataset": {"sha256": "' + "AB" * 32 + '"}}', "sha256"),
    ('{"prompt_template_sha256": "abc"}', "prompt_template_sha256"),
    ('{"decoding": {"stop": ["a"]}}', "decoding"),
    ('{"decoding": {"top_p": null}}', "decoding"),
    ('{"format": "tallylock.setup.v2"}', "tallylock.setup.v1"),
    ('[]', "object"),
    ('{"notes": 5}', "notes"),
    ('{"model": "qwen"}', "model"),
    ('{"harness": {"name": ""}}', "harness"),
    ('{"notes": "a", "notes": "b"}', "JSON"),
    ('{"notes": "' + "x" * 70000 + '"}', "64 KiB"),
    ("not json", "JSON"),
])
def test_setup_file_rejections_are_clear(tmp_path, text, words):
    project = Project(tmp_path, [])
    with pytest.raises(TallyLockError) as error:
        project.plan(setup=write_setup(project, text))
    assert words in error.value.message
    assert not (project.repo/".tallylock").exists()


def test_missing_setup_file(tmp_path):
    project = Project(tmp_path, [])
    with pytest.raises(TallyLockError) as error:
        project.plan(setup=project.repo/"absent.json")
    assert "not found" in error.value.message


def crash_after_seal(project, plan):
    """Run once more, then drop the last ledger line as a crash between seal and append would."""
    project.run(plan)
    lines = ledger_lines(plan)
    rewrite(plan, lines[:-1])
    return lines[-1]


def test_recover_appends_the_sealed_attempt_once_and_verify_reports_it(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1/4\n"}, {"exit": 3}, {"stdout": "tallylock: score=1\n"},
                                 {"stdout": "tallylock: score=0\n"}])
    plan = project.plan()
    project.run(plan)
    assert ledger.recover(project.repo, plan.plan_id) == {
        "format": "tallylock.ledger-recovery.v1", "plan_id": plan.plan_id, "state": "unchanged", "recovered": []}
    lost = crash_after_seal(project, plan)
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "removed"
    report = ledger.recover(project.repo, plan.plan_id)
    assert report["state"] == "recovered" and report["recovered"] == [2]
    lines = ledger_lines(plan)
    assert canonical.loads(lines[-1][:-1]) == {**canonical.loads(lost[:-1]),
                                               "format": "tallylock.ledger-recovered-entry.v1"}
    assert ledger.recover(project.repo, plan.plan_id)["state"] == "unchanged"
    assert ledger_lines(plan) == lines
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert checked["entries"] == 2 and checked["recovered"] == [2]
    assert checked["ledger"][1]["outcome"] == "failed" and checked["ledger"][1]["exit_code"] == 3
    # Relabelling the recovered entry as an ordinary one breaks the chain to later entries.
    project.run(plan)
    assert ledger.verify_ledger(project.repo, plan.plan_id)["recovered"] == [2]
    lines = ledger_lines(plan)
    rewrite(plan, [lines[0], edit_line(lines[1], format="tallylock.ledger-entry.v1"), lines[2]])
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "edited"


def test_run_recovers_a_missing_entry_instead_of_blocking(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}] * 3)
    plan = project.plan()
    project.run(plan)
    crash_after_seal(project, plan)
    report = project.run(plan)
    assert report["seq"] == 3 and report["recovered"] == [2]
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert checked["entries"] == 3 and checked["recovered"] == [2]
    assert ledger.recover(project.repo, plan.plan_id)["recovered"] == []


def test_recover_refuses_a_damaged_sealed_attempt(tmp_path):
    ledger = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}] * 3)
    plan = project.plan()
    project.run(plan)
    crash_after_seal(project, plan)
    (plan.directory/"attempts/run-2/artifacts/stdout.log").write_bytes(b"changed")
    before = ledger_lines(plan)
    with pytest.raises(ledger.LedgerError) as error:
        ledger.recover(project.repo, plan.plan_id)
    assert error.value.kind == "receipt_invalid"
    with pytest.raises(ledger.LedgerError):
        project.run(plan)
    assert ledger_lines(plan) == before


def pending_heads(project, plan, *seqs):
    for seq in seqs:
        api().anchor_head(project.repo, plan.plan_id, seq=seq, submit=lambda origin, commitment, **kw: reply(commitment, origin))


def test_upgrade_heads_replaces_pending_proofs_and_keeps_history(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    pending_heads(project, plan, 2, 3)
    pending = (plan.directory/"ledger-head-3.ots").read_bytes()
    headers, calls = [], []
    def upgrade(origin, commitment, **kwargs):
        calls.append(origin)
        headers.append(CBlockHeader(hashMerkleRoot=commitment, nTime=1700000000).serialize())
        return attested_reply(commitment, BitcoinBlockHeaderAttestation(1))
    report = ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=upgrade)
    assert report["format"] == "tallylock.ledger-upgrade.v1" and report["plan_id"] == plan.plan_id
    assert [(h["seq"], h["state"], h["bitcoin_heights"]) for h in report["heads"]] == [
        (3, "attestation_present", [1]), (2, "attestation_present", [1])]
    assert len(calls) == 8
    history = plan.directory/"proof-history"/"ledger-head-3"/(hashlib.sha256(pending).hexdigest() + ".ots")
    assert history.read_bytes() == pending
    cache = cache_for({1: headers[0]}, tip_height=6)
    assert ledger.verify_anchor(project.repo, plan.plan_id, 3, chain_cache=cache)["state"] == "anchored"
    assert [a["seq"] for a in ledger.verify_ledger(project.repo, plan.plan_id)["anchors"]] == [2, 3]
    again = ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=upgrade)
    assert [h["state"] for h in again["heads"]] == ["unchanged", "unchanged"] and len(calls) == 8


def test_upgrade_heads_reports_waits_failures_and_no_news(tmp_path):
    ledger = api()
    project, plan, _ = three_runs(tmp_path)
    assert ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=None)["heads"] == []
    pending_heads(project, plan, 3)
    before = (plan.directory/"ledger-head-3.ots").read_bytes()
    due = int(time.time()) + 600
    def wait(origin, commitment, **kwargs):
        raise transport.RetryDeferred(due)
    head = ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=wait)["heads"][0]
    assert head["state"] == "retry_wait" and head["next_retry_at"] == due and head["pending_count"] == 4
    def down(origin, commitment, **kwargs):
        raise TallyLockError("calendar request failed after bounded retries", code=5)
    report = ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=down)
    assert report["heads"][0]["state"] == "failed" and report["warnings"]
    def garbage(origin, commitment, **kwargs):
        return b"not a proof"
    assert ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=garbage)["heads"][0]["state"] == "failed"
    assert ledger.upgrade_heads(project.repo, plan.plan_id,
                                upgrade=lambda origin, commitment, **kw: None)["heads"][0]["state"] == "unchanged"
    assert (plan.directory/"ledger-head-3.ots").read_bytes() == before
    with open(plan.directory/"run.lock", "a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(TallyLockError) as error:
            ledger.upgrade_heads(project.repo, plan.plan_id, upgrade=wait)
        assert error.value.code == 5


TSAS = ("https://tsa.one.test/tsr", "http://tsa.two.test")


@pytest.fixture
def tsa(monkeypatch):
    forge = Forge(label="Ledger")
    monkeypatch.setattr(rfc3161, "trusted_roots", lambda: (forge.root,))
    calls = []
    def post(url, body, **kwargs):
        calls.append(url)
        if "down" in url:
            raise TallyLockError("timestamp request failed after bounded retries", code=5)
        digest, size = body[24:56], body[57]
        nonce = int.from_bytes(body[58:58 + size], "big")
        return forge.reply(digest, nonce=nonce + 1 if "stale" in url else nonce)
    return forge, post, calls


def test_timestamp_head_stores_tokens_that_verify_offline(tmp_path, tsa):
    ledger = api()
    forge, post, calls = tsa
    project, plan, _ = three_runs(tmp_path)
    report = ledger.timestamp_head(project.repo, plan.plan_id, tsas=TSAS, post=post)
    head = ledger.ledger_head(project.repo, plan.plan_id)
    assert report["format"] == "tallylock.ledger-tsa.v1" and report["seq"] == 3 and report["head_sha256"] == head
    assert report["state"] == "stamped" and calls == list(TSAS)
    first, second = report["tsas"]
    assert first == {"url": TSAS[0], "tsa": "tsa.one.test", "state": "stamped", "time": "2026-11-07T12:00:00Z",
                     "signer": "Ledger Test TSA", "reason": None,
                     "token": f".tallylock/plans/{plan.plan_id}/ledger-head-3.tsa.one.test.tsr"}
    assert second["token"].endswith("ledger-head-3.tsa.two.test.tsr")
    token = (project.repo/first["token"]).read_bytes()
    assert rfc3161.verify(token, bytes.fromhex(head))["time"] == "2026-11-07T12:00:00Z"
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert checked["instant_timestamps"] == [
        {"seq": 3, "tsa": "tsa.one.test", "state": "verified", "time": "2026-11-07T12:00:00Z",
         "signer": "Ledger Test TSA", "reason": None},
        {"seq": 3, "tsa": "tsa.two.test", "state": "verified", "time": "2026-11-07T12:00:00Z",
         "signer": "Ledger Test TSA", "reason": None}]
    again = ledger.timestamp_head(project.repo, plan.plan_id, tsas=TSAS, post=post)
    assert [item["state"] for item in again["tsas"]] == ["unchanged", "unchanged"] and len(calls) == 2
    older = ledger.timestamp_head(project.repo, plan.plan_id, seq=1, tsas=TSAS[:1], post=post)
    assert older["seq"] == 1 and older["state"] == "stamped"
    assert [item["seq"] for item in ledger.verify_ledger(project.repo, plan.plan_id)["instant_timestamps"]] == [1, 3, 3]


@pytest.mark.parametrize("tsas", [(), ("ftp://tsa.test",), ("https://tsa.test/a", "https://tsa.test/b"), "https://tsa.test"])
def test_timestamp_service_list_is_checked(tmp_path, tsa, tsas):
    project, plan, _ = three_runs(tmp_path)
    with pytest.raises(TallyLockError):
        api().timestamp_head(project.repo, plan.plan_id, tsas=tsas, post=tsa[1])


def test_timestamp_failures_are_reported_and_never_fail_a_run(tmp_path, tsa):
    _, post, calls = tsa
    project = Project(tmp_path, [{"stdout": "tallylock: score=1\n"}] * 4)
    plan = project.plan()
    assert project.run(plan)["instant"] == {"state": "not_requested"} and calls == []
    report = project.run(plan, tsa=True, tsas=("https://down.test/tsr", "http://tsa.two.test"), tsa_post=post)
    assert report["outcome"] == "completed"
    instant = report["instant"]
    assert instant["state"] == "partial" and instant["seq"] == 2
    assert [(item["tsa"], item["state"], item["token"]) for item in instant["tsas"]] == [
        ("down.test", "failed", None), ("tsa.two.test", "stamped", instant["tsas"][1]["token"])]
    assert "failed" in instant["tsas"][0]["reason"]
    report = project.run(plan, tsa=True, tsas=("https://stale.test/tsr",), tsa_post=post)
    assert report["instant"]["state"] == "failed"
    assert report["instant"]["tsas"][0]["reason"] == "the timestamp reply does not answer this request"
    assert not list(plan.directory.glob("ledger-head-3.*.tsr"))
    report = project.run(plan, tsa=True, tsas=("bad url",), tsa_post=post)
    assert report["outcome"] == "completed" and report["instant"]["state"] == "failed"
    assert api().verify_ledger(project.repo, plan.plan_id)["entries"] == 4


def test_moved_foreign_and_untrusted_tokens(tmp_path, tsa):
    ledger = api()
    _, post, _ = tsa
    project, plan, _ = three_runs(tmp_path)
    ledger.timestamp_head(project.repo, plan.plan_id, tsas=TSAS[:1], post=post)
    token = plan.directory/"ledger-head-3.tsa.one.test.tsr"
    token.rename(plan.directory/"ledger-head-2.tsa.one.test.tsr")
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "timestamp_mismatch"
    (plan.directory/"ledger-head-2.tsa.one.test.tsr").rename(plan.directory/"ledger-head-9.tsa.one.test.tsr")
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "removed"
    (plan.directory/"ledger-head-9.tsa.one.test.tsr").unlink()
    # A real DigiCert token for other data is caught as a mismatch, not trusted.
    (plan.directory/"ledger-head-1.timestamp.digicert.com.tsr").write_bytes(recorded("digicert"))
    with pytest.raises(ledger.LedgerError) as error:
        ledger.verify_ledger(project.repo, plan.plan_id)
    assert error.value.kind == "timestamp_mismatch"
    (plan.directory/"ledger-head-1.timestamp.digicert.com.tsr").unlink()
    head = bytes.fromhex(ledger.ledger_head(project.repo, plan.plan_id))
    (plan.directory/"ledger-head-3.stranger.test.tsr").write_bytes(Forge(label="Stranger").reply(head))
    (plan.directory/"ledger-head-3.junk.test.tsr").write_bytes(b"junk")
    checked = ledger.verify_ledger(project.repo, plan.plan_id)
    assert [(item["tsa"], item["state"], item["reason"]) for item in checked["instant_timestamps"]] == [
        ("junk.test", "rejected", "malformed"), ("stranger.test", "rejected", "untrusted")]
