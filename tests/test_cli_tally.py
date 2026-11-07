"""CLI wiring for run, score and check, with the repository and git faked in-process."""
import json
import sys

import pytest

from tallylock import cli, ledger
from test_ledger import FakeGit


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_repo", lambda: tmp_path)
    monkeypatch.setattr(ledger, "_git", FakeGit())
    return tmp_path


def call(capsys, *argv):
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 1, captured.out
    return code, json.loads(lines[0]), captured.err


def test_run_keeps_stdout_pure_json_and_sends_command_output_to_stderr(repo, capsys):
    code, report, err = call(capsys, "run", "--json", "--no-anchor", "--",
                             sys.executable, "-c", "print('noise'); print('tallylock: score=0.5')")
    assert code == 0 and report["format"] == "tallylock.run.v1" and report["outcome"] == "completed"
    assert report["score"] == {"numerator": 5, "denominator": 10}
    assert "noise" in err


def test_failed_command_is_recorded_with_exit_zero(repo, capsys):
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--", sys.executable, "-c", "raise SystemExit(4)")
    assert code == 0 and report["outcome"] == "failed" and report["exit_code"] == 4


def test_repeat_score_and_check_round_trip(repo, capsys):
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--repeat", "3", "--",
                           sys.executable, "-c", "import sys; print(f'tallylock: score=0.{sys.argv[1]}')", "{seed}")
    assert code == 0 and [item["seq"] for item in report["repeat"]] == [1, 2, 3]
    code, score, _ = call(capsys, "score", "--json")
    assert code == 0 and score["plan"]["attempts"] == 3 and score["claim"].startswith("0.300 best of 3 runs; adjusted 0.200 ± 0.249")
    code, verdict, _ = call(capsys, "check", "--json", score["claim"])
    assert code == 0 and verdict["verdict"] == "match"
    code, verdict, _ = call(capsys, "check", "--json", score["claim"].replace("best of 3", "best of 2"))
    assert code == 3 and verdict["verdict"] == "mismatch"


def test_score_without_runs_explains_next_step(repo, capsys):
    code, report, _ = call(capsys, "score", "--json")
    assert code == 3 and "tallylock run --" in report["errors"][0]["message"]


def test_flags_after_double_dash_belong_to_the_command(capsys):
    assert cli._human_mode(["run", "--", "prog", "--human"]) is False
    assert cli._human_mode(["run", "--human", "--", "prog", "--json"]) is True
