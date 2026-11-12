"""CLI wiring for run, score and check, with the repository and git faked in-process."""
import json
import signal
import sys

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
import pytest

from tallylock import cli, headers, ledger
from test_headers import MEMPOOL, REGTEST_BITS, Fetch, synthetic_chain
from test_ledger import FakeGit
from test_transport import attested_reply, reply


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


def test_failed_command_is_recorded_and_exits_with_its_own_code(repo, capsys):
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--", sys.executable, "-c", "raise SystemExit(4)")
    assert code == 4 and report["code"] == 4 and report["outcome"] == "failed" and report["exit_code"] == 4
    code, score, _ = call(capsys, "score", "--json")
    assert code == 0 and score["plan"]["failed"] == 1


def test_repeat_runs_every_attempt_then_exits_with_the_first_failure(repo, capsys):
    script = "import sys; raise SystemExit({1: 0, 2: 7, 3: 9}[int(sys.argv[1])])"
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--repeat", "3", "--",
                           sys.executable, "-c", script, "{seed}")
    assert code == 7 and [item["exit_code"] for item in report["repeat"]] == [0, 7, 9]


@pytest.mark.skipif(not hasattr(signal, "SIGTERM") or sys.platform == "win32", reason="POSIX signals")
def test_command_stopped_by_a_signal_exits_with_128_plus_the_signal(repo, capsys):
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--", sys.executable, "-c",
                           "import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
    assert code == 128 + signal.SIGTERM and report["exit_code"] == -signal.SIGTERM
    assert report["outcome"] == "failed"


def test_tallylock_errors_keep_their_own_codes(repo, capsys):
    code, report, _ = call(capsys, "run", "--json", "--no-anchor")
    assert code == 2 and report["errors"]


def test_human_run_says_which_exit_code_it_passes_on(repo, capsys):
    code = cli.main(["run", "--human", "--no-anchor", "--", sys.executable, "-c", "raise SystemExit(3)"])
    text = capsys.readouterr().out
    assert code == 3 and "failed (exit code 3)" in text and "Exit code 3, from your command." in text


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


def never(url, *, deadline):
    raise AssertionError("no network without --online")


@pytest.fixture
def anchored(repo, capsys, monkeypatch):
    """Head 1 carries a completed Bitcoin proof at regtest height 1; head 2 is still pending."""
    code, report, _ = call(capsys, "run", "--json", "--no-anchor", "--repeat", "2", "--",
                           sys.executable, "-c", "print('tallylock: score=0.5')")
    assert code == 0
    plan_id, roots = report["plan_id"], []

    def bitcoin(origin, commitment, **kwargs):
        roots.append(commitment)
        return attested_reply(commitment, BitcoinBlockHeaderAttestation(1))
    ledger.anchor_head(repo, plan_id, seq=1, submit=bitcoin)
    ledger.anchor_head(repo, plan_id, seq=2, submit=lambda origin, commitment, **kwargs: reply(commitment, origin))
    monkeypatch.setattr(headers, "POW_LIMIT", headers.compact_target(REGTEST_BITS))
    monkeypatch.setattr(headers, "DIFFICULTY", (REGTEST_BITS,))
    monkeypatch.setattr(headers, "_fetch", never)
    code, score, _ = call(capsys, "score", "--json")
    return {"plan_id": plan_id, "root": roots[0], "claim": score["claim"]}


def online(monkeypatch, maps):
    fetch = Fetch(maps)
    monkeypatch.setattr(headers, "_fetch", fetch)
    return fetch


def test_check_without_online_makes_no_requests_and_reports_no_timestamps(anchored, capsys):
    code, verdict, _ = call(capsys, "check", "--json", anchored["claim"])
    assert code == 0 and verdict["verdict"] == "match" and "timestamps" not in verdict


def test_check_online_confirms_completed_heads_and_names_pending_ones(anchored, capsys, monkeypatch):
    fetch = online(monkeypatch, synthetic_chain({1: anchored["root"]}, 110))
    code, verdict, _ = call(capsys, "check", "--json", "--online", anchored["claim"])
    assert code == 0 and verdict["verdict"] == "match"
    heads = verdict["timestamps"]["heads"]
    assert [(item["seq"], item["state"]) for item in heads] == [(1, "checked"), (2, "pending")]
    assert heads[0]["height"] == 1 and heads[0]["confirmations"] == 110
    assert verdict["timestamps"]["providers"]["providers_agreed"] is True
    assert fetch.calls and all(url.startswith(tuple(headers.PROVIDERS)) for url in fetch.calls)
    code = cli.main(["check", "--human", "--online", anchored["claim"]])
    text = capsys.readouterr().out
    assert code == 0 and "Claim checked" in text
    assert "Head 1: checked. 110 later blocks confirm it." in text
    assert "Head 2: Bitcoin proof pending, run tallylock refresh." in text


def test_check_online_fails_when_the_newest_proof_was_skipped_unchecked(anchored, repo, capsys, monkeypatch):
    # A proof naming more blocks than one check covers is skipped; it must not pass as checked.
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    plan_id = anchored["plan_id"]
    stamp = Timestamp(bytes.fromhex(ledger.ledger_head(repo, plan_id)))
    for height in range(1, headers.MAX_HEIGHTS + 2):
        stamp.attestations.add(BitcoinBlockHeaderAttestation(height))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
    (repo / ".tallylock" / "plans" / plan_id / "ledger-head-2.ots").write_bytes(ctx.getbytes())
    online(monkeypatch, synthetic_chain({1: anchored["root"]}, 110))
    code, verdict, _ = call(capsys, "check", "--json", "--online", anchored["claim"])
    assert [item["state"] for item in verdict["timestamps"]["heads"]] == ["checked", "skipped"]
    assert code == 3


def test_check_online_reports_disagreeing_providers_as_a_failure(anchored, capsys, monkeypatch):
    maps = synthetic_chain({1: anchored["root"]}, 110)
    maps[MEMPOOL]["/block-height/101"] = "00" * 32
    online(monkeypatch, maps)
    code, verdict, _ = call(capsys, "check", "--json", "--online", anchored["claim"])
    assert code == 3 and verdict["verdict"] == "match"
    first = verdict["timestamps"]["heads"][0]
    assert first["state"] == "failed" and "disagree" in first["reason"]
    code = cli.main(["check", "--human", "--online", anchored["claim"]])
    assert code == 3 and "Head 1: timestamp check failed." in capsys.readouterr().out


def test_check_online_says_when_too_few_blocks_confirm_a_head(anchored, capsys, monkeypatch):
    online(monkeypatch, synthetic_chain({1: anchored["root"]}, 3))
    code, verdict, _ = call(capsys, "check", "--json", "--online", anchored["claim"])
    first = verdict["timestamps"]["heads"][0]
    assert code == 3 and first["state"] == "too_few_confirmations" and first["confirmations"] == 3
    code = cli.main(["check", "--human", "--online", anchored["claim"]])
    assert "Head 1: only 3 blocks confirm it so far, 6 needed." in capsys.readouterr().out


def test_score_online_reports_the_same_head_checks(anchored, capsys, monkeypatch):
    online(monkeypatch, synthetic_chain({1: anchored["root"]}, 110))
    code, score, _ = call(capsys, "score", "--json", "--online")
    assert code == 0 and score["claim"] == anchored["claim"]
    assert [item["state"] for item in score["timestamps"]["heads"]] == ["checked", "pending"]
