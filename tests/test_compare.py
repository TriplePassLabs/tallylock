"""Comparing two plans: setup fields, Welch noise interval and plain verdicts."""
from decimal import Decimal
import json
import math
import statistics

import pytest

from test_ledger import Project, SETUP, write_setup
from tallylock import compare, ledger, tally


def make(tmp_path, name, scores, setup=None, failed=0):
    root = tmp_path / name
    root.mkdir()
    steps = [{"stdout": f"tallylock: score={score}\n"} for score in scores]
    steps += [{"stdout": "tallylock: score=0.99\n", "exit": 1}] * failed
    project = Project(root, steps)
    options = {} if setup is None else {"setup": write_setup(project, setup)}
    plan = project.plan(**options)
    for _ in steps:
        project.run(plan)
    return project.repo, plan.plan_id


def welch(a, b):
    """Independent float calculation with the same table rule: next smaller tabulated df."""
    va, vb = statistics.variance(a) / len(a), statistics.variance(b) / len(b)
    df = (va + vb) ** 2 / (va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1))
    return statistics.mean(a) - statistics.mean(b), math.sqrt(va + vb), df


def test_clearly_different_means_are_not_tied_and_match_hand_calculation(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.1", "0.2", "0.3"], SETUP)
    result = compare.compare(left, right)
    assert result["format"] == "tallylock.compare.v1"
    assert result["comparable"] is True and result["verdict"] == "left is higher"
    diff, se, df = welch([0.5, 0.6, 0.7], [0.1, 0.2, 0.3])
    assert df == pytest.approx(4.0)
    half = 2.7764451 * se
    assert float(result["difference"]["mean"]) == pytest.approx(diff, abs=2e-6) == pytest.approx(0.4, abs=2e-6)
    assert float(result["difference"]["low"]) == pytest.approx(diff - half, abs=2e-6)
    assert float(result["difference"]["high"]) == pytest.approx(diff + half, abs=2e-6)
    assert Decimal(result["difference"]["low"]) <= Decimal(str(diff - half))
    assert Decimal(result["difference"]["high"]) >= Decimal(str(diff + half))
    assert all(isinstance(sentence, str) and "—" not in sentence for sentence in result["plain"])


def test_unequal_runs_use_welch_satterthwaite_df_floored(tmp_path):
    a, b = ["0.50", "0.62", "0.71", "0.55"], ["0.30", "0.20", "0.45"]
    result = compare.compare(make(tmp_path, "l", a, SETUP), make(tmp_path, "r", b, SETUP))
    fa, fb = [float(x) for x in a], [float(x) for x in b]
    diff, se, df = welch(fa, fb)
    assert 2 < df < 6 and df != int(df)
    table = {1: 12.7062047, 2: 4.3026527, 3: 3.1824463, 4: 2.7764451, 5: 2.5705818}
    half = table[int(df)] * se
    assert float(result["difference"]["low"]) == pytest.approx(diff - half, abs=2e-6)
    assert float(result["difference"]["high"]) == pytest.approx(diff + half, abs=2e-6)


def test_overlapping_noise_is_statistically_tied(tmp_path):
    left = make(tmp_path, "l", ["0.50", "0.60", "0.70"], SETUP)
    right = make(tmp_path, "r", ["0.45", "0.62", "0.68"], SETUP)
    result = compare.compare(left, right)
    assert result["verdict"] == "statistically tied" and result["comparable"] is True
    assert Decimal(result["difference"]["low"]) < 0 < Decimal(result["difference"]["high"])
    assert any("tied" in sentence for sentence in result["plain"])


def test_identical_scores_tie_even_with_zero_variance(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.5"], SETUP)
    right = make(tmp_path, "r", ["0.5", "0.5"], SETUP)
    result = compare.compare(left, right)
    assert result["verdict"] == "statistically tied"
    assert result["difference"] == {"mean": "0.000000", "low": "0.000000", "high": "0.000000"}
    other = make(tmp_path, "o", ["0.4", "0.4"], SETUP)
    assert compare.compare(left, other)["verdict"] == "left is higher"
    assert compare.compare(other, left)["verdict"] == "right is higher"


def test_failed_attempts_never_count_as_scores(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP, failed=2)
    right = make(tmp_path, "r", ["0.1", "0.2", "0.3"], SETUP)
    result = compare.compare(left, right)
    assert float(result["difference"]["mean"]) == pytest.approx(0.4, abs=2e-6)


@pytest.mark.parametrize("change, field", [
    ({"dataset": {**SETUP["dataset"], "sha256": "ee" * 32}}, "dataset"),
    ({"harness": {"name": "lm-eval", "version": "0.5.0"}}, "harness"),
    ({"prompt_template_sha256": "ee" * 32}, "prompt template"),
    ({"decoding": {**SETUP["decoding"], "temperature": "0.9"}}, "decoding.temperature"),
])
def test_blocking_differences_are_not_comparable(tmp_path, change, field):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.1", "0.2", "0.3"], {**SETUP, **change})
    result = compare.compare(left, right)
    assert result["comparable"] is False and result["verdict"] == "not comparable"
    assert result["difference"] is None
    blocking = [item for item in result["mismatches"] if item["blocks"]]
    assert [item["field"] for item in blocking] == [field]
    assert blocking[0]["left"] != blocking[0]["right"]
    assert any("not comparable" in sentence.lower() for sentence in result["plain"])


def test_dataset_without_hashes_falls_back_to_name_and_version(tmp_path):
    base = {key: value for key, value in SETUP.items() if key != "dataset"}
    left = make(tmp_path, "l", ["0.5", "0.6"], {**base, "dataset": {"name": "gsm8k", "version": "1.0"}})
    same = make(tmp_path, "s", ["0.5", "0.6"], {**base, "dataset": {"name": "gsm8k", "version": "1.0"}})
    newer = make(tmp_path, "n", ["0.5", "0.6"], {**base, "dataset": {"name": "gsm8k", "version": "2.0"}})
    assert compare.compare(left, same)["comparable"] is True
    result = compare.compare(left, newer)
    assert result["comparable"] is False and result["mismatches"][0]["field"] == "dataset"


def test_model_command_and_commit_differences_do_not_block(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.5", "0.6", "0.7"], {**SETUP, "model": {"name": "llama", "revision": "main"}})
    result = compare.compare(left, right)
    assert result["comparable"] is True
    soft = {item["field"]: item for item in result["mismatches"] if not item["blocks"]}
    assert "model" in soft and "command" in soft
    assert soft["model"]["left"] == "qwen main" and soft["model"]["right"] == "llama main"


def test_missing_fields_are_unknown_not_equal(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.5", "0.6", "0.7"])
    result = compare.compare(left, right)
    names = {item["field"] for item in result["unknown"]}
    assert {"dataset", "harness", "prompt template", "decoding.temperature", "model"} <= names
    assert result["comparable"] is True and result["mismatches"] and all(not m["blocks"] for m in result["mismatches"])
    assert any("unknown" in sentence.lower() or "not recorded" in sentence.lower() for sentence in result["plain"])
    partial = make(tmp_path, "p", ["0.5", "0.6", "0.7"], {key: value for key, value in SETUP.items() if key != "decoding"} | {"decoding": {"temperature": "0.7"}})
    result = compare.compare(left, partial)
    assert {"decoding.max_tokens", "decoding.greedy"} <= {item["field"] for item in result["unknown"]}
    assert "decoding.temperature" not in {item["field"] for item in result["unknown"]}


def test_fewer_than_two_scored_runs_cannot_tell(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.1"], SETUP)
    result = compare.compare(left, right)
    assert result["verdict"] == "not enough runs to tell"
    assert result["difference"] is None and result["comparable"] is True
    assert any("2" in sentence for sentence in result["plain"])


def test_result_is_canonical_json_and_left_right_order_mirrors(tmp_path):
    left = make(tmp_path, "l", ["0.5", "0.6", "0.7"], SETUP)
    right = make(tmp_path, "r", ["0.1", "0.2", "0.3"], SETUP)
    forward, backward = compare.compare(left, right), compare.compare(right, left)
    json.dumps(forward)
    assert Decimal(forward["difference"]["mean"]) == -Decimal(backward["difference"]["mean"])
    assert (forward["verdict"], backward["verdict"]) == ("left is higher", "right is higher")
