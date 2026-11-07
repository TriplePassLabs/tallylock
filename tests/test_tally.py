"""Plan statistics, the claim line and its offline check."""
from decimal import Decimal
from fractions import Fraction
import shutil
import importlib.util
import math
import random

import pytest

from test_ledger import Project, api as ledger_api, ledger_lines, rewrite, edit_line, three_runs


def api():
    assert importlib.util.find_spec("tallylock.tally") is not None, "tally missing"
    from tallylock import tally
    return tally


def t_cdf(t, df, steps=20000):
    """Numerically integrate the Student-t density from zero (test-only floats)."""
    c = math.gamma((df + 1) / 2) / (math.sqrt(df * math.pi) * math.gamma(df / 2))
    h = t / steps
    total = sum((1 if i in (0, steps) else 4 if i % 2 else 2) * c * (1 + (i*h)**2/df) ** (-(df+1)/2)
                for i in range(steps + 1))
    return 0.5 + total * h / 3


def test_t_quantiles_are_exact_to_table_precision():
    tally = api()
    for df in list(range(1, 31)) + [40, 50, 60, 80, 100, 120]:
        q = tally.t_quantile(df)
        assert isinstance(q, Decimal)
        assert abs(t_cdf(float(q), df) - 0.975) < 2e-6, df
    # Between table rows the next smaller degrees of freedom is used, which is conservative.
    assert tally.t_quantile(45) == tally.t_quantile(40)
    assert tally.t_quantile(10**6) == tally.t_quantile(120)
    with pytest.raises(ValueError):
        tally.t_quantile(0)


def test_statistics_are_exact_rationals():
    tally = api()
    values = [Fraction(742, 1000), Fraction(7, 10), Fraction(74, 100)]
    stats = tally.statistics(values)
    assert stats["n"] == 3
    assert stats["best"] == Fraction(742, 1000)
    assert stats["mean"] == sum(values) / 3
    assert stats["variance"] == sum((v - stats["mean"]) ** 2 for v in values) / 2
    assert type(stats["mean"]) is Fraction and type(stats["variance"]) is Fraction
    expected = tally.t_quantile(2) * (Decimal(stats["variance"].numerator) / Decimal(stats["variance"].denominator * 3)).sqrt()
    assert abs(stats["half_width"] - expected) < Decimal("1e-20")
    one = tally.statistics([Fraction(1, 2)])
    assert one["mean"] == one["best"] == Fraction(1, 2)
    assert one["variance"] is None and one["half_width"] is None
    empty = tally.statistics([])
    assert empty == {"n": 0, "best": None, "mean": None, "variance": None, "sd": None, "half_width": None}


def test_interval_coverage_simulation():
    tally = api()
    truth = Fraction(7, 10)
    for n in range(2, 51):
        rng = random.Random(1000 + n)
        covered = 0
        trials = 2000
        for _ in range(trials):
            values = [Fraction(round(rng.gauss(0.7, 0.05) * 10000), 10000) for _ in range(n)]
            stats = tally.statistics(values)
            mean = Decimal(stats["mean"].numerator) / Decimal(stats["mean"].denominator)
            covered += abs(mean - Decimal("0.7")) <= stats["half_width"]
        assert covered / trials >= 0.90, (n, covered / trials)


def test_adjusted_never_exceeds_best():
    tally = api()
    rng = random.Random(7)
    for _ in range(500):
        values = [Fraction(rng.randrange(0, 1000), rng.randrange(1, 1000)) for _ in range(rng.randrange(1, 12))]
        stats = tally.statistics(values)
        assert stats["mean"] <= stats["best"]


def test_plan_summary_discloses_failures_without_averaging_them(tmp_path):
    tally = api()
    project, plan, _ = three_runs(tmp_path)
    summary = tally.plan_summary(project.repo, plan.plan_id)
    assert summary["attempts"] == 3 and summary["completed"] == 2 and summary["failed"] == 1
    assert summary["unscored"] == 0
    assert summary["plan_number"] == 1 and summary["seq"] == 3
    assert summary["ledger_head"] == ledger_api().ledger_head(project.repo, plan.plan_id)
    # The failed run printed 0.9; it is disclosed but neither best nor averaged.
    assert summary["best"] == {"numerator": 371, "denominator": 500}
    assert summary["mean"] == {"numerator": 741, "denominator": 1000}
    assert Fraction(summary["mean"]["numerator"], summary["mean"]["denominator"]) \
        <= Fraction(summary["best"]["numerator"], summary["best"]["denominator"])
    assert summary["interval"] is not None
    assert set(summary["interval"]) == {"level", "low", "high", "half_width", "sd"}


def test_repo_summary_lists_every_plan(tmp_path):
    tally = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=1/2\n"}] * 3)
    first = project.plan()
    project.run(first)
    (project.repo/"config.toml").write_text("seed = 9\n")
    second = project.plan()
    project.run(second)
    project.run(second)
    summary = tally.repo_summary(project.repo)
    assert summary["count"] == 2
    by_id = {p["plan_id"]: p for p in summary["plans"]}
    assert by_id[first.plan_id]["attempts"] == 1 and by_id[second.plan_id]["attempts"] == 2
    assert [p["plan_number"] for p in summary["plans"]] == [1, 2]
    rewrite(first, [edit_line(ledger_lines(first)[0], exit_code=4)])
    damaged = {p["plan_id"]: p for p in tally.repo_summary(project.repo)["plans"]}
    assert damaged[first.plan_id]["state"] == "invalid" and damaged[first.plan_id]["error"] == "edited"
    assert damaged[second.plan_id]["state"] == "valid"


def test_claim_line_text_is_deterministic(tmp_path):
    tally = api()
    project, plan, _ = three_runs(tmp_path)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    head = ledger_api().ledger_head(project.repo, plan.plan_id)
    stats = tally.statistics([Fraction(742, 1000), Fraction(74, 100)])
    half = stats["half_width"].quantize(Decimal("0.001"), rounding="ROUND_CEILING")
    assert line == (f"0.742 best of 3 runs; adjusted 0.741 ± {half} (95% CI, 2 completed, 1 failed); "
                    f"plan {plan.plan_id[:8]} (1 of 1 in repo); ledger {head[:8]}; tallylock check")
    assert "—" not in line


def test_claim_without_interval_and_without_scores(tmp_path):
    tally = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=0.5\n"}, {"stdout": "none\n"}, {"exit": 2}])
    plan = project.plan()
    project.run(plan)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    assert line.startswith("0.500 best of 1 runs; adjusted 0.500 (no interval, 1 completed, 0 failed); ")
    project.run(plan)
    project.run(plan)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    assert line.startswith("0.500 best of 3 runs; adjusted 0.500 (no interval, 2 completed, 1 failed, 1 unscored); ")
    assert tally.check_claim(project.repo, line)["verdict"] == "match"
    (tmp_path/"other").mkdir()
    other = Project(tmp_path/"other", [{"stdout": "none\n"}])
    blank = other.plan()
    other.run(blank)
    line = tally.format_claim(tally.plan_summary(other.repo, blank.plan_id), tally.repo_summary(other.repo))
    assert line.startswith("unscored best of 1 runs; adjusted unscored (no interval, 1 completed, 0 failed, 1 unscored); ")
    assert tally.check_claim(other.repo, line)["verdict"] == "match"


def test_parse_claim_round_trip(tmp_path):
    tally = api()
    project, plan, _ = three_runs(tmp_path)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    parsed = tally.parse_claim(line)
    assert parsed["best"] == "0.742" and parsed["runs"] == 3 and parsed["mean"] == "0.741"
    assert parsed["completed"] == 2 and parsed["failed"] == 1 and parsed["unscored"] == 0
    assert parsed["plan"] == plan.plan_id[:8] and parsed["plan_number"] == 1 and parsed["plans"] == 1
    assert tally.format_claim_fields(parsed) == line
    for bad in ["", "0.742 best of 3 runs", line + " extra", line.replace("plan ", "plan X")]:
        with pytest.raises(Exception) as error:
            tally.parse_claim(bad)
        assert error.type.__name__ == "TallyLockError"


def test_check_claim_match_mismatch_and_not_found(tmp_path):
    tally = api()
    project, plan, _ = three_runs(tmp_path)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    verdict = tally.check_claim(project.repo, line)
    assert verdict["verdict"] == "match" and verdict["reasons"] == []
    assert verdict["plan_id"] == plan.plan_id and verdict["seq"] == 3
    tampered = line.replace("0.742 best", "0.802 best")
    verdict = tally.check_claim(project.repo, tampered)
    assert verdict["verdict"] == "mismatch"
    assert verdict["reasons"] == [{"field": "best", "claimed": "0.802", "actual": "0.742"}]
    verdict = tally.check_claim(project.repo, line.replace("2 completed, 1 failed", "3 completed, 0 failed"))
    assert {r["field"] for r in verdict["reasons"]} == {"completed", "failed"}
    missing = tally.check_claim(project.repo, line.replace(f"plan {plan.plan_id[:8]}", "plan 00000000"))
    assert missing["verdict"] == "not_found"
    head = ledger_api().ledger_head(project.repo, plan.plan_id)
    gone = tally.check_claim(project.repo, line.replace(f"ledger {head[:8]}", "ledger ffffffff"))
    assert gone["verdict"] == "not_found"


def test_claim_on_earlier_head_still_checks_and_tamper_is_mismatch(tmp_path):
    tally = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=0.6\n"}, {"stdout": "tallylock: score=0.8\n"},
                                 {"stdout": "tallylock: score=0.1\n"}])
    plan = project.plan()
    project.run(plan)
    project.run(plan)
    line = tally.format_claim(tally.plan_summary(project.repo, plan.plan_id), tally.repo_summary(project.repo))
    project.run(plan)
    verdict = tally.check_claim(project.repo, line)
    assert verdict["verdict"] == "match" and verdict["seq"] == 2
    lines = ledger_lines(plan)
    rewrite(plan, [lines[0], lines[2]])
    verdict = tally.check_claim(project.repo, line)
    assert verdict["verdict"] == "mismatch"
    assert verdict["reasons"] == [{"field": "ledger", "claimed": "valid", "actual": "removed"}]


def test_claim_disclosure_of_plan_count(tmp_path):
    tally = api()
    project = Project(tmp_path, [{"stdout": "tallylock: score=0.6\n"}] * 2)
    first = project.plan()
    project.run(first)
    line = tally.format_claim(tally.plan_summary(project.repo, first.plan_id), tally.repo_summary(project.repo))
    assert "(1 of 1 in repo)" in line
    (project.repo/"config.toml").write_text("seed = 5\n")
    second = project.plan()
    project.run(second)
    # A plan created after the claim does not invalidate it.
    assert tally.check_claim(project.repo, line)["verdict"] == "match"
    later = tally.format_claim(tally.plan_summary(project.repo, second.plan_id), tally.repo_summary(project.repo))
    assert "(2 of 2 in repo)" in later
    # Deleting a plan that existed when the claim was made is caught.
    shutil.rmtree(first.directory)
    verdict = tally.check_claim(project.repo, later)
    assert verdict["verdict"] == "mismatch"
    assert verdict["reasons"] == [{"field": "plans", "claimed": "2", "actual": "1"}]
