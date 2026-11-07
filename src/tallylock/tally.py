"""Exact plan statistics, repo summaries and the checkable claim line."""
from __future__ import annotations

from decimal import ROUND_CEILING, Decimal, localcontext
from fractions import Fraction
import hashlib
import math
from pathlib import Path
import re

from . import canonical, ledger
from .errors import TallyLockError


# Two-sided 95% Student-t quantiles (0.975 one-sided), rounded to 7 decimals.
_T975 = {
    1: "12.7062047", 2: "4.3026527", 3: "3.1824463", 4: "2.7764451", 5: "2.5705818",
    6: "2.4469119", 7: "2.3646243", 8: "2.3060041", 9: "2.2621572", 10: "2.2281389",
    11: "2.2009852", 12: "2.1788128", 13: "2.1603687", 14: "2.1447867", 15: "2.1314495",
    16: "2.1199053", 17: "2.1098155", 18: "2.1009220", 19: "2.0930241", 20: "2.0859634",
    21: "2.0796138", 22: "2.0738731", 23: "2.0686576", 24: "2.0638986", 25: "2.0595386",
    26: "2.0555294", 27: "2.0518305", 28: "2.0484071", 29: "2.0452296", 30: "2.0422725",
    40: "2.0210754", 50: "2.0085591", 60: "2.0002978", 80: "1.9900634", 100: "1.9839715",
    120: "1.9799304",
}
_PLACES = Decimal("0.001")
_CLAIM = re.compile(
    r"(?P<best>unscored|[0-9]{1,16}\.[0-9]{3}) best of (?P<runs>[0-9]{1,16}) runs; "
    r"adjusted (?P<mean>unscored|[0-9]{1,16}\.[0-9]{3}) "
    r"(?:± (?P<half>[0-9]{1,16}\.[0-9]{3}) \(95% CI|\(no interval), "
    r"(?P<completed>[0-9]{1,16}) completed, (?P<failed>[0-9]{1,16}) failed"
    r"(?:, (?P<unscored>[0-9]{1,16}) unscored)?\); "
    r"plan (?P<plan>[0-9a-f]{8}) \((?P<plan_number>[0-9]{1,16}) of (?P<plans>[0-9]{1,16}) in repo\); "
    r"ledger (?P<ledger>[0-9a-f]{8}); tallylock check")
_NUMBERS = ("runs", "completed", "failed", "unscored", "plan_number", "plans")
_COMPARED = ("best", "runs", "mean", "half", "completed", "failed", "unscored", "plan_number")


def _require(condition, message, code=2):
    if not condition:
        raise TallyLockError(message, code=code)


def t_quantile(df: int) -> Decimal:
    """Table quantile; between rows the next smaller df is used, which widens the interval."""
    if type(df) is not int or df < 1:
        raise ValueError("degrees of freedom must be a positive integer")
    return Decimal(_T975[max(row for row in _T975 if row <= df)])


def statistics(values) -> dict:
    """Exact best, mean and sample variance; the interval half-width is a 40-digit decimal."""
    values = [Fraction(value) for value in values]
    n = len(values)
    if n == 0:
        return {"n": 0, "best": None, "mean": None, "variance": None, "sd": None, "half_width": None}
    scale = math.lcm(*(value.denominator for value in values))
    scaled = [value.numerator * (scale // value.denominator) for value in values]
    total = sum(scaled)
    stats = {"n": n, "best": max(values), "mean": Fraction(total, n * scale),
             "variance": None, "sd": None, "half_width": None}
    if n > 1:
        variance = Fraction(n * sum(x * x for x in scaled) - total * total, n * (n - 1) * scale * scale)
        with localcontext() as context:
            context.prec = 40
            exact = Decimal(variance.numerator) / Decimal(variance.denominator)
            stats.update(variance=variance, sd=exact.sqrt(), half_width=t_quantile(n - 1) * (exact / n).sqrt())
    return stats


def _exact(value: Fraction | None) -> dict | None:
    return None if value is None else {"numerator": value.numerator, "denominator": value.denominator}


def _display(value: Fraction | None) -> str:
    if value is None:
        return "unscored"
    scaled = round(value * 1000)
    return f"{scaled // 1000}.{scaled % 1000:03d}"


def _summary(plan_id: str, plan_number: int, entries: list[dict]) -> dict:
    completed = [entry for entry in entries if entry["outcome"] == "completed"]
    scores = [Fraction(e["score"]["numerator"], e["score"]["denominator"]) for e in completed if e["score"] is not None]
    stats = statistics(scores)
    interval = None
    if stats["half_width"] is not None:
        with localcontext() as context:
            context.prec = 40
            mean = Decimal(stats["mean"].numerator) / Decimal(stats["mean"].denominator)
            interval = {"level": "0.95", "low": str(mean - stats["half_width"]), "high": str(mean + stats["half_width"]),
                        "half_width": str(stats["half_width"]), "sd": str(stats["sd"])}
    return {"format": "tallylock.plan-summary.v1", "plan_id": plan_id, "plan_number": plan_number,
            "seq": len(entries),
            "ledger_head": hashlib.sha256(canonical.dumps(entries[-1])).hexdigest() if entries else None,
            "attempts": len(entries), "completed": len(completed), "failed": len(entries) - len(completed),
            "scored": len(scores), "unscored": len(completed) - len(scores),
            "best": _exact(stats["best"]), "mean": _exact(stats["mean"]),
            "best_display": _display(stats["best"]), "mean_display": _display(stats["mean"]),
            "interval": interval}


def plan_summary(repo: Path, plan_id: str) -> dict:
    """Summarize one verified plan ledger; failed attempts are counted, never averaged."""
    checked = ledger.verify_ledger(repo, plan_id)
    return _summary(plan_id, checked["plan_number"], checked["ledger"])


def repo_summary(repo: Path) -> dict:
    """List every plan in the repository with its counts, marking ledgers that fail."""
    plans = []
    for plan_id in ledger.list_plans(repo):
        try:
            plans.append({**plan_summary(repo, plan_id), "state": "valid"})
        except ledger.LedgerError as error:
            number = ledger.load_plan(repo, plan_id)["metadata"]["tallylock_plan"]["plan_number"]
            plans.append({"plan_id": plan_id, "plan_number": number, "state": "invalid", "error": error.kind})
    return {"format": "tallylock.repo-summary.v1", "count": len(plans), "plans": plans}


def _fields(summary: dict, plans: int) -> dict:
    _require(summary["attempts"] > 0, "this plan has no attempts yet", code=3)
    half = summary["interval"]
    return {"best": summary["best_display"], "runs": summary["attempts"], "mean": summary["mean_display"],
            "half": None if half is None else str(Decimal(half["half_width"]).quantize(_PLACES, rounding=ROUND_CEILING)),
            "completed": summary["completed"], "failed": summary["failed"], "unscored": summary["unscored"],
            "plan": summary["plan_id"][:8], "plan_number": summary["plan_number"], "plans": plans,
            "ledger": summary["ledger_head"][:8]}


def format_claim_fields(fields: dict) -> str:
    interval = f"± {fields['half']} (95% CI" if fields["half"] is not None else "(no interval"
    unscored = f", {fields['unscored']} unscored" if fields["unscored"] else ""
    return (f"{fields['best']} best of {fields['runs']} runs; adjusted {fields['mean']} {interval}, "
            f"{fields['completed']} completed, {fields['failed']} failed{unscored}); "
            f"plan {fields['plan']} ({fields['plan_number']} of {fields['plans']} in repo); "
            f"ledger {fields['ledger']}; tallylock check")


def format_claim(summary: dict, repo: dict) -> str:
    """Render the deterministic one-line claim from a plan summary and repo summary."""
    return format_claim_fields(_fields(summary, repo["count"]))


def parse_claim(line: str) -> dict:
    _require(isinstance(line, str), "a claim line must be text")
    match = _CLAIM.fullmatch(line.strip())
    _require(match is not None, "this is not a TallyLock claim line")
    fields = match.groupdict()
    fields["unscored"] = fields["unscored"] or "0"
    for name in _NUMBERS:
        fields[name] = int(fields[name])
    return fields


def _text(value) -> str:
    return "none" if value is None else str(value)


def _verdict(verdict, reasons, plan_id=None, seq=None):
    return {"format": "tallylock.claim-check.v1", "verdict": verdict, "reasons": reasons,
            "plan_id": plan_id, "seq": seq}


def check_claim(repo: Path, line: str) -> dict:
    """Find the claimed plan and ledger head, verify the ledger and recompute every number."""
    claim = parse_claim(line)
    plans = ledger.list_plans(repo)
    matches = [plan_id for plan_id in plans if plan_id.startswith(claim["plan"])]
    if len(matches) != 1:
        return _verdict("not_found", [{"field": "plan", "claimed": claim["plan"],
                                       "actual": "ambiguous" if matches else "none"}])
    plan_id = matches[0]
    try:
        checked = ledger.verify_ledger(repo, plan_id)
    except ledger.LedgerError as error:
        return _verdict("mismatch", [{"field": "ledger", "claimed": "valid", "actual": error.kind}], plan_id)
    heads = [seq for seq, entry in enumerate(checked["ledger"], 1)
             if hashlib.sha256(canonical.dumps(entry)).hexdigest().startswith(claim["ledger"])]
    if len(heads) != 1:
        return _verdict("not_found", [{"field": "ledger", "claimed": claim["ledger"],
                                       "actual": "ambiguous" if heads else "none"}], plan_id)
    seq = heads[0]
    actual = _fields(_summary(plan_id, checked["plan_number"], checked["ledger"][:seq]), len(plans))
    reasons = [{"field": name, "claimed": _text(claim[name]), "actual": _text(actual[name])}
               for name in _COMPARED if claim[name] != actual[name]]
    # Plans created after the claim are fine; a plan that existed then must still exist.
    numbers = [ledger.load_plan(repo, item)["metadata"]["tallylock_plan"]["plan_number"] for item in plans]
    earlier = sum(1 for number in numbers if number <= claim["plans"])
    if earlier != claim["plans"]:
        reasons.append({"field": "plans", "claimed": _text(claim["plans"]), "actual": _text(earlier)})
    return _verdict("mismatch" if reasons else "match", reasons, plan_id, seq)
