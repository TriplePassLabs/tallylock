"""Compare two plans: setup fields, a Welch interval for the difference and plain verdicts."""
from __future__ import annotations

from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from fractions import Fraction
from pathlib import Path

from . import ledger, registry as registry_module, tally


FORMAT = "tallylock.compare.v1"
_PLACES = Decimal("0.000001")


def _text(*parts):
    return " ".join(str(part) for part in parts if part is not None)


def _pair(section, *names):
    """A setup object's named values as text; None when the name or the object is missing."""
    def get(info):
        value = info.get("setup", {}).get(section)
        if not isinstance(value, dict) or names[0] not in value:
            return None
        return _text(*(value.get(name) for name in names))
    return get


def _sha(info):
    return info.get("setup", {}).get("dataset", {}).get("sha256")


def _fields(left: dict, right: dict) -> list[tuple[str, bool, object, object]]:
    """Each field as (name, blocks ranking, left value, right value); None means not recorded."""
    rows = []
    if _sha(left) and _sha(right):
        rows.append(("dataset", True, _sha(left), _sha(right)))
    else:
        rows.append(("dataset", True, _pair("dataset", "name", "version")(left), _pair("dataset", "name", "version")(right)))
    rows.append(("harness", True, _pair("harness", "name", "version")(left), _pair("harness", "name", "version")(right)))
    rows.append(("prompt template", True, left.get("setup", {}).get("prompt_template_sha256"),
                 right.get("setup", {}).get("prompt_template_sha256")))
    decoding = [info.get("setup", {}).get("decoding") for info in (left, right)]
    names = sorted(set(decoding[0] or {}) | set(decoding[1] or {}))
    if not names:
        rows.append(("decoding", True, None, None))
    for name in names:
        values = [None if not item or name not in item else (type(item[name]).__name__, item[name]) for item in decoding]
        rows.append((f"decoding.{name}", True, *values))
    rows.append(("model", False, _pair("model", "name", "revision")(left), _pair("model", "name", "revision")(right)))
    rows.append(("command", False, left.get("argv"), right.get("argv")))
    rows.append(("config files", False, left.get("configs"), right.get("configs")))
    rows.append(("code version", False, left.get("head"), right.get("head")))
    return rows


def _shown(value):
    return value[1] if isinstance(value, tuple) else value


def compare_setups(left: dict, right: dict) -> tuple[list[dict], list[dict]]:
    """Split the fields into differences and unknowns; matching fields are not listed."""
    mismatches, unknown = [], []
    for name, blocks, a, b in _fields(left, right):
        if a is None or b is None:
            unknown.append({"field": name, "missing": "both" if a is None and b is None else "left" if a is None else "right"})
        elif a != b:
            mismatches.append({"field": name, "left": _shown(a), "right": _shown(b), "blocks": blocks})
    return mismatches, unknown


def welch(left: list[Fraction], right: list[Fraction]) -> dict:
    """Exact mean difference and a 95% Welch interval; the table row never exceeds the real df."""
    a, b = tally.statistics(left), tally.statistics(right)
    diff = a["mean"] - b["mean"]
    parts = [a["variance"] / a["n"], b["variance"] / b["n"]]
    variance = parts[0] + parts[1]
    if variance == 0:
        df = a["n"] + b["n"] - 2
    else:
        df = int(variance * variance / (parts[0] ** 2 / (a["n"] - 1) + parts[1] ** 2 / (b["n"] - 1)))
    with localcontext() as context:
        context.prec = 40
        half = tally.t_quantile(df) * (Decimal(variance.numerator) / Decimal(variance.denominator)).sqrt()
        mean = Decimal(diff.numerator) / Decimal(diff.denominator)
        tied = abs(mean) <= half
        low, high = mean - half, mean + half
        shown = {"mean": (mean.quantize(_PLACES) + 0), "low": (low.quantize(_PLACES, rounding=ROUND_FLOOR) + 0),
                 "high": (high.quantize(_PLACES, rounding=ROUND_CEILING) + 0)}
    return {"difference": {name: str(value) for name, value in shown.items()}, "tied": tied, "df": df,
            "positive": diff > 0}


def _side(side):
    repo, plan_id = side
    summary, scores = tally.plan_detail(Path(repo), plan_id)
    info = ledger.load_plan(Path(repo), plan_id)["metadata"]["tallylock_plan"]
    return info, summary, scores


def compare(left, right) -> dict:
    """Compare two (repo_root, plan_id) sides; never ranks across a blocking difference."""
    (info_a, _, scores_a), (info_b, _, scores_b) = _side(left), _side(right)
    mismatches, unknown = compare_setups(info_a, info_b)
    blocking = [item for item in mismatches if item["blocks"]]
    plain = []
    difference = None
    if blocking:
        verdict = "not comparable"
        reasons = ", ".join(item["field"] for item in blocking)
        plain.append(f"These runs are not comparable: they differ in {reasons}.")
        plain.append("Scores from different setups should not be ranked against each other.")
    elif len(scores_a) < 2 or len(scores_b) < 2:
        verdict = "not enough runs to tell"
        plain.append("Each side needs at least 2 scored runs to tell a real difference from noise.")
        plain.append(f"The left side has {len(scores_a)} scored runs and the right side has {len(scores_b)}.")
    else:
        result = welch(scores_a, scores_b)
        difference = result["difference"]
        if result["tied"]:
            verdict = "statistically tied"
            plain.append("The two averages are within the noise of each other, so the two sides are statistically tied.")
        else:
            verdict = "left is higher" if result["positive"] else "right is higher"
            side = "left" if result["positive"] else "right"
            plain.append(f"The {side} side scored higher, by more than the run-to-run noise.")
        plain.append(f"The left average minus the right average is {difference['mean']}, "
                     f"with a 95% range of {difference['low']} to {difference['high']}.")
    if unknown:
        names = ", ".join(item["field"] for item in unknown)
        plain.append(f"These settings are not recorded on one or both sides, so they are unknown: {names}.")
    soft = [item["field"] for item in mismatches if not item["blocks"]]
    if soft:
        plain.append(f"These also differ, which is fine if it is what you are comparing: {', '.join(soft)}.")
    return {"format": FORMAT, "comparable": not blocking, "mismatches": mismatches, "unknown": unknown,
            "difference": difference, "verdict": verdict, "plain": plain}


def groups_for_board(registry: Path, *, report: dict | None = None) -> list[dict]:
    """Tied pairs (comparable and within each other's noise) and warnings for mismatched pairs.

    Ties are reported pair by pair because a tie is not transitive: A may tie B and B tie C while A beats C.

    A warning is raised only for a pair that agrees on at least one ranking field but differs on
    another, because entries with nothing in common are simply different projects.
    """
    registry = Path(registry)
    report = registry_module.verify_registry(registry) if report is None else report
    ids = [item["plan_id"] for item in report["entries"] if item["ok"]]
    sides = {plan_id: _side((registry/"entries"/plan_id, plan_id)) for plan_id in ids}
    ties, warnings = [], []
    for index, first in enumerate(ids):
        for second in ids[index + 1:]:
            info_a, _, scores_a = sides[first]
            info_b, _, scores_b = sides[second]
            mismatches, unknown = compare_setups(info_a, info_b)
            blocking = [item["field"] for item in mismatches if item["blocks"]]
            if blocking:
                shared = [name for name, blocks, a, b in _fields(info_a, info_b) if blocks and a is not None and a == b]
                if shared:
                    warnings.append({"kind": "warning", "plan_ids": [first, second],
                                     "label": f"Not comparable, so not ranked against each other (differs in {', '.join(blocking)})"})
            elif len(scores_a) >= 2 and len(scores_b) >= 2 and welch(scores_a, scores_b)["tied"]:
                ties.append({"kind": "tie", "label": "Statistical tie", "plan_ids": [first, second]})
    return ties + warnings
