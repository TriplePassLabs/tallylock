"""A static board of verified registry entries: one HTML file and entries.json."""
from __future__ import annotations

from decimal import Decimal
from html import escape
import json
from pathlib import Path
import shlex

from . import compare, registry as registry_module, tally


BOARD_FORMAT = "tallylock.board.v1"

_STYLE = """
:root { color-scheme: light dark; --bg: #fafaf7; --fg: #1d1d1b; --muted: #66665f; --line: #d9d9d0; --card: #ffffff; --accent: #0b5cad; --warn: #8a4b00; }
@media (prefers-color-scheme: dark) { :root { --bg: #151514; --fg: #ecece6; --muted: #a2a29a; --line: #34342f; --card: #1e1e1c; --accent: #6db3f2; --warn: #f0b765; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 32px 0 8px; }
p.lead, p.note { color: var(--muted); margin: 4px 0 16px; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.wrap { overflow-x: auto; }
.claim { color: var(--muted); font-size: 0.9rem; }
.tag { display: inline-block; padding: 1px 8px; border: 1px solid var(--line); border-radius: 999px; font-size: 0.85rem; }
.warn { color: var(--warn); font-size: 0.9rem; }
code.cmd { display: block; margin-top: 6px; padding: 6px 8px; background: var(--bg); border: 1px solid var(--line); font: 0.8rem/1.4 ui-monospace, monospace; user-select: all; overflow-wrap: anywhere; }
a { color: var(--accent); }
td:first-child, li, p, strong, code, .claim, .warn { overflow-wrap: anywhere; }
th, td[data-label], .tag { white-space: nowrap; }
.wrap { overflow-x: auto; }
table { width: 100%; }
@media (max-width: 640px) {
  thead { display: none; }
  table, tbody, tr, td { display: block; width: 100%; box-sizing: border-box; }
  tr { border-bottom: 1px solid var(--line); padding: 6px 0; }
  td[data-label] { display: flex; gap: 8px; white-space: normal; }
  td[data-label]::before { content: attr(data-label); color: var(--muted); min-width: 4.5em; }
}
"""


def recheck_command(plan_id: str, claim: str) -> str:
    return (f'd=$(mktemp -d) && cp -r REGISTRY/entries/{plan_id}/. "$d" && cd "$d" && git init -q '
            f'&& tallylock check {shlex.quote(claim)}')


def _sort_key(row):
    score = Decimal(row["score"]) if row["score"] is not None else Decimal("-1")
    return (-score, row["title"].lower(), row["plan_id"])


def _row(item: dict) -> dict:
    entry = item["entry"]
    claim = tally.parse_claim(entry["claim"])
    scored = claim["mean"] != "unscored"
    return {"plan_id": entry["plan_id"], "title": entry["title"], "claim": entry["claim"],
            "best": claim["best"], "score": claim["mean"] if scored else None,
            "range": claim["half"], "runs": claim["runs"], "completed": claim["completed"],
            "failed": claim["failed"], "unscored": claim["unscored"], "trust": entry["trust"],
            "source": entry["source"], "submitted_by": entry["submitted_by"], "links": entry["links"],
            "other_plans_not_in_bundle": item["other_plans_not_in_bundle"],
            "recheck": recheck_command(entry["plan_id"], entry["claim"])}


def _cell(text):
    return escape(str(text), quote=True)


def _score(row):
    if row["score"] is None:
        return "unscored"
    return f"{row['score']} ± {row['range']}" if row["range"] is not None else f"{row['score']} (no range)"


def _html(rows, excluded, groups) -> str:
    titles = {row["plan_id"]: row["title"] for row in rows}
    parts = ['<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
             '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
             '<title>TallyLock board</title>\n<style>' + _STYLE + '</style>\n</head>\n<body>\n<main>\n'
             '<h1>TallyLock board</h1>\n'
             '<p class="lead">Every row below was re-checked when this page was built. '
             'Scores show the average over scored runs, not the best run.</p>\n']
    if groups:
        parts.append('<h2>Groups</h2>\n')
        for group in groups:
            names = ", ".join(_cell(titles.get(plan_id, plan_id[:8])) for plan_id in group["plan_ids"])
            css = ' class="warn"' if group["kind"] == "warning" else ""
            parts.append(f'<p{css}><strong>{_cell(group["label"])}</strong>: {names}</p>\n')
    if rows:
        parts.append('<div class="wrap"><table>\n<thead><tr><th>Entry</th><th>Best</th><th>Score</th><th>Runs</th>'
                     '<th>Failed</th><th>Trust</th><th>Source</th></tr></thead>\n<tbody>\n')
        for row in rows:
            links = "".join(f' <a href="{_cell(link)}" rel="noopener nofollow">link</a>' for link in row["links"])
            warning = ('<div class="warn">Other plans from the same repo are not part of this entry.</div>'
                       if row["other_plans_not_in_bundle"] else "")
            parts.append(
                f'<tr><td><strong>{_cell(row["title"])}</strong>{links}'
                f'<div class="claim">{_cell(row["claim"])}</div>{warning}'
                f'<details><summary>Re-check it yourself</summary><code class="cmd">{_cell(row["recheck"])}</code>'
                f'<p class="note">Replace REGISTRY with the path of your registry checkout.</p></details></td>'
                f'<td data-label="Best" class="num">{_cell(row["best"])}</td><td data-label="Score" class="num">{_cell(_score(row))}</td>'
                f'<td data-label="Runs" class="num">{row["runs"]}</td><td data-label="Failed" class="num">{row["failed"]}</td>'
                f'<td data-label="Trust"><span class="tag">{_cell(row["trust"])}</span></td><td data-label="Source">{_cell(row["source"])}'
                f'<div class="claim">by {_cell(row["submitted_by"])}</div></td></tr>\n')
        parts.append('</tbody></table></div>\n')
    else:
        parts.append('<p class="note">No entries have passed verification yet.</p>\n')
    if excluded:
        parts.append('<h2>Could not verify</h2>\n<p class="note">These entries were left off the board.</p>\n<ul>\n')
        for item in excluded:
            parts.append(f'<li><code>{_cell(item["plan_id"][:12])}</code>: {_cell(item["reason"])}</li>\n')
        parts.append('</ul>\n')
    parts.append('</main>\n</body>\n</html>\n')
    return "".join(parts)


def build(registry: Path, out_dir: Path, *, groups: list[dict] | None = None) -> dict:
    """Write index.html and entries.json; groups overrides the tie groups and warnings from compare."""
    report = registry_module.verify_registry(registry)
    rows = sorted((_row(item) for item in report["entries"] if item["ok"]), key=_sort_key)
    excluded = [{"plan_id": item["plan_id"], "reason": item["reason"]} for item in report["entries"] if not item["ok"]]
    if groups is None:
        groups = compare.groups_for_board(registry, report=report)
    groups = [{"kind": group.get("kind", "tie"), "label": str(group["label"]), "plan_ids": list(group["plan_ids"])}
              for group in groups]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {"format": BOARD_FORMAT, "rows": rows, "could_not_verify": excluded, "groups": groups}
    (out_dir/"entries.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    (out_dir/"index.html").write_text(_html(rows, excluded, groups))
    return {"format": BOARD_FORMAT, "rows": len(rows), "excluded": len(excluded), "out": str(out_dir)}
