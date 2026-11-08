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
:root { color-scheme: dark light; --bg: #000000; --ink: #f4f6f8; --muted: #8e9097; --faint: #66676d; --accent: #6aa8f0;
  --accent-soft: rgba(106,168,240,0.14); --rule: rgba(244,246,248,0.12); --panel: rgba(244,246,248,0.03); --warn: #f0b765; }
@media (prefers-color-scheme: light) { :root { --bg: #f4f6f8; --ink: #07090c; --muted: #4f545c; --faint: #6b7079; --accent: #1d5ca8;
  --accent-soft: rgba(29,92,168,0.10); --rule: rgba(7,9,12,0.13); --panel: rgba(255,255,255,0.7); --warn: #8a4b00; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 48px 16px 72px; background: var(--bg); color: var(--ink); font: 16px/1.55 "Schibsted Grotesk", system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
main { max-width: 1040px; margin: 0 auto; }
h1 { font-size: clamp(2rem, 5vw, 3.2rem); line-height: 1.02; letter-spacing: -0.03em; font-weight: 800; margin: 0 0 12px; }
h2 { font-size: 0.8rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); margin: 40px 0 12px; }
p.lead { color: var(--muted); max-width: 46em; margin: 0 0 28px; font-size: 1.05rem; }
p.note { color: var(--faint); font-size: 0.9rem; margin: 10px 0; }
.mono, .claim, code.cmd, td.num { font-family: "JetBrains Mono", ui-monospace, monospace; }
ul.groups { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
ul.groups li { padding: 10px 14px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--panel); border-radius: 6px; }
ul.groups li.warn { border-left-color: var(--warn); }
table { width: 100%; border-collapse: collapse; border: 1px solid var(--rule); border-radius: 8px; overflow: hidden; background: var(--panel); }
th, td { text-align: left; padding: 14px 14px; border-bottom: 1px solid var(--rule); vertical-align: top; }
th { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--faint); }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
td.score { color: var(--accent); font-weight: 600; }
.title { font-weight: 700; font-size: 1.02rem; }
.by { color: var(--faint); font-size: 0.82rem; }
td:first-child { width: 46%; }
.claim { color: var(--muted); font-size: 0.8rem; line-height: 1.6; margin-top: 6px; }
.tag { display: inline-block; padding: 2px 10px; border: 1px solid var(--accent); color: var(--accent); background: var(--accent-soft); border-radius: 999px; font-size: 0.78rem; }
.warn { color: var(--warn); font-size: 0.88rem; margin-top: 6px; }
details { margin-top: 8px; font-size: 0.88rem; color: var(--muted); }
summary { cursor: pointer; }
code.cmd { display: block; margin-top: 6px; padding: 8px 10px; background: var(--bg); border: 1px solid var(--rule); border-radius: 4px; font-size: 0.76rem; line-height: 1.5; user-select: all; overflow-wrap: anywhere; }
a { color: var(--accent); }
td:first-child, li, p, strong, code, .claim, .warn { overflow-wrap: anywhere; }
th, td[data-label], .tag { white-space: nowrap; }
.wrap { overflow-x: auto; }
@media (max-width: 640px) {
  body { padding-top: 28px; }
  thead { display: none; }
  table, tbody, tr, td { display: block; width: 100%; }
  tr { border-bottom: 1px solid var(--rule); padding: 8px 0; }
  td { border-bottom: 0; padding: 6px 14px; }
  td[data-label] { display: flex; gap: 12px; white-space: normal; }
  td[data-label]::before { content: attr(data-label); color: var(--faint); min-width: 4.5em; font-family: system-ui, sans-serif; }
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
             '<title>TallyLock Receipts Board</title>\n<style>' + _STYLE + '</style>\n</head>\n<body>\n<main>\n'
             '<h1>Receipts Board</h1>\n'
             '<p class="lead">Every entry below was re-checked from its recorded runs when this page was built. '
             'The score is the average over completed runs with its 95% range, not the best run, and failed runs are counted.</p>\n']
    if groups:
        parts.append('<h2>Ties and warnings</h2>\n<ul class="groups">\n')
        for group in groups:
            names = " and ".join(_cell(titles.get(plan_id, plan_id[:8])) for plan_id in group["plan_ids"])
            css = ' class="warn"' if group["kind"] == "warning" else ""
            parts.append(f'<li{css}><strong>{_cell(group["label"])}</strong>: {names}</li>\n')
        parts.append('</ul>\n')
    if rows:
        parts.append('<h2>Entries</h2>\n<div class="wrap"><table>\n<thead><tr><th>Entry</th><th>Best</th><th>Score</th><th>Runs</th>'
                     '<th>Failed</th><th>Trust</th><th>Source</th></tr></thead>\n<tbody>\n')
        for row in rows:
            links = "".join(f' <a href="{_cell(link)}" rel="noopener nofollow">link</a>' for link in row["links"])
            # The locked plan number proves earlier plans exist; a larger claimed count alone is not checked.
            number = tally.parse_claim(row["claim"])["plan_number"]
            warning = (f'<div class="warn">Plan {number} in its repo. Only this plan is part of this entry; '
                       'the earlier plans stay in the repo.</div>' if number > 1 else "")
            parts.append(
                f'<tr><td><div class="title">{_cell(row["title"])}{links}</div>'
                f'<div class="claim">{_cell(row["claim"])}</div>{warning}'
                f'<details><summary>Re-check it yourself</summary><code class="cmd">{_cell(row["recheck"])}</code>'
                f'<p class="note">Replace REGISTRY with the path of your registry checkout.</p></details></td>'
                f'<td data-label="Best" class="num">{_cell(row["best"])}</td><td data-label="Score" class="num score">{_cell(_score(row))}</td>'
                f'<td data-label="Runs" class="num">{row["runs"]}</td><td data-label="Failed" class="num">{row["failed"]}</td>'
                f'<td data-label="Trust"><span class="tag">{_cell(row["trust"])}</span></td><td data-label="Source">{_cell(row["source"])}'
                f'<div class="by">by {_cell(row["submitted_by"])}</div></td></tr>\n')
        parts.append('</tbody></table></div>\n')
        if any(row["other_plans_not_in_bundle"] and tally.parse_claim(row["claim"])["plan_number"] == 1 for row in rows):
            parts.append('<p class="note">Some claims count other plans in the same repo. A board entry holds one plan, '
                         'so those plans are not part of it and were not checked here.</p>\n')
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
