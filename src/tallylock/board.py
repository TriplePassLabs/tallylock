"""A static board of verified registry entries: one HTML file and entries.json.

The page is plain HTML that works without scripts. A short inline script only adds the opening animation,
deep links, the Esc key and copy buttons; it never inserts entry text into the page.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from fractions import Fraction
from html import escape
import json
from pathlib import Path
import re
import shlex

from . import __version__, compare, ledger, registry as registry_module, tally


BOARD_FORMAT = "tallylock.board.v1"

_STYLE = """
:root { color-scheme: dark light; --bg: #000000; --ink: #f4f6f8; --muted: #8e9097; --faint: #66676d; --accent: #6aa8f0;
  --accent-soft: rgba(106,168,240,0.14); --glow: rgba(106,168,240,0.28); --rule: rgba(244,246,248,0.12);
  --panel: rgba(244,246,248,0.035); --panel-hi: rgba(244,246,248,0.06); --warn: #f0b765; --bad: #f07a6a; --good: #7fd6a4; }
@media (prefers-color-scheme: light) { :root { --bg: #f4f6f8; --ink: #07090c; --muted: #4f545c; --faint: #6b7079; --accent: #1d5ca8;
  --accent-soft: rgba(29,92,168,0.10); --glow: rgba(29,92,168,0.18); --rule: rgba(7,9,12,0.13); --panel: rgba(255,255,255,0.72);
  --panel-hi: #ffffff; --warn: #8a4b00; --bad: #b3261e; --good: #1d7a46; } }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; padding: 48px 16px 72px; background: var(--bg); color: var(--ink); font: 16px/1.55 "Schibsted Grotesk", system-ui, sans-serif;
  -webkit-font-smoothing: antialiased; overflow-x: hidden; }
main { max-width: 1040px; margin: 0 auto; }
a { color: var(--accent); }
p, li, dd, strong, code, .claim, .warn, .title { overflow-wrap: anywhere; }
.mono, .claim, code.cmd, .num { font-family: "JetBrains Mono", ui-monospace, monospace; font-variant-numeric: tabular-nums; }
h1 { font-size: clamp(2.2rem, 6vw, 3.6rem); line-height: 1; letter-spacing: -0.035em; font-weight: 800; margin: 0 0 14px; }
h2 { font-size: 0.78rem; font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin: 0 0 10px; }
p.lead { color: var(--muted); max-width: 44em; margin: 0 0 28px; font-size: 1.06rem; }
p.note { color: var(--faint); font-size: 0.88rem; margin: 10px 0; }
.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 0 0 18px; padding: 0; }
.stats div { border: 1px solid var(--rule); background: var(--panel); border-radius: 14px; padding: 14px 16px; }
.stats dt { font-size: 0.72rem; letter-spacing: 0.1em; text-transform: uppercase; color: var(--faint); }
.stats dd { margin: 4px 0 0; font-size: 1.9rem; font-weight: 800; letter-spacing: -0.02em; line-height: 1.1; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 0.84rem; color: var(--muted); margin: 0 0 8px; }
.legend span { display: inline-flex; align-items: center; gap: 8px; }
.key { position: relative; display: inline-block; width: 22px; height: 12px; }
.key.k-dot::after, .key.k-band::after, .key.k-tick::after { content: ""; position: absolute; top: 50%; transform: translate(-50%, -50%); left: 50%; }
.key.k-dot::after { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
.key.k-band::after { width: 22px; height: 6px; border-radius: 3px; background: var(--accent-soft); box-shadow: inset 0 0 0 1px var(--accent); }
.key.k-tick::after { width: 8px; height: 8px; border: 2px solid var(--ink); border-radius: 2px; transform: translate(-50%, -50%) rotate(45deg); }
.bench { margin-top: 44px; }
.bench-title { font-size: 1.25rem; font-weight: 700; letter-spacing: -0.01em; margin: 0 0 10px; line-height: 1.3; }
.setup { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 18px; }
.chip { display: inline-block; max-width: 100%; padding: 3px 10px; border: 1px solid var(--rule); border-radius: 999px; font-size: 0.76rem;
  color: var(--muted); background: var(--panel); overflow-wrap: anywhere; }
.chip b { color: var(--ink); font-weight: 600; }
.axis { display: grid; grid-template-columns: 2.2rem minmax(0, 30%) minmax(0, 1fr) 7.6rem 1.4rem; gap: 14px; padding: 0 18px; margin-bottom: 6px; }
.axis .scale { grid-column: 3; display: flex; justify-content: space-between; font-size: 0.72rem; color: var(--faint); }
ol.ladder { list-style: none; margin: 0; padding: 0; display: grid; gap: 0; }
ol.ladder > li { margin: 0; }
.tie-link { display: flex; align-items: center; gap: 10px; padding: 3px 0 3px 34px; font-size: 0.76rem; color: var(--accent); }
.tie-link::before { content: ""; width: 2px; height: 18px; background: var(--accent); border-radius: 1px; opacity: 0.7; }
.gap { height: 10px; }
details.entry { border: 1px solid var(--rule); border-radius: 30px; background: var(--panel);
  transition: border-radius 0.45s cubic-bezier(.2,.8,.2,1), border-color 0.3s, background 0.3s, box-shadow 0.45s, opacity 0.35s, filter 0.35s; }
details.entry[open] { border-radius: 20px; border-color: var(--accent); background: var(--panel-hi);
  box-shadow: 0 0 0 1px var(--accent), 0 18px 60px -18px var(--glow); }
.ladder:has(details[open]) details.entry:not([open]) { opacity: 0.5; filter: saturate(0.5); }
.ladder:has(details[open]) details.entry:not([open]):hover { opacity: 0.85; }
details.entry > summary { list-style: none; cursor: pointer; display: grid; align-items: center; gap: 14px;
  grid-template-columns: 2.2rem minmax(0, 30%) minmax(0, 1fr) 7.6rem 1.4rem; padding: 12px 18px; min-height: 60px; border-radius: 30px; }
details.entry > summary::-webkit-details-marker { display: none; }
summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
details.entry:not([open]) > summary:hover { background: var(--panel-hi); }
.rank { font-weight: 800; font-size: 1.05rem; color: var(--faint); text-align: center; }
details[open] .rank { color: var(--accent); }
.who { min-width: 0; display: grid; }
.who .title { font-weight: 700; font-size: 1.02rem; line-height: 1.25; }
.who .sub { color: var(--faint); font-size: 0.78rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.track { position: relative; height: 22px; }
.track::before { content: ""; position: absolute; left: 0; right: 0; top: 50%; height: 1px; background: var(--rule); }
.band { position: absolute; top: 50%; height: 8px; transform: translateY(-50%); border-radius: 4px; background: var(--accent-soft);
  box-shadow: inset 0 0 0 1px var(--accent); }
.mean { position: absolute; top: 50%; width: 12px; height: 12px; margin-left: -6px; transform: translateY(-50%); border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 0 3px var(--bg); }
.best { position: absolute; top: 50%; width: 9px; height: 9px; margin-left: -4.5px; border: 2px solid var(--ink); border-radius: 2px;
  transform: translateY(-50%) rotate(45deg); }
.run { position: absolute; top: 50%; width: 9px; height: 9px; margin-left: -4.5px; transform: translateY(-50%); border-radius: 50%;
  background: var(--ink); opacity: 0.85; box-shadow: 0 0 0 2px var(--panel-hi); }
.nums { text-align: right; white-space: nowrap; }
.nums .score { color: var(--accent); font-weight: 600; font-size: 1.02rem; }
.nums .pm { color: var(--muted); font-size: 0.8rem; margin-left: 4px; }
.nums .bestnum { display: block; color: var(--faint); font-size: 0.72rem; }
.chev { width: 10px; height: 10px; border-right: 2px solid var(--faint); border-bottom: 2px solid var(--faint); transform: rotate(45deg);
  transition: transform 0.4s cubic-bezier(.2,.8,.2,1); justify-self: center; margin-top: -4px; }
details[open] .chev { transform: rotate(-135deg); margin-top: 4px; border-color: var(--accent); }
.panel { overflow: hidden; }
.panel-in { padding: 4px 22px 22px; display: grid; gap: 22px; }
.fulltitle { margin: 0; color: var(--muted); font-size: 0.92rem; }
.panel h3 { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--faint); margin: 0 0 8px; }
.runs .track { display: block; height: 30px; }
.runs .track .run { width: 11px; height: 11px; margin-left: -5.5px; }
.fails { margin-top: 6px; font-size: 0.82rem; color: var(--bad); }
.fails .x { font-weight: 800; margin-right: 2px; }
.facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 0; }
.facts div { border: 1px solid var(--rule); border-radius: 12px; padding: 10px 12px; min-width: 0; }
.facts dt { font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; color: var(--faint); }
.facts dd { margin: 2px 0 0; font-size: 0.92rem; }
.tag { display: inline-block; padding: 1px 10px; border: 1px solid var(--accent); color: var(--accent); background: var(--accent-soft);
  border-radius: 999px; font-size: 0.78rem; }
ol.timeline { list-style: none; margin: 0; padding: 0 0 0 4px; }
ol.timeline li { position: relative; padding: 0 0 14px 24px; font-size: 0.9rem; }
ol.timeline li::before { content: ""; position: absolute; left: 0; top: 6px; width: 10px; height: 10px; border-radius: 50%;
  background: var(--bg); box-shadow: inset 0 0 0 2px var(--accent); }
ol.timeline li.done::before { background: var(--accent); }
ol.timeline li.wait::before { box-shadow: inset 0 0 0 2px var(--warn); }
ol.timeline li:not(:last-child)::after { content: ""; position: absolute; left: 4px; top: 18px; bottom: 0; width: 2px; background: var(--rule); }
ol.timeline strong { display: block; font-weight: 600; }
ol.timeline span { color: var(--muted); }
.versus { display: flex; flex-wrap: wrap; gap: 8px; }
.versus .chip.ahead { border-color: var(--good); color: var(--good); }
.versus .chip.tied { border-color: var(--accent); color: var(--accent); }
.block { position: relative; }
.claim { color: var(--muted); font-size: 0.8rem; line-height: 1.6; margin: 0; padding: 10px 12px; border: 1px solid var(--rule); border-radius: 10px; }
code.cmd { display: block; padding: 10px 12px; background: var(--bg); border: 1px solid var(--rule); border-radius: 10px; font-size: 0.76rem;
  line-height: 1.5; user-select: all; overflow-wrap: anywhere; }
.bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px; }
.bar h3 { margin: 0; }
button.copy { font: 600 0.74rem/1 "Schibsted Grotesk", system-ui, sans-serif; color: var(--accent);
  background: transparent; border: 1px solid var(--rule); border-radius: 999px; padding: 6px 12px; cursor: pointer; }
button.copy:hover { border-color: var(--accent); }
.warn { color: var(--warn); font-size: 0.88rem; }
.by { color: var(--faint); font-size: 0.82rem; }
ul.groups { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
ul.groups li { padding: 10px 14px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--panel); border-radius: 8px; font-size: 0.92rem; }
ul.groups li.warn { border-left-color: var(--warn); }
.section { margin-top: 44px; }
footer { margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--rule); color: var(--faint); font-size: 0.84rem; }
@media (max-width: 720px) {
  body { padding-top: 28px; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .stats dd { font-size: 1.6rem; }
  .axis { grid-template-columns: 2rem minmax(0, 1fr) auto 1.2rem; padding: 0 14px; }
  .axis .scale { grid-column: 1 / -1; }
  details.entry > summary { grid-template-columns: 2rem minmax(0, 1fr) auto 1.2rem; grid-template-areas: "rank who nums chev" "track track track track";
    gap: 6px 10px; padding: 12px 14px; border-radius: 24px; }
  details.entry { border-radius: 24px; }
  .rank { grid-area: rank; } .who { grid-area: who; } .nums { grid-area: nums; } .chev { grid-area: chev; }
  summary > .track { grid-area: track; }
  .panel-in { padding: 4px 14px 18px; }
  .facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tie-link { padding-left: 24px; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition: none !important; scroll-behavior: auto !important; } }
"""

# Progressive enhancement only: animation, deep links, Esc and copy. It reads ids and text, never writes HTML.
_SCRIPT = """
(() => {
  const d = document, still = matchMedia("(prefers-reduced-motion: reduce)");
  d.documentElement.classList.add("js");
  const entries = [...d.querySelectorAll("details.entry")];
  const setHash = (id) => history.replaceState(null, "", id ? "#" + id : location.pathname + location.search);
  function toggle(el, open, quiet) {
    const panel = el.querySelector(".panel");
    if (el._anim) { el._anim.cancel(); el._anim = null; }
    if (still.matches || quiet || !panel.animate) { el.open = open; return; }
    if (open) {
      el.open = true;
      const h = panel.scrollHeight;
      el._anim = panel.animate([{ height: "0px", opacity: 0, transform: "translateY(-8px)" },
                                { height: h + "px", opacity: 1, transform: "none" }],
                               { duration: 520, easing: "cubic-bezier(.2,.8,.2,1)" });
    } else {
      const h = panel.offsetHeight;
      el._anim = panel.animate([{ height: h + "px", opacity: 1 }, { height: "0px", opacity: 0 }],
                               { duration: 300, easing: "cubic-bezier(.4,0,.2,1)" });
      el._anim.onfinish = () => { el.open = false; el._anim = null; };
    }
  }
  function show(el, quiet) {
    for (const other of entries) if (other !== el && other.open) toggle(other, false, quiet);
    toggle(el, true, quiet);
    setHash(el.id);
    requestAnimationFrame(() => el.scrollIntoView({ block: "nearest", behavior: still.matches || quiet ? "auto" : "smooth" }));
  }
  for (const el of entries) {
    el.querySelector("summary").addEventListener("click", (event) => {
      event.preventDefault();
      if (el.open && !(el._anim && el._anim.onfinish)) { toggle(el, false); setHash(""); } else show(el);
    });
  }
  d.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const el = entries.find((item) => item.open);
    if (el) { toggle(el, false); setHash(""); el.querySelector("summary").focus(); }
  });
  const fromHash = () => {
    const el = d.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (el && entries.includes(el)) show(el, true);
  };
  addEventListener("hashchange", fromHash);
  fromHash();
  for (const button of d.querySelectorAll("button.copy")) {
    button.hidden = false;
    button.addEventListener("click", () => {
      const source = d.getElementById(button.dataset.copy);
      if (!source || !navigator.clipboard) return;
      navigator.clipboard.writeText(source.textContent).then(() => {
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = "Copy"; }, 1600);
      });
    });
  }
})();
"""


def recheck_command(plan_id: str, claim: str) -> str:
    return (f'd=$(mktemp -d) && cp -r REGISTRY/entries/{plan_id}/. "$d" && cd "$d" && git init -q '
            f'&& tallylock check {shlex.quote(claim)}')


def _sort_key(row):
    score = Decimal(row["score"]) if row["score"] is not None else Decimal("-1")
    return (-score, row["title"].lower(), row["plan_id"])


def _fraction(score):
    return None if score is None else Fraction(score["numerator"], score["denominator"])


def _row(item: dict, root: Path) -> dict:
    entry = item["entry"]
    claim = tally.parse_claim(entry["claim"])
    scored = claim["mean"] != "unscored"
    folder = root/"entries"/entry["plan_id"]
    checked = ledger.verify_ledger(folder, entry["plan_id"])
    info = ledger.load_plan(folder, entry["plan_id"])["metadata"]["tallylock_plan"]
    attempts = [{"seq": e["seq"], "outcome": e["outcome"], "duration_ms": e["duration_ms"],
                 "score": None if e["score"] is None else tally._display(_fraction(e["score"]))} for e in checked["ledger"]]
    return {"plan_id": entry["plan_id"], "title": entry["title"], "claim": entry["claim"],
            "best": claim["best"], "score": claim["mean"] if scored else None,
            "range": claim["half"], "runs": claim["runs"], "completed": claim["completed"],
            "failed": claim["failed"], "unscored": claim["unscored"], "trust": entry["trust"],
            "source": entry["source"], "submitted_by": entry["submitted_by"], "links": entry["links"],
            "other_plans_not_in_bundle": item["other_plans_not_in_bundle"],
            "recheck": recheck_command(entry["plan_id"], entry["claim"]),
            "attempts": attempts, "setup": info.get("setup"), "head": info.get("head"), "argv": info.get("argv"),
            "instant_timestamps": [{k: s[k] for k in ("seq", "tsa", "state", "time")} for s in checked["instant_timestamps"]],
            "bitcoin": [{"seq": a["seq"], "state": a["state"], "heights": a["heights"]} for a in checked["anchors"]],
            "_scores": [_fraction(e["score"]) for e in checked["ledger"] if e["outcome"] == "completed" and e["score"] is not None]}


def _cell(text):
    return escape(str(text), quote=True)


def _benchmark_key(setup):
    """Rows share a benchmark when every ranking field of their setups agrees; no setup is its own group."""
    if not isinstance(setup, dict):
        return None
    dataset = setup.get("dataset") or {}
    return json.dumps([dataset.get("sha256") or [dataset.get("name"), dataset.get("version")],
                       setup.get("harness"), setup.get("prompt_template_sha256"), setup.get("decoding")], sort_keys=True)


def _sections(rows):
    order, sections = [], {}
    for row in rows:
        key = _benchmark_key(row["setup"])
        if key not in sections:
            sections[key] = []
            order.append(key)
        sections[key].append(row)
    return [sections[key] for key in order]


def _axis(rows):
    values = []
    for row in rows:
        values += [float(s) for s in row["_scores"]]
        if row["score"] is not None and row["range"] is not None:
            values += [float(row["score"]) - float(row["range"]), float(row["score"]) + float(row["range"])]
    if not values:
        return None
    low, high = min(values), max(values)
    pad = (high - low) * 0.08 if high > low else 0.01
    return low - pad, high + pad


def _at(axis, value):
    low, high = axis
    return f"{max(0.0, min(100.0, (float(value) - low) / (high - low) * 100)):.2f}%"


def _track(row, axis, runs=False):
    if axis is None:
        return '<span class="track"></span>'
    parts = ['<span class="track">']
    if runs:
        for attempt in row["attempts"]:
            if attempt["score"] is not None:
                parts.append(f'<span class="run" style="left:{_at(axis, attempt["score"])}" title="run {attempt["seq"]}: {attempt["score"]}"></span>')
    else:
        if row["score"] is not None and row["range"] is not None:
            low = float(row["score"]) - float(row["range"])
            high = float(row["score"]) + float(row["range"])
            width = float(_at(axis, high)[:-1]) - float(_at(axis, low)[:-1])
            parts.append(f'<span class="band" style="left:{_at(axis, low)};width:{width:.2f}%"></span>')
        if row["best"] not in (None, "unscored"):
            parts.append(f'<span class="best" style="left:{_at(axis, row["best"])}" title="best run {row["best"]}"></span>')
        if row["score"] is not None:
            parts.append(f'<span class="mean" style="left:{_at(axis, row["score"])}" title="score {row["score"]}"></span>')
    parts.append('</span>')
    return "".join(parts)


def _score(row):
    if row["score"] is None:
        return "unscored"
    return f"{row['score']} ± {row['range']}" if row["range"] is not None else f"{row['score']} (no range)"


def _slug(title, used):
    # The name before any "(" or "," makes a short link: "Quentin (Qwen3 0.6B)" becomes #quentin.
    short = re.split(r"[(,]", title, maxsplit=1)[0]
    base = re.sub(r"[^a-z0-9]+", "-", (short if short.strip() else title).lower()).strip("-")[:32].strip("-") or "entry"
    slug, number = base, 2
    while slug in used:
        slug, number = f"{base}-{number}", number + 1
    used.add(slug)
    return slug


def _verdict(row, other, names=None):
    """This row against another in the same benchmark, with the same Welch rule as tallylock compare."""
    name = _cell((names or {}).get(other["plan_id"], other["title"]))
    if len(row["_scores"]) < 2 or len(other["_scores"]) < 2:
        return "", f"Not enough runs to tell against {name}"
    result = compare.welch(row["_scores"], other["_scores"])
    if result["tied"]:
        return "tied", f"Tied with {name}"
    if result["positive"]:
        return "ahead", f"Ahead of {name} beyond noise"
    return "", f"Behind {name} beyond noise"


def _when(text):
    moment = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
    return f"{moment:%b} {moment.day}, {moment:%Y %H:%M} UTC"


def _duration(ms):
    seconds = round(ms / 1000)
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


def _timeline(row):
    steps = []
    head = (row["head"] or "")[:7]
    command = " ".join(row["argv"] or [])
    steps.append(("done", "Plan locked", f'Commit <span class="mono">{_cell(head) or "unknown"}</span>, command '
                  f'<span class="mono">{_cell(command)}</span>. Changing either starts a new plan.'))
    total = sum(a["duration_ms"] for a in row["attempts"])
    steps.append(("done", f'{row["runs"]} run{"s" if row["runs"] != 1 else ""} recorded',
                  f'{row["completed"]} completed, {row["failed"]} failed, {_duration(total)} in all. Every run is in the ledger.'))
    stamps = row["instant_timestamps"]
    good = [s for s in stamps if s["state"] == "verified" and s["time"]]
    if stamps:
        times = sorted(s["time"] for s in good)
        services = len({s["tsa"] for s in stamps})
        span = f' from {_when(times[0])} to {_when(times[-1])}' if times else ""
        steps.append(("done" if len(good) == len(stamps) else "wait", "Instant timestamps",
                      f'{len(good)} of {len(stamps)} verified from {services} public service{"s" if services != 1 else ""}{span}.'))
    proofs = row["bitcoin"]
    if proofs:
        heights = sorted({h for p in proofs for h in p["heights"]})
        if heights and all(p["heights"] for p in proofs):
            blocks = ", ".join(f"{h:,}" for h in heights)
            steps.append(("done", "Bitcoin timestamp", f'Every ledger update is in Bitcoin block {blocks}. '
                          'Check the blocks with <span class="mono">tallylock check --online</span>.'))
        else:
            waiting = sum(1 for p in proofs if not p["heights"])
            steps.append(("wait", "Bitcoin timestamp", f'{waiting} of {len(proofs)} proofs still waiting for a Bitcoin block. '
                          'They finish a few hours after each run with <span class="mono">tallylock refresh</span>.'))
    return ('<ol class="timeline">' + "".join(f'<li class="{css}"><strong>{title}</strong><span>{text}</span></li>'
                                               for css, title, text in steps) + '</ol>')


def _entry(row, rank, axis, peers, slug, names):
    shown = names[row["plan_id"]]
    short = row["plan_id"][:12]
    setup = row["setup"] or {}
    model = (setup.get("model") or {}).get("name")
    sub = model or f"by {row['submitted_by']}"
    links = " ".join(f'<a href="{_cell(link)}" rel="noopener nofollow">{_cell(link)}</a>' for link in row["links"])
    number = tally.parse_claim(row["claim"])["plan_number"]
    # The locked plan number proves earlier plans exist; a larger claimed count alone is not checked.
    warning = (f'<p class="warn">Plan {number} in its repo. Only this plan is part of this entry; '
               'the earlier plans stay in the repo.</p>' if number > 1 else "")
    if row["score"] is None:
        nums = '<span class="score">unscored</span>'
    else:
        pm = f'<span class="pm">± {_cell(row["range"])}</span>' if row["range"] is not None else '<span class="pm">no range</span>'
        nums = f'<span class="score">{_cell(row["score"])}</span>{pm}'
    nums += f'<span class="bestnum">best {_cell(row["best"])}</span>'
    failed = [a for a in row["attempts"] if a["outcome"] != "completed"]
    fails = ""
    if failed:
        marks = " ".join(f'<span class="x" title="run {a["seq"]} failed">✕</span>' for a in failed)
        fails = (f'<div class="fails">{marks} {len(failed)} failed run{"s" if len(failed) != 1 else ""}: '
                 'counted in the claim, never averaged in.</div>')
    versus = "".join(f'<span class="chip {css}">{text}</span>' for css, text in (_verdict(row, other, names) for other in peers))
    facts = [("Score", _cell(_score(row))), ("Best run", f'{_cell(row["best"])} <span class="by">(not the score)</span>'),
             ("Runs", f'{row["runs"]} recorded, {row["failed"]} failed'), ("Model", _cell(model or "not recorded")),
             ("Trust", f'<span class="tag">{_cell(row["trust"])}</span>'),
             ("Source", f'{_cell(row["source"])}, by {_cell(row["submitted_by"])}')]
    panel = [f'<p class="fulltitle">{_cell(row["title"])}</p>' if shown != row["title"] else "",
             f'<div class="runs"><h3>Every run</h3>{_track(row, axis, runs=True)}{fails}</div>',
             '<dl class="facts">' + "".join(f'<div><dt>{name}</dt><dd>{value}</dd></div>' for name, value in facts) + '</dl>',
             f'<div><h3>Record</h3>{_timeline(row)}</div>']
    if versus:
        panel.append(f'<div><h3>Against the others here</h3><div class="versus">{versus}</div></div>')
    panel.append(f'<div class="block"><div class="bar"><h3>Claim line</h3><button class="copy" type="button" data-copy="c-{short}" hidden>Copy</button></div>'
                 f'<p class="claim" id="c-{short}">{_cell(row["claim"])}</p>{warning}</div>')
    panel.append(f'<div class="block"><div class="bar"><h3>Re-check it yourself</h3><button class="copy" type="button" data-copy="r-{short}" hidden>Copy</button></div>'
                 f'<code class="cmd" id="r-{short}">{_cell(row["recheck"])}</code>'
                 f'<p class="note">Replace REGISTRY with the path of your registry checkout. Plan <span class="mono">{short}</span>.'
                 f'{" Links: " + links if links else ""}</p></div>')
    return (f'<details class="entry" id="{slug}"><summary><span class="rank">{rank}</span>'
            f'<span class="who"><span class="title">{_cell(shown)}</span><span class="sub">{_cell(sub)}</span></span>'
            f'{_track(row, axis)}<span class="nums num">{nums}</span><span class="chev" aria-hidden="true"></span></summary>'
            f'<div class="panel"><div class="panel-in">{"".join(panel)}</div></div></details>')


def _short_titles(section):
    """Drop words that end every title in a benchmark, such as " on Dataset X", so each pill shows only the difference."""
    titles = [row["title"] for row in section]
    if len(titles) > 1:
        tail = titles[0]
        for title in titles[1:]:
            while not title.endswith(tail):
                tail = tail[1:]
        # Cut at a space where every remaining name is whole: brackets closed, no trailing comma.
        for index, char in enumerate(tail):
            rest = tail[index:]
            heads = [title[:-len(rest)].strip() for title in titles]
            if (char == " " and len(rest) >= 10 and all(heads)
                    and all(head.count("(") == head.count(")") and not head.endswith(",") for head in heads)):
                return {row["plan_id"]: head for row, head in zip(section, heads)}
    return {row["plan_id"]: row["title"] for row in section}


def _setup_chips(setup):
    if not isinstance(setup, dict):
        return '<p class="note">These entries recorded no setup file, so nothing says they share a benchmark.</p>'
    chips = []
    harness = setup.get("harness") or {}
    if harness.get("name"):
        chips.append(("Harness", harness["name"]))
    if setup.get("prompt_template_sha256"):
        chips.append(("Prompt template", setup["prompt_template_sha256"][:12]))
    dataset = setup.get("dataset") or {}
    if dataset.get("sha256"):
        chips.append(("Dataset", dataset["sha256"][:12]))
    for name, value in sorted((setup.get("decoding") or {}).items()):
        chips.append((name, value))
    return '<div class="setup">' + "".join(f'<span class="chip">{_cell(k)} <b>{_cell(v)}</b></span>' for k, v in chips) + '</div>'


def _html(rows, excluded, groups) -> str:
    titles = {row["plan_id"]: row["title"] for row in rows}
    sections = _sections(rows)
    parts = ['<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
             '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
             '<title>TallyLock Receipts Board</title>\n<style>' + _STYLE + '</style>\n</head>\n<body>\n<main>\n'
             '<header>\n<h1>Receipts Board</h1>\n'
             '<p class="lead">Every entry below was re-checked from its recorded runs when this page was built. '
             'The score is the average over completed runs with its 95% range, not the best run, and failed runs are counted. '
             'Tap an entry to see every run.</p>\n'
             '<dl class="stats">'
             f'<div><dt>Entries</dt><dd class="num">{len(rows)}</dd></div>'
             f'<div><dt>Runs recorded</dt><dd class="num">{sum(row["runs"] for row in rows)}</dd></div>'
             f'<div><dt>Failed runs counted</dt><dd class="num">{sum(row["failed"] for row in rows)}</dd></div>'
             f'<div><dt>Benchmarks</dt><dd class="num">{len(sections)}</dd></div></dl>\n'
             '<p class="legend"><span><i class="key k-dot"></i>score (average of runs)</span><span><i class="key k-band"></i>95% range</span>'
             '<span><i class="key k-tick"></i>best single run</span></p>\n</header>\n']
    used, short_names = set(), {}
    for index, section in enumerate(sections, 1):
        setup = section[0]["setup"]
        dataset = (setup or {}).get("dataset") or {} if isinstance(setup, dict) else {}
        name = dataset.get("name") or ("No setup recorded" if not isinstance(setup, dict) else "Unnamed dataset")
        axis = _axis(section)
        parts.append(f'<section class="bench">\n<h2>Benchmark {index}</h2>\n<p class="bench-title">{_cell(name)}</p>\n'
                     f'{_setup_chips(setup)}\n')
        if axis is not None:
            low, high = axis
            parts.append(f'<div class="axis" aria-hidden="true"><span class="scale num"><span>{low:.3f}</span>'
                         f'<span>{(low + high) / 2:.3f}</span><span>{high:.3f}</span></span></div>\n')
        names = _short_titles(section)
        short_names.update(names)
        parts.append('<ol class="ladder">\n')
        for rank, row in enumerate(section, 1):
            if rank > 1:
                previous = section[rank - 2]
                css, _ = _verdict(previous, row)
                parts.append('<li class="tie-link" aria-hidden="true">statistical tie: the gap is within run-to-run noise</li>\n'
                             if css == "tied" else '<li class="gap" aria-hidden="true"></li>\n')
            peers = [other for other in section if other is not row]
            parts.append(f'<li>{_entry(row, rank, axis, peers, _slug(row["title"], used), short_names)}</li>\n')
        parts.append('</ol>\n</section>\n')
    if not rows:
        parts.append('<p class="note">No entries have passed verification yet.</p>\n')
    if groups:
        parts.append('<section class="section">\n<h2>Ties and warnings</h2>\n<ul class="groups">\n')
        for group in groups:
            names = " and ".join(_cell(short_names.get(plan_id, titles.get(plan_id, plan_id[:8]))) for plan_id in group["plan_ids"])
            css = ' class="warn"' if group["kind"] == "warning" else ""
            parts.append(f'<li{css}><strong>{_cell(group["label"])}</strong>: {names}</li>\n')
        parts.append('</ul>\n</section>\n')
    if excluded:
        parts.append('<section class="section">\n<h2>Could not verify</h2>\n<p class="note">These entries were left off the board.</p>\n<ul>\n')
        for item in excluded:
            parts.append(f'<li><code>{_cell(item["plan_id"][:12])}</code>: {_cell(item["reason"])}</li>\n')
        parts.append('</ul>\n</section>\n')
    parts.append('<footer>\n')
    if any(row["other_plans_not_in_bundle"] and tally.parse_claim(row["claim"])["plan_number"] == 1 for row in rows):
        parts.append('<p class="note">Some claims count other plans in the same repo. A board entry holds one plan, '
                     'so those plans are not part of it and were not checked here.</p>\n')
    parts.append('<p>Entries are ranked only against others on the same benchmark: same dataset, harness, prompt template and '
                 f'decoding settings. Built with TallyLock {_cell(__version__)}. The data is in '
                 '<a href="entries.json">entries.json</a>.</p>\n</footer>\n'
                 '</main>\n<script>' + _SCRIPT + '</script>\n</body>\n</html>\n')
    return "".join(parts)


def build(registry: Path, out_dir: Path, *, groups: list[dict] | None = None) -> dict:
    """Write index.html and entries.json; groups overrides the tie groups and warnings from compare."""
    registry = Path(registry)
    report = registry_module.verify_registry(registry)
    rows = sorted((_row(item, registry) for item in report["entries"] if item["ok"]), key=_sort_key)
    excluded = [{"plan_id": item["plan_id"], "reason": item["reason"]} for item in report["entries"] if not item["ok"]]
    if groups is None:
        groups = compare.groups_for_board(registry, report=report)
    groups = [{"kind": group.get("kind", "tie"), "label": str(group["label"]), "plan_ids": list(group["plan_ids"])}
              for group in groups]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    public = [{key: value for key, value in row.items() if not key.startswith("_")} for row in rows]
    data = {"format": BOARD_FORMAT, "rows": public, "could_not_verify": excluded, "groups": groups}
    (out_dir/"entries.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    (out_dir/"index.html").write_text(_html(rows, excluded, groups))
    return {"format": BOARD_FORMAT, "rows": len(rows), "excluded": len(excluded), "out": str(out_dir)}
