"""Exported plan bundles and a registry of entries that each verify on their own."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import shutil

from . import ledger, tally
from .errors import TallyLockError


ENTRY_FORMAT = "tallylock.registry-entry.v1"
REPORT_FORMAT = "tallylock.registry-verification.v1"
TRUSTS = ("anchored", "signed", "declared")
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_FILES = 100000
_ENTRY_LIMIT = 64 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REQUIRED = {"source", "trust", "title", "submitted_by"}
_OPTIONAL = {"links", "claim"}
_LIMITS = {"source": 64, "title": 200, "submitted_by": 100, "claim": 1000}


def _require(condition, message, code=2):
    if not condition:
        raise TallyLockError(message, code=code)


def _plan_directory(root: Path, plan_id: str) -> Path:
    _require(isinstance(plan_id, str) and _HEX.fullmatch(plan_id), "plan IDs are 64 lowercase hex characters")
    return Path(root)/".tallylock"/"plans"/plan_id


def _check_tree(source: Path) -> None:
    """Allow only regular files and directories, within size and count limits."""
    files = size = 0
    for current, directories, names in os.walk(source, followlinks=False):
        for name in directories + names:
            path = Path(current)/name
            _require(not path.is_symlink(), "bundles cannot contain links")
            if name in names:
                _require(path.is_file(), "bundles can only contain regular files")
                files += 1
                size += path.stat().st_size
    _require(files <= MAX_BUNDLE_FILES and size <= MAX_BUNDLE_BYTES, "this plan is too large to export")


def export(repo: Path, plan_id: str, out_dir: Path) -> Path:
    """Copy one plan into a bundle directory whose root verifies like a repo root."""
    source = _plan_directory(repo, plan_id)
    _require(source.is_dir() and not source.is_symlink() and (source/"manifest.json").is_file(),
             f"plan {plan_id[:8]} was not found")
    out_dir = Path(out_dir)
    _require(not out_dir.exists() or (out_dir.is_dir() and not any(out_dir.iterdir())),
             "the output folder must be new or empty")
    _check_tree(source)
    target = _plan_directory(out_dir, plan_id)
    target.parent.mkdir(parents=True)
    try:
        shutil.copytree(source, target, symlinks=True)
    except BaseException:
        shutil.rmtree(out_dir/".tallylock", ignore_errors=True)
        raise
    return out_dir


def _text(value, name):
    _require(isinstance(value, str) and value.strip() == value and value and value.isprintable(),
             f"{name} must be plain text on one line")
    _require(len(value) <= _LIMITS[name], f"{name} is too long")
    return value


def _meta(meta: dict) -> dict:
    _require(isinstance(meta, dict) and _REQUIRED <= set(meta) <= _REQUIRED | _OPTIONAL,
             "entry details need source, trust, title and submitted_by, and may add links and claim")
    clean = {name: _text(meta[name], name) for name in ("source", "title", "submitted_by")}
    _require(meta["trust"] in TRUSTS, "trust must be anchored, signed or declared")
    clean["trust"] = meta["trust"]
    links = meta.get("links", [])
    _require(isinstance(links, list) and len(links) <= 10, "links must be a short list")
    for link in links:
        _require(isinstance(link, str) and re.fullmatch(r"https?://[^\s<>\"']{1,500}", link), "links must be http or https addresses")
    clean["links"] = list(links)
    if "claim" in meta:
        clean["claim"] = _text(meta["claim"], "claim")
    return clean


def _check_entry(root: Path, plan_id: str, claim: str) -> dict:
    """Verify the ledger and the claim; a bundle holds one plan, so the plan count is noted, not rechecked."""
    checked = ledger.verify_ledger(root, plan_id)
    verdict = tally.check_claim(root, claim, bundle=True)
    if verdict["plan_id"] != plan_id:
        return {"ok": False, "reason": "the claim names a different plan"}
    if verdict["verdict"] == "match" and verdict["seq"] != checked["entries"]:
        # An older head is a true claim about fewer runs; the board must show every run, so it needs the latest.
        return {"ok": False, "reason": f"the claim covers {verdict['seq']} of {checked['entries']} runs; "
                                       "claim the latest ledger head"}
    if verdict["verdict"] == "match":
        return {"ok": True, "other_plans_not_in_bundle": tally.parse_claim(claim)["plans"] > 1}
    item = verdict["reasons"][0]
    return {"ok": False, "reason": f"the claim does not match the ledger: {item['field']} says {item['claimed']}, ledger says {item['actual']}"}


def add_entry(registry: Path, bundle_or_repo: Path, plan_id: str, meta: dict) -> dict:
    """Verify one plan, store its bundle under entries/<plan_id> and write entry.json."""
    clean = _meta(meta)
    source = Path(bundle_or_repo)
    ledger.load_plan(source, plan_id)
    claim = clean.get("claim")
    if claim is None:
        claim = tally.format_claim(tally.plan_summary(source, plan_id), tally.repo_summary(source))
    result = _check_entry(source, plan_id, claim)
    _require(result["ok"], result.get("reason", "the plan does not verify"), code=3)
    entries = Path(registry)/"entries"
    final = entries/plan_id
    _require(not final.exists(), f"plan {plan_id[:8]} is already in this registry")
    entry = {"format": ENTRY_FORMAT, "plan_id": plan_id, "claim": claim, "source": clean["source"],
             "trust": clean["trust"], "title": clean["title"], "submitted_by": clean["submitted_by"],
             "links": clean["links"]}
    staging = entries/f".adding-{secrets.token_hex(8)}"
    try:
        export(source, plan_id, staging)
        (staging/"entry.json").write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n")
        os.rename(staging, final)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return entry


def read_entry(registry: Path, plan_id: str) -> dict:
    path = Path(registry)/"entries"/plan_id/"entry.json"
    _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= _ENTRY_LIMIT, "entry.json is missing or too large")
    entry = json.loads(path.read_bytes())
    _require(isinstance(entry, dict) and set(entry) == {"format", "plan_id", "claim", "source", "trust", "title",
                                                       "submitted_by", "links"}
             and entry["format"] == ENTRY_FORMAT and entry["plan_id"] == plan_id,
             "entry.json is not a registry entry for this plan")
    _meta({k: v for k, v in entry.items() if k not in ("format", "plan_id")})
    return entry


def verify_registry(registry: Path) -> dict:
    """Reverify every entry with the ledger and claim checks; entries that fail are reported, never hidden."""
    root = Path(registry)/"entries"
    results = []
    names = sorted(path.name for path in root.iterdir()) if root.is_dir() else []
    for name in names:
        if not _HEX.fullmatch(name) or not (root/name).is_dir():
            continue
        item = {"plan_id": name, "ok": False}
        try:
            _check_tree(root/name)
            entry = read_entry(registry, name)
            item.update(_check_entry(root/name, name, entry["claim"]))
            if item["ok"]:
                item.update(entry=entry, summary=tally.plan_summary(root/name, name))
        except TallyLockError as error:
            item["reason"] = error.message
        except (OSError, ValueError):
            item["reason"] = "the entry could not be read"
        results.append(item)
    verified = sum(1 for item in results if item["ok"])
    return {"format": REPORT_FORMAT, "verified": verified, "failed": len(results) - verified, "entries": results}
