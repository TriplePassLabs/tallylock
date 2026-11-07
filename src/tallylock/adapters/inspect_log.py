"""Read Inspect AI eval logs (.json and .eval zip) without importing inspect_ai.

Upstream: UKGovernmentBEIS/inspect_ai, commit da64cc6475734b3b4873de6c1957d727c86ba192
(2026-11-07, release 0.3.288). Format read from src/inspect_ai/log/_log.py at that commit and
from the log files under tests/log/test_eval_log and tests/analysis/test_logs. A .eval file is
a zip holding header.json, summaries.json, reductions.json and samples/<id>_epoch_<n>.json.
"""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from pathlib import Path
import zipfile
import zlib

from ..errors import TallyLockError
from . import _json


MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SAMPLES = 100000
_LETTERS = {"C": Fraction(1), "I": Fraction(0), "P": Fraction(1, 2), "N": Fraction(0)}


def _require(condition, message):
    if not condition:
        raise TallyLockError(message)


def _member(archive: zipfile.ZipFile, name: str, total: list) -> bytes:
    info = archive.getinfo(name)
    _require(info.file_size <= MAX_MEMBER_BYTES, f"{name} exceeds {MAX_MEMBER_BYTES} bytes")
    total[0] += info.file_size
    _require(total[0] <= MAX_ARCHIVE_BYTES, f"archive contents exceed {MAX_ARCHIVE_BYTES} bytes")
    with archive.open(info) as handle:
        data = handle.read(MAX_MEMBER_BYTES + 1)
    _require(len(data) <= MAX_MEMBER_BYTES, f"{name} exceeds {MAX_MEMBER_BYTES} bytes")
    return data


def _read_eval(path: Path) -> tuple[dict, list | None, list | None]:
    _require(path.stat().st_size <= MAX_ARCHIVE_BYTES, f"log exceeds {MAX_ARCHIVE_BYTES} bytes")
    total = [0]
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as error:
        raise TallyLockError("log is not a readable .eval archive") from error
    with archive:
        names = set(archive.namelist())
        _require("header.json" in names, "archive has no header.json")
        try:
            header = _json.loads(_member(archive, "header.json", total))
            reductions = _json.loads(_member(archive, "reductions.json", total)) if "reductions.json" in names else None
            if "summaries.json" in names:
                samples = _json.loads(_member(archive, "summaries.json", total))
            else:
                members = sorted(n for n in names if n.startswith("samples/") and n.endswith(".json"))
                _require(len(members) <= MAX_SAMPLES, f"log has more than {MAX_SAMPLES} samples")
                samples = [_json.loads(_member(archive, n, total)) for n in members] if members else None
        except (zipfile.BadZipFile, zlib.error) as error:
            raise TallyLockError("log archive is damaged") from error
    return header, samples, reductions


def _value(raw):
    if isinstance(raw, bool):
        return Fraction(int(raw))
    if isinstance(raw, int):
        return Fraction(raw)
    if isinstance(raw, Decimal):
        return Fraction(raw)
    if isinstance(raw, str) and raw in _LETTERS:
        return _LETTERS[raw]
    raise TallyLockError("unsupported score value")


def _scorer(header: dict, samples, reductions, wanted):
    scores = header.get("results", {}).get("scores") if isinstance(header.get("results"), dict) else None
    names = [s.get("name") for s in scores if isinstance(s, dict)] if isinstance(scores, list) else []
    found = set()
    for sample in samples or ():
        if isinstance(sample, dict) and isinstance(sample.get("scores"), dict):
            found.update(sample["scores"])
    for reduction in reductions or ():
        if isinstance(reduction, dict):
            found.add(reduction.get("scorer"))
    if wanted is not None:
        _require(wanted in found or wanted in names, f"scorer {wanted!r} is not in this log")
        return wanted
    return names[0] if names else (sorted(found, key=str)[0] if found else None)


def _collect(samples, reductions, scorer):
    values = []
    for sample in samples or ():
        if isinstance(sample, dict) and isinstance(sample.get("scores"), dict) and isinstance(sample["scores"].get(scorer), dict):
            values.append(sample["scores"][scorer].get("value"))
    if values or samples:
        return values
    for reduction in reductions or ():
        if isinstance(reduction, dict) and reduction.get("scorer") == scorer and isinstance(reduction.get("samples"), list):
            return [s.get("value") if isinstance(s, dict) else None for s in reduction["samples"]]
    return []


def import_inspect(log_path, *, scorer: str | None = None) -> list[dict]:
    """Return one declared attempt for the log, with the score as an exact fraction."""
    path = Path(log_path)
    _require(path.is_file(), f"log not found: {path.name}")
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic[:2] == b"PK":
        header, samples, reductions = _read_eval(path)
        form = "eval"
    else:
        header = _json.loads(_json.read_bounded(path, MAX_JSON_BYTES, "log"))
        _require(isinstance(header, dict), "log must be a JSON object")
        samples, reductions = header.get("samples"), header.get("reductions")
        form = "json"
    _require(isinstance(header, dict), "log header must be a JSON object")
    spec = header.get("eval")
    _require(isinstance(spec, dict), "log has no eval section")
    _require(isinstance(samples, (list, type(None))) and isinstance(reductions, (list, type(None))),
             "log samples must be a list")
    _require(samples is None or len(samples) <= MAX_SAMPLES, f"log has more than {MAX_SAMPLES} samples")
    chosen = _scorer(header, samples, reductions, scorer)
    values = _collect(samples, reductions, chosen)
    score, note = None, None
    if values:
        try:
            mean = sum((_value(v) for v in values), Fraction(0)) / len(values)
            score = {"numerator": mean.numerator, "denominator": mean.denominator}
        except TallyLockError as error:
            note = error.message
    results = header.get("results") if isinstance(header.get("results"), dict) else {}
    stats = header.get("stats") if isinstance(header.get("stats"), dict) else {}
    total = results.get("total_samples")
    attempt = {"source": "inspect", "trust": "declared", "log_format": form, "log_version": header.get("version"),
               "task": spec.get("task"), "model": spec.get("model"), "status": header.get("status"),
               "scorer": chosen, "score": score, "samples": len(values),
               "total_samples": total if isinstance(total, int) and not isinstance(total, bool) else None,
               "run_id": spec.get("run_id"), "created": spec.get("created"),
               "started_at": stats.get("started_at"), "completed_at": stats.get("completed_at")}
    if note is not None:
        attempt["score_note"] = note
    elif chosen is None or not values:
        attempt["score_note"] = "no per-sample scores in this log"
    return [attempt]
