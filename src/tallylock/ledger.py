"""Plans of repeated attempts, their runs and the append-only run ledger."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time

from opentimestamps.calendar import DEFAULT_AGGREGATORS

from . import anchors, canonical, chain, schema, store, timestamping, transport, verify
from .errors import TallyLockError


LEDGER_FORMAT = "tallylock.ledger-entry.v1"
PLAN_FORMAT = "tallylock.plan.v1"
KEY_FORMAT = "tallylock.plan-key.v1"
ATTEMPT_FORMAT = "tallylock.attempt.v1"
STREAM_LIMIT = 64 * 1024 * 1024
MAX_ATTEMPTS = 10000
_LEDGER_LIMIT = 64 * 1024 * 1024
_LINE_LIMIT = 4096
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?\Z")
_PROOF = re.compile(r"ledger-head-([1-9][0-9]{0,15})\.ots\Z")
_SCORE = re.compile(rb"tallylock: score=(?:([0-9]{1,15})(?:\.([0-9]{1,15}))?|([0-9]{1,15})/([0-9]{1,15}))[ \t]*\Z")
_FIELDS = {"format", "plan_id", "seq", "attempt_id", "receipt_id", "outcome", "exit_code",
           "duration_ms", "score", "argv", "prev_sha256"}
_NOT_TREE = "TallyLock plans need a git work tree. Run this inside a git repository."


class LedgerError(TallyLockError):
    """A ledger check failure; kind names what was wrong."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message, code=2)
        self.kind = kind


@dataclass(frozen=True)
class Plan:
    repo: Path
    plan_id: str
    key: str
    argv: tuple[str, ...]
    max_attempts: int
    created: bool

    @property
    def directory(self) -> Path:
        return self.repo/".tallylock"/"plans"/self.plan_id


def _require(condition, message, code=2):
    if not condition:
        raise TallyLockError(message, code=code)


def _git(repo: Path, args: list[str]) -> bytes:
    try:
        done = subprocess.run(["git", *args], cwd=repo, stdin=subprocess.DEVNULL, capture_output=True)
    except OSError as error:
        raise TallyLockError(f"cannot run git: {error.strerror}", code=5) from error
    _require(done.returncode == 0, done.stderr.decode(errors="replace").strip() or "git failed", code=5)
    return done.stdout


def _write(path: Path, data: bytes, *, replace: bool = True) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if replace:
        os.replace(temporary, path)
    else:
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise TallyLockError(f"{path.name} already exists", code=5) from None
        finally:
            os.unlink(temporary)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _score(line: bytes) -> dict | None:
    match = _SCORE.fullmatch(line.rstrip(b"\r"))
    if match is None:
        return None
    whole, fraction, numerator, denominator = match.groups()
    if numerator is not None:
        value = {"numerator": int(numerator), "denominator": int(denominator)}
    else:
        fraction = fraction or b""
        value = {"numerator": int(whole + fraction), "denominator": 10 ** len(fraction)}
    if not 0 < value["denominator"] <= canonical.MAX_SAFE_INTEGER or value["numerator"] > canonical.MAX_SAFE_INTEGER:
        return None
    return value


class _Scanner:
    """Keep the last score line of a byte stream, holding only one bounded line."""

    def __init__(self) -> None:
        self.tail: bytes | None = b""
        self.score: dict | None = None

    def feed(self, chunk: bytes) -> None:
        parts = chunk.split(b"\n")
        for index, part in enumerate(parts):
            if self.tail is not None:
                self.tail = self.tail + part if len(self.tail) + len(part) <= _LINE_LIMIT else None
            if index < len(parts) - 1:
                self.finish()
                self.tail = b""

    def finish(self) -> None:
        if self.tail:
            self.score = _score(self.tail) or self.score


def parse_score(data: bytes) -> dict | None:
    """Return the last `tallylock: score=` line's exact value, or None."""
    scanner = _Scanner()
    scanner.feed(data)
    scanner.finish()
    return scanner.score


def _score_file(path: Path) -> tuple[dict | None, bytes | None]:
    if not path.is_file() or path.stat().st_size > _LINE_LIMIT:
        return None, None
    data = path.read_bytes()
    try:
        value = canonical.loads(data)
    except TallyLockError:
        return None, None
    valid = (isinstance(value, dict) and set(value) == {"numerator", "denominator"}
             and all(type(value[k]) is int for k in value)
             and 0 <= value["numerator"] <= canonical.MAX_SAFE_INTEGER
             and 0 < value["denominator"] <= canonical.MAX_SAFE_INTEGER)
    return (value, data) if valid else (None, None)


def plan_identity(repo: Path, argv, *, configs=(), max_attempts: int = 100, git=None) -> dict:
    """Digest the commit, tracked changes, command, declared configs and attempt budget."""
    git = _git if git is None else git
    repo = Path(repo)
    _require(isinstance(argv, (list, tuple)) and argv and all(isinstance(a, str) and a for a in argv),
             "the command must be a nonempty list of nonempty strings")
    _require(type(max_attempts) is int and 1 <= max_attempts <= MAX_ATTEMPTS,
             f"max attempts must be an integer from 1 to {MAX_ATTEMPTS}")
    try:
        inside = git(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == b"true"
    except TallyLockError:
        inside = False
    _require(inside, _NOT_TREE)
    try:
        head = git(repo, ["rev-parse", "--verify", "HEAD"]).decode("ascii", "replace").strip()
    except TallyLockError:
        head = ""
    _require(_COMMIT.fullmatch(head), "TallyLock plans need at least one git commit. Commit your work first.")
    diff = git(repo, ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "HEAD",
                      "--", ".", ":(exclude).tallylock"])
    digests = {}
    for name in configs:
        name = str(name)
        relative = Path(name)
        _require(not relative.is_absolute() and ".." not in relative.parts and (repo/relative).is_file(),
                 f"config file {name!r} must be a file inside the repository")
        digests[relative.as_posix()] = hashlib.sha256((repo/relative).read_bytes()).hexdigest()
    identity = {"format": KEY_FORMAT, "head": head, "diff_sha256": hashlib.sha256(diff).hexdigest(),
                "argv": list(argv), "configs": digests, "max_attempts": max_attempts}
    identity["key"] = canonical.digest(identity)
    return identity


def load_plan(repo: Path, plan_id: str) -> dict:
    """Return a plan's frozen manifest after checking it against its ID."""
    _require(isinstance(plan_id, str) and _HEX.fullmatch(plan_id), "plan IDs are 64 lowercase hex characters")
    path = Path(repo)/".tallylock"/"plans"/plan_id/"manifest.json"
    _require(path.is_file(), f"plan {plan_id[:8]} was not found")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != plan_id:
        raise LedgerError("plan_invalid", f"plan {plan_id[:8]} manifest does not match its ID")
    manifest = schema.validate_manifest(canonical.loads(data))
    info = manifest["metadata"].get("tallylock_plan")
    if not isinstance(info, dict) or info.get("format") != PLAN_FORMAT:
        raise LedgerError("plan_invalid", f"plan {plan_id[:8]} is not a TallyLock plan")
    return manifest


def list_plans(repo: Path) -> list[str]:
    """List plan IDs with valid manifests, in plan-number order."""
    root = Path(repo)/".tallylock"/"plans"
    found = []
    for path in root.iterdir() if root.is_dir() else ():
        if _HEX.fullmatch(path.name) and (path/"manifest.json").is_file():
            try:
                manifest = load_plan(repo, path.name)
            except TallyLockError:
                continue
            found.append((manifest["metadata"]["tallylock_plan"]["plan_number"], path.name))
    return [plan_id for _, plan_id in sorted(found)]


def start_plan(repo: Path, argv, *, configs=(), max_attempts: int = 100, git=None) -> Plan:
    """Resolve the plan for this exact setup, freezing a new one when the key changed."""
    repo = Path(repo)
    identity = plan_identity(repo, argv, configs=configs, max_attempts=max_attempts, git=git)
    existing = list_plans(repo)
    for plan_id in existing:
        if load_plan(repo, plan_id)["metadata"]["tallylock_plan"]["key"] == identity["key"]:
            return Plan(repo, plan_id, identity["key"], tuple(argv), max_attempts, False)
    manifest = schema.default_manifest("TallyLock plan")
    manifest["description"] = "Repeated attempts of one fixed command and configuration."
    manifest["attempts"] = [{"id": f"run-{n}", "sample_ids": []} for n in range(1, max_attempts + 1)]
    manifest["stopping_rule"] = f"at most {max_attempts} attempts; every attempt is recorded in the plan ledger"
    manifest["metadata"]["tallylock_plan"] = {"format": PLAN_FORMAT, "plan_number": len(existing) + 1,
                                              **{k: v for k, v in identity.items() if k != "format"}}
    plan_id = canonical.digest(manifest)
    plan = Plan(repo, plan_id, identity["key"], tuple(argv), max_attempts, True)
    first = plan.directory/"attempts"/"run-1"
    first.mkdir(parents=True)
    _require(store.register(manifest, first) == plan_id, "plan registration ID differs", code=5)
    _write(plan.directory/"manifest.json", (first/"manifest.json").read_bytes(), replace=False)
    return plan


def _read(repo: Path, plan_id: str) -> tuple[list[dict], list[bytes]]:
    """Parse the ledger and check order, contiguity and chaining, without receipts."""
    path = Path(repo)/".tallylock"/"plans"/plan_id/"ledger.jsonl"
    if not path.exists():
        return [], []
    _require(path.stat().st_size <= _LEDGER_LIMIT, "ledger exceeds its size limit")
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        raise LedgerError("malformed", "the ledger ends with a partial line")
    lines = data.split(b"\n")[:-1]
    entries = []
    for number, line in enumerate(lines, 1):
        try:
            entry = canonical.loads(line)
        except TallyLockError:
            raise LedgerError("malformed", f"ledger line {number} is not valid JSON") from None
        if (not isinstance(entry, dict) or set(entry) != _FIELDS or entry["format"] != LEDGER_FORMAT
                or entry["plan_id"] != plan_id or type(entry["seq"]) is not int or entry["seq"] < 1
                or canonical.dumps(entry) != line):
            raise LedgerError("malformed", f"ledger line {number} is not a canonical ledger entry")
        entries.append(entry)
    seqs = [entry["seq"] for entry in entries]
    if len(set(seqs)) != len(seqs):
        raise LedgerError("duplicated", "the ledger repeats an attempt")
    if sorted(seqs) != list(range(1, len(seqs) + 1)):
        raise LedgerError("removed", "the ledger is missing an attempt")
    if seqs != sorted(seqs):
        raise LedgerError("reordered", "ledger attempts are out of order")
    previous = None
    for entry, line in zip(entries, lines):
        if entry["prev_sha256"] != previous or entry["attempt_id"] != f"run-{entry['seq']}":
            raise LedgerError("edited", f"ledger entry {entry['seq']} does not chain to the entry before it")
        previous = hashlib.sha256(line).hexdigest()
    return entries, lines


def ledger_head(repo: Path, plan_id: str) -> str | None:
    """SHA256 of the last canonical ledger line; it commits to every earlier line."""
    load_plan(repo, plan_id)
    _, lines = _read(repo, plan_id)
    return hashlib.sha256(lines[-1]).hexdigest() if lines else None


def _submit(origin, commitment, **options):
    return transport.submit(origin, commitment, **options)


def anchor_head(repo: Path, plan_id: str, *, seq: int | None = None, submit=None) -> dict:
    """Submit one ledger head digest to the calendars and store its detached proof."""
    submit = _submit if submit is None else submit
    load_plan(repo, plan_id)
    _, lines = _read(repo, plan_id)
    _require(lines, "the ledger is empty. Run an attempt first.", code=3)
    seq = len(lines) if seq is None else seq
    _require(type(seq) is int and 1 <= seq <= len(lines), "no such ledger entry")
    head = hashlib.sha256(lines[seq - 1]).hexdigest()
    relative = f".tallylock/plans/{plan_id}/ledger-head-{seq}.ots"
    path = Path(repo)/relative
    report = {"format": "tallylock.ledger-anchor.v1", "plan_id": plan_id, "seq": seq,
              "head_sha256": head, "proof": relative, "warnings": []}
    if path.exists():
        anchors.inspect(path.read_bytes(), head)
        return {**report, "state": "unchanged"}
    nonce = secrets.token_hex(16)
    _, commitment = timestamping._fresh_stamp(head, nonce)
    proof = None
    deadline = time.monotonic() + 60
    for origin in DEFAULT_AGGREGATORS:
        try:
            proof = timestamping._merge(proof, head, nonce, commitment, submit(origin, commitment, deadline=deadline))
        except TallyLockError:
            report["warnings"].append(f"{origin}: calendar request failed")
    _require(proof is not None, "every calendar request failed. The ledger head is not anchored yet.", code=5)
    _write(path, proof, replace=False)
    state = "attestation_present" if anchors.inspect(proof, head)["bitcoin_heights"] else "pending"
    return {**report, "state": state}


def _view(chain_cache):
    return None if chain_cache is None else chain.prepare(chain_cache)


def verify_anchor(repo: Path, plan_id: str, seq: int, *, chain_cache: dict | None = None,
                  minimum_confirmations: int = 6) -> dict:
    """Check one stored ledger-head proof offline against an explicit chain cache."""
    load_plan(repo, plan_id)
    _, lines = _read(repo, plan_id)
    _require(type(seq) is int and 1 <= seq <= len(lines), "no such ledger entry")
    head = hashlib.sha256(lines[seq - 1]).hexdigest()
    path = Path(repo)/".tallylock"/"plans"/plan_id/f"ledger-head-{seq}.ots"
    data = path.read_bytes() if path.is_file() else None
    result = anchors.verify(data, head, _view(chain_cache), minimum_confirmations=minimum_confirmations)
    return {"seq": seq, "head_sha256": head, **result}


def verify_ledger(repo: Path, plan_id: str, *, chain_cache: dict | None = None,
                  minimum_confirmations: int = 6) -> dict:
    """Recheck the chain, contiguity, every attempt receipt and any stored head proofs."""
    repo = Path(repo)
    manifest = load_plan(repo, plan_id)
    info = manifest["metadata"]["tallylock_plan"]
    entries, lines = _read(repo, plan_id)
    directory = repo/".tallylock"/"plans"/plan_id
    for entry in entries:
        receipt = directory/"attempts"/entry["attempt_id"]
        if verify.full(receipt, policy="integrity-only").code != 0:
            raise LedgerError("receipt_invalid", f"attempt {entry['attempt_id']} receipt failed verification")
        data = (receipt/"result.json").read_bytes()
        result = canonical.loads(data)
        attempt = result["metadata"].get("tallylock_attempt")
        aggregate = result["score"]["aggregate"] if result["score"] is not None else None
        if not (hashlib.sha256(data).hexdigest() == entry["receipt_id"] and result["registration_id"] == plan_id
                and result["attempt_id"] == entry["attempt_id"] and result["outcome"] == entry["outcome"]
                and isinstance(attempt, dict) and attempt.get("format") == ATTEMPT_FORMAT
                and all(attempt.get(k) == entry[k] for k in ("exit_code", "duration_ms", "score", "argv"))
                and aggregate == entry["score"] and entry["argv"] == info["argv"]):
            raise LedgerError("edited", f"ledger entry {entry['seq']} differs from its attempt receipt")
    listed = {entry["attempt_id"] for entry in entries}
    attempts = directory/"attempts"
    for path in sorted(attempts.iterdir()) if attempts.is_dir() else ():
        if path.name not in listed and (path/"result.json").exists():
            raise LedgerError("removed", f"sealed attempt {path.name} is missing from the ledger")
    view = _view(chain_cache)
    proofs = []
    for path in directory.iterdir():
        match = _PROOF.fullmatch(path.name)
        if match is None:
            continue
        seq = int(match.group(1))
        if seq > len(lines):
            raise LedgerError("removed", f"anchored ledger head {seq} is missing from the ledger")
        _require(path.stat().st_size <= anchors.MAX_PROOF_BYTES, "ledger head proof exceeds its byte limit")
        try:
            state = anchors.verify(path.read_bytes(), hashlib.sha256(lines[seq - 1]).hexdigest(), view,
                                   minimum_confirmations=minimum_confirmations)["state"]
        except TallyLockError:
            raise LedgerError("anchor_mismatch", f"anchored ledger head {seq} does not match the ledger") from None
        proofs.append({"seq": seq, "state": state})
    return {"format": "tallylock.ledger-verification.v1", "plan_id": plan_id,
            "plan_number": info["plan_number"], "entries": len(entries), "receipts_verified": len(entries),
            "head_sha256": hashlib.sha256(lines[-1]).hexdigest() if lines else None,
            "anchors": sorted(proofs, key=lambda item: item["seq"]), "ledger": entries}


def _pump(source, sink, path: Path, scanner: _Scanner | None, stats: dict) -> None:
    with open(path, "wb") as capture:
        while chunk := source.read1(65536):
            sink.write(chunk)
            sink.flush()
            room = STREAM_LIMIT - stats["captured"]
            if room > 0:
                capture.write(chunk[:room])
                stats["captured"] += min(room, len(chunk))
            stats["bytes"] += len(chunk)
            if scanner is not None:
                scanner.feed(chunk)
    if scanner is not None:
        scanner.finish()
    stats["truncated"] = stats["bytes"] > stats["captured"]


def run_attempt(plan: Plan, *, outputs: Path | None = None, score_file: Path | None = None,
                stdout=None, stderr=None, cwd: Path | None = None, anchor: bool = True,
                calendar_submit=None) -> dict:
    """Run the caller's command once, seal its receipt and append one ledger entry."""
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr.buffer if stderr is None else stderr
    manifest = load_plan(plan.repo, plan.plan_id)
    directory = plan.directory
    with open(directory/"run.lock", "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TallyLockError("another tallylock run is using this plan", code=5) from None
        entries, lines = _read(plan.repo, plan.plan_id)
        seq = len(entries) + 1
        _require(seq <= len(manifest["attempts"]),
                 f"this plan has used all {len(manifest['attempts'])} attempts. "
                 "Change the command or config to start a new plan.")
        attempt_id = f"run-{seq}"
        # {seed} in the command becomes the attempt number; the plan keeps the template.
        executed = [arg.replace("{seed}", str(seq)) for arg in plan.argv]
        receipt = directory/"attempts"/attempt_id
        receipt.mkdir(parents=True, exist_ok=True)
        _require(not (receipt/"result.json").exists(),
                 f"attempt {attempt_id} was sealed but is missing from the ledger", code=5)
        store.register(manifest, receipt)
        staging = plan.repo/".tallylock"/"staging"/secrets.token_hex(16)
        staging.mkdir(parents=True)
        try:
            scanner = _Scanner()
            streams = {name: {"bytes": 0, "captured": 0, "truncated": False} for name in ("stdout", "stderr")}
            started = time.monotonic_ns()
            try:
                process = subprocess.Popen(executed, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           cwd=plan.repo if cwd is None else cwd,
                                           env={**os.environ, "TALLYLOCK_SEED": str(seq), "TALLYLOCK_ATTEMPT": str(seq)})
            except OSError as error:
                raise TallyLockError(f"cannot start the command: {error.strerror}", code=5) from error
            pumps = [threading.Thread(target=_pump, args=(process.stdout, stdout, staging/"stdout.log", scanner, streams["stdout"])),
                     threading.Thread(target=_pump, args=(process.stderr, stderr, staging/"stderr.log", None, streams["stderr"]))]
            for pump in pumps:
                pump.start()
            for pump in pumps:
                pump.join()
            exit_code = process.wait()
            duration_ms = (time.monotonic_ns() - started) // 1_000_000
            if score_file is not None:
                score, score_bytes = _score_file(Path(score_file))
                source = "score_file" if score is not None else None
            else:
                score, source = scanner.score, "stdout" if scanner.score is not None else None
                score_bytes = canonical.dumps({"format": "tallylock.score.v1", "source": "stdout", **score}) if score else None
            media_types = {"stdout.log": "text/plain", "stderr.log": "text/plain"}
            if score is not None:
                (staging/"score.json").write_bytes(score_bytes)
                media_types["score.json"] = "application/json"
            sealed_outputs = None
            if outputs is not None:
                sealed_outputs = "sealed" if Path(outputs).is_dir() else "missing"
                if sealed_outputs == "sealed":
                    shutil.copytree(outputs, staging/"outputs", symlinks=True)
            attempt = {"format": ATTEMPT_FORMAT, "argv": list(plan.argv), "executed_argv": executed, "seed": seq,
                       "exit_code": exit_code,
                       "duration_ms": duration_ms, "score": score, "score_source": source,
                       "streams": streams, "outputs": sealed_outputs}
            outcome = "completed" if exit_code == 0 else "failed"
            result = store.seal(receipt, staging, attempt_id=attempt_id, outcome=outcome,
                                reason=None if exit_code == 0 else f"exit code {exit_code}",
                                roles={"stdout.log": "stdout", "stderr.log": "stderr"}, media_types=media_types,
                                score_path="score.json" if score is not None else None, aggregate=score,
                                metadata={"tallylock_attempt": attempt})
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        entry = {"format": LEDGER_FORMAT, "plan_id": plan.plan_id, "seq": seq, "attempt_id": attempt_id,
                 "receipt_id": canonical.digest(result), "outcome": outcome, "exit_code": exit_code,
                 "duration_ms": duration_ms, "score": score, "argv": list(plan.argv),
                 "prev_sha256": hashlib.sha256(lines[-1]).hexdigest() if lines else None}
        line = canonical.dumps(entry)
        _write(directory/"ledger.jsonl", b"".join(item + b"\n" for item in lines) + line + b"\n")
        anchored = {"state": "not_requested"}
        if anchor:
            try:
                done = anchor_head(plan.repo, plan.plan_id, seq=seq, submit=calendar_submit)
                anchored = {"state": done["state"], "submitted": True, "seq": seq, "proof": done["proof"]}
            except TallyLockError as error:
                anchored = {"state": "pending", "submitted": False, "seq": seq, "proof": None, "warning": error.message}
    return {"format": "tallylock.run.v1", "plan_id": plan.plan_id, "seq": seq, "attempt_id": attempt_id,
            "executed_argv": executed,
            "receipt": f".tallylock/plans/{plan.plan_id}/attempts/{attempt_id}", "receipt_id": entry["receipt_id"],
            "outcome": outcome, "reason": None if exit_code == 0 else f"exit code {exit_code}",
            "exit_code": exit_code, "duration_ms": duration_ms, "score": score,
            "ledger_head": hashlib.sha256(line).hexdigest(), "anchor": anchored}
