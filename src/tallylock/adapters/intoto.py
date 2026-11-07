"""Export a plan's attempt ledger as an in-toto Statement v1.

Upstream: in-toto/attestation, commit 50bf01716982189898823e90586075f37cd9bb7d (spec/v1/statement.md
and spec/v1/envelope.md), and sigstore/cosign v3.1.4 (`cosign attest-blob --statement`).
"""
from __future__ import annotations

from pathlib import Path

from .. import ledger


STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://triplepasslabs.com/tallylock/attempt-ledger/v1"


def to_intoto(repo, plan_id: str, *, chain_cache: dict | None = None) -> dict:
    """Return the Statement for a plan after its ledger verifies; every attempt receipt is a subject."""
    repo = Path(repo)
    checked = ledger.verify_ledger(repo, plan_id, chain_cache=chain_cache)
    info = ledger.load_plan(repo, plan_id)["metadata"]["tallylock_plan"]
    entries = checked["ledger"]
    attempts = [{"seq": e["seq"], "attempt_id": e["attempt_id"], "receipt_sha256": e["receipt_id"],
                 "outcome": e["outcome"], "exit_code": e["exit_code"], "duration_ms": e["duration_ms"],
                 "score": e["score"]} for e in entries]
    counts = {"attempts": len(entries)}
    for entry in entries:
        counts[entry["outcome"]] = counts.get(entry["outcome"], 0) + 1
    predicate = {"plan_id": plan_id, "plan_number": info["plan_number"], "argv": info["argv"],
                 "max_attempts": info["max_attempts"], "ledger_head_sha256": checked["head_sha256"],
                 "counts": counts, "attempts": attempts}
    if "setup" in info:
        predicate["setup"] = info["setup"]
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": f"attempt/{e['attempt_id']}", "digest": {"sha256": e["receipt_id"]}} for e in entries],
            "predicateType": PREDICATE_TYPE, "predicate": predicate}
