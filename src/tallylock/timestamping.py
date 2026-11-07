"""Serialized calendar actions with durable nonces, reservations and proof history."""
from __future__ import annotations

import hashlib
import io
from collections import deque
from pathlib import Path
import re
import secrets
import time

from opentimestamps.calendar import DEFAULT_AGGREGATORS
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import StreamSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from . import anchors, canonical, schema, store, transport
from .errors import TallyLockError
from .filesystem import Directory, WriterLock


_STATE = ".prove/ots-state.json"
_STATE_LIMIT = 2 * 1024 * 1024
_MAX_REQUESTS = 4096
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")


def _require(condition, message):
    if not condition:
        raise TallyLockError(message)


def _encode(stamp):
    class BoundedOutput(io.BytesIO):
        def write(self, data):
            if self.tell() + len(data) > anchors.MAX_PROOF_BYTES:
                raise TallyLockError("merged proof exceeds its byte limit", code=5)
            return super().write(data)

    items = 0
    stack = [(stamp, 1)]
    while stack:
        node, depth = stack.pop()
        items += 1 + len(node.attestations)
        if depth > anchors.MAX_TIMESTAMP_DEPTH or items > anchors.MAX_TIMESTAMP_ITEMS:
            raise TallyLockError("merged proof exceeds its structural limits", code=5)
        stack.extend((child, depth+1) for child in node.ops.values())
    output = BoundedOutput()
    context = StreamSerializationContext(output)
    DetachedTimestampFile(OpSHA256(), stamp).serialize(context)
    return output.getvalue()


def _cores(directory, targets):
    store._root(directory)
    frozen = {"manifest": directory.read("manifest.json")}
    manifest = store._canonical_object(frozen["manifest"], "manifest")
    schema.validate_manifest(manifest)
    result_data = store._optional_read(directory, "result.json")
    if "result" in targets and result_data is None:
        raise TallyLockError("selected result is absent", code=3)
    if result_data is not None:
        result = store._canonical_object(result_data, "result")
        schema.validate_result(result, manifest)
        frozen["result"] = result_data
    ids = {name: hashlib.sha256(data).hexdigest() for name, data in frozen.items()}
    return frozen, ids


def _check_cores(directory, frozen):
    store._root(directory)
    for name, data in frozen.items():
        _require(directory.read(f"{name}.json") == data, "frozen core changed during timestamp action")
    if "result" not in frozen:
        _require(store._optional_read(directory, "result.json") is None, "result appeared during timestamp action")


def _integer(value):
    return type(value) is int and 0 <= value <= canonical.MAX_SAFE_INTEGER


def _load_state(directory, ids):
    raw = store._optional_read(directory, _STATE, limit=_STATE_LIMIT)
    if raw is None:
        return {"format": "prove.ots-state.v1", "registration_id": ids["manifest"],
                "receipt_id": ids.get("result"), "targets": {}, "requests": []}, raw
    state = store._canonical_object(raw, "timestamp state")
    _require(set(state) == {"format", "registration_id", "receipt_id", "targets", "requests"},
             "invalid timestamp state fields")
    _require(isinstance(state["format"], str), "invalid timestamp state format")
    if state["format"] != "prove.ots-state.v1":
        raise TallyLockError("unsupported timestamp state format", code=4)
    _require(state["registration_id"] == ids["manifest"]
             and (state["receipt_id"] is None or state["receipt_id"] == ids.get("result")),
             "timestamp state core IDs differ")
    _require(isinstance(state["targets"], dict) and state["targets"].keys() <= ids.keys(),
             "invalid timestamp state targets")
    for name, target in state["targets"].items():
        _require(isinstance(target, dict) and set(target) == {"sha256", "nonce"}, "invalid nonce state")
        _require(target["sha256"] == ids[name], "timestamp target ID differs")
        nonce = target["nonce"]
        _require(nonce is None or isinstance(nonce, str) and _NONCE.fullmatch(nonce), "invalid timestamp nonce")
    requests = state["requests"]
    _require(isinstance(requests, list) and len(requests) <= _MAX_REQUESTS, "invalid request state")
    seen = set()
    for item in requests:
        _require(isinstance(item, dict) and set(item) == {
            "target", "origin", "commitment", "attempted_at", "next_retry_at"}, "invalid request reservation")
        _require(isinstance(item["target"], str) and item["target"] in state["targets"], "invalid request target")
        origin = transport.normalize_origin(item["origin"], upgrade=True)
        _require(origin == item["origin"], "noncanonical request authority")
        commitment = item["commitment"]
        _require(isinstance(commitment, str) and re.fullmatch(r"(?:[0-9a-f]{2}){1,4096}", commitment),
                 "invalid request commitment")
        _require(_integer(item["attempted_at"]) and _integer(item["next_retry_at"])
                 and item["next_retry_at"] >= item["attempted_at"] + 300, "invalid request cooldown")
        key = (item["target"], origin, commitment)
        _require(key not in seen, "duplicate request reservation")
        seen.add(key)
    # Sealing may add a result to a registration that was timestamped earlier.
    # Only the previously unknown identity may become known; core IDs stay fixed.
    state["receipt_id"] = ids.get("result")
    return state, raw


def _save_state(directory, state, previous, frozen):
    _check_cores(directory, frozen)
    _require(store._optional_read(directory, _STATE, limit=_STATE_LIMIT) == previous,
             "timestamp state changed during action")
    raw = canonical.dumps(state)
    _require(len(raw) <= _STATE_LIMIT, "timestamp state exceeds size limit")
    if raw != previous:
        directory.atomic_write(_STATE, raw, replace=previous is not None)
    store._persist_expected(directory, _STATE, hashlib.sha256(raw).hexdigest(), len(raw))
    _check_cores(directory, frozen)
    return raw


def _fresh_stamp(core_id, nonce):
    stamp = Timestamp(bytes.fromhex(core_id))
    end = stamp.ops.add(OpAppend(bytes.fromhex(nonce))).ops.add(OpSHA256())
    return stamp, end.msg


def _nodes(stamp):
    stack = [stamp]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.ops.values())


def _jobs(name, proof, nonce, core_id, action, warnings):
    if proof is None:
        _require(nonce is not None, "missing proof has no resumable nonce")
        _, commitment = _fresh_stamp(core_id, nonce)
        return [(name, origin, commitment, False) for origin in DEFAULT_AGGREGATORS]
    if action == "submit":
        return []
    stamp = anchors._load(proof, core_id)
    jobs, seen = [], set()
    for node in _nodes(stamp):
        for attestation in sorted(node.attestations):
            if not isinstance(attestation, PendingAttestation):
                continue
            try:
                origin = transport.normalize_origin(attestation.uri, upgrade=True)
            except TallyLockError:
                if len(warnings) < 16:
                    warnings.append("ignored an unapproved pending calendar authority")
                continue
            key = (origin, node.msg)
            if key not in seen:
                seen.add(key)
                jobs.append((name, origin, node.msg, True))
    return jobs


def _merge(old, core_id, nonce, commitment, response):
    try:
        addition = anchors.parse_timestamp(response, commitment)
        bitcoin, _, pending, _ = anchors._evidence(addition)
        if not bitcoin and not pending:
            raise TallyLockError("calendar timestamp has no supported witness")
        stamp = anchors._load(old, core_id) if old is not None else _fresh_stamp(core_id, nonce)[0]
        matching = [node for node in _nodes(stamp) if node.msg == commitment]
        if not matching:
            raise TallyLockError("calendar commitment is absent from the existing proof")
        # One correctly bound path suffices; duplicating the reply into every
        # equivalent message can multiply an untrusted tree unnecessarily.
        matching[0].merge(addition)
        data = _encode(stamp)
        anchors.inspect(data, core_id)
        return data
    except (TallyLockError, ValueError, RecursionError):
        raise TallyLockError("calendar proof merge failed validation", code=5) from None


def _publish(directory, name, old, data, frozen):
    path = f"proofs/{name}.ots"
    _check_cores(directory, frozen)
    _require(store._optional_read(directory, path, limit=anchors.MAX_PROOF_BYTES) == old,
             "proof changed during timestamp action")
    if old is not None and old != data:
        directory.mkdirs(f".prove/proof-history/{name}")
        backup = f".prove/proof-history/{name}/{hashlib.sha256(old).hexdigest()}.ots"
        store._publish_exact(directory, backup, old, limit=anchors.MAX_PROOF_BYTES)
    _check_cores(directory, frozen)
    _require(store._optional_read(directory, path, limit=anchors.MAX_PROOF_BYTES) == old,
             "proof changed before publication")
    if old != data:
        directory.atomic_write(path, data, replace=old is not None)
    store._persist_expected(directory, path, hashlib.sha256(data).hexdigest(), len(data))
    _check_cores(directory, frozen)


def _action(receipt, targets, action):
    _require(isinstance(targets, tuple) and 1 <= len(targets) <= 2
             and all(isinstance(name, str) and name in {"manifest", "result"} for name in targets)
             and len(set(targets)) == len(targets), "invalid selected timestamp targets")
    with Directory(Path(receipt)) as directory:
        store._root(directory)
        with WriterLock(directory):
            frozen, ids = _cores(directory, targets)
            directory.mkdirs("proofs")
            proofs = {}
            for name in targets:
                proof = store._optional_read(directory, f"proofs/{name}.ots", limit=anchors.MAX_PROOF_BYTES)
                if proof is not None:
                    info = anchors.inspect(proof, ids[name])
                    if not info["bitcoin_heights"] and not info["pending_count"]:
                        raise TallyLockError("existing proof has no supported Bitcoin or pending witness", code=4)
                proofs[name] = proof
            state, previous = _load_state(directory, ids)
            for name in targets:
                saved = state["targets"].get(name)
                if action == "upgrade" and proofs[name] is None and (saved is None or saved["nonce"] is None):
                    raise TallyLockError("upgrade requires an existing proof or saved submission nonce", code=3)
                if name not in state["targets"]:
                    state["targets"][name] = {"sha256": ids[name],
                        "nonce": secrets.token_hex(16) if proofs[name] is None else None}
                _require(proofs[name] is not None or state["targets"][name]["nonce"] is not None,
                         "missing imported proof cannot resume an unknown nonce")
            previous = _save_state(directory, state, previous, frozen)
            warnings = []
            reservations = {(r["target"], r["origin"], r["commitment"]): r for r in state["requests"]}

            def priority(job):
                name, origin, commitment, _ = job
                saved = reservations.get((name, origin, commitment.hex()))
                if saved is None:
                    return (0, 0, 0)
                return (1, saved["next_retry_at"], saved["attempted_at"])

            # Rotate due work durably within each target; stable origin order
            # alone would repeatedly spend the eight-call budget on the same URLs.
            queues = {name: deque(sorted(_jobs(name, proofs[name], state["targets"][name]["nonce"], ids[name], action, warnings), key=priority))
                      for name in targets}
            # Round robin preserves a turn for each selected core even with many URLs.
            jobs = []
            while any(queues.values()) and len(jobs) < _MAX_REQUESTS:
                for name in targets:
                    if queues[name]:
                        jobs.append(queues[name].popleft())
            attempts = {name: 0 for name in targets}
            failures = {name: 0 for name in targets}
            successes = {name: 0 for name in targets}
            deferred = {name: [] for name in targets}
            changed = {name: False for name in targets}
            deadline = time.monotonic() + 120
            count = 0
            for index, (name, origin, commitment, upgrading) in enumerate(jobs):
                now = int(time.time())
                _require(_integer(now) and now <= canonical.MAX_SAFE_INTEGER-300, "invalid operator clock")
                key = (name, origin, commitment.hex())
                reservation = reservations.get(key)
                if reservation is not None and reservation["next_retry_at"] > now:
                    deferred[name].append(reservation["next_retry_at"])
                    continue
                if count >= 8 or time.monotonic() >= deadline:
                    deferred[name].append(now + 300)
                    continue
                _check_cores(directory, frozen)
                if reservation is None:
                    _require(len(state["requests"]) < _MAX_REQUESTS, "timestamp reservation limit reached")
                    reservation = {"target": name, "origin": origin, "commitment": commitment.hex(),
                                   "attempted_at": now, "next_retry_at": now + 300}
                    state["requests"].append(reservation)
                    reservations[key] = reservation
                else:
                    reservation.update(attempted_at=now, next_retry_at=now+300)
                previous = _save_state(directory, state, previous, frozen)
                count += 1
                attempts[name] += 1
                # Reserve a fair portion for the remaining logical calls, capped by global time.
                remaining_calls = min(8-count+1, len(jobs)-index)
                request_deadline = min(deadline, time.monotonic() + max(0, deadline-time.monotonic())/remaining_calls)
                try:
                    call = transport.upgrade if upgrading else transport.submit
                    response = call(origin, commitment, deadline=request_deadline)
                except transport.RetryDeferred as error:
                    _require(_integer(error.next_retry_at), "invalid retry deferral")
                    reservation["next_retry_at"] = max(reservation["next_retry_at"], error.next_retry_at)
                    previous = _save_state(directory, state, previous, frozen)
                    deferred[name].append(reservation["next_retry_at"])
                    continue
                except TallyLockError as error:
                    _check_cores(directory, frozen)
                    if error.code != 5:
                        raise
                    failures[name] += 1
                    if len(warnings) < 16:
                        warnings.append(f"{name}: calendar request failed")
                    continue
                _check_cores(directory, frozen)
                try:
                    if response is not None:
                        candidate = _merge(proofs[name], ids[name], state["targets"][name]["nonce"], commitment, response)
                    else:
                        candidate = proofs[name]
                except TallyLockError as error:
                    if error.code != 5:
                        raise
                    failures[name] += 1
                    if len(warnings) < 16:
                        warnings.append(f"{name}: invalid calendar proof")
                    continue
                if candidate is not None:
                    _publish(directory, name, proofs[name], candidate, frozen)
                    changed[name] |= candidate != proofs[name]
                    proofs[name] = candidate
                successes[name] += 1
            _check_cores(directory, frozen)
            reports = {}
            for name in targets:
                data = proofs[name]
                if data is not None:
                    _publish(directory, name, data, data, frozen)
                    info = anchors.inspect(data, ids[name])
                else:
                    info = {"bitcoin_heights": [], "pending_count": 0}
                if attempts[name] and failures[name] == attempts[name] and not successes[name]:
                    raise TallyLockError("all due calendar requests failed for a selected target", code=5)
                if deferred[name] and not successes[name]:
                    status = "retry_wait"
                elif changed[name]:
                    status = "attestation_present" if info["bitcoin_heights"] else "pending"
                elif data is not None:
                    status = "unchanged"
                else:
                    # No unattested intermediate timestamp is ever a proof.
                    raise TallyLockError("calendar action produced no proof", code=5)
                reports[name] = {"state": status,
                    "proof_sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                    "proof_bytes": len(data) if data is not None else 0,
                    "bitcoin_heights": info["bitcoin_heights"], "pending_count": info["pending_count"],
                    "next_retry_at": min(deferred[name]) if deferred[name] else None}
            return {"format": "prove.anchor-action.v1", "action": action,
                    "registration_id": ids["manifest"], "receipt_id": ids.get("result"),
                    "targets": reports, "warnings": warnings}


def submit(receipt: Path, *, targets: tuple[str, ...] = ("manifest", "result")) -> dict:
    return _action(receipt, targets, "submit")


def upgrade(receipt: Path, *, targets: tuple[str, ...] = ("manifest", "result")) -> dict:
    return _action(receipt, targets, "upgrade")
