"""Check proofbundle/v0.1 receipts with pycryptodomex, without importing proofbundle.

Upstream: b7n0de/proofbundle (MIT), commit 65bd4b7a34b84724298961254eaba5d67bb3fc3b (release 6.5.0).
Format read from SPEC.md sections 2 to 6 and 7i at that commit, and checked against
examples/example_bundle.json and conformance/bundle/forged-anchor-own-frozen/bundle.json.
What a pass establishes: the payload bytes carry a valid Ed25519 signature from the stated key and are
a leaf of the stated RFC 6962 tree. Anchors count only when the caller confirms them.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

from Cryptodome.Signature import eddsa
import rfc8785

from .. import canonical, merkle
from ..errors import TallyLockError
from . import _json


MAX_BUNDLE_BYTES = 4 * 1024 * 1024
_TOP = {"schema", "payload_b64", "signature", "merkle", "sd_jwt_vc", "anchors"}
_SIGNATURE = {"alg", "public_key_b64", "sig_b64"}
_MERKLE = {"hash_alg", "leaf_index", "tree_size", "inclusion_proof_b64", "root_b64"}
_ANCHOR_TYPES = {"rfc3161-tsa", "opentimestamps", "chia-datalayer/v1"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _require(condition, message):
    if not condition:
        raise TallyLockError(message)


def _decode(value, what, length=None):
    _require(isinstance(value, str), f"{what} must be a string")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise TallyLockError(f"{what} is not valid base64") from error
    _require(base64.b64encode(data).decode() == value, f"{what} is not canonical base64")
    _require(length is None or len(data) == length, f"{what} has the wrong length")
    return data


def _integer(value, what, minimum):
    _require(type(value) is int and value >= minimum, f"{what} must be an integer of at least {minimum}")
    return value


def _closed(value, allowed, what):
    _require(isinstance(value, dict), f"{what} must be an object")
    for name in sorted(set(value) - allowed):
        raise TallyLockError(f"{what} has unknown member {name!r}")


def _anchor_root(bundle, payload, target):
    if target == "receipt":
        if "sd_jwt_vc" in bundle:
            return None, "root_not_checked"
        return hashlib.sha256(rfc8785.dumps({k: v for k, v in bundle.items() if k != "anchors"})).digest(), None
    try:
        claim = _json.loads(payload)
    except TallyLockError:
        claim = None
    prereg = claim.get("prereg_sha256") if isinstance(claim, dict) else None
    if isinstance(prereg, str) and _HEX.fullmatch(prereg):
        return bytes.fromhex(prereg), None
    return None, "target_has_no_root"


def _anchors(bundle, payload, confirm_anchor):
    listed = bundle.get("anchors", [])
    _require(isinstance(listed, list), "anchors must be a list")
    reports = []
    for entry in listed:
        _require(isinstance(entry, dict) and entry.get("target") in ("receipt", "preRegistration"),
                 "an anchor must be an object whose target is receipt or preRegistration")
        kind, target = entry.get("type"), entry["target"]
        root, state = _anchor_root(bundle, payload, target)
        if kind not in _ANCHOR_TYPES:
            state = "unknown_type"
        elif state is None:
            try:
                same = _decode(entry.get("canonicalRoot"), "canonicalRoot") == root
                _decode(entry.get("proof"), "proof")
            except TallyLockError:
                same = None
            if same is None:
                state = "malformed_proof"
            elif not same:
                state = "root_mismatch"
            elif confirm_anchor is None:
                state = "needs_relying_party_trust"
            else:
                state = "confirmed" if confirm_anchor(entry, root) else "not_confirmed"
        reports.append({"type": kind, "target": target, "state": state})
    return reports


def _check(bundle, confirm_anchor):
    _require(isinstance(bundle, dict), "bundle must be a JSON object")
    _closed(bundle, _TOP, "bundle")
    _require(bundle.get("schema") == "proofbundle/v0.1", "unsupported bundle schema")
    payload = _decode(bundle.get("payload_b64"), "payload_b64")
    signature, tree = bundle.get("signature"), bundle.get("merkle")
    _closed(signature, _SIGNATURE, "signature")
    _closed(tree, _MERKLE, "merkle")
    _require(signature.get("alg") == "ed25519", "signature alg must be ed25519")
    _require(tree.get("hash_alg") == "sha256-rfc6962", "merkle hash_alg must be sha256-rfc6962")
    _require(isinstance(bundle.get("sd_jwt_vc", {}), dict), "sd_jwt_vc must be an object")
    key = _decode(signature.get("public_key_b64"), "public_key_b64")
    sig = _decode(signature.get("sig_b64"), "sig_b64")
    index, size = _integer(tree.get("leaf_index"), "leaf_index", 0), _integer(tree.get("tree_size"), "tree_size", 1)
    proof = tree.get("inclusion_proof_b64")
    _require(isinstance(proof, list), "inclusion_proof_b64 must be a list")
    siblings = [_decode(item, "inclusion proof entry", 32).hex() for item in proof]
    root = _decode(tree.get("root_b64"), "root_b64", 32)
    reports = _anchors(bundle, payload, confirm_anchor)
    try:
        eddsa.new(eddsa.import_public_key(key), "rfc8032").verify(payload, sig)
    except (ValueError, TypeError):
        return {"ok": False, "reason": "signature check failed"}
    if not merkle.verify(payload, index, size, siblings, root.hex()):
        return {"ok": False, "reason": "inclusion proof does not match the root"}
    confirmed = any(item["state"] == "confirmed" for item in reports)
    not_checked = ["who holds the signing key", "whether the signed result is true"]
    if "sd_jwt_vc" in bundle:
        not_checked.append("SD-JWT credential")
    if any(item["state"] != "confirmed" for item in reports):
        not_checked.append("external time anchors not confirmed")
    return {"ok": True, "trust": "anchored" if confirmed else "signed", "source": "proofbundle",
            "schema": bundle["schema"], "public_key_b64": signature["public_key_b64"],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "merkle": {"leaf_index": index, "tree_size": size, "root_sha256": root.hex()},
            "anchors": reports, "checks": {"signature": True, "inclusion": True}, "not_checked": not_checked}


def verify_proofbundle(path, *, confirm_anchor=None) -> dict:
    """Return what the bundle proves, or ok False with a reason; never raises on bad input."""
    try:
        bundle = canonical.loads(_json.read_bounded(path, MAX_BUNDLE_BYTES, "bundle"))
        return _check(bundle, confirm_anchor)
    except TallyLockError as error:
        return {"ok": False, "reason": error.message}
