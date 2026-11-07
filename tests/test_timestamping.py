"""Durable receipt timestamp requests with synthetic calendar replies."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, UnknownAttestation, LitecoinBlockHeaderAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile

from tallylock import canonical, store
from tallylock.errors import TallyLockError
from test_transport import ORIGIN, reply, attested_reply


def api():
    assert importlib.util.find_spec("tallylock.timestamping") is not None, "durable timestamping missing"
    from tallylock import timestamping
    return timestamping


@pytest.fixture
def receipt(tmp_path):
    core = json.loads((Path(__file__).resolve().parents[1]/"examples/basic/manifest.json").read_bytes())
    store.register(core, tmp_path)
    store.seal(tmp_path, outcome="failed", reason="synthetic fixture")
    return tmp_path


def test_submit_canonical_ids_nonce_pending_and_identical_repeat(receipt, monkeypatch):
    client = api()
    cores = {name: (receipt/f"{name}.json").read_bytes() for name in ("manifest", "result")}
    calls = []
    def submit(origin, commitment, **kwargs):
        state = canonical.loads((receipt/".prove/ots-state.json").read_bytes())
        assert state["format"] == "prove.ots-state.v1"
        assert state["requests"]
        calls.append((origin, commitment))
        return reply(commitment, origin)
    monkeypatch.setattr(client.transport, "submit", submit)
    report = client.submit(receipt)
    assert report["registration_id"] == hashlib.sha256(cores["manifest"]).hexdigest()
    assert report["receipt_id"] == hashlib.sha256(cores["result"]).hexdigest()
    assert set(report["targets"]) == {"manifest", "result"}
    assert all(t["state"] == "pending" for t in report["targets"].values())
    assert len(calls) == 8
    for name in cores:
        assert (receipt/f"{name}.json").read_bytes() == cores[name]
        proof = DetachedTimestampFile.deserialize(BytesDeserializationContext((receipt/f"proofs/{name}.ots").read_bytes()))
        operation = next(iter(proof.timestamp.ops))
        assert isinstance(operation, OpAppend) and len(operation[0]) == 16
        end = proof.timestamp.ops[operation].ops[OpSHA256()]
        assert any(commitment == end.msg for _, commitment in calls)
    repeat = client.submit(receipt)
    assert len(calls) == 8
    assert all(t["state"] == "unchanged" for t in repeat["targets"].values())


def test_failed_submit_nonce_resumes_after_cooldown(receipt, monkeypatch):
    client = api()
    monkeypatch.setattr(client.time, "time", lambda: 1000)
    calls = []
    def failure(origin, commitment, **kwargs):
        calls.append(commitment)
        raise TallyLockError("synthetic failure", code=5)
    monkeypatch.setattr(client.transport, "submit", failure)
    with pytest.raises(TallyLockError) as error:
        client.submit(receipt, targets=("manifest",))
    assert error.value.code == 5
    frozen = (receipt/".prove/ots-state.json").read_bytes()
    assert not (receipt/"proofs/manifest.ots").exists()
    report = client.upgrade(receipt, targets=("manifest",))
    assert report["targets"]["manifest"]["state"] == "retry_wait"
    assert report["targets"]["manifest"]["proof_sha256"] is None
    assert (receipt/".prove/ots-state.json").read_bytes() == frozen
    monkeypatch.setattr(client.time, "time", lambda: 1301)
    monkeypatch.setattr(client.transport, "submit", lambda origin, commitment, **k: reply(commitment, origin))
    report = client.upgrade(receipt, targets=("manifest",))
    assert report["targets"]["manifest"]["state"] == "pending"
    proof = DetachedTimestampFile.deserialize(BytesDeserializationContext((receipt/"proofs/manifest.ots").read_bytes()))
    assert next(iter(proof.timestamp.ops.values())).ops[OpSHA256()].msg in calls


def test_malformed_selected_core_blocks_every_request(receipt, monkeypatch):
    client = api()
    (receipt/"result.json").write_bytes((receipt/"result.json").read_bytes()+b"\n")
    monkeypatch.setattr(client.transport, "submit", lambda *a, **k: pytest.fail("unexpected request"))
    with pytest.raises(TallyLockError) as error:
        client.submit(receipt)
    assert error.value.code == 2


def import_proof(receipt, *, origins=(ORIGIN,), bitcoin=False):
    client = api()
    from opentimestamps.core.timestamp import Timestamp
    stamp = Timestamp(hashlib.sha256((receipt/"manifest.json").read_bytes()).digest())
    if bitcoin:
        stamp.attestations.add(BitcoinBlockHeaderAttestation(1))
    for origin in origins:
        stamp.attestations.add(PendingAttestation(origin))
    (receipt/"proofs").mkdir(exist_ok=True)
    data = client._encode(stamp)
    (receipt/"proofs/manifest.ots").write_bytes(data)
    return data


def test_imported_unknown_nonce_upgrades_backup_and_unverified_attestation(receipt, monkeypatch):
    client = api()
    old = import_proof(receipt)
    def upgrade(origin, commitment, **kwargs):
        from opentimestamps.core.timestamp import Timestamp
        from opentimestamps.core.serialize import BytesSerializationContext
        stamp = Timestamp(commitment)
        stamp.attestations.add(BitcoinBlockHeaderAttestation(11))
        context = BytesSerializationContext(); stamp.serialize(context)
        return context.getbytes()
    monkeypatch.setattr(client.transport, "upgrade", upgrade)
    report = client.upgrade(receipt, targets=("manifest",))
    item = report["targets"]["manifest"]
    assert item["state"] == "attestation_present" and item["bitcoin_heights"] == [11]
    assert "anchored" not in str(report)
    backup = receipt/f".prove/proof-history/manifest/{hashlib.sha256(old).hexdigest()}.ots"
    assert backup.read_bytes() == old
    assert canonical.loads((receipt/".prove/ots-state.json").read_bytes())["targets"]["manifest"]["nonce"] is None


def test_typed_deferral_absence_is_retry_wait_and_persisted(receipt, monkeypatch):
    client = api()
    monkeypatch.setattr(client.time, "time", lambda: 1000)
    def defer(*args, **kwargs):
        raise client.transport.RetryDeferred(9000)
    monkeypatch.setattr(client.transport, "submit", defer)
    report = client.submit(receipt, targets=("manifest",))
    assert report["targets"]["manifest"] == {"state": "retry_wait", "proof_sha256": None,
        "proof_bytes": 0, "bitcoin_heights": [], "pending_count": 0, "next_retry_at": 9000}
    state = canonical.loads((receipt/".prove/ots-state.json").read_bytes())
    assert all(r["next_retry_at"] == 9000 for r in state["requests"])


def test_partial_target_success_preserved_when_other_target_fails(receipt, monkeypatch):
    client = api()
    expected = hashlib.sha256((receipt/"manifest.json").read_bytes()).hexdigest()
    def submit(origin, commitment, **kwargs):
        state = canonical.loads((receipt/".prove/ots-state.json").read_bytes())
        target = state["requests"][-1]["target"]
        if target == "result":
            raise TallyLockError("failed", code=5)
        return reply(commitment, origin)
    monkeypatch.setattr(client.transport, "submit", submit)
    with pytest.raises(TallyLockError) as error:
        client.submit(receipt)
    assert error.value.code == 5
    from tallylock import anchors
    assert anchors.inspect((receipt/"proofs/manifest.ots").read_bytes(), expected)["pending_count"] == 4
    assert not (receipt/"proofs/result.ots").exists()


@pytest.mark.parametrize("attack", ["extra", "id", "nonce", "authority", "duplicate", "cooldown", "bool"])
def test_untrusted_state_rejected_before_request(receipt, monkeypatch, attack):
    client = api()
    monkeypatch.setattr(client.transport, "submit", lambda origin, commitment, **k: reply(commitment, origin))
    client.submit(receipt, targets=("manifest",))
    path = receipt/".prove/ots-state.json"
    state = canonical.loads(path.read_bytes())
    if attack == "extra": state["unknown"] = True
    elif attack == "id": state["registration_id"] = "00"*32
    elif attack == "nonce": state["targets"]["manifest"]["nonce"] = "bad"
    elif attack == "authority": state["requests"][0]["origin"] = "https://evil.invalid"
    elif attack == "duplicate": state["requests"].append(state["requests"][0])
    elif attack == "cooldown": state["requests"][0]["next_retry_at"] = 0
    elif attack == "bool": state["requests"][0]["attempted_at"] = True
    path.write_bytes(canonical.dumps(state))
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: pytest.fail("unexpected request"))
    with pytest.raises(TallyLockError):
        client.upgrade(receipt, targets=("manifest",))


def test_request_budget_round_robin_and_shared_fair_deadlines(receipt, monkeypatch):
    client = api()
    monkeypatch.setattr(client.time, "time", lambda: 1000)
    def fail(*args, **kwargs):
        raise TallyLockError("synthetic failure", code=5)
    monkeypatch.setattr(client.transport, "submit", fail)
    with pytest.raises(TallyLockError):
        client.submit(receipt, targets=("result",))
    monkeypatch.setattr(client.time, "time", lambda: 1301)
    origins = tuple(f"https://n{i}.calendar.opentimestamps.org" for i in range(12))
    import_proof(receipt, origins=origins)
    calls = []
    def upgrade(origin, commitment, **kwargs):
        calls.append(("upgrade", kwargs["deadline"]))
        return None
    def submit(origin, commitment, **kwargs):
        calls.append(("submit", kwargs["deadline"]))
        return reply(commitment, origin)
    monkeypatch.setattr(client.transport, "upgrade", upgrade)
    monkeypatch.setattr(client.transport, "submit", submit)
    before = client.time.monotonic()
    report = client.upgrade(receipt)
    assert len(calls) == 8
    assert [c[0] for c in calls] == ["upgrade", "submit"]*4
    assert all(before < d <= before+121 for _, d in calls)
    assert calls[0][1] < before+20
    assert report["targets"]["result"]["proof_bytes"] > 0


@pytest.mark.parametrize("point", ["reservation", "backup", "replace", "persist"])
def test_interrupted_publication_preserves_previous_and_resumes(receipt, monkeypatch, point):
    client = api()
    from tallylock.filesystem import Directory
    old = import_proof(receipt)
    write, persist = Directory.atomic_write, Directory.persist_file
    fired = False
    def interrupted_write(self, path, data, replace=False):
        nonlocal fired
        if not fired and ((point == "reservation" and path == ".prove/ots-state.json")
                or (point == "backup" and path.startswith(".prove/proof-history/"))
                or (point == "replace" and path == "proofs/manifest.ots")):
            fired = True
            raise TallyLockError("synthetic interrupted publication", code=5)
        return write(self, path, data, replace=replace)
    def interrupted_persist(self, path):
        nonlocal fired
        if not fired and point == "persist" and path == "proofs/manifest.ots":
            fired = True
            raise TallyLockError("synthetic interrupted fsync", code=5)
        return persist(self, path)
    monkeypatch.setattr(Directory, "atomic_write", interrupted_write)
    monkeypatch.setattr(Directory, "persist_file", interrupted_persist)
    monkeypatch.setattr(client.transport, "upgrade", lambda origin, commitment, **k: reply(commitment, "https://b.pool.opentimestamps.org"))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 5 and fired
    if point != "persist":
        assert (receipt/"proofs/manifest.ots").read_bytes() == old
    else:
        assert (receipt/f".prove/proof-history/manifest/{hashlib.sha256(old).hexdigest()}.ots").read_bytes() == old
    assert not (receipt/".prove/lock").exists()
    clock = int(client.time.time())
    monkeypatch.setattr(client.time, "time", lambda: clock+301)
    resumed = client.upgrade(receipt, targets=("manifest",))
    assert resumed["targets"]["manifest"]["proof_bytes"] > 0
    assert not (receipt/".prove/lock").exists()


def test_core_mutation_during_network_rejected_before_proof_publication(receipt, monkeypatch):
    client = api()
    def submit(*args, **kwargs):
        (receipt/"manifest.json").write_bytes(b"substituted")
        return reply(args[1], args[0])
    monkeypatch.setattr(client.transport, "submit", submit)
    with pytest.raises(TallyLockError) as error:
        client.submit(receipt, targets=("manifest",))
    assert error.value.code == 2
    assert not (receipt/"proofs/manifest.ots").exists()


def test_one_writer_lock_and_no_unsafe_proof_authority(receipt, monkeypatch):
    client = api()
    from tallylock.filesystem import Directory, WriterLock
    import_proof(receipt, origins=("https://evil.invalid",))
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: pytest.fail("unexpected request"))
    with Directory(receipt) as directory, WriterLock(directory):
        with pytest.raises(TallyLockError) as error:
            client.upgrade(receipt, targets=("manifest",))
        assert error.value.code == 5
    report = client.upgrade(receipt, targets=("manifest",))
    assert report["warnings"] and report["targets"]["manifest"]["state"] == "unchanged"


def test_malformed_reply_preserves_imported_bytes(receipt, monkeypatch):
    client = api()
    old = import_proof(receipt)
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: b"bad reply")
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 5
    assert (receipt/"proofs/manifest.ots").read_bytes() == old


def test_manifest_before_seal_promotes_only_null_receipt_id(tmp_path, monkeypatch):
    client = api()
    core = json.loads((Path(__file__).resolve().parents[1]/"examples/basic/manifest.json").read_bytes())
    store.register(core, tmp_path)
    monkeypatch.setattr(client.transport, "submit", lambda origin, commitment, **k: reply(commitment, origin))
    report = client.submit(tmp_path, targets=("manifest",))
    assert report["receipt_id"] is None
    state_before = canonical.loads((tmp_path/".prove/ots-state.json").read_bytes())
    proof_before = (tmp_path/"proofs/manifest.ots").read_bytes()
    store.seal(tmp_path, outcome="failed", reason="synthetic fixture")
    report = client.submit(tmp_path)
    state_after = canonical.loads((tmp_path/".prove/ots-state.json").read_bytes())
    assert state_after["targets"]["manifest"] == state_before["targets"]["manifest"]
    assert state_after["receipt_id"] == report["receipt_id"]
    assert (tmp_path/"proofs/manifest.ots").read_bytes() == proof_before


def test_merged_byte_limit_enforced_during_serialization(receipt, monkeypatch):
    client = api()
    old = import_proof(receipt)
    monkeypatch.setattr(client.anchors, "MAX_PROOF_BYTES", len(old)+1)
    monkeypatch.setattr(client.transport, "upgrade", lambda origin, commitment, **k: reply(commitment, "https://b.pool.opentimestamps.org"))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 5
    assert (receipt/"proofs/manifest.ots").read_bytes() == old


def test_serialization_stops_at_byte_limit_before_inspection(receipt, monkeypatch):
    client = api()
    from opentimestamps.core.timestamp import Timestamp
    stamp = Timestamp(b"a"*32)
    stamp.attestations.add(PendingAttestation(ORIGIN))
    monkeypatch.setattr(client.anchors, "MAX_PROOF_BYTES", 20)
    with pytest.raises(TallyLockError) as error:
        client._encode(stamp)
    assert error.value.code == 5


def test_fresh_upgrade_requires_proof_or_saved_nonce(receipt, monkeypatch):
    client = api()
    monkeypatch.setattr(client.transport, "submit", lambda *a, **k: pytest.fail("unexpected submission"))
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: pytest.fail("unexpected upgrade"))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 3
    assert not (receipt/".prove/ots-state.json").exists()


def test_imported_unknown_nonce_without_proof_is_insufficient(receipt, monkeypatch):
    client = api()
    import_proof(receipt)
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: None)
    client.upgrade(receipt, targets=("manifest",))
    (receipt/"proofs/manifest.ots").unlink()
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 3


def test_conflicting_history_never_clobbered_and_old_proof_preserved(receipt, monkeypatch):
    client = api()
    old = import_proof(receipt)
    history = receipt/f".prove/proof-history/manifest/{hashlib.sha256(old).hexdigest()}.ots"
    history.parent.mkdir(parents=True)
    history.write_bytes(b"conflicting existing history")
    monkeypatch.setattr(client.transport, "upgrade", lambda origin, commitment, **k: reply(commitment, "https://b.pool.opentimestamps.org"))
    with pytest.raises(TallyLockError):
        client.upgrade(receipt, targets=("manifest",))
    assert history.read_bytes() == b"conflicting existing history"
    assert (receipt/"proofs/manifest.ots").read_bytes() == old


def test_reply_with_valid_own_depth_but_excessive_merged_depth_preserves_old(receipt, monkeypatch):
    client = api()
    from opentimestamps.core.timestamp import Timestamp
    from opentimestamps.core.serialize import BytesSerializationContext
    stamp = Timestamp(hashlib.sha256((receipt/"manifest.json").read_bytes()).digest())
    leaf = stamp
    for _ in range(client.anchors.MAX_TIMESTAMP_DEPTH - 1):
        leaf = leaf.ops.add(OpSHA256())
    leaf.attestations.add(PendingAttestation(ORIGIN))
    old = client._encode(stamp)
    (receipt/"proofs").mkdir()
    (receipt/"proofs/manifest.ots").write_bytes(old)
    def upgrade(origin, commitment, **kwargs):
        addition = Timestamp(commitment)
        addition.ops.add(OpSHA256()).attestations.add(PendingAttestation(origin))
        context = BytesSerializationContext(); addition.serialize(context)
        return context.getbytes()
    monkeypatch.setattr(client.transport, "upgrade", upgrade)
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 5
    assert (receipt/"proofs/manifest.ots").read_bytes() == old


@pytest.mark.parametrize("attestation", [UnknownAttestation(b"unknown!", b"opaque"), LitecoinBlockHeaderAttestation(1)])
def test_unsupported_only_upgrade_reply_preserves_supported_previous(receipt, monkeypatch, attestation):
    client = api()
    old = import_proof(receipt)
    monkeypatch.setattr(client.transport, "upgrade", lambda origin, commitment, **k: attested_reply(commitment, attestation))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == 5
    assert (receipt/"proofs/manifest.ots").read_bytes() == old


@pytest.mark.parametrize("attestation", [UnknownAttestation(b"unknown!", b"opaque"), LitecoinBlockHeaderAttestation(1)])
def test_imported_unsupported_only_proof_is_unsupported_before_io(receipt, monkeypatch, attestation):
    client = api()
    from opentimestamps.core.timestamp import Timestamp
    stamp = Timestamp(hashlib.sha256((receipt/"manifest.json").read_bytes()).digest())
    stamp.attestations.add(attestation)
    old = client._encode(stamp)
    (receipt/"proofs").mkdir()
    path = receipt/"proofs/manifest.ots"
    path.write_bytes(old)
    monkeypatch.setattr(client.transport, "submit", lambda *a, **k: pytest.fail("unexpected request"))
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: pytest.fail("unexpected request"))
    for action in (client.submit, client.upgrade):
        with pytest.raises(TallyLockError) as error:
            action(receipt, targets=("manifest",))
        assert error.value.code == 4
        assert path.read_bytes() == old


def test_unsupported_only_submission_fails_without_publishing_fake_pending(receipt, monkeypatch):
    client = api()
    monkeypatch.setattr(client.transport, "submit", lambda origin, commitment, **k:
        attested_reply(commitment, LitecoinBlockHeaderAttestation(1)))
    with pytest.raises(TallyLockError) as error:
        client.submit(receipt, targets=("manifest",))
    assert error.value.code == 5
    assert not (receipt/"proofs/manifest.ots").exists()


def test_unsupported_calendar_failure_preserves_other_supported_successes(receipt, monkeypatch):
    client = api()
    from tallylock import anchors
    calls = []
    def submit(origin, commitment, **kwargs):
        calls.append(origin)
        if len(calls) == 1:
            return attested_reply(commitment, LitecoinBlockHeaderAttestation(1))
        return reply(commitment, origin)
    monkeypatch.setattr(client.transport, "submit", submit)
    report = client.submit(receipt, targets=("manifest",))
    assert report["warnings"] and len(calls) == 4
    item = report["targets"]["manifest"]
    assert item["state"] == "pending" and item["pending_count"] == 3
    info = anchors.inspect((receipt/"proofs/manifest.ots").read_bytes(), report["registration_id"])
    assert info["unsupported_attestations"] == 0


@pytest.mark.parametrize("supported", [PendingAttestation(ORIGIN), BitcoinBlockHeaderAttestation(11)])
def test_mixed_supported_and_opaque_reply_preserves_extras_unverified(receipt, monkeypatch, supported):
    client = api()
    from tallylock import anchors
    monkeypatch.setattr(client.transport, "submit", lambda origin, commitment, **k:
        attested_reply(commitment, supported, UnknownAttestation(b"unknown!", b"opaque")))
    report = client.submit(receipt, targets=("manifest",))
    info = anchors.inspect((receipt/"proofs/manifest.ots").read_bytes(), report["registration_id"])
    assert info["unsupported_attestations"] == 1
    item = report["targets"]["manifest"]
    assert item["state"] == ("pending" if isinstance(supported, PendingAttestation) else "attestation_present")
    assert "anchored" not in str(report)


@pytest.mark.parametrize("both_targets", [False, True])
def test_repeated_commands_reach_origins_beyond_first_request_budget(receipt, monkeypatch, both_targets):
    client = api()
    from opentimestamps.core.timestamp import Timestamp
    origins = tuple(f"https://fair{i}.calendar.opentimestamps.org" for i in range(12))
    targets = ("manifest", "result") if both_targets else ("manifest",)
    (receipt/"proofs").mkdir()
    names = {}
    for name in targets:
        digest = hashlib.sha256((receipt/f"{name}.json").read_bytes()).digest()
        names[digest] = name
        stamp = Timestamp(digest)
        stamp.attestations.update(PendingAttestation(origin) for origin in origins)
        (receipt/f"proofs/{name}.ots").write_bytes(client._encode(stamp))
    clock = [1000]
    monkeypatch.setattr(client.time, "time", lambda: clock[0])
    calls = []
    def upgrade(origin, commitment, **kwargs):
        calls.append((names[commitment], origin))
        return None
    monkeypatch.setattr(client.transport, "upgrade", upgrade)
    seen = {name: set() for name in targets}
    for _ in range(4):
        before = len(calls)
        report = client.upgrade(receipt, targets=targets)
        batch = calls[before:]
        assert len(batch) <= 8
        if both_targets:
            assert [name for name, _ in batch] == ["manifest", "result"]*4
        for name, origin in batch:
            seen[name].add(origin)
        due = [item["next_retry_at"] for item in report["targets"].values() if item["next_retry_at"] is not None]
        assert due
        clock[0] = max(clock[0]+301, min(due)+1)
    assert all(values == set(origins) for values in seen.values())


@pytest.mark.parametrize("discriminator,code", [(None, 2), (7, 2), ("prove.ots-state.v999", 4)])
def test_state_format_distinguishes_malformed_from_unsupported(receipt, monkeypatch, discriminator, code):
    client = api()
    import_proof(receipt)
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: None)
    client.upgrade(receipt, targets=("manifest",))
    path = receipt/".prove/ots-state.json"
    state = canonical.loads(path.read_bytes())
    state["format"] = discriminator
    malformed = canonical.dumps(state)
    path.write_bytes(malformed)
    monkeypatch.setattr(client.transport, "upgrade", lambda *a, **k: pytest.fail("unexpected request"))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(receipt, targets=("manifest",))
    assert error.value.code == code
    assert path.read_bytes() == malformed
