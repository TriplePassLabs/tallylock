"""Provider header evidence: recorded mainnet replies, forgeries and offline re-checks."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path

from bitcoin.core import CBlockHeader, b2lx
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
import pytest

from tallylock import _http, canonical
from tallylock.errors import TallyLockError


FIXTURES = Path(__file__).parent / "fixtures/headers"
RECORDED = json.loads((FIXTURES / "mainnet-replies.json").read_text())
BLOCKSTREAM, MEMPOOL = "https://blockstream.info/api", "https://mempool.space/api"
PROOF = (FIXTURES / "hello-world.txt.ots").read_bytes()
PROOF_DIGEST = hashlib.sha256((FIXTURES / "hello-world.txt").read_bytes()).hexdigest()
OBSERVED = 1794087110  # 2026-11-07T21:31:50Z, when the replies were recorded


def api():
    assert importlib.util.find_spec("tallylock.headers") is not None, "W1 headers module absent"
    return importlib.import_module("tallylock.headers")


def replies():
    return deepcopy(RECORDED["providers"])


def header_at(provider, height):
    return provider[f"/block/{provider[f'/block-height/{height}']}/header"]


class Fetch:
    """Serve recorded replies; values may be bodies, Responses or exceptions."""

    def __init__(self, maps, *, clock=None, step=0.0):
        self.maps, self.calls, self.clock, self.step = maps, [], clock, step

    def __call__(self, url, *, deadline):
        self.calls.append(url)
        if self.clock is not None:
            self.clock.now += self.step
        for base, table in self.maps.items():
            if url.startswith(base + "/"):
                value = table.get(url[len(base):])
                if isinstance(value, list):
                    value = value.pop(0) if len(value) > 1 else value[0]
                if isinstance(value, BaseException):
                    raise value
                if isinstance(value, _http.Response):
                    return value
                if value is None:
                    return _http.Response(404, b"", None)
                return _http.Response(200, value.encode() if isinstance(value, str) else value, None)
        raise AssertionError(f"unexpected URL {url}")


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def observe(maps=None, heights=(358391,), *, blocks_on_top=10, **options):
    maps = replies() if maps is None else maps
    fetch = options.pop("fetch", Fetch(maps))
    clock = options.pop("clock", Clock())
    evidence = api().observe(list(heights), blocks_on_top=blocks_on_top, fetch=fetch, sleep=clock.sleep,
                             clock=clock, now=lambda: OBSERVED, **options)
    return evidence, fetch


def failure(call, code):
    with pytest.raises(TallyLockError) as error:
        call()
    assert error.value.code == code
    return error.value.message


def test_real_proof_verifies_against_two_agreeing_providers():
    fetch = Fetch(replies())
    output = api().verify_proof(PROOF, PROOF_DIGEST, blocks_on_top=10, fetch=fetch, sleep=Clock().sleep,
                                now=lambda: OBSERVED)
    anchor = output["anchor"]
    assert anchor["state"] == "anchored" and anchor["height"] == 358391
    assert anchor["hash"] == RECORDED["providers"][BLOCKSTREAM]["/block-height/358391"]
    assert anchor["confirmations"] == 974990 - 358391 + 1
    summary = output["providers"]
    assert summary["proof_of_work"] == "checked" and summary["links"] == "checked"
    assert summary["providers_agreed"] is True and summary["blocks_on_top"] == {"358391": 10}
    assert summary["consensus"] == "full consensus not validated"
    assert summary["providers"] == [BLOCKSTREAM, MEMPOOL]
    assert summary["tip"] == {"height": 974990, "hash": RECORDED["providers"][BLOCKSTREAM]["/blocks/tip/hash"]}
    assert output["freshness"]["state"] == "current"
    evidence = output["evidence"]
    assert evidence["format"] == "tallylock.provider-evidence.v1"
    assert evidence["observed_at"] == "2026-11-07T21:31:50Z"
    assert evidence["checks"] == {"proof_of_work": True, "links": True, "providers_agreed": True,
                                  "tips_within_one_block": True}
    assert [len(segment["headers"]) for segment in evidence["segments"]] == [11]
    # Serial requests: tips, both ends of the range from each provider, then one walk.
    assert all(url.startswith((BLOCKSTREAM + "/", MEMPOOL + "/")) for url in fetch.calls)
    assert len(fetch.calls) == 2 * 4 + 11


@pytest.mark.parametrize("height", [0, 840000])
def test_real_genesis_and_modern_difficulty_headers_pass_work_and_links(height):
    evidence, _ = observe(heights=(height,), blocks_on_top=3 if height == 0 else 10)
    checked = api().check(evidence)
    block = checked.view.block(height)
    assert block.hash == RECORDED["providers"][MEMPOOL][f"/block-height/{height}"]
    assert block.confirmations == 974990 - height + 1
    assert checked.view.block(height + (3 if height == 0 else 10)) is not None


def test_default_hundred_blocks_on_top_are_capped_by_the_tip():
    maps = replies()
    for table in maps.values():
        table["/blocks/tip/height"] = "358395"
        table["/blocks/tip/hash"] = table["/block-height/358395"]
    evidence = api().observe([358391], fetch=Fetch(maps), sleep=Clock().sleep, clock=Clock(), now=lambda: OBSERVED)
    assert evidence["blocks_on_top"] == 100
    assert [len(segment["headers"]) for segment in evidence["segments"]] == [5]
    assert api().check(evidence).view.block(358391).confirmations == 5


def test_tips_within_one_block_pass_and_confirmations_use_the_lower_tip():
    maps = replies()
    maps[MEMPOOL]["/blocks/tip/height"] = "974991"
    evidence, _ = observe(maps)
    assert api().check(evidence).view.block(358391).confirmations == 974990 - 358391 + 1
    maps[MEMPOOL]["/blocks/tip/height"] = "974992"
    assert "tips differ by more than one block" in failure(lambda: observe(maps), 3)


def forged_top(maps, height=358401):
    raw = bytearray(bytes.fromhex(header_at(maps[BLOCKSTREAM], height)))
    raw[-1] ^= 1
    forged = b2lx(CBlockHeader.deserialize(bytes(raw)).GetHash())
    for table in maps.values():
        table[f"/block-height/{height}"] = forged
        table[f"/block/{forged}/header"] = raw.hex()
    return maps


def test_forged_header_with_bad_work_fails_even_when_providers_agree():
    message = failure(lambda: observe(forged_top(replies())), 2)
    assert "height 358401 does not meet its proof-of-work target" in message


def test_header_that_differs_from_the_requested_block_is_rejected():
    maps = replies()
    table = maps[BLOCKSTREAM]
    table[f"/block/{table['/block-height/358401']}/header"] = header_at(table, 840000)
    assert "does not match the requested block" in failure(lambda: observe(maps), 2)


def test_broken_link_and_edited_evidence_fail_offline():
    evidence, _ = observe()
    linked = deepcopy(evidence)
    linked["segments"][0]["headers"][3] = linked["segments"][0]["headers"][0]  # same period, valid work
    assert "height 358394 does not link to the previous header" in failure(lambda: api().check(linked), 2)
    worked = deepcopy(evidence)
    raw = bytearray(bytes.fromhex(worked["segments"][0]["headers"][10]))
    raw[-1] ^= 1
    worked["segments"][0]["headers"][10] = raw.hex()
    assert "proof-of-work target" in failure(lambda: api().check(worked), 2)


def test_providers_disagreeing_on_a_block_fail():
    maps = replies()
    maps[MEMPOOL]["/block-height/358401"] = maps[MEMPOOL]["/block-height/840000"]
    assert "providers disagree on the block at height 358401" in failure(lambda: observe(maps), 3)
    evidence, _ = observe()
    evidence["answers"][MEMPOOL]["358391"] = "00" * 32
    assert "providers disagree on the block at height 358391" in failure(lambda: api().check(evidence), 3)


@pytest.mark.parametrize("path, body", [
    ("/blocks/tip/height", "tip"), ("/blocks/tip/height", "01"), ("/blocks/tip/hash", "AB" * 32),
    ("/block-height/358391", "00" * 31), ("header", "zz" * 80), ("header", "00" * 79),
])
def test_malformed_replies_fail_with_their_own_message(path, body):
    maps = replies()
    table = maps[MEMPOOL if path != "header" else BLOCKSTREAM]
    if path == "header":
        path = f"/block/{table['/block-height/358395']}/header"
    table[path] = body
    assert "sent a malformed reply" in failure(lambda: observe(maps), 5)


def test_oversized_and_unreadable_replies_fail():
    maps = replies()
    maps[BLOCKSTREAM]["/blocks/tip/hash"] = "0" * 300
    assert "sent a reply that is too large" in failure(lambda: observe(maps), 5)
    maps = replies()
    maps[BLOCKSTREAM]["/blocks/tip/hash"] = TallyLockError("HTTP response exceeds size limit", code=5)
    assert "sent a reply that could not be read" in failure(lambda: observe(maps), 5)


def test_default_fetch_bounds_each_reply(monkeypatch):
    seen = []

    def request(method, url, **options):
        seen.append((method, url, options))
        return _http.Response(200, b"974990", None)

    monkeypatch.setattr(_http, "request", request)
    assert api()._fetch(BLOCKSTREAM + "/blocks/tip/height", deadline=5.0).body == b"974990"
    method, url, options = seen[0]
    assert method == "GET" and options["body"] is None and options["deadline"] == 5.0
    assert options["response_limit"] == api().MAX_REPLY_BYTES <= 256


def test_timeouts_retry_three_times_then_fail():
    maps = replies()
    maps[BLOCKSTREAM]["/blocks/tip/height"] = _http.NetworkError()
    clock = Clock()
    message = failure(lambda: observe(maps, clock=clock), 5)
    assert "still failing after 3 attempts" in message and clock.slept == [1, 2]


def test_operation_deadline_is_one_hundred_twenty_seconds():
    clock = Clock()
    fetch = Fetch(replies(), clock=clock, step=10.0)
    message = failure(lambda: observe(fetch=fetch, clock=clock), 5)
    assert "120 second limit" in message and len(fetch.calls) == 12


def test_rate_limits_honor_retry_after_and_never_wait_past_the_deadline():
    maps = replies()
    maps[BLOCKSTREAM]["/blocks/tip/height"] = [_http.Response(429, b"", "7"), "974990"]
    clock = Clock()
    evidence, fetch = observe(maps, clock=clock)
    assert len(clock.slept) == 1 and 6 < clock.slept[0] <= 7
    assert fetch.calls.count(BLOCKSTREAM + "/blocks/tip/height") == 2
    for status in (403, 503):
        maps = replies()
        maps[MEMPOOL]["/blocks/tip/hash"] = _http.Response(status, b"", "500")
        clock = Clock()
        assert "asked to wait past the 120 second limit" in failure(lambda: observe(maps, clock=clock), 5)
        assert clock.slept == []
    maps = replies()
    maps[MEMPOOL]["/blocks/tip/hash"] = _http.Response(404, b"", None)
    clock = Clock()
    assert "returned HTTP 404" in failure(lambda: observe(maps, clock=clock), 5)
    assert clock.slept == []


def never(url, *, deadline):
    raise AssertionError("offline re-check must not fetch")


def modern_proof():
    """A proof naming block 840000 for that block's own merkle root, so saved evidence for it can be re-checked."""
    root = CBlockHeader.deserialize(bytes.fromhex(header_at(RECORDED["providers"][MEMPOOL], 840000))).hashMerkleRoot
    stamp = Timestamp(root)
    stamp.attestations.add(BitcoinBlockHeaderAttestation(840000))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
    return ctx.getbytes(), root.hex()


def test_saved_evidence_rechecks_offline_without_any_fetch():
    evidence, _ = observe(heights=(840000,))
    saved = canonical.loads(canonical.dumps(evidence))
    proof, digest = modern_proof()
    output = api().verify_proof(proof, digest, evidence=saved, fetch=never, now=lambda: OBSERVED + 86400)
    assert output["anchor"]["state"] == "anchored" and output["anchor"]["height"] == 840000
    # Saved evidence counts the headers it carries, not the tip it reports.
    assert output["anchor"]["confirmations"] == 11
    assert output["freshness"] == {"state": "as_observed", "label": "as observed at 2026-11-07T21:31:50Z",
                                   "observed_at": "2026-11-07T21:31:50Z", "age_seconds": 86400}
    assert output["evidence"] == saved


def test_saved_evidence_for_cheap_old_blocks_is_refused_offline():
    # One header of 2015-era work costs little to mine, so a saved file cannot vouch for it.
    evidence, _ = observe()
    saved = canonical.loads(canonical.dumps(evidence))
    message = failure(lambda: api().verify_proof(PROOF, PROOF_DIGEST, evidence=saved, fetch=never), 3)
    assert "re-check online" in message
    online = api().verify_proof(PROOF, PROOF_DIGEST, blocks_on_top=10, fetch=Fetch(replies()), sleep=Clock().sleep,
                                now=lambda: OBSERVED)
    assert online["anchor"]["state"] == "anchored"


def test_saved_evidence_cannot_claim_confirmations_it_has_no_headers_for():
    # A forger mines one header and writes any tip; only the headers in the file count.
    evidence, _ = observe(heights=(840000,))
    forged = deepcopy(evidence)
    forged.update(blocks_on_top=0, segments=[{"start": 840000, "headers": evidence["segments"][0]["headers"][:1]}],
                  answers={p: {"840000": evidence["answers"][p]["840000"]} for p in evidence["providers"]})
    assert api().check(forged).view.block(840000).confirmations == 974990 - 840000 + 1
    assert api().check(forged, saved=True).view.block(840000).confirmations == 1
    proof, digest = modern_proof()
    output = api().verify_proof(proof, digest, evidence=forged, fetch=never, now=lambda: OBSERVED)
    assert output["anchor"]["state"] == "insufficient_confirmations"


def test_difficulty_one_headers_far_past_the_table_are_refused():
    # Chained 4x steps once let a header 26 periods past the table use difficulty 1 (2^32 work to forge).
    height = (len(api().DIFFICULTY) + 25) * api().PERIOD
    assert "too easy" in failure(lambda: api()._difficulty(height, 0x1D00FFFF, {}), 2)
    last = api().DIFFICULTY[-1]
    api()._difficulty(height, last, {})


def test_attested_root_must_match_the_header():
    stamp = Timestamp(bytes.fromhex("12" * 32))
    stamp.attestations.add(BitcoinBlockHeaderAttestation(358391))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
    message = failure(lambda: api().verify_proof(ctx.getbytes(), "12" * 32, blocks_on_top=10, fetch=Fetch(replies()),
                                                 sleep=Clock().sleep, now=lambda: OBSERVED), 2)
    assert "contradicts the proof" in message


def test_pending_or_missing_proofs_make_no_requests():
    output = api().verify_proof(None, PROOF_DIGEST, fetch=never, now=lambda: OBSERVED)
    assert output["anchor"]["state"] == "missing" and output["evidence"] is None


@pytest.mark.parametrize("confirmations, offline, age, state", [
    (5, False, 901, "stale"), (5, True, 901, "stale"), (5, False, 900, "current"),
    (None, True, 3600, "stale"), (6, False, 90000, "current"), (6, True, 90000, "as_observed"),
    (5, True, 60, "as_observed"),
])
def test_freshness_is_stale_only_below_the_threshold(confirmations, offline, age, state):
    value = api().freshness("2026-11-07T21:31:50Z", confirmations, 6, offline=offline, now=OBSERVED + age)
    assert value["state"] == state and value["age_seconds"] == age
    if state == "stale":
        assert value["label"] == "stale, re-check"
    if state == "as_observed":
        assert value["label"] == "as observed at 2026-11-07T21:31:50Z"


@pytest.mark.parametrize("change", [
    lambda e: e.update(extra=1),
    lambda e: e.update(format="prove.provider-evidence.v1"),
    lambda e: e["checks"].update(links=False),
    lambda e: e["answers"].pop(MEMPOOL),
    lambda e: e.update(providers=[BLOCKSTREAM]),
    lambda e: e["segments"][0]["headers"].pop(),
    lambda e: e["segments"][0].update(start=358392),
    lambda e: e.update(heights=[358391, 358500]),
    lambda e: e.update(observed_at="2026-11-07 21:31:50"),
    lambda e: e["tips"][0].update(height=True),
    lambda e: e.update(blocks_on_top=5000),
])
def test_tampered_evidence_shapes_are_rejected(change):
    evidence, _ = observe()
    change(evidence)
    with pytest.raises(TallyLockError):
        api().check(evidence)


def test_bad_options_are_rejected_before_any_request():
    for heights, options in (([-1], {}), ([True], {}), (list(range(17)), {}),
                             ([1], {"providers": [BLOCKSTREAM]}), ([1], {"providers": [BLOCKSTREAM, BLOCKSTREAM]}),
                             ([1], {"providers": ["http://example.com/api", MEMPOOL]}),
                             ([1], {"blocks_on_top": -1}), ([1], {"blocks_on_top": 2017})):
        with pytest.raises(TallyLockError):
            api().observe(heights, fetch=never, **options)


# Verifier policy path, using synthetic receipts and regtest-difficulty headers.

REGTEST_BITS = 0x207FFFFF


def mine(prev, merkle, time, bits=REGTEST_BITS):
    nonce = 0
    while True:
        header = CBlockHeader(nVersion=1, hashPrevBlock=prev, hashMerkleRoot=merkle, nTime=time,
                              nBits=bits, nNonce=nonce)
        if int.from_bytes(header.GetHash(), "little") <= api().compact_target(bits):
            return header.serialize()
        nonce += 1


def synthetic_chain(roots, tip, bits=lambda height: REGTEST_BITS):
    chain, prev = {}, b"\x00" * 32
    for height in range(tip + 1):
        chain[height] = mine(prev, roots.get(height, hashlib.sha256(b"%d" % height).digest()), 1700000000 + height,
                             bits(height))
        prev = CBlockHeader.deserialize(chain[height]).GetHash()
    table = {"/blocks/tip/height": str(tip), "/blocks/tip/hash": b2lx(prev)}
    for height, raw in chain.items():
        name = b2lx(CBlockHeader.deserialize(raw).GetHash())
        table[f"/block-height/{height}"] = name
        table[f"/block/{name}/header"] = raw.hex()
    return {BLOCKSTREAM: table, MEMPOOL: deepcopy(table)}


@pytest.fixture
def regtest(monkeypatch):
    monkeypatch.setattr(api(), "SAVED_FLOOR_HEIGHT", 0)
    monkeypatch.setattr(api(), "POW_LIMIT", api().compact_target(REGTEST_BITS))
    monkeypatch.setattr(api(), "DIFFICULTY", (REGTEST_BITS,))


def anchored_receipt(tmp_path, tip=110):
    from test_verify import receipt
    manifest, result = receipt(tmp_path)
    roots = {}
    (tmp_path / "proofs").mkdir()
    for height, (name, core) in enumerate((("manifest", manifest), ("result", result)), 1):
        stamp = Timestamp(bytes.fromhex(canonical.digest(core)))
        stamp.attestations.add(BitcoinBlockHeaderAttestation(height))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
        (tmp_path / "proofs" / f"{name}.ots").write_bytes(ctx.getbytes())
        roots[height] = stamp.msg
    return synthetic_chain(roots, tip)


def verifier():
    return importlib.import_module("tallylock.verify")


def test_verify_provider_policy_online_then_offline(tmp_path, regtest):
    maps = anchored_receipt(tmp_path)
    fetch = Fetch(maps)
    output = verifier().full(tmp_path, policy="provider-pow", fetch=fetch)
    assert output.code == 0, output.report["errors"]
    report = output.report
    assert report["policy"] == "provider-pow"
    assert report["manifest_anchor"]["state"] == report["result_anchor"]["state"] == "anchored"
    assert report["result_anchor"]["confirmations"] == 109
    provider = report["provider_pow"]
    assert provider["state"] == "checked" and provider["proof_of_work"] == "checked"
    assert provider["blocks_on_top"] == {"1": 100, "2": 100} and provider["providers_agreed"] is True
    assert provider["consensus"] == "full consensus not validated"
    assert provider["freshness"]["state"] == "current"
    assert any("full consensus" in item for item in report["limitations"])
    assert output.evidence["format"] == "tallylock.provider-evidence.v1"
    assert len(output.evidence["segments"]) == 1 and output.evidence["heights"] == [1, 2]
    saved = canonical.loads(canonical.dumps(output.evidence))
    offline = verifier().full(tmp_path, policy="provider-pow", provider_evidence=saved, fetch=never)
    assert offline.code == 0 and offline.report["provider_pow"]["freshness"]["state"] == "as_observed"
    assert offline.evidence == saved
    assert verifier().full(tmp_path, policy="provider-pow", provider_evidence=saved,
                           minimum_confirmations=200).code == 3


def test_verify_provider_policy_failures_are_reported(tmp_path, regtest):
    maps = anchored_receipt(tmp_path)
    maps[MEMPOOL]["/block-height/102"] = "00" * 32
    output = verifier().full(tmp_path, policy="provider-pow", fetch=Fetch(maps))
    assert output.code == 3 and output.report["provider_pow"]["state"] == "unavailable"
    assert output.report["errors"][0]["stage"] == "providers"
    assert output.report["manifest_anchor"]["state"] == "unavailable"


def test_verify_provider_policy_inclusion_and_untouched_existing_reports(tmp_path, regtest):
    maps = anchored_receipt(tmp_path)
    package = verifier().make_inclusion(tmp_path, 1)
    output = verifier().inclusion(package, policy="provider-pow", fetch=Fetch(maps))
    assert output.code == 0 and output.report["provider_pow"]["state"] == "checked"
    from test_verify import FIELDS
    plain = verifier().full(tmp_path, policy="integrity-only")
    assert set(plain.report) == FIELDS and plain.evidence is None
    rejected = verifier().full(tmp_path, policy="integrity-only", provider_evidence=output.evidence)
    assert rejected.code == 2 and rejected.report["errors"][0]["stage"] == "options"


# Difficulty: bundled mainnet table, then the consensus factor-of-4 rule for a bounded distance past it.

DIFFICULTY_FILE = Path(__file__).parents[1] / "src/tallylock/data/difficulty.json"


def table():
    return tuple(json.loads(DIFFICULTY_FILE.read_text())["bits"])


def test_bundled_table_matches_real_headers():
    assert table()[0] == 0x1D00FFFF and len(table()) >= 483
    for height in (0, 3, 358391, 358401, 840000, 840010):
        raw = bytes.fromhex(header_at(RECORDED["providers"][BLOCKSTREAM], height))
        assert CBlockHeader.deserialize(raw).nBits == table()[height // 2016]


def test_min_difficulty_forged_chain_with_valid_links_fails():
    maps, prev = replies(), None
    for height in range(840000, 840011):
        header = CBlockHeader.deserialize(bytes.fromhex(header_at(RECORDED["providers"][BLOCKSTREAM], height)))
        forged = CBlockHeader(nVersion=header.nVersion, hashPrevBlock=prev or header.hashPrevBlock,
                              hashMerkleRoot=header.hashMerkleRoot, nTime=header.nTime, nBits=0x1D00FFFF,
                              nNonce=header.nNonce)
        prev, name = forged.GetHash(), b2lx(forged.GetHash())
        for provider in maps.values():
            provider[f"/block-height/{height}"] = name
            provider[f"/block/{name}/header"] = forged.serialize().hex()
    message = failure(lambda: observe(maps, heights=(840000,)), 2)
    assert "height 840000 does not use the known difficulty for its period" in message


def test_easy_work_at_a_tabled_height_fails_even_with_valid_work(regtest, monkeypatch):
    monkeypatch.setattr(api(), "DIFFICULTY", table())
    maps = synthetic_chain({}, 12)
    assert "does not use the known difficulty" in failure(lambda: observe(maps, heights=(2,)), 2)


@pytest.mark.parametrize("keep, ok", [(391, True), (390, False)])
def test_real_headers_past_the_table_are_capped_at_twenty_six_periods(monkeypatch, keep, ok):
    monkeypatch.setattr(api(), "DIFFICULTY", table()[:keep])
    call = lambda: observe(heights=(840000,))
    if ok:
        assert api().check(call()[0]).view.block(840000) is not None
    else:
        assert failure(call, 4) == "difficulty table too old, update TallyLock"


def extension(changes):
    """Period 0 is tabled; period 1 (heights 2016 and up) is past the table."""
    return synthetic_chain({}, 2026, lambda height: REGTEST_BITS if height < 2016 else changes.get(height, changes[0]))


def test_synthetic_extension_within_four_times_passes(regtest):
    evidence, _ = observe(extension({0: 0x203FFFFF}), heights=(2016,))
    assert api().check(evidence).view.block(2026) is not None


def test_synthetic_extension_rejects_mid_period_changes_and_large_steps(regtest):
    maps = extension({0: 0x203FFFFF, 2020: 0x201FFFFF})
    message = failure(lambda: observe(maps, heights=(2016,)), 2)
    assert "height 2020 changes difficulty inside a retarget period" in message
    maps = extension({0: 0x200FFFFF})
    message = failure(lambda: observe(maps, heights=(2016,)), 2)
    assert "height 2016 changes difficulty by more than the consensus limit" in message
