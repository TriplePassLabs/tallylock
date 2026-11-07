"""Explicit cache validation, with historical and synthetic headers."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import importlib
from pathlib import Path

from bitcoin.core import CBlockHeader, b2lx
import pytest

from tallylock.errors import TallyLockError


HEADER = bytes.fromhex((Path(__file__).parent / "fixtures/ots/historical-header.hex").read_text())


def cache_for(headers=None, tip_height=6):
    """Build an explicitly synthetic cache around upstream-parsed headers."""
    headers = {1: HEADER} if headers is None else headers
    return {
        "format": "prove.chain.v1", "exported_at": "2026-11-06T00:00:00Z",
        "source": "synthetic test cache, not independent node evidence",
        "tip": {"height": tip_height, "hash": "ab" * 32},
        "node": {"chain": "main", "initialblockdownload": False,
                 "blocks": tip_height, "headers": tip_height, "verificationprogress": "1"},
        "blocks": {str(h): {"header": raw.hex(), "hash": b2lx(CBlockHeader.deserialize(raw).GetHash()),
                             "confirmations": tip_height - h + 1} for h, raw in headers.items()},
    }


@pytest.fixture
def chain_module():
    return ModuleByName("chain")


class ModuleByName:
    """Delay module availability assertion to the behavior test, before source exists."""

    def __init__(self, name):
        self.name = f"tallylock.{name}"

    def __getattr__(self, name):
        assert importlib.util.find_spec(self.name) is not None, f"Task6a {self.name} module absent"
        return getattr(importlib.import_module(self.name), name)


def test_historical_header_fields_and_defensive_snapshots(chain_module):
    original = cache_for()
    view = chain_module.prepare(original)
    block = view.block(1)
    parsed = CBlockHeader.deserialize(HEADER)
    assert block.header == HEADER
    assert block.hash == b2lx(parsed.GetHash())
    assert block.height == 1 and block.confirmations == 6
    assert block.time == parsed.nTime and block.merkle_root == parsed.hashMerkleRoot
    summary = view.summary()
    assert summary == {"exported_at": original["exported_at"], "source": original["source"],
                       "tip": original["tip"], "trust": "external_explicit", "freshness": "cached_only"}
    original["tip"]["height"] = 1000
    original["blocks"]["1"]["header"] = "00" * 80
    summary["tip"]["height"] = 999
    assert view.block(1) == block and view.summary()["tip"]["height"] == 6
    assert view.block(2) is None
    with pytest.raises((FrozenInstanceError, AttributeError)):
        block.confirmations = 500


@pytest.mark.parametrize("change", [
    lambda v: v["blocks"]["1"].update(hash="00" * 32),
    lambda v: v["blocks"]["1"].update(header="00" * 79),
    lambda v: v["blocks"]["1"].update(header=HEADER.hex().upper()),
    lambda v: v["blocks"]["1"].update(confirmations=7),
    lambda v: v["blocks"]["1"].update(confirmations=True),
    lambda v: v["blocks"].update({"01": v["blocks"].pop("1")}),
    lambda v: v["blocks"].update({"7": v["blocks"].pop("1")}),
    lambda v: v["node"].update(blocks=7),
    lambda v: v["node"].update(headers=7),
    lambda v: v["node"].update(initialblockdownload=True),
    lambda v: v["node"].update(chain="test"),
    lambda v: v["tip"].update(height=True),
    lambda v: v.update(extra=True),
])
def test_invalid_cache_bindings_fail_two(chain_module, change):
    value = cache_for()
    change(value)
    with pytest.raises(TallyLockError) as error:
        chain_module.prepare(value)
    assert error.value.code == 2


def test_every_header_is_checked_and_tip_hash_is_bound(chain_module):
    value = cache_for({1: HEADER, 6: HEADER})
    value["tip"]["hash"] = value["blocks"]["6"]["hash"]
    chain_module.prepare(value)
    bad = deepcopy(value)
    bad["blocks"]["1"]["hash"] = "00" * 32
    with pytest.raises(TallyLockError):
        chain_module.prepare(bad)
    value["tip"]["hash"] = "00" * 32
    with pytest.raises(TallyLockError):
        chain_module.prepare(value)


def test_empty_cache_and_unknown_format(chain_module):
    assert chain_module.prepare(cache_for({})).block(1) is None
    value = cache_for()
    value["format"] = "prove.chain.v2"
    with pytest.raises(TallyLockError) as error:
        chain_module.prepare(value)
    assert error.value.code == 4


@pytest.mark.parametrize("height", [True, -1, 1.0, "1", None, 2**53])
def test_lookup_rejects_non_safe_height(chain_module, height):
    with pytest.raises(TallyLockError) as error:
        chain_module.prepare(cache_for()).block(height)
    assert error.value.code == 2


@pytest.mark.parametrize("value", [None, [], True, "cache"])
def test_malformed_cache_uses_typed_error(chain_module, value):
    with pytest.raises(TallyLockError) as error:
        chain_module.prepare(value)
    assert error.value.code == 2


def test_deep_untrusted_cache_is_rejected_before_recursive_copy(chain_module):
    value = cache_for()
    nested = value
    for _ in range(1200):
        nested["extra"] = {}
        nested = nested["extra"]
    with pytest.raises(TallyLockError) as error:
        chain_module.prepare(value)
    assert error.value.code == 2
