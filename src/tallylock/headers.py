"""Bitcoin headers from two public providers, checked locally for work and links."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
import re
import time
from types import MappingProxyType

from bitcoin.core import CBlockHeader, b2lx

from . import anchors, canonical
from .canonical import MAX_SAFE_INTEGER
from .chain import CachedBlock, ChainView
from .errors import TallyLockError


EVIDENCE_FORMAT = "tallylock.provider-evidence.v1"
PROVIDERS = ("https://blockstream.info/api", "https://mempool.space/api")
BLOCKS_ON_TOP = 100
MAX_BLOCKS_ON_TOP = 2016
MAX_HEIGHTS = 16
DEADLINE_SECONDS = 120
STALE_SECONDS = 15 * 60
MAX_REPLY_BYTES = 256
# Bitcoin mainnet consensus powLimit; no header target may be easier than this.
POW_LIMIT = (1 << 224) - 1
PERIOD = 2016
MAX_PERIODS_PAST_TABLE = 26
# Saved evidence is only as good as its work: below this height one header costs too little to mine.
SAVED_FLOOR_HEIGHT = 840000
DIFFICULTY_FORMAT = "tallylock.difficulty-table.v1"
CONSENSUS = "full consensus not validated"
_KEYS = {"format", "observed_at", "providers", "heights", "blocks_on_top", "tips", "segments", "answers",
         "checks", "consensus"}
_CHECKS = ("proof_of_work", "links", "providers_agreed", "tips_within_one_block")
_HEIGHT = rb"0|[1-9][0-9]{0,15}"
_HASH = rb"[0-9a-f]{64}"
_HEADER = rb"[0-9a-f]{160}"
_PROVIDER = re.compile(r"https://[a-z0-9.-]{1,253}(/[a-z0-9._-]{1,64}){0,8}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def _require(condition, message, code=2):
    if not condition:
        raise TallyLockError(message, code=code)


def _table() -> tuple[int, ...]:
    value = canonical.loads(resources.files("tallylock").joinpath("data/difficulty.json").read_bytes())
    bits = value["bits"] if isinstance(value, dict) and value.get("format") == DIFFICULTY_FORMAT else None
    _require(isinstance(bits, list) and bits and all(type(b) is int and 0 < b < 1 << 32 for b in bits),
             "bundled difficulty table is invalid", 4)
    return tuple(bits)


# nBits of the first block of every completed retarget period, from genesis.
DIFFICULTY = _table()


@dataclass(frozen=True)
class Checked:
    view: ChainView
    summary: dict


def compact_target(bits: int) -> int:
    """Expand a header's compact nBits into its full proof-of-work target."""
    size, word = bits >> 24, bits & 0x007FFFFF
    if bits & 0x00800000 and word:
        return 0
    return word >> 8 * (3 - size) if size <= 3 else word << 8 * (size - 3)


def _difficulty(height: int, bits: int, known: dict) -> None:
    period, last = height // PERIOD, len(DIFFICULTY) - 1
    if period <= last:
        _require(bits == DIFFICULTY[period], f"header at height {height} does not use the known difficulty for its period")
        return
    _require(period - last <= MAX_PERIODS_PAST_TABLE, "difficulty table too old, update TallyLock", 4)
    if period in known:
        _require(bits == known[period], f"header at height {height} changes difficulty inside a retarget period")
        return
    base = max([p for p in known if p < period], default=last)
    steps, old, new = period - base, compact_target(known.get(base, DIFFICULTY[last])), compact_target(bits)
    # Compact encoding truncates each retarget slightly below old/4, so allow that rounding.
    _require(new <= old * 4 ** steps and new * 4 ** steps * 2 ** 15 >= old * (2 ** 15 - steps),
             f"header at height {height} changes difficulty by more than the consensus limit")
    # Past the table, work may not fall below a quarter of the last known period, or headers become cheap to mine.
    _require(new <= compact_target(DIFFICULTY[last]) * 4,
             f"header at height {height} is too easy compared with the known difficulty")
    known[period] = bits


def _fetch(url, *, deadline):
    from . import _http
    return _http.request("GET", url, body=None, headers={"Accept": "text/plain", "User-Agent": "tallylock"},
                         response_limit=MAX_REPLY_BYTES, deadline=deadline)


class _Client:
    def __init__(self, fetch, sleep, clock):
        self.fetch, self.sleep, self.clock = fetch, sleep, clock
        self.deadline = clock() + DEADLINE_SECONDS

    def get(self, provider, path, pattern) -> str:
        from .transport import _retry_at
        from . import _http
        for attempt in range(3):
            _require(self.clock() < self.deadline, "provider requests passed the 120 second limit", 5)
            try:
                response = self.fetch(provider + path, deadline=self.deadline)
            except _http.NetworkError:
                response = None
            except TallyLockError:
                raise TallyLockError(f"{provider} sent a reply that could not be read", code=5) from None
            if response is not None:
                if response.status == 200:
                    _require(len(response.body) <= MAX_REPLY_BYTES, f"{provider} sent a reply that is too large", 5)
                    body = response.body.strip()
                    _require(re.fullmatch(pattern, body) is not None, f"{provider} sent a malformed reply", 5)
                    return body.decode("ascii")
                _require(response.status in {403, 429} or 500 <= response.status <= 599,
                         f"{provider} returned HTTP {response.status}", 5)
            _require(attempt < 2, f"{provider} is still failing after 3 attempts", 5)
            delay = 2 ** attempt
            due = None if response is None else _retry_at(response.retry_after)
            if due is not None:
                delay = max(delay, due - time.time())
            _require(self.clock() + delay < self.deadline, f"{provider} asked to wait past the 120 second limit", 5)
            self.sleep(delay)


def _heights(values) -> list[int]:
    _require(isinstance(values, (list, tuple)) and all(type(h) is int and 0 <= h <= MAX_SAFE_INTEGER for h in values),
             "attested heights must be nonnegative safe integers")
    heights = sorted(set(values))
    _require(len(heights) <= MAX_HEIGHTS, f"at most {MAX_HEIGHTS} attested heights can be checked")
    return heights


def _options(providers, blocks_on_top):
    _require(isinstance(providers, (list, tuple)) and len(providers) >= 2 and len(set(providers)) == len(providers)
             and all(isinstance(p, str) and _PROVIDER.fullmatch(p) for p in providers),
             "at least two distinct https provider URLs are required")
    _require(type(blocks_on_top) is int and 0 <= blocks_on_top <= MAX_BLOCKS_ON_TOP,
             f"blocks on top must be an integer from 0 to {MAX_BLOCKS_ON_TOP}")


def _ranges(heights, blocks_on_top, tip):
    ranges = []
    for height in heights:
        if height > tip:
            continue
        top = min(height + blocks_on_top, tip)
        if ranges and height <= ranges[-1][1] + 1:
            ranges[-1][1] = max(ranges[-1][1], top)
        else:
            ranges.append([height, top])
    return ranges


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value) -> int:
    _require(isinstance(value, str) and _TIME.fullmatch(value), "observed_at must be a UTC time like 2026-01-01T00:00:00Z")
    try:
        return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        raise TallyLockError("observed_at must be a UTC time like 2026-01-01T00:00:00Z") from None


def observe(heights, *, providers=PROVIDERS, blocks_on_top: int = BLOCKS_ON_TOP, fetch=None,
            sleep=time.sleep, clock=time.monotonic, now=time.time) -> dict:
    """Fetch each attested header plus blocks on top, serially, then check them locally."""
    heights = _heights(heights)
    _options(providers, blocks_on_top)
    client = _Client(_fetch if fetch is None else fetch, sleep, clock)
    observed_at = _timestamp(now())
    tips = []
    for provider in providers:
        height = int(client.get(provider, "/blocks/tip/height", _HEIGHT))
        tips.append({"provider": provider, "height": height, "hash": client.get(provider, "/blocks/tip/hash", _HASH)})
    ranges = _ranges(heights, blocks_on_top, min(tip["height"] for tip in tips))
    answers = {provider: {} for provider in providers}
    for provider in providers:
        for start, top in ranges:
            for height in (start, top):
                answers[provider][str(height)] = client.get(provider, f"/block-height/{height}", _HASH)
    segments = []
    primary = providers[0]
    for start, top in ranges:
        # Walk down from the top: each header names the next one to request.
        name, headers = answers[primary][str(top)], []
        for _ in range(top - start + 1):
            raw = bytes.fromhex(client.get(primary, f"/block/{name}/header", _HEADER))
            parsed = CBlockHeader.deserialize(raw)
            _require(b2lx(parsed.GetHash()) == name, f"{primary} returned a header that does not match the requested block")
            headers.append(raw.hex())
            name = b2lx(parsed.hashPrevBlock)
        segments.append({"start": start, "headers": headers[::-1]})
    evidence = {"format": EVIDENCE_FORMAT, "observed_at": observed_at, "providers": list(providers),
                "heights": heights, "blocks_on_top": blocks_on_top, "tips": tips, "segments": segments,
                "answers": answers, "checks": dict.fromkeys(_CHECKS, True), "consensus": CONSENSUS}
    check(evidence)
    return evidence


def _shape(value):
    _require(isinstance(value, dict) and set(value) == _KEYS, "provider evidence has unknown or missing fields")
    _require(value["format"] == EVIDENCE_FORMAT, "unsupported provider evidence format", 4)
    _require(value["consensus"] == CONSENSUS, "provider evidence must state that full consensus is not validated")
    _epoch(value["observed_at"])
    _options(value["providers"], value["blocks_on_top"])
    _heights(value["heights"])
    _require(value["heights"] == sorted(set(value["heights"])), "provider evidence heights must be sorted and unique")
    _require(isinstance(value["checks"], dict) and value["checks"] == dict.fromkeys(_CHECKS, True),
             "provider evidence does not record every check as passed")
    tips = value["tips"]
    _require(isinstance(tips, list) and len(tips) == len(value["providers"]), "provider evidence needs one tip per provider")
    for tip, provider in zip(tips, value["providers"]):
        _require(isinstance(tip, dict) and set(tip) == {"provider", "height", "hash"} and tip["provider"] == provider
                 and type(tip["height"]) is int and 0 <= tip["height"] <= MAX_SAFE_INTEGER
                 and isinstance(tip["hash"], str) and re.fullmatch(_HASH.decode(), tip["hash"]),
                 "provider evidence has an invalid tip observation")
    segments = value["segments"]
    _require(isinstance(segments, list) and all(
        isinstance(s, dict) and set(s) == {"start", "headers"} and isinstance(s["headers"], list)
        and all(isinstance(h, str) and re.fullmatch(_HEADER.decode(), h) for h in s["headers"]) for s in segments),
        "provider evidence has an invalid header segment")
    answers = value["answers"]
    _require(isinstance(answers, dict) and set(answers) == set(value["providers"]) and all(
        isinstance(table, dict) and all(isinstance(h, str) and re.fullmatch(_HASH.decode(), h) for h in table.values())
        for table in answers.values()), "provider evidence has invalid provider answers")


def check(evidence: dict, *, saved: bool = False) -> Checked:
    """Re-check evidence offline: work, links and agreement; saved evidence counts only its own recent headers."""
    value = canonical.loads(canonical.dumps(evidence))
    _shape(value)
    if saved:
        _require(all(h >= SAVED_FLOOR_HEIGHT for h in value["heights"]),
                 f"saved evidence cannot vouch for blocks below height {SAVED_FLOOR_HEIGHT}; re-check online", 3)
    tip = min(t["height"] for t in value["tips"])
    ranges = _ranges(value["heights"], value["blocks_on_top"], tip)
    _require([[s["start"], s["start"] + len(s["headers"]) - 1] for s in value["segments"]] == ranges,
             "provider evidence segments do not match its heights, blocks on top and tip")
    blocks, known = {}, {}
    for segment in value["segments"]:
        previous = None
        top = segment["start"] + len(segment["headers"]) - 1 if saved else tip
        for offset, text in enumerate(segment["headers"]):
            height = segment["start"] + offset
            raw = bytes.fromhex(text)
            parsed = CBlockHeader.deserialize(raw)
            digest = parsed.GetHash()
            _difficulty(height, parsed.nBits, known)
            target = compact_target(parsed.nBits)
            _require(0 < target <= POW_LIMIT and int.from_bytes(digest, "little") <= target,
                     f"header at height {height} does not meet its proof-of-work target")
            _require(previous is None or parsed.hashPrevBlock == previous,
                     f"header at height {height} does not link to the previous header")
            previous = digest
            blocks[height] = CachedBlock(height, b2lx(digest), raw, top - height + 1, parsed.nTime, parsed.hashMerkleRoot)
    expected = {str(h) for pair in ranges for h in pair}
    for provider, table in value["answers"].items():
        _require(set(table) == expected, f"provider evidence lacks answers from {provider}")
        for height, name in sorted(table.items(), key=lambda item: int(item[0])):
            _require(blocks[int(height)].hash == name, f"providers disagree on the block at height {height}", 3)
    heights = [t["height"] for t in value["tips"]]
    _require(max(heights) - min(heights) <= 1, "provider tips differ by more than one block", 3)
    low = next(t for t in value["tips"] if t["height"] == tip)
    view = ChainView(MappingProxyType(blocks), value["observed_at"], ", ".join(value["providers"]), tip, low["hash"])
    summary = {"state": "checked", "providers": value["providers"], "observed_at": value["observed_at"],
               "tip": {"height": tip, "hash": low["hash"]}, "tip_heights": heights,
               "headers_checked": len(blocks), "proof_of_work": "checked", "links": "checked",
               "blocks_on_top": {str(h): min(h + value["blocks_on_top"], tip) - h for h in value["heights"] if h <= tip},
               "providers_agreed": True, "consensus": CONSENSUS}
    return Checked(view, summary)


def freshness(observed_at: str, confirmations: int | None, minimum_confirmations: int, *, offline: bool,
              now: float | None = None) -> dict:
    """Below the threshold an old observation is stale; at or above it, only its age is reported."""
    age = max(0, int((time.time() if now is None else now) - _epoch(observed_at)))
    if (confirmations is None or confirmations < minimum_confirmations) and age > STALE_SECONDS:
        state, label = "stale", "stale, re-check"
    elif offline:
        state, label = "as_observed", f"as observed at {observed_at}"
    else:
        state, label = "current", f"observed at {observed_at}"
    return {"state": state, "label": label, "observed_at": observed_at, "age_seconds": age}


def verify_proof(data: bytes | None, expected_sha256: str, *, evidence: dict | None = None,
                 minimum_confirmations: int = 6, now=time.time, **options) -> dict:
    """Check one detached proof against provider headers; saved evidence never fetches."""
    offline = evidence is not None
    if not offline:
        heights = [] if data is None else anchors.inspect(data, expected_sha256)["bitcoin_heights"]
        if heights:
            evidence = observe(heights, now=now, **options)
    checked = None if evidence is None else check(evidence, saved=offline)
    anchor = anchors.verify(data, expected_sha256, None if checked is None else checked.view,
                            minimum_confirmations=minimum_confirmations)
    fresh = None if checked is None else freshness(
        checked.summary["observed_at"], anchor["confirmations"], minimum_confirmations, offline=offline, now=now())
    return {"anchor": anchor, "providers": None if checked is None else checked.summary,
            "freshness": fresh, "evidence": evidence}
