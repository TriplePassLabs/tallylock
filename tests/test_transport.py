"""Calendar authority, bounded upstream parsing and scheduling."""
import importlib.util
import time

import pytest
from opentimestamps.core.notary import PendingAttestation, UnknownAttestation, LitecoinBlockHeaderAttestation
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

from tallylock.errors import TallyLockError

ORIGIN = "https://a.pool.opentimestamps.org"
COMMITMENT = b"a" * 32


def api():
    assert importlib.util.find_spec("tallylock.transport") is not None, "calendar transport missing"
    from tallylock import transport
    return transport


def reply(commitment=COMMITMENT, origin=ORIGIN):
    stamp = Timestamp(commitment)
    stamp.attestations.add(PendingAttestation(origin))
    ctx = BytesSerializationContext()
    stamp.serialize(ctx)
    return ctx.getbytes()


def attested_reply(commitment, *attestations):
    stamp = Timestamp(commitment)
    stamp.attestations.update(attestations)
    ctx = BytesSerializationContext()
    stamp.serialize(ctx)
    return ctx.getbytes()


@pytest.mark.parametrize("origin", ["http://a.pool.opentimestamps.org", ORIGIN+":444", ORIGIN+"/digest",
    ORIGIN+"?x", ORIGIN+"#", "https://user@a.pool.opentimestamps.org", "https://a.pool.opentimestamps.org.evil",
    "https://%61.pool.opentimestamps.org", ORIGIN+"\n", "https://x.calendar.opentimestamps.org"])
def test_submission_rejects_untrusted_origins_without_io(origin, monkeypatch):
    client = api()
    monkeypatch.setattr(client._http, "request", lambda *a, **k: pytest.fail("unexpected request"))
    with pytest.raises(TallyLockError) as error:
        client.submit(origin, COMMITMENT)
    assert error.value.code == 2


def test_constructed_requests_retry_limit_and_pending(monkeypatch):
    client = api()
    calls = []
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return client._http.Response(503 if len(calls) < 3 else 200, reply(), None)
    monkeypatch.setattr(client._http, "request", request)
    monkeypatch.setattr(client.time, "sleep", lambda _: None)
    deadline = time.monotonic()+10
    assert client.submit(ORIGIN, COMMITMENT, deadline=deadline) == reply()
    assert len(calls) == 3
    assert all(c[1] == ORIGIN+"/digest" and c[2]["deadline"] == deadline for c in calls)
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(404, b"", None))
    assert client.upgrade("https://x.calendar.opentimestamps.org", COMMITMENT) is None


def test_retry_after_defers_and_bad_response_is_operational(monkeypatch):
    client = api()
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(429, b"secret", "600"))
    with pytest.raises(client.RetryDeferred) as error:
        client.submit(ORIGIN, COMMITMENT)
    assert error.value.next_retry_at >= int(time.time())+599
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(200, b"bad", None))
    with pytest.raises(TallyLockError) as error:
        client.submit(ORIGIN, COMMITMENT)
    assert error.value.code == 5


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 400])
def test_redirects_auth_and_other_client_errors_never_retry(monkeypatch, status):
    client = api()
    calls = []
    def request(*args, **kwargs):
        calls.append(args)
        return client._http.Response(status, b"credential-like body", None)
    monkeypatch.setattr(client._http, "request", request)
    with pytest.raises(TallyLockError) as error:
        client.submit(ORIGIN, COMMITMENT)
    assert error.value.code == 5 and len(calls) == 1
    assert "credential-like" not in str(error.value)


@pytest.mark.parametrize("failure", [403, 429, 500, 599, "network"])
def test_transient_failures_get_exactly_three_attempts_and_one_two_backoff(monkeypatch, failure):
    client = api()
    calls, sleeps = [], []
    def request(*args, **kwargs):
        calls.append(args)
        if failure == "network":
            raise client._http.NetworkError()
        return client._http.Response(failure, b"private", None)
    monkeypatch.setattr(client._http, "request", request)
    monkeypatch.setattr(client.time, "sleep", sleeps.append)
    with pytest.raises(TallyLockError) as error:
        client.submit(ORIGIN, COMMITMENT)
    assert error.value.code == 5 and len(calls) == 3 and sleeps == [1, 2]


def test_retry_budget_exhaustion_never_sleeps_past_shared_deadline(monkeypatch):
    client = api()
    calls = []
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(503, b"", None))
    monkeypatch.setattr(client.time, "sleep", lambda _: pytest.fail("budget exceeded"))
    with pytest.raises(TallyLockError) as error:
        client.submit(ORIGIN, COMMITMENT, deadline=time.monotonic()+.2)
    assert error.value.code == 5


def test_retry_after_http_date_and_origin_normalization(monkeypatch):
    client = api()
    from email.utils import formatdate
    now = int(time.time())
    date = formatdate(now+400, usegmt=True)
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(503, b"", date))
    with pytest.raises(client.RetryDeferred) as error:
        client.submit("HTTPS://A.POOL.OPENTIMESTAMPS.ORG:443/", COMMITMENT)
    assert error.value.next_retry_at == now+400


@pytest.mark.parametrize("origin", ["https://calendar.opentimestamps.org", "https://evilcalendar.opentimestamps.org",
    "https://x.calendar.opentimestamps.org:444", "https://x.calendar.opentimestamps.org./",
    "https://x..calendar.opentimestamps.org", "https://-x.calendar.opentimestamps.org",
    "https://x.calendar.opentimestamps.org/%2f", "https://x.calendar.opentimestamps.org?",
    "https://x.calendar.opentimestamps.org\\@127.0.0.1"])
def test_upgrade_authority_attacks(origin, monkeypatch):
    client = api()
    monkeypatch.setattr(client._http, "request", lambda *a, **k: pytest.fail("unexpected request"))
    with pytest.raises(TallyLockError) as error:
        client.upgrade(origin, COMMITMENT)
    assert error.value.code == 2


@pytest.mark.parametrize("attestation", [UnknownAttestation(b"unknown!", b"opaque"), LitecoinBlockHeaderAttestation(1)])
def test_unsupported_only_calendar_reply_is_operational(monkeypatch, attestation):
    client = api()
    data = attested_reply(COMMITMENT, attestation)
    monkeypatch.setattr(client._http, "request", lambda *a, **k: client._http.Response(200, data, None))
    with pytest.raises(TallyLockError) as error:
        client.submit(ORIGIN, COMMITMENT)
    assert error.value.code == 5
