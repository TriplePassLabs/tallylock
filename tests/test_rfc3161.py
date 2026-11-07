"""RFC 3161 requests, replies and offline token checks against recorded and synthetic services."""
import hashlib
import importlib.util
import re
from pathlib import Path

import pytest
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from tallylock import _http
from tallylock.errors import TallyLockError


FIXTURES = Path(__file__).parent/"fixtures"/"tsa"
DIGEST = hashlib.sha256(b"TallyLock RFC 3161 fixture\n").digest()
NONCES = {"freetsa": 37777802110563428264632080986, "digicert": 37777802110563709739608810917}


def api():
    assert importlib.util.find_spec("tallylock.rfc3161") is not None, "RFC 3161 module missing"
    from tallylock import rfc3161
    return rfc3161


def recorded(name, suffix="tsr"):
    return (FIXTURES/f"{name}.{suffix}").read_bytes()


# A small independent DER writer for the synthetic test service.
def tlv(tag, body):
    if len(body) < 128:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def seq(*items):
    return tlv(0x30, b"".join(items))


def der_set(*items):
    return tlv(0x31, b"".join(items))


def integer(value):
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big", signed=False))


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def octets(data):
    return tlv(0x04, data)


SHA256_ALG = seq(oid("2.16.840.1.101.3.4.2.1"), b"\x05\x00")
ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
TSTINFO = "1.2.840.113549.1.9.16.1.4"


def name(common):
    return seq(der_set(seq(oid("2.5.4.3"), tlv(0x0c, common.encode()))))


def extension(dotted, value, critical=False):
    return seq(oid(dotted), b"\x01\x01\xff" if critical else b"", octets(value))


def sign(key, data):
    return DSS.new(key, "fips-186-3", encoding="der").sign(SHA256.new(data))


def certificate(serial, issuer, subject, valid, public, signer, extensions):
    tbs = seq(tlv(0xa0, integer(2)), integer(serial), ECDSA_SHA256, issuer,
              seq(tlv(0x17, valid[0].encode()), tlv(0x17, valid[1].encode())), subject,
              public.export_key(format="DER"), tlv(0xa3, seq(*extensions)))
    return seq(tbs, ECDSA_SHA256, tlv(0x03, b"\x00" + sign(signer, tbs)))


class Forge:
    """An explicitly synthetic test TSA: a P-256 root and a P-256 responder."""

    def __init__(self, *, signer_valid=("210101000000Z", "391231235959Z"), eku=True, label="Synthetic"):
        self.root_key, self.signer_key = ECC.generate(curve="P-256"), ECC.generate(curve="P-256")
        self.root_name, self.signer_name = name(f"{label} Test Root"), name(f"{label} Test TSA")
        self.root = certificate(1, self.root_name, self.root_name, ("200101000000Z", "491231235959Z"),
                                self.root_key.public_key(), self.root_key,
                                [extension("2.5.29.19", seq(b"\x01\x01\xff"), critical=True)])
        extensions = [extension("2.5.29.19", seq())]
        if eku:
            extensions.append(extension("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.8")), critical=True))
        self.signer = certificate(2, self.root_name, self.signer_name, signer_valid,
                                  self.signer_key.public_key(), self.root_key, extensions)
        self.serial = 100

    def reply(self, digest, *, nonce=None, gen_time="20261107120000Z", status=0, imprint=None,
              break_signature=False, wrong_message_digest=False, wrong_binding=False, certs=None):
        self.serial += 1
        tst = seq(integer(1), oid("1.3.6.1.4.1.99999.1"), seq(SHA256_ALG, octets(imprint or digest)),
                  integer(self.serial), tlv(0x18, gen_time.encode()),
                  integer(nonce) if nonce is not None else b"")
        content = hashlib.sha256(b"other" if wrong_message_digest else tst).digest()
        bound = hashlib.sha256(self.root if wrong_binding else self.signer).digest()
        attributes = [seq(oid("1.2.840.113549.1.9.3"), der_set(oid(TSTINFO))),
                      seq(oid("1.2.840.113549.1.9.4"), der_set(octets(content))),
                      seq(oid("1.2.840.113549.1.9.16.2.47"), der_set(seq(seq(seq(octets(bound))))))]
        signed = der_set(*attributes)
        signature = sign(self.signer_key, signed)
        if break_signature:
            signature = sign(self.signer_key, signed + b"x")
        signer_info = seq(integer(1), seq(self.root_name, integer(2)), SHA256_ALG, b"\xa0" + signed[1:],
                          ECDSA_SHA256, octets(signature))
        chain = (self.signer, self.root) if certs is None else certs
        signed_data = seq(integer(3), der_set(SHA256_ALG), seq(oid(TSTINFO), tlv(0xa0, octets(tst))),
                          tlv(0xa0, b"".join(chain)), der_set(signer_info))
        token = seq(oid("1.2.840.113549.1.7.2"), tlv(0xa0, signed_data))
        return seq(seq(integer(status)), token if status in (0, 1) else b"")


@pytest.fixture(scope="module")
def forge():
    return Forge()


def test_request_matches_bytes_real_services_accepted():
    rfc3161 = api()
    for service, nonce in NONCES.items():
        assert rfc3161.build_request(DIGEST, nonce) == recorded(service, "tsq")
    assert rfc3161.build_request(b"\x00" * 32, 1).hex() == (
        "303c0201013031300d060960864801650304020105000420" + "00" * 32 + "0201010101ff")
    for bad in (b"\x00" * 31, "00" * 32, None):
        with pytest.raises(TallyLockError):
            rfc3161.build_request(bad, 1)
    with pytest.raises(TallyLockError):
        rfc3161.build_request(DIGEST, 0)


@pytest.mark.parametrize("service, signer, root", [
    ("freetsa", "www.freetsa.org", "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"),
    ("digicert", "DigiCert SHA256 RSA4096 Timestamp Responder 2026 1",
     "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"),
])
def test_recorded_replies_verify_offline_against_bundled_roots(service, signer, root):
    rfc3161 = api()
    checked = rfc3161.verify(recorded(service), DIGEST, nonce=NONCES[service])
    assert checked["time"].startswith("2026-11-07T21:32:1") and checked["time"].endswith("Z")
    assert checked["tsa"] == signer
    assert checked["root_sha256"] == root
    assert checked["hash"] == "sha256"
    assert rfc3161.verify(recorded(service), DIGEST) == checked


def test_bundled_roots_match_their_recorded_digests():
    rfc3161 = api()
    readme = (Path(rfc3161.__file__).parent/"data"/"tsa"/"README.md").read_text()
    rows = re.findall(r"^\| ([a-z0-9.-]+\.(?:pem|crt)) \| (https://\S+) \| ([0-9a-f]{64}) \| ([0-9a-f]{64}) \|",
                      readme, re.M)
    assert len(rows) == 2
    for filename, url, file_sha, cert_sha in rows:
        data = (Path(rfc3161.__file__).parent/"data"/"tsa"/filename).read_bytes()
        assert hashlib.sha256(data).hexdigest() == file_sha
    roots = rfc3161.trusted_roots()
    assert sorted(hashlib.sha256(r).hexdigest() for r in roots) == sorted(row[3] for row in rows)


def test_wrong_imprint_and_wrong_nonce_are_named():
    rfc3161 = api()
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(recorded("digicert"), hashlib.sha256(b"other").digest())
    assert error.value.kind == "imprint"
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(recorded("freetsa"), DIGEST, nonce=NONCES["digicert"])
    assert error.value.kind == "nonce"


def flip(data, index):
    return data[:index] + bytes([data[index] ^ 1]) + data[index + 1:]


@pytest.mark.parametrize("service", ["freetsa", "digicert"])
def test_altered_real_replies_fail(service):
    rfc3161 = api()
    data = recorded(service)
    # The signer's signature is the final element of each recorded reply.
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(flip(data, len(data) - 1), DIGEST)
    assert error.value.kind == "signature"
    stamp = re.search(rb"\x18\x0f(20261107[0-9]{6}Z)", data).start(1)
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(flip(data, stamp + 13), DIGEST)
    assert error.value.kind == "digest"
    for broken in (data[:-1], data + b"\x00", b"", b"\x30\x80" + data[2:]):
        with pytest.raises(rfc3161.TSAError) as error:
            rfc3161.verify(broken, DIGEST)
        assert error.value.kind == "malformed"


def test_untrusted_chains_are_rejected():
    rfc3161 = api()
    freetsa_root = next(r for r in rfc3161.trusted_roots()
                        if hashlib.sha256(r).hexdigest().startswith("a6379e7c"))
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(recorded("digicert"), DIGEST, roots=[freetsa_root])
    assert error.value.kind == "untrusted"
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(recorded("freetsa"), DIGEST, roots=[])
    assert error.value.kind == "untrusted"


def test_synthetic_p256_service_verifies_only_with_its_own_root(forge):
    rfc3161 = api()
    data = forge.reply(DIGEST, nonce=7)
    checked = rfc3161.verify(data, DIGEST, nonce=7, roots=[forge.root])
    assert checked["tsa"] == "Synthetic Test TSA" and checked["time"] == "2026-11-07T12:00:00Z"
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(data, DIGEST)
    assert error.value.kind == "untrusted"
    other = Forge(label="Other")
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(data, DIGEST, roots=[other.root])
    assert error.value.kind == "untrusted"


@pytest.mark.parametrize("options, kind", [
    ({"break_signature": True}, "signature"),
    ({"wrong_message_digest": True}, "digest"),
    ({"wrong_binding": True}, "binding"),
    ({"imprint": b"\x11" * 32}, "imprint"),
    ({"status": 2}, "rejected"),
    ({"gen_time": "20450101000000Z"}, "expired"),
    ({"certs": ()}, "untrusted"),
])
def test_synthetic_failures_are_named(forge, options, kind):
    rfc3161 = api()
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(forge.reply(DIGEST, **options), DIGEST, roots=[forge.root])
    assert error.value.kind == kind


def test_expired_signer_and_missing_time_stamping_usage():
    rfc3161 = api()
    expired = Forge(signer_valid=("210101000000Z", "250101000000Z"))
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(expired.reply(DIGEST), DIGEST, roots=[expired.root])
    assert error.value.kind == "expired"
    assert rfc3161.verify(expired.reply(DIGEST, gen_time="20240601000000Z"), DIGEST, roots=[expired.root])
    unusable = Forge(eku=False)
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(unusable.reply(DIGEST), DIGEST, roots=[unusable.root])
    assert error.value.kind == "untrusted"


def test_request_uses_injected_post_and_checks_the_reply():
    rfc3161 = api()
    calls = []
    def post(url, body, **kwargs):
        calls.append((url, body))
        return recorded("digicert")
    data, checked = rfc3161.request("http://timestamp.digicert.com", DIGEST, post=post, nonce=NONCES["digicert"])
    assert data == recorded("digicert") and checked["tsa"].startswith("DigiCert")
    assert calls == [("http://timestamp.digicert.com", recorded("digicert", "tsq"))]
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.request("http://timestamp.digicert.com", DIGEST, post=post, nonce=12345)
    assert error.value.kind == "nonce"
    random_nonces = set()
    def capture(url, body, **kwargs):
        random_nonces.add(body)
        return recorded("digicert")
    for _ in range(2):
        with pytest.raises(rfc3161.TSAError):
            rfc3161.request("http://timestamp.digicert.com", DIGEST, post=capture)
    assert len(random_nonces) == 2


def fake_http(monkeypatch, responses):
    calls, sleeps = [], []
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
    monkeypatch.setattr(_http, "request", request)
    monkeypatch.setattr(api().time, "sleep", sleeps.append)
    return calls, sleeps


def test_default_post_headers_bounds_and_retry_after(monkeypatch):
    rfc3161 = api()
    calls, sleeps = fake_http(monkeypatch, [_http.Response(429, b"", "3"), _http.Response(200, recorded("freetsa"), None)])
    data, checked = rfc3161.request("https://freetsa.org/tsr", DIGEST, nonce=NONCES["freetsa"])
    assert checked["tsa"] == "www.freetsa.org" and len(calls) == 2
    method, url, options = calls[0]
    assert method == "POST" and url == "https://freetsa.org/tsr"
    assert options["body"] == recorded("freetsa", "tsq")
    assert options["headers"]["Content-Type"] == "application/timestamp-query"
    assert options["response_limit"] == rfc3161.TOKEN_LIMIT
    assert 3 <= sleeps[0] <= 4
    calls, sleeps = fake_http(monkeypatch, [_http.NetworkError(), _http.Response(503, b"", None), _http.Response(500, b"", None)])
    with pytest.raises(TallyLockError) as error:
        rfc3161.request("https://freetsa.org/tsr", DIGEST)
    assert error.value.code == 5 and len(calls) == 3 and sleeps == [1, 2]
    calls, _ = fake_http(monkeypatch, [_http.Response(400, b"", None)])
    with pytest.raises(TallyLockError) as error:
        rfc3161.request("https://freetsa.org/tsr", DIGEST)
    assert error.value.code == 5 and len(calls) == 1
    calls, _ = fake_http(monkeypatch, [_http.Response(429, b"", "86400")])
    with pytest.raises(TallyLockError) as error:
        rfc3161.request("https://freetsa.org/tsr", DIGEST)
    assert error.value.code == 5 and len(calls) == 1


def test_oversized_and_rejected_replies():
    rfc3161 = api()
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(b"\x30\x84" + (rfc3161.TOKEN_LIMIT).to_bytes(4, "big") + b"\x00" * rfc3161.TOKEN_LIMIT, DIGEST)
    assert error.value.kind == "malformed"
    refused = seq(seq(integer(2), seq(tlv(0x0c, b"bad request"))))
    with pytest.raises(rfc3161.TSAError) as error:
        rfc3161.verify(refused, DIGEST)
    assert error.value.kind == "rejected"
