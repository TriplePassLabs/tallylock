"""RFC 3161 instant timestamps: hand-built DER requests and offline token checks."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from importlib.resources import files
import re
import secrets
import time

from Cryptodome.Hash import SHA256, SHA384, SHA512
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, pkcs1_15

from . import _http, transport
from .errors import TallyLockError


DEFAULT_TSAS = ("https://freetsa.org/tsr", "http://timestamp.digicert.com")
TOKEN_LIMIT = 128 * 1024
_SHA256 = "2.16.840.1.101.3.4.2.1"
_HASHES = {_SHA256: ("sha256", SHA256), "2.16.840.1.101.3.4.2.2": ("sha384", SHA384),
           "2.16.840.1.101.3.4.2.3": ("sha512", SHA512)}
_RSA = {"1.2.840.113549.1.1.11": SHA256, "1.2.840.113549.1.1.12": SHA384, "1.2.840.113549.1.1.13": SHA512}
_ECDSA = {"1.2.840.10045.4.3.2": SHA256, "1.2.840.10045.4.3.3": SHA384, "1.2.840.10045.4.3.4": SHA512}
_RSA_KEY = "1.2.840.113549.1.1.1"
_SIGNED_DATA = "1.2.840.113549.1.7.2"
_TSTINFO = "1.2.840.113549.1.9.16.1.4"
_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
_BASIC, _KEY_USAGE, _EXTENDED, _SUBJECT_KEY = "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.14"
_HANDLED = {_BASIC, _KEY_USAGE, _EXTENDED}
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----")
_MAX_CHAIN = 8


class TSAError(TallyLockError):
    """A timestamp reply or token failure; kind names what was wrong."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message, code=2)
        self.kind = kind


def _fail(kind, message):
    raise TSAError(kind, message)


def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 128:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _integer(value: int) -> bytes:
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def build_request(digest: bytes, nonce: int) -> bytes:
    """DER TimeStampReq: v1, SHA-256 imprint, nonce, and a request for the signer certificate."""
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise TallyLockError("the timestamp digest must be 32 SHA-256 bytes")
    if type(nonce) is not int or not 0 < nonce < 1 << 160:
        raise TallyLockError("the timestamp nonce must be a positive integer below 2^160")
    algorithm = _tlv(0x30, bytes.fromhex("0609608648016503040201") + b"\x05\x00")
    imprint = _tlv(0x30, algorithm + _tlv(0x04, digest))
    return _tlv(0x30, _integer(1) + imprint + _integer(nonce) + b"\x01\x01\xff")


def _read(data: bytes, offset: int = 0) -> tuple[int, bytes, bytes, int]:
    """Read one strict DER element: tag, content, the whole element and the next offset."""
    if offset + 2 > len(data):
        _fail("malformed", "the timestamp data ends early")
    tag, first = data[offset], data[offset + 1]
    if tag & 0x1f == 0x1f:
        _fail("malformed", "the timestamp data uses an unsupported tag")
    start = offset + 2
    if first < 0x80:
        size = first
    else:
        count = first & 0x7f
        if not 1 <= count <= 4 or start + count > len(data) or data[start] == 0:
            _fail("malformed", "the timestamp data has an invalid length")
        size = int.from_bytes(data[start:start + count], "big")
        start += count
        if size < 128 or size < 1 << (8 * (count - 1)):
            _fail("malformed", "the timestamp data has a non-minimal length")
    end = start + size
    if end > len(data):
        _fail("malformed", "the timestamp data ends early")
    return tag, data[start:end], data[offset:end], end


def _one(data: bytes, tag: int) -> bytes:
    found, content, _, end = _read(data)
    if found != tag or end != len(data):
        _fail("malformed", "the timestamp data has an unexpected structure")
    return content


def _items(content: bytes) -> list[tuple[int, bytes, bytes]]:
    items, offset = [], 0
    while offset < len(content):
        tag, body, whole, offset = _read(content, offset)
        items.append((tag, body, whole))
    return items


def _expect(item, tag):
    if item[0] != tag:
        _fail("malformed", "the timestamp data has an unexpected structure")
    return item[1]


def _int(content: bytes) -> int:
    if not content or len(content) > 1 and (content[0] == 0 and content[1] < 0x80 or content[0] == 0xff and content[1] >= 0x80):
        _fail("malformed", "the timestamp data has an invalid integer")
    return int.from_bytes(content, "big", signed=True)


def _oid(content: bytes) -> str:
    if not content or content[-1] & 0x80:
        _fail("malformed", "the timestamp data has an invalid identifier")
    parts, value = [], 0
    for byte in content:
        if value == 0 and byte == 0x80:
            _fail("malformed", "the timestamp data has an invalid identifier")
        value = value << 7 | byte & 0x7f
        if not byte & 0x80:
            parts.append(value)
            value = 0
    first = min(parts[0] // 40, 2)
    return ".".join(str(p) for p in [first, parts[0] - 40 * first, *parts[1:]])


def _algorithm(content: bytes) -> str:
    items = _items(content)
    if not items or len(items) > 2 or len(items) == 2 and items[1][2] != b"\x05\x00":
        _fail("unsupported", "the timestamp uses unsupported algorithm parameters")
    return _oid(_expect(items[0], 0x06))


def _time(tag: int, content: bytes) -> datetime:
    try:
        text = content.decode("ascii")
        if tag == 0x17 and re.fullmatch(r"[0-9]{12}Z", text):
            year = int(text[:2])
            text = ("19" if year >= 50 else "20") + text
        elif tag != 0x18 or not re.fullmatch(r"[0-9]{14}(\.[0-9]{1,6})?Z", text):
            raise ValueError(text)
        moment = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        fraction = text[15:-1]
        return moment.replace(microsecond=int(fraction.ljust(6, "0"))) if fraction else moment
    except (UnicodeDecodeError, ValueError):
        _fail("malformed", "the timestamp data has an invalid time")


class _Certificate:
    def __init__(self, whole: bytes) -> None:
        tbs, algorithm, signature = _items(_one(whole, 0x30))
        _expect(tbs, 0x30)
        self.raw, self.tbs = whole, tbs[2]
        self.algorithm = _expect(algorithm, 0x30)
        bits = _expect(signature, 0x03)
        if not bits or bits[0] != 0:
            _fail("malformed", "a certificate signature is not whole bytes")
        self.signature = bits[1:]
        fields = _items(tbs[1])
        if fields and fields[0][0] == 0xa0:
            fields = fields[1:]
        if len(fields) < 6:
            _fail("malformed", "a certificate is incomplete")
        self.serial = _int(_expect(fields[0], 0x02))
        self.issuer, self.subject, self.public = fields[2][2], fields[4][2], fields[5][2]
        validity = _items(_expect(fields[3], 0x30))
        if len(validity) != 2:
            _fail("malformed", "a certificate validity is invalid")
        self.not_before, self.not_after = (_time(tag, body) for tag, body, _ in validity)
        self.extensions = {}
        for tag, body, _ in fields[6:]:
            if tag != 0xa3:
                continue
            for item in _items(_one(body, 0x30)):
                parts = _items(_expect(item, 0x30))
                critical = len(parts) == 3 and _expect(parts[1], 0x01) == b"\xff"
                name = _oid(_expect(parts[0], 0x06))
                if name in self.extensions:
                    _fail("malformed", "a certificate repeats an extension")
                self.extensions[name] = (critical, _expect(parts[-1], 0x04))

    def name(self) -> str:
        found = ""
        for rdn in _items(_one(self.subject, 0x30)):
            for attribute in _items(_expect(rdn, 0x31)):
                kind, value = _items(_expect(attribute, 0x30))
                if _oid(_expect(kind, 0x06)) == "2.5.4.3":
                    found = value[1].decode("utf-8", "replace")
        return found

    def is_ca(self) -> bool:
        if _BASIC not in self.extensions:
            return False
        parts = _items(_one(self.extensions[_BASIC][1], 0x30))
        if not parts or parts[0][0] != 0x01 or parts[0][1] != b"\xff":
            return False
        if _KEY_USAGE in self.extensions:
            bits = _one(self.extensions[_KEY_USAGE][1], 0x03)
            return len(bits) > 1 and bool(bits[1] & 0x04)
        return True

    def can_stamp(self) -> bool:
        if _EXTENDED not in self.extensions:
            return False
        critical, value = self.extensions[_EXTENDED]
        usages = {_oid(_expect(item, 0x06)) for item in _items(_one(value, 0x30))}
        return critical and _TIME_STAMPING in usages

    def unknown_critical(self) -> bool:
        return any(critical and name not in _HANDLED for name, (critical, _) in self.extensions.items())


def _check_signature(public: bytes, algorithm: str, message: bytes, signature: bytes, digest=None) -> bool:
    if algorithm == _RSA_KEY and digest is not None:
        hasher, family = digest, "rsa"
    elif algorithm in _RSA:
        hasher, family = _RSA[algorithm], "rsa"
    elif algorithm in _ECDSA:
        hasher, family = _ECDSA[algorithm], "ecdsa"
    else:
        _fail("unsupported", "the timestamp uses an unsupported signature algorithm")
    try:
        if family == "rsa":
            key = RSA.import_key(public)
            if key.size_in_bits() < 2048:
                _fail("unsupported", "the timestamp uses an RSA key shorter than 2048 bits")
            pkcs1_15.new(key).verify(hasher.new(message), signature)
        else:
            key = ECC.import_key(public)
            if key.curve not in {"NIST P-256", "NIST P-384"}:
                _fail("unsupported", "the timestamp uses an unsupported elliptic curve")
            DSS.new(key, "fips-186-3", encoding="der").verify(hasher.new(message), signature)
    except (ValueError, TypeError, IndexError):
        return False
    return True


def _signed_by(child: _Certificate, issuer: _Certificate) -> bool:
    return child.issuer == issuer.subject and _check_signature(
        issuer.public, _algorithm(child.algorithm), child.tbs, child.signature)


def _within(certificate: _Certificate, moment: datetime) -> None:
    if not certificate.not_before <= moment <= certificate.not_after:
        _fail("expired", "a certificate in the timestamp chain was not valid at the stamped time")


def _chain(signer: _Certificate, pool: list[_Certificate], anchors: list[_Certificate], moment: datetime):
    if not signer.can_stamp():
        _fail("untrusted", "the signing certificate is not allowed to make timestamps")
    current, seen = signer, {signer.raw}
    for _ in range(_MAX_CHAIN):
        if current.unknown_critical():
            _fail("untrusted", "a certificate in the timestamp chain has an unknown critical extension")
        _within(current, moment)
        for anchor in anchors:
            if _signed_by(current, anchor):
                _within(anchor, moment)
                return anchor
        step = next((c for c in pool if c.raw not in seen and c.is_ca() and _signed_by(current, c)), None)
        if step is None:
            _fail("untrusted", "the timestamp does not chain to a trusted root")
        current = step
        seen.add(current.raw)
    _fail("untrusted", "the timestamp chain is too long")


def trusted_roots() -> tuple[bytes, ...]:
    """DER certificates bundled in tallylock/data/tsa, in file-name order."""
    roots = []
    folder = files("tallylock").joinpath("data/tsa")
    for entry in sorted(folder.iterdir(), key=lambda item: item.name):
        if entry.name.endswith(".pem"):
            roots.extend(base64.b64decode(block) for block in _PEM.findall(entry.read_bytes()))
        elif entry.name.endswith(".crt"):
            roots.append(entry.read_bytes())
    return tuple(roots)


def _attributes(content: bytes) -> dict[str, list[tuple[int, bytes, bytes]]]:
    found = {}
    for item in _items(content):
        kind, values = _items(_expect(item, 0x30))
        name = _oid(_expect(kind, 0x06))
        if name in found:
            _fail("malformed", "the timestamp repeats a signed attribute")
        found[name] = _items(_expect(values, 0x31))
    return found


def _bound(attributes, signer: _Certificate) -> None:
    if _SIGNING_CERT_V2 in attributes:
        certs = _items(_expect(attributes[_SIGNING_CERT_V2][0], 0x30))
        parts = _items(_expect(_items(_expect(certs[0], 0x30))[0], 0x30))
        hasher = hashlib.sha256
        if parts[0][0] == 0x30:
            name = _algorithm(parts[0][1])
            if name not in _HASHES:
                _fail("unsupported", "the timestamp binds its certificate with an unsupported hash")
            hasher = getattr(hashlib, _HASHES[name][0])
            parts = parts[1:]
    elif _SIGNING_CERT in attributes:
        certs = _items(_expect(attributes[_SIGNING_CERT][0], 0x30))
        parts = _items(_expect(_items(_expect(certs[0], 0x30))[0], 0x30))
        hasher = hashlib.sha1
    else:
        _fail("binding", "the timestamp does not name its signing certificate")
    if _expect(parts[0], 0x04) != hasher(signer.raw).digest():
        _fail("binding", "the timestamp names a different signing certificate")


def verify(data: bytes, digest: bytes, *, nonce: int | None = None, roots=None) -> dict:
    """Check one TimeStampResp offline: status, imprint, nonce, signature and chain to a trusted root."""
    if not isinstance(data, bytes) or len(data) > TOKEN_LIMIT:
        _fail("malformed", "the timestamp reply is missing or too large")
    try:
        return _verify(data, digest, nonce, trusted_roots() if roots is None else roots)
    except (ValueError, IndexError, TypeError, UnicodeDecodeError):
        _fail("malformed", "the timestamp reply is not valid")


def _verify(data, digest, nonce, roots):
    response = _items(_one(data, 0x30))
    status = _items(_expect(response[0], 0x30))
    if _int(_expect(status[0], 0x02)) not in (0, 1):
        _fail("rejected", "the timestamp service refused the request")
    if len(response) != 2:
        _fail("malformed", "the timestamp reply has no token")
    info, content = _items(_expect(response[1], 0x30))
    if _oid(_expect(info, 0x06)) != _SIGNED_DATA:
        _fail("malformed", "the timestamp token is not signed data")
    signed = _items(_one(_expect(content, 0xa0), 0x30))
    encapsulated = _items(_expect(signed[2], 0x30))
    if _oid(_expect(encapsulated[0], 0x06)) != _TSTINFO:
        _fail("malformed", "the timestamp token does not hold timestamp information")
    tst = _one(_expect(encapsulated[1], 0xa0), 0x04)
    fields = _items(_one(tst, 0x30))
    if _int(_expect(fields[0], 0x02)) != 1:
        _fail("unsupported", "the timestamp information version is not 1")
    policy = _oid(_expect(fields[1], 0x06))
    imprint = _items(_expect(fields[2], 0x30))
    if _algorithm(_expect(imprint[0], 0x30)) != _SHA256 or _expect(imprint[1], 0x04) != digest:
        _fail("imprint", "the timestamp is for different data")
    serial = _int(_expect(fields[3], 0x02))
    moment = _time(fields[4][0], fields[4][1])
    stamped_nonce = next((_int(body) for tag, body, _ in fields[5:] if tag == 0x02), None)
    if nonce is not None and stamped_nonce != nonce:
        _fail("nonce", "the timestamp reply does not answer this request")
    pool, rest = [], signed[3:]
    if rest and rest[0][0] == 0xa0:
        pool = [_Certificate(whole) for _, _, whole in _items(rest[0][1])]
        rest = rest[1:]
    if rest and rest[0][0] == 0xa1:
        rest = rest[1:]
    if len(rest) != 1:
        _fail("malformed", "the timestamp token has an unexpected structure")
    signers = _items(_expect(rest[0], 0x31))
    if len(signers) != 1:
        _fail("unsupported", "the timestamp token must have exactly one signer")
    parts = _items(_expect(signers[0], 0x30))
    version, sid, digest_algorithm, attributes_item, signature_algorithm, signature = parts[:6]
    digest_name = _algorithm(_expect(digest_algorithm, 0x30))
    if digest_name not in _HASHES:
        _fail("unsupported", "the timestamp uses an unsupported digest")
    hasher = _HASHES[digest_name][1]
    attributes = _attributes(_expect(attributes_item, 0xa0))
    kinds = attributes.get(_CONTENT_TYPE, [])
    digests = attributes.get(_MESSAGE_DIGEST, [])
    if len(kinds) != 1 or _oid(_expect(kinds[0], 0x06)) != _TSTINFO or len(digests) != 1:
        _fail("malformed", "the timestamp token lacks its signed content type or digest")
    if _expect(digests[0], 0x04) != hasher.new(tst).digest():
        _fail("digest", "the timestamp information was changed after signing")
    if _int(_expect(version, 0x02)) == 3 and sid[0] == 0x80:
        signer = next((c for c in pool if c.extensions.get(_SUBJECT_KEY, (0, b""))[1] == _tlv(0x04, sid[1])), None)
    else:
        issuer, number = _items(_expect(sid, 0x30))
        signer = next((c for c in pool if c.issuer == issuer[2] and c.serial == _int(_expect(number, 0x02))), None)
    if signer is None:
        _fail("untrusted", "the timestamp token does not include its signing certificate")
    _bound(attributes, signer)
    message = b"\x31" + attributes_item[2][1:]
    if not _check_signature(signer.public, _algorithm(_expect(signature_algorithm, 0x30)), message,
                            _expect(signature, 0x04), hasher):
        _fail("signature", "the timestamp signature is not valid")
    anchors = [_Certificate(root) for root in roots]
    anchor = _chain(signer, pool, anchors, moment)
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%S") + (f".{moment.microsecond:06d}".rstrip("0") if moment.microsecond else "") + "Z"
    return {"time": stamp, "tsa": signer.name(), "hash": "sha256", "policy": policy,
            "serial": format(serial, "x"),
            "root_sha256": hashlib.sha256(anchor.raw).hexdigest()}


def _post(url: str, body: bytes, *, deadline: float) -> bytes:
    headers = {"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply",
               "User-Agent": "tallylock"}
    for attempt in range(3):
        if time.monotonic() >= deadline:
            raise TallyLockError("timestamp request deadline exceeded", code=5)
        try:
            response = _http.request("POST", url, body=body, headers=headers, response_limit=TOKEN_LIMIT,
                                     deadline=deadline)
        except _http.NetworkError:
            response = None
        delay = 2 ** attempt
        if response is not None:
            if response.status == 200:
                return response.body
            if response.status not in {403, 429} and not 500 <= response.status <= 599:
                raise TallyLockError("timestamp service returned an unsuccessful status", code=5)
            due = transport._retry_at(response.retry_after)
            if due is not None:
                delay = max(delay, due - int(time.time()))
        if attempt == 2:
            raise TallyLockError("timestamp request failed after bounded retries", code=5)
        if time.monotonic() + delay >= deadline:
            raise TallyLockError("timestamp retry exceeds the request deadline", code=5)
        time.sleep(delay)


def request(url: str, digest: bytes, *, post=None, nonce: int | None = None,
            deadline: float | None = None) -> tuple[bytes, dict]:
    """Ask one service to stamp digest and return its reply bytes after a full offline check."""
    post = _post if post is None else post
    nonce = secrets.randbits(64) | 1 << 63 if nonce is None else nonce
    body = build_request(digest, nonce)
    deadline = time.monotonic() + 30 if deadline is None else deadline
    data = post(url, body, deadline=deadline)
    return data, verify(data, digest, nonce=nonce)
