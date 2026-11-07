"""Synthetic RPC acquisition tests, never independent-node evidence."""

import base64
from copy import deepcopy
import importlib
import json
from pathlib import Path
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bitcoin.core import CBlockHeader, b2lx
import pytest

from tallylock import _http, chain
from tallylock.errors import TallyLockError


HEADER = (Path(__file__).parent / "fixtures/ots/historical-header.hex").read_text().strip()
HASH = b2lx(CBlockHeader.deserialize(bytes.fromhex(HEADER)).GetHash())
SECRET = "synthetic-user:synthetic-test-password"


@pytest.fixture
def evidence():
    assert importlib.util.find_spec("tallylock.evidence") is not None, "Task6c exporter absent"
    return importlib.import_module("tallylock.evidence")


@pytest.fixture
def config(tmp_path):
    (tmp_path / "synthetic.cookie").write_text(SECRET + "\n")
    path = tmp_path / "rpc.json"
    path.write_text(json.dumps({"format": "prove.bitcoin-rpc.v1",
        "endpoint": "http://127.0.0.1:8332", "cookie_file": "synthetic.cookie",
        "source": "synthetic mocked RPC; not independent node evidence"}))
    return path


def info(**changes):
    value = {"chain": "main", "initialblockdownload": False, "blocks": 6, "headers": 6,
             "bestblockhash": "ab" * 32, "verificationprogress": 1}
    value.update(changes)
    return value


def mock_rpc(monkeypatch, evidence, *, node=None, modify=None):
    calls = []
    def request(method, url, **kwargs):
        payload = json.loads(kwargs["body"])
        calls.append((payload, kwargs))
        assert method == "POST" and url.startswith("http://127.0.0.1:")
        assert kwargs["headers"]["Authorization"] == "Basic " + base64.b64encode(SECRET.encode()).decode()
        assert kwargs["deadline"] > evidence.time.monotonic()
        rpc = payload["method"]
        if rpc == "getblockchaininfo":
            result = deepcopy(info() if node is None else node)
        elif rpc == "getblockhash":
            assert len(payload["params"]) == 1 and type(payload["params"][0]) is int
            result = HASH
        else:
            assert rpc == "getblockheader" and payload["params"] == [HASH, False]
            result = HEADER
        envelope = {"result": result, "error": None, "id": payload["id"]}
        response = _http.Response(200, json.dumps(envelope).encode(), None)
        return modify(response, payload, len(calls)) if modify else response
    monkeypatch.setattr(evidence._http, "request", request)
    return calls


def fails(code, callback):
    with pytest.raises(TallyLockError) as error:
        callback()
    assert error.value.code == code
    assert SECRET not in str(error.value)
    assert "synthetic-test-password" not in str(error.value)
    return error.value


def test_stable_snapshot_normalized_heights_exact_headers_and_no_auth_output(evidence, config, monkeypatch):
    calls = mock_rpc(monkeypatch, evidence)
    value = evidence.export(config, [2, 1, 1])
    assert list(value["blocks"]) == ["1", "2"]
    assert value["blocks"]["1"] == {"hash": HASH, "header": HEADER, "confirmations": 6}
    assert value["blocks"]["2"]["confirmations"] == 5
    assert value["node"]["verificationprogress"] == "1"
    assert value["source"] == json.loads(config.read_text())["source"]
    assert SECRET not in json.dumps(value) and "127.0.0.1" not in json.dumps(value)
    assert chain.prepare(value).block(1).header == bytes.fromhex(HEADER)
    assert [v[0]["method"] for v in calls] == ["getblockchaininfo", "getblockhash", "getblockheader",
        "getblockhash", "getblockheader", "getblockhash", "getblockhash", "getblockchaininfo"]
    assert len({v[0]["id"] for v in calls}) == len(calls)
    assert len({v[1]["deadline"] for v in calls}) == 1


@pytest.mark.parametrize("heights", [[], [True], [-1], [1.0], ["1"], [2**53], None, (1,), [1]*129])
def test_bad_height_arguments_have_no_io(evidence, config, monkeypatch, heights):
    monkeypatch.setattr(evidence._http, "request", lambda *a, **k: pytest.fail("unexpected I/O"))
    fails(2, lambda: evidence.export(config, heights))


@pytest.mark.parametrize("change", [
    {"extra": True}, {"format": "prove.bitcoin-rpc.v2"}, {"source": 5}, {"source": ""},
    {"cookie_file": 7}, {"endpoint": "http://user:password@127.0.0.1"},
    {"endpoint": "http://127.0.0.1?secret"}, {"endpoint": "http://127.0.0.1#secret"},
    {"endpoint": "http://127.0.0.1/wallet/test"}, {"endpoint": "ftp://127.0.0.1"},
    {"endpoint": "http://127.0.0.1:99999"}, {"endpoint": "http://127.0.0.1\\@elsewhere"},
    {"endpoint": "http://127.0.0.1\n"}, {"endpoint": "http://127.0.0.1?"},
    {"endpoint": "http://[::1]ignored-authority"},
])
def test_closed_local_config_fails_without_network(evidence, config, monkeypatch, change):
    value = json.loads(config.read_text()); value.update(change)
    config.write_text(json.dumps(value))
    monkeypatch.setattr(evidence._http, "request", lambda *a, **k: pytest.fail("unexpected I/O"))
    fails(2, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("cookie", ["", "useronly", "user:", ":password", SECRET + "\nextra", "a:" + "x"*5000])
def test_cookie_is_bounded_and_well_formed(evidence, config, monkeypatch, cookie):
    config.with_name("synthetic.cookie").write_text(cookie)
    monkeypatch.setattr(evidence._http, "request", lambda *a, **k: pytest.fail("unexpected I/O"))
    fails(2, lambda: evidence.export(config, [1]))


def test_nonregular_cookie_fifo_rejected_before_read(evidence, config, monkeypatch):
    cookie = config.with_name("synthetic.cookie")
    cookie.unlink()
    evidence.os.mkfifo(cookie)
    monkeypatch.setattr(evidence._http, "request", lambda *a, **k: pytest.fail("unexpected I/O"))
    fails(2, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("text", ['[]', '{"format":1,"format":2}', '"' + 'x'*17000 + '"'])
def test_bad_config_encoding_shape_and_size(evidence, config, monkeypatch, text):
    config.write_text(text)
    monkeypatch.setattr(evidence._http, "request", lambda *a, **k: pytest.fail("unexpected I/O"))
    fails(2, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("literal,expected", [
    ("0.999999999999999999999999999999999999999999999999999999999", "0.999999999999999999999999999999999999999999999999999999999"),
    ("1.0000", "1"), ("0.12000", "0.12"), ("1e-5", "0.00001"),
    ("0e-128", "0"), ("-0.0", "0"), ("1e-126", "0." + "0"*125 + "1"),
])
def test_exact_decimal_progress(evidence, config, monkeypatch, literal, expected):
    def replace(response, payload, count):
        return _http.Response(200, response.body.replace(b'"verificationprogress": 1',
            b'"verificationprogress": ' + literal.encode()), None)
    mock_rpc(monkeypatch, evidence, modify=replace)
    assert evidence.export(config, [1])["node"]["verificationprogress"] == expected


@pytest.mark.parametrize("literal", ["1e999999999", "1e-999999999", "0e999999999", "0e-999999999",
    "1e-127", "NaN", "Infinity", "-Infinity", "1.1", "-0.1", '"1"', "true", "null",
    "0." + "9"*129])
def test_bad_decimal_is_rejected_without_unbounded_expansion(evidence, config, monkeypatch, literal):
    def replace(response, payload, count):
        return _http.Response(200, response.body.replace(b'"verificationprogress": 1',
            b'"verificationprogress": ' + literal.encode()), None)
    mock_rpc(monkeypatch, evidence, modify=replace)
    fails(5, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("node,code", [
    (info(chain="test"), 4), (info(chain=1), 5), (info(initialblockdownload=True), 3),
    (info(initialblockdownload=0), 5), (info(headers=7), 3), (info(blocks=True), 5),
    (info(blocks=-1), 5), (info(headers=6.0), 5), (info(bestblockhash="garbage"), 5),
    (info(blocks=0, headers=0), 3), (info(blocks=2**53, headers=2**53), 5),
])
def test_node_states_and_types(evidence, config, monkeypatch, node, code):
    mock_rpc(monkeypatch, evidence, node=node)
    fails(code, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("body", [b'[]', b'null', b'{', b'{"id":1,"id":1}',
    b'{"id":1,"result":{},"error":null,"extra":NaN}', b'['*1200+b']'*1200,
    b'"' + b'x'*70000 + b'"', b'\xff'])
def test_malformed_rpc_json(evidence, config, monkeypatch, body):
    mock_rpc(monkeypatch, evidence, modify=lambda r, p, n: _http.Response(200, body, None))
    fails(5, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("change", [
    {"id": True}, {"id": "1"}, {"id": 1.0}, {"id": None}, {"id": 9},
    {"error": "bad"}, {"error": {"code": True, "message": SECRET}},
    {"error": {"code": -1, "message": SECRET}}, {"result": None},
])
def test_envelopes_and_errors_are_strict_and_scrubbed(evidence, config, monkeypatch, change):
    def replace(response, payload, count):
        value = json.loads(response.body); value.update(change)
        return _http.Response(200, json.dumps(value).encode(), None)
    mock_rpc(monkeypatch, evidence, modify=replace)
    fails(5, lambda: evidence.export(config, [1]))


def test_unsupported_rpc_error(evidence, config, monkeypatch):
    def replace(response, payload, count):
        return _http.Response(200, json.dumps({"id": payload["id"], "result": None,
            "error": {"code": -32601, "message": SECRET}}).encode(), None)
    mock_rpc(monkeypatch, evidence, modify=replace)
    fails(4, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("missing", ["id", "error", "result"])
def test_missing_required_envelope_fields(evidence, config, monkeypatch, missing):
    def modify(response, payload, count):
        value = json.loads(response.body); value.pop(missing)
        return _http.Response(200, json.dumps(value).encode(), None)
    mock_rpc(monkeypatch, evidence, modify=modify)
    fails(5, lambda: evidence.export(config, [1]))


@pytest.mark.parametrize("status,code,count", [(401,5,1), (403,5,3), (429,5,3), (500,5,3),
    (503,5,3), (302,5,1), (404,4,1), (405,4,1), (501,4,3)])
def test_http_status_retry_and_scrubbing(evidence, config, monkeypatch, status, code, count):
    calls = mock_rpc(monkeypatch, evidence,
        modify=lambda r,p,n: _http.Response(status, SECRET.encode(), None))
    sleeps = []; monkeypatch.setattr(evidence.time, "sleep", sleeps.append)
    fails(code, lambda: evidence.export(config, [1]))
    assert len(calls) == count
    assert sleeps == ([1,2] if count == 3 else [])


def test_retry_after_honored_without_sleeping_past_deadline(evidence, config, monkeypatch):
    calls = mock_rpc(monkeypatch, evidence,
        modify=lambda r,p,n: _http.Response(429, b"", "600"))
    monkeypatch.setattr(evidence.time, "sleep", lambda n: pytest.fail("sleep exceeded deadline"))
    fails(5, lambda: evidence.export(config, [1]))
    assert len(calls) == 1


def test_short_retry_after_is_respected(evidence, config, monkeypatch):
    mock_rpc(monkeypatch, evidence, modify=lambda r,p,n: _http.Response(429, b"", "7") if n == 1 else r)
    sleeps = []; monkeypatch.setattr(evidence.time, "sleep", sleeps.append)
    evidence.export(config, [1])
    assert sleeps == [7]


def test_global_deadline_shared_and_stops_before_next_rpc(evidence, config, monkeypatch):
    now = [0]
    monkeypatch.setattr(evidence.time, "monotonic", lambda: now[0])
    calls = mock_rpc(monkeypatch, evidence)
    good = evidence._http.request
    def consumes_budget(*args, **kwargs):
        value = good(*args, **kwargs)
        now[0] = 121
        return value
    monkeypatch.setattr(evidence._http, "request", consumes_budget)
    fails(5, lambda: evidence.export(config, [1]))
    assert len(calls) == 1


def test_transient_retry_recovers_with_same_rpc_id(evidence, config, monkeypatch):
    calls = mock_rpc(monkeypatch, evidence)
    good = evidence._http.request
    attempts = []
    def flaky(*args, **kwargs):
        attempts.append(json.loads(kwargs["body"])["id"])
        if len(attempts) < 3:
            raise _http.NetworkError()
        return good(*args, **kwargs)
    monkeypatch.setattr(evidence._http, "request", flaky)
    monkeypatch.setattr(evidence.time, "sleep", lambda n: None)
    evidence.export(config, [1])
    assert attempts[:3] == [1,1,1] and len(calls) == 5


def test_changed_tip_and_reorg_retry_fresh_snapshot(evidence, config, monkeypatch):
    def modify(response, payload, count):
        value = json.loads(response.body)
        if count == 4:
            assert payload["method"] == "getblockhash"
            value["result"] = "cd"*32
        return _http.Response(200, json.dumps(value).encode(), None)
    calls = mock_rpc(monkeypatch, evidence, modify=modify)
    result = evidence.export(config, [1])
    assert result["blocks"]["1"]["hash"] == HASH
    assert len([c for c in calls if c[0]["method"] == "getblockchaininfo"]) >= 3


def test_unstable_tip_is_insufficient_after_three_snapshots(evidence, config, monkeypatch):
    observations = []
    def modify(response, payload, count):
        if payload["method"] != "getblockchaininfo":
            return response
        value = json.loads(response.body)
        observations.append(1)
        if len(observations) % 2 == 0:
            value["result"]["bestblockhash"] = "cd"*32
        return _http.Response(200, json.dumps(value).encode(), None)
    mock_rpc(monkeypatch, evidence, modify=modify)
    fails(3, lambda: evidence.export(config, [1]))
    assert len(observations) == 6


@pytest.mark.parametrize("bad_header", ["00"*80, "00"*79, HEADER.upper(), "z"*160, None])
def test_invalid_raw_header_or_hash_is_operational(evidence, config, monkeypatch, bad_header):
    def modify(response, payload, count):
        if payload["method"] == "getblockheader":
            value = json.loads(response.body); value["result"] = bad_header
            return _http.Response(200, json.dumps(value).encode(), None)
        return response
    mock_rpc(monkeypatch, evidence, modify=modify)
    fails(5, lambda: evidence.export(config, [1]))


def test_cache_tip_header_binding_is_checked(evidence, config, monkeypatch):
    mock_rpc(monkeypatch, evidence)
    fails(5, lambda: evidence.export(config, [6]))


def test_future_rpc_fields_ignored(evidence, config, monkeypatch):
    node = info(future={"arbitrary": [1,2,3]})
    mock_rpc(monkeypatch, evidence, node=node)
    assert "future" not in evidence.export(config, [1])["node"]


def test_maximum_height_batch_rechecks_every_selected_block(evidence, config, monkeypatch):
    calls = mock_rpc(monkeypatch, evidence, node=info(blocks=1000, headers=1000))
    value = evidence.export(config, list(range(128)))
    assert len(value["blocks"]) == 128 and len(calls) == 386
    active = [c[0]["params"][0] for c in calls if c[0]["method"] == "getblockhash"]
    assert active == list(range(128)) * 2


@pytest.mark.parametrize("mode", ["redirect", "auth", "failure", "tls", "timeout"])
def test_real_http_failure_paths_are_bounded_and_scrubbed(evidence, config, monkeypatch, mode):
    seen = []
    stop = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            seen.append(self.path)
            self.rfile.read(int(self.headers["Content-Length"]))
            if mode == "timeout":
                stop.wait(2)
                return
            status = {"redirect": 302, "auth": 401, "failure": 503}.get(mode, 200)
            self.send_response(status)
            self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Length", str(len(SECRET)))
            self.end_headers()
            try:
                self.wfile.write(SECRET.encode())
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever); thread.start()
    value = json.loads(config.read_text())
    value["endpoint"] = ("https" if mode == "tls" else "http") + f"://127.0.0.1:{server.server_port}"
    config.write_text(json.dumps(value))
    original = evidence._http.request
    def short_request(*args, **kwargs):
        # Include isolated-interpreter startup on every supported Linux runtime.
        kwargs["timeout_seconds"] = 1
        return original(*args, **kwargs)
    monkeypatch.setattr(evidence._http, "request", short_request)
    monkeypatch.setattr(evidence.time, "sleep", lambda n: None)
    start = evidence.time.monotonic()
    try:
        fails(5, lambda: evidence.export(config, [1]))
        assert evidence.time.monotonic() - start < 5
        assert "/must-not-follow" not in seen
        assert len(seen) == (3 if mode in {"failure", "timeout"} else 0 if mode == "tls" else 1)
    finally:
        stop.set(); server.shutdown(); server.server_close(); thread.join()


def test_actual_loopback_auth_is_in_header_never_subprocess_argv(evidence, config, monkeypatch):
    seen = []; argv = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((payload, self.headers.get("Authorization")))
            result = info() if payload["method"] == "getblockchaininfo" else HASH if payload["method"] == "getblockhash" else HEADER
            body = json.dumps({"result": result, "error": None, "id": payload["id"]}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever); thread.start()
    value = json.loads(config.read_text()); value["endpoint"] = f"http://127.0.0.1:{server.server_port}"
    config.write_text(json.dumps(value))
    popen = _http.subprocess.Popen
    def tracked(args, **kwargs):
        argv.append(args)
        return popen(args, **kwargs)
    monkeypatch.setattr(_http.subprocess, "Popen", tracked)
    try:
        result = evidence.export(config, [1])
    finally:
        server.shutdown(); server.server_close(); thread.join()
    assert len(seen) == 5 and len(argv) == 5
    assert all(args == [sys.executable, "-I", "-m", "tallylock._http"] for args in argv)
    assert all(auth == "Basic " + base64.b64encode(SECRET.encode()).decode() for _, auth in seen)
    assert SECRET not in json.dumps(result)
