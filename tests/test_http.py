"""Real bounded HTTP calls run only against local worker-owned servers."""
import importlib.util
import errno
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tallylock.errors import TallyLockError


def api():
    assert importlib.util.find_spec("tallylock._http") is not None, "bounded HTTP boundary missing"
    from tallylock import _http
    return _http


@pytest.fixture
def request_children(monkeypatch):
    client = api()
    launch = client.subprocess.Popen
    children = []
    def tracked(*args, **kwargs):
        child = launch(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(client.subprocess, "Popen", tracked)
    yield children
    assert all(child.poll() is not None for child in children)
    assert all(child.stdin.closed and child.stdout.closed for child in children)


@pytest.fixture
def server():
    seen = {path: threading.Event() for path in ("/hang", "/dribble")}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/disconnect":
                self.close_connection = True
                return
            if self.path in seen:
                seen[self.path].set()
            if self.path == "/hang":
                time.sleep(1)
                return
            status = 429 if self.path == "/large-429" else 503 if self.path in {"/failure", "/large-503"} else 302 if self.path == "/redirect" else 200
            self.send_response(status)
            self.send_header("Location", "/secret")
            if self.path.startswith("/large-"):
                self.send_header("Content-Length", "1000000")
                self.send_header("Retry-After", "600")
            if self.path == "/truncated":
                self.send_header("Content-Length", "100")
            if self.path == "/bad-length":
                self.send_header("Content-Length", "garbage")
            if self.path == "/conflicting-length":
                self.send_header("Content-Length", "7")
                self.send_header("Content-Length", "12")
            self.end_headers()
            try:
                if self.path == "/dribble":
                    for _ in range(20):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(.05)
                else:
                    self.wfile.write(b"payload")
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    value = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=value.serve_forever)
    thread.start()
    class Address(str):
        pass
    address = Address(f"http://127.0.0.1:{value.server_port}")
    address.seen = seen
    yield address
    value.shutdown()
    value.server_close()
    thread.join()


@pytest.mark.parametrize("path", ["/hang", "/dribble"])
def test_absolute_deadline_and_no_request_child_after_return(server, path, request_children):
    client = api()
    start = time.monotonic()
    with pytest.raises(TallyLockError) as error:
        client.request("GET", server + path, body=None, headers={"Authorization": "synthetic-secret"},
                       response_limit=100, timeout_seconds=5, deadline=start + .6)
    assert error.value.code == 5
    assert "synthetic-secret" not in str(error.value)
    assert server.seen[path].is_set()
    assert time.monotonic() - start < 1.5
    assert request_children and all(child.returncode is not None for child in request_children)
    assert all(child.args == [sys.executable, "-I", "-m", "tallylock._http"] for child in request_children)


def test_response_limit_and_redirect_not_followed(server):
    client = api()
    response = client.request("GET", server + "/redirect", body=None, headers={}, response_limit=100)
    assert response.status == 302
    with pytest.raises(TallyLockError) as error:
        client.request("GET", server, body=None, headers={}, response_limit=3)
    assert error.value.code == 5


def test_tls_handshake_stall_is_bounded_and_child_reaped(request_children):
    client = api()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen()
    listener.settimeout(2)
    accepted = threading.Event()
    stop = threading.Event()
    def stall():
        try:
            with listener.accept()[0] as connection:
                accepted.set()
                stop.wait(2)
        except (TimeoutError, OSError):
            pass
    thread = threading.Thread(target=stall)
    thread.start()
    start = time.monotonic()
    try:
        with pytest.raises(TallyLockError) as error:
            client.request("GET", f"https://127.0.0.1:{listener.getsockname()[1]}", body=None,
                headers={}, response_limit=100, deadline=start+.6)
        assert error.value.code == 5 and accepted.is_set()
        assert time.monotonic()-start < 1.5
        assert request_children and all(child.returncode is not None for child in request_children)
    finally:
        stop.set(); listener.close(); thread.join(3)
    assert not thread.is_alive()


def test_interrupt_cleanup_and_preexpired_deadline(server, monkeypatch, request_children):
    client = api()
    with pytest.raises(TallyLockError):
        client.request("GET", server, body=None, headers={}, response_limit=100, deadline=time.monotonic()-1)
    def interrupt(*args):
        raise KeyboardInterrupt()
    monkeypatch.setattr(client.select, "select", interrupt)
    with pytest.raises(KeyboardInterrupt):
        client.request("GET", server+"/hang", body=None, headers={}, response_limit=100)
    assert request_children and all(child.returncode is not None for child in request_children)


@pytest.mark.parametrize("path", ["/truncated", "/bad-length", "/conflicting-length"])
def test_malformed_http_framing_is_operational(server, path):
    client = api()
    with pytest.raises(TallyLockError) as error:
        client.request("GET", server+path, body=None, headers={}, response_limit=1000)
    assert error.value.code == 5


@pytest.mark.parametrize("mode", ["stdin", "-c"])
def test_api_works_from_unguarded_python_entry_points(server, mode):
    code = (
        "from tallylock import _http\n"
        "import sys\n"
        "response = _http.request('GET', sys.argv[1]+'/dribble', body=None, headers={}, "
        "response_limit=100, timeout_seconds=3)\n"
        "assert response.status == 200 and response.body == b'a'*20\n"
    )
    args = [sys.executable, "-", server] if mode == "stdin" else [sys.executable, "-c", code, server]
    result = subprocess.run(args, input=code.encode() if mode == "stdin" else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert server.seen["/dribble"].is_set()


def test_bounded_request_ipc_transfers_body_without_credentials_in_argv(server, request_children):
    client = api()
    data = b"a"*131072
    response = client.request("POST", server, body=data, headers={"Authorization": "synthetic-secret"},
                              response_limit=len(data), timeout_seconds=3)
    assert response.status == 200 and response.body == data
    assert request_children[0].args == [sys.executable, "-I", "-m", "tallylock._http"]
    calls = len(request_children)
    with pytest.raises(TallyLockError) as error:
        client.request("POST", server, body=b"a"*(1024*1024+1), headers={}, response_limit=1)
    assert error.value.code == 5 and len(request_children) == calls


def test_error_response_body_does_not_cross_private_ipc(server):
    client = api()
    response = client.request("GET", server+"/failure", body=None, headers={}, response_limit=100)
    assert response.status == 503 and response.body == b""


def test_remote_disconnect_is_a_retryable_network_failure(server):
    client = api()
    with pytest.raises(client.NetworkError):
        client.request("GET", server+"/disconnect", body=None, headers={}, response_limit=100)


@pytest.mark.parametrize("status", [429, 503])
def test_large_discarded_error_page_preserves_typed_retry_after(server, monkeypatch, status):
    from tallylock import transport
    client = api()
    actual_request = client.request
    def loopback_request(method, url, **kwargs):
        kwargs["body"] = None
        return actual_request("GET", server+f"/large-{status}", **kwargs)
    monkeypatch.setattr(transport._http, "request", loopback_request)
    with pytest.raises(transport.RetryDeferred) as error:
        transport.submit("https://a.pool.opentimestamps.org", b"a"*32)
    assert error.value.next_retry_at >= int(time.time())+599


@pytest.mark.parametrize("mode,failed_stream", [("deadline", "stdin"), ("deadline", "stdout"),
    ("success", "stdin"), ("success", "stdout"), ("interrupt", "stdout")])
def test_close_after_release_drains_all_cleanup_preserving_primary(server, monkeypatch, mode, failed_stream):
    client = api()
    actual_launch = client.subprocess.Popen
    children, streams = [], []
    sentinel = KeyboardInterrupt("synthetic primary interrupt")
    class Stream:
        def __init__(self, raw, name):
            self.raw, self.name, self.calls = raw, name, 0
        def __getattr__(self, name):
            return getattr(self.raw, name)
        def close(self):
            self.calls += 1
            self.raw.close()
            if self.name == failed_stream and (self.name == "stdout" or self.calls > 1):
                raise OSError(errno.EIO, "synthetic close after release")
    def launch(*args, **kwargs):
        child = actual_launch(*args, **kwargs)
        children.append(child)
        child.stdin = Stream(child.stdin, "stdin")
        child.stdout = Stream(child.stdout, "stdout")
        streams.extend((child.stdin, child.stdout))
        return child
    monkeypatch.setattr(client.subprocess, "Popen", launch)
    if mode == "interrupt":
        actual_select = client.select.select
        def interrupt(reads, writes, errors, timeout):
            if not writes:
                assert server.seen["/hang"].wait(1)
                raise sentinel
            return actual_select(reads, writes, errors, timeout)
        monkeypatch.setattr(client.select, "select", interrupt)
    try:
        if mode == "success" and failed_stream == "stdin":
            response = client.request("GET", server, body=None, headers={}, response_limit=100)
            assert response.status == 200
        else:
            with pytest.raises(BaseException) as error:
                client.request("GET", server+("/hang" if mode != "success" else ""), body=None,
                    headers={}, response_limit=100, deadline=time.monotonic()+.6)
            if mode == "interrupt":
                assert error.value is sentinel
            elif mode == "deadline":
                assert isinstance(error.value, client.NetworkError)
            else:
                assert isinstance(error.value, TallyLockError) and error.value.code == 5
        assert children and all(child.returncode is not None for child in children)
        assert all(stream.closed and stream.calls == 1 for stream in streams)
        if mode != "success":
            assert server.seen["/hang"].is_set()
    finally:
        # The deliberately broken pre-fix boundary must not orphan the real child.
        for child in children:
            for stream in (child.stdin, child.stdout):
                stream.raw.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
