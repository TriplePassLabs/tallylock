"""Private one-request HTTP boundary, supervised by an absolute deadline."""
from __future__ import annotations

from dataclasses import dataclass
import base64
import http.client
import json
import math
import os
import re
import select
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

from .errors import TallyLockError


_MAX_REQUEST_IPC = 2 * 1024 * 1024
_MAX_REQUEST_BODY = 1024 * 1024


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    retry_after: str | None


class NetworkError(TallyLockError):
    def __init__(self):
        super().__init__("HTTP network request failed or exceeded its deadline", code=5)


def _perform(method, url, body, headers, limit, timeout):
    connection = None
    try:
        parsed = urlsplit(url)
        cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        options = {"timeout": timeout}
        if parsed.scheme == "https":
            options["context"] = ssl.create_default_context()
        connection = cls(parsed.hostname, parsed.port, **options)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        lengths = response.headers.get_all("Content-Length", [])
        encodings = response.headers.get_all("Transfer-Encoding", [])
        if (len(lengths) > 1 or len(encodings) > 1 or lengths and encodings
                or encodings and encodings[0].lower() != "chunked"):
            raise ValueError("response framing")
        expected = None
        if lengths:
            if re.fullmatch(r"[0-9]{1,16}", lengths[0]) is None:
                raise ValueError("response framing")
            expected = int(lengths[0])
            if response.status == 200 and expected > limit:
                raise ValueError("response limit")
        retry = response.getheader("Retry-After")
        if retry is not None and (len(retry) > 256 or not retry.isascii()):
            retry = None
        # Error/redirect bodies are neither useful evidence nor safe diagnostics.
        # Keep them entirely inside the remote connection, outside our IPC.
        data = response.read(limit + 1) if response.status == 200 else b""
        if len(data) > limit:
            raise ValueError("response limit")
        if response.status == 200 and expected is not None and len(data) != expected:
            raise ValueError("truncated response")
        metadata = {"status": response.status, "retry_after": retry}
    except http.client.RemoteDisconnected:
        metadata, data = {"error": "network"}, b""
    except (ssl.SSLError, http.client.HTTPException, ValueError):
        metadata, data = {"error": "response"}, b""
    except OSError:
        metadata, data = {"error": "network"}, b""
    except Exception:
        metadata, data = {"error": "response"}, b""
    finally:
        if connection is not None:
            connection.close()
    return json.dumps(metadata, separators=(",", ":")).encode() + b"\n" + data


def _worker():
    """Static child entry: request data arrives exclusively through bounded stdin."""
    try:
        data = sys.stdin.buffer.read(_MAX_REQUEST_IPC + 1)
        if len(data) > _MAX_REQUEST_IPC:
            raise ValueError("request IPC limit")
        value = json.loads(data)
        body = base64.b64decode(value["body"], validate=True) if value["body"] is not None else None
        output = _perform(value["method"], value["url"], body, value["headers"],
                          value["response_limit"], value["timeout"])
    except Exception:
        output = b'{"error":"response"}\n'
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()


def request(method, url, *, body, headers, response_limit, timeout_seconds=10,
            deadline: float | None = None) -> Response:
    """Do one request; DNS, TLS, body reads and IPC share one wall-clock bound."""
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and not parsed.fragment and not any(ord(c) <= 32 or ord(c) == 127 for c in url))
        parsed.port
    except (ValueError, TypeError):
        valid = False
    if not valid or method not in {"GET", "POST"}:
        raise TallyLockError("invalid HTTP request", code=5)
    if (body is not None and (not isinstance(body, bytes) or len(body) > _MAX_REQUEST_BODY)
            or not isinstance(headers, dict) or len(headers) > 128
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())):
        raise TallyLockError("invalid HTTP request payload", code=5)
    if len(url) > 16384 or sum(len(k)+len(v) for k, v in headers.items()) > 65536:
        raise TallyLockError("HTTP request metadata exceeds size limit", code=5)
    if (type(response_limit) is not int or not 0 <= response_limit <= 32 * 1024 * 1024
            or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
        raise TallyLockError("invalid HTTP request bounds", code=5)
    end = time.monotonic() + timeout_seconds
    if deadline is not None:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            raise TallyLockError("invalid absolute HTTP deadline", code=5)
        end = min(end, deadline)
    if end <= time.monotonic():
        raise NetworkError()
    payload = json.dumps({"method": method, "url": url,
        "body": base64.b64encode(body).decode("ascii") if body is not None else None,
        "headers": headers, "response_limit": response_limit,
        "timeout": end-time.monotonic()}, separators=(",", ":")).encode()
    if len(payload) > _MAX_REQUEST_IPC:
        raise TallyLockError("HTTP request IPC exceeds size limit", code=5)
    chunks = bytearray()
    child = None
    primary = None
    closed_streams = set()

    def close_once(name):
        if name not in closed_streams:
            closed_streams.add(name)
            getattr(child, name).close()

    try:
        child = subprocess.Popen([sys.executable, "-I", "-m", "tallylock._http"], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        position = 0
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise NetworkError()
            writes = [child.stdin.fileno()] if not child.stdin.closed else []
            ready, writable, _ = select.select([child.stdout.fileno()], writes, [], remaining)
            if not ready and not writable:
                raise NetworkError()
            if writable:
                position += os.write(child.stdin.fileno(), payload[position:position+65536])
                if position == len(payload):
                    close_once("stdin")
            if not ready:
                continue
            chunk = os.read(child.stdout.fileno(), 65536)
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > response_limit + 2048:
                raise TallyLockError("HTTP response exceeds size limit", code=5)
        header, separator, data = bytes(chunks).partition(b"\n")
        if not separator:
            raise TallyLockError("HTTP request failed", code=5)
        metadata = json.loads(header)
        if metadata.get("error") == "network":
            raise NetworkError()
        if "error" in metadata:
            raise TallyLockError("HTTP response failed validation", code=5)
        if metadata["status"] == 401:
            raise TallyLockError("HTTP authentication failed", code=5)
        return Response(metadata["status"], data, metadata["retry_after"])
    except (OSError, ValueError, KeyError):
        primary = TallyLockError("HTTP request failed", code=5)
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        if child is not None:
            cleanup_failed = False

            def cleanup(operation):
                nonlocal cleanup_failed
                try:
                    operation()
                except BaseException:
                    cleanup_failed = True

            # A close can release its descriptor and still raise. Attempt each
            # close once, then finish child cleanup even after secondary errors.
            cleanup(lambda: close_once("stdin"))
            cleanup(lambda: close_once("stdout"))
            cleanup(child.terminate)
            try:
                child.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                cleanup(child.kill)
                cleanup(child.wait)
            except BaseException:
                cleanup_failed = True
                cleanup(child.kill)
                cleanup(child.wait)
            if cleanup_failed and primary is None:
                raise TallyLockError("HTTP request cleanup failed", code=5) from None


if __name__ == "__main__":
    _worker()
