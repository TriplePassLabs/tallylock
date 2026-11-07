"""Main-owned launcher isolation checks with benign local shadow packages."""

import os

import pytest

from tallylock import _http
from tallylock.errors import TallyLockError
from test_http import server


@pytest.mark.parametrize("shadow_source", ["cwd", "pythonpath", "startup"])
def test_http_child_uses_trusted_package_not_evaluation_directory(tmp_path, monkeypatch, server, shadow_source):
    origin = server
    shadow = tmp_path / "unrelated-evaluation"
    shadow.mkdir()
    marker = shadow / "shadow-imported.txt"
    # A harmless observable marker proves whether the child imported local code.
    marker_code = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unexpected local import')\n"
    )
    if shadow_source == "startup":
        (shadow / "sitecustomize.py").write_text(marker_code)
    else:
        package = shadow / "tallylock"
        package.mkdir()
        (package / "__init__.py").write_text(marker_code)
        (package / "_http.py").write_text("raise SystemExit(1)\n")
    if shadow_source == "cwd":
        monkeypatch.chdir(shadow)
    else:
        monkeypatch.setenv("PYTHONPATH", f"{shadow}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
    failure = None
    response = None
    try:
        response = _http.request("GET", origin + "/ok", body=None, headers={}, response_limit=100)
    except TallyLockError as error:
        failure = error
    assert not marker.exists(), "HTTP subprocess imported an unrelated evaluation's prove package"
    assert failure is None
    assert response.status == 200 and response.body == b"payload"
