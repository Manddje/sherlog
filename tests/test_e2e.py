"""
End-to-end tests for the IME Log Analyzer web layer.

Runs the real analysis script (pwsh) against ./testdata, plus upload-validation
tests: oversized upload, wrong extension, zip-slip attempt.
"""

import io
import os
import time
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTDATA = REPO_ROOT / "testdata"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Isolate job storage and keep auth off for the test app.
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("APP_USER", "")
    monkeypatch.setenv("APP_PASSWORD", "")
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")  # 1 MB cap for the size test

    # Import fresh so module-level config picks up the env above.
    import importlib
    import app as app_module
    importlib.reload(app_module)

    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        yield c


def _zip_of_testdata() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for log in TESTDATA.glob("*.log"):
            zf.write(log, arcname=log.name)
    return buf.getvalue()


def _wait_for_result(client, location: str, timeout: float = 300.0) -> str:
    """Poll the result page until the job finishes, then return the report HTML.

    A finished job renders a wrapper page that frames the report in a sandboxed
    <iframe src=".../report">; the actual report content lives at that subpath.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(location)
        if "Analyzing" in r.text:  # busy/queued page
            time.sleep(1.0)
            continue
        if "/report" in r.text:  # done -> fetch the framed report
            return client.get(location.rstrip("/") + "/report").text
        return r.text  # failed page
    raise AssertionError("analysis did not finish within timeout")


def test_health_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_landing_shows_both_tools(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Timeline Analyzer" in r.text
    assert "CMTrace Viewer" in r.text
    assert 'href="/timeline"' in r.text
    assert 'href="/cmtrace"' in r.text
    assert "<form" not in r.text  # landing has no upload form


@pytest.mark.parametrize("path,action", [
    ("/timeline", "/analyze"),
    ("/cmtrace", "/cmtrace-view"),
])
def test_upload_pages_show_limits(client, path, action):
    r = client.get(path)
    assert r.status_code == 200
    assert "Max total upload" in r.text
    assert f'action="{action}"' in r.text
    assert "formaction" not in r.text  # single submit button per tool


def test_full_flow_zip_produces_report(client):
    data = _zip_of_testdata()
    r = client.post(
        "/analyze",
        files={"files": ("logs.zip", data, "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    location = r.headers["location"]
    assert location.startswith("/result/")

    html = _wait_for_result(client, location)
    # Recognizable timeline-report content from the IME script.
    assert "Timeline" in html
    assert "Win32App" in html
    assert "Get-IntuneManagementExtensionDiagnostics" in html


def test_oversized_upload_rejected(client):
    # MAX_UPLOAD_MB=1 in the fixture; send ~2 MB.
    big = b"x" * (2 * 1024 * 1024)
    r = client.post(
        "/analyze",
        files={"files": ("big.log", big, "text/plain")},
        follow_redirects=False,
    )
    assert r.status_code == 413


def test_wrong_extension_rejected(client):
    r = client.post(
        "/analyze",
        files={"files": ("evil.exe", b"nope", "application/octet-stream")},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_cmtrace_viewer(client):
    data = _zip_of_testdata()
    r = client.post(
        "/analyze",
        files={"files": ("logs.zip", data, "application/zip")},
        follow_redirects=False,
    )
    location = r.headers["location"]
    _wait_for_result(client, location)  # block until the job is done
    job_id = location.rstrip("/").rsplit("/", 1)[-1]

    page = client.get(f"/result/{job_id}/cmtrace")
    assert page.status_code == 200
    assert "IntuneManagementExtension.log" in page.text
    assert "AgentExecutor.log" in page.text
    assert "iframe" in page.text

    view = client.get(
        f"/result/{job_id}/cmtrace/view",
        params={"file": "IntuneManagementExtension.log"},
    )
    assert view.status_code == 200
    assert "Win32App" in view.text
    assert "sandbox" in view.headers.get("content-security-policy", "")

    # Membership check rejects traversal and unknown files.
    assert client.get(
        f"/result/{job_id}/cmtrace/view", params={"file": "../app.py"}
    ).status_code == 404
    assert client.get(
        f"/result/{job_id}/cmtrace/view", params={"file": "nope.log"}
    ).status_code == 404


def test_parse_cmtrace_against_testdata():
    import app as app_module
    text = (TESTDATA / "IntuneManagementExtension.log").read_text(encoding="utf-8")
    records, truncated = app_module.parse_cmtrace(text)
    assert records
    assert any(r["component"] == "IntuneManagementExtension" for r in records)
    assert any("Win32App" in r["msg"] for r in records)
    assert not truncated


def test_parse_cmtrace_multiline_and_plain():
    import app as app_module
    text = (
        "plain line before\n"
        '<![LOG[first\nsecond]LOG]!><time="01:02:03.000" date="1-2-2024" '
        'component="X" context="" type="3" thread="7" file="">\n'
    )
    records, _ = app_module.parse_cmtrace(text)
    assert records[0]["msg"] == "plain line before"
    assert records[0]["structured"] is False
    assert records[1]["msg"] == "first\nsecond"   # multi-line message stays one record
    assert records[1]["structured"] is True
    assert records[1]["component"] == "X"
    assert records[1]["type"] == "3"
    assert records[1]["thread"] == "7"


def test_parse_cmtrace_plain_splits_per_line():
    import app as app_module
    # A command-output (non-CMTrace) log becomes one record per non-blank line.
    records, _ = app_module.parse_cmtrace("line one\n\nline two\nline three\n")
    assert [r["msg"] for r in records] == ["line one", "line two", "line three"]
    assert all(r["structured"] is False for r in records)


def test_render_log_tree_groups_folders():
    import app as app_module
    html = app_module.render_log_tree([
        "IntuneManagementExtension.log",
        "mdmdiagnostics/(29) Command foo output.log",
    ])
    assert "<details" in html and "mdmdiagnostics" in html
    assert 'data-file="mdmdiagnostics/(29) Command foo output.log"' in html
    assert ">(29) Command foo output.log<" in html  # leaf shown, not full path


def test_render_view_plain_vs_structured():
    import app as app_module
    plain, _ = app_module.parse_cmtrace("ERROR: boom\nall good\n")
    html = app_module.render_cmtrace_view("cmd.log", plain, False)
    assert 'class="ln"' in html       # line-number column for plain logs
    assert "Component" not in html    # structured columns hidden
    assert 'class="err"' in html      # ERROR line coloured

    struct, _ = app_module.parse_cmtrace(
        '<![LOG[hi]LOG]!><time="1" date="2" component="C" context="" '
        'type="2" thread="3" file="">'
    )
    html2 = app_module.render_cmtrace_view("ime.log", struct, False)
    assert "Component" in html2       # full CMTrace table
    assert 'class="warn"' in html2


def test_zip_slip_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.log", "pwned")
    r = client.post(
        "/analyze",
        files={"files": ("evil.zip", buf.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 400
