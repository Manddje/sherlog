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


def test_landing_shows_tools_and_dropzone(client):
    r = client.get("/")
    assert r.status_code == 200
    # Timeline is no longer a standalone tool — only inside the diagnostics package.
    assert "Timeline Analyzer" not in r.text
    assert 'href="/timeline"' not in r.text
    assert "CMTrace Viewer" in r.text
    assert "Diagnostics Package" in r.text
    assert "Error codes" in r.text
    for href in ('href="/cmtrace"', 'href="/diagnostics"', 'href="/errorcodes"'):
        assert href in r.text
    # The homepage has its own upload dropzone (no sample-logs demo anymore).
    assert 'enctype="multipart/form-data"' in r.text
    assert 'id="drop"' in r.text
    assert 'action="/demo"' not in r.text
    assert "How it works" in r.text
    # Cross-promo link in the header, opened safely in a new tab.
    assert 'https://payloadkit.app' in r.text
    assert 'rel="noopener"' in r.text


def test_csp_allows_same_origin_fetch_and_images(client):
    """The diag page polls /status with fetch() and the landing page loads
    /static screenshots; both need an explicit CSP allowance because
    default-src is 'none'."""
    csp = client.get("/").headers["content-security-policy"]
    assert "connect-src 'self'" in csp
    assert "img-src 'self'" in csp


def test_static_screenshots_served(client):
    r = client.get("/static/timeline.png")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"


def test_standalone_timeline_removed(client):
    # Timeline is only available inside a diagnostics package now.
    assert client.get("/timeline").status_code == 404
    assert client.post("/analyze").status_code == 404
    assert client.post("/demo").status_code == 404


@pytest.mark.parametrize("path,action", [
    ("/cmtrace", "/cmtrace-view"),
])
def test_upload_pages_show_limits(client, path, action):
    r = client.get(path)
    assert r.status_code == 200
    assert "Max total upload" in r.text
    assert f'action="{action}"' in r.text
    assert "formaction" not in r.text  # single submit button per tool


def test_history_section_on_upload_pages(client):
    for path in ("/", "/cmtrace"):
        r = client.get(path)
        assert r.status_code == 200
        assert 'id="recent"' in r.text       # browser-side history list
        assert "sherlog.history" in r.text   # localStorage key
        # History prunes vanished jobs via the status endpoint (a HEAD on
        # /result/<id> returns 405, not 404, so it never pruned).
        assert "/status'" in r.text and "method: 'HEAD'" not in r.text


def test_status_endpoint_404_for_missing_job(client):
    # The history-prune contract: a gone job's status is 404.
    assert client.get("/result/deadbeefdeadbeef/status").status_code == 404


def test_delete_job_removes_it_server_side(client):
    """The history 'Delete all' calls POST /result/<id>/delete per job."""
    r = client.post(
        "/cmtrace-view",
        files={"files": ("a.log", b"<![LOG[hi]LOG]!><time=\"1\" date=\"2\" "
                                  b"component=\"C\" type=\"1\" thread=\"3\">",
                         "text/plain")},
        follow_redirects=False,
    )
    job_id = r.headers["location"].rstrip("/").split("/")[2]
    assert client.get(f"/result/{job_id}/status").status_code == 200
    d = client.post(f"/result/{job_id}/delete")
    assert d.status_code == 200 and d.json()["deleted"] is True
    assert client.get(f"/result/{job_id}/status").status_code == 404
    # The homepage history wires the button to this endpoint.
    assert 'id="recent-clear"' in client.get("/").text


def test_inbox_delete_all(upload_client):
    import app as app_module
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    pkg = buf.getvalue()
    job_id = upload_client.post(
        "/api/diagnostics", content=pkg,
        headers={"X-Upload-Token": _TOK, "Content-Type": "application/zip"},
    ).json()["job_id"]
    assert "id=\"delall\"" in upload_client.get("/inbox", params={"token": _TOK}).text
    d = upload_client.post("/inbox/delete", headers={"X-Upload-Token": _TOK})
    assert d.status_code == 200 and d.json()["deleted"] == 1
    assert app_module.read_status(job_id) is None      # gone from disk
    assert "PC01" not in upload_client.get("/inbox", params={"token": _TOK}).text
    # A too-short token is rejected.
    assert upload_client.post("/inbox/delete",
                              headers={"X-Upload-Token": "short"}).status_code == 401


def test_inbox_delete_disabled_by_default(client):
    assert client.post("/inbox/delete",
                       headers={"X-Upload-Token": "a" * 30}).status_code == 404


def test_result_pages_record_history(client):
    # Logs-only flow: CMTRACE_PAGE embeds a history-record snippet.
    r = client.post(
        "/cmtrace-view",
        files={"files": ("a.log", b"<![LOG[hi]LOG]!><time=\"1\" date=\"2\" "
                                  b"component=\"C\" context=\"\" type=\"1\" "
                                  b"thread=\"3\" file=\"\">", "text/plain")},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert "sherlog.history" in r.text
    assert '"tool": "logs"' in r.text
    assert '"a.log"' in r.text  # original upload name, not the staged path
    job_id = r.url.path.split("/")[2]
    assert f'"id": "{job_id}"' in r.text


@pytest.mark.skipif(not __import__("shutil").which("pwsh"),
                    reason="needs PowerShell (pwsh) for the real analysis")
def test_full_flow_diagnostics_runs_timeline(client):
    """Timeline now only runs inside a diagnostics package: upload a zip with
    IME logs, the diag job runs the analysis, and /result/<id>/timeline shows
    the native summary."""
    import app as app_module
    data = _zip_of_testdata()
    r = client.post(
        "/diagnostics-analyze",
        files={"files": ("IntuneDiag.zip", data, "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    location = r.headers["location"]
    assert location.startswith("/result/")
    job_id = location.rstrip("/").rsplit("/", 1)[-1]
    assert client.get(location).status_code == 200    # diagnostics page renders

    # Wait for the in-package timeline analysis to finish.
    deadline = time.time() + 300
    while True:
        analysis = client.get(f"/result/{job_id}/status").json().get("analysis")
        if analysis not in ("queued", "running"):
            break
        if time.time() > deadline:
            raise AssertionError("analysis did not finish")
        time.sleep(1.0)
    assert analysis == "done"

    summary_file = app_module.job_dir(job_id) / "output" / "summary.json"
    assert summary_file.is_file()
    model = app_module.read_summary(job_id)
    assert model is not None and model["parse_ok"] and model["counts"]

    # The timeline report page (inside the diagnostics job) shows the summary.
    rep = client.get(f"/result/{job_id}/timeline").text
    assert "Analysis summary" in rep
    assert "Win32App" in rep


def test_oversized_upload_rejected(client):
    # MAX_UPLOAD_MB=1 in the fixture; send ~2 MB.
    big = b"x" * (2 * 1024 * 1024)
    r = client.post(
        "/cmtrace-view",
        files={"files": ("big.log", big, "text/plain")},
        follow_redirects=False,
    )
    assert r.status_code == 413


def test_wrong_extension_rejected(client):
    r = client.post(
        "/cmtrace-view",
        files={"files": ("evil.exe", b"nope", "application/octet-stream")},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_cmtrace_viewer(client):
    data = _zip_of_testdata()
    r = client.post(
        "/cmtrace-view",
        files={"files": ("logs.zip", data, "application/zip")},
        follow_redirects=False,
    )
    location = r.headers["location"]   # -> /result/<id>/cmtrace (no analysis)
    job_id = location.rstrip("/").split("/")[2]

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
    assert "<th>Component" not in html and '<th class="c">' not in html  # structured columns hidden
    assert 'class="err"' in html      # ERROR line coloured

    struct, _ = app_module.parse_cmtrace(
        '<![LOG[hi]LOG]!><time="1" date="2" component="C" context="" '
        'type="2" thread="3" file="">'
    )
    html2 = app_module.render_cmtrace_view("ime.log", struct, False)
    assert "Component" in html2       # full CMTrace table
    assert 'class="warn"' in html2


def test_cmtrace_severity_filter_and_legend():
    import app as app_module
    records, _ = app_module.parse_cmtrace(
        '<![LOG[info]LOG]!><time="1" date="2" component="C" context="" '
        'type="1" thread="3" file="">\n'
        '<![LOG[warn]LOG]!><time="1" date="2" component="C" context="" '
        'type="2" thread="3" file="">\n'
        '<![LOG[err]LOG]!><time="1" date="2" component="C" context="" '
        'type="3" thread="3" file="">'
    )
    html = app_module.render_cmtrace_view("ime.log", records, False)
    assert 'id="sev"' in html                  # severity dropdown
    assert 'class="legend"' in html            # colour legend in the bar
    assert 'class="warn"' in html
    assert 'class="err"' in html

    # Plain (non-CMTrace) view keeps the severity filter too.
    plain, _ = app_module.parse_cmtrace("ERROR: boom\nall good\n")
    html2 = app_module.render_cmtrace_view("cmd.log", plain, False)
    assert 'id="sev"' in html2


def test_cmtrace_detail_panel():
    import app as app_module
    # Core error codes ship with a plain-language explanation.
    assert "0x87D1041C" in app_module.ERROR_CODES
    assert "0x80070643" in app_module.ERROR_CODES

    records, _ = app_module.parse_cmtrace(
        '<![LOG[Install failed with 0x87D1041C]LOG]!><time="1" date="2" '
        'component="C" context="" type="3" thread="3" file="">'
    )
    html = app_module.render_cmtrace_view("ime.log", records, False)
    assert 'id="detail"' in html              # click-to-read panel
    assert 'id="d-explain"' in html
    assert "0x87D1041C" in html               # codes JSON embedded for lookup

    # Plain view gets the panel too.
    plain, _ = app_module.parse_cmtrace("exit code 1603\n")
    html2 = app_module.render_cmtrace_view("cmd.log", plain, False)
    assert 'id="detail"' in html2


_SYNTHETIC_REPORT = """
<html><body>
<table id="ObservedTimeline">
<tr><th>Index</th><th>Date</th><th>Status</th><th>Type</th><th>Intent</th>
<th>Detail</th><th>Seconds</th><th>LogEntry</th><th>Color</th><th>DetailToolTip</th></tr>
<tr><td>1</td><td>2023-09-13 08:46:48</td><td>Success</td><td>Win32App</td>
<td>Required Install</td><td>7-Zip (0 Success)</td><td>46</td><td>Line 8</td>
<td>Green</td><td></td></tr>
<tr><td>2</td><td>2023-09-13 08:47:14</td><td>Failed</td><td>Win32App</td>
<td>Required Install</td><td>BadApp install failed 0x87D1041C</td><td></td>
<td>Line 17</td><td>Red</td><td></td></tr>
<tr><td>3</td><td>2023-09-13 08:47:20</td><td>Warning</td><td>Powershell script</td>
<td>Execute</td><td>slow script</td><td>200</td><td>Line 20</td><td>Yellow</td><td></td></tr>
<tr><td>4</td><td>2023-09-13 08:48:00</td><td>Failed</td><td>Win32App</td>
<td>Required Install</td><td>hostile <detail with="raw tags"> exit code 1603 &amp; more
multi-line</td><td></td><td>Line 30</td><td>Red</td><td>tooltip
spanning <lines></td></tr>
</table>
<h2>App Download Statistics</h2>
<table id="ApplicationDownloadStatistics">
<tr><th>AppType</th><th>AppName</th><th>DL Sec</th><th>Size (MB)</th>
<th>MB/s</th><th>Delivery Optimization %</th></tr>
<tr><td>Win32App</td><td>7-Zip</td><td>3</td><td>2.1</td><td>0.7</td><td>0%</td></tr>
</table>
</body></html>
"""


def test_parse_report_summary_synthetic():
    import app as app_module

    s = app_module.parse_report_summary(_SYNTHETIC_REPORT)
    assert s.parse_ok
    assert len(s.timeline) == 4
    assert s.timeline[0]["status"] == "Success"
    assert s.timeline[0]["type"] == "Win32App"
    # Hostile row: raw pseudo-tags inside Detail must not break cell tracking.
    hostile = s.timeline[3]
    assert hostile["status"] == "Failed"
    assert "exit code 1603" in hostile["detail"]
    assert len(s.downloads) == 1
    assert s.downloads[0]["app_name"] == "7-Zip"

    model = app_module.summarize(s)
    win32 = next(c for c in model["counts"] if c["type"] == "Win32App")
    assert win32["success"] == 1 and win32["failed"] == 2
    assert model["warnings"] == 1
    assert len(model["failed_items"]) == 2
    codes = {e["code"] for e in model["top_errors"]}
    assert "0x87D1041C" in codes and "1603" in codes
    # Drill-down items keep every outcome row, success and warnings included.
    statuses = [i["status"] for i in model["items"]]
    assert statuses.count("Failed") == 2
    assert "Success" in statuses and "Warning" in statuses


def test_parse_report_summary_garbage_degrades():
    import app as app_module

    s = app_module.parse_report_summary("not html at all <<<>>")
    assert s.parse_ok and s.timeline == [] and s.downloads == []
    assert app_module.render_summary_panel(app_module.summarize(s)) == ""
    assert app_module.render_summary_panel(None) == ""


def test_find_error_codes():
    import app as app_module

    found = app_module.find_error_codes(
        "failed 0x87d1041c then -2016345060 and exit code 1603")
    assert "0x87D1041C" in found
    assert "1603" in found
    assert len(found) == 2  # signed decimal maps to the same hex code


def test_render_summary_panel_escapes():
    import app as app_module

    model = {
        "parse_ok": True,
        "counts": [{"type": "Win32App", "success": 0, "failed": 1}],
        "warnings": 0, "not_detected": 0,
        "failed_items": [{"date": "d", "type": "Win32App", "intent": "i",
                          "detail": '<script>alert(1)</script>'}],
        "top_errors": [], "downloads": [],
    }
    html = app_module.render_summary_panel(model)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert 'class="summary" open' in html
    # Legacy model (no `items`): chips not clickable, failed table rendered.
    assert "data-type=" not in html
    assert "Failed items" in html


def test_render_summary_panel_drilldown():
    import app as app_module

    model = {
        "parse_ok": True,
        "counts": [{"type": "Powershell script", "success": 9, "failed": 3}],
        "warnings": 0, "not_detected": 2,
        "failed_items": [],
        "items": [
            {"date": "d1", "type": "Powershell script", "intent": "Execute",
             "status": "Success", "detail": "ok"},
            {"date": "d2", "type": "Powershell script", "intent": "Execute",
             "status": "Failed", "detail": "boom"},
            {"date": "d3", "type": "Win32App", "intent": "Install",
             "status": "Not Detected", "detail": "gone"},
        ],
        "top_errors": [], "downloads": [],
    }
    html = app_module.render_summary_panel(model)
    # Chips carry the drill-down filters.
    assert 'data-type="Powershell script"' in html
    assert 'data-status="Not Detected"' in html
    # The items table holds every outcome row, success included.
    assert 'class="st-ok">Success' in html
    assert 'class="st-bad">Failed' in html
    assert 'class="st-nd">Not Detected' in html
    assert html.count('<tr class="it"') == 3


def test_error_codes_shape_and_coverage():
    import re

    import app as app_module

    # Keys must match what the client-side lookup produces: '0x' + uppercase
    # hex for HRESULTs, bare 3-4 digit decimals for MSI exit codes.
    for key in app_module.ERROR_CODES:
        assert re.fullmatch(r"0x[0-9A-F]{8}|\d{3,4}", key), key
    assert len(app_module.ERROR_CODES) >= 95
    # One representative per added group.
    for code in ("0x87D00324", "0x87D5507B", "0x80D02002", "0x8007007E",
                 "0x80073CFF", "0x80072F05", "1619"):
        assert code in app_module.ERROR_CODES, code


def test_run_script_passes_report_flags():
    # Guard against accidental removal of the always-on report flags.
    script = (REPO_ROOT / "scripts" / "run-analysis.sh").read_text()
    for flag in (
        "-ShowErrorsInReport",
        "-ShowErrorsSummary",
        "-ShowAllTimelineEvents",
        "-ShowStdOutInReport",
        "-LongRunningPowershellNotifyThreshold",
    ):
        assert flag in script
    assert "LONG_SCRIPT_THRESHOLD_SECONDS" in script


def test_zip_slip_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.log", "pwned")
    r = client.post(
        "/cmtrace-view",
        files={"files": ("evil.zip", buf.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 400


# --- Diagnostics package tool --------------------------------------------------

def _u16(s: str) -> bytes:
    """UTF-16LE with BOM, like PowerShell 5.1 Out-File / reg export."""
    return s.encode("utf-16")


_DSREGCMD = """\
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
                  DeviceId : 11111111-2222-3333-4444-555555555555
                TenantName : Contoso

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES

+----------------------------------------------------------------------+
| Management                                                           |
+----------------------------------------------------------------------+

                    MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
"""

_ENDPOINTS = """\
Endpoint                              Reachable RemoteIP
--------                              --------- --------
login.microsoftonline.com             True      20.190.160.2
graph.microsoft.com                   False
"""

_SERVICE = """\
Name                      Status StartType
----                      ------ ---------
IntuneManagementExtension Running Automatic
"""

_CERTS = """\
Subject    : CN=11111111-2222-3333-4444-555555555555
NotAfter   : 1/1/2027 10:00:00
Thumbprint : AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
Expired    : False

Subject    : CN=OldIntuneCert
NotAfter   : 1/1/2024 10:00:00
Thumbprint : 9999888877776666555544443333222211110000
Expired    : True
"""

_REG = """\
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments]
"ProviderID"="MS DM Server"
"""


def _zip_of_diag_package() -> bytes:
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as zf:
        zf.writestr("areas/info.txt", "mdm diag area info")
        zf.writestr("areas/blob.cab", b"\x00binary cab\x00")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("_SUMMARY.txt", _u16(
            " Device   : TESTPC-01\n Date     : 06/11/2026 10:00:00\n"
            "  AzureAdJoined : YES\n"))
        zf.writestr("Identity/dsregcmd-status.txt", _u16(_DSREGCMD))
        zf.writestr("Identity/certs-machine-overview.txt", _u16(_CERTS))
        zf.writestr("Network/endpoint-connectivity.txt", _u16(_ENDPOINTS))
        zf.writestr("Apps-IME/service-status.txt", _u16(_SERVICE))
        zf.writestr("Registry/Enrollments.reg", _u16(_REG))
        for log in TESTDATA.glob("*.log"):
            zf.writestr(f"Apps-IME/Logs/{log.name}", log.read_bytes())
        zf.writestr("MDM/MDMDiag-AllAreas.zip", nested.getvalue())
        zf.writestr("Defender/MpSupportFiles.cab", b"\x00cab\x00")
        zf.writestr("System/battery-report.html",
                     "<html><body>battery</body></html>")
    return buf.getvalue()


def test_diagnostics_upload_page(client):
    r = client.get("/diagnostics")
    assert r.status_code == 200
    assert 'action="/diagnostics-analyze"' in r.text
    assert 'accept=".zip"' in r.text
    assert "Max total upload" in r.text


def test_collect_script_shown_and_downloadable(client):
    page = client.get("/diagnostics")
    assert "Download Collect-IntuneDiagnostics.ps1" in page.text
    assert "View script source" in page.text
    assert "elevated" in page.text

    r = client.get("/collect-script")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert "Collect-IntuneDiagnostics.ps1" in r.headers["content-disposition"]
    assert "mdmdiagnosticstool" in r.text  # actual script content served


def test_landing_and_nav_show_diagnostics(client):
    r = client.get("/")
    assert "Diagnostics Package" in r.text
    assert 'href="/diagnostics"' in r.text


def test_dark_mode_toggle_on_every_page(client):
    for path in ("/", "/cmtrace", "/diagnostics"):
        page = client.get(path)
        assert "localStorage.getItem('sherlog.theme')" in page.text  # head init
        assert 'onclick="sherlogTheme()"' in page.text               # nav toggle
        assert "html.dark{" in page.text                             # dark palette


def test_about_dialog_on_every_page(client):
    for path in ("/", "/cmtrace", "/diagnostics"):
        page = client.get(path)
        assert 'id="about"' in page.text
        assert "Kris Mandemaker" in page.text
        assert "linkedin.com/in/kris-mandemaker" in page.text
        assert "mand-it.nl" in page.text
    photo = client.get("/static/kris.jpeg")
    assert photo.status_code == 200
    assert photo.headers["content-type"].startswith("image/")


def test_diag_upload_requires_single_zip(client):
    r = client.post(
        "/diagnostics-analyze",
        files=[("files", ("a.log", b"hi", "text/plain"))],
        follow_redirects=False,
    )
    assert r.status_code == 400

    r = client.post(
        "/diagnostics-analyze",
        files=[("files", ("a.zip", _zip_of_diag_package(), "application/zip")),
               ("files", ("b.zip", _zip_of_diag_package(), "application/zip"))],
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_diag_zip_without_viewable_files_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("only.cab", b"\x00")
    r = client.post(
        "/diagnostics-analyze",
        files={"files": ("diag.zip", buf.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 400


def _wait_for_analysis(client, job_id: str, timeout: float = 300.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = client.get(f"/result/{job_id}/status").json()
        if st["analysis"] not in ("queued", "running"):
            return st["analysis"]
        time.sleep(1.0)
    raise AssertionError("diagnostics analysis did not finish within timeout")


def test_diag_full_flow(client):
    r = client.post(
        "/diagnostics-analyze",
        files={"files": ("IntuneDiag-TESTPC-01.zip", _zip_of_diag_package(),
                         "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    job_id = r.headers["location"].rstrip("/").rsplit("/", 1)[-1]

    # Dashboard + browser are available immediately (state "ready").
    page = client.get(f"/result/{job_id}")
    assert page.status_code == 200
    assert "Device health" in page.text
    assert "Entra joined" in page.text
    assert "graph.microsoft.com" in page.text       # unreachable endpoint named
    assert "1 of 2 expired" in page.text            # expired machine cert
    assert "Enrollments.reg" in page.text           # UTF-16 file in the tree
    assert "info.txt" in page.text                  # nested-zip member extracted
    assert "MpSupportFiles.cab" in page.text        # listed …
    assert 'class="file disabled"' in page.text     # … but not clickable
    assert '"tool": "diag"' in page.text            # history entry
    assert '"IntuneDiag-TESTPC-01.zip"' in page.text  # original upload name

    # Dashboard model on disk: ok/bad/warn statuses derived from the package.
    import app as app_module
    dash = app_module.read_dashboard(job_id)
    by_label = {c["label"]: c for c in dash["checks"]}
    assert by_label["Entra joined"]["status"] == "ok"
    assert by_label["Entra PRT"]["status"] == "ok"
    assert by_label["MDM enrollment"]["status"] == "ok"
    assert by_label["IME service"]["status"] == "ok"
    assert by_label["Intune/Entra endpoints"]["status"] == "warn"
    assert by_label["Machine certificates"]["status"] == "warn"

    # File viewer: UTF-16 .reg decodes readable, html is sandboxed.
    view = client.get(f"/result/{job_id}/files/view",
                      params={"file": "Registry/Enrollments.reg"})
    assert view.status_code == 200
    assert "Windows Registry Editor" in view.text
    assert "sandbox" in view.headers.get("content-security-policy", "")
    assert "html.dark{" in view.text  # sandboxed viewer ships the dark palette

    html_view = client.get(f"/result/{job_id}/files/view",
                           params={"file": "System/battery-report.html"})
    assert html_view.status_code == 200
    assert "sandbox" in html_view.headers.get("content-security-policy", "")

    # Membership check: traversal, unknown and non-extracted files all 404.
    for bad in ("../app.py", "nope.txt", "Defender/MpSupportFiles.cab"):
        assert client.get(f"/result/{job_id}/files/view",
                          params={"file": bad}).status_code == 404

    # CMTrace viewer works on the diag job's logs too.
    cm = client.get(f"/result/{job_id}/cmtrace")
    assert cm.status_code == 200
    assert "IntuneManagementExtension.log" in cm.text

    # The timeline analysis on Apps-IME/Logs completes and serves a report.
    assert _wait_for_analysis(client, job_id) == "done"
    page2 = client.get(f"/result/{job_id}")
    assert "Timeline analysis ready" in page2.text
    assert "Analysis summary" in page2.text          # inline summary panel
    timeline = client.get(f"/result/{job_id}/timeline")
    assert timeline.status_code == 200
    report = client.get(f"/result/{job_id}/report")
    assert report.status_code == 200
    assert "Win32App" in report.text


def _make_cab(files: dict) -> bytes:
    """Minimal single-folder, uncompressed .cab (cabextract-compatible).

    Member names use the cab-native backslash separator for subdirectories.
    """
    import struct
    data = b"".join(files.values())
    cffile_block = b""
    off = 0
    for name, raw in files.items():
        cffile_block += struct.pack("<IIHHHH", len(raw), off, 0,
                                    0x54AB, 0x5C00, 0x20) + name.encode() + b"\x00"
        off += len(raw)
    files_off = 36 + 8                      # CFHEADER + one CFFOLDER
    data_off = files_off + len(cffile_block)
    cfdata = struct.pack("<IHH", 0, len(data), len(data)) + data
    header = b"MSCF" + struct.pack(
        "<IIIIIBBHHHHH", 0, data_off + len(cfdata), 0, files_off,
        0, 3, 1, 1, len(files), 0, 0x1234, 0)
    folder = struct.pack("<IHH", data_off, 1, 0)
    return header + folder + cffile_block + cfdata


def _zip_with_cab(cab: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", _u16(_DSREGCMD))
        zf.writestr("Defender/MpSupportFiles.cab", cab)
    return buf.getvalue()


def _upload_diag(client, payload: bytes) -> str:
    r = client.post(
        "/diagnostics-analyze",
        files={"files": ("diag.zip", payload, "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    return r.headers["location"].rstrip("/").rsplit("/", 1)[-1]


@pytest.mark.skipif(not __import__("shutil").which("cabextract"),
                    reason="cabextract not installed")
def test_diag_cab_expanded(client):
    cab = _make_cab({
        "MPLog-1.log": b"<![LOG[defender says hi]LOG]!"
                       b"<time=\"10:00:00.000+000\" date=\"06-11-2026\" "
                       b"component=\"MP\" context=\"\" type=\"1\" "
                       b"thread=\"1\" file=\"x\">\n",
        "Support\\trace.etl": b"\x00etl\x00",
    })
    job_id = _upload_diag(client, _zip_with_cab(cab))

    page = client.get(f"/result/{job_id}")
    # Cab replaced by a folder with its viewable contents …
    assert "MPLog-1.log" in page.text
    assert 'data-file="Defender/MpSupportFiles.cab"' not in page.text
    # … and the unviewable .etl inside is listed (disabled) as skipped.
    import app as app_module
    status = app_module.read_status(job_id)
    skipped = {s["name"] for s in status["skipped"]}
    assert "Defender/MpSupportFiles.cab!/Support/trace.etl" in skipped

    view = client.get(f"/result/{job_id}/files/view",
                      params={"file": "Defender/MpSupportFiles/MPLog-1.log"})
    assert view.status_code == 200
    assert "defender says hi" in view.text


def test_diag_corrupt_cab_skipped_not_fatal(client):
    job_id = _upload_diag(client, _zip_with_cab(b"\x00not a cab\x00"))
    page = client.get(f"/result/{job_id}")
    assert page.status_code == 200
    assert "MpSupportFiles.cab" in page.text        # listed …
    assert 'class="file disabled"' in page.text     # … but not clickable
    import app as app_module
    status = app_module.read_status(job_id)
    assert "Defender/MpSupportFiles.cab" in {s["name"] for s in status["skipped"]}


def test_diag_cab_without_cabextract_skipped(client, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "CABEXTRACT", None)
    cab = _make_cab({"MPLog-1.log": b"hello"})
    job_id = _upload_diag(client, _zip_with_cab(cab))
    page = client.get(f"/result/{job_id}")
    assert "MpSupportFiles.cab" in page.text
    assert "MPLog-1.log" not in page.text           # nothing expanded
    status = app_module.read_status(job_id)
    assert "Defender/MpSupportFiles.cab" in {s["name"] for s in status["skipped"]}


def test_interrupted_jobs_marked_failed(client):
    # Simulate jobs left behind by a previous process: a timeline job stuck
    # on "running" and a diag job whose analysis is stuck on "queued".
    import app as app_module
    t_job, d_job = "deadbeef" * 4, "cafebabe" * 4
    for j in (t_job, d_job):
        (app_module.job_dir(j) / "input").mkdir(parents=True)
    app_module.write_status(t_job, state="running")
    app_module.write_status(d_job, kind="diag", state="ready",
                            analysis={"state": "queued"})

    assert app_module.fail_interrupted_jobs() == 2
    assert app_module.read_status(t_job)["state"] == "failed"
    diag = app_module.read_status(d_job)
    assert diag["state"] == "ready"  # package stays browsable
    assert diag["analysis"]["state"] == "failed"
    assert "restart" in diag["analysis"]["stderr"]

    # Idempotent: done/failed/none states are left alone.
    assert app_module.fail_interrupted_jobs() == 0


def test_read_text_tolerant_encodings(tmp_path):
    import app as app_module
    import codecs
    cases = {
        "utf16le.txt": "héllo wörld".encode("utf-16"),          # BOM + LE
        "utf16be.txt": codecs.BOM_UTF16_BE + "héllo wörld".encode("utf-16-be"),
        "utf8bom.txt": "héllo wörld".encode("utf-8-sig"),
        "utf8.txt": "héllo wörld".encode("utf-8"),
        "utf16le_nobom.txt": "héllo wörld".encode("utf-16-le"),
    }
    for name, data in cases.items():
        p = tmp_path / name
        p.write_bytes(data)
        assert app_module.read_text_tolerant(p) == "héllo wörld", name


def test_dashboard_parsers():
    import app as app_module

    info = app_module.parse_dsregcmd(_DSREGCMD)
    assert info["AzureAdJoined"] == "YES"
    assert info["AzureAdPrt"] == "YES"
    assert "manage.microsoft.com" in info["MdmUrl"]
    assert info["TenantName"] == "Contoso"

    eps = app_module.parse_endpoint_connectivity(_ENDPOINTS)
    assert {e["endpoint"]: e["reachable"] for e in eps} == {
        "login.microsoftonline.com": True, "graph.microsoft.com": False}

    assert app_module.parse_service_status(_SERVICE) is True
    assert app_module.parse_service_status("") is None
    assert app_module.parse_service_status(
        "IntuneManagementExtension Stopped Manual") is False

    certs = app_module.parse_cert_overview(_CERTS)
    assert len(certs) == 2
    assert [c["expired"] for c in certs] == [False, True]

    # Garbage in -> empty out, never raises.
    assert app_module.parse_dsregcmd("\x00\x01 nonsense") == {}
    assert app_module.parse_endpoint_connectivity("garbage") == []
    assert app_module.parse_cert_overview("garbage") == []


def test_build_dashboard_missing_files_unknown(tmp_path):
    import app as app_module
    dash = app_module.build_dashboard(tmp_path)  # empty package
    assert all(c["status"] == "unknown" for c in dash["checks"])


def test_build_dashboard_dutch_names(tmp_path):
    import app as app_module
    (tmp_path / "Identity").mkdir()
    (tmp_path / "Identity" / "certs-machine-overzicht.txt").write_bytes(_u16(
        "Subject    : CN=X\nThumbprint : AB\nVerlopen   : True\n"))
    (tmp_path / "_SAMENVATTING.txt").write_bytes(_u16(
        "  AzureAdJoined : YES\n  AzureAdPrt    : NO\n"))
    dash = app_module.build_dashboard(tmp_path)
    by_label = {c["label"]: c for c in dash["checks"]}
    assert by_label["Entra joined"]["status"] == "ok"
    assert by_label["Entra PRT"]["status"] == "bad"
    assert by_label["Machine certificates"]["status"] == "warn"


def test_dashboard_source_links(tmp_path):
    """Checks carry src + line pointing at the evidence row as the file
    viewer numbers it (blank lines are skipped by the viewer)."""
    import app as app_module
    (tmp_path / "Identity").mkdir()
    (tmp_path / "Apps-IME").mkdir()
    (tmp_path / "Identity" / "dsregcmd-status.txt").write_text(
        "\n\nDevice State\n\n     AzureAdJoined : YES\n     AzureAdPrt : NO\n",
        encoding="utf-8")
    (tmp_path / "Apps-IME" / "service-status.txt").write_text(
        "\nName Status StartType\n---- ------ ---------\n"
        "IntuneManagementExtension Running Automatic\n", encoding="utf-8")

    dash = app_module.build_dashboard(tmp_path)
    by_label = {c["label"]: c for c in dash["checks"]}

    joined = by_label["Entra joined"]
    assert joined["src"] == "Identity/dsregcmd-status.txt"
    assert joined["line"] == 2  # "Device State" is viewer row 1, blanks skipped

    svc = by_label["IME service"]
    assert svc["src"] == "Apps-IME/service-status.txt"
    assert svc["line"] == 3  # header + separator rows precede the service row

    # Missing source file -> no link, status unknown (total parsers).
    endpoints = by_label["Intune/Entra endpoints"]
    assert endpoints["status"] == "unknown"
    assert "src" not in endpoints
    assert by_label["Installed apps"]["status"] == "unknown"


def test_dashboard_installed_apps(tmp_path):
    import app as app_module
    (tmp_path / "Apps-IME").mkdir()
    (tmp_path / "Apps-IME" / "installed-apps.txt").write_text(
        "\n"
        "DisplayName        DisplayVersion Publisher             InstallDate\n"
        "-----------        -------------- ---------             -----------\n"
        "7-Zip 23.01 (x64)  23.01          Igor Pavlov           20230815\n"
        "Company Portal     11.2.205.0     Microsoft Corporation\n"
        "\n"
        "Notepad++ (64-bit) 8.6            Notepad++ Team        20240101\n",
        encoding="utf-8")

    apps = app_module.parse_installed_apps(
        (tmp_path / "Apps-IME" / "installed-apps.txt").read_text())
    assert len(apps) == 3
    assert apps[0]["DisplayName"] == "7-Zip 23.01 (x64)"
    assert apps[1]["Publisher"] == "Microsoft Corporation"

    dash = app_module.build_dashboard(tmp_path)
    by_label = {c["label"]: c for c in dash["checks"]}
    card = by_label["Installed apps"]
    assert card["status"] == "ok"
    assert card["detail"].startswith("3 apps")
    assert card["src"] == "Apps-IME/installed-apps.txt"


def test_extract_zip_members_nested_and_policy(tmp_path):
    import app as app_module
    nested2 = io.BytesIO()
    with zipfile.ZipFile(nested2, "w") as zf:
        zf.writestr("deep.txt", "too deep")
    nested1 = io.BytesIO()
    with zipfile.ZipFile(nested1, "w") as zf:
        zf.writestr("inner.txt", "inner")
        zf.writestr("deeper.zip", nested2.getvalue())
        zf.writestr("inner.cab", b"\x00")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("top.txt", "top")
        zf.writestr("MDM/nested.zip", nested1.getvalue())
        zf.writestr("top.etl", b"\x00")

    dest = tmp_path / "out"
    count, skipped = app_module.extract_zip_members(
        outer, dest, app_module.DIAG_KEEP_EXTS)
    assert count == 2  # top.txt + inner.txt; depth-2 zip and binaries skipped
    assert (dest / "top.txt").is_file()
    assert (dest / "MDM" / "nested" / "inner.txt").is_file()
    assert not list(dest.rglob("deep.txt"))
    names = {s["name"] for s in skipped}
    assert "top.etl" in names
    assert "MDM/nested.zip!/inner.cab" in names
    assert "MDM/nested.zip!/deeper.zip" in names
    assert not (dest / "MDM" / "nested.zip").exists()  # temp zip removed


def test_extract_zip_members_backslash_separators(tmp_path):
    """Windows PowerShell 5.1 Compress-Archive writes `\\` separators in zip
    entry names; they must extract as directories, not flat backslash files."""
    import app as app_module
    z = tmp_path / "diag.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("_SUMMARY.txt", "Device : X\n")
        zf.writestr("Apps-IME\\service-status.txt", "Running")
        zf.writestr("Apps-IME\\Logs\\IntuneManagementExtension.log", "log")
    dest = tmp_path / "out"
    count, _skipped = app_module.extract_zip_members(
        z, dest, app_module.DIAG_KEEP_EXTS)
    assert count == 3
    assert (dest / "Apps-IME" / "service-status.txt").is_file()
    assert (dest / "Apps-IME" / "Logs" / "IntuneManagementExtension.log").is_file()
    assert app_module.find_ime_log_dir(dest) == dest / "Apps-IME" / "Logs"
    by_label = {c["label"]: c
                for c in app_module.build_dashboard(dest)["checks"]}
    assert by_label["IME service"]["status"] == "ok"


def test_extract_zip_members_nested_zip_slip(tmp_path):
    import app as app_module
    evil_inner = io.BytesIO()
    with zipfile.ZipFile(evil_inner, "w") as zf:
        zf.writestr("../../../escape.txt", "pwned")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("evil.zip", evil_inner.getvalue())
    with pytest.raises(app_module.UploadError):
        app_module.extract_zip_members(outer, tmp_path / "out",
                                       app_module.DIAG_KEEP_EXTS)


def test_extract_zip_members_shared_bomb_budget(tmp_path, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "MAX_UNCOMPRESSED_BYTES", 1024)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("b.txt", "y" * 600)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "x" * 600)
        zf.writestr("nested.zip", inner.getvalue())
    # 600 + len(nested.zip) + 600 > 1024: the budget must carry across nesting.
    with pytest.raises(app_module.UploadError):
        app_module.extract_zip_members(outer, tmp_path / "out",
                                       app_module.DIAG_KEEP_EXTS)


def test_render_file_tree_disabled_entries():
    import app as app_module
    html = app_module.render_file_tree(
        ["Registry/Enrollments.reg"], ["Defender/MpSupportFiles.cab"])
    assert 'data-file="Registry/Enrollments.reg"' in html
    assert 'class="file disabled"' in html
    assert "MpSupportFiles.cab" in html
    assert 'data-file="Defender/MpSupportFiles.cab"' not in html  # not clickable


_EVTX_XML = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"/>
    <EventID Qualifiers="0">404</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-01-02T03:04:05.678901Z"/>
  </System>
  <EventData>
    <Data Name="Error">0x87D1041C</Data>
    <Data Name="Detail">install failed</Data>
  </EventData>
</Event>
"""


def test_evtx_xml_to_record():
    import app as app_module
    rec = app_module.evtx_xml_to_record(_EVTX_XML)
    assert rec["time"] == "2026-01-02 03:04:05"
    assert rec["event_id"] == "404"
    assert rec["level"] == "2" and rec["level_name"] == "Error"
    assert rec["provider"].startswith("Microsoft-Windows-DeviceManagement")
    assert "Error: 0x87D1041C" in rec["msg"]
    assert "Detail: install failed" in rec["msg"]

    # RenderingInfo message wins over raw EventData when present.
    with_msg = _EVTX_XML.replace(
        "</Event>",
        "<RenderingInfo Culture=\"en-US\"><Message>Readable text</Message>"
        "</RenderingInfo></Event>")
    assert app_module.evtx_xml_to_record(with_msg)["msg"] == "Readable text"

    # Malformed XML degrades to a raw record, never raises.
    bad = app_module.evtx_xml_to_record("<not<xml")
    assert bad["msg"].startswith("<not<xml")


def test_render_evtx_view():
    import app as app_module
    rec = app_module.evtx_xml_to_record(_EVTX_XML)
    html = app_module.render_evtx_view("EventLogs/System.evtx", [rec], True)
    assert "All providers" in html
    assert 'class="err"' in html                 # level 2 -> error colouring
    assert "0x87D1041C" in html
    assert "EVTX_MAX_EVENTS" in html             # truncation note
    assert 'id="detail"' in html                 # shared detail panel


@pytest.mark.skipif(not (TESTDATA / "sample.evtx").is_file(),
                    reason="no sample.evtx in testdata")
def test_parse_evtx_file_sample():
    pytest.importorskip("Evtx")
    import app as app_module
    records, _truncated = app_module.parse_evtx_file(TESTDATA / "sample.evtx")
    assert records
    assert any(r["event_id"] for r in records)


# --- Diagnostics-package registry/network parsers (Intune Debug Toolkit
#     inspired dashboard cards) --------------------------------------------

_WIN32_REG = (
    "Windows Registry Editor Version 5.00\r\n\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IntuneManagementExtension"
    "\\Win32Apps\\{11111111-1111-1111-1111-111111111111}"
    "\\{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}_1]\r\n"
    "\"Intent\"=\"3\"\r\n\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IntuneManagementExtension"
    "\\Win32Apps\\{11111111-1111-1111-1111-111111111111}"
    "\\{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}_1\\ComplianceStateMessage]\r\n"
    "\"ComplianceStateMessage\"=\"{\\\"ComplianceState\\\":1,\\\"DesiredState\\\":2,"
    "\\\"ErrorCode\\\":null}\"\r\n\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IntuneManagementExtension"
    "\\Win32Apps\\{11111111-1111-1111-1111-111111111111}"
    "\\{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}_1\\EnforcementStateMessage]\r\n"
    "\"EnforcementStateMessage\"=\"{\\\"EnforcementState\\\":1000,\\\"ErrorCode\\\":null}\"\r\n\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IntuneManagementExtension"
    "\\Win32Apps\\{11111111-1111-1111-1111-111111111111}"
    "\\{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}_4\\ComplianceStateMessage]\r\n"
    "\"ComplianceStateMessage\"=\"{\\\"ComplianceState\\\":4,\\\"ErrorCode\\\":-2016345060}\"\r\n\r\n"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IntuneManagementExtension"
    "\\Win32Apps\\{11111111-1111-1111-1111-111111111111}"
    "\\{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}_4\\EnforcementStateMessage]\r\n"
    "\"EnforcementStateMessage\"=\"{\\\"EnforcementState\\\":3000,\\\"ErrorCode\\\":-2016345060}\"\r\n"
)


def test_parse_reg_strings_and_dwords():
    import app as app_module
    reg = app_module.parse_reg(
        "[HKLM\\Test\\Key]\r\n\"S\"=\"a\\\\b \\\"q\\\"\"\r\n\"D\"=dword:0000001f\r\n")
    assert reg["HKLM\\Test\\Key"]["S"] == 'a\\b "q"'
    assert reg["HKLM\\Test\\Key"]["D"] == 31


def test_parse_reg_total_on_garbage():
    import app as app_module
    assert app_module.parse_reg("") == {}
    assert app_module.parse_reg("no keys here\n=oops\n") == {}


def test_hresult_code_normalizes():
    import app as app_module
    assert app_module.hresult_code(-2016345060) == "0x87D1041C"
    assert app_module.hresult_code(None) == ""
    assert app_module.hresult_code(0) == ""
    assert app_module.hresult_code("1603") == "1603"   # decimal MSI key


def test_parse_win32apps_joins_state_subkeys():
    import app as app_module
    apps = app_module.parse_win32apps(app_module.parse_reg(_WIN32_REG))
    assert len(apps) == 2
    failed = [a for a in apps if a["failed"]]
    assert len(failed) == 1
    bad = failed[0]
    assert bad["error_code"] == "0x87D1041C"
    assert bad["error_text"]                       # mapped to an explanation
    assert bad["enforcement"] == "Failed"
    ok = [a for a in apps if not a["failed"]][0]
    assert ok["compliance"] == "Installed"
    assert ok["enforcement"] == "Succeeded"


def test_parse_enrollments_flags_intune():
    import app as app_module
    reg = app_module.parse_reg(
        "[HKLM\\SOFTWARE\\Microsoft\\Enrollments\\{ee111111-1111-1111-1111-111111111111}]\r\n"
        "\"UPN\"=\"user@contoso.com\"\r\n\"ProviderID\"=\"MS DM Server\"\r\n"
        "\"EnrollmentState\"=dword:00000001\r\n"
        "\"DiscoveryServiceFullURL\"=\"https://enrollment.manage.microsoft.com/x\"\r\n")
    enrolls = app_module.parse_enrollments(reg)
    assert len(enrolls) == 1
    assert enrolls[0]["is_intune"] is True
    assert enrolls[0]["upn"] == "user@contoso.com"


def test_parse_policymanager_counts_settings():
    import app as app_module
    reg = app_module.parse_reg(
        "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\AboveLock]\r\n"
        "\"AllowX_WinningProvider\"=\"{p1}\"\r\n"
        "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Bitlocker]\r\n"
        "\"A_WinningProvider\"=\"{p1}\"\r\n\"B_WinningProvider\"=\"{p2}\"\r\n")
    pm = app_module.parse_policymanager(reg)
    assert pm["area_count"] == 2
    assert pm["setting_count"] == 3
    assert pm["provider_count"] == 2


def test_parse_sidecar_scripts():
    import app as app_module
    reg = app_module.parse_reg(
        "[HKLM\\SOFTWARE\\Microsoft\\IntuneManagementExtension\\SideCarPolicies"
        "\\Scripts\\Execution\\{cc111111-1111-1111-1111-111111111111}"
        "\\{dd222222-2222-2222-2222-222222222222}_2]\r\n"
        "\"LastExecution\"=\"5/27/2026 12:50:13 PM\"\r\n")
    scripts = app_module.parse_sidecar_scripts(reg)
    assert len(scripts) == 1
    assert scripts[0]["last_execution"].startswith("5/27/2026")


def test_parse_winhttp_proxy_and_firewall():
    import app as app_module
    assert app_module.parse_winhttp_proxy(
        "Current WinHTTP proxy settings:\r\n\r\n    Direct access (no proxy server).\r\n"
    )["direct"] is True
    p = app_module.parse_winhttp_proxy("    Proxy Server(s) :  proxy:8080\r\n")
    assert p["direct"] is False and p["server"] == "proxy:8080"
    fw = app_module.parse_firewall_profiles(
        "Domain Profile Settings:\r\nState                                 ON\r\n"
        "Public Profile Settings:\r\nState                                 OFF\r\n")
    assert {f["profile"]: f["on"] for f in fw} == {"Domain": True, "Public": False}


def test_count_event_issues():
    import app as app_module
    txt = ("LevelDisplayName : Error\n...\nLevelDisplayName : Warning\n"
           "LevelDisplayName : Error\nLevelDisplayName : Information\n")
    assert app_module.count_event_issues(txt) == {"errors": 2, "warnings": 1}


def _write_utf16(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-16-le"))   # BOM-less; reader sniffs NULs


def test_build_dashboard_adds_registry_cards(tmp_path):
    import app as app_module
    inp = tmp_path / "pkg"
    _write_utf16(inp / "Registry" / "Win32Apps.reg", _WIN32_REG)
    _write_utf16(inp / "Registry" / "Enrollments.reg",
                 "[HKLM\\SOFTWARE\\Microsoft\\Enrollments\\{ee111111-1111-1111-1111-111111111111}]\r\n"
                 "\"UPN\"=\"u@c.com\"\r\n\"DiscoveryServiceFullURL\"=\"https://x.manage.microsoft.com/y\"\r\n")
    (inp / "EventLogs").mkdir(parents=True, exist_ok=True)
    (inp / "EventLogs" / "DeviceManagement-Admin-ErrorsWarnings.txt").write_text(
        "LevelDisplayName : Error\nLevelDisplayName : Warning\n", encoding="utf-8")
    dash = app_module.build_dashboard(inp)
    labels = {c["label"]: c for c in dash["checks"]}
    assert labels["Win32 apps"]["status"] == "bad"     # one app has an error
    assert labels["Enrollment"]["status"] == "ok"
    assert labels["MDM event log"]["status"] == "bad"
    titles = [s["title"] for s in dash["sections"]]
    assert any("Win32 app deployment status" in t for t in titles)


def test_errorcodes_page(client):
    r = client.get("/errorcodes")
    assert r.status_code == 200
    assert "0x87D1041C" in r.text
    assert 'class="ec"' in r.text


def test_nav_links_errorcodes(client):
    assert "/errorcodes" in client.get("/").text


# --- RSOP settings -> Intune/CSP setting name (OMA-URI + Learn deep-link) ---

_PM_REG = (
    "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\AboveLock]\r\n"
    "\"AllowCortanaAboveLock\"=dword:00000000\r\n"
    "\"AllowCortanaAboveLock_ProviderSet\"=dword:00000001\r\n"
    "\"AllowCortanaAboveLock_WinningProvider\"=\"{11111111-1111-1111-1111-111111111111}\"\r\n"
    "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\ADMX_CredUI]\r\n"
    "\"NoLocalPasswordResetQuestions_ProviderSet\"=dword:00000001\r\n"
    "\"NoLocalPasswordResetQuestions_WinningProvider\"=\"{11111111-1111-1111-1111-111111111111}\"\r\n"
    "\"NoLocalPasswordResetQuestions_ADMXInstanceData\"=\"Software\\\\X\"\r\n"
)


def test_policy_oma_uri_and_doc_url():
    import app as app_module
    assert app_module.policy_oma_uri("device", "AboveLock", "AllowCortanaAboveLock") == \
        "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock"
    assert app_module.policy_oma_uri("user", "X", "Y").startswith("./User/")
    assert app_module.policy_doc_url("AboveLock", "AllowCortanaAboveLock") == \
        ("https://learn.microsoft.com/windows/client-management/mdm/"
         "policy-csp-abovelock#allowcortanaabovelock")
    assert app_module.policy_doc_url("ADMX_CredUI", "NoLocalPasswordResetQuestions") == ""


def test_parse_policymanager_settings_couples_csp_name():
    import app as app_module
    rows = app_module.parse_policymanager_settings(app_module.parse_reg(_PM_REG))
    assert len(rows) == 2
    by = {r["setting"]: r for r in rows}
    csp = by["AllowCortanaAboveLock"]
    assert csp["value"] == "0"
    assert csp["admx"] is False
    assert csp["oma_uri"].endswith("/AboveLock/AllowCortanaAboveLock")
    assert csp["doc_url"].endswith("#allowcortanaabovelock")
    admx = by["NoLocalPasswordResetQuestions"]
    assert admx["admx"] is True            # flagged via *_ADMXInstanceData
    assert admx["doc_url"] == ""           # no reliable anchor for ADMX
    assert admx["oma_uri"]                 # OMA-URI still built


_PM_CURRENT_NOVAL = (
    "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\ApplicationManagement]\r\n"
    "\"AllowAppStoreAutoUpdate\"=dword:00000001\r\n"
    "\"AllowAppStoreAutoUpdate_WinningProvider\"=\"{11111111-1111-1111-1111-111111111111}\"\r\n"
    "\"MSIAllowUserControlOverInstall_WinningProvider\"=\"{11111111-1111-1111-1111-111111111111}\"\r\n"
)
_PM_PROVIDERS = (
    "[HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\Providers"
    "\\{11111111-1111-1111-1111-111111111111}\\default\\device\\ApplicationManagement]\r\n"
    "\"MSIAllowUserControlOverInstall\"=dword:00000001\r\n"
)


def test_policymanager_value_from_providers_hive():
    import app as app_module
    cur = app_module.parse_reg(_PM_CURRENT_NOVAL)
    prov = app_module.parse_reg(_PM_PROVIDERS)
    # Without the providers hive the value is missing in `current`.
    no_prov = {r["setting"]: r for r in
               app_module.parse_policymanager_settings(cur)}
    assert no_prov["MSIAllowUserControlOverInstall"]["value"] == ""
    assert no_prov["AllowAppStoreAutoUpdate"]["value"] == "1"
    # With the providers hive it is filled from the winning provider's subtree.
    with_prov = {r["setting"]: r for r in
                 app_module.parse_policymanager_settings(cur, prov)}
    assert with_prov["MSIAllowUserControlOverInstall"]["value"] == "1"
    assert with_prov["AllowAppStoreAutoUpdate"]["value"] == "1"  # bare value kept


def test_build_dashboard_policy_settings_section(tmp_path):
    import app as app_module
    inp = tmp_path / "pkg"
    _write_utf16(inp / "Registry" / "PolicyManager-Current.reg", _PM_REG)
    dash = app_module.build_dashboard(inp)
    sec = next(s for s in dash["sections"] if s["title"].startswith("Policy settings"))
    assert sec["columns"][-1] == "OMA-URI"
    # The CSP setting carries a dict link cell; the ADMX one stays plain text.
    cells = [row[-1] for row in sec["rows"]]
    assert any(isinstance(c, dict) and "policy-csp-abovelock" in c["href"] for c in cells)
    assert any(isinstance(c, str) and "(ADMX)" in c for c in cells)
    # Fixed column widths render as a <colgroup> so the Value column isn't
    # crushed by the long OMA-URI column.
    assert sec["widths"] and len(sec["widths"]) == len(sec["columns"])
    assert sec.get("searchable") is True            # has a row filter
    html = app_module.render_dashboard_panel(dash)
    assert 'href="https://learn.microsoft.com/windows/client-management/mdm/policy-csp-' in html
    assert 'rel="noopener"' in html
    assert "<colgroup>" in html and html.count("<col ") == len(sec["columns"])
    assert 'class="secsearch"' in html              # filter input rendered


# --- Settings-Catalog name enrichment (Microsoft Graph, optional) ----------

_GRAPH_ITEMS = [
    {"id": "device_vendor_msft_policy_config_abovelock_allowcortanaabovelock",
     "displayName": "Allow Cortana above lock screen",
     "baseUri": "./Device/Vendor/MSFT/Policy/Config",
     "offsetUri": "AboveLock/AllowCortanaAboveLock"},
    {"id": "skipme", "displayName": "", "baseUri": "", "offsetUri": ""},
]


def test_build_csp_name_map_keys_path_and_id():
    import app as app_module
    m = app_module.build_csp_name_map(_GRAPH_ITEMS)
    assert m["device/vendor/msft/policy/config/abovelock/allowcortanaabovelock"] == \
        "Allow Cortana above lock screen"
    assert m["device_vendor_msft_policy_config_abovelock_allowcortanaabovelock"] == \
        "Allow Cortana above lock screen"
    assert "skipme" not in m            # entries without a display name are dropped


def test_csp_display_name_lookup(monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "_CSP_NAMES",
                        app_module.build_csp_name_map(_GRAPH_ITEMS))
    oma = app_module.policy_oma_uri("device", "AboveLock", "AllowCortanaAboveLock")
    assert app_module.csp_display_name("AboveLock", "AllowCortanaAboveLock", oma) == \
        "Allow Cortana above lock screen"
    # Falls back to the settingDefinitionId when the path doesn't match.
    assert app_module.csp_display_name(
        "AboveLock", "AllowCortanaAboveLock", "./bogus") == \
        "Allow Cortana above lock screen"
    assert app_module.csp_display_name("Foo", "Bar", "./none") == ""


def test_csp_display_name_empty_without_map(monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "_CSP_NAMES", {})
    assert app_module.csp_display_name("AboveLock", "X", "./y") == ""


def test_build_dashboard_intune_name_column(tmp_path, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "_CSP_NAMES",
                        app_module.build_csp_name_map(_GRAPH_ITEMS))
    inp = tmp_path / "pkg"
    _write_utf16(inp / "Registry" / "PolicyManager-Current.reg", _PM_REG)
    dash = app_module.build_dashboard(inp)
    sec = next(s for s in dash["sections"] if s["title"].startswith("Policy settings"))
    assert sec["columns"] == ["Area", "Setting", "Intune name", "Value", "OMA-URI"]
    intune_cells = [r[2] for r in sec["rows"]]
    assert "Allow Cortana above lock screen" in intune_cells
    html = app_module.render_dashboard_panel(dash)
    assert "Allow Cortana above lock screen" in html


# --- Device drop-off API + inbox (ENABLE_UPLOAD_API) ------------------------

@pytest.fixture()
def upload_client(tmp_path, monkeypatch):
    """App with the drop-off API enabled (separate jobs dir)."""
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("APP_USER", "")
    monkeypatch.setenv("APP_PASSWORD", "")
    monkeypatch.setenv("ENABLE_UPLOAD_API", "1")
    import importlib
    import app as app_module
    importlib.reload(app_module)
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        yield c
    importlib.reload(app_module)  # restore defaults for later tests


def _diag_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Apps-IME/Logs/IntuneManagementExtension.log",
                    '<![LOG[hi]LOG]!><time="1" date="2" component="C" '
                    'type="1" thread="3">')
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    return buf.getvalue()


_TOK = "abcdefghijklmnopqrstuvwxyz0123456789"  # >= 24 chars


def test_token_hash_stable_and_hex():
    import app as app_module
    h = app_module.token_hash("hello")
    assert h == app_module.token_hash("hello")
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def test_api_disabled_by_default(client):
    r = client.post("/api/diagnostics", content=b"x",
                    headers={"X-Upload-Token": "a" * 30,
                             "Content-Type": "application/zip"})
    assert r.status_code == 404
    assert client.get("/inbox", params={"token": "a" * 30}).status_code == 404
    assert "/inbox" not in client.get("/").text   # nav link hidden


def test_api_upload_and_inbox(upload_client):
    import app as app_module
    r = upload_client.post("/api/diagnostics", content=_diag_zip(),
                           headers={"X-Upload-Token": _TOK,
                                    "X-Device-Name": "PC01",
                                    "Content-Type": "application/zip"})
    assert r.status_code == 200
    body = r.json()
    job_id = body["job_id"]
    assert body["url"] == f"/result/{job_id}"
    status = app_module.read_status(job_id)
    assert status["source"] == "api"
    assert status["device"] == "PC01"
    assert status["upload_token_hash"] == app_module.token_hash(_TOK)
    # The raw token is never persisted, only its hash.
    assert _TOK not in app_module.status_path(job_id).read_text(encoding="utf-8")

    inbox = upload_client.get("/inbox", params={"token": _TOK})
    assert inbox.status_code == 200
    assert "PC01" in inbox.text
    assert f"/result/{job_id}" in inbox.text
    # A different token sees nothing.
    other = upload_client.get("/inbox", params={"token": "z" * 36})
    assert "PC01" not in other.text


def test_api_delete_one(upload_client):
    """A token can delete a single one of its own uploads; a different token
    cannot, and only the targeted job is removed."""
    import app as app_module
    h = {"Content-Type": "application/zip"}
    j1 = upload_client.post("/api/diagnostics", content=_diag_zip(),
                            headers={**h, "X-Upload-Token": _TOK}).json()["job_id"]
    j2 = upload_client.post("/api/diagnostics", content=_diag_zip(),
                            headers={**h, "X-Upload-Token": _TOK}).json()["job_id"]
    # Per-row delete buttons are present in the listing.
    listing = upload_client.get("/inbox", params={"token": _TOK}).text
    assert f'data-job="{j1}"' in listing and f'data-job="{j2}"' in listing

    # A different token may not delete this job (404, untouched).
    bad = upload_client.post("/inbox/delete-one",
                             headers={"X-Upload-Token": "z" * 30, "X-Job-Id": j1})
    assert bad.status_code == 404
    assert app_module.read_status(j1) is not None

    # The owning token deletes only the targeted job.
    ok = upload_client.post("/inbox/delete-one",
                            headers={"X-Upload-Token": _TOK, "X-Job-Id": j1})
    assert ok.status_code == 200 and ok.json()["deleted"] is True
    assert app_module.read_status(j1) is None
    assert app_module.read_status(j2) is not None


def test_api_token_too_short(upload_client):
    r = upload_client.post("/api/diagnostics", content=_diag_zip(),
                           headers={"X-Upload-Token": "short",
                                    "Content-Type": "application/zip"})
    assert r.status_code == 401


def test_dropoff_uses_jobs_dir_and_shared_retention(tmp_path, monkeypatch):
    """Drop-off packages live in JOBS_DIR and obey the shared
    JOB_RETENTION_HOURS, just like every other job."""
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("ENABLE_UPLOAD_API", "1")
    monkeypatch.setenv("JOB_RETENTION_HOURS", "1")
    monkeypatch.setenv("APP_USER", "")
    monkeypatch.setenv("APP_PASSWORD", "")
    import importlib
    import app as app_module
    importlib.reload(app_module)
    # No IME logs -> no analysis task spawned (keeps teardown clean).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    payload = buf.getvalue()
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        job_id = c.post("/api/diagnostics", content=payload,
                        headers={"X-Upload-Token": _TOK, "X-Device-Name": "PC01",
                                 "Content-Type": "application/zip"}).json()["job_id"]
        d = app_module.job_dir(job_id)
        assert d == app_module.JOBS_DIR / job_id and d.is_dir()
        # Younger than the window: kept; older: removed.
        app_module.cleanup_old_jobs()
        assert d.is_dir()
        old = time.time() - 2 * 3600
        os.utime(d, (old, old))
        app_module.cleanup_old_jobs()
        assert not d.exists()
    importlib.reload(app_module)


def test_api_per_token_cap(tmp_path, monkeypatch):
    """The per-token cap blocks a token's own next upload with 429, but a
    different token's inbox is unaffected (it's per-inbox, not global)."""
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("ENABLE_UPLOAD_API", "1")
    monkeypatch.setenv("UPLOAD_API_MAX_JOBS_PER_TOKEN", "1")
    monkeypatch.setenv("APP_USER", "")
    monkeypatch.setenv("APP_PASSWORD", "")
    import importlib
    import app as app_module
    importlib.reload(app_module)
    # No IME logs -> no analysis task spawned (keeps teardown clean).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    pkg = buf.getvalue()
    hdr = {"Content-Type": "application/zip"}
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        first = c.post("/api/diagnostics", content=pkg,
                       headers={**hdr, "X-Upload-Token": _TOK})
        assert first.status_code == 200
        # Same token, now at its cap -> 429.
        second = c.post("/api/diagnostics", content=pkg,
                        headers={**hdr, "X-Upload-Token": _TOK})
        assert second.status_code == 429
        # A different token's inbox is independent.
        other = c.post("/api/diagnostics", content=pkg,
                       headers={**hdr, "X-Upload-Token": "z" * 30})
        assert other.status_code == 200
    importlib.reload(app_module)


def test_dropoff_excluded_from_recent_uploads(upload_client):
    """A device drop-off result page must not upsert into the viewer's personal
    'Recent uploads' history; a self-uploaded package still does."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    pkg = buf.getvalue()

    # Drop-off via the API: not recorded.
    drop_id = upload_client.post(
        "/api/diagnostics", content=pkg,
        headers={"X-Upload-Token": _TOK, "Content-Type": "application/zip"},
    ).json()["job_id"]
    assert "h.unshift" not in upload_client.get(f"/result/{drop_id}").text

    # Own upload via the form: recorded.
    r = upload_client.post(
        "/diagnostics-analyze",
        files={"files": ("IntuneDiag-PC.zip", pkg, "application/zip")},
        follow_redirects=True,
    )
    assert "h.unshift" in r.text


def test_inbox_form_has_generator(upload_client):
    r = upload_client.get("/inbox")
    assert r.status_code == 200
    assert "Generate token" in r.text
    assert "crypto.getRandomValues" in r.text
    # Generating a token reveals the remediation script + an Intune guide.
    assert "SCRIPT_TPL =" in r.text
    assert "function fillScript" in r.text
    assert "Collect-IntuneDiagnostics.ps1" in r.text   # embedded script body
    assert "Deploy in Intune" in r.text
    assert "Run remediation" in r.text


def test_inbox_anonymize_toggle(upload_client):
    r = upload_client.get("/inbox")
    assert 'id="anon"' in r.text                       # the toggle
    assert "best-effort" in r.text                     # disclaimer text
    # Toggle on inserts -Anonymize into the collector call.
    assert "'-Remote -Anonymize -OutputPath'" in r.text


def test_collector_has_anonymize_option():
    text = (REPO_ROOT / "Collect-IntuneDiagnostics.ps1").read_text(encoding="utf-8")
    assert "[switch]$Anonymize" in text
    assert "<TENANT-ID>" in text and "<COMPANY>" in text and "<UPN>" in text
    # Best-effort disclaimer present.
    assert "best-effort" in text.lower()
    # The inbox JS rewrites this exact token in the remediation template.
    import app as app_module
    assert "-Remote -OutputPath" in app_module.REMEDIATION_TEMPLATE


def test_device_scripts_are_ascii_only():
    """Device scripts are downloaded and run by Windows PowerShell 5.1, which
    reads BOM-less files as ANSI; non-ASCII (e.g. em-dashes) corrupts parsing."""
    import app as app_module
    text = (REPO_ROOT / "Collect-IntuneDiagnostics.ps1").read_text(encoding="utf-8")
    assert text.isascii(), "Collect-IntuneDiagnostics.ps1 must be ASCII-only"
    assert app_module.REMEDIATION_TEMPLATE.isascii(), \
        "REMEDIATION_TEMPLATE must be ASCII-only"


def test_diag_downloads(client):
    """Download the open file and the whole package zip from a diagnostics job."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
        zf.writestr("Apps-IME/Logs/IntuneManagementExtension.log",
                    '<![LOG[hi]LOG]!><time="1" date="2" component="C" '
                    'type="1" thread="3">')
    r = client.post("/diagnostics-analyze",
                    files={"files": ("IntuneDiag.zip", buf.getvalue(),
                                     "application/zip")}, follow_redirects=False)
    job_id = r.headers["location"].rstrip("/").rsplit("/", 1)[-1]

    page = client.get(f"/result/{job_id}").text
    assert 'id="dlfile"' in page                      # download-open-file button
    assert f'href="/result/{job_id}/download"' in page  # download-package button

    # Single file download.
    fd = client.get(f"/result/{job_id}/files/download",
                    params={"file": "Identity/dsregcmd-status.txt"})
    assert fd.status_code == 200
    assert "attachment" in fd.headers.get("content-disposition", "")
    assert "AzureAdJoined" in fd.text
    # Membership check still rejects unknown/traversal.
    assert client.get(f"/result/{job_id}/files/download",
                      params={"file": "../x.txt"}).status_code == 404

    # Whole-package zip (rebuilt from the extracted files).
    dz = client.get(f"/result/{job_id}/download")
    assert dz.status_code == 200 and dz.headers["content-type"] == "application/zip"
    members = zipfile.ZipFile(io.BytesIO(dz.content)).namelist()
    assert "Identity/dsregcmd-status.txt" in members


def test_summary_shows_failed_script_error_code():
    """A failed PowerShell script's error code (often only in the full log entry)
    is surfaced in the summary items + top errors."""
    import app as app_module
    rs = app_module.ReportSummary()
    rs.timeline = [
        {"index": "1", "date": "2026-05-27", "status": "Failed",
         "type": "Powershell script", "intent": "Execute",
         "detail": "52f1bd15-da4f-49cb-98ee-eb81642a5cef for user System",
         "seconds": "", "logentry": "AgentExecutor exit code 0x87D1041C"},
    ]
    s = app_module.summarize(rs)
    item = next(i for i in s["items"] if i["status"] == "Failed")
    assert item["code"] == "0x87D1041C" and item["code_text"]
    assert ("0x87D1041C", 1) in [(e["code"], e["count"]) for e in s["top_errors"]]
    html = app_module.render_summary_panel(s)
    assert "<th>Error</th>" in html and "0x87D1041C" in html


def test_summary_error_code_from_detailtooltip():
    """The upstream report puts a failed script's real error in DetailToolTip
    (hover), not Detail — that column is parsed and scanned for failure rows."""
    import app as app_module
    html = (
        '<table id="ObservedTimeline"><tr><th>Index</th><th>Date</th>'
        '<th>Status</th><th>Type</th><th>Intent</th><th>Detail</th>'
        '<th>Seconds</th><th>LogEntry</th><th>Color</th><th>DetailToolTip</th></tr>'
        '<tr><td>1</td><td>2026-05-27</td><td>Failed</td><td>Powershell script</td>'
        '<td>Execute</td><td>See Powershell error message. Hover for details.</td>'
        '<td>3</td><td>Line 1234</td><td>Red</td>'
        '<td>The system cannot find the file specified. 0x80070002</td></tr>'
        '<tr><td>2</td><td>2026-05-27</td><td>Success</td><td>Win32App</td>'
        '<td>Required</td><td>ok</td><td>1</td><td>Line 9</td><td>Green</td>'
        '<td>script content</td></tr></table>')
    rs = app_module.parse_report_summary(html)
    assert "detailtooltip" in rs.timeline[0]
    s = app_module.summarize(rs)
    failed = next(i for i in s["items"] if i["status"] == "Failed")
    assert failed["code"] == "0x80070002"
    # Success row's tooltip (script content) is not scanned -> no false code.
    ok = next(i for i in s["items"] if i["status"] == "Success")
    assert ok["code"] == ""


def test_summary_merges_errorlog_message_into_failed_script():
    """With -ShowErrorsInReport the real PowerShell error is a separate ErrorLog
    row; it is merged onto the preceding failed-script row (message or code)."""
    import app as app_module
    rs = app_module.ReportSummary()
    rs.timeline = [
        {"index": "1", "date": "t", "status": "Failed", "type": "Powershell script",
         "intent": "Execute", "detail": "52f1bd15 for user System", "seconds": "1",
         "logentry": "Line 1", "color": "Red", "detailtooltip": "script content"},
        {"index": "2", "date": "t", "status": "ErrorLog", "type": "Powershell script",
         "intent": "Execute", "detail": "The term 'Get-Foo' is not recognized.",
         "seconds": "", "logentry": "", "color": "Red", "detailtooltip": ""},
    ]
    s = app_module.summarize(rs)
    # ErrorLog is not a standalone item; its message lands on the failed row.
    assert all(i["status"] != "ErrorLog" for i in s["items"])
    failed = next(i for i in s["items"] if i["status"] == "Failed")
    assert "not recognized" in failed["error_msg"]
    assert [c["failed"] for c in s["counts"]] == [1]   # not double-counted
    assert "not recognized" in app_module.render_summary_panel(s)


def test_parse_omadm_accounts():
    import app as app_module
    reg = app_module.parse_reg(
        "Windows Registry Editor Version 5.00\n\n"
        r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\{12345678-1234-1234-1234-123456789012}]"
        "\n"
        '"LastSessionResult"=dword:00000000\n'
        '"ServerLastAccessTime"="2026-06-14T10:00:00Z"\n'
        '"ServerLastSuccessTime"="2026-05-01T10:00:00Z"\n'
    )
    om = app_module.parse_omadm_accounts(reg)
    assert om["last_session_result"] == 0
    assert om["server_last_access"] == "2026-06-14T10:00:00Z"
    assert om["server_last_success"] == "2026-05-01T10:00:00Z"
    # Total: no OMADM key -> empty.
    assert app_module.parse_omadm_accounts({}) == {}


def test_count_push_events():
    import app as app_module
    recs = [
        {"event_id": 1010}, {"event_id": 1225}, {"event_id": 1010},
        {"event_id": 99},
    ]
    assert app_module.count_push_events(recs) == {"ev1010": 2, "ev1225": 1}
    assert app_module.count_push_events([]) == {"ev1010": 0, "ev1225": 0}
    assert app_module.count_push_events(None) == {"ev1010": 0, "ev1225": 0}


def test_build_dashboard_zombie_sync(client, tmp_path):
    """Expired machine cert + a recent OMADM access time -> 'MDM sync health'
    flags the device as managed-but-dead; a 0x87D1041C Win32 app is decoded
    with the enriched error code."""
    import app as app_module
    pkg = tmp_path / "pkg"
    (pkg / "Registry").mkdir(parents=True)
    (pkg / "Identity").mkdir(parents=True)

    (pkg / "Identity" / "certs-machine-overview.txt").write_text(
        "Subject : CN=device\nNotAfter : 1-1-2020\n"
        "Thumbprint : ABC123\nExpired : True\n",
        encoding="utf-8",
    )
    (pkg / "Registry" / "OMADM-Accounts.reg").write_text(
        "Windows Registry Editor Version 5.00\n\n"
        r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\{12345678-1234-1234-1234-123456789012}]"
        "\n"
        '"LastSessionResult"=dword:00000000\n'
        '"ServerLastAccessTime"="2026-06-14T10:00:00Z"\n',
        encoding="utf-8",
    )
    base = (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension"
            r"\Win32Apps\S-1-12-1-111\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}_1")
    (pkg / "Registry" / "Win32Apps.reg").write_text(
        "Windows Registry Editor Version 5.00\n\n"
        f"[{base}]\n\n"
        f"[{base}\\EnforcementStateMessage]\n"
        '"EnforcementStateMessage"="{\\"EnforcementState\\":3000,'
        '\\"ErrorCode\\":-2016345060}"\n',
        encoding="utf-8",
    )

    dash = app_module.build_dashboard(pkg)
    by_label = {c["label"]: c for c in dash["checks"]}

    assert by_label["MDM sync health"]["status"] == "bad"
    assert "expired" in by_label["MDM sync health"]["detail"].lower()
    # No standalone Company Portal / ESP card any more.
    assert "Company Portal / ESP" not in by_label
    # Underlying Win32 app was decoded with the enriched error code.
    assert by_label["Win32 apps"]["status"] == "bad"


def test_collect_log_error_codes(tmp_path):
    import app as app_module
    pkg = tmp_path / "pkg"
    (pkg / "Apps-IME" / "Logs").mkdir(parents=True)
    log = pkg / "Apps-IME" / "Logs" / "IntuneManagementExtension.log"
    log.write_text(
        "benign first line\n"
        "install failed with 0x87D1041C while detecting app\n"
        "another line, code 0x87D1041C again\n"
        "unrelated 0xDEADBEEF not in table\n",
        encoding="utf-8",
    )
    found = app_module.collect_log_error_codes(pkg)
    assert len(found) == 1
    e = found[0]
    assert e["code"] == "0x87D1041C"
    assert e["count"] == 2
    assert e["src"] == "Apps-IME/Logs/IntuneManagementExtension.log"
    assert e["line"] == 2          # 1-based record index of first hit
    assert e["explanation"]
    # Empty package -> no codes.
    assert app_module.collect_log_error_codes(tmp_path / "empty") == []


def test_build_dashboard_known_error_codes_table(tmp_path):
    import app as app_module
    pkg = tmp_path / "pkg"
    (pkg / "Apps-IME" / "Logs").mkdir(parents=True)
    (pkg / "Apps-IME" / "Logs" / "IntuneManagementExtension.log").write_text(
        "app install error 0x87D1041C detected\n", encoding="utf-8")

    dash = app_module.build_dashboard(pkg)
    by_label = {c["label"]: c for c in dash["checks"]}
    assert by_label["Known error codes"]["status"] == "bad"
    assert by_label["Known error codes"]["section"] == "errorcodes"

    sec = next(s for s in dash["sections"] if s.get("key") == "errorcodes")
    code_cell = sec["rows"][0][0]
    assert code_cell["text"] == "0x87D1041C"
    assert code_cell["file"] == "Apps-IME/Logs/IntuneManagementExtension.log"
    assert isinstance(code_cell["line"], int)
    # The Autopilot pre-provisioning hint is folded into the explanation cell.
    assert "Autopilot pre-provisioning" in sec["rows"][0][3]

    # The render wires the deep-link (seclink + data-file/data-line).
    html = app_module.render_dashboard_panel(dash)
    assert 'class="seclink"' in html
    assert 'data-file="Apps-IME/Logs/IntuneManagementExtension.log"' in html
    assert "data-line=" in html
    assert "0x87D1041C" in html


# --- XSS hardening: inline-<script> JSON + hostile filenames ----------------

def test_js_json_neutralises_script_breakout():
    import json

    import app as app_module
    out = app_module.js_json("</script><img src=x onerror=alert(1)>")
    # No raw HTML metacharacters can survive into a <script> block.
    assert "<" not in out and ">" not in out
    # Still valid JSON that round-trips to the original value.
    assert json.loads(out) == "</script><img src=x onerror=alert(1)>"


def test_history_record_js_escapes_filename():
    """A crafted upload filename must not be able to close the inline <script>."""
    import app as app_module
    js = app_module.history_record_js(
        "abc123", "logs", "done",
        ["</script><script>alert(1)</script>.log"])
    # The only literal </script> in the snippet is its own closing tag; the
    # filename's </script> sequences are \u-escaped.
    assert js.count("</script>") == 1
    assert "\\u003c/script\\u003e" in js


def test_cmtrace_page_escapes_breakout_filename(client):
    """A flat .log upload whose name carries HTML metacharacters reaches the
    (non-sandboxed) CMTRACE_PAGE via history + firstjson; both must be escaped."""
    payload = ("<![LOG[hi]LOG]!><time=\"1\" date=\"2\" component=\"C\" "
               "context=\"\" type=\"1\" thread=\"3\" file=\"\">").encode()
    r = client.post(
        "/cmtrace-view",
        files={"files": ("x<img src=q onerror=alert(1)>.log", payload,
                         "text/plain")},
        follow_redirects=True,
    )
    assert r.status_code == 200
    # The raw metacharacters from the filename never appear unescaped in the
    # page chrome; js_json emitted the \u-escaped form instead.
    assert "<img src=q onerror=alert(1)>" not in r.text
    assert "\\u003cimg src=q onerror=alert(1)\\u003e" in r.text


def test_diag_zip_rejects_unsafe_member_names(client):
    """Zip members with control chars or < > " are skipped at extraction, so a
    hostile filename never becomes the first-file pointer on the diag page."""
    import app as app_module
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Apps-IME/Logs/IntuneManagementExtension.log",
                    '<![LOG[hi]LOG]!><time="1" date="2" component="C" '
                    'type="1" thread="3">')
        zf.writestr("Apps-IME/Logs/x<script>evil</script>.log", "payload")
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    r = client.post(
        "/diagnostics-analyze",
        files={"files": ("IntuneDiag.zip", buf.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    job_id = r.headers["location"].split("/")[2]
    files = app_module.list_input_files(job_id, exts=app_module.DIAG_KEEP_EXTS)
    assert not any("<" in f or ">" in f for f in files)   # unsafe one not staged
    skipped = [s["name"] for s in (app_module.read_status(job_id) or {}).get(
        "skipped", [])]
    assert any("<script>" in n for n in skipped)          # recorded as skipped
    assert "<script>evil</script>" not in client.get(f"/result/{job_id}").text


def test_delete_refuses_api_drop_off_jobs(upload_client):
    """An untokened /result/{id}/delete must not remove a token-scoped drop-off
    job; only /inbox/delete[-one] with the matching token can."""
    import app as app_module
    job_id = upload_client.post(
        "/api/diagnostics", content=_diag_zip(),
        headers={"X-Upload-Token": _TOK, "Content-Type": "application/zip"},
    ).json()["job_id"]
    r = upload_client.post(f"/result/{job_id}/delete")
    assert r.status_code == 403
    assert app_module.read_status(job_id) is not None     # still on disk
    d = upload_client.post(
        "/inbox/delete-one",
        headers={"X-Upload-Token": _TOK, "X-Job-Id": job_id})
    assert d.json()["deleted"] is True
    assert app_module.read_status(job_id) is None


_CMTRACE_LINE = (b'<![LOG[hi]LOG]!><time="1" date="2" component="C" '
                 b'type="1" thread="3">')


def test_local_job_cap_returns_429(tmp_path, monkeypatch):
    """MAX_LOCAL_JOBS bounds the interactive web-upload path: once the cap is
    reached new uploads get 429 (the drop-off API has its own separate cap), so
    a public deployment can't be filled with anonymous uploads."""
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("APP_USER", "")
    monkeypatch.setenv("APP_PASSWORD", "")
    monkeypatch.setenv("MAX_LOCAL_JOBS", "1")
    import importlib
    import app as app_module
    importlib.reload(app_module)
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        first = c.post("/cmtrace-view",
                       files={"files": ("a.log", _CMTRACE_LINE, "text/plain")},
                       follow_redirects=False)
        assert first.status_code == 303          # one job allowed
        second = c.post("/cmtrace-view",
                        files={"files": ("b.log", _CMTRACE_LINE, "text/plain")},
                        follow_redirects=False)
        assert second.status_code == 429         # cap reached
        # The diagnostics upload route is gated by the same cap.
        third = c.post("/diagnostics-analyze",
                       files={"files": ("d.zip", _diag_zip(), "application/zip")},
                       follow_redirects=False)
        assert third.status_code == 429
    importlib.reload(app_module)  # restore defaults for later tests


def test_untrusted_html_csp_blocks_exfiltration(client):
    """A .html inside a package (and the raw report) runs sandboxed AND with
    default-src 'none', so a malicious script in attacker-influenced content
    can't beacon the data out; the opaque origin already blocks app access."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("System/report.html", "<h1>hi</h1>")
        zf.writestr("Identity/dsregcmd-status.txt", "AzureAdJoined : YES\n")
    r = client.post("/diagnostics-analyze",
                    files={"files": ("d.zip", buf.getvalue(), "application/zip")},
                    follow_redirects=False)
    assert r.status_code == 303
    job_id = r.headers["location"].rstrip("/").rsplit("/", 1)[-1]
    view = client.get(f"/result/{job_id}/files/view",
                      params={"file": "System/report.html"})
    assert view.status_code == 200
    csp = view.headers.get("content-security-policy", "")
    assert "sandbox" in csp and "default-src 'none'" in csp
    assert "allow-same-origin" not in csp        # opaque origin: no app access
