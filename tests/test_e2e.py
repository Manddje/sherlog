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


def test_history_section_on_upload_pages(client):
    for path in ("/", "/timeline", "/cmtrace"):
        r = client.get(path)
        assert r.status_code == 200
        assert 'id="recent"' in r.text       # browser-side history list
        assert "sherlog.history" in r.text   # localStorage key


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

    # The completed job derives a summary.json from the real report …
    import app as app_module
    job_id = location.rstrip("/").rsplit("/", 1)[-1]
    summary_file = app_module.job_dir(job_id) / "output" / "summary.json"
    assert summary_file.is_file()
    model = app_module.read_summary(job_id)
    assert model is not None and model["parse_ok"]
    assert model["counts"]  # testdata contains Win32App/script events

    # … and the wrapper page shows the summary panel above the iframe.
    wrapper = client.get(location).text
    assert 'class="summary"' in wrapper
    assert "Analysis summary" in wrapper
    # History records the original upload name, not the staged log paths.
    assert '"logs.zip"' in wrapper


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
    assert '<tr class="warn"' in html
    assert '<tr class="err"' in html

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
        "/analyze",
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
    assert '<tr class="err"' in html             # level 2 -> error colouring
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
