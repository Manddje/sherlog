"""Regression tests for the review hardening pass: parser DoS, upload
pipeline, job lifecycle, drop-off credentials, CSP nonces and friends."""

import importlib
import io
import json
import os
import re
import signal
import stat
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
LEGACY_TOK = "abcdefghijklmnopqrstuvwxyz0123456789"


def _load_app(monkeypatch, tmp_path, **env):
    base = {"JOBS_DIR": str(tmp_path / "jobs"), "APP_USER": "", "APP_PASSWORD": "",
            "MAX_UPLOAD_MB": "1", "ENABLE_UPLOAD_API": "1"}
    base.update({k: str(v) for k, v in env.items()})
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    import app as app_module
    importlib.reload(app_module)
    return app_module


@pytest.fixture()
def mk(monkeypatch, tmp_path):
    """Factory: mk(**env) -> (app_module, TestClient) with the app started."""
    clients = []

    def make(**env):
        mod = _load_app(monkeypatch, tmp_path, **env)
        c = TestClient(mod.app)
        c.__enter__()
        clients.append(c)
        return mod, c

    yield make
    for c in clients:
        c.__exit__(None, None, None)
    import app as app_module
    importlib.reload(app_module)


def _zip(members: dict, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _job_dirs(mod):
    return [p for p in mod.JOBS_DIR.iterdir() if p.is_dir()]


# --- CMTrace parser ---------------------------------------------------------

def test_cmtrace_parser_is_linear_on_unterminated_markers(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    for text in ("<![LOG[" * 100_000,
                 "<![LOG[x]LOG]!><time=\"" * 50_000,
                 "<![LOG[bad]LOG]!><x>\n" * 50_000):
        t0 = time.perf_counter()
        mod.parse_cmtrace(text, 10**9)
        assert time.perf_counter() - t0 < 3.0


def test_cmtrace_malformed_record_does_not_swallow_the_next(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    good = ('<![LOG[good]LOG]!><time="1" date="2" component="c" '
            'context="" type="3" thread="4" file="">')
    recs, _ = mod.parse_cmtrace("<![LOG[bad]LOG]!><x>\n" + good)
    structured = [r for r in recs if r["structured"]]
    assert [r["msg"] for r in structured] == ["good"]
    assert structured[0]["type"] == "3"


# --- Upload pipeline ----------------------------------------------------------

def test_unsupported_zip_member_is_skipped_not_500(mk):
    mod, c = mk()
    data = bytearray(_zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n",
                           "weird.txt": "x" * 100}))
    # Rewrite weird.txt's compression method to deflate64 (9) in both headers.
    idx = data.find(b"weird.txt")
    lh = data.rfind(b"PK\x03\x04", 0, idx)
    data[lh + 8:lh + 10] = (9).to_bytes(2, "little")
    cd = data.find(b"PK\x01\x02" , lh + 1)
    while cd != -1:
        if data[cd + 46:cd + 55] == b"weird.txt":
            data[cd + 10:cd + 12] = (9).to_bytes(2, "little")
        cd = data.find(b"PK\x01\x02", cd + 1)
    r = c.post("/diagnostics-analyze",
               files={"files": ("pkg.zip", bytes(data), "application/zip")},
               follow_redirects=False)
    assert r.status_code == 303
    job = r.headers["location"].rsplit("/", 1)[-1]
    st = mod.read_status(job)
    assert any(s["name"] == "weird.txt" for s in st["skipped"])


def test_name_clash_in_zip_is_skipped_not_500(mk):
    mod, c = mk()
    pkg = _zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n",
                "x.txt": "a", "x.txt/y.txt": "b"})
    r = c.post("/api/diagnostics", content=pkg,
               headers={"X-Upload-Token": LEGACY_TOK, "Content-Type": "application/zip"})
    assert r.status_code == 200, r.text


def test_failed_upload_leaves_no_job_dir(mk):
    mod, c = mk()
    r = c.post("/cmtrace-view", files=[
        ("files", ("a.log", b"hello\n" * 1000, "text/plain")),
        ("files", ("x.zip", b"this is not a zip", "application/zip"))])
    assert r.status_code == 400
    assert _job_dirs(mod) == []


def test_zip_member_cap(mk):
    mod, c = mk(MAX_ZIP_MEMBERS=5)
    pkg = _zip({f"f{i}.txt": "" for i in range(10)})
    r = c.post("/diagnostics-analyze",
               files={"files": ("pkg.zip", pkg, "application/zip")})
    assert r.status_code == 413
    assert _job_dirs(mod) == []


def test_duplicate_log_names_are_kept(mk):
    mod, c = mk()
    r = c.post("/cmtrace-view", files=[
        ("files", ("dir1/IME.log", b"one\n", "text/plain")),
        ("files", ("dir2/IME.log", b"two\n", "text/plain"))], follow_redirects=False)
    assert r.status_code == 303
    job = r.headers["location"].split("/")[2]
    assert sorted(mod.list_input_logs(job)) == ["IME (2).log", "IME.log"]


def test_chunked_body_over_limit_is_rejected_while_streaming(mk):
    mod, c = mk()

    def gen():
        for _ in range(4):
            yield b"x" * (1024 * 1024)

    r = c.post("/api/diagnostics", content=gen(),
               headers={"X-Upload-Token": LEGACY_TOK})
    assert r.status_code == 413
    r = c.post("/api/collect-status", content=(b"{" + b" " * 8000 for _ in range(1)),
               headers={"X-Upload-Token": LEGACY_TOK})
    assert r.status_code == 413
    # A multipart web upload without Content-Length is capped too.
    r = c.post("/inbox", content=(b"a" * 70000 for _ in range(1)),
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert _job_dirs(mod) == []


def test_in_flight_reservations_count_against_the_cap(mk):
    mod, c = mk(MAX_LOCAL_JOBS=1)
    mod.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    (mod.JOBS_DIR / ("a" * 32)).mkdir()
    mod.write_status("a" * 32, state="uploading", source="web", created=time.time())
    r = c.post("/cmtrace-view", files={"files": ("a.log", b"x\n", "text/plain")})
    assert r.status_code == 429


def test_low_disk_space_rejects_upload(mk, monkeypatch):
    mod, c = mk()
    monkeypatch.setattr(mod, "disk_free_bytes", lambda: 10)
    r = c.post("/cmtrace-view", files={"files": ("a.log", b"x\n", "text/plain")})
    assert r.status_code == 507
    assert _job_dirs(mod) == []


def test_upload_rate_limit_per_ip(mk):
    mod, c = mk(UPLOAD_RATE_PER_HOUR=2)
    codes = [c.post("/cmtrace-view", files={"files": ("a.log", b"x\n", "text/plain")},
                    follow_redirects=False).status_code for _ in range(3)]
    assert codes == [303, 303, 429]


def test_startup_removes_unfinished_reservations(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    mod.JOBS_DIR.mkdir(parents=True)
    (mod.JOBS_DIR / ("b" * 32)).mkdir()
    mod.write_status("b" * 32, state="uploading", source="web", created=time.time())
    mod.fail_interrupted_jobs()
    assert not (mod.JOBS_DIR / ("b" * 32)).exists()


# --- Job lifecycle ------------------------------------------------------------

def _fake_script(tmp_path, body: str) -> Path:
    p = tmp_path / "fake-run.sh"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def _wait(pred, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def test_analysis_output_is_capped(mk, tmp_path, monkeypatch):
    mod, c = mk()
    monkeypatch.setattr(mod, "RUN_SCRIPT", _fake_script(
        tmp_path, "head -c 2000000 /dev/zero | tr '\\0' 'e' >&2\nexit 3\n"))
    r = c.post("/cmtrace-view", files={"files": ("a.log", b"x\n", "text/plain")},
               follow_redirects=False)
    job = r.headers["location"].split("/")[2]
    assert c.post(f"/result/{job}/analyze", follow_redirects=False).status_code in (200, 303)
    assert _wait(lambda: (mod.read_status(job) or {}).get("state") == "failed")
    st = mod.read_status(job)
    assert len(st["stderr"]) <= mod._PROC_OUTPUT_TAIL + 100
    assert "truncated" in st["stderr"]


def test_subprocess_env_has_no_secrets(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path, GRAPH_CLIENT_SECRET="s3cret",
                    APP_PASSWORD="pw")
    env = mod.subprocess_env()
    assert "GRAPH_CLIENT_SECRET" not in env and "APP_PASSWORD" not in env
    assert "PATH" in env


def test_deleting_a_running_job_kills_its_process(mk, tmp_path, monkeypatch):
    mod, c = mk()
    pidfile = tmp_path / "pid"
    monkeypatch.setattr(mod, "RUN_SCRIPT", _fake_script(
        tmp_path, f"echo $$ > {pidfile}\nsleep 60\n"))
    r = c.post("/cmtrace-view", files={"files": ("a.log", b"x\n", "text/plain")},
               follow_redirects=False)
    job = r.headers["location"].split("/")[2]
    c.post(f"/result/{job}/analyze", follow_redirects=False)
    assert _wait(lambda: pidfile.exists() and pidfile.read_text().strip())
    pid = int(pidfile.read_text())
    assert c.post(f"/result/{job}/delete").json()["deleted"] is True

    def gone():
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        # A killed child may linger as a zombie until reaped.
        try:
            with open(f"/proc/{pid}/stat") as fh:
                return fh.read().split()[2] == "Z"
        except OSError:
            return True
    assert _wait(gone, 5)
    assert not mod.job_dir(job).exists()


def test_atomic_status_writes_leave_no_temp_files(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    jid = "c" * 32
    mod.job_dir(jid).mkdir(parents=True)
    for i in range(20):
        mod.write_status(jid, state="x", i=i)
        mod.update_status(jid, more=i)
    assert sorted(p.name for p in mod.job_dir(jid).iterdir()) == ["job.json"]
    assert mod.update_status("d" * 32, state="x") is False   # gone job: no-op


def test_retention_uses_created_stamp(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path, JOB_RETENTION_HOURS=1)
    jid = "e" * 32
    mod.job_dir(jid).mkdir(parents=True)
    mod.write_status(jid, state="logs", created=time.time() - 7200)
    # Fresh mtime (e.g. from a status update) must not extend the life.
    assert mod.cleanup_old_jobs() == 1


def test_single_worker_lock(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    mod.JOBS_DIR.mkdir(parents=True)
    mod.acquire_worker_lock()
    try:
        import fcntl
        with open(mod.JOBS_DIR / ".worker.lock", "a+") as fh:
            with pytest.raises(OSError):
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        mod.release_worker_lock()


# --- Drop-off credentials -------------------------------------------------------

def _gen_key() -> str:
    import base64
    import secrets as s
    return "shk_" + base64.urlsafe_b64encode(s.token_bytes(32)).rstrip(b"=").decode()


def test_inbox_key_and_upload_token_are_split(mk):
    mod, c = mk()
    key = _gen_key()
    up = c.post("/inbox/upload-token", headers={"X-Inbox-Key": key}).json()
    token = up["upload_token"]
    assert token.startswith("shu_") and token == mod.derive_upload_token(key)
    assert up["legacy"] is False

    pkg = _zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n"})
    # The inbox key itself must never be accepted on a device.
    assert c.post("/api/diagnostics", content=pkg,
                  headers={"X-Upload-Token": key}).status_code == 401
    r = c.post("/api/diagnostics", content=pkg,
               headers={"X-Upload-Token": token, "X-Device-Name": "PC42"})
    assert r.status_code == 200
    job = r.json()["job_id"]

    # The key lists it; the device's upload token cannot open the inbox.
    assert "PC42" in c.post("/inbox", data={"token": key}).text
    denied = c.post("/inbox", data={"token": token})
    assert denied.status_code == 400 and "PC42" not in denied.text
    assert c.post("/inbox/delete", headers={"X-Inbox-Key": token}).status_code == 401
    assert c.post("/inbox/delete-one", headers={"X-Inbox-Key": token,
                                                "X-Job-Id": job}).status_code == 401
    assert c.post("/inbox/delete-one", headers={"X-Inbox-Key": key,
                                                "X-Job-Id": job}).json()["deleted"]


def test_legacy_token_still_works_and_is_flagged(mk):
    mod, c = mk()
    pkg = _zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n"})
    assert c.post("/api/diagnostics", content=pkg,
                  headers={"X-Upload-Token": LEGACY_TOK,
                           "X-Device-Name": "OLD1"}).status_code == 200
    page = c.post("/inbox", data={"token": LEGACY_TOK}).text
    assert "OLD1" in page and "legacy token" in page
    assert c.post("/inbox/upload-token",
                  headers={"X-Inbox-Key": LEGACY_TOK}).json()["upload_token"] == LEGACY_TOK


def test_prefixed_tokens_have_a_strict_charset(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    assert mod.token_problem("shu_" + "a" * 30 + "'", "upload")
    assert mod.token_problem("x" * 30 + " y", "upload")
    assert mod.token_problem("shu_" + "A" * 43, "upload") is None


def test_pending_file_cap(mk):
    mod, c = mk(MAX_PENDING_FILES=2)
    codes = [c.post("/api/collect-status", json={"phase": "start"},
                    headers={"X-Upload-Token": f"tok{i}" + "x" * 30}).status_code
             for i in range(3)]
    assert codes == [204, 204, 429]


def test_remediation_template_pins_collector_hash(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    fake = tmp_path / "Remediate.ps1"
    fake.write_text("$CollectorSha256 = '<COLLECTOR-SHA256>'\n")
    monkeypatch.setattr(mod, "REMEDIATE_SCRIPT", fake)
    import hashlib
    want = hashlib.sha256(mod.COLLECT_SCRIPT.read_bytes()).hexdigest().upper()
    assert mod.load_remediation_template() == f"$CollectorSha256 = '{want}'\n"


# --- CSP nonces / headers ---------------------------------------------------------

_SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.I)


def _nonce_of(resp) -> str:
    m = re.search(r"'nonce-([0-9a-f]{32})'", resp.headers["content-security-policy"])
    assert m, resp.headers["content-security-policy"]
    return m.group(1)


def test_every_inline_script_has_a_fresh_nonce(mk):
    mod, c = mk()
    pages = ["/", "/cmtrace", "/diagnostics", "/errorcodes", "/inbox"]
    r = c.post("/cmtrace-view", files={"files": ("a.log", b"<![LOG[hi]LOG]!><time=\"1\" date=\"2\" component=\"c\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n", "text/plain")},
               follow_redirects=False)
    job = r.headers["location"].split("/")[2]
    pages += [f"/result/{job}/cmtrace", f"/result/{job}/cmtrace/view?file=a.log"]
    seen = set()
    for url in pages:
        resp = c.get(url)
        assert resp.status_code == 200, url
        nonce = _nonce_of(resp)
        seen.add(nonce)
        tags = _SCRIPT_TAG.findall(resp.text)
        assert tags, url
        for attrs in tags:
            assert f'nonce="{nonce}"' in attrs, (url, attrs)
        assert mod._CSP_NONCE_SENTINEL not in resp.text
        assert "unsafe-inline" not in resp.headers["content-security-policy"].split("script-src")[1].split(";")[0]
        assert " on" + "click=" not in resp.text
    assert len(seen) == len(pages)


def test_security_headers(mk):
    mod, c = mk()
    r = c.get("/")
    assert r.headers["strict-transport-security"].startswith("max-age=")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get("/inbox").headers["cache-control"] == "no-store"


# --- Basic auth ---------------------------------------------------------------

def test_basic_auth_handles_non_ascii_and_throttles_failures(mk):
    import base64
    mod, c = mk(APP_USER="beheerder", APP_PASSWORD="wachtwoord-é")

    def hdr(u, p):
        return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}

    assert c.get("/", headers=hdr("beheerder", "wachtwoord-é")).status_code == 200
    assert c.get("/", headers=hdr("béheerder", "x")).status_code == 401   # no 500
    assert c.get("/", headers={"Authorization": "Basic !!notb64"}).status_code == 401
    codes = [c.get("/", headers=hdr("x", "y")).status_code for _ in range(25)]
    assert codes[-1] == 429


# --- Dashboard correctness -----------------------------------------------------

_OMADM = ("Windows Registry Editor Version 5.00\n\n"
          r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\{12345678-1234-1234-1234-123456789012}]"
          "\n" '"LastSessionResult"=dword:00000000\n'
          '"ServerLastAccessTime"="2026-06-14T10:00:00Z"\n')


def _mdm_pkg(tmp_path, cert_block: str, enrollments: str = "") -> Path:
    pkg = tmp_path / "pkg"
    (pkg / "Registry").mkdir(parents=True)
    (pkg / "Identity").mkdir(parents=True)
    (pkg / "Identity" / "certs-machine-overview.txt").write_text(cert_block)
    (pkg / "Registry" / "OMADM-Accounts.reg").write_text(_OMADM)
    if enrollments:
        (pkg / "Registry" / "Enrollments.reg").write_text(enrollments)
    return pkg


def test_unrelated_expired_cert_is_not_a_zombie_device(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    pkg = _mdm_pkg(tmp_path, "Subject : CN=corp-wifi\nNotAfter : 1-1-2020\n"
                             "Thumbprint : DEF456\nExpired : True\n")
    checks = {c["label"]: c for c in mod.build_dashboard(pkg)["checks"]}
    assert checks["MDM sync health"]["status"] == "ok"


def test_mdm_cert_found_via_enrollment_reference(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    certs = mod.parse_cert_overview(
        "Subject : CN=whatever\nNotAfter : 1-1-2020\nThumbprint : AB CD 12\nExpired : True\n\n"
        "Subject : CN=other\nNotAfter : 1-1-2020\nThumbprint : FF00\nExpired : True\n")
    import types
    monkeypatch.setattr(mod, "parse_enrollments", lambda reg: [
        {"is_intune": True, "cert_thumbprint": "ABCD12"}])
    picked = mod._mdm_client_certs(certs, "x")
    assert [c["subject"] for c in picked] == ["CN=whatever"]


def test_read_text_tolerant_encodings(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    f = tmp_path / "t.txt"
    f.write_bytes("Hello Wörld".encode("utf-16-be"))
    assert mod.read_text_tolerant(f) == "Hello Wörld"
    f.write_bytes("Hello Wörld".encode("utf-16-le"))
    assert mod.read_text_tolerant(f) == "Hello Wörld"
    f.write_bytes("Café €5".encode("cp1252"))
    assert mod.read_text_tolerant(f) == "Café €5"
    f.write_bytes("Café".encode("utf-8"))
    assert mod.read_text_tolerant(f) == "Café"


def test_event_issue_json_accepts_single_object(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    assert mod.count_event_issues_json('{"Level": 2}') == {"errors": 1, "warnings": 0}


def test_html_escape_covers_attribute_quotes(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    page = mod.render_evtx_view("x.evtx", [{
        "time": "", "event_id": "1", "level": "2", "level_name": "Error",
        "provider": 'x" autofocus onfocus="alert(1)', "msg": "m"}], False)
    assert 'onfocus="alert(1)' not in page
    assert "&quot;" in page


def test_untrusted_html_is_never_top_level(mk):
    mod, c = mk()
    pkg = _zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n",
                "Reports/evil.html": "<script>location='https://evil'</script>"})
    r = c.post("/diagnostics-analyze", files={"files": ("p.zip", pkg, "application/zip")},
               follow_redirects=False)
    job = r.headers["location"].rsplit("/", 1)[-1]
    url = f"/result/{job}/files/view?file=Reports/evil.html"
    top = c.get(url, headers={"Sec-Fetch-Dest": "document"}, follow_redirects=False)
    assert top.status_code == 303 and top.headers["location"] == f"/result/{job}"
    framed = c.get(url, headers={"Sec-Fetch-Dest": "iframe"})
    assert framed.status_code == 200
    csp = framed.headers["content-security-policy"]
    assert csp.startswith("sandbox") and "allow-popups" not in csp
    assert "default-src 'none'" in csp


def test_search_reports_hits_beyond_viewer_limit(mk):
    mod, c = mk(CMTRACE_MAX_LINES=10)
    body = "".join(f"line {i}\n" for i in range(50)) + "needle here\n"
    r = c.post("/cmtrace-view", files={"files": ("a.log", body.encode(), "text/plain")},
               follow_redirects=False)
    job = r.headers["location"].split("/")[2]
    res = c.get(f"/result/{job}/search", params={"q": "needle"}).json()
    assert res["hits"][0]["line"] == 51 and res["hits"][0]["beyond_view"] is True


def test_health_does_not_leak_paths(mk):
    mod, c = mk()
    body = c.get("/health").json()
    assert body["pwsh"] in ("available", "missing")


def test_graph_partial_fetch_is_not_cached(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    calls = {"n": 0}

    class R:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(self.payload).encode()

    def fake_open(req, timeout=0):
        calls["n"] += 1
        if calls["n"] == 1:
            return R({"value": [{"id": "a"}],
                      "@odata.nextLink": "https://graph.microsoft.com/next"})
        raise OSError("boom")

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_open)
    assert mod._graph_fetch_all("https://graph.microsoft.com/x", "t", "t") is None


def test_access_log_redacts_ids_and_queries(monkeypatch, tmp_path):
    import logging
    mod = _load_app(monkeypatch, tmp_path)
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                            '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4", "GET", "/result/" + "a" * 32 + "/search?q=secret",
                             "1.1", 200), None)
    mod._AccessLogRedactor().filter(rec)
    line = rec.getMessage()
    assert "secret" not in line and "a" * 32 not in line


def test_html_is_gzipped_but_downloads_are_not(mk):
    mod, c = mk()
    r = c.get("/", headers={"Accept-Encoding": "gzip"})
    assert r.headers.get("content-encoding") == "gzip"
    # The nonce survives compression (replaced before gzip).
    assert mod._CSP_NONCE_SENTINEL not in r.text


def test_collection_card_reports_redaction_outcome(monkeypatch, tmp_path):
    mod = _load_app(monkeypatch, tmp_path)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "_MANIFEST.json").write_text(json.dumps({
        "CollectorVersion": "1.4.0", "WrapperVersion": "1.4.0", "Profile": "Remote",
        "Anonymized": False,
        "Redaction": {"Performed": True, "Ok": False, "FilesRemoved": 2,
                      "AnonymizeGaps": []},
        "Steps": [{"Name": "a", "Ok": True}]}))
    dash = mod.build_dashboard(pkg)
    card = {c["label"]: c for c in dash["checks"]}["Collection"]
    assert card["status"] == "warn"
    assert "2 file(s) removed" in card["detail"]


def test_inbox_limit_counts_only_empty_lookups(mk):
    mod, c = mk()
    mod._inbox_limiter.limit = 3
    pkg = _zip({"Identity/dsregcmd-status.txt": "AzureAdJoined : YES\n"})
    c.post("/api/diagnostics", content=pkg, headers={"X-Upload-Token": LEGACY_TOK})
    # A real inbox can be refreshed as often as it likes...
    assert all(c.post("/inbox", data={"token": LEGACY_TOK}).status_code == 200
               for _ in range(10))
    # ...but guessing (empty results) is throttled.
    codes = [c.post("/inbox", data={"token": "g" * 30 + str(i)}).status_code
             for i in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[-1] == 429
