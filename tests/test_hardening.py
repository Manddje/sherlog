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
