"""
IME Log Analyzer — web layer (FastAPI).

Uploads IME .log files (or a .zip), runs the headless analysis script
(scripts/run-analysis.sh) and serves the generated HTML timeline report.

State lives on the filesystem only (no DB/Redis):
  <JOBS_DIR>/<uuid>/input/    uploaded .log files
  <JOBS_DIR>/<uuid>/output/   generated HTML report
  <JOBS_DIR>/<uuid>/job.json  job status (running|done|failed)

Configuration (env, with safe defaults):
  MAX_UPLOAD_MB           default 100
  JOB_RETENTION_HOURS     default 24
  SCRIPT_TIMEOUT_SECONDS  default 300
  APP_USER / APP_PASSWORD default empty (auth disabled, logs a warning)
  JOBS_DIR                default /data/jobs
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import shutil
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.datastructures import UploadFile
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ime-analyzer")

# --- Configuration -----------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
RUN_SCRIPT = APP_DIR / "scripts" / "run-analysis.sh"

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
# Defence against zip bombs: cap total uncompressed bytes extracted.
MAX_UNCOMPRESSED_BYTES = MAX_UPLOAD_BYTES * 20
JOB_RETENTION_HOURS = int(os.environ.get("JOB_RETENTION_HOURS", "24"))
SCRIPT_TIMEOUT_SECONDS = int(os.environ.get("SCRIPT_TIMEOUT_SECONDS", "300"))
# Cap parallel analysis subprocesses so a public deployment can't be exhausted
# by many concurrent uploads (each run is CPU/memory heavy).
JOB_CONCURRENCY = max(1, int(os.environ.get("JOB_CONCURRENCY", "2")))
JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/data/jobs"))
APP_USER = os.environ.get("APP_USER", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

ALLOWED_EXTENSIONS = {".log", ".zip"}
CHUNK = 1024 * 1024

# Bounds the number of analysis subprocesses running at once.
_job_sem = asyncio.Semaphore(JOB_CONCURRENCY)


# --- Job state on disk -------------------------------------------------------

def job_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


def status_path(job_id: str) -> Path:
    return job_dir(job_id) / "job.json"


def write_status(job_id: str, **fields) -> None:
    status_path(job_id).write_text(json.dumps(fields), encoding="utf-8")


def read_status(job_id: str) -> Optional[dict]:
    p = status_path(job_id)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def find_report(output_dir: Path) -> Optional[Path]:
    reports = sorted(output_dir.glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
    return reports[0] if reports else None


# --- Analysis subprocess -----------------------------------------------------

async def run_job(job_id: str, input_dir: Path, output_dir: Path) -> None:
    """Run the headless analysis script and record the outcome."""
    write_status(job_id, state="queued")
    async with _job_sem:  # wait here if we are at the concurrency cap
        await _run_job_locked(job_id, input_dir, output_dir)


async def _run_job_locked(job_id: str, input_dir: Path, output_dir: Path) -> None:
    write_status(job_id, state="running")
    try:
        proc = await asyncio.create_subprocess_exec(
            str(RUN_SCRIPT), str(input_dir), str(output_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(), timeout=SCRIPT_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            write_status(
                job_id, state="failed", exitcode=None,
                stdout="", stderr=f"Analysis timed out after {SCRIPT_TIMEOUT_SECONDS}s.",
            )
            log.warning("job %s timed out", job_id)
            return

        stdout = out_b.decode("utf-8", "replace")
        stderr = err_b.decode("utf-8", "replace")
        rc = proc.returncode
        report = find_report(output_dir)
        if rc == 0 and report is not None:
            write_status(job_id, state="done", exitcode=0,
                         report=report.name, stdout=stdout, stderr=stderr)
            log.info("job %s done -> %s", job_id, report.name)
        else:
            write_status(job_id, state="failed", exitcode=rc,
                         stdout=stdout, stderr=stderr)
            log.warning("job %s failed (exit %s)", job_id, rc)
    except Exception as e:  # pragma: no cover - defensive
        write_status(job_id, state="failed", exitcode=None, stdout="", stderr=repr(e))
        log.exception("job %s crashed", job_id)


# --- Upload handling ---------------------------------------------------------

class UploadError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


async def save_uploads(files: List[UploadFile], input_dir: Path) -> int:
    """Validate + store uploads into input_dir. Returns count of .log files staged.

    Raises UploadError on bad extension, size overrun or unsafe zip.
    """
    total = 0
    log_count = 0
    tmp_dir = input_dir.parent / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    for up in files:
        name = up.filename or ""
        ext = Path(name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise UploadError(400, f"Disallowed file type: {name!r} (only .log or .zip).")

        dest = tmp_dir / f"{uuid.uuid4().hex}{ext}"
        with dest.open("wb") as fh:
            while True:
                chunk = await up.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise UploadError(413, f"Upload exceeds {MAX_UPLOAD_MB} MB limit.")
                fh.write(chunk)

        if ext == ".zip":
            log_count += extract_zip_logs(dest, input_dir)
        else:  # .log
            target = input_dir / Path(name).name
            shutil.move(str(dest), str(target))
            log_count += 1

    return log_count


def extract_zip_logs(zip_path: Path, input_dir: Path) -> int:
    """Safely extract only .log members from a zip (zip-slip protected)."""
    base = input_dir.resolve()
    count = 0
    uncompressed = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member = info.filename
            if Path(member).suffix.lower() != ".log":
                continue
            # Resolve target and ensure it stays inside input_dir (zip-slip guard).
            target = (input_dir / member).resolve()
            if base != target and base not in target.parents:
                raise UploadError(400, f"Unsafe path in zip: {member!r}.")
            uncompressed += info.file_size
            if uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise UploadError(413, "Zip contents too large (possible zip bomb).")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, CHUNK)
            count += 1
    return count


# --- Auth middleware ---------------------------------------------------------

AUTH_ENABLED = bool(APP_USER and APP_PASSWORD)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers for a public deployment.

    The raw report (untrusted, built from log content) is served at
    /result/{id}/report and framed by a sandboxed <iframe>, so it does NOT
    get a permissive CSP here — that route sets its own sandbox header.
    """

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        # App chrome only frames its own same-origin report iframe.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; img-src data:; frame-src 'self'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'self'",
        )
        return resp


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health" or not AUTH_ENABLED:
            return await call_next(request)

        header = request.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
                user, _, pwd = decoded.partition(":")
            except Exception:
                user = pwd = ""
            if secrets.compare_digest(user, APP_USER) and secrets.compare_digest(pwd, APP_PASSWORD):
                return await call_next(request)

        return Response(
            "Authentication required.", status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="IME Log Analyzer"'},
        )


# --- Background cleanup ------------------------------------------------------

def cleanup_old_jobs() -> int:
    if not JOBS_DIR.is_dir():
        return 0
    cutoff = time.time() - JOB_RETENTION_HOURS * 3600
    removed = 0
    for child in JOBS_DIR.iterdir():
        if not child.is_dir():
            continue
        try:
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    if removed:
        log.info("cleanup removed %d old job(s)", removed)
    return removed


async def cleanup_loop() -> None:
    while True:
        try:
            cleanup_old_jobs()
        except Exception:  # pragma: no cover
            log.exception("cleanup loop error")
        await asyncio.sleep(3600)


# --- App lifespan ------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_ENABLED:
        log.warning("AUTH DISABLED: APP_USER/APP_PASSWORD not both set. App is OPEN.")
    else:
        log.info("Basic auth enabled for user %r", APP_USER)
    task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="IME Log Analyzer", lifespan=lifespan)
# Order matters: last added runs outermost. Auth must gate before anything,
# and security headers should be applied to every response (incl. 401s).
app.add_middleware(BasicAuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# --- HTML pages --------------------------------------------------------------

PAGE_CSS = """
  :root{ --bg:#ffffff; --fg:#1f2937; --muted:#6b7280; --accent:#2563eb;
    --border:#e5e7eb; --surface:#f9fafb; --radius:8px; }
  *{ box-sizing:border-box; }
  body{ font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    color:var(--fg); background:var(--bg); margin:0; line-height:1.55;
    -webkit-font-smoothing:antialiased; }
  a{ color:var(--accent); text-decoration:none; }
  a:hover{ text-decoration:underline; }
  .nav{ display:flex; align-items:center; justify-content:space-between;
    max-width:880px; margin:0 auto; padding:1.1rem 1.25rem; }
  .brand{ display:flex; align-items:center; gap:.55rem; font-weight:700;
    font-size:1.05rem; color:var(--fg); }
  .brand:hover{ text-decoration:none; }
  .dot{ width:1.7rem; height:1.7rem; border-radius:7px; background:var(--accent);
    display:inline-flex; align-items:center; justify-content:center; }
  .navlink{ color:var(--muted); font-size:.92rem; margin-left:1.4rem; }
  .wrap{ max-width:880px; margin:0 auto; padding:0 1.25rem; }
  .hero{ text-align:center; padding:3.5rem 0 2rem; }
  .hero h1{ font-size:2.4rem; line-height:1.15; letter-spacing:-.02em; margin:0 0 .9rem; }
  .hero p{ font-size:1.1rem; color:var(--muted); max-width:34rem; margin:0 auto; }
  .card{ border:1px solid var(--border); border-radius:12px; background:var(--bg);
    padding:1.75rem; box-shadow:0 1px 2px rgba(0,0,0,.04); }
  .drop{ border:2px dashed var(--border); border-radius:10px; padding:2.75rem 1rem;
    text-align:center; color:var(--muted); transition:.15s; cursor:pointer;
    background:var(--surface); }
  .drop:hover{ border-color:var(--accent); }
  .drop.hl{ border-color:var(--accent); background:rgba(37,99,235,.06); color:var(--accent); }
  .drop strong{ color:var(--fg); }
  ul#files{ list-style:none; padding:0; margin:1rem 0 0; font-size:.9rem; color:var(--muted); }
  ul#files li{ padding:.45rem .7rem; background:var(--surface); border:1px solid var(--border);
    border-radius:6px; margin-bottom:.4rem; }
  .row{ display:flex; align-items:center; justify-content:space-between; gap:1rem;
    margin-top:1.25rem; flex-wrap:wrap; }
  .limits{ color:var(--muted); font-size:.88rem; margin:0; }
  .badge{ display:inline-block; font-size:.72rem; font-weight:600; padding:.22rem .6rem;
    border-radius:999px; background:var(--surface); border:1px solid var(--border);
    color:var(--muted); margin:.15rem .35rem .15rem 0; }
  .btn{ font-size:.95rem; font-weight:600; padding:.62rem 1.5rem; border:0;
    border-radius:var(--radius); background:var(--accent); color:#fff; cursor:pointer;
    transition:.15s; }
  .btn:hover{ background:#1d4ed8; }
  .btn:disabled{ opacity:.45; cursor:not-allowed; }
  .btn-ghost{ background:transparent; color:var(--accent); border:1px solid var(--border); }
  .btn-ghost:hover{ background:var(--surface); }
  .center{ text-align:center; }
  pre{ background:var(--surface); border:1px solid var(--border); padding:1rem;
    border-radius:8px; overflow:auto; font-size:.85rem; }
  .spinner{ width:2.2rem; height:2.2rem; border:3px solid var(--border);
    border-top-color:var(--accent); border-radius:50%; animation:spin 1s linear infinite;
    margin:1.5rem auto; }
  @keyframes spin{ to{ transform:rotate(360deg); } }
  footer{ max-width:880px; margin:3rem auto 2rem; padding:1.5rem 1.25rem 0;
    border-top:1px solid var(--border); color:var(--muted); font-size:.85rem;
    display:flex; justify-content:space-between; flex-wrap:wrap; gap:.5rem; }
"""

_LOGO = ('<span class="dot"><svg width="15" height="15" viewBox="0 0 24 24" '
         'fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round">'
         '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>'
         '</svg></span>')

NAV = ("""<header><nav class="nav">
  <a class="brand" href="/">%(logo)s IME&nbsp;Analyzer</a>
  <span>
    <a class="navlink" href="https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics" target="_blank" rel="noopener">Engine</a>
    <a class="navlink" href="/health">Status</a>
  </span>
</nav></header>""" % {"logo": _LOGO})

FOOTER = ("""<footer>
  <span>IME Log Analyzer &middot; public tool, no login</span>
  <span>Timeline engine by <a href="https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics" target="_blank" rel="noopener">Petri Paavola</a></span>
</footer>""")

UPLOAD_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IME Log Analyzer</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>Analyze Intune Management Extension logs</h1>
    <p>Upload your IME logs and get an interactive HTML timeline of Win32App
       installs, detections and errors &mdash; right in your browser.</p>
  </section>
  <main class="wrap">
    <div class="card">
      <form id="form" action="/analyze" method="post" enctype="multipart/form-data">
        <div class="drop" id="drop">
          <strong>Drag &amp; drop</strong> a <code>.zip</code> or one or more
          <code>.log</code> files here, or <u>click to choose</u>.
          <input id="input" name="files" type="file" multiple
                 accept=".log,.zip" style="display:none">
        </div>
        <ul id="files"></ul>
        <div class="row">
          <p class="limits">
            <span class="badge">.log</span><span class="badge">.zip</span>
            Max total upload: <strong>%(max)d&nbsp;MB</strong>
          </p>
          <button id="submit" class="btn" type="submit" disabled>Analyze logs</button>
        </div>
      </form>
    </div>
  </main>
  %(footer)s
<script>
  const drop = document.getElementById('drop');
  const input = document.getElementById('input');
  const list = document.getElementById('files');
  const submit = document.getElementById('submit');
  function refresh() {
    list.innerHTML = '';
    for (const f of input.files) {
      const li = document.createElement('li');
      li.textContent = f.name + ' (' + (f.size/1048576).toFixed(2) + ' MB)';
      list.appendChild(li);
    }
    submit.disabled = input.files.length === 0;
  }
  drop.addEventListener('click', () => input.click());
  input.addEventListener('change', refresh);
  ['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.add('hl'); }));
  ['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.remove('hl'); }));
  drop.addEventListener('drop', ev => { input.files = ev.dataTransfer.files; refresh(); });
</script>
</body></html>"""

BUSY_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>Analyzing…</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <section class="hero">
    <div class="spinner"></div>
    <h1>Analyzing your logs…</h1>
    <p>The report is being generated. This page refreshes automatically.</p>
  </section>
  <main class="wrap center"><p class="limits">Job %(job)s</p></main>
  %(footer)s
</body></html>"""

REPORT_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IME timeline report</title>
<style>%(css)s
  html,body{height:100%%}
  .topbar{display:flex;align-items:center;justify-content:space-between;
    padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:var(--bg)}
  iframe{border:0;width:100%%;height:calc(100vh - 3.4rem);display:block}
</style></head><body>
  <div class="topbar">
    <a class="brand" href="/">%(logo)s IME&nbsp;Analyzer</a>
    <a class="btn btn-ghost" href="/">New analysis</a>
  </div>
  <iframe src="/result/%(job)s/report"
          sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"></iframe>
</body></html>"""

ERROR_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Analysis failed</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>Analysis failed</h1>
    <p>The analysis engine exited with code <code>%(exit)s</code>.</p>
  </section>
  <main class="wrap">
    <div class="card">
      <h3 style="margin-top:0">stderr</h3><pre>%(stderr)s</pre>
      <h3>stdout</h3><pre>%(stdout)s</pre>
      <p class="center"><a class="btn btn-ghost" href="/">&larr; Try another upload</a></p>
    </div>
  </main>
  %(footer)s
</body></html>"""


def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# The upstream script appends an author/branding banner (<footer> with author
# photo, MVP logo and a GitHub download link). We strip it from the served
# report at display time so the PowerShell script stays unpatched and
# upstream-mergeable (see CLAUDE.md: report format in the script is unchanged).
_BRANDING_FOOTER = re.compile(r"<footer\b[^>]*>.*?</footer>", re.IGNORECASE | re.DOTALL)


def strip_branding(html: str) -> str:
    return _BRANDING_FOOTER.sub("", html, count=1)


# --- Routes ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(UPLOAD_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "max": MAX_UPLOAD_MB,
    })


@app.get("/health")
async def health() -> JSONResponse:
    pwsh = shutil.which("pwsh")
    if pwsh:
        return JSONResponse({"status": "ok", "pwsh": pwsh})
    return JSONResponse({"status": "degraded", "pwsh": None}, status_code=503)


@app.post("/analyze")
async def analyze(request: Request) -> Response:
    # Early server-side size guard: reject before parsing/buffering the body.
    # Content-Length can be absent/spoofed, so save_uploads() still enforces the
    # real limit by counting bytes as it streams; this just fails fast.
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_UPLOAD_BYTES:
                return HTMLResponse(
                    f"Upload exceeds {MAX_UPLOAD_MB} MB limit.", status_code=413
                )
        except ValueError:
            return HTMLResponse("Invalid Content-Length.", status_code=400)

    form = await request.form()
    files = [v for v in form.getlist("files") if isinstance(v, UploadFile) and v.filename]
    if not files:
        return HTMLResponse("No files uploaded.", status_code=400)

    job_id = uuid.uuid4().hex
    base = job_dir(job_id)
    input_dir = base / "input"
    output_dir = base / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        staged = await save_uploads(files, input_dir)
    except UploadError as e:
        shutil.rmtree(base, ignore_errors=True)
        return HTMLResponse(html_escape(e.message), status_code=e.status_code)
    finally:
        shutil.rmtree(base / "tmp", ignore_errors=True)

    if staged == 0:
        shutil.rmtree(base, ignore_errors=True)
        return HTMLResponse("No .log files found in the upload.", status_code=400)

    asyncio.create_task(run_job(job_id, input_dir, output_dir))
    return RedirectResponse(url=f"/result/{job_id}", status_code=303)


@app.get("/result/{job_id}", response_class=HTMLResponse)
async def result(job_id: str) -> Response:
    # Reject anything that isn't a clean job id (no path traversal).
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)

    status = read_status(job_id)
    if status is None:
        return HTMLResponse("Unknown job.", status_code=404)

    state = status.get("state")
    if state in ("running", "queued"):
        return HTMLResponse(BUSY_PAGE % {
            "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "job": job_id,
        })

    if state == "done":
        # Wrap the (untrusted) report in a sandboxed iframe — see /report below.
        return HTMLResponse(REPORT_PAGE % {"css": PAGE_CSS, "logo": _LOGO, "job": job_id})

    # failed
    return HTMLResponse(
        ERROR_PAGE % {
            "css": PAGE_CSS, "nav": NAV, "footer": FOOTER,
            "exit": html_escape(str(status.get("exitcode"))),
            "stderr": html_escape(status.get("stderr", "")) or "(empty)",
            "stdout": html_escape(status.get("stdout", "")) or "(empty)",
        },
        status_code=500,
    )


@app.get("/result/{job_id}/report", response_class=HTMLResponse)
async def report_raw(job_id: str) -> Response:
    """Serve the raw report. Untrusted (built from log content), so it is only
    ever loaded inside the sandboxed iframe in REPORT_PAGE. A CSP `sandbox`
    directive isolates it from the app origin even if framed elsewhere."""
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)

    status = read_status(job_id)
    if status is None or status.get("state") != "done":
        return HTMLResponse("Report not available.", status_code=404)

    report = job_dir(job_id) / "output" / status.get("report", "")
    if not report.is_file():
        return HTMLResponse("Report missing.", status_code=500)

    return HTMLResponse(
        strip_branding(report.read_text(encoding="utf-8", errors="replace")),
        headers={"Content-Security-Policy": "sandbox allow-scripts allow-popups"},
    )
