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
  CMTRACE_MAX_LINES       default 50000 (cap rendered rows in the log viewer)
  LONG_SCRIPT_THRESHOLD_SECONDS  default 180 (flag long-running PowerShell
                          scripts in the timeline; consumed by run-analysis.sh)
  EVTX_MAX_EVENTS         default 2000 (cap events parsed per .evtx view)
  GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET
                          default empty; set all three to enrich the RSOP table
                          with friendly Intune setting names from the (global)
                          Microsoft Graph settings catalog. Off by default.
  CSP_NAMES_CACHE         default <JOBS_DIR>/../csp-names.json (catalog cache)
  CSP_NAMES_TTL_HOURS     default 720 (re-fetch the catalog after this age)
  ENABLE_UPLOAD_API       default off; enables /api/diagnostics + /inbox so an
                          Intune-deployed collector can drop off packages
  UPLOAD_TOKEN_MIN_LEN    default 24 (minimum length of a self-chosen token)
  UPLOAD_API_MAX_JOBS     default 2000 (global cap to bound disk abuse)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.datastructures import UploadFile
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles

try:  # optional: .evtx viewing degrades gracefully when python-evtx is absent
    from Evtx.Evtx import Evtx
except ImportError:  # pragma: no cover
    Evtx = None

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
# Cap rows rendered by the CMTrace log viewer so a large upload can't build a
# multi-hundred-MB HTML table; extra lines are dropped with a notice.
CMTRACE_MAX_LINES = max(1, int(os.environ.get("CMTRACE_MAX_LINES", "50000")))

ALLOWED_EXTENSIONS = {".log", ".zip"}
CHUNK = 1024 * 1024

# Cap events parsed per .evtx file in the event log viewer (python-evtx is
# pure Python; large System.evtx files would otherwise stall the request).
EVTX_MAX_EVENTS = max(1, int(os.environ.get("EVTX_MAX_EVENTS", "2000")))

# Optional Settings-Catalog name enrichment via Microsoft Graph. When all three
# GRAPH_* vars are set, the (tenant-independent) configuration-settings catalog
# is fetched ONCE at startup and cached to CSP_NAMES_CACHE, so the RSOP table
# can show the friendly Intune setting display name next to each CSP setting.
# Off by default: no creds -> no external call, behaviour is unchanged. The
# cache file can also be pre-generated (build-time) and shipped without creds.
GRAPH_TENANT_ID = os.environ.get("GRAPH_TENANT_ID", "")
GRAPH_CLIENT_ID = os.environ.get("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET = os.environ.get("GRAPH_CLIENT_SECRET", "")
GRAPH_ENABLED = bool(GRAPH_TENANT_ID and GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET)
CSP_NAMES_CACHE = Path(os.environ.get(
    "CSP_NAMES_CACHE", str(JOBS_DIR.parent / "csp-names.json")))
CSP_NAMES_TTL_HOURS = max(1, int(os.environ.get("CSP_NAMES_TTL_HOURS", "720")))

# Unattended device drop-off API (off by default). When ENABLE_UPLOAD_API is on,
# an Intune-deployed collector can POST a diagnostics zip to /api/diagnostics with
# a self-chosen secret in the X-Upload-Token header; the admin reviews uploads at
# /inbox?token=<same secret>. The token IS the namespace: only its sha256 hash is
# stored (on each job), never the token itself, and there is no token registry.
ENABLE_UPLOAD_API = os.environ.get("ENABLE_UPLOAD_API", "").lower() in (
    "1", "true", "yes", "on")
UPLOAD_TOKEN_MIN_LEN = max(8, int(os.environ.get("UPLOAD_TOKEN_MIN_LEN", "24")))
UPLOAD_API_MAX_JOBS = max(1, int(os.environ.get("UPLOAD_API_MAX_JOBS", "2000")))

# Diagnostics-package extension policy. Text-ish files get the line viewer,
# .log the CMTrace viewer, .html a sandboxed iframe, .evtx the event viewer.
# .cab archives (Defender MpSupportFiles.cab, LicensingDiag.cab) are expanded
# with cabextract when it is installed (handles MSZIP and LZX, which pure
# Python does not); without cabextract they stay listed (disabled) in the
# file tree. .etl is binary and unparseable on Linux: never extracted.
DIAG_TEXT_EXTS = {".txt", ".reg", ".xml", ".json", ".csv"}
DIAG_KEEP_EXTS = {".log", ".html", ".htm", ".evtx"} | DIAG_TEXT_EXTS

# cabextract binary (in the Docker image via apt). None → .cab not expanded.
CABEXTRACT = shutil.which("cabextract")
# A single .cab never takes longer than this to list or extract; a corrupt
# or hostile cab is treated as unexpandable instead of hanging the upload.
CAB_TIMEOUT_SECONDS = 120

# Bounds the number of analysis subprocesses running at once.
_job_sem = asyncio.Semaphore(JOB_CONCURRENCY)


# --- Job state on disk -------------------------------------------------------

def token_hash(raw: str) -> str:
    """Stable sha256 hex of an upload token. Only this hash is persisted (on the
    job) and compared for the inbox; the token itself never touches disk."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def job_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


def iter_job_dirs():
    """Yield every job directory under JOBS_DIR."""
    try:
        children = list(JOBS_DIR.iterdir())
    except OSError:
        return
    for child in children:
        if child.is_dir():
            yield child


def status_path(job_id: str) -> Path:
    return job_dir(job_id) / "job.json"


def write_status(job_id: str, **fields) -> None:
    status_path(job_id).write_text(json.dumps(fields), encoding="utf-8")


def update_status(job_id: str, **fields) -> None:
    """Merge fields into job.json (read-modify-write, atomic replace).

    Used by diagnostics jobs where the analysis task updates only its own
    sub-dict while the rest of the record stays intact.
    """
    current = read_status(job_id) or {}
    current.update(fields)
    p = status_path(job_id)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(current), encoding="utf-8")
    os.replace(tmp, p)


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


def _log_sort_key(rel: str):
    """Order classic IME CMTrace logs first; command-output dumps last."""
    leaf = rel.rsplit("/", 1)[-1].lower()
    is_cmd = leaf.startswith("(") or ("command" in leaf and "output" in leaf)
    return (1 if is_cmd else 0, rel.lower())


def list_input_files(job_id: str, exts: Optional[set] = None) -> List[str]:
    """Relative POSIX paths of files under <job>/input (the raw uploads).

    Recurses so a folder structure from a diagnostics zip is preserved; the
    returned paths double as the membership allow-list for the view routes.
    `exts` restricts to those suffixes (lowercased); None lists everything.
    """
    input_dir = job_dir(job_id) / "input"
    if not input_dir.is_dir():
        return []
    rels = [
        p.relative_to(input_dir).as_posix()
        for p in input_dir.rglob("*")
        if p.is_file() and (exts is None or p.suffix.lower() in exts)
    ]
    return sorted(rels, key=_log_sort_key)


def list_input_logs(job_id: str) -> List[str]:
    return list_input_files(job_id, exts={".log"})


def find_ime_log_dir(input_dir: Path) -> Optional[Path]:
    """Best directory inside a diagnostics package to run the timeline on.

    The analysis script scans a folder recursively, so point it at the IME
    logs only — not the whole package full of non-CMTrace noise. Preference:
    the collector's Apps-IME/Logs folder, then any folder holding
    IntuneManagementExtension.log, then any folder with .log files at all.
    """
    preferred = input_dir / "Apps-IME" / "Logs"
    if preferred.is_dir() and any(preferred.glob("*.log")):
        return preferred
    for marker in sorted(input_dir.rglob("IntuneManagementExtension.log")):
        return marker.parent
    for any_log in sorted(input_dir.rglob("*.log")):
        return any_log.parent
    return None


def read_text_tolerant(path: Path, max_bytes: int = MAX_UPLOAD_BYTES) -> str:
    """Read a text file whose encoding is unknown.

    PowerShell 5.1 Out-File and `reg export` write UTF-16LE (usually with a
    BOM); other files in a diagnostics package are UTF-8 or ANSI. Sniff the
    BOM, fall back to a NUL-byte heuristic for BOM-less UTF-16, then UTF-8
    with replacement so decoding never raises.
    """
    data = path.read_bytes()[:max_bytes]
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")  # BOM picks endianness
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    # BOM-less UTF-16LE: ASCII text shows as `c\x00h\x00…` — many NULs in
    # the sample is a strong signal (UTF-8/ANSI text contains none).
    sample = data[:4096]
    if sample and sample.count(b"\x00") > len(sample) // 4:
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


# --- CMTrace log parsing -----------------------------------------------------
# IME logs use the CMTrace format, e.g.
#   <![LOG[message]LOG]!><time="08:45:50.100" date="9-13-2023"
#       component="IntuneManagementExtension" context="" type="1" thread="4" file="">
# The message may span newlines, so match non-greedily with DOTALL.
CMTRACE_RE = re.compile(
    r'<!\[LOG\[(?P<msg>.*?)\]LOG\]!>'
    r'<time="(?P<time>[^"]*)"\s+date="(?P<date>[^"]*)"'
    r'\s+component="(?P<component>[^"]*)"'
    r'[^>]*?\btype="(?P<type>[^"]*)"'
    r'[^>]*?\bthread="(?P<thread>[^"]*)"',
    re.DOTALL,
)


def _plain_records(chunk: str):
    """Yield one info record per non-blank line of a non-CMTrace chunk.

    Command-output logs (ipconfig, netsh, …) aren't CMTrace-formatted, so we keep
    them readable line-by-line instead of as one giant blob.
    """
    for line in chunk.splitlines():
        if line.strip() == "":
            continue
        yield {"msg": line.rstrip("\r"), "time": "", "date": "",
               "component": "", "type": "", "thread": "", "structured": False}


def parse_cmtrace(text: str, limit: int = CMTRACE_MAX_LINES) -> tuple[List[dict], bool]:
    """Parse CMTrace-formatted text into records.

    Returns (records, truncated). CMTrace lines become structured records;
    anything between/around them is split into per-line info records so no content
    is dropped. Stops at `limit` records and reports truncation.
    """
    records: List[dict] = []
    truncated = False
    pos = 0

    def add(rec: dict) -> bool:
        nonlocal truncated
        if len(records) >= limit:
            truncated = True
            return False
        records.append(rec)
        return True

    def add_plain(chunk: str) -> bool:
        for rec in _plain_records(chunk):
            if not add(rec):
                return False
        return True

    for m in CMTRACE_RE.finditer(text):
        if not add_plain(text[pos:m.start()]):
            return records, truncated
        if not add({
            "msg": m.group("msg"),
            "time": m.group("time"),
            "date": m.group("date"),
            "component": m.group("component"),
            "type": m.group("type"),
            "thread": m.group("thread"),
            "structured": True,
        }):
            return records, truncated
        pos = m.end()
        # Skip the trailing `... file="">` tail of the matched line.
        tail = text.find(">", pos)
        if tail != -1 and text.find("<![LOG[", pos, tail) == -1:
            pos = tail + 1

    add_plain(text[pos:])
    return records, truncated


# --- EVTX (Windows event log) parsing ----------------------------------------
# python-evtx renders each record as the standard Event XML. Offline rendering
# of localized message tables is impossible on Linux, so the message is the
# RenderingInfo text when the exporter embedded it, else the raw EventData
# values — still enough to spot error codes and failing components.

_EVTX_LEVELS = {"1": "Critical", "2": "Error", "3": "Warning",
                "4": "Information", "5": "Verbose", "0": "LogAlways"}


def evtx_xml_to_record(xml_text: str) -> dict:
    """Reduce one Event XML blob to the record shape the viewer renders.

    Total: malformed XML degrades to a raw-text record, never raises.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"time": "", "event_id": "", "level": "", "level_name": "",
                "provider": "", "msg": xml_text.strip()[:_CELL_CAP]}

    def text_of(path: str) -> str:
        el = root.find(path)
        return (el.text or "").strip() if el is not None else ""

    time_el = root.find(".//{*}System/{*}TimeCreated")
    when = time_el.get("SystemTime", "") if time_el is not None else ""
    when = when[:19].replace("T", " ")
    prov_el = root.find(".//{*}System/{*}Provider")
    provider = prov_el.get("Name", "") if prov_el is not None else ""
    level = text_of(".//{*}System/{*}Level")

    msg = text_of(".//{*}RenderingInfo/{*}Message")
    if not msg:
        parts = []
        for d in root.findall(".//{*}EventData/{*}Data"):
            val = (d.text or "").strip()
            if not val:
                continue
            name = d.get("Name", "")
            parts.append(f"{name}: {val}" if name else val)
        msg = "\n".join(parts)

    return {"time": when,
            "event_id": text_of(".//{*}System/{*}EventID"),
            "level": level,
            "level_name": _EVTX_LEVELS.get(level, level),
            "provider": provider,
            "msg": msg}


def parse_evtx_file(path: Path, limit: int = EVTX_MAX_EVENTS) -> tuple[List[dict], bool]:
    """Parse up to `limit` records from an .evtx file.

    Corrupt chunks/records are common in exported logs; per-record failures
    are skipped so one bad record never kills the view.
    """
    if Evtx is None:
        raise RuntimeError("python-evtx is not installed")
    records: List[dict] = []
    truncated = False
    with Evtx(str(path)) as ev:
        for rec in ev.records():
            if len(records) >= limit:
                truncated = True
                break
            try:
                records.append(evtx_xml_to_record(rec.xml()))
            except Exception:
                continue
    return records, truncated


def _evtx_row_class(level: str) -> str:
    if level in ("1", "2"):
        return "err"
    if level == "3":
        return "warn"
    return ""


# --- Timeline report summary -------------------------------------------------
# The generated HTML report contains the full observed timeline as
# <table id="ObservedTimeline"> (columns: Index, Date, Status, Type, Intent,
# Detail, Seconds, LogEntry, Color, DetailToolTip) and the download stats as
# <table id="ApplicationDownloadStatistics">. We parse those tables back out to
# build a compact summary for the result page. The report unescapes <\> inside
# timeline cells (upstream "Fix-HTMLSyntax"), so log content can contain raw
# pseudo-tags; the parser ignores unknown tags and keeps accumulating cell text.

_TIMELINE_COLS = ("index", "date", "status", "type", "intent",
                  "detail", "seconds", "logentry")
_DOWNLOAD_COLS = ("app_type", "app_name", "dl_sec", "size_mb", "mbps", "do_pct")
_CELL_CAP = 1000  # bound memory per parsed cell
SUMMARY_DETAIL_CAP = 300
SUMMARY_MAX_FAILED_ITEMS = 50
SUMMARY_MAX_ITEMS = 500


@dataclass
class ReportSummary:
    timeline: list[dict] = field(default_factory=list)
    downloads: list[dict] = field(default_factory=list)
    parse_ok: bool = True


class _ReportTableParser(HTMLParser):
    """Pull rows out of the two known summary tables of the timeline report."""

    TABLES = {"ObservedTimeline": "timeline",
              "ApplicationDownloadStatistics": "downloads"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: dict[str, list[list[str]]] = {"timeline": [], "downloads": []}
        self._table: Optional[str] = None
        self._row: Optional[list[str]] = None
        self._cell: Optional[list[str]] = None
        self._row_is_header = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "table":
            table_id = dict(attrs).get("id", "")
            self._table = self.TABLES.get(table_id)
        elif self._table and tag == "tr":
            self._row, self._row_is_header = [], False
        elif self._table and self._row is not None and tag in ("td", "th"):
            self._cell = []
            self._row_is_header = self._row_is_header or tag == "th"
        # Anything else (including unescaped pseudo-tags from log content) is
        # ignored; cell text keeps accumulating across it.

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._table = None
        elif self._table and tag in ("td", "th") and self._cell is not None:
            if self._row is not None:
                self._row.append("".join(self._cell)[:_CELL_CAP].strip())
            self._cell = None
        elif self._table and tag == "tr" and self._row is not None:
            if not self._row_is_header and self._row:
                self.rows[self._table].append(self._row)
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None and len(self._cell) < _CELL_CAP:
            self._cell.append(data)


def parse_report_summary(html: str) -> ReportSummary:
    """Parse the timeline + download tables out of a generated report.

    Never raises: any parse failure degrades to parse_ok=False so the job
    outcome is unaffected.
    """
    summary = ReportSummary()
    try:
        parser = _ReportTableParser()
        parser.feed(html)
        parser.close()
        for row in parser.rows["timeline"]:
            if len(row) < len(_TIMELINE_COLS):
                continue
            summary.timeline.append(dict(zip(_TIMELINE_COLS, row)))
        for row in parser.rows["downloads"]:
            if len(row) < len(_DOWNLOAD_COLS):
                continue
            summary.downloads.append(dict(zip(_DOWNLOAD_COLS, row)))
    except Exception:
        log.warning("report summary parse failed", exc_info=True)
        return ReportSummary(parse_ok=False)
    return summary


_HEX_CODE_RE = re.compile(r"0x[0-9A-Fa-f]{8}")
_SIGNED_DEC_RE = re.compile(r"-2\d{9}")
_EXIT_CODE_RE = re.compile(r"\b(?:exit|error)\s*code[:\s]+(\d{3,4})\b", re.IGNORECASE)


def find_error_codes(text: str) -> dict[str, str]:
    """Server-side mirror of the CMTrace viewer's client-side code lookup."""
    found: dict[str, str] = {}
    for m in _HEX_CODE_RE.finditer(text):
        key = "0x" + m.group(0)[2:].upper()
        if key in ERROR_CODES:
            found[key] = ERROR_CODES[key]
    for m in _SIGNED_DEC_RE.finditer(text):
        key = "0x" + format(int(m.group(0)) & 0xFFFFFFFF, "08X")
        if key in ERROR_CODES:
            found[key] = ERROR_CODES[key]
    for m in _EXIT_CODE_RE.finditer(text):
        if m.group(1) in ERROR_CODES:
            found[m.group(1)] = ERROR_CODES[m.group(1)]
    return found


def summarize(summary: ReportSummary) -> dict:
    """Reduce a parsed report to the model rendered on the result page."""
    counts: dict[str, dict[str, int]] = {}
    failed_items: list[dict] = []
    items: list[dict] = []
    code_counter: Counter[str] = Counter()
    warnings = 0
    not_detected = 0

    for row in summary.timeline:
        status, rtype = row["status"], row["type"]
        if status in ("Success", "Failed") and rtype:
            bucket = counts.setdefault(rtype, {"success": 0, "failed": 0})
            bucket["success" if status == "Success" else "failed"] += 1
        if status == "Warning":
            warnings += 1
        if status == "Not Detected":
            not_detected += 1
        if status in ("Failed", "ErrorLog"):
            for code in find_error_codes(row["detail"]):
                code_counter[code] += 1
        if status == "Failed":
            failed_items.append({
                "date": row["date"],
                "type": rtype,
                "intent": row["intent"],
                "detail": row["detail"][:SUMMARY_DETAIL_CAP],
            })
        # Per-type drill-down behind the summary chips: keep every outcome
        # row, success included (failed_items above stays for old jobs).
        if status in ("Success", "Failed", "Not Detected", "Warning"):
            items.append({
                "date": row["date"],
                "type": rtype,
                "intent": row["intent"],
                "status": status,
                "detail": row["detail"][:SUMMARY_DETAIL_CAP],
            })

    return {
        "parse_ok": summary.parse_ok,
        "counts": [{"type": t, **c} for t, c in sorted(counts.items())],
        "warnings": warnings,
        "not_detected": not_detected,
        "failed_items": failed_items[:SUMMARY_MAX_FAILED_ITEMS],
        "items": items[:SUMMARY_MAX_ITEMS],
        "top_errors": [
            {"code": code, "count": n, "explanation": ERROR_CODES[code]}
            for code, n in code_counter.most_common(10)
        ],
        "downloads": summary.downloads,
    }


# --- Diagnostics dashboard ---------------------------------------------------
# Health checks parsed from the text files a Collect-IntuneDiagnostics package
# contains. Every parser is total: garbage in -> empty out, never raises. The
# collector wraps every section in Invoke-Safe, so ANY file can be missing —
# a missing source yields status "unknown", not an error.

_KV_LINE_RE = re.compile(r"^\s*([A-Za-z][\w -]*?)\s*:\s*(.+?)\s*$", re.MULTILINE)


def parse_dsregcmd(text: str) -> dict:
    """Key/value scrape of `dsregcmd /status` output (also fits _SUMMARY.txt)."""
    return {m.group(1): m.group(2) for m in _KV_LINE_RE.finditer(text)}


# Same shape: the summary file uses `Key : value` lines for identity fields.
parse_summary_txt = parse_dsregcmd

_ENDPOINT_RE = re.compile(r"^\s*([a-z0-9.-]+\.[a-z]{2,})\s+(True|False)\b\s*(\S*)",
                          re.IGNORECASE | re.MULTILINE)


def parse_endpoint_connectivity(text: str) -> List[dict]:
    """Rows of the Test-NetConnection table: endpoint, reachable, remote IP."""
    return [
        {"endpoint": m.group(1), "reachable": m.group(2).lower() == "true",
         "remote_ip": m.group(3)}
        for m in _ENDPOINT_RE.finditer(text)
    ]


def parse_service_status(text: str) -> Optional[bool]:
    """True/False when a Running/Stopped state is found, None when unknown."""
    for line in text.splitlines():
        m = re.search(r"\b(Running|Stopped)\b", line)
        if m and re.search(r"intune", line, re.IGNORECASE):
            return m.group(1) == "Running"
    # Single-service table: the state may sit on a line without the name.
    m = re.search(r"\b(Running|Stopped)\b", text)
    return m.group(1) == "Running" if m else None


def parse_installed_apps(text: str) -> List[dict]:
    """Rows of the installed-apps Format-Table dump (header + dashes + rows).

    Column boundaries come from the dash runs under the header; the last
    column runs to the end of the line. Total: returns [] when the table
    (or the whole file) is missing.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if i == 0 or not re.match(r"^\s*-{2,}[\s-]*$", line):
            continue
        # The dash runs mark column *starts*; a column ends where the next
        # one starts (the dashes themselves are only as wide as the header).
        starts = [m.start() for m in re.finditer(r"-+", line)]
        bounds = list(zip(starts, starts[1:] + [None]))
        header = lines[i - 1]
        keys = [header[s:e].strip() or f"col{n}"
                for n, (s, e) in enumerate(bounds)]
        apps = []
        for row in lines[i + 1:]:
            if not row.strip():
                continue
            vals = [row[s:e].strip() for s, e in bounds]
            if any(vals):
                apps.append(dict(zip(keys, vals)))
        return apps
    return []


def parse_cert_overview(text: str) -> List[dict]:
    """Format-List blocks (blank-line separated) of the machine cert overview."""
    certs = []
    for block in re.split(r"\n\s*\n", text):
        kv = {m.group(1): m.group(2) for m in _KV_LINE_RE.finditer(block)}
        if not kv.get("Subject") and not kv.get("Thumbprint"):
            continue
        expired_raw = kv.get("Expired", kv.get("Verlopen", ""))
        certs.append({
            "subject": kv.get("Subject", ""),
            "not_after": kv.get("NotAfter", ""),
            "thumbprint": kv.get("Thumbprint", ""),
            "expired": expired_raw.strip().lower() == "true",
        })
    return certs


# --- Registry (.reg export) parsing -----------------------------------------
# `reg export` writes UTF-16LE text in a stable, simple grammar:
#   [Full\Key\Path]
#   "ValueName"=<typed-data>      (or @=... for the default value)
# Long values wrap with a trailing backslash. We only need string and dword
# data for the dashboards; other types keep their raw right-hand side.

_REG_KEY_RE = re.compile(r"^\[(.+)\]\s*$")
_GUID_TAIL = r"\{?[0-9a-fA-F-]{36}\}?"


def _reg_unescape(s: str) -> str:
    return s.replace('\\\\', '\\').replace('\\"', '"')


def parse_reg(text: str) -> "dict[str, dict[str, object]]":
    """Parse a `reg export` dump into {key_path: {value_name: data}}.

    Total: malformed lines are skipped, never raised. String values are
    unescaped; `dword:` becomes an int; everything else stays a raw string.
    Backslash-continued lines (hex blobs wrap) are joined first.
    """
    out: "dict[str, dict[str, object]]" = {}
    cur: Optional[dict] = None
    joined: List[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if joined and joined[-1].endswith("\\"):
            joined[-1] = joined[-1][:-1] + line.strip()
        else:
            joined.append(line)
    for line in joined:
        km = _REG_KEY_RE.match(line)
        if km:
            cur = out.setdefault(km.group(1), {})
            continue
        if cur is None or "=" not in line:
            continue
        name, _, rhs = line.partition("=")
        name = name.strip()
        if name != "@":
            if name[:1] == '"' and name[-1:] == '"':
                name = _reg_unescape(name[1:-1])
            else:
                continue
        rhs = rhs.strip()
        if rhs[:1] == '"':
            cur[name] = _reg_unescape(rhs[1:-1] if rhs.endswith('"') else rhs[1:])
        elif rhs.startswith("dword:"):
            try:
                cur[name] = int(rhs[6:], 16)
            except ValueError:
                cur[name] = rhs
        else:
            cur[name] = rhs
    return out


def _json_or_empty(s) -> dict:
    if not isinstance(s, str) or not s.strip():
        return {}
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def hresult_code(err) -> str:
    """Normalize an Intune ErrorCode (decimal int/string) to the 0xXXXXXXXX
    key form used in ERROR_CODES; '' for null/zero/empty/non-numeric."""
    if err in (None, "", "null", 0, "0"):
        return ""
    try:
        n = int(err)
    except (TypeError, ValueError):
        return ""
    if n == 0:
        return ""
    if str(n) in ERROR_CODES:          # MSI exit codes are decimal keys
        return str(n)
    return f"0x{n & 0xFFFFFFFF:08X}"


# Intune Win32 app state enums (as written to the IME registry).
_ENFORCEMENT_STATE = {
    1000: "Succeeded", 1001: "Succeeded (already compliant)",
    2000: "In progress", 3000: "Failed", 5000: "Error",
}
_COMPLIANCE_STATE = {
    0: "Unknown", 1: "Installed", 2: "Not installed",
    3: "Conflict", 4: "Error", 5: "Not applicable",
}
# An app-instance key is `…\Win32Apps\<userGUID>\<appGUID>_<intent>`; the
# ComplianceStateMessage / EnforcementStateMessage JSON live in same-named
# child keys (value name == subkey name).
_WIN32_APP_KEY_RE = re.compile(rf"(?P<base>\\Win32Apps\\[^\\]+\\(?P<app>{_GUID_TAIL})_\d+)$")
_WIN32_STATE_RE = re.compile(
    rf"\\Win32Apps\\[^\\]+\\{_GUID_TAIL}_\d+\\(ComplianceStateMessage|EnforcementStateMessage)$")


def parse_win32apps(reg: dict) -> List[dict]:
    """One row per tracked Win32 app from a Win32Apps.reg dump.

    Joins each app-instance key with its ComplianceStateMessage /
    EnforcementStateMessage child keys (the JSON the IME writes) and surfaces
    the state + deployment error code.
    """
    entries: "dict[str, dict]" = {}

    def slot(base: str, app: str) -> dict:
        return entries.setdefault(base, {"app_id": app.strip("{}"),
                                         "comp": {}, "enf": {}})

    for key, vals in reg.items():
        m = _WIN32_APP_KEY_RE.search(key)
        if m:
            slot(key, m.group("app"))
            continue
        sm = _WIN32_STATE_RE.search(key)
        if not sm:
            continue
        base = key[:sm.start(1) - 1]  # strip the trailing "\<StateName>"
        app = re.search(_GUID_TAIL + r"_\d+$", base)
        e = slot(base, app.group(0) if app else "")
        data = _json_or_empty(vals.get(sm.group(1)))
        e["comp" if sm.group(1).startswith("Compliance") else "enf"] = data

    apps = []
    for e in entries.values():
        comp, enf = e["comp"], e["enf"]
        code = hresult_code(enf.get("ErrorCode")) or hresult_code(comp.get("ErrorCode"))
        cs, es = comp.get("ComplianceState"), enf.get("EnforcementState")
        apps.append({
            "app_id": e["app_id"],
            "compliance": _COMPLIANCE_STATE.get(cs, "" if cs is None else str(cs)),
            "enforcement": _ENFORCEMENT_STATE.get(es, "" if es is None else str(es)),
            "error_code": code,
            "error_text": ERROR_CODES.get(code, "") if code else "",
            "failed": cs == 4 or es in (3000, 5000) or bool(code),
        })
    apps.sort(key=lambda a: (not a["failed"], a["app_id"]))
    return apps


def parse_enrollments(reg: dict) -> List[dict]:
    """MDM enrollment entries (the GUID subkeys directly under Enrollments)."""
    out = []
    rx = re.compile(rf"\\Enrollments\\({_GUID_TAIL})$")
    for key, vals in reg.items():
        m = rx.search(key)
        if not m:
            continue
        disc = str(vals.get("DiscoveryServiceFullURL", ""))
        upn = vals.get("UPN", "")
        provider = vals.get("ProviderID", "")
        if not (upn or provider or disc):
            continue
        out.append({
            "id": m.group(1).strip("{}"),
            "upn": str(upn), "provider": str(provider),
            "state": str(vals.get("EnrollmentState", "")),
            "discovery": disc,
            "is_intune": "manage.microsoft.com" in disc,
        })
    return out


def parse_sidecar_scripts(reg: dict) -> List[dict]:
    """Platform-script / Proactive-Remediation executions (SideCarPolicies)."""
    out = []
    rx = re.compile(
        rf"\\SideCarPolicies\\Scripts\\Execution\\[^\\]+\\({_GUID_TAIL}_\d+)$")
    for key, vals in reg.items():
        m = rx.search(key)
        if m:
            out.append({"policy": m.group(1).strip("{}"),
                        "last_execution": str(vals.get("LastExecution", ""))})
    return out


def parse_policymanager(reg: dict) -> dict:
    """Summarize PolicyManager\\current\\<scope>\\<area> settings + providers."""
    areas: "dict[str, int]" = {}
    providers = set()
    settings = 0
    rx = re.compile(r"\\PolicyManager\\current\\[^\\]+\\([^\\]+)$", re.IGNORECASE)
    for key, vals in reg.items():
        m = rx.search(key)
        if not m:
            continue
        names = [n for n in vals if n.endswith("_WinningProvider")]
        if not names:
            continue
        area = m.group(1)
        areas[area] = areas.get(area, 0) + len(names)
        settings += len(names)
        providers.update(str(vals[n]) for n in names)
    return {"area_count": len(areas), "setting_count": settings,
            "provider_count": len(providers), "areas": sorted(areas.items())}


_POLICY_DOC_BASE = "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-"


def policy_oma_uri(scope: str, area: str, setting: str) -> str:
    """Canonical Policy CSP OMA-URI for a PolicyManager registry setting.

    The registry scope segment is `device` (or `user`/a user SID); the CSP
    path uses `Device`/`User`. This is the same name Intune uses in a custom
    OMA-URI profile and in the Policy CSP reference.
    """
    csp_scope = "Device" if scope.lower() == "device" else "User"
    return f"./{csp_scope}/Vendor/MSFT/Policy/Config/{area}/{setting}"


def policy_doc_url(area: str, setting: str) -> str:
    """Deep-link to the Policy CSP doc for a setting, or '' for ADMX-backed
    areas (Group-Policy ingested — no reliable per-setting anchor)."""
    if area.upper().startswith("ADMX_"):
        return ""
    return f"{_POLICY_DOC_BASE}{area.lower()}#{setting.lower()}"


def _index_policy_providers(providers: dict) -> dict:
    """Index a PolicyManager-Providers.reg dump as
    {(provider_id, scope, area): {value_name: value}} for value lookups.
    provider_id is lowercased and brace-stripped to match the WinningProvider."""
    rx = re.compile(
        r"\\PolicyManager\\Providers\\([^\\]+)\\default\\([^\\]+)\\([^\\]+)$",
        re.IGNORECASE)
    out: dict = {}
    for key, vals in providers.items():
        m = rx.search(key)
        if m:
            pid = m.group(1).strip("{}").lower()
            out[(pid, m.group(2).lower(), m.group(3).lower())] = vals
    return out


def parse_policymanager_settings(reg: dict, providers: Optional[dict] = None,
                                 limit: int = 5000) -> List[dict]:
    """One row per applied PolicyManager setting, coupled to its CSP name.

    A setting is any `<Setting>_WinningProvider` value under
    `…\\PolicyManager\\current\\<scope>\\<area>`. The value comes from the bare
    `<Setting>` value when present; otherwise it is looked up in the providers
    hive (PolicyManager-Providers.reg) under the winning provider's subtree —
    where the actual value lives for most non-ADMX settings.
    """
    prov_idx = _index_policy_providers(providers) if providers else {}

    def provider_value(wp: str, scope: str, area: str, setting: str) -> str:
        scope_l, area_l = scope.lower(), area.lower()
        # Prefer the winning provider; fall back to any provider that has it.
        vals = prov_idx.get((wp, scope_l, area_l))
        if vals and setting in vals:
            return str(vals[setting])
        for (_pid, s, a), pv in prov_idx.items():
            if s == scope_l and a == area_l and setting in pv:
                return str(pv[setting])
        return ""

    rx = re.compile(r"\\PolicyManager\\current\\([^\\]+)\\([^\\]+)$", re.IGNORECASE)
    out: List[dict] = []
    for key, vals in reg.items():
        m = rx.search(key)
        if not m:
            continue
        scope, area = m.group(1), m.group(2)
        for name in vals:
            if not name.endswith("_WinningProvider"):
                continue
            setting = name[: -len("_WinningProvider")]
            admx = (area.upper().startswith("ADMX_")
                    or f"{setting}_ADMXInstanceData" in vals)
            value = vals.get(setting, "")
            if value == "" and prov_idx:
                wp = str(vals[name]).strip("{}").lower()
                value = provider_value(wp, scope, area, setting)
            out.append({
                "scope": scope, "area": area, "setting": setting,
                "value": "" if value == "" else str(value),
                "admx": admx,
                "oma_uri": policy_oma_uri(scope, area, setting),
                "doc_url": "" if admx else policy_doc_url(area, setting),
            })
            if len(out) >= limit:
                out.sort(key=lambda r: (r["area"].lower(), r["setting"].lower()))
                return out
    out.sort(key=lambda r: (r["area"].lower(), r["setting"].lower()))
    return out


def parse_winhttp_proxy(text: str) -> dict:
    """WinHTTP proxy config from `netsh winhttp show proxy`."""
    direct = bool(re.search(r"Direct access \(no proxy", text, re.IGNORECASE))
    m = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", text, re.IGNORECASE)
    return {"direct": direct, "server": (m.group(1).strip() if m else "")}


def parse_firewall_profiles(text: str) -> List[dict]:
    """State (ON/OFF) per firewall profile from `netsh advfirewall`."""
    out, cur = [], None
    for line in text.splitlines():
        h = re.match(r"^(Domain|Private|Public)\s+Profile", line, re.IGNORECASE)
        if h:
            cur = h.group(1).capitalize()
            continue
        s = re.match(r"^State\s+(ON|OFF)\b", line.strip(), re.IGNORECASE)
        if cur and s:
            out.append({"profile": cur, "on": s.group(1).upper() == "ON"})
            cur = None
    return out


def count_event_issues(text: str) -> dict:
    """Tally Error/Warning rows in a *-ErrorsWarnings.txt Format-List dump."""
    return {
        "errors": len(re.findall(r"LevelDisplayName\s*:\s*Error", text, re.I)),
        "warnings": len(re.findall(r"LevelDisplayName\s*:\s*Warning", text, re.I)),
    }


# --- Settings-Catalog name enrichment (optional, Microsoft Graph) ------------
# Maps a Policy CSP setting to its friendly Intune display name. The catalog is
# global Microsoft metadata (no tenant/log data), fetched once and cached. Every
# function is total: a network/credential failure logs and yields no names, so a
# diagnostics job never fails because of this enrichment.

_CSP_NAMES: Optional[dict] = None  # in-memory map cache (path/id -> displayName)
_GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH_SETTINGS_URL = (
    "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"
    "?$select=id,displayName,baseUri,offsetUri")


def _norm_csp_key(s: str) -> str:
    """Normalize a CSP path/OMA-URI to a stable lookup key (lowercase, no
    leading `./`, single slashes)."""
    s = (s or "").strip().lower().lstrip(".")
    s = re.sub(r"/+", "/", s).strip("/")
    return s


def _graph_token() -> Optional[str]:
    """Client-credentials access token for Graph, or None on any failure."""
    if not GRAPH_ENABLED:
        return None
    data = urllib.parse.urlencode({
        "client_id": GRAPH_CLIENT_ID,
        "client_secret": GRAPH_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    url = _GRAPH_TOKEN_URL.format(tenant=urllib.parse.quote(GRAPH_TENANT_ID))
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, data=data), timeout=30) as r:
            return json.loads(r.read()).get("access_token")
    except (urllib.error.URLError, ValueError, OSError) as e:
        log.warning("Graph token request failed: %s", e)
        return None


def _graph_fetch_settings(token: str) -> List[dict]:
    """Page through the configuration-settings catalog; [] on any failure."""
    items: List[dict] = []
    url: Optional[str] = _GRAPH_SETTINGS_URL
    headers = {"Authorization": f"Bearer {token}"}
    pages = 0
    while url and pages < 200:
        pages += 1
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, headers=headers), timeout=60) as r:
                payload = json.loads(r.read())
        except (urllib.error.URLError, ValueError, OSError) as e:
            log.warning("Graph settings fetch failed: %s", e)
            break
        items.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")
    return items


def build_csp_name_map(items: List[dict]) -> dict:
    """Pure transform: catalog items -> {csp-path-or-settingDefinitionId:
    displayName}. Keyed by both the normalized baseUri/offsetUri path and the
    settingDefinitionId so either lookup resolves."""
    out: dict = {}
    for it in items:
        name = (it.get("displayName") or "").strip()
        if not name:
            continue
        base, offset = it.get("baseUri") or "", it.get("offsetUri") or ""
        if base or offset:
            out[_norm_csp_key(f"{base}/{offset}")] = name
        sid = (it.get("id") or "").strip().lower()
        if sid:
            out[sid] = name
    return out


def load_csp_names() -> dict:
    """Return the name map: in-memory cache, else the on-disk cache, else {}."""
    global _CSP_NAMES
    if _CSP_NAMES is not None:
        return _CSP_NAMES
    try:
        if CSP_NAMES_CACHE.is_file():
            _CSP_NAMES = json.loads(CSP_NAMES_CACHE.read_text(encoding="utf-8")
                                    ).get("map", {})
            return _CSP_NAMES
    except (ValueError, OSError) as e:
        log.warning("Could not read CSP names cache: %s", e)
    _CSP_NAMES = {}
    return _CSP_NAMES


def refresh_csp_names(force: bool = False) -> dict:
    """Fetch + cache the catalog when creds are set and the cache is missing or
    older than the TTL. Total: never raises; returns the (possibly empty) map."""
    global _CSP_NAMES
    if not GRAPH_ENABLED:
        return load_csp_names()
    try:
        fresh = (CSP_NAMES_CACHE.is_file()
                 and (time.time() - CSP_NAMES_CACHE.stat().st_mtime)
                 < CSP_NAMES_TTL_HOURS * 3600)
    except OSError:
        fresh = False
    if fresh and not force:
        return load_csp_names()
    token = _graph_token()
    if not token:
        return load_csp_names()
    items = _graph_fetch_settings(token)
    if not items:
        return load_csp_names()
    mapping = build_csp_name_map(items)
    try:
        CSP_NAMES_CACHE.parent.mkdir(parents=True, exist_ok=True)
        CSP_NAMES_CACHE.write_text(
            json.dumps({"generated": time.time(), "map": mapping}),
            encoding="utf-8")
    except OSError as e:
        log.warning("Could not write CSP names cache: %s", e)
    _CSP_NAMES = mapping
    log.info("Loaded %d Intune setting display names from Graph", len(mapping))
    return mapping


def csp_display_name(area: str, setting: str, oma_uri: str) -> str:
    """Friendly Intune display name for a CSP setting, or '' when unknown."""
    names = load_csp_names()
    if not names:
        return ""
    hit = names.get(_norm_csp_key(oma_uri))
    if hit:
        return hit
    sid = f"device_vendor_msft_policy_config_{area}_{setting}".lower()
    return names.get(sid, "")


# The collector exists in an English and a Dutch variant; accept both names.
_DASH_SOURCES = {
    "summary": ("_SUMMARY.txt", "_SAMENVATTING.txt"),
    "dsregcmd": ("Identity/dsregcmd-status.txt",),
    "endpoints": ("Network/endpoint-connectivity.txt",),
    "ime_service": ("Apps-IME/service-status.txt",),
    "certs": ("Identity/certs-machine-overview.txt",
              "Identity/certs-machine-overzicht.txt"),
    "apps": ("Apps-IME/installed-apps.txt",),
    "win32apps": ("Registry/Win32Apps.reg",),
    "ime_reg": ("Registry/IntuneManagementExtension.reg",),
    "enrollments": ("Registry/Enrollments.reg",),
    "policymanager": ("Registry/PolicyManager-Current.reg",),
    "policymanager_providers": ("Registry/PolicyManager-Providers.reg",),
    "proxy": ("Network/winhttp-proxy.txt",),
    "firewall": ("Network/firewall-profiles.txt",),
}


def _find_package_file(input_dir: Path, candidates) -> Optional[Path]:
    """Locate a package file by relative path, falling back to a leaf-name
    search so a zip with an extra top-level folder still resolves."""
    for rel in candidates:
        p = input_dir / rel
        if p.is_file():
            return p
    leaves = {Path(c).name.lower() for c in candidates}
    for p in sorted(input_dir.rglob("*")):
        if p.is_file() and p.name.lower() in leaves:
            return p
    return None


def _yesno_check(label: str, value: str, detail: str = "") -> dict:
    v = value.strip().upper()
    status = "ok" if v == "YES" else "bad" if v == "NO" else "unknown"
    return {"label": label, "status": status, "detail": detail or (value or "not found")}


def build_dashboard(input_dir: Path) -> dict:
    """Derive the health-check model from a staged diagnostics package.

    Each check carries an optional source pointer (`src` = relative package
    path, `line` = row in the file viewer) so the dashboard card can deep-link
    to the evidence it was parsed from.
    """
    found: dict = {}  # key -> (Optional[Path], text)

    def read(key: str) -> str:
        if key not in found:
            p = _find_package_file(input_dir, _DASH_SOURCES[key])
            found[key] = (p, read_text_tolerant(p) if p else "")
        return found[key][1]

    def link(key: str, *patterns: str) -> dict:
        """Source pointer for a check. The file viewer numbers non-blank
        lines (it skips blanks), so locate the evidence row through the same
        parser the viewer uses; first pattern that matches a row wins."""
        path, text = found.get(key) or (None, "")
        if path is None:
            return {}
        src = {"src": path.relative_to(input_dir).as_posix()}
        records, _ = parse_cmtrace(text)
        for pat in patterns:
            rx = re.compile(pat, re.IGNORECASE)
            for i, rec in enumerate(records, 1):
                if rx.search(rec["msg"]):
                    return {**src, "line": i}
        return src

    identity = parse_dsregcmd(read("dsregcmd"))
    if not identity.get("AzureAdJoined"):
        identity = {**parse_summary_txt(read("summary")), **identity}

    def id_link(*patterns: str) -> dict:
        """Identity evidence lives in dsregcmd-status.txt or, for packages
        without it, in the collector summary; prefer the file that matches."""
        primary = link("dsregcmd", *patterns)
        if primary.get("line"):
            return primary
        read("summary")
        fallback = link("summary", *patterns)
        return fallback if fallback.get("line") else (primary or fallback)

    checks = [
        {**_yesno_check("Entra joined", identity.get("AzureAdJoined", "")),
         **id_link(r"AzureAdJoined")},
        {**_yesno_check("Entra PRT", identity.get("AzureAdPrt", "")),
         **id_link(r"AzureAdPrt")},
    ]

    mdm_url = identity.get("MdmUrl", identity.get("MDM URL", ""))
    checks.append({
        "label": "MDM enrollment",
        "status": "ok" if "manage.microsoft.com" in mdm_url
                  else "bad" if mdm_url else "unknown",
        "detail": mdm_url or "MDM URL not found",
        **id_link(r"MdmUrl|MDM URL"),
    })

    svc = parse_service_status(read("ime_service"))
    checks.append({
        "label": "IME service",
        "status": "ok" if svc else "unknown" if svc is None else "bad",
        "detail": "Running" if svc else "status unknown" if svc is None else "Stopped",
        **link("ime_service",
               r"intune.*\b(Running|Stopped)\b|\b(Running|Stopped)\b.*intune",
               r"\b(Running|Stopped)\b"),
    })

    endpoints = parse_endpoint_connectivity(read("endpoints"))
    if endpoints:
        down = [e["endpoint"] for e in endpoints if not e["reachable"]]
        checks.append({
            "label": "Intune/Entra endpoints",
            "status": "ok" if not down
                      else "warn" if len(down) < len(endpoints) else "bad",
            "detail": (f"{len(endpoints)} reachable" if not down
                       else "unreachable: " + ", ".join(down)),
            # Point at the first failing row when something is down.
            **link("endpoints",
                   *((rf"{re.escape(down[0])}\s.*\bFalse\b",) if down else ()),
                   r"\b(True|False)\b"),
        })
    else:
        checks.append({"label": "Intune/Entra endpoints", "status": "unknown",
                       "detail": "no connectivity test found"})

    certs = parse_cert_overview(read("certs"))
    if certs:
        expired = [c for c in certs if c["expired"]]
        checks.append({
            "label": "Machine certificates",
            "status": "warn" if expired else "ok",
            "detail": (f"{len(expired)} of {len(certs)} expired" if expired
                       else f"{len(certs)} certificates, none expired"),
            # Point at the first expired cert when there is one.
            **link("certs", r"(Expired|Verlopen)\s*:\s*True", r"Subject\s*:"),
        })
    else:
        checks.append({"label": "Machine certificates", "status": "unknown",
                       "detail": "no certificate overview found"})

    apps = parse_installed_apps(read("apps"))
    if apps:
        checks.append({
            "label": "Installed apps",
            "status": "ok",
            "detail": f"{len(apps)} apps — click for the inventory",
            # No line: the card opens the inventory file itself.
            **link("apps"),
        })
    else:
        checks.append({"label": "Installed apps", "status": "unknown",
                       "detail": "no app inventory found"})

    # --- Registry/network-derived checks + detail tables --------------------
    # Everything below parses files the collector already gathers but the
    # original dashboard ignored. Each parser is total; a missing source just
    # means the check is skipped (no card), never an error.
    sections: List[dict] = []

    def reg(key: str) -> dict:
        text = read(key)
        return parse_reg(text) if text else {}

    def src_of(key: str) -> Optional[str]:
        return (link(key) or {}).get("src")

    # Win32 apps (Sherlog's core domain): per-app state + deployment error code.
    w32 = parse_win32apps(reg("win32apps"))
    if w32:
        failed = [a for a in w32 if a["failed"]]
        checks.append({
            "label": "Win32 apps",
            "status": "bad" if failed else "ok",
            "detail": (f"{len(failed)} of {len(w32)} with errors" if failed
                       else f"{len(w32)} tracked, all healthy"),
            **link("win32apps"),
        })
        sections.append({
            "title": f"Win32 app deployment status ({len(w32)})",
            "src": src_of("win32apps"),
            "columns": ["App ID", "Compliance", "Enforcement", "Error"],
            "widths": [30, 16, 18, 36],
            "rows": [[a["app_id"], a["compliance"], a["enforcement"],
                      (f'{a["error_code"]} — {a["error_text"]}' if a["error_text"]
                       else a["error_code"])]
                     for a in w32[:200]],
        })
    else:
        checks.append({"label": "Win32 apps", "status": "unknown",
                       "detail": "no Win32Apps registry export found"})

    # MDM enrollment detail (UPN, provider) from the Enrollments hive.
    enrolls = parse_enrollments(reg("enrollments"))
    intune = next((e for e in enrolls if e["is_intune"]), None)
    if enrolls:
        checks.append({
            "label": "Enrollment",
            "status": "ok" if intune else "warn",
            "detail": (f'{intune["upn"] or "device"} · state {intune["state"]}'
                       if intune else f"{len(enrolls)} enrollment(s), none Intune"),
            **link("enrollments"),
        })

    # PolicyManager / RSOP: how many settings landed and from how many
    # providers (the winning-provider model, like GPResult).
    pm = parse_policymanager(reg("policymanager"))
    if pm["setting_count"]:
        checks.append({
            "label": "Policies (RSOP)",
            "status": "ok",
            "detail": (f'{pm["setting_count"]} settings, {pm["area_count"]} '
                       f'areas, {pm["provider_count"]} provider(s)'),
            **link("policymanager"),
        })
        # Per-setting table: couple each applied setting to its CSP/OMA-URI
        # name with a deep-link to the Microsoft Learn Policy CSP doc.
        pm_settings = parse_policymanager_settings(
            reg("policymanager"), reg("policymanager_providers"))
        rows = []
        for s in pm_settings[:2000]:
            oma = ({"text": s["oma_uri"], "href": s["doc_url"]} if s["doc_url"]
                   else s["oma_uri"] + ("  (ADMX)" if s["admx"] else ""))
            # Friendly Intune display name from the Graph catalog (empty when
            # enrichment is off or the setting is ADMX/unmatched).
            intune = csp_display_name(s["area"], s["setting"], s["oma_uri"])
            rows.append([s["area"], s["setting"], intune, s["value"], oma])
        sections.append({
            "title": f'Policy settings ({len(pm_settings)})',
            "src": src_of("policymanager"),
            "columns": ["Area", "Setting", "Intune name", "Value", "OMA-URI"],
            "widths": [13, 20, 23, 12, 32],
            "rows": rows,
        })

    # Proactive Remediations / platform scripts (SideCarPolicies executions).
    scripts = parse_sidecar_scripts(reg("ime_reg"))
    if scripts:
        last = max((s["last_execution"] for s in scripts if s["last_execution"]),
                   default="")
        npol = len({s["policy"] for s in scripts})
        checks.append({
            "label": "Scripts / remediations",
            "status": "ok",
            "detail": f"{npol} policies executed" + (f", last {last}" if last else ""),
            **link("ime_reg"),
        })

    # MDM / Entra event-log health: aggregate the Error/Warning rows the
    # collector already distilled into *-ErrorsWarnings.txt files.
    ev_files = sorted(input_dir.rglob("*-ErrorsWarnings.txt"))
    if ev_files:
        tot_e = tot_w = 0
        for p in ev_files:
            c = count_event_issues(read_text_tolerant(p))
            tot_e += c["errors"]
            tot_w += c["warnings"]
        dm = next((p for p in ev_files if "DeviceManagement-Admin" in p.name),
                  ev_files[0])
        checks.append({
            "label": "MDM event log",
            "status": "bad" if tot_e else "warn" if tot_w else "ok",
            "detail": f"{tot_e} errors, {tot_w} warnings across {len(ev_files)} logs",
            "src": dm.relative_to(input_dir).as_posix(),
        })

    # Network: WinHTTP proxy + firewall profile states.
    if read("proxy"):
        proxy = parse_winhttp_proxy(read("proxy"))
        checks.append({
            "label": "WinHTTP proxy",
            "status": "ok",
            "detail": ("direct (no proxy)" if proxy["direct"]
                       else proxy["server"] or "configured"),
            **link("proxy"),
        })
    fw = parse_firewall_profiles(read("firewall")) if read("firewall") else []
    if fw:
        off = [f["profile"] for f in fw if not f["on"]]
        checks.append({
            "label": "Firewall",
            "status": "warn" if off else "ok",
            "detail": ("off: " + ", ".join(off) if off else "all profiles on"),
            **link("firewall"),
        })

    device = {
        "name": identity.get("Device", ""),
        "device_id": identity.get("DeviceId", ""),
        "tenant": identity.get("TenantName", ""),
        "collected": identity.get("Date", identity.get("Datum", "")),
    }
    return {"device": device, "checks": checks, "sections": sections}


def read_dashboard(job_id: str) -> Optional[dict]:
    p = job_dir(job_id) / "output" / "dashboard.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


# --- Analysis subprocess -----------------------------------------------------

def _write_summary(report: Path, dest: Path) -> None:
    """Derive summary.json from a finished report. Failures only log a warning;
    the job outcome must never depend on the summary."""
    try:
        html = report.read_text(encoding="utf-8", errors="replace")
        dest.write_text(json.dumps(summarize(parse_report_summary(html))),
                        encoding="utf-8")
    except Exception:
        log.warning("could not write summary for %s", report.name, exc_info=True)


def read_summary(job_id: str) -> Optional[dict]:
    p = job_dir(job_id) / "output" / "summary.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _diag_state_writer(job_id: str):
    """State writer for the analysis sub-task of a diagnostics job: updates
    only the `analysis` dict in job.json, never the top-level job state."""
    def set_state(**fields) -> None:
        update_status(job_id, analysis=fields)
    return set_state


async def run_job(job_id: str, input_dir: Path, output_dir: Path,
                  set_state=None) -> None:
    """Run the headless analysis script and record the outcome.

    `set_state(**fields)` records state transitions; the default writes the
    top-level job.json record (timeline jobs). Diagnostics jobs pass
    `_diag_state_writer(job_id)` so the analysis is a sub-state.
    """
    if set_state is None:
        def set_state(**fields) -> None:
            # Merge, don't replace: the upload route stores metadata (the
            # original upload names) in job.json that must survive state
            # transitions.
            update_status(job_id, **fields)
    set_state(state="queued")
    async with _job_sem:  # wait here if we are at the concurrency cap
        await _run_job_locked(job_id, input_dir, output_dir, set_state)


async def _run_job_locked(job_id: str, input_dir: Path, output_dir: Path,
                          set_state) -> None:
    set_state(state="running")
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
            set_state(
                state="failed", exitcode=None,
                stdout="", stderr=f"Analysis timed out after {SCRIPT_TIMEOUT_SECONDS}s.",
            )
            log.warning("job %s timed out", job_id)
            return

        stdout = out_b.decode("utf-8", "replace")
        stderr = err_b.decode("utf-8", "replace")
        rc = proc.returncode
        report = find_report(output_dir)
        if rc == 0 and report is not None:
            _write_summary(report, output_dir / "summary.json")
            set_state(state="done", exitcode=0,
                      report=report.name, stdout=stdout, stderr=stderr)
            log.info("job %s done -> %s", job_id, report.name)
        else:
            set_state(state="failed", exitcode=rc,
                      stdout=stdout, stderr=stderr)
            log.warning("job %s failed (exit %s)", job_id, rc)
    except Exception as e:  # pragma: no cover - defensive
        set_state(state="failed", exitcode=None, stdout="", stderr=repr(e))
        log.exception("job %s crashed", job_id)


# --- Upload handling ---------------------------------------------------------

class UploadError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


async def save_uploads(files: List[UploadFile], input_dir: Path) -> int:
    """Validate + store uploads into input_dir. Returns count of .log files staged.

    Files with a non-.log/.zip extension are skipped silently — this lets users
    pick a whole folder (webkitdirectory), which also yields unrelated files;
    only logs are kept. If nothing usable is staged the caller reports it.

    Raises UploadError on size overrun or unsafe zip.
    """
    total = 0
    log_count = 0
    tmp_dir = input_dir.parent / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    for up in files:
        name = up.filename or ""
        ext = Path(name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue  # skip non-log files (e.g. extras from a folder selection)

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


async def save_diag_upload(files: List[UploadFile], input_dir: Path) -> tuple[int, list]:
    """Validate + extract a diagnostics-package upload (exactly one .zip).

    Returns (extracted_count, skipped). Raises UploadError on a wrong file
    set, size overrun or unsafe zip.
    """
    zips = [up for up in files
            if Path(up.filename or "").suffix.lower() == ".zip"]
    if len(files) != 1 or len(zips) != 1:
        raise UploadError(400, "Upload exactly one diagnostics .zip file.")

    up = zips[0]
    tmp_dir = input_dir.parent / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    dest = tmp_dir / f"{uuid.uuid4().hex}.zip"
    total = 0
    with dest.open("wb") as fh:
        while True:
            chunk = await up.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise UploadError(413, f"Upload exceeds {MAX_UPLOAD_MB} MB limit.")
            fh.write(chunk)

    return await _extract_diag_zip(dest, input_dir)


async def _extract_diag_zip(dest_zip: Path, input_dir: Path) -> tuple[int, list]:
    """Extract a staged diagnostics .zip into input_dir, expanding .cab members
    when cabextract is available. Shared by the form upload and the drop-off API.
    Raises UploadError on a bad/empty archive."""
    # Keep .cab members only when cabextract can expand them afterwards;
    # otherwise they are skipped (and listed disabled) as before.
    keep_exts = DIAG_KEEP_EXTS | ({".cab"} if CABEXTRACT else set())
    budget = [0]
    try:
        count, skipped = extract_zip_members(dest_zip, input_dir, keep_exts,
                                             budget=budget)
    except zipfile.BadZipFile:
        raise UploadError(400, "The uploaded file is not a valid zip archive.")
    if CABEXTRACT:
        cab_kept, cab_count, cab_skipped = await asyncio.to_thread(
            expand_cab_files, input_dir, DIAG_KEEP_EXTS, budget)
        count += cab_kept - cab_count  # cabs are replaced by their contents
        skipped.extend(cab_skipped)
    if count == 0:
        raise UploadError(400, "No viewable files found in the diagnostics zip.")
    return count, skipped


def extract_zip_members(zip_path: Path, dest_dir: Path, keep_exts: set,
                        depth: int = 0,
                        budget: Optional[list] = None) -> tuple[int, list]:
    """Safely extract members with a kept extension from a zip.

    Zip-slip protected; `budget` is a single-element mutable byte counter
    shared across the outer zip and any nested zips so nesting cannot reset
    the zip-bomb cap. Nested .zip members are extracted one level deep into
    `<dest>/<zipname-stem>/`; deeper nesting is skipped. Returns
    (kept_count, skipped) where skipped lists {"name", "size"} of members
    that were not extracted.
    """
    if budget is None:
        budget = [0]
    base = dest_dir.resolve()
    count = 0
    skipped: list = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Windows PowerShell 5.1 Compress-Archive writes backslash
            # separators in entry names (against the zip spec); without
            # normalisation the package extracts as flat files with literal
            # backslashes and every path-based lookup misses.
            member = info.filename.replace("\\", "/")
            ext = Path(member).suffix.lower()
            nested_zip = ext == ".zip" and depth == 0
            if ext not in keep_exts and not nested_zip:
                skipped.append({"name": member, "size": info.file_size})
                continue
            # Resolve target and ensure it stays inside dest_dir (zip-slip guard).
            target = (dest_dir / member).resolve()
            if base != target and base not in target.parents:
                raise UploadError(400, f"Unsafe path in zip: {member!r}.")
            budget[0] += info.file_size
            if budget[0] > MAX_UNCOMPRESSED_BYTES:
                raise UploadError(413, "Zip contents too large (possible zip bomb).")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, CHUNK)
            if nested_zip:
                nested_dest = target.parent / Path(member).stem
                try:
                    sub_count, sub_skipped = extract_zip_members(
                        target, nested_dest, keep_exts, depth + 1, budget)
                except zipfile.BadZipFile:
                    sub_count, sub_skipped = 0, [{"name": member,
                                                  "size": info.file_size}]
                finally:
                    target.unlink(missing_ok=True)
                count += sub_count
                prefix = f"{member}!/"
                skipped.extend({"name": prefix + s["name"], "size": s["size"]}
                               for s in sub_skipped)
            else:
                count += 1
    return count, skipped


def _cab_member_sizes(cab: Path) -> Optional[List[int]]:
    """Member sizes from `cabextract -l`, or None when the cab is unreadable.

    Listing first lets the zip-bomb budget be checked *before* anything is
    written to disk. Output rows look like:
    `      1234 | 27.05.2026 14:36:11 | EventLogs/System.evtx`
    """
    try:
        proc = subprocess.run([CABEXTRACT, "-l", str(cab)],
                              capture_output=True, text=True,
                              timeout=CAB_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    sizes: List[int] = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 3 and parts[0].strip().isdigit():
            sizes.append(int(parts[0].strip()))
    return sizes


def expand_cab_files(root: Path, keep_exts: set,
                     budget: list) -> tuple[int, int, list]:
    """Expand every .cab under `root` in place (one pass, no recursion).

    Each `<dir>/<name>.cab` becomes `<dir>/<name>/` holding only members
    with a kept extension; the .cab itself is always removed afterwards.
    `budget` is the shared zip-bomb byte counter from the zip extraction.
    A cab that cannot be expanded (corrupt, over budget, cabextract error
    or timeout) is reported as skipped — never an upload failure, so one
    bad cab cannot sink the diagnostics job. Returns
    (kept_count, cab_count, skipped).
    """
    base = root.resolve()
    kept = 0
    cabs = 0
    skipped: list = []
    for cab in sorted(root.rglob("*.cab")):
        cabs += 1
        rel = cab.relative_to(root).as_posix()
        cab_entry = {"name": rel, "size": cab.stat().st_size}
        dest = cab.parent / cab.stem
        sizes = _cab_member_sizes(cab)
        if sizes is None or budget[0] + sum(sizes) > MAX_UNCOMPRESSED_BYTES:
            skipped.append(cab_entry)
            cab.unlink(missing_ok=True)
            continue
        budget[0] += sum(sizes)
        try:
            proc = subprocess.run(
                [CABEXTRACT, "-q", "-d", str(dest), str(cab)],
                capture_output=True, timeout=CAB_TIMEOUT_SECONDS)
            ok = proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        cab.unlink(missing_ok=True)
        if not ok:
            shutil.rmtree(dest, ignore_errors=True)
            skipped.append(cab_entry)
            continue
        for f in sorted(dest.rglob("*")):
            if not f.is_file():
                continue
            # Defence in depth on top of cabextract's own name sanitising:
            # anything resolving outside the input dir is dropped.
            resolved = f.resolve()
            if base != resolved and base not in resolved.parents:
                f.unlink(missing_ok=True)
                continue
            if f.suffix.lower() not in keep_exts:
                skipped.append({"name": f"{rel}!/{f.relative_to(dest).as_posix()}",
                                "size": f.stat().st_size})
                f.unlink(missing_ok=True)
            else:
                kept += 1
    return kept, cabs, skipped


def extract_zip_logs(zip_path: Path, input_dir: Path) -> int:
    """Safely extract only .log members from a zip (zip-slip protected)."""
    count, _skipped = extract_zip_members(zip_path, input_dir,
                                          keep_exts={".log"}, depth=1)
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
            "style-src 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'self'",
        )
        return resp


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # /health and the token-authenticated drop-off API carry their own
        # auth (or none), so they bypass basic auth — a device collector can't
        # do the interactive basic-auth challenge.
        if (request.url.path in ("/health", "/api/diagnostics")
                or not AUTH_ENABLED):
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
            headers={"WWW-Authenticate": 'Basic realm="Sherlog"'},
        )


# --- Background cleanup ------------------------------------------------------

def fail_interrupted_jobs() -> int:
    """Mark jobs left queued/running by a previous process as failed.

    Analysis tasks live in this process only; after a restart (deploy,
    crash) any job still queued/running can never finish, and its result
    page would poll forever.
    """
    msg = ("The analysis was interrupted by an app restart. "
           "Please upload again.")
    failed = 0
    for child in iter_job_dirs():
        status = read_status(child.name)
        if not status:
            continue
        if status.get("kind") == "diag":
            analysis = status.get("analysis") or {}
            if analysis.get("state") in ("queued", "running"):
                update_status(child.name, analysis={
                    "state": "failed", "exitcode": None,
                    "stdout": "", "stderr": msg,
                })
                failed += 1
        elif status.get("state") in ("queued", "running"):
            update_status(child.name, state="failed", exitcode=None,
                          stdout="", stderr=msg)
            failed += 1
    if failed:
        log.warning("marked %d interrupted job(s) as failed", failed)
    return failed


def cleanup_old_jobs() -> int:
    # All jobs (incl. device drop-off) share one retention: JOB_RETENTION_HOURS.
    cutoff = time.time() - JOB_RETENTION_HOURS * 3600
    removed = 0
    for child in iter_job_dirs():
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


# asyncio only holds weak references to tasks; without a strong reference a
# job task can be garbage-collected mid-run, leaving job.json on "running"
# forever. Keep tasks alive until they finish.
_bg_tasks: set = set()


def spawn_job(coro) -> None:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


# --- App lifespan ------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    fail_interrupted_jobs()
    if not AUTH_ENABLED:
        log.warning("AUTH DISABLED: APP_USER/APP_PASSWORD not both set. App is OPEN.")
    else:
        log.info("Basic auth enabled for user %r", APP_USER)
    task = asyncio.create_task(cleanup_loop())
    # Warm the Intune setting-name cache in the background (only when Graph
    # creds are set); never blocks startup or fails it.
    if GRAPH_ENABLED:
        asyncio.create_task(asyncio.to_thread(refresh_csp_names))
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Sherlog", lifespan=lifespan)
# Order matters: last added runs outermost. Auth must gate before anything,
# and security headers should be applied to every response (incl. 401s).
app.add_middleware(BasicAuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Screenshots shown on the landing page. Guarded so a build without the
# assets still boots; the homepage then just shows broken images.
STATIC_DIR = APP_DIR / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --- HTML pages --------------------------------------------------------------

PAGE_CSS = """
  :root{ --bg:#ffffff; --fg:#1f2937; --muted:#6b7280; --accent:#2563eb;
    --border:#e5e7eb; --surface:#f9fafb; --radius:8px; }
  /* Dark theme: the head script toggles .dark on <html> (localStorage
     "sherlog.theme", falling back to prefers-color-scheme). */
  html.dark{ --bg:#0f172a; --fg:#e2e8f0; --muted:#94a3b8; --accent:#3b82f6;
    --border:#293548; --surface:#16202f; }
  html.dark .btn:hover{ background:#2563eb; }
  html.dark .recent .state.done{ background:rgba(16,185,129,.12);
    border-color:#065f46; color:#34d399; }
  html.dark .recent .state.failed{ background:rgba(239,68,68,.12);
    border-color:#7f1d1d; color:#f87171; }
  /* Status text colours on the result pages need lighter shades on dark. */
  html.dark .sum-chip .ok, html.dark details.summary .st-ok{ color:#4ade80; }
  html.dark .sum-chip .bad, html.dark details.summary .st-bad{ color:#f87171; }
  html.dark .sum-chip .warn, html.dark details.summary .st-warn{ color:#fbbf24; }
  html.dark details.summary .st-nd{ color:#94a3b8; }
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
  /* External cross-promo link: visually separated from the tool tabs. */
  .navlink.ext{ border-left:1px solid var(--border); padding-left:1.4rem; }
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
  .hero .cta{ margin:1.5rem 0 0; }
  .hero .trust{ font-size:.88rem; margin-top:.9rem; }
  .cards{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:1.25rem; }
  @media (max-width:640px){ .cards{ grid-template-columns:1fr; } }
  .cards .card{ display:flex; flex-direction:column; }
  .card h2{ margin:0 0 .4rem; font-size:1.25rem; }
  .card .desc{ color:var(--muted); margin:0 0 1.25rem; flex:1; overflow-wrap:anywhere; }
  /* Screenshot bleeds to the card edges (cancels the 1.75rem card padding). */
  .card .shot{ display:block; margin:-1.75rem -1.75rem 1.1rem;
    border-bottom:1px solid var(--border); border-radius:12px 12px 0 0;
    overflow:hidden; background:var(--surface); }
  .card .shot img{ display:block; width:100%; height:auto; aspect-ratio:8/5;
    object-fit:cover; object-position:top left; }
  .card .when{ color:var(--fg); font-size:.9rem; font-style:italic; margin:0 0 .5rem; }
  /* --- Home (split hero + icon tiles) --- */
  .home-hero{ display:grid; grid-template-columns:1.05fr .95fr; gap:2.5rem;
    align-items:center; padding:3rem 0 2.25rem; }
  @media (max-width:820px){ .home-hero{ grid-template-columns:1fr; gap:1.5rem;
    padding:1.75rem 0 1rem; } }
  .home-copy h1{ font-size:2.3rem; line-height:1.13; letter-spacing:-.02em;
    margin:0 0 .9rem; }
  .home-copy .lead{ font-size:1.1rem; color:var(--muted); margin:0; max-width:34rem; }
  .badges{ display:flex; flex-wrap:wrap; gap:.5rem; margin:1.2rem 0 0; }
  .badges span{ font-size:.78rem; font-weight:600; color:var(--muted);
    border:1px solid var(--border); border-radius:999px; padding:.2rem .65rem; }
  .home-upload .drop{ padding:2.25rem 1.25rem; line-height:1.6; }
  .home-upload .row{ margin-top:1rem; }
  .home-upload .or{ text-align:center; color:var(--muted); font-size:.9rem;
    margin:.8rem 0 0; }
  .inline{ display:inline; }
  .linkbtn{ background:none; border:0; color:var(--accent); cursor:pointer;
    font:inherit; padding:0; }
  .linkbtn:hover{ text-decoration:underline; }
  .eyebrow{ font-size:.8rem; font-weight:700; letter-spacing:.08em;
    text-transform:uppercase; color:var(--muted); margin:0 0 .9rem; }
  .tools{ margin-top:2.5rem; }
  .tiles{ display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
    gap:1rem; }
  .tile{ display:flex; gap:.85rem; align-items:flex-start; padding:1.1rem;
    border:1px solid var(--border); border-radius:12px; background:var(--bg);
    color:var(--fg); transition:border-color .12s, transform .12s; }
  .tile:hover{ border-color:var(--accent); transform:translateY(-2px); }
  .tile .ic{ flex:none; width:2.3rem; height:2.3rem; border-radius:9px;
    display:flex; align-items:center; justify-content:center;
    background:var(--surface); color:var(--accent); }
  .tile .ic svg{ width:1.3rem; height:1.3rem; }
  .tile h3{ margin:.1rem 0 .25rem; font-size:1.02rem; }
  .tile p{ margin:0; color:var(--muted); font-size:.88rem; line-height:1.45; }
  .stepper{ list-style:none; margin:0; padding:0; display:grid;
    grid-template-columns:repeat(3,1fr); gap:1.1rem; }
  @media (max-width:760px){ .stepper{ grid-template-columns:1fr; } }
  .stepper li{ display:flex; gap:.7rem; color:var(--muted); min-width:0; }
  .stepper li div{ min-width:0; overflow-wrap:anywhere; line-height:1.5; }
  .stepper code{ overflow-wrap:anywhere; }
  .stepper .n{ flex:none; width:1.6rem; height:1.6rem; border-radius:50%;
    background:var(--accent); color:#fff; font-weight:700; font-size:.85rem;
    display:flex; align-items:center; justify-content:center; }
  .stepper strong{ color:var(--fg); }
  .explain{ margin-top:2.75rem; }
  .explain h2{ font-size:1.25rem; margin:0 0 .7rem; }
  .steps{ margin:0; padding-left:1.4rem; }
  .steps li{ color:var(--muted); margin-bottom:.65rem; }
  .steps li strong{ color:var(--fg); }
  ul.pick{ list-style:none; margin:0; padding:0; }
  ul.pick li{ color:var(--muted); padding:.45rem 0;
    border-bottom:1px solid var(--border); }
  ul.pick li:last-child{ border-bottom:0; }
  .cards .card .btn{ align-self:stretch; text-align:center; padding-left:.5rem;
    padding-right:.5rem; }
  .recent{ margin-top:1.25rem; }
  .recent h2{ margin:0 0 .5rem; font-size:1.1rem; }
  .recent ul{ list-style:none; margin:0; padding:0; }
  .recent li{ display:flex; align-items:center; gap:.7rem; padding:.5rem .2rem;
    border-bottom:1px solid var(--border); font-size:.92rem; }
  .recent li:last-child{ border-bottom:0; }
  .recent .files{ flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis;
    white-space:nowrap; }
  .recent .when{ color:var(--muted); white-space:nowrap; font-size:.85rem; }
  .recent .state{ font-size:.72rem; font-weight:600; padding:.18rem .55rem;
    border-radius:999px; border:1px solid var(--border); background:var(--surface);
    color:var(--muted); white-space:nowrap; }
  .recent .state.done{ background:#ecfdf5; border-color:#a7f3d0; color:#047857; }
  .recent .state.failed{ background:#fef2f2; border-color:#fecaca; color:#b91c1c; }
  .recent .rm{ border:0; background:none; color:var(--muted); cursor:pointer;
    font-size:1rem; padding:.1rem .3rem; }
  .recent .rm:hover{ color:var(--fg); }
  /* About-me dialog (nav "About"), same content as on payloadkit.app. */
  dialog.about{ position:relative; border:1px solid var(--border); border-radius:12px;
    padding:2rem; max-width:26rem; width:calc(100vw - 2.5rem);
    box-shadow:0 10px 40px rgba(0,0,0,.15); color:var(--fg); background:var(--bg); }
  dialog.about::backdrop{ background:rgba(15,23,42,.45); }
  .about .close{ position:absolute; top:.55rem; right:.8rem; border:0; background:none;
    font-size:1.35rem; line-height:1; color:var(--muted); cursor:pointer; }
  .about .close:hover{ color:var(--fg); }
  .about .head{ text-align:center; margin-bottom:1.1rem; }
  .about .head img{ width:6.5rem; height:6.5rem; border-radius:50%; object-fit:cover;
    display:block; margin:0 auto .8rem; border:1px solid var(--border); }
  .about h2{ margin:0; font-size:1.2rem; }
  .about .role{ color:var(--muted); font-size:.9rem; margin:.2rem 0 0; }
  .about p{ font-size:.92rem; margin:.8rem 0; }
  .about .links{ display:flex; justify-content:center; gap:.7rem; margin-top:1.25rem; }
  /* Dark-mode toggle in the nav: moon in light theme, sun in dark theme. */
  button.navlink.theme{ border:0; background:none; cursor:pointer; padding:0;
    font:inherit; }
  .theme svg{ vertical-align:-2px; }
  .theme:hover{ color:var(--fg); }
  .theme .sun{ display:none; }
  html.dark .theme .sun{ display:inline; }
  html.dark .theme .moon{ display:none; }
"""

_LOGO = ('<span class="dot"><svg width="15" height="15" viewBox="0 0 24 24" '
         'fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round">'
         '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>'
         '</svg></span>')

NAV = ("""<header><nav class="nav">
  <a class="brand" href="/">%(logo)s Sherlog</a>
  <span>
    <a class="navlink" href="/timeline">Timeline</a>
    <a class="navlink" href="/cmtrace">CMTrace</a>
    <a class="navlink" href="/diagnostics">Diagnostics</a>
    <a class="navlink" href="/errorcodes">Error codes</a>
    %(inbox_nav)s
    <a class="navlink ext" href="https://payloadkit.app" target="_blank"
       rel="noopener" title="PayloadKit &mdash; browse &amp; build Apple
       Configuration Profiles for macOS, iOS and tvOS, by the maker of
       Sherlog">PayloadKit&nbsp;&#8599;</a>
    <a class="navlink" href="#about"
       onclick="document.getElementById('about').showModal();return false">About</a>
    <button class="navlink theme" type="button" aria-label="Toggle dark mode"
            onclick="sherlogTheme()"><svg class="moon" width="14" height="14"
        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"><path
        d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg><svg
        class="sun" width="14" height="14" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="2" stroke-linecap="round"
        stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path
        d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20
        12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg></button>
  </span>
</nav>
<dialog id="about" class="about" aria-label="About the maintainer of Sherlog">
  <button class="close" aria-label="Close"
          onclick="this.closest('dialog').close()">&times;</button>
  <div class="head">
    <img src="/static/kris.jpeg" alt="Kris Mandemaker">
    <h2>Kris Mandemaker</h2>
    <p class="role">Senior Workspace Consultant @ Mand-IT</p>
  </div>
  <p>I'm a freelance Senior Workspace Consultant operating as Mand-IT,
     based in Alkmaar, Netherlands.</p>
  <p>My day job centres on the Microsoft ecosystem &mdash; Intune, Entra ID,
     Azure Virtual Desktop, and modern workplace design.</p>
  <p>Sherlog is a side project &mdash; I spend a lot of time digging through
     Intune Management Extension logs and wanted the timeline analysis and a
     CMTrace-style viewer one drag-and-drop away, right in the browser.</p>
  <div class="links">
    <a class="btn" href="https://www.linkedin.com/in/kris-mandemaker/"
       target="_blank" rel="noopener">LinkedIn</a>
    <a class="btn btn-ghost" href="https://mand-it.nl"
       target="_blank" rel="noopener">Mand-IT</a>
  </div>
</dialog>
<script>
(function () {
  // Close the about dialog on a backdrop click (native <dialog> only closes
  // on Esc by itself).
  var d = document.getElementById('about');
  d.addEventListener('click', function (e) { if (e.target === d) d.close(); });
})();
</script>
</header>""" % {"logo": _LOGO, "inbox_nav": (
    '<a class="navlink" href="/inbox">Inbox</a>' if ENABLE_UPLOAD_API else "")})

FOOTER = ("""<footer>
  <span>Sherlog &middot; sherlog.nl
  </span>
</footer>""")

# Browser-side job history. The list lives only in the visitor's own
# localStorage (key sherlog.history) — the server keeps no per-user state and
# sets no cookies. Result pages upsert an entry (history_record_js); this
# section renders the list and silently prunes jobs the server has deleted.
HISTORY_SECTION = """<section class="card recent" id="recent" hidden>
  <h2>Recent uploads</h2>
  <ul id="recent-list"></ul>
</section>
<script>
(function () {
  const KEY = 'sherlog.history';
  let hist;
  try { hist = JSON.parse(localStorage.getItem(KEY)) || []; } catch (e) { hist = []; }
  if (!Array.isArray(hist) || hist.length === 0) return;
  const section = document.getElementById('recent');
  const list = document.getElementById('recent-list');
  const save = () => localStorage.setItem(KEY, JSON.stringify(hist));
  function ago(ts) {
    const m = Math.max(1, Math.round((Date.now() - ts) / 60000));
    if (m < 60) return m + ' min ago';
    const h = Math.round(m / 60);
    if (h < 48) return h + ' h ago';
    return Math.round(h / 24) + ' d ago';
  }
  function drop(id, li) {
    hist = hist.filter(e => e.id !== id);
    save();
    li.remove();
    if (!list.children.length) section.hidden = true;
  }
  for (const e of hist) {
    const li = document.createElement('li');
    const badge = document.createElement('span');
    badge.className = 'state' + (e.state === 'done' ? ' done'
                               : e.state === 'failed' ? ' failed' : '');
    badge.textContent = (e.tool === 'logs' ? 'CMTrace'
                       : e.tool === 'diag' ? 'Diagnostics' : 'Timeline') +
                        (e.state === 'busy' ? ' \\u2026'
                       : e.state === 'failed' ? ' failed' : '');
    const a = document.createElement('a');
    a.className = 'files';
    a.href = e.tool === 'logs' ? '/result/' + e.id + '/cmtrace'
                               : '/result/' + e.id;
    // File names come from uploads (untrusted) — textContent only, never HTML.
    a.textContent = (e.files && e.files.length)
      ? e.files.join(', ') : 'job ' + String(e.id).slice(0, 8);
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = ago(e.ts || Date.now());
    const rm = document.createElement('button');
    rm.className = 'rm';
    rm.textContent = '\\u00d7';
    rm.title = 'Remove from history';
    rm.addEventListener('click', () => drop(e.id, li));
    li.append(badge, a, when, rm);
    list.appendChild(li);
    section.hidden = false;
    // Prune entries whose job the server already cleaned up (retention).
    fetch('/result/' + encodeURIComponent(e.id), { method: 'HEAD' })
      .then(r => { if (r.status === 404) drop(e.id, li); })
      .catch(() => {});
  }
})();
</script>"""


def upload_names(status: Optional[dict], job_id: str) -> List[str]:
    """Original upload file names for the browser-side history list.

    Jobs created before this field existed fall back to the staged log paths.
    """
    names = (status or {}).get("uploads")
    if isinstance(names, list) and names:
        return [str(n) for n in names]
    return list_input_logs(job_id)


def history_record_js(job_id: str, tool: str, state: str, files: List[str]) -> str:
    """Inline script that upserts this job into the browser's own history
    (localStorage); the server keeps no per-user state. Keeps the original
    timestamp on update so a busy->done transition doesn't bump the order."""
    entry = json.dumps({"id": job_id, "tool": tool, "state": state,
                        "files": files[:5]})
    return ("""<script>
(function () {
  const KEY = 'sherlog.history';
  const e = """ + entry + """;
  let h;
  try { h = JSON.parse(localStorage.getItem(KEY)) || []; } catch (_) { h = []; }
  if (!Array.isArray(h)) h = [];
  const old = h.find(x => x && x.id === e.id);
  e.ts = (old && old.ts) ? old.ts : Date.now();
  h = h.filter(x => x && x.id !== e.id);
  h.unshift(e);
  localStorage.setItem(KEY, JSON.stringify(h.slice(0, 20)));
})();
</script>""")

LANDING_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; IME log analyzer</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <main class="wrap">
    <section class="home-hero">
      <div class="home-copy">
        <h1>Troubleshoot Intune-managed Windows devices</h1>
        <p class="lead">Upload IME logs or a full diagnostics package and see
          what actually happened &mdash; app installs, scripts, errors, device
          health and applied policies. Runs in your browser; nothing touches
          the device or Intune.</p>
        <p class="badges"><span>No account</span><span>Browser-only</span>
          <span>Deleted after %(retention)dh</span></p>
      </div>
      <div class="home-upload">
        <form id="form" action="/analyze" method="post" enctype="multipart/form-data">
          <div class="drop" id="drop">
            <strong>Drag &amp; drop</strong> a <code>.zip</code>,
            <code>.log</code> files <em>or a whole folder</em>, or
            <a href="#" id="pickfiles">choose files</a> &middot;
            <a href="#" id="pickdir">choose a folder</a>.
          </div>
          <input id="input" name="files" type="file" multiple
                 accept="%(accept)s" style="display:none">
          <input id="dirinput" type="file" multiple webkitdirectory style="display:none">
          <ul id="files"></ul>
          <div class="row">
            <p class="limits"><span class="badge">.log</span><span class="badge">.zip</span>
              Max <strong>%(max)d&nbsp;MB</strong></p>
            <button class="btn go" type="submit" disabled>Analyze</button>
          </div>
        </form>
        <div class="or">or
          <form class="inline" method="post" action="/demo">
            <button class="linkbtn" type="submit">try with sample logs</button>
          </form>
        </div>
      </div>
    </section>

    <section class="tools">
      <h2 class="eyebrow">Tools</h2>
      <div class="tiles">
        <a class="tile" href="/timeline">
          <span class="ic">%(ic_timeline)s</span>
          <span class="tx"><h3>Timeline Analyzer</h3>
            <p>IME <code>.log</code> &rarr; interactive timeline of app installs,
              scripts and errors with a failure summary.</p></span>
        </a>
        <a class="tile" href="/cmtrace">
          <span class="ic">%(ic_cmtrace)s</span>
          <span class="tx"><h3>CMTrace Viewer</h3>
            <p>Read raw logs in a colored, filterable CMTrace table &mdash;
              warnings yellow, errors red. No analysis.</p></span>
        </a>
        <a class="tile" href="/diagnostics">
          <span class="ic">%(ic_diag)s</span>
          <span class="tx"><h3>Diagnostics Package</h3>
            <p>Device health dashboard, Win32 app status, applied policies (RSOP)
              with Intune names, plus a file viewer.</p></span>
        </a>
        <a class="tile" href="/errorcodes">
          <span class="ic">%(ic_codes)s</span>
          <span class="tx"><h3>Error codes</h3>
            <p>Searchable reference of Intune / Win32, Windows, network, DO and
              MSI codes with plain-language fixes.</p></span>
        </a>
        %(dropoff_tile)s
      </div>
    </section>

    <section class="explain">
      <h2 class="eyebrow">How it works</h2>
      <ol class="stepper">
        <li><span class="n">1</span><div><strong>Get the logs.</strong> From
          <code>%%ProgramData%%\\Microsoft\\IntuneManagementExtension\\Logs</code>,
          the Intune <em>Collect diagnostics</em> export, or the
          <a href="/collect-script">collector script</a>.</div></li>
        <li><span class="n">2</span><div><strong>Upload here.</strong> Drop a
          <code>.zip</code>, loose <code>.log</code> files or a folder &mdash;
          a zip goes to Diagnostics, loose logs to the Timeline.</div></li>
        <li><span class="n">3</span><div><strong>Read it in the browser.</strong>
          Timeline, log table or health dashboard &mdash; every result links
          back to the raw evidence.</div></li>
      </ol>
    </section>
    %(recent)s
  </main>
  %(footer)s
<script>
  const drop = document.getElementById('drop');
  const input = document.getElementById('input');
  const dirinput = document.getElementById('dirinput');
  const list = document.getElementById('files');
  const form = document.getElementById('form');
  const buttons = [...document.querySelectorAll('.go')];
  const LOGRE = new RegExp(%(patternjson)s, 'i');

  function setFiles(files) {
    const dt = new DataTransfer();
    files.filter(f => LOGRE.test(f.name)).forEach(f => dt.items.add(f));
    input.files = dt.files;
    refresh();
  }
  function refresh() {
    list.innerHTML = '';
    for (const f of input.files) {
      const li = document.createElement('li');
      li.textContent = (f.webkitRelativePath || f.name) +
                       ' (' + (f.size/1048576).toFixed(2) + ' MB)';
      list.appendChild(li);
    }
    const files = [...input.files];
    // Route by content: a single .zip -> Diagnostics; anything else -> Timeline.
    const oneZip = files.length === 1 && /\\.zip$/i.test(files[0].name);
    form.action = oneZip ? '/diagnostics-analyze' : '/analyze';
    buttons.forEach(b => b.disabled = files.length === 0);
  }

  const readBatch = r => new Promise(res => r.readEntries(res, () => res([])));
  async function walk(entry, out) {
    if (entry.isFile) {
      out.push(await new Promise((res, rej) => entry.file(res, rej)));
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      let batch;
      do { batch = await readBatch(reader); for (const e of batch) await walk(e, out); }
      while (batch.length);
    }
  }

  function pick(el, ev) { if (ev) { ev.preventDefault(); ev.stopPropagation(); } el.click(); }
  document.getElementById('pickfiles').addEventListener('click', ev => pick(input, ev));
  document.getElementById('pickdir').addEventListener('click', ev => pick(dirinput, ev));
  drop.addEventListener('click', () => input.click());
  input.addEventListener('change', refresh);
  dirinput.addEventListener('change', () => setFiles([...dirinput.files]));

  ['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.add('hl'); }));
  ['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.remove('hl'); }));
  drop.addEventListener('drop', async ev => {
    ev.preventDefault();
    const items = ev.dataTransfer.items;
    const out = [];
    if (items && items.length && items[0].webkitGetAsEntry) {
      const entries = [...items].map(i => i.webkitGetAsEntry()).filter(Boolean);
      for (const e of entries) await walk(e, out);
    } else {
      out.push(...ev.dataTransfer.files);
    }
    setFiles(out);
  });
</script>
</body></html>"""

UPLOAD_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; %(title)s</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>%(heading)s</h1>
    <p>%(intro)s</p>
  </section>
  <main class="wrap">
    <div class="card">
      <form id="form" action="%(action)s" method="post" enctype="multipart/form-data">
        <div class="drop" id="drop">
          %(droptext)s
          <a href="#" id="pickfiles">choose files</a> &middot;
          <a href="#" id="pickdir">choose a folder</a>.
        </div>
        <!-- Kept OUTSIDE #drop: a hidden input fires a click that bubbles, and
             if it bubbled to #drop it would re-open the file picker.
             #input is the only field that submits; #dirinput just opens the
             folder dialog and its files are transferred into #input. -->
        <input id="input" name="files" type="file" multiple
               accept="%(accept)s" style="display:none">
        <input id="dirinput" type="file" multiple
               webkitdirectory style="display:none">
        <ul id="files"></ul>
        <div class="row">
          <p class="limits">
            %(badges)s
            Max total upload: <strong>%(max)d&nbsp;MB</strong>
          </p>
          <button class="btn go" type="submit" disabled>%(button)s</button>
        </div>
      </form>
    </div>
    %(extra)s
    %(recent)s
  </main>
  %(footer)s
<script>
  const drop = document.getElementById('drop');
  const input = document.getElementById('input');      // the field that submits
  const dirinput = document.getElementById('dirinput'); // folder dialog trigger
  const list = document.getElementById('files');
  const buttons = [...document.querySelectorAll('.go')];
  const LOGRE = new RegExp(%(patternjson)s, 'i');

  // Assign a list of File objects to the (submitting) input via DataTransfer,
  // keeping only .log/.zip. Used by the folder dialog and folder drag-drop.
  function setFiles(files) {
    const dt = new DataTransfer();
    files.filter(f => LOGRE.test(f.name)).forEach(f => dt.items.add(f));
    input.files = dt.files;
    refresh();
  }
  function refresh() {
    list.innerHTML = '';
    for (const f of input.files) {
      const li = document.createElement('li');
      li.textContent = (f.webkitRelativePath || f.name) +
                       ' (' + (f.size/1048576).toFixed(2) + ' MB)';
      list.appendChild(li);
    }
    const empty = input.files.length === 0;
    buttons.forEach(b => b.disabled = empty);
  }

  // Recurse a dropped directory entry, collecting all files.
  const readBatch = r => new Promise(res => r.readEntries(res, () => res([])));
  async function walk(entry, out) {
    if (entry.isFile) {
      out.push(await new Promise((res, rej) => entry.file(res, rej)));
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      let batch;
      do { batch = await readBatch(reader); for (const e of batch) await walk(e, out); }
      while (batch.length);
    }
  }

  function pick(el, ev) { if (ev) { ev.preventDefault(); ev.stopPropagation(); } el.click(); }
  document.getElementById('pickfiles').addEventListener('click', ev => pick(input, ev));
  document.getElementById('pickdir').addEventListener('click', ev => pick(dirinput, ev));
  drop.addEventListener('click', () => input.click());
  input.addEventListener('change', refresh);                       // native file picker
  dirinput.addEventListener('change', () => setFiles([...dirinput.files])); // folder picker

  ['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.add('hl'); }));
  ['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {
    ev.preventDefault(); drop.classList.remove('hl'); }));
  drop.addEventListener('drop', async ev => {
    ev.preventDefault();
    const items = ev.dataTransfer.items;
    const out = [];
    if (items && items.length && items[0].webkitGetAsEntry) {
      const entries = [...items].map(i => i.webkitGetAsEntry()).filter(Boolean);
      for (const e of entries) await walk(e, out);   // handles dropped folders
    } else {
      out.push(...ev.dataTransfer.files);
    }
    setFiles(out);
  });
</script>
</body></html>"""

BUSY_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
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
  %(history)s
</body></html>"""

REPORT_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; timeline report</title>
<style>%(css)s
  html,body{height:100%%}
  body{display:flex;flex-direction:column}
  .topbar{display:flex;align-items:center;justify-content:space-between;
    padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:var(--bg)}
  iframe{border:0;width:100%%;flex:1;display:block}
  details.summary{flex:none;max-height:45vh;overflow:auto;background:var(--surface);
    border-bottom:1px solid var(--border);padding:.4rem 1.25rem;font-size:.9rem}
  details.summary>summary{cursor:pointer;font-weight:600;padding:.25rem 0}
  .sum-chips{display:flex;flex-wrap:wrap;gap:.4rem;margin:.5rem 0}
  .sum-chip{border:1px solid var(--border);border-radius:999px;padding:.15rem .7rem;
    background:var(--bg);white-space:nowrap}
  .sum-chip .ok{color:#1a7f37;font-weight:600}
  .sum-chip .bad{color:#c33;font-weight:600}
  .sum-chip .warn{color:#9a6700;font-weight:600}
  details.summary h3{margin:.7rem 0 .3rem;font-size:.95rem}
  details.summary table{border-collapse:collapse;width:100%%;font-size:.86rem}
  details.summary th,details.summary td{text-align:left;padding:.25rem .6rem;
    border-bottom:1px solid var(--border);vertical-align:top}
  details.summary .code{margin:.2rem 0}
  .sum-chip[data-type],.sum-chip[data-status]{cursor:pointer}
  .sum-chip[data-type]:hover,.sum-chip[data-status]:hover{border-color:var(--accent)}
  .sum-chip.active{border-color:var(--accent);background:rgba(37,99,235,.08)}
  details.summary .st-ok{color:#1a7f37;font-weight:600}
  details.summary .st-bad{color:#c33;font-weight:600}
  details.summary .st-warn{color:#9a6700;font-weight:600}
  details.summary .st-nd{color:#6b7280;font-weight:600}
</style></head><body>
  <div class="topbar">
    <a class="brand" href="/">%(logo)s Sherlog</a>
    <span>
      <a class="btn btn-ghost" href="/result/%(job)s/cmtrace">Raw logs (CMTrace)</a>
      <a class="btn btn-ghost" href="/timeline">New analysis</a>
    </span>
  </div>
  %(summary)s
  <iframe src="/result/%(job)s/report"
          sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"></iframe>
  %(history)s
</body></html>"""

CMTRACE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; raw logs (CMTrace)</title>
<style>%(css)s
  html,body{height:100%%}
  .topbar{display:flex;align-items:center;justify-content:space-between;
    padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:var(--bg)}
  .body{display:flex;height:calc(100vh - 3.6rem)}
  .side{width:300px;flex:none;overflow:auto;border-right:1px solid var(--border);
    background:var(--surface);padding:.5rem .35rem;font-size:.86rem}
  .side details{margin:0}
  .side summary{cursor:pointer;padding:.25rem .4rem;color:var(--fg);font-weight:600;
    border-radius:6px;list-style:none;display:flex;align-items:center;gap:.35rem}
  .side summary::before{content:'▸';color:var(--muted);font-size:.7rem;transition:.1s}
  .side details[open]>summary::before{transform:rotate(90deg)}
  .side .grp{padding-left:.6rem;border-left:1px solid var(--border);margin-left:.55rem}
  .side .file{padding:.3rem .5rem;border-radius:6px;color:var(--muted);cursor:pointer;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .side .file:hover{background:var(--bg);color:var(--fg)}
  .side .file.active{background:var(--accent);color:#fff}
  iframe{border:0;flex:1;height:100%%;display:block}
</style></head><body>
  <div class="topbar">
    <a class="brand" href="/">%(logo)s Sherlog</a>
    <span>
      %(timeline)s
      <a class="btn btn-ghost" href="/cmtrace">New analysis</a>
    </span>
  </div>
  <div class="body">
    <nav class="side" id="side">%(tree)s</nav>
    <iframe id="view" src="/result/%(job)s/cmtrace/view?file=%(first)s"></iframe>
  </div>
<script>
  const job = %(jobjson)s;
  const first = %(firstjson)s;
  const side = document.getElementById('side');
  const view = document.getElementById('view');
  const files = [...side.querySelectorAll('.file')];
  function select(el) {
    files.forEach(f => f.classList.toggle('active', f === el));
    view.src = '/result/' + job + '/cmtrace/view?file=' +
               encodeURIComponent(el.dataset.file);
  }
  side.addEventListener('click', ev => {
    const f = ev.target.closest('.file');
    if (f && f.dataset.file) select(f);
  });
  // Highlight the file the iframe already loaded (server's first/default).
  (files.find(f => f.dataset.file === first) || files[0])?.classList.add('active');
</script>
  %(history)s
</body></html>"""

DIAG_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; diagnostics package</title>
<style>%(css)s
  .topbar{display:flex;align-items:center;justify-content:space-between;
    padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:var(--bg)}
  .panels{padding:.9rem 1.25rem;display:flex;
    flex-direction:column;gap:.8rem}
  .panels>h2{margin:.2rem 0 0;font-size:1.15rem}
  .devline{color:var(--muted);font-size:.9rem;margin:0}
  .dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.7rem}
  .check{border:1px solid var(--border);border-radius:10px;padding:.65rem .9rem;
    background:var(--bg)}
  .check .lbl{font-weight:600;font-size:.92rem;display:flex;align-items:center;gap:.45rem}
  .check .st{width:.65rem;height:.65rem;border-radius:50%%;display:inline-block;flex:none}
  .st.ok{background:#16a34a}.st.bad{background:#dc2626}
  .st.warn{background:#d97706}.st.unknown{background:#9ca3af}
  .check .det{color:var(--muted);font-size:.85rem;margin-top:.2rem;word-break:break-word}
  .check[data-file]{cursor:pointer}
  .check[data-file]:hover,.check[data-file]:focus-visible{border-color:var(--accent)}
  details.section{background:var(--surface);border:1px solid var(--border);
    border-radius:10px;padding:.4rem 1rem;font-size:.85rem;max-height:45vh;overflow:auto}
  details.section>summary{cursor:pointer;font-weight:600;padding:.25rem 0}
  details.section .seclink{margin-left:.5rem;font-weight:400;font-size:.8rem;
    color:var(--accent);cursor:pointer}
  details.section table{border-collapse:collapse;width:100%%;margin-top:.5rem;
    table-layout:fixed}
  details.section th,details.section td{text-align:left;padding:.25rem .5rem;
    border-bottom:1px solid var(--row-border);vertical-align:top;
    overflow-wrap:anywhere;font-family:ui-monospace,Menlo,Consolas,monospace}
  details.section th{color:var(--muted);font-weight:600;position:sticky;top:0;
    background:var(--surface)}
  .acard{border:1px solid var(--border);border-radius:10px;padding:.75rem 1rem;
    background:var(--surface);display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}
  .acard pre{margin:.4rem 0 0;width:100%%;max-height:10rem}
  .spin-sm{width:1.1rem;height:1.1rem;border:2px solid var(--border);
    border-top-color:var(--accent);border-radius:50%%;flex:none;
    animation:spin 1s linear infinite}
  details.summary{background:var(--surface);border:1px solid var(--border);
    border-radius:10px;padding:.4rem 1rem;font-size:.9rem;max-height:45vh;overflow:auto}
  details.summary>summary{cursor:pointer;font-weight:600;padding:.25rem 0}
  .sum-chips{display:flex;flex-wrap:wrap;gap:.4rem;margin:.5rem 0}
  .sum-chip{border:1px solid var(--border);border-radius:999px;padding:.15rem .7rem;
    background:var(--bg);white-space:nowrap}
  .sum-chip .ok{color:#1a7f37;font-weight:600}
  .sum-chip .bad{color:#c33;font-weight:600}
  .sum-chip .warn{color:#9a6700;font-weight:600}
  details.summary h3{margin:.7rem 0 .3rem;font-size:.95rem}
  details.summary table{border-collapse:collapse;width:100%%;font-size:.86rem}
  details.summary th,details.summary td{text-align:left;padding:.25rem .6rem;
    border-bottom:1px solid var(--border);vertical-align:top}
  details.summary .code{margin:.2rem 0}
  .sum-chip[data-type],.sum-chip[data-status]{cursor:pointer}
  .sum-chip[data-type]:hover,.sum-chip[data-status]:hover{border-color:var(--accent)}
  .sum-chip.active{border-color:var(--accent);background:rgba(37,99,235,.08)}
  details.summary .st-ok{color:#1a7f37;font-weight:600}
  details.summary .st-bad{color:#c33;font-weight:600}
  details.summary .st-warn{color:#9a6700;font-weight:600}
  details.summary .st-nd{color:#6b7280;font-weight:600}
  .browser{display:flex;height:75vh;border-top:1px solid var(--border)}
  .side{width:300px;flex:none;overflow:auto;border-right:1px solid var(--border);
    background:var(--surface);padding:.5rem .35rem;font-size:.86rem}
  .side details{margin:0}
  .side summary{cursor:pointer;padding:.25rem .4rem;color:var(--fg);font-weight:600;
    border-radius:6px;list-style:none;display:flex;align-items:center;gap:.35rem}
  .side summary::before{content:'▸';color:var(--muted);font-size:.7rem;transition:.1s}
  .side details[open]>summary::before{transform:rotate(90deg)}
  .side .grp{padding-left:.6rem;border-left:1px solid var(--border);margin-left:.55rem}
  .side .file{padding:.3rem .5rem;border-radius:6px;color:var(--muted);cursor:pointer;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .side .file:hover{background:var(--bg);color:var(--fg)}
  .side .file.active{background:var(--accent);color:#fff}
  .side .file.disabled{opacity:.45;cursor:default}
  .side .file.disabled:hover{background:none;color:var(--muted)}
  .browser iframe{border:0;flex:1;height:100%%;display:block}
</style></head><body>
  <div class="topbar">
    <a class="brand" href="/">%(logo)s Sherlog</a>
    <span>
      <a class="btn btn-ghost" href="/result/%(job)s/cmtrace">Raw logs (CMTrace)</a>
      <a class="btn btn-ghost" href="/diagnostics">New upload</a>
    </span>
  </div>
  <div class="panels">
    <h2>Device health</h2>
    %(dashboard)s
    %(analysis)s
    %(summary)s
  </div>
  <div class="browser">
    <nav class="side" id="side">%(tree)s</nav>
    <iframe id="view" src="%(firstsrc)s"></iframe>
  </div>
<script>
  const job = %(jobjson)s;
  const first = %(firstjson)s;
  const side = document.getElementById('side');
  const view = document.getElementById('view');
  const files = [...side.querySelectorAll('.file')];
  function select(el, line) {
    files.forEach(f => f.classList.toggle('active', f === el));
    view.src = '/result/' + job + '/files/view?file=' +
               encodeURIComponent(el.dataset.file) +
               (line ? '#L' + encodeURIComponent(line) : '');
  }
  side.addEventListener('click', ev => {
    const f = ev.target.closest('.file');
    if (f && f.dataset.file) select(f);
  });
  (files.find(f => f.dataset.file === first) || null)?.classList.add('active');

  // Health-check cards deep-link to the evidence line in their source file.
  function openSource(card) {
    const f = files.find(x => x.dataset.file === card.dataset.file);
    if (!f) return;
    // Unfold the tree groups so the highlighted file is visible.
    for (let d = f.closest('details'); d;
         d = d.parentElement && d.parentElement.closest('details')) d.open = true;
    select(f, card.dataset.line);
    f.scrollIntoView({block: 'nearest'});
    view.scrollIntoView({behavior: 'smooth', block: 'nearest'});
  }
  document.querySelectorAll('.check[data-file],.seclink[data-file]').forEach(card => {
    card.addEventListener('click', () => openSource(card));
    card.addEventListener('keydown', ev => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openSource(card); }
    });
  });

  // While the timeline analysis runs, poll the job status and reload once it
  // settles so the analysis card and summary panel appear without user action.
  const analysisState = %(analysisjson)s;
  if (analysisState === 'queued' || analysisState === 'running') {
    const timer = setInterval(async () => {
      try {
        const r = await fetch('/result/' + job + '/status');
        if (!r.ok) return;
        const j = await r.json();
        if (j.analysis !== 'queued' && j.analysis !== 'running') {
          clearInterval(timer);
          location.reload();
        }
      } catch (e) {}
    }, 5000);
  }
</script>
  %(history)s
</body></html>"""

ERROR_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
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
      <p class="center"><a class="btn btn-ghost" href="/timeline">&larr; Try another upload</a></p>
    </div>
  </main>
  %(footer)s
  %(history)s
</body></html>"""


def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def attr_escape(s: str) -> str:
    """Escape for double-quoted HTML attribute values (filenames from
    untrusted zips can contain quotes)."""
    return html_escape(s).replace('"', "&quot;")


# The upstream script appends an author/branding banner (<footer> with author
# photo, MVP logo and a GitHub download link). We strip it from the served
# report at display time so the PowerShell script stays unpatched and
# upstream-mergeable (see CLAUDE.md: report format in the script is unchanged).
_BRANDING_FOOTER = re.compile(r"<footer\b[^>]*>.*?</footer>", re.IGNORECASE | re.DOTALL)


def strip_branding(html: str) -> str:
    return _BRANDING_FOOTER.sub("", html, count=1)


_SUMMARY_STATUS_CLASS = {"Success": "st-ok", "Failed": "st-bad",
                         "Warning": "st-warn", "Not Detected": "st-nd"}

_SUMMARY_ITEMS_JS = """<script>
(function () {
  const root = document.currentScript.closest('details');
  const rows = [...root.querySelectorAll('tr.it')];
  const chips = [...root.querySelectorAll('.sum-chip[data-type],.sum-chip[data-status]')];
  const heading = root.querySelector('.items-h');
  const table = root.querySelector('.items-t');
  let active = null;  // null = default failed-only view
  function key(el) { return el.dataset.type || el.dataset.status; }
  function apply() {
    let shown = 0;
    for (const r of rows) {
      const on = active === null ? r.dataset.status === 'Failed'
               : active.type ? r.dataset.type === active.type
                             : r.dataset.status === active.status;
      r.style.display = on ? '' : 'none';
      if (on) shown++;
    }
    heading.textContent = active === null ? 'Failed items'
      : (active.type || active.status) + ' \\u2014 ' + shown + ' item(s)';
    heading.style.display = table.style.display = shown ? '' : 'none';
    chips.forEach(c => c.classList.toggle('active',
      active !== null && key(c) === (active.type || active.status)));
  }
  chips.forEach(c => c.addEventListener('click', () => {
    const sel = {type: c.dataset.type || '', status: c.dataset.status || ''};
    active = (active && key(c) === (active.type || active.status)) ? null : sel;
    apply();
  }));
  apply();
})();
</script>"""


def _render_summary_items(items: List[dict]) -> str:
    """Drill-down table behind the summary chips: every outcome row, filtered
    client-side (default: failed only; chip click: everything of that type)."""
    rows = []
    for i in items:
        status = str(i.get("status", ""))
        cls = _SUMMARY_STATUS_CLASS.get(status, "")
        rows.append(
            f'<tr class="it" data-type="{attr_escape(str(i.get("type", "")))}"'
            f' data-status="{attr_escape(status)}">'
            f"<td>{html_escape(str(i.get('date', '')))}</td>"
            f"<td>{html_escape(str(i.get('type', '')))}</td>"
            f"<td>{html_escape(str(i.get('intent', '')))}</td>"
            f'<td class="{cls}">{html_escape(status)}</td>'
            f"<td>{html_escape(str(i.get('detail', '')))}</td></tr>"
        )
    return (
        '<h3 class="items-h">Failed items</h3>'
        '<table class="items-t"><tr><th>Date</th><th>Type</th><th>Intent</th>'
        f'<th>Status</th><th>Detail</th></tr>{"".join(rows)}</table>'
        + _SUMMARY_ITEMS_JS
    )


def render_summary_panel(summary: Optional[dict]) -> str:
    """Collapsible summary panel for the result page.

    Renders in the app origin (not sandboxed), so every value — all derived
    from untrusted log content — is escaped. Returns "" when there is nothing
    worth showing so the page degrades to the plain report view.
    """
    if not summary or not summary.get("parse_ok"):
        return ""
    counts = summary.get("counts", [])
    warnings = summary.get("warnings", 0)
    not_detected = summary.get("not_detected", 0)
    failed_items = summary.get("failed_items", [])
    items = summary.get("items") or []  # absent in pre-drilldown summary.json
    top_errors = summary.get("top_errors", [])
    downloads = summary.get("downloads", [])
    if not (counts or warnings or not_detected or failed_items or downloads):
        return ""

    total_failed = sum(c.get("failed", 0) for c in counts)
    total_success = sum(c.get("success", 0) for c in counts)

    def chip(label_html: str, **data: str) -> str:
        attrs = "".join(f' data-{k}="{attr_escape(v)}"' for k, v in data.items()
                        if items)  # only clickable when there is a drill-down
        return f'<span class="sum-chip"{attrs}>{label_html}</span>'

    chips = []
    for c in counts:
        chips.append(chip(
            f'{html_escape(c["type"])}: '
            f'<span class="ok">{c.get("success", 0)} ok</span> / '
            f'<span class="bad">{c.get("failed", 0)} failed</span>',
            type=str(c["type"])))
    if warnings:
        chips.append(chip(f'<span class="warn">{warnings} warning(s)</span>',
                          status="Warning"))
    if not_detected:
        chips.append(chip(f'<span class="bad">{not_detected} not detected</span>',
                          status="Not Detected"))

    parts = [f'<div class="sum-chips">{"".join(chips)}</div>']

    if top_errors:
        rows = "".join(
            f'<div class="code"><strong>{html_escape(e["code"])}</strong> '
            f'({e["count"]}&times;) &mdash; {html_escape(e["explanation"])}</div>'
            for e in top_errors
        )
        parts.append(f"<h3>Known error codes</h3>{rows}")

    if items:
        parts.append(_render_summary_items(items))
    elif failed_items:
        rows = "".join(
            f"<tr><td>{html_escape(i['date'])}</td>"
            f"<td>{html_escape(i['type'])}</td>"
            f"<td>{html_escape(i['intent'])}</td>"
            f"<td>{html_escape(i['detail'])}</td></tr>"
            for i in failed_items
        )
        parts.append(
            "<h3>Failed items</h3><table><tr><th>Date</th><th>Type</th>"
            f"<th>Intent</th><th>Detail</th></tr>{rows}</table>"
        )

    if downloads:
        rows = "".join(
            f"<tr><td>{html_escape(d['app_type'])}</td>"
            f"<td>{html_escape(d['app_name'])}</td>"
            f"<td>{html_escape(d['dl_sec'])}</td>"
            f"<td>{html_escape(d['size_mb'])}</td>"
            f"<td>{html_escape(d['mbps'])}</td>"
            f"<td>{html_escape(d['do_pct'])}</td></tr>"
            for d in downloads
        )
        parts.append(
            "<h3>App downloads</h3><table><tr><th>Type</th><th>App</th>"
            "<th>DL sec</th><th>Size (MB)</th><th>MB/s</th>"
            f"<th>Delivery Optimization %</th></tr>{rows}</table>"
        )

    open_attr = " open" if (total_failed or warnings or not_detected) else ""
    heading = (f"Analysis summary &mdash; {total_failed} failed, "
               f"{total_success} succeeded")
    return (f'<details class="summary"{open_attr}><summary>{heading}</summary>'
            f'{"".join(parts)}</details>')


def render_dashboard_panel(dash: Optional[dict]) -> str:
    """Health-check cards for the diagnostics result page.

    Rendered in the app origin, so every value — all parsed from untrusted
    package content — is escaped.
    """
    if not dash:
        return '<p class="devline">No dashboard data for this package.</p>'
    parts = []
    device = dash.get("device", {})
    bits = [device.get("name", ""), device.get("tenant", ""),
            device.get("collected", "")]
    bits = [b for b in bits if b]
    if bits:
        parts.append(f'<p class="devline">{html_escape(" · ".join(bits))}</p>')
    cards = []
    for c in dash.get("checks", []):
        st = c.get("status", "unknown")
        if st not in ("ok", "bad", "warn", "unknown"):
            st = "unknown"
        # Deep-link to the evidence in the file browser when the parser
        # recorded a source (older dashboard.json files have none).
        attrs = ""
        src = c.get("src")
        if isinstance(src, str) and src:
            line = c.get("line")
            attrs = (f' data-file="{attr_escape(src)}"'
                     + (f' data-line="{line}"' if isinstance(line, int) else "")
                     + f' role="link" tabindex="0"'
                       f' title="Open {attr_escape(src)}"')
        cards.append(
            f'<div class="check"{attrs}>'
            f'<span class="lbl"><span class="st {st}"></span>'
            f'{html_escape(str(c.get("label", "")))}</span>'
            f'<div class="det">{html_escape(str(c.get("detail", "")))}</div></div>'
        )
    if cards:
        parts.append(f'<div class="dash">{"".join(cards)}</div>')
    for sec in dash.get("sections", []):
        cols = sec.get("columns", [])
        rows = sec.get("rows", [])
        if not rows:
            continue
        src = sec.get("src")
        link = ""
        if isinstance(src, str) and src:
            link = (f'<span class="seclink" data-file="{attr_escape(src)}"'
                    f' role="link" tabindex="0"'
                    f' title="Open {attr_escape(src)}">source &rarr;</span>')
        head = "".join(f"<th>{html_escape(str(c))}</th>" for c in cols)
        # Optional per-column widths (percent ints) for the fixed table layout,
        # so a short column (e.g. Value) isn't crushed by long ones (OMA-URI).
        widths = sec.get("widths")
        colgroup = ""
        if widths and len(widths) == len(cols):
            colgroup = ("<colgroup>"
                        + "".join(f'<col style="width:{int(w)}%">' for w in widths)
                        + "</colgroup>")

        def render_cell(cell) -> str:
            # A dict cell {text, href} becomes an external link (e.g. the
            # Microsoft Learn deep-link for a policy setting); else plain text.
            if isinstance(cell, dict) and cell.get("href"):
                return (f'<td><a href="{attr_escape(str(cell["href"]))}"'
                        f' target="_blank" rel="noopener">'
                        f'{html_escape(str(cell.get("text", "")))}</a></td>')
            return f"<td>{html_escape(str(cell))}</td>"

        body = "".join(
            "<tr>" + "".join(render_cell(cell) for cell in row) + "</tr>"
            for row in rows)
        parts.append(
            f'<details class="section"><summary>'
            f'{html_escape(str(sec.get("title", "")))}{link}</summary>'
            f'<table>{colgroup}<thead><tr>{head}</tr></thead>'
            f'<tbody>{body}</tbody></table></details>')
    return "".join(parts)


def render_analysis_card(job_id: str, analysis: dict) -> str:
    """State card for the timeline-analysis sub-task of a diagnostics job."""
    state = analysis.get("state", "none")
    if state == "done":
        return (f'<div class="acard"><strong>Timeline analysis ready.</strong>'
                f'<a class="btn" href="/result/{job_id}/timeline">'
                f'Open timeline report</a></div>')
    if state in ("queued", "running"):
        return ('<div class="acard"><span class="spin-sm"></span>'
                'Running the timeline analysis on the IME logs in this package&hellip; '
                'this page updates automatically.</div>')
    if state == "failed":
        stderr = html_escape(analysis.get("stderr", "") or "(empty)")
        return ('<div class="acard"><strong>Timeline analysis failed.</strong> '
                'The package files below are still browsable.'
                f'<pre>{stderr}</pre></div>')
    return ('<div class="acard">No IME logs found in this package &mdash; '
            'timeline analysis skipped.</div>')


# --- CMTrace viewer rendering ------------------------------------------------

# Standalone styles: the view is served inside a sandboxed iframe (separate
# origin), so it cannot share the app's stylesheet — keep it self-contained.
# Dark mode: the sandbox has no localStorage, so the head script falls back
# to prefers-color-scheme and the parent page syncs its toggle via
# postMessage (both set .dark on <html>).
_CMTRACE_CSS = """
  :root{ --bg:#ffffff; --fg:#1f2937; --muted:#6b7280; --faint:#9ca3af;
    --surface:#f9fafb; --surface2:#f3f4f6; --border:#e5e7eb; --border2:#d1d5db;
    --row-border:#f1f5f9; --hl:#e0e7ff; --accent:#2563eb;
    --warn-bg:#fffbeb; --warn-fg:#92400e; --warn-border:#fde68a;
    --err-bg:#fef2f2; --err-fg:#b91c1c; --err-border:#fecaca;
    --info-bg:#eff6ff; --info-fg:#1d4ed8; --note-bg:#fef3c7; }
  html.dark{ --bg:#0f172a; --fg:#e2e8f0; --muted:#94a3b8; --faint:#64748b;
    --surface:#16202f; --surface2:#1e293b; --border:#293548; --border2:#334155;
    --row-border:#1c2638; --hl:#1e3a8a; --accent:#3b82f6;
    --warn-bg:#27200c; --warn-fg:#fbbf24; --warn-border:#5b4708;
    --err-bg:#2c1517; --err-fg:#f87171; --err-border:#7f1d1d;
    --info-bg:#172554; --info-fg:#93c5fd; --note-bg:#27200c; }
  *{box-sizing:border-box}
  body{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    margin:0;color:var(--fg);background:var(--bg)}
  .bar{position:sticky;top:0;display:flex;gap:.5rem;align-items:center;
    padding:.5rem .75rem;background:var(--surface);
    border-bottom:1px solid var(--border);z-index:2}
  .bar input,.bar select{font:inherit;padding:.3rem .5rem;
    border:1px solid var(--border2);border-radius:6px;
    background:var(--bg);color:var(--fg)}
  .bar input{flex:1;min-width:8rem}
  .qjump{display:flex;gap:.3rem;flex-wrap:wrap}
  .qjump button{font:inherit;font-size:.8rem;padding:.2rem .55rem;cursor:pointer;
    border:1px solid var(--border2);border-radius:999px;
    background:var(--surface);color:var(--muted)}
  .qjump button:hover{border-color:var(--accent);color:var(--fg)}
  .qjump button.on{background:var(--accent);border-color:var(--accent);color:#fff}
  .count{color:var(--muted);white-space:nowrap}
  .note{padding:.5rem .75rem;color:var(--warn-fg);background:var(--note-bg);
    border-bottom:1px solid var(--warn-border)}
  table{border-collapse:collapse;width:100%;table-layout:fixed}
  th,td{text-align:left;padding:.25rem .6rem;
    border-bottom:1px solid var(--row-border);
    vertical-align:top;word-break:break-word;white-space:pre-wrap}
  th{position:sticky;top:2.6rem;background:var(--surface2);font-weight:600;z-index:1}
  td.msg{width:auto}
  td.c,td.t,td.th{width:9rem;color:var(--muted);white-space:nowrap}
  td.th{width:4rem}
  td.ln,th.ln{width:4rem;color:var(--faint);text-align:right;
    font-variant-numeric:tabular-nums;user-select:none}
  tr.warn{background:var(--warn-bg)}
  tr.warn td.msg{color:var(--warn-fg)}
  tr.err{background:var(--err-bg)}
  tr.err td.msg{color:var(--err-fg);font-weight:600}
  tr.hide{display:none}
  /* Deep-link target (#L<n> from a dashboard card): highlight and keep the
     row clear of the sticky filter bar + header. */
  tr:target td{background:var(--hl)}
  tr:target{scroll-margin-top:6rem}
  .legend{display:flex;gap:.6rem;align-items:center;color:var(--muted);
    white-space:nowrap}
  .legend .sw{display:inline-block;width:.8rem;height:.8rem;border-radius:3px;
    margin-right:.25rem;vertical-align:-1px;border:1px solid rgba(0,0,0,.08)}
  .sw.w{background:var(--warn-bg);border-color:var(--warn-border)}
  .sw.e{background:var(--err-bg);border-color:var(--err-border)}
  #body tr{cursor:pointer}
  tr.sel,tr.sel.warn,tr.sel.err{background:var(--hl)}
  #detail{position:fixed;bottom:0;left:0;right:0;max-height:45%;overflow-y:auto;overflow-x:hidden;
    background:var(--bg);border-top:2px solid var(--border2);
    box-shadow:0 -6px 16px rgba(0,0,0,.1);padding:.6rem 1rem;z-index:3}
  #d-resize{height:8px;margin:-.6rem -1rem .45rem;cursor:ns-resize;
    background:linear-gradient(var(--border2),var(--border2)) center/2rem 2px no-repeat;
    user-select:none;flex-shrink:0}
  #d-resize:hover,#d-resize.active{background-color:var(--surface2);
    background-image:linear-gradient(var(--accent),var(--accent))}
  .d-bar{display:flex;justify-content:space-between;align-items:center;gap:.5rem}
  .d-actions{display:flex;gap:.35rem}
  #d-close,#d-copy{font:inherit;border:1px solid var(--border2);background:var(--surface);
    color:var(--fg);border-radius:6px;cursor:pointer;padding:.05rem .55rem}
  #d-close:hover,#d-copy:hover{background:var(--surface2)}
  #d-copy.copied{color:var(--accent);border-color:var(--accent)}
  #d-msg{margin:.45rem 0;white-space:pre-wrap;word-break:break-word}
  .d-meta{color:var(--muted);margin-bottom:.4rem}
  .sev{font-weight:600;padding:.1rem .55rem;border-radius:999px}
  .sev.e{background:var(--err-bg);color:var(--err-fg)}
  .sev.w{background:var(--warn-bg);color:var(--warn-fg)}
  .sev.i{background:var(--info-bg);color:var(--info-fg)}
  #d-explain .code{margin:.35rem 0;padding:.45rem .6rem;background:var(--info-bg);
    border-left:3px solid var(--accent);border-radius:0 6px 6px 0}
"""


def _row_class(type_str: str) -> str:
    t = type_str.strip().lower()
    if t in ("3", "error"):
        return "err"
    if t in ("2", "warning", "warn"):
        return "warn"
    return ""


# Keyword colouring for plain (non-CMTrace) command-output lines.
_PLAIN_ERR = re.compile(r"\b(error|errors|failed|failure|fatal|exception|0x8)\b|0x8[0-9a-f]{7}", re.I)
_PLAIN_WARN = re.compile(r"\b(warn|warning|warnings)\b", re.I)


def _plain_class(text: str) -> str:
    if _PLAIN_ERR.search(text):
        return "err"
    if _PLAIN_WARN.search(text):
        return "warn"
    return ""


# Plain-language explanations for error codes commonly seen in IME logs, shown
# in the detail panel when a clicked entry contains one. Hex keys are uppercase
# `0x`-form; bare decimal keys are MSI exit codes (matched only in an
# "exit/error code N" context to avoid false positives). Sources: Microsoft
# Learn — Intune app installation error reference & application installation
# common error codes reference.
ERROR_CODES: dict[str, str] = {
    # Intune Win32 / IME (0x87D1xxxx, 0x87D5xxxx)
    "0x87D1041C": "The app installed successfully, but the detection rules did "
                  "not find it afterwards (or the user uninstalled it). Check "
                  "the app's detection rule: file path, MSI product code or "
                  "registry key.",
    "0x87D5501C": "Download failed: the downloaded file could not be found. "
                  "The content was removed or corrupted before installation.",
    "0x87D5501D": "Download failed because of an input/output error. Intune "
                  "retries automatically.",
    "0x87D5501E": "Download failed because it took too long (more than 8 "
                  "hours). Intune cancels and retries the download.",
    "0x87D5501F": "The downloaded app could not be validated: the file hash "
                  "does not match the policy. Often a corrupted download or "
                  "an SSL-inspecting proxy.",
    "0x87D55078": "Download failed because of an Intune service error. "
                  "Retried automatically.",
    "0x87D55079": "Download failed because of a network error (generic HTTP "
                  "failure). Retried automatically.",
    "0x87D5507A": "Download failed: the app no longer exists or is no longer "
                  "assigned to this device (assignment removed while the "
                  "policy was applying).",
    "0x87D5507B": "Download failed because of an Intune service error. "
                  "Retried automatically.",
    "0x87D5507C": "Download failed because of an Intune service error. "
                  "Retried automatically.",
    "0x87D5507D": "Download failed because of an Intune service error. "
                  "Retried automatically.",
    "0x87D103E8": "Unknown error during app installation. Check the "
                  "surrounding log lines and the app's own install log.",
    # Management agent / app evaluation (0x87D00xxx — shared agent codes,
    # seen on co-managed devices and in agent logs)
    "0x87D00215": "Item not found: the deployment or its content is not "
                  "available to the client. Check that the assignment still "
                  "exists and content is reachable.",
    "0x87D00321": "The script execution has timed out. The install or "
                  "detection script ran longer than the allowed run time.",
    "0x87D00324": "The application was not detected after installation "
                  "completed. The install finished but the detection rule "
                  "did not match — verify the detection rule.",
    "0x87D00325": "The application was still detected after the uninstall "
                  "completed. The uninstall command did not remove what the "
                  "detection rule checks.",
    "0x87D00327": "Script is not signed. The PowerShell execution policy "
                  "requires signed scripts; sign the script or change the "
                  "policy.",
    "0x87D00329": "Application requirement evaluation or detection failed. "
                  "Check dependency and supersedence rules and the "
                  "detection script for errors.",
    "0x87D00607": "Content not found: the app content could not be located "
                  "for download.",
    "0x87D01107": "Failed to access the provided program locations; the "
                  "client retries if attempts remain.",
    "0x87D01201": "The content download cannot be performed: not enough "
                  "available cache space or the disk is full.",
    "0x87D01202": "The content download cannot be performed: the configured "
                  "client cache is smaller than the requested content.",
    # Windows installer / general Windows (0x800700xx = Win32 error as HRESULT)
    "0x80004005": "Unspecified error. Check the surrounding log lines and the "
                  "app's own install log for the real cause.",
    "0x8000FFFF": "Catastrophic failure — an unexpected error during "
                  "installation. Check the installation logs.",
    "0x80040154": "Class not registered: a required COM component or DLL is "
                  "not registered on the device.",
    "0x80070002": "The system cannot find the file specified — an expected "
                  "file or path is missing.",
    "0x80070003": "The system cannot find the path specified.",
    "0x80070005": "Access denied. The installing process lacks permission "
                  "(NTFS rights, antivirus blocking, or admin rights needed).",
    "0x8007000D": "The data is invalid — often a corrupt installer package "
                  "or malformed configuration.",
    "0x8007000E": "Not enough memory to complete the operation.",
    "0x80070032": "The request is not supported on this device or OS "
                  "version.",
    "0x8007007E": "The specified module could not be found — a required "
                  "DLL is missing or a dependency is not installed.",
    "0x800704C7": "The operation was cancelled by the user.",
    "0x80070570": "The file or directory is corrupted and unreadable — "
                  "often a corrupt download or failing disk.",
    "0x800706BA": "The RPC server is unavailable — a required service is "
                  "not running or is blocked.",
    "0x80070020": "The file is in use by another process (sharing violation).",
    "0x80070057": "Invalid parameter — often a malformed install command line.",
    "0x800700C1": "Not a valid Win32 application — usually a corrupt download "
                  "or a wrong-architecture (x86/x64/ARM64) binary.",
    "0x80070490": "Element not found — a required registry key, setting or "
                  "component is missing.",
    "0x800705B4": "The operation timed out.",
    "0x80070641": "The Windows Installer service could not be accessed "
                  "(MSI 1601). Check that the msiserver service can run.",
    "0x80070642": "The user cancelled the installation (MSI 1602).",
    "0x80070643": "Fatal error during installation (MSI 1603). The installer "
                  "itself failed; check the application's own install log.",
    "0x80070645": "This action is only valid for products that are "
                  "currently installed (MSI 1605) — often an uninstall of "
                  "something already removed.",
    "0x80070652": "Another installation is already in progress (MSI 1618). "
                  "Wait for it to finish and retry.",
    "0x80070659": "The installation is forbidden by system policy "
                  "(MSI 1625). Check Windows Installer group policies.",
    "0x80070661": "The package is not supported by this processor type "
                  "(MSI 1633) — architecture mismatch.",
    "0x80070666": "Another version of this product is already installed "
                  "(MSI 1638). Uninstall or upgrade the existing version.",
    "0x80070BC2": "The installation succeeded but a restart is required to "
                  "complete it (MSI 3010).",
    "0x80091007": "The hash value is not correct: downloaded content does not "
                  "match the expected hash. Often caused by a proxy or "
                  "security software modifying the file.",
    "0xC0000142": "A DLL failed to initialize and the process terminated "
                  "abnormally — often a broken dependency.",
    # MSIX / Store packages
    "0x80073CF0": "The package could not be opened — it is unsigned or the "
                  "publisher name does not match the signing certificate.",
    "0x80073CF3": "The package conflicts with an installed package, a "
                  "dependency is missing, or the processor architecture does "
                  "not match.",
    "0x80073CFB": "The package is already installed and reinstalling a "
                  "non-identical (rebuilt/re-signed) version is blocked. "
                  "Increment the package version.",
    "0x80073CFF": "Sideloading is required to install this package: the "
                  "package must be signed with a trusted certificate and "
                  "the device must allow trusted apps.",
    # Network / WinHTTP
    "0x80072EE2": "The network request timed out while contacting the server.",
    "0x80072EE7": "The server name could not be resolved — DNS failure or "
                  "proxy issue.",
    "0x80072EFD": "Could not connect to the server (firewall, proxy or "
                  "network outage).",
    "0x80072EFE": "The connection to the server was closed unexpectedly.",
    "0x80072F05": "The server certificate's date is invalid (expired or not "
                  "yet valid) — check the system clock and any "
                  "SSL-inspecting proxy.",
    "0x80072F06": "The server certificate's hostname does not match the "
                  "requested host — often an SSL-inspecting proxy.",
    "0x80072F8F": "TLS/SSL security error — often a wrong system clock or an "
                  "SSL-inspecting proxy presenting an untrusted certificate.",
    # Delivery Optimization (0x80D0xxxx) — used for Win32 app content downloads
    "0x80D01001": "Delivery Optimization was unable to provide the service. "
                  "Check that the DoSvc service is running.",
    "0x80D02002": "The download made no progress within the defined period "
                  "— a stalled connection, proxy or firewall issue.",
    "0x80D02010": "No file is available because no download URL produced a "
                  "result.",
    "0x80D02013": "The requested action is not allowed in the current "
                  "download job state (job cancelled or already completed).",
    "0x80D03002": "The download job is not allowed due to user or admin "
                  "settings — often Delivery Optimization DownloadMode set "
                  "to 100 (Bypass), which is deprecated.",
    "0x80D03801": "Delivery Optimization paused the download due to "
                  "metered-connection cost policy restrictions.",
    "0x80D03803": "Delivery Optimization paused the download because a "
                  "cellular network was detected and policy restricts it.",
    "0x80D03804": "Delivery Optimization paused the download because the "
                  "device switched to battery power.",
    "0x80D03805": "Delivery Optimization paused the download due to loss of "
                  "network connectivity.",
    "0x80D03807": "Delivery Optimization paused the download because a VPN "
                  "connection was detected.",
    "0x80D03808": "Delivery Optimization paused the download due to "
                  "critical memory usage on the system.",
    "0x80D05001": "The HTTP server returned a response with a different "
                  "data size than requested — often a proxy or captive "
                  "portal interfering with the download.",
    "0x80D05010": "The specified byte range is invalid.",
    "0x80D05011": "The server does not support the HTTP Range header that "
                  "Delivery Optimization requires — often a proxy that "
                  "strips range support.",
    # HTTP status wrapped as HRESULT (0x80190xxx, last hex digits = status)
    "0x80190190": "HTTP 400 Bad Request — the service rejected the request.",
    "0x80190191": "HTTP 401 Unauthorized — authentication failed or the "
                  "token expired.",
    "0x80190193": "HTTP 403 Forbidden — the device or user may not access "
                  "the resource.",
    "0x80190194": "HTTP 404 Not Found — the requested content is missing "
                  "(often an expired download link).",
    "0x801901F4": "HTTP 500 Internal Server Error — a service-side failure, "
                  "usually transient.",
    "0x801901F7": "HTTP 503 Service Unavailable — the service is temporarily "
                  "overloaded; retried later.",
    # .NET
    "0x80131500": "A .NET exception occurred in the agent or installer; see "
                  "the surrounding log lines for the stack trace.",
    # Bare MSI exit codes (matched as "exit code N" / "error code N")
    "1601": "MSI: the Windows Installer service could not be accessed. "
            "Check that the msiserver service can run.",
    "1602": "MSI: the user cancelled the installation.",
    "1603": "MSI: fatal error during installation. Check the application's "
            "own install log for the real cause.",
    "1605": "MSI: the product is not installed — often an uninstall or "
            "upgrade of something already removed.",
    "1606": "MSI: could not access a required (network) location.",
    "1618": "MSI: another installation is already in progress.",
    "1619": "MSI: the installation package could not be opened — missing "
            "file or insufficient permissions.",
    "1620": "MSI: the installation package could not be opened — it is not "
            "a valid Windows Installer package or is corrupt.",
    "1622": "MSI: error opening the installation log file — the log path "
            "is invalid or not writable.",
    "1625": "MSI: this installation is forbidden by system policy. Check "
            "Windows Installer group policies.",
    "1632": "MSI: the Temp folder is full or inaccessible. Free up space "
            "and check permissions on the Temp directory.",
    "1633": "MSI: the package is not supported by this processor type "
            "(architecture mismatch).",
    "1638": "MSI: another version of this product is already installed.",
    "1639": "MSI: invalid command line argument — check the install "
            "command line in the app configuration.",
    "1641": "MSI: installation succeeded and a restart has been initiated.",
    "1642": "MSI: the upgrade patch does not match the installed program "
            "(missing or different version).",
    "3010": "MSI: installation succeeded but a restart is required.",
}


def render_cmtrace_view(filename: str, records: List[dict], truncated: bool) -> str:
    """Standalone (sandboxed) HTML view for one parsed log file.

    Two layouts: a full CMTrace table when the file has structured records, or a
    compact line-numbered single column for plain command-output logs (empty
    Component/Date/Thread columns are dropped). Every field is html-escaped —
    log content is untrusted.
    """
    structured = any(r["structured"] for r in records)
    note = ""
    if truncated:
        note = (f'<div class="note">Showing the first {len(records):,} lines '
                f'(file is larger; output truncated).</div>')

    if structured:
        meta_labels = [["c", "Component"], ["t", "Time"], ["th", "Thread"]]
        components = sorted({r["component"] for r in records if r["component"]})
        opts = "".join(
            f'<option value="{html_escape(c)}">{html_escape(c)}</option>'
            for c in components
        )
        rows = []
        for i, r in enumerate(records, 1):
            cls = _row_class(r["type"]) if r["structured"] else _plain_class(r["msg"])
            when = (r["date"] + " " + r["time"]).strip()
            rows.append(
                f'<tr id="L{i}" class="{cls}" data-c="{html_escape(r["component"])}">'
                f'<td class="msg">{html_escape(r["msg"])}</td>'
                f'<td class="c">{html_escape(r["component"])}</td>'
                f'<td class="t">{html_escape(when)}</td>'
                f'<td class="th">{html_escape(r["thread"])}</td></tr>'
            )
        head = ('<th>Log text</th><th class="c">Component</th>'
                '<th class="t">Date / time</th><th class="th">Thread</th>')
        comp_sel = ('<select id="comp"><option value="">All components</option>'
                    f'{opts}</select>')
    else:
        meta_labels = []
        rows = []
        for i, r in enumerate(records, 1):
            cls = _plain_class(r["msg"])
            rows.append(
                f'<tr id="L{i}" class="{cls}" data-c="">'
                f'<td class="ln">{i}</td>'
                f'<td class="msg">{html_escape(r["msg"])}</td></tr>'
            )
        head = '<th class="ln">#</th><th>Log text</th>'
        comp_sel = ""

    return _render_records_page(filename, head, rows, comp_sel, note, meta_labels)


def render_evtx_view(filename: str, records: List[dict], truncated: bool) -> str:
    """Standalone (sandboxed) HTML view for one parsed .evtx event log."""
    note = ""
    if truncated:
        note = (f'<div class="note">Showing the first {len(records):,} events '
                f'(EVTX_MAX_EVENTS cap). Messages are best-effort: offline '
                f'message tables are unavailable, so raw event data is shown.</div>')

    providers = sorted({r["provider"] for r in records if r["provider"]})
    opts = "".join(
        f'<option value="{html_escape(p)}">{html_escape(p)}</option>'
        for p in providers
    )
    rows = []
    for i, r in enumerate(records, 1):
        cls = _evtx_row_class(r["level"])
        rows.append(
            f'<tr id="L{i}" class="{cls}" data-c="{html_escape(r["provider"])}">'
            f'<td class="msg">{html_escape(r["msg"])}</td>'
            f'<td class="c">{html_escape(r["provider"])}</td>'
            f'<td class="t">{html_escape(r["time"])}</td>'
            f'<td class="th">{html_escape(r["event_id"])}</td>'
            f'<td class="th">{html_escape(r["level_name"])}</td></tr>'
        )
    head = ('<th>Message</th><th class="c">Provider</th>'
            '<th class="t">Time (UTC)</th><th class="th">Event ID</th>'
            '<th class="th">Level</th>')
    comp_sel = ('<select id="comp"><option value="">All providers</option>'
                f'{opts}</select>')
    meta_labels = [["c", "Provider"], ["t", "Time"], ["th", "Event ID"]]
    return _render_records_page(filename, head, rows, comp_sel, note, meta_labels)


def _render_records_page(filename: str, head: str, rows: List[str],
                         comp_sel: str, note: str,
                         meta_labels: List[list]) -> str:
    """Shared sandboxed record-table page (CMTrace + EVTX viewers): filter bar,
    severity legend, colored rows and the click-for-detail panel with error
    code explanations."""
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<title>%(file)s</title><style>%(css)s</style></head><body>
  <div class="bar">
    <input id="q" type="search" placeholder="Filter text…" autocomplete="off">
    %(comp)s
    <select id="sev">
      <option value="">All severities</option>
      <option value="we">Warnings + errors</option>
      <option value="e">Errors</option>
      <option value="w">Warnings</option>
    </select>
    <span class="qjump" id="qjump">
      <button type="button" data-q="Win32App">Win32App</button>
      <button type="button" data-q="detection">Detection</button>
      <button type="button" data-q="PowerShell">Scripts</button>
      <button type="button" data-q="policy">Policy</button>
      <button type="button" data-q="Download">Download</button>
      <button type="button" data-q="reboot">Reboot</button>
    </span>
    <span class="legend"><span><span class="sw w"></span>Warning</span>
      <span><span class="sw e"></span>Error</span></span>
    <span class="count" id="count"></span>
  </div>
  %(note)s
  <table><thead><tr>%(head)s</tr></thead><tbody id="body">
  %(rows)s
  </tbody></table>
  <div id="detail" hidden>
    <div id="d-resize"></div>
    <div class="d-bar"><span id="d-sev" class="sev"></span>
      <div class="d-actions">
        <button id="d-copy" title="Copy to clipboard">&#x2398;</button>
        <button id="d-close" title="Close (Esc)">&times;</button>
      </div></div>
    <pre id="d-msg"></pre>
    <div id="d-meta" class="d-meta"></div>
    <div id="d-explain"></div>
  </div>
<script>
  const q = document.getElementById('q');
  const comp = document.getElementById('comp');
  const sev = document.getElementById('sev');
  const count = document.getElementById('count');
  const rows = [...document.querySelectorAll('#body tr')];
  function sevOk(tr, s) {
    if (!s) return true;
    const e = tr.classList.contains('err'), w = tr.classList.contains('warn');
    return (s === 'e' && e) || (s === 'w' && w) || (s === 'we' && (e || w));
  }
  function apply() {
    const needle = q.value.toLowerCase();
    const c = comp ? comp.value : '';
    const s = sev.value;
    let shown = 0;
    for (const tr of rows) {
      const ok = (!c || tr.dataset.c === c) &&
                 sevOk(tr, s) &&
                 (!needle || tr.textContent.toLowerCase().includes(needle));
      tr.classList.toggle('hide', !ok);
      if (ok) shown++;
    }
    count.textContent = shown + ' / ' + rows.length + ' lines';
  }
  q.addEventListener('input', apply);
  if (comp) comp.addEventListener('change', apply);
  sev.addEventListener('change', apply);
  // IME quick-jumps: toggle a preset into the text filter (click again clears).
  document.getElementById('qjump').addEventListener('click', function (ev) {
    const b = ev.target.closest('button[data-q]');
    if (!b) return;
    const v = b.dataset.q;
    const on = q.value.toLowerCase() === v.toLowerCase();
    q.value = on ? '' : v;
    [...this.children].forEach(c => c.classList.toggle('on', !on && c === b));
    apply();
  });
  apply();

  // Detail panel: click a row to read the full message, with plain-language
  // explanations for known error codes (hex, signed decimal, or MSI exit).
  const CODES = %(codes)s;
  const META = %(meta)s;
  const detail = document.getElementById('detail');
  const dMsg = document.getElementById('d-msg');
  const dMeta = document.getElementById('d-meta');
  const dSev = document.getElementById('d-sev');
  const dExplain = document.getElementById('d-explain');
  function findCodes(text) {
    const found = new Map();
    for (const m of text.matchAll(/0x[0-9A-Fa-f]{8}/g)) {
      const k = '0x' + m[0].slice(2).toUpperCase();
      if (CODES[k]) found.set(k, CODES[k]);
    }
    // IME often logs HRESULTs as signed decimals (-2016345060 = 0x87D1041C).
    for (const m of text.matchAll(/-2\\d{9}/g)) {
      const k = '0x' + (Number(m[0]) >>> 0).toString(16).toUpperCase();
      if (CODES[k]) found.set(k + ' (' + m[0] + ')', CODES[k]);
    }
    for (const m of text.matchAll(/\\b(?:exit|error)\\s*code[:\\s]+(\\d{3,4})\\b/gi)) {
      if (CODES[m[1]]) found.set(m[1], CODES[m[1]]);
    }
    return found;
  }
  function showDetail(tr) {
    rows.forEach(r => r.classList.toggle('sel', r === tr));
    const msg = tr.querySelector('td.msg').textContent;
    dMsg.textContent = msg;
    const isErr = tr.classList.contains('err'), isWarn = tr.classList.contains('warn');
    dSev.textContent = isErr ? 'Error' : isWarn ? 'Warning' : 'Info';
    dSev.className = 'sev ' + (isErr ? 'e' : isWarn ? 'w' : 'i');
    const meta = [];
    for (const [cls, label] of META) {
      const td = tr.querySelector('td.' + cls);
      if (td && td.textContent) meta.push(label + ': ' + td.textContent);
    }
    const ln = tr.querySelector('td.ln');
    if (ln) meta.push('Line ' + ln.textContent);
    dMeta.textContent = meta.join('  \\u00b7  ');
    dExplain.innerHTML = '';
    for (const [code, expl] of findCodes(msg)) {
      const div = document.createElement('div');
      div.className = 'code';
      const b = document.createElement('strong');
      b.textContent = code;
      div.appendChild(b);
      div.appendChild(document.createTextNode(' \\u2014 ' + expl));
      dExplain.appendChild(div);
    }
    detail.hidden = false;
  }
  function closeDetail() {
    detail.hidden = true;
    rows.forEach(r => r.classList.remove('sel'));
  }
  document.getElementById('body').addEventListener('click', ev => {
    const tr = ev.target.closest('tr');
    if (tr) showDetail(tr);
  });
  document.getElementById('d-close').addEventListener('click', closeDetail);
  document.getElementById('d-copy').addEventListener('click', function(){
    var parts = [dSev.textContent];
    if (dMeta.textContent) parts.push(dMeta.textContent);
    parts.push(dMsg.textContent);
    for (var el of dExplain.querySelectorAll('.code'))
      parts.push(el.textContent.trim());
    navigator.clipboard.writeText(parts.join('\\n')).then(function(){
      var btn = document.getElementById('d-copy');
      btn.classList.add('copied');
      setTimeout(function(){ btn.classList.remove('copied'); }, 1500);
    });
  });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeDetail(); });
  // Resize handle: drag top edge of detail panel
  (function(){
    var handle = document.getElementById('d-resize');
    var startY, startH;
    function onMove(ev){
      var y = ev.touches ? ev.touches[0].clientY : ev.clientY;
      var h = Math.max(80, Math.min(window.innerHeight - 50, startH + startY - y));
      detail.style.height = h + 'px';
      detail.style.maxHeight = 'none';
    }
    function onUp(){
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.removeEventListener('touchmove', onMove);
      document.removeEventListener('touchend', onUp);
      handle.classList.remove('active');
      try { localStorage.setItem('sherlog.detail-h', detail.style.height); } catch(e){}
    }
    handle.addEventListener('mousedown', function(ev){
      ev.preventDefault();
      startY = ev.clientY;
      startH = detail.getBoundingClientRect().height;
      handle.classList.add('active');
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
    handle.addEventListener('touchstart', function(ev){
      ev.preventDefault();
      startY = ev.touches[0].clientY;
      startH = detail.getBoundingClientRect().height;
      document.addEventListener('touchmove', onMove, {passive:false});
      document.addEventListener('touchend', onUp);
    }, {passive:false});
    try {
      var h = localStorage.getItem('sherlog.detail-h');
      if (h){ detail.style.height = h; detail.style.maxHeight = 'none'; }
    } catch(e){}
  })();
</script>
</body></html>""" % {
        "file": html_escape(filename), "css": _CMTRACE_CSS, "comp": comp_sel,
        "head": head, "note": note, "rows": "\n".join(rows),
        "codes": json.dumps(ERROR_CODES), "meta": json.dumps(meta_labels),
    }


# --- Routes ------------------------------------------------------------------

# Inline line icons for the homepage tool tiles (stroke = currentColor).
_SVG = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">')
_ICONS = {
    "timeline": _SVG + '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    "cmtrace": _SVG + '<line x1="8" y1="6" x2="20" y2="6"/><line x1="8" y1="12" '
               'x2="20" y2="12"/><line x1="8" y1="18" x2="20" y2="18"/>'
               '<line x1="3.5" y1="6" x2="4" y2="6"/><line x1="3.5" y1="12" x2="4" y2="12"/>'
               '<line x1="3.5" y1="18" x2="4" y2="18"/></svg>',
    "diag": _SVG + '<path d="M3 12h4l2 6 4-15 2 9h6"/></svg>',
    "codes": _SVG + '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" '
             'x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/>'
             '<line x1="16" y1="3" x2="14" y2="21"/></svg>',
    "inbox": _SVG + '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>'
             '<path d="M5.5 5h13l3.5 7v6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-6z"/></svg>',
}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    dropoff_tile = ("""<a class="tile" href="/inbox">
          <span class="ic">%s</span>
          <span class="tx"><h3>Inbox</h3>
            <p>Device drop-off: Intune-deployed collectors upload diagnostics
              straight to your token-scoped inbox.</p></span>
        </a>""" % _ICONS["inbox"]) if ENABLE_UPLOAD_API else ""
    return HTMLResponse(LANDING_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "recent": HISTORY_SECTION,
        "retention": JOB_RETENTION_HOURS, "max": MAX_UPLOAD_MB,
        "accept": ".log,.zip", "patternjson": json.dumps(r"\.(log|zip)$"),
        "ic_timeline": _ICONS["timeline"], "ic_cmtrace": _ICONS["cmtrace"],
        "ic_diag": _ICONS["diag"], "ic_codes": _ICONS["codes"],
        "dropoff_tile": dropoff_tile,
    })


_DEFAULT_DROPTEXT = ("<strong>Drag &amp; drop</strong> a <code>.zip</code>, "
                     "one or more <code>.log</code> files, <em>or a whole "
                     "folder</em> here, or")


def render_upload_page(*, title: str, heading: str, intro: str,
                       action: str, button: str,
                       accept: str = ".log,.zip",
                       pattern: str = r"\.(log|zip)$",
                       badges: str = '<span class="badge">.log</span>'
                                     '<span class="badge">.zip</span>',
                       droptext: str = _DEFAULT_DROPTEXT,
                       extra: str = "") -> HTMLResponse:
    return HTMLResponse(UPLOAD_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "max": MAX_UPLOAD_MB,
        "title": title, "heading": heading, "intro": intro,
        "action": action, "button": button, "recent": HISTORY_SECTION,
        "accept": accept, "patternjson": json.dumps(pattern),
        "badges": badges, "droptext": droptext, "extra": extra,
    })


@app.get("/timeline", response_class=HTMLResponse)
async def timeline_upload_page() -> HTMLResponse:
    return render_upload_page(
        title="Timeline Analyzer",
        heading="Build a logging timeline",
        intro=("Upload your IME logs and get an interactive "
               "<strong>timeline</strong> report &mdash; right in your browser."),
        action="/analyze",
        button="Build timeline",
    )


@app.get("/cmtrace", response_class=HTMLResponse)
async def cmtrace_upload_page() -> HTMLResponse:
    return render_upload_page(
        title="CMTrace Viewer",
        heading="Browse raw logs in CMTrace style",
        intro=("Upload <code>.log</code> files and read them in a colored, "
               "filterable <strong>CMTrace</strong> table &mdash; no analysis run."),
        action="/cmtrace-view",
        button="Open viewer",
    )


# The collector script users run (elevated) on the device to produce the
# package this tool analyzes; shipped in the repo root so it can be shown
# and downloaded from the upload page.
COLLECT_SCRIPT = APP_DIR / "Collect-IntuneDiagnostics.ps1"

# Canonical remediation script, also shipped as Remediate-CollectToSherlog.ps1.
# Kept inline so
# the inbox can always show it, even if the file isn't in the running image.
REMEDIATION_TEMPLATE = r"""<#
.SYNOPSIS
    Intune remediation script: collect a slim Intune diagnostics package and
    upload it to a Sherlog drop-off inbox.

.DESCRIPTION
    Deploy this single script as a Remediation (Devices > Scripts and
    remediations) and trigger it on-demand ("Run remediation") per device, or
    assign it to a group. It downloads Collect-IntuneDiagnostics.ps1 from your
    Sherlog server and runs it with the slim -Remote profile, uploading the zip
    with your token. Review the uploads at <SherlogBase>/inbox?token=<token>.

    Runs as SYSTEM. Output is kept short to fit the 2048-char remediation cap.

.NOTES
    Edit the two settings below. Generate the token on the Sherlog /inbox page.
    Run in 64-bit PowerShell. Trigger it on-demand with "Run remediation".
#>

# ---- settings -------------------------------------------------------------
$SherlogBase = 'https://sherlog.nl'          # your Sherlog base URL
$UploadToken = '<PASTE-YOUR-TOKEN-HERE>'     # from <SherlogBase>/inbox
# ---------------------------------------------------------------------------

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

$collector = Join-Path $env:TEMP 'Collect-IntuneDiagnostics.ps1'
try {
    Invoke-WebRequest -Uri "$SherlogBase/collect-script" -OutFile $collector -UseBasicParsing
} catch {
    Write-Output "Sherlog: collector download failed: $($_.Exception.Message)"
    exit 1
}

try {
    & $collector -Remote -OutputPath $env:TEMP `
        -UploadUrl "$SherlogBase/api/diagnostics" -UploadToken $UploadToken |
        Where-Object { $_ -match 'Review at:|Upload failed' } |
        Select-Object -Last 1 |
        ForEach-Object { Write-Output "Sherlog: $_" }
} catch {
    Write-Output "Sherlog: collection failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item $collector -Force -ErrorAction SilentlyContinue
}

exit 0
"""


def render_collect_script_panel() -> str:
    try:
        text = COLLECT_SCRIPT.read_text(encoding="utf-8", errors="replace")
    except OSError:  # missing or unreadable: hide the panel, don't break upload
        return ""
    return f"""<section class="card recent">
  <h2>Don't have a package yet?</h2>
  <p class="limits">Run <code>Collect-IntuneDiagnostics.ps1</code> in an
    <strong>elevated</strong> PowerShell on the device. It collects MDM logs,
    event logs, registry exports, identity/network info and the IME logs, and
    writes <code>IntuneDiag-&lt;device&gt;-&lt;timestamp&gt;.zip</code> to
    <code>C:\\Temp</code>. Upload that zip above.</p>
  <p><a class="btn btn-ghost" href="/collect-script" download>
    Download Collect-IntuneDiagnostics.ps1</a></p>
  <details><summary>View script source</summary>
    <pre style="max-height:24rem">{html_escape(text)}</pre></details>
</section>{_render_dropoff_panel()}"""


def _render_dropoff_panel() -> str:
    """Pointer to the Intune device drop-off flow, only when it's enabled."""
    if not ENABLE_UPLOAD_API:
        return ""
    return """<section class="card recent">
  <h2>Collect straight from Intune</h2>
  <p class="limits">Deploy the collector as an Intune remediation and have devices
    upload here automatically. Generate a token in the
    <a href="/inbox">inbox</a>, then review each device's upload there &mdash; no
    manual zipping.</p>
  <p><a class="btn btn-ghost" href="/inbox">Open inbox</a></p>
</section>"""


@app.get("/diagnostics", response_class=HTMLResponse)
async def diagnostics_upload_page() -> HTMLResponse:
    return render_upload_page(
        title="Diagnostics Package",
        heading="Troubleshoot a diagnostics package",
        intro=("Upload the <code>IntuneDiag-*.zip</code> produced by "
               "<code>Collect-IntuneDiagnostics.ps1</code> and get device "
               "health checks, an automatic Win32App <strong>timeline</strong> "
               "and a browser for every file in the package."),
        action="/diagnostics-analyze",
        button="Analyze package",
        accept=".zip",
        pattern=r"\.zip$",
        badges='<span class="badge">.zip</span>',
        droptext=("<strong>Drag &amp; drop</strong> the "
                  "<code>IntuneDiag-*.zip</code> here, or"),
        extra=render_collect_script_panel(),
    )


ERRORCODES_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}function tell(w){try{w.postMessage({sherlogTheme:cur()?'dark':'light'},'*')}catch(e){}}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}var fs=document.querySelectorAll('iframe');for(var i=0;i<fs.length;i++)tell(fs[i].contentWindow)};window.addEventListener('load',function(e){if(e.target&&e.target.tagName==='IFRAME')tell(e.target.contentWindow)},true);window.addEventListener('message',function(e){var v=e.data&&e.data.sherlogTheme;if(v==='dark'||v==='light')a(v==='dark')})})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; Intune error codes</title><style>%(css)s
  .ec-tools{display:flex;gap:.6rem;align-items:center;margin:0 0 1rem}
  .ec-tools input{flex:1;padding:.55rem .8rem;border:1px solid var(--border);
    border-radius:8px;background:var(--bg);color:var(--fg);font-size:.95rem}
  .ec-count{color:var(--muted);font-size:.85rem;white-space:nowrap}
  table.ec{border-collapse:collapse;width:100%%}
  table.ec th,table.ec td{text-align:left;padding:.5rem .6rem;
    border-bottom:1px solid var(--border);vertical-align:top}
  table.ec td.code{font-family:ui-monospace,Menlo,Consolas,monospace;
    white-space:nowrap;font-weight:600}
  table.ec tr.hide{display:none}
  .ec-empty{color:var(--muted);padding:1rem 0}
</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>Intune &amp; Win32 error codes</h1>
    <p>Searchable reference of the IME / Win32 app, Windows, network, Delivery
       Optimization and MSI exit codes Sherlog recognises.</p>
  </section>
  <main class="wrap">
    <div class="card">
      <div class="ec-tools">
        <input id="q" type="search" autofocus
          placeholder="Filter by code or text &mdash; e.g. 0x87D1041C, detection, proxy">
        <span class="ec-count" id="count"></span>
      </div>
      <table class="ec"><thead><tr><th>Code</th><th>Meaning</th></tr></thead>
        <tbody id="body"></tbody></table>
      <p class="ec-empty" id="empty" hidden>No codes match your filter.</p>
    </div>
  </main>
  %(footer)s
<script>
  const CODES = %(codes)s;
  const body = document.getElementById('body');
  const rows = Object.keys(CODES).sort().map(function (code) {
    const tr = document.createElement('tr');
    const c = document.createElement('td'); c.className = 'code'; c.textContent = code;
    const m = document.createElement('td'); m.textContent = CODES[code];
    tr.appendChild(c); tr.appendChild(m);
    tr.dataset.hay = (code + ' ' + CODES[code]).toLowerCase();
    body.appendChild(tr); return tr;
  });
  const q = document.getElementById('q');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');
  function apply() {
    const t = q.value.trim().toLowerCase();
    let n = 0;
    rows.forEach(function (tr) {
      const show = !t || tr.dataset.hay.indexOf(t) !== -1;
      tr.classList.toggle('hide', !show); if (show) n++;
    });
    count.textContent = n + ' of ' + rows.length;
    empty.hidden = n !== 0;
  }
  q.addEventListener('input', apply);
  if (location.hash.length > 1) { q.value = decodeURIComponent(location.hash.slice(1)); }
  apply();
</script>
</body></html>"""


@app.get("/errorcodes", response_class=HTMLResponse)
async def error_codes_page() -> HTMLResponse:
    """Searchable reference of every error code Sherlog can explain."""
    return HTMLResponse(ERRORCODES_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER,
        "codes": json.dumps(ERROR_CODES),
    })


@app.get("/collect-script")
async def collect_script_download() -> Response:
    """Serve the collector script as a download (it ships with the app)."""
    try:
        data = COLLECT_SCRIPT.read_bytes()
    except OSError:
        return HTMLResponse("Script not available.", status_code=404)
    return Response(
        data,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition":
                 'attachment; filename="Collect-IntuneDiagnostics.ps1"'},
    )


@app.get("/health")
async def health() -> JSONResponse:
    pwsh = shutil.which("pwsh")
    if pwsh:
        return JSONResponse({"status": "ok", "pwsh": pwsh})
    return JSONResponse({"status": "degraded", "pwsh": None}, status_code=503)


def _content_length_error(request: Request) -> Optional[HTMLResponse]:
    """Early server-side size guard: reject before parsing/buffering the body.

    Content-Length can be absent/spoofed, so the save functions still enforce
    the real limit by counting bytes as they stream; this just fails fast.
    """
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_UPLOAD_BYTES:
                return HTMLResponse(
                    f"Upload exceeds {MAX_UPLOAD_MB} MB limit.", status_code=413
                )
        except ValueError:
            return HTMLResponse("Invalid Content-Length.", status_code=400)
    return None


async def stage_upload(request: Request):
    """Validate + stage an upload into a fresh job dir.

    Returns (job_id, input_dir, output_dir, upload_names) on success, or an
    HTMLResponse error to return to the client. Shared by /analyze (timeline)
    and /cmtrace-view. `upload_names` are the original (client-side) file
    names, kept for the browser-side history list.
    """
    err = _content_length_error(request)
    if err is not None:
        return err

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

    names = [Path(f.filename or "").name for f in files if f.filename]
    return job_id, input_dir, output_dir, names


@app.post("/analyze")
async def analyze(request: Request) -> Response:
    staged = await stage_upload(request)
    if isinstance(staged, Response):
        return staged
    job_id, input_dir, output_dir, names = staged

    # Stored before the job task starts; run_job merges its state into this.
    write_status(job_id, state="queued", uploads=names[:5])
    spawn_job(run_job(job_id, input_dir, output_dir))
    return RedirectResponse(url=f"/result/{job_id}", status_code=303)


# The anonymised sample logs the repo tests against double as the homepage
# demo data set.
TESTDATA_DIR = APP_DIR / "testdata"


@app.post("/demo")
async def demo() -> Response:
    """Run the timeline analysis on the bundled sample logs.

    Reuses an existing pending/finished demo job when one is still within
    retention, so repeated clicks don't queue duplicate analyses; the cleanup
    task removes it like any job, after which a click simply rebuilds it.
    """
    if JOBS_DIR.is_dir():
        for child in sorted(JOBS_DIR.iterdir()):
            status = read_status(child.name)
            if (status and status.get("demo")
                    and status.get("state") in ("queued", "running", "done")):
                return RedirectResponse(url=f"/result/{child.name}",
                                        status_code=303)

    samples = sorted(TESTDATA_DIR.glob("*.log")) if TESTDATA_DIR.is_dir() else []
    if not samples:
        return HTMLResponse("Sample logs are not available on this server.",
                            status_code=503)

    job_id = uuid.uuid4().hex
    base = job_dir(job_id)
    input_dir = base / "input"
    output_dir = base / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    for p in samples:
        shutil.copy(p, input_dir / p.name)

    write_status(job_id, state="queued", demo=True,
                 uploads=[f"{p.name} (sample)" for p in samples[:5]])
    spawn_job(run_job(job_id, input_dir, output_dir))
    return RedirectResponse(url=f"/result/{job_id}", status_code=303)


@app.post("/cmtrace-view")
async def cmtrace_view_upload(request: Request) -> Response:
    """Stage logs for the raw CMTrace viewer only — no timeline analysis runs."""
    staged = await stage_upload(request)
    if isinstance(staged, Response):
        return staged
    job_id, _input_dir, _output_dir, names = staged

    # No subprocess; mark the job as logs-only so the cmtrace routes serve it.
    write_status(job_id, state="logs", uploads=names[:5])
    return RedirectResponse(url=f"/result/{job_id}/cmtrace", status_code=303)


# Cap the skipped-members list persisted in job.json (a hostile zip could
# contain millions of entries).
_MAX_SKIPPED_LISTED = 200


@app.post("/diagnostics-analyze")
async def diagnostics_analyze(request: Request) -> Response:
    """Stage a diagnostics package: extract, build the dashboard, kick off the
    timeline analysis on the IME logs inside (when present)."""
    err = _content_length_error(request)
    if err is not None:
        return err

    form = await request.form()
    files = [v for v in form.getlist("files")
             if isinstance(v, UploadFile) and v.filename]
    if not files:
        return HTMLResponse("No files uploaded.", status_code=400)

    job_id = uuid.uuid4().hex
    base = job_dir(job_id)
    input_dir = base / "input"
    output_dir = base / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        _count, skipped = await save_diag_upload(files, input_dir)
    except UploadError as e:
        shutil.rmtree(base, ignore_errors=True)
        return HTMLResponse(html_escape(e.message), status_code=e.status_code)
    finally:
        shutil.rmtree(base / "tmp", ignore_errors=True)

    dashboard = build_dashboard(input_dir)
    (output_dir / "dashboard.json").write_text(json.dumps(dashboard),
                                               encoding="utf-8")

    ime_dir = find_ime_log_dir(input_dir)
    write_status(job_id, kind="diag", state="ready",
                 uploads=[Path(files[0].filename or "").name],
                 skipped=skipped[:_MAX_SKIPPED_LISTED],
                 analysis={"state": "queued" if ime_dir else "none"})
    if ime_dir is not None:
        spawn_job(run_job(job_id, ime_dir, output_dir,
                            _diag_state_writer(job_id)))
    return RedirectResponse(url=f"/result/{job_id}", status_code=303)


def _count_api_jobs() -> int:
    """How many drop-off (source=api) jobs currently exist on disk."""
    n = 0
    for child in iter_job_dirs():
        st = read_status(child.name)
        if st and st.get("source") == "api":
            n += 1
    return n


@app.post("/api/diagnostics")
async def api_diagnostics(request: Request) -> Response:
    """Unattended drop-off: a device collector POSTs a diagnostics zip as the raw
    request body with a self-chosen secret in X-Upload-Token. The package is
    staged like a normal diagnostics job and tagged with the token hash so the
    matching /inbox can list it. Off unless ENABLE_UPLOAD_API is set."""
    if not ENABLE_UPLOAD_API:
        return JSONResponse({"error": "upload api disabled"}, status_code=404)

    token = (request.headers.get("X-Upload-Token")
             or request.headers.get("Authorization", "").removeprefix("Bearer ").strip())
    if not token or len(token) < UPLOAD_TOKEN_MIN_LEN:
        return JSONResponse(
            {"error": f"missing or too-short token (min {UPLOAD_TOKEN_MIN_LEN})"},
            status_code=401)

    err = _content_length_error(request)
    if err is not None:
        return JSONResponse({"error": "upload too large"}, status_code=413)
    if _count_api_jobs() >= UPLOAD_API_MAX_JOBS:
        return JSONResponse({"error": "server inbox full, try later"},
                            status_code=429)

    device = (request.headers.get("X-Device-Name") or "device").strip()[:128]
    job_id = uuid.uuid4().hex
    base = job_dir(job_id)
    input_dir = base / "input"
    output_dir = base / "output"
    tmp_dir = base / "tmp"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    dest = tmp_dir / f"{uuid.uuid4().hex}.zip"

    try:
        total = 0
        with dest.open("wb") as fh:
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise UploadError(413, f"Upload exceeds {MAX_UPLOAD_MB} MB limit.")
                fh.write(chunk)
        if total == 0:
            raise UploadError(400, "Empty request body.")
        _count, skipped = await _extract_diag_zip(dest, input_dir)
    except UploadError as e:
        shutil.rmtree(base, ignore_errors=True)
        return JSONResponse({"error": e.message}, status_code=e.status_code)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    dashboard = build_dashboard(input_dir)
    (output_dir / "dashboard.json").write_text(json.dumps(dashboard),
                                               encoding="utf-8")

    ime_dir = find_ime_log_dir(input_dir)
    write_status(job_id, kind="diag", state="ready",
                 source="api", upload_token_hash=token_hash(token), device=device,
                 uploads=[f"{device}.zip"],
                 skipped=skipped[:_MAX_SKIPPED_LISTED],
                 analysis={"state": "queued" if ime_dir else "none"})
    if ime_dir is not None:
        spawn_job(run_job(job_id, ime_dir, output_dir,
                            _diag_state_writer(job_id)))
    return JSONResponse({"job_id": job_id, "url": f"/result/{job_id}"})


def list_inbox_jobs(token: str) -> List[dict]:
    """Drop-off jobs whose stored token hash matches `token`, newest first."""
    want = token_hash(token)
    rows = []
    for child in iter_job_dirs():
        st = read_status(child.name)
        if not st or st.get("source") != "api":
            continue
        if not secrets.compare_digest(str(st.get("upload_token_hash", "")), want):
            continue
        try:
            mtime = (child / "job.json").stat().st_mtime
        except OSError:
            mtime = 0
        analysis = (st.get("analysis") or {}).get("state", "none")
        rows.append({"job_id": child.name, "device": st.get("device", "device"),
                     "mtime": mtime, "state": st.get("state", "?"),
                     "analysis": analysis})
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows[:200]


INBOX_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<script>(function(){var de=document.documentElement;function a(d){de.classList.toggle('dark',d);de.style.colorScheme=d?'dark':'light'}function cur(){return de.classList.contains('dark')}var t=null;try{t=localStorage.getItem('sherlog.theme')}catch(e){}a(t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches));window.sherlogTheme=function(){a(!cur());try{localStorage.setItem('sherlog.theme',cur()?'dark':'light')}catch(e){}}})()</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; Inbox</title><style>%(css)s
  table.inbox{border-collapse:collapse;width:100%%;margin-top:1rem}
  table.inbox th,table.inbox td{text-align:left;padding:.5rem .6rem;
    border-bottom:1px solid var(--border);vertical-align:top}
  table.inbox th{color:var(--muted);font-weight:600}
  .tokrow{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.5rem 0}
  .tokrow input{flex:1;min-width:16rem;padding:.55rem .8rem;border:1px solid var(--border);
    border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
  .muted{color:var(--muted);font-size:.9rem}
  .tokval{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;
    background:var(--surface);border:1px solid var(--border);border-radius:6px;
    padding:.4rem .6rem;display:inline-block}
  pre.scriptbox{max-height:26rem;overflow:auto;white-space:pre;background:var(--surface);
    border:1px solid var(--border);border-radius:8px;padding:.75rem;font-size:.82rem}
  ol.guide{line-height:1.65;padding-left:1.2rem}
  ol.guide code{background:var(--surface);padding:.05rem .3rem;border-radius:4px}
</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>Device drop-off inbox</h1>
    <p>Packages an Intune-deployed collector uploaded with your token.</p>
  </section>
  <main class="wrap">
    <div class="card">%(body)s</div>
  </main>
  %(footer)s
</body></html>"""


# No-token inbox view: token field + generator. Generating (or typing) a token
# reveals the ready-to-paste Intune remediation script with the token already
# filled in, plus a short Intune deployment guide.
_INBOX_FORM = """
      <p>Enter your upload token to open this device inbox, or generate a new one
         to use in your Intune remediation script.</p>
      <form method="get" action="/inbox" class="tokrow">
        <input name="token" id="tok" type="text" placeholder="upload token"
               autocomplete="off" minlength="%(min)d" required>
        <button class="btn" type="submit">Open inbox</button>
        <button class="btn btn-ghost" type="button" id="gen">Generate token</button>
      </form>
      <p class="muted" id="genout" hidden></p>

      <section id="result" hidden>
        <h2>Your token</h2>
        <p><span class="tokval" id="tokshow"></span></p>
        <p class="muted">Store it safely &mdash; it is shown once and is both your
           upload secret <em>and</em> your inbox key
           (<code>/inbox?token=&lt;token&gt;</code>).</p>

        <h2>Remediation script (token filled in)</h2>
        <div class="tokrow">
          <button class="btn btn-ghost" type="button" id="copy">Copy script</button>
          <button class="btn btn-ghost" type="button" id="dl">Download .ps1</button>
        </div>
        <pre class="scriptbox" id="script"></pre>

        <h2>Deploy in Intune</h2>
        <ol class="guide">
          <li>Copy or download the script above (your token is already in it).</li>
          <li>Intune admin center &rarr; <strong>Devices</strong> &rarr;
              <strong>Scripts and remediations</strong> &rarr; <strong>Create</strong>.</li>
          <li>Paste the script above as the <strong>Remediation script</strong>.</li>
          <li>Settings: <strong>Run script in 64-bit PowerShell</strong> =
              <code>Yes</code>; <strong>Run using logged-on credentials</strong> =
              <code>No</code> (runs as SYSTEM); signature check = <code>No</code>.</li>
          <li>Assign to a device group, <em>or</em> run it targeted: pick a device
              &rarr; <strong>Run remediation</strong>.</li>
          <li>After a few minutes the device upload appears in
              <a id="inboxlink" href="/inbox">this inbox</a> &mdash; refresh it.</li>
        </ol>
      </section>

      <script>
        var SCRIPT_TPL = %(script)s;
        function fillScript(token) {
          var base = window.location.origin;
          var s = SCRIPT_TPL
            .replace(/\\$SherlogBase\\s*=\\s*'[^']*'/, "$SherlogBase = '" + base + "'")
            .replace(/\\$UploadToken\\s*=\\s*'[^']*'/, "$UploadToken = '" + token + "'");
          // Also fill the placeholders in the comment text so the shown script
          // is fully concrete.
          s = s.split('<SherlogBase>').join(base).split('<token>').join(token);
          document.getElementById('script').textContent = s;
          document.getElementById('tokshow').textContent = token;
          document.getElementById('inboxlink').href = '/inbox?token=' + encodeURIComponent(token);
          document.getElementById('result').hidden = !s;
          return s;
        }
        document.getElementById('gen').addEventListener('click', function () {
          var b = new Uint8Array(32); crypto.getRandomValues(b);
          var s = btoa(String.fromCharCode.apply(null, b))
                    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
          document.getElementById('tok').value = s;
          var o = document.getElementById('genout');
          o.hidden = false;
          o.textContent = 'New token generated and filled into the script below.';
          fillScript(s);
          document.getElementById('result').scrollIntoView({behavior: 'smooth', block: 'start'});
        });
        document.getElementById('tok').addEventListener('input', function () {
          var v = this.value.trim();
          if (v.length >= %(min)d) { fillScript(v); }
          else { document.getElementById('result').hidden = true; }
        });
        document.getElementById('copy').addEventListener('click', function () {
          if (navigator.clipboard) {
            navigator.clipboard.writeText(document.getElementById('script').textContent);
            this.textContent = 'Copied!';
            var b = this; setTimeout(function(){ b.textContent = 'Copy script'; }, 1500);
          }
        });
        document.getElementById('dl').addEventListener('click', function () {
          var blob = new Blob([document.getElementById('script').textContent],
                              {type: 'text/plain'});
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'Remediate-CollectToSherlog.ps1';
          a.click();
        });
      </script>"""


@app.get("/inbox", response_class=HTMLResponse)
async def inbox(request: Request, token: str = "") -> HTMLResponse:
    """Token-scoped list of device drop-off uploads. The token is the namespace;
    no token shows a form plus a client-side token generator."""
    if not ENABLE_UPLOAD_API:
        return HTMLResponse("Inbox is not enabled on this server.", status_code=404)
    token = token or request.headers.get("X-Upload-Token", "")
    if not token:
        body = _INBOX_FORM % {"min": UPLOAD_TOKEN_MIN_LEN,
                              "script": json.dumps(REMEDIATION_TEMPLATE)}
        return HTMLResponse(INBOX_PAGE % {
            "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "body": body})

    rows = list_inbox_jobs(token)
    if rows:
        trs = "".join(
            f'<tr><td>{html_escape(r["device"])}</td>'
            f'<td>{time.strftime("%Y-%m-%d %H:%M", time.localtime(r["mtime"]))}</td>'
            f'<td>{html_escape(r["state"])}'
            + (f' · analysis {html_escape(r["analysis"])}'
               if r["analysis"] not in ("none", "") else "")
            + f'</td><td><a href="/result/{r["job_id"]}">open</a></td></tr>'
            for r in rows)
        body = (f'<p class="muted">{len(rows)} upload(s) for this token.</p>'
                '<table class="inbox"><thead><tr><th>Device</th><th>Uploaded</th>'
                '<th>Status</th><th></th></tr></thead><tbody>'
                f'{trs}</tbody></table>')
    else:
        body = ('<p>No uploads found for this token yet. Deploy the collector '
                'with this token via Intune, then refresh.</p>'
                '<p class="muted"><a href="/inbox">&larr; use another token</a></p>')
    return HTMLResponse(INBOX_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "body": body})


@app.get("/result/{job_id}", response_class=HTMLResponse)
async def result(job_id: str) -> Response:
    # Reject anything that isn't a clean job id (no path traversal).
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)

    status = read_status(job_id)
    if status is None:
        return HTMLResponse("Unknown job.", status_code=404)

    if status.get("kind") == "diag":
        return render_diag_page(job_id, status)

    state = status.get("state")
    if state == "logs":  # CMTrace-only job, no timeline report exists
        return RedirectResponse(url=f"/result/{job_id}/cmtrace", status_code=303)
    if state in ("running", "queued"):
        return HTMLResponse(BUSY_PAGE % {
            "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "job": job_id,
            "history": history_record_js(job_id, "timeline", "busy",
                                         upload_names(status, job_id)),
        })

    if state == "done":
        # Wrap the (untrusted) report in a sandboxed iframe — see /report below.
        return HTMLResponse(REPORT_PAGE % {
            "css": PAGE_CSS, "logo": _LOGO, "job": job_id,
            "summary": render_summary_panel(read_summary(job_id)),
            "history": history_record_js(job_id, "timeline", "done",
                                         upload_names(status, job_id)),
        })

    # failed
    return HTMLResponse(
        ERROR_PAGE % {
            "css": PAGE_CSS, "nav": NAV, "footer": FOOTER,
            "exit": html_escape(str(status.get("exitcode"))),
            "stderr": html_escape(status.get("stderr", "")) or "(empty)",
            "stdout": html_escape(status.get("stdout", "")) or "(empty)",
            "history": history_record_js(job_id, "timeline", "failed",
                                         upload_names(status, job_id)),
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
    if status is None:
        return HTMLResponse("Report not available.", status_code=404)
    # Diagnostics jobs keep the analysis outcome in a sub-dict.
    rec = status.get("analysis") or {} if status.get("kind") == "diag" else status
    if rec.get("state") != "done":
        return HTMLResponse("Report not available.", status_code=404)

    report = job_dir(job_id) / "output" / rec.get("report", "")
    if not report.is_file():
        return HTMLResponse("Report missing.", status_code=500)

    return HTMLResponse(
        strip_branding(report.read_text(encoding="utf-8", errors="replace")),
        headers={"Content-Security-Policy": "sandbox allow-scripts allow-popups"},
    )


def _attr(s: str) -> str:  # safe inside a double-quoted HTML attribute
    return html_escape(s).replace('"', "&quot;")


def render_file_tree(paths: List[str], skipped: List[str] = ()) -> str:
    """Nested <details> folder tree from sorted relative file paths.

    Folders come from the uploaded structure (a diagnostics zip); flat uploads
    just yield files at the root. File order within a folder keeps the incoming
    (CMTrace-first) sort. `skipped` paths (members not extracted, e.g. .cab)
    are rendered as disabled, non-clickable entries so the user knows they
    exist in the original package.
    """
    tree: dict = {}

    def insert(p: str, disabled: bool) -> None:
        *dirs, leaf = p.split("/")
        node = tree
        for d in dirs:
            node = node.setdefault(d, {})
        node.setdefault("__files__", []).append((leaf, p, disabled))

    for p in paths:
        insert(p, False)
    for p in skipped:
        insert(p, True)

    def render(node: dict) -> str:
        out = []
        for name in sorted(k for k in node if k != "__files__"):
            out.append(
                f"<details open><summary>{html_escape(name)}</summary>"
                f'<div class="grp">{render(node[name])}</div></details>'
            )
        for leaf, full, disabled in node.get("__files__", []):
            if disabled:
                out.append(
                    f'<div class="file disabled" '
                    f'title="{_attr(full)} (not extracted)">{html_escape(leaf)}</div>'
                )
            else:
                out.append(
                    f'<div class="file" data-file="{_attr(full)}" '
                    f'title="{_attr(full)}">{html_escape(leaf)}</div>'
                )
        return "".join(out)

    return render(tree)


def render_log_tree(paths: List[str]) -> str:
    return render_file_tree(paths)


@app.get("/result/{job_id}/cmtrace", response_class=HTMLResponse)
async def cmtrace(job_id: str) -> Response:
    """App-chrome page: a folder tree of raw logs + a sandboxed viewer iframe."""
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)
    status = read_status(job_id)
    if status is None or status.get("state") not in ("done", "logs", "ready"):
        return HTMLResponse("Logs not available.", status_code=404)

    logs = list_input_logs(job_id)
    if not logs:
        return HTMLResponse("No raw logs found for this job.", status_code=404)

    # Link back to whichever overview this job has.
    if status.get("kind") == "diag":
        timeline = (f'<a class="btn btn-ghost" href="/result/{job_id}">'
                    f'&larr; Diagnostics</a>')
    elif status.get("state") == "done":  # finished timeline job has a report
        timeline = f'<a class="btn btn-ghost" href="/result/{job_id}">&larr; Timeline</a>'
    else:
        timeline = ""

    # A logs-only job is its own history entry; a finished timeline or
    # diagnostics job viewed here keeps its existing entry (same id, update).
    job_state = status.get("state", "logs")
    if status.get("kind") == "diag":
        tool, job_state = "diag", "done"
    else:
        tool = "logs" if job_state == "logs" else "timeline"
    return HTMLResponse(CMTRACE_PAGE % {
        "css": PAGE_CSS, "logo": _LOGO, "job": job_id, "timeline": timeline,
        "tree": render_log_tree(logs), "first": quote(logs[0]),
        "firstjson": json.dumps(logs[0]), "jobjson": json.dumps(job_id),
        "history": history_record_js(job_id, tool, job_state,
                                     upload_names(status, job_id)),
    })


@app.get("/result/{job_id}/cmtrace/view", response_class=HTMLResponse)
async def cmtrace_view(job_id: str, file: str) -> Response:
    """Sandboxed CMTrace table for one raw log. Untrusted content, so it is
    served with a CSP `sandbox` directive and only framed by the page above."""
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)
    status = read_status(job_id)
    if status is None or status.get("state") not in ("done", "logs", "ready"):
        return HTMLResponse("Logs not available.", status_code=404)

    # Membership check: `file` must be exactly one of the staged logs — this
    # rejects any path-traversal attempt without touching the filesystem.
    if file not in list_input_logs(job_id):
        return HTMLResponse("Unknown log file.", status_code=404)

    text = read_text_tolerant(job_dir(job_id) / "input" / file)
    records, truncated = parse_cmtrace(text)
    return HTMLResponse(
        render_cmtrace_view(file, records, truncated),
        headers={"Content-Security-Policy": "sandbox allow-scripts"},
    )


# --- Diagnostics package routes ------------------------------------------------

def render_diag_page(job_id: str, status: dict) -> HTMLResponse:
    """Diagnostics overview: dashboard, analysis card, summary, file browser."""
    analysis = status.get("analysis") or {}
    files = list_input_files(job_id, exts=DIAG_KEEP_EXTS)
    skipped = [s.get("name", "") for s in status.get("skipped", [])
               if isinstance(s, dict) and s.get("name")]
    first = files[0] if files else ""
    firstsrc = (f"/result/{job_id}/files/view?file={quote(first)}"
                if first else "about:blank")
    summary = (render_summary_panel(read_summary(job_id))
               if analysis.get("state") == "done" else "")
    hist_state = ("busy" if analysis.get("state") in ("queued", "running")
                  else "done")
    return HTMLResponse(DIAG_PAGE % {
        "css": PAGE_CSS, "logo": _LOGO, "job": job_id,
        "dashboard": render_dashboard_panel(read_dashboard(job_id)),
        "analysis": render_analysis_card(job_id, analysis),
        "summary": summary,
        "tree": render_file_tree(files, skipped),
        "firstsrc": firstsrc,
        "jobjson": json.dumps(job_id), "firstjson": json.dumps(first),
        "analysisjson": json.dumps(analysis.get("state", "none")),
        # Device drop-off jobs belong in the token inbox, not in the viewer's
        # personal "Recent uploads" history.
        "history": ("" if status.get("source") == "api"
                    else history_record_js(job_id, "diag", hist_state,
                                           upload_names(status, job_id))),
    })


@app.get("/result/{job_id}/status")
async def job_status(job_id: str) -> JSONResponse:
    """Small sanitized status poll for the diagnostics result page."""
    if not job_id.isalnum():
        return JSONResponse({"error": "invalid job id"}, status_code=400)
    status = read_status(job_id)
    if status is None:
        return JSONResponse({"error": "unknown job"}, status_code=404)
    return JSONResponse({
        "state": status.get("state"),
        "analysis": (status.get("analysis") or {}).get("state"),
    })


@app.get("/result/{job_id}/timeline", response_class=HTMLResponse)
async def diag_timeline(job_id: str) -> Response:
    """Full timeline report page for the analysis inside a diagnostics job."""
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)
    status = read_status(job_id)
    if (status is None or status.get("kind") != "diag"
            or (status.get("analysis") or {}).get("state") != "done"):
        return HTMLResponse("Timeline report not available.", status_code=404)

    return HTMLResponse(REPORT_PAGE % {
        "css": PAGE_CSS, "logo": _LOGO, "job": job_id,
        "summary": render_summary_panel(read_summary(job_id)),
        "history": ("" if status.get("source") == "api"
                    else history_record_js(job_id, "diag", "done",
                                           upload_names(status, job_id))),
    })


_SANDBOX_HEADERS = {"Content-Security-Policy": "sandbox allow-scripts"}


@app.get("/result/{job_id}/files/view", response_class=HTMLResponse)
async def diag_file_view(job_id: str, file: str) -> Response:
    """Sandboxed view of one package file, dispatched on its extension.

    Untrusted content, so every branch is served with a CSP `sandbox`
    directive and only framed by the diagnostics page.
    """
    if not job_id.isalnum():
        return HTMLResponse("Invalid job id.", status_code=400)
    status = read_status(job_id)
    if status is None or status.get("kind") != "diag":
        return HTMLResponse("Files not available.", status_code=404)

    # Membership check, same pattern as the CMTrace viewer: rejects any
    # path-traversal attempt without touching the filesystem.
    if file not in list_input_files(job_id, exts=DIAG_KEEP_EXTS):
        return HTMLResponse("Unknown file.", status_code=404)

    path = job_dir(job_id) / "input" / file
    ext = Path(file).suffix.lower()

    if ext in (".html", ".htm"):
        return HTMLResponse(read_text_tolerant(path), headers=_SANDBOX_HEADERS)

    if ext == ".evtx":
        if Evtx is None:
            return HTMLResponse("EVTX viewing is unavailable: python-evtx "
                                "is not installed.", status_code=501,
                                headers=_SANDBOX_HEADERS)
        try:
            # python-evtx is pure Python and slow on big logs; keep the event
            # loop responsive.
            records, truncated = await asyncio.to_thread(parse_evtx_file, path)
        except Exception:
            log.warning("evtx parse failed for job %s file %s", job_id, file,
                        exc_info=True)
            return HTMLResponse("Could not parse this .evtx file.",
                                status_code=422, headers=_SANDBOX_HEADERS)
        return HTMLResponse(render_evtx_view(file, records, truncated),
                            headers=_SANDBOX_HEADERS)

    # .log gets the CMTrace layout; other text files fall back to the plain
    # line-numbered layout inside the same renderer.
    text = read_text_tolerant(path)
    records, truncated = parse_cmtrace(text)
    return HTMLResponse(render_cmtrace_view(file, records, truncated),
                        headers=_SANDBOX_HEADERS)
