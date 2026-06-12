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

# Diagnostics-package extension policy. Text-ish files get the line viewer,
# .log the CMTrace viewer, .html a sandboxed iframe, .evtx the event viewer.
# .cab/.etl are binary and unparseable on Linux: they are not extracted but
# still listed (disabled) in the file tree so the user knows they exist.
DIAG_TEXT_EXTS = {".txt", ".reg", ".xml", ".json", ".csv"}
DIAG_KEEP_EXTS = {".log", ".html", ".htm", ".evtx"} | DIAG_TEXT_EXTS

# Bounds the number of analysis subprocesses running at once.
_job_sem = asyncio.Semaphore(JOB_CONCURRENCY)


# --- Job state on disk -------------------------------------------------------

def job_dir(job_id: str) -> Path:
    return JOBS_DIR / job_id


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

    return {
        "parse_ok": summary.parse_ok,
        "counts": [{"type": t, **c} for t, c in sorted(counts.items())],
        "warnings": warnings,
        "not_detected": not_detected,
        "failed_items": failed_items[:SUMMARY_MAX_FAILED_ITEMS],
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


# The collector exists in an English and a Dutch variant; accept both names.
_DASH_SOURCES = {
    "summary": ("_SUMMARY.txt", "_SAMENVATTING.txt"),
    "dsregcmd": ("Identity/dsregcmd-status.txt",),
    "endpoints": ("Network/endpoint-connectivity.txt",),
    "ime_service": ("Apps-IME/service-status.txt",),
    "certs": ("Identity/certs-machine-overview.txt",
              "Identity/certs-machine-overzicht.txt"),
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
    """Derive the health-check model from a staged diagnostics package."""
    def read(key: str) -> str:
        p = _find_package_file(input_dir, _DASH_SOURCES[key])
        return read_text_tolerant(p) if p else ""

    identity = parse_dsregcmd(read("dsregcmd"))
    if not identity.get("AzureAdJoined"):
        identity = {**parse_summary_txt(read("summary")), **identity}

    checks = [
        _yesno_check("Entra joined", identity.get("AzureAdJoined", "")),
        _yesno_check("Entra PRT", identity.get("AzureAdPrt", "")),
    ]

    mdm_url = identity.get("MdmUrl", identity.get("MDM URL", ""))
    checks.append({
        "label": "MDM enrollment",
        "status": "ok" if "manage.microsoft.com" in mdm_url
                  else "bad" if mdm_url else "unknown",
        "detail": mdm_url or "MDM URL not found",
    })

    svc = parse_service_status(read("ime_service"))
    checks.append({
        "label": "IME service",
        "status": "ok" if svc else "unknown" if svc is None else "bad",
        "detail": "Running" if svc else "status unknown" if svc is None else "Stopped",
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
        })
    else:
        checks.append({"label": "Machine certificates", "status": "unknown",
                       "detail": "no certificate overview found"})

    device = {
        "name": identity.get("Device", ""),
        "device_id": identity.get("DeviceId", ""),
        "tenant": identity.get("TenantName", ""),
        "collected": identity.get("Date", identity.get("Datum", "")),
    }
    return {"device": device, "checks": checks}


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

    try:
        count, skipped = extract_zip_members(dest, input_dir, DIAG_KEEP_EXTS)
    except zipfile.BadZipFile:
        raise UploadError(400, "The uploaded file is not a valid zip archive.")
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
            headers={"WWW-Authenticate": 'Basic realm="Sherlog"'},
        )


# --- Background cleanup ------------------------------------------------------

def fail_interrupted_jobs() -> int:
    """Mark jobs left queued/running by a previous process as failed.

    Analysis tasks live in this process only; after a restart (deploy,
    crash) any job still queued/running can never finish, and its result
    page would poll forever.
    """
    if not JOBS_DIR.is_dir():
        return 0
    msg = ("The analysis was interrupted by an app restart. "
           "Please upload again.")
    failed = 0
    for child in JOBS_DIR.iterdir():
        if not child.is_dir():
            continue
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
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Sherlog", lifespan=lifespan)
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
  .cards{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:1.25rem; }
  @media (max-width:640px){ .cards{ grid-template-columns:1fr; } }
  .cards .card{ display:flex; flex-direction:column; }
  .card h2{ margin:0 0 .4rem; font-size:1.25rem; }
  .card .desc{ color:var(--muted); margin:0 0 1.25rem; flex:1; overflow-wrap:anywhere; }
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
  </span>
</nav></header>""" % {"logo": _LOGO})

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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; IME log analyzer</title><style>%(css)s</style></head>
<body>
  %(nav)s
  <section class="hero">
    <h1>Analyze Intune Management Extension logs</h1>
    <p>Build a Win32App <strong>timeline</strong> from your IME logs, read raw
       logs in a <strong>CMTrace</strong> table, or troubleshoot a full
       <strong>diagnostics package</strong> &mdash; right in your browser.</p>
  </section>
  <main class="wrap">
    <div class="cards">
      <div class="card">
        <h2>Timeline Analyzer</h2>
        <p class="desc">Upload IME <code>.log</code> files and get an
          interactive timeline report: app installs, scripts and errors in
          chronological order, with a summary of failures and known error
          codes.</p>
        <a class="btn" href="/timeline">Open Timeline</a>
      </div>
      <div class="card">
        <h2>CMTrace Viewer</h2>
        <p class="desc">Read raw <code>.log</code> files in a colored,
          filterable CMTrace-style table: warnings yellow, errors red, with
          text, component and severity filters. No analysis run.</p>
        <a class="btn" href="/cmtrace">Open CMTrace</a>
      </div>
      <div class="card">
        <h2>Diagnostics Package</h2>
        <p class="desc">Upload the zip from
          <code>Collect-IntuneDiagnostics.ps1</code> and get device health
          checks, an automatic timeline analysis and a viewer for every file
          in the package &mdash; including event logs and registry
          exports.</p>
        <a class="btn" href="/diagnostics">Open Diagnostics</a>
      </div>
    </div>
    %(recent)s
  </main>
  %(footer)s
</body></html>"""

UPLOAD_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sherlog &mdash; diagnostics package</title>
<style>%(css)s
  .topbar{display:flex;align-items:center;justify-content:space-between;
    padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:var(--bg)}
  .panels{max-width:1100px;margin:0 auto;padding:.9rem 1.25rem;display:flex;
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
  function select(el) {
    files.forEach(f => f.classList.toggle('active', f === el));
    view.src = '/result/' + job + '/files/view?file=' +
               encodeURIComponent(el.dataset.file);
  }
  side.addEventListener('click', ev => {
    const f = ev.target.closest('.file');
    if (f && f.dataset.file) select(f);
  });
  (files.find(f => f.dataset.file === first) || null)?.classList.add('active');

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


# The upstream script appends an author/branding banner (<footer> with author
# photo, MVP logo and a GitHub download link). We strip it from the served
# report at display time so the PowerShell script stays unpatched and
# upstream-mergeable (see CLAUDE.md: report format in the script is unchanged).
_BRANDING_FOOTER = re.compile(r"<footer\b[^>]*>.*?</footer>", re.IGNORECASE | re.DOTALL)


def strip_branding(html: str) -> str:
    return _BRANDING_FOOTER.sub("", html, count=1)


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
    top_errors = summary.get("top_errors", [])
    downloads = summary.get("downloads", [])
    if not (counts or warnings or not_detected or failed_items or downloads):
        return ""

    total_failed = sum(c.get("failed", 0) for c in counts)
    total_success = sum(c.get("success", 0) for c in counts)

    chips = []
    for c in counts:
        chips.append(
            f'<span class="sum-chip">{html_escape(c["type"])}: '
            f'<span class="ok">{c.get("success", 0)} ok</span> / '
            f'<span class="bad">{c.get("failed", 0)} failed</span></span>'
        )
    if warnings:
        chips.append(f'<span class="sum-chip"><span class="warn">{warnings} '
                     f'warning(s)</span></span>')
    if not_detected:
        chips.append(f'<span class="sum-chip"><span class="bad">{not_detected} '
                     f'not detected</span></span>')

    parts = [f'<div class="sum-chips">{"".join(chips)}</div>']

    if top_errors:
        rows = "".join(
            f'<div class="code"><strong>{html_escape(e["code"])}</strong> '
            f'({e["count"]}&times;) &mdash; {html_escape(e["explanation"])}</div>'
            for e in top_errors
        )
        parts.append(f"<h3>Known error codes</h3>{rows}")

    if failed_items:
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
        cards.append(
            f'<div class="check"><span class="lbl"><span class="st {st}"></span>'
            f'{html_escape(str(c.get("label", "")))}</span>'
            f'<div class="det">{html_escape(str(c.get("detail", "")))}</div></div>'
        )
    if cards:
        parts.append(f'<div class="dash">{"".join(cards)}</div>')
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
_CMTRACE_CSS = """
  *{box-sizing:border-box}
  body{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    margin:0;color:#1f2937;background:#fff}
  .bar{position:sticky;top:0;display:flex;gap:.5rem;align-items:center;
    padding:.5rem .75rem;background:#f9fafb;border-bottom:1px solid #e5e7eb;z-index:2}
  .bar input,.bar select{font:inherit;padding:.3rem .5rem;border:1px solid #d1d5db;
    border-radius:6px}
  .bar input{flex:1;min-width:8rem}
  .count{color:#6b7280;white-space:nowrap}
  .note{padding:.5rem .75rem;color:#92400e;background:#fef3c7;
    border-bottom:1px solid #fde68a}
  table{border-collapse:collapse;width:100%;table-layout:fixed}
  th,td{text-align:left;padding:.25rem .6rem;border-bottom:1px solid #f1f5f9;
    vertical-align:top;word-break:break-word;white-space:pre-wrap}
  th{position:sticky;top:2.6rem;background:#f3f4f6;font-weight:600;z-index:1}
  td.msg{width:auto}
  td.c,td.t,td.th{width:9rem;color:#6b7280;white-space:nowrap}
  td.th{width:4rem}
  td.ln,th.ln{width:4rem;color:#9ca3af;text-align:right;
    font-variant-numeric:tabular-nums;user-select:none}
  tr.warn{background:#fffbeb}
  tr.warn td.msg{color:#92400e}
  tr.err{background:#fef2f2}
  tr.err td.msg{color:#b91c1c;font-weight:600}
  tr.hide{display:none}
  .legend{display:flex;gap:.6rem;align-items:center;color:#6b7280;white-space:nowrap}
  .legend .sw{display:inline-block;width:.8rem;height:.8rem;border-radius:3px;
    margin-right:.25rem;vertical-align:-1px;border:1px solid rgba(0,0,0,.08)}
  .sw.w{background:#fffbeb;border-color:#fde68a}
  .sw.e{background:#fef2f2;border-color:#fecaca}
  #body tr{cursor:pointer}
  tr.sel,tr.sel.warn,tr.sel.err{background:#e0e7ff}
  #detail{position:fixed;bottom:0;left:0;right:0;max-height:45%;overflow:auto;
    background:#fff;border-top:2px solid #d1d5db;
    box-shadow:0 -6px 16px rgba(0,0,0,.1);padding:.6rem 1rem;z-index:3}
  .d-bar{display:flex;justify-content:space-between;align-items:center;gap:.5rem}
  #d-close{font:inherit;border:1px solid #d1d5db;background:#f9fafb;
    border-radius:6px;cursor:pointer;padding:.05rem .55rem}
  #d-close:hover{background:#f3f4f6}
  #d-msg{margin:.45rem 0;white-space:pre-wrap;word-break:break-word}
  .d-meta{color:#6b7280;margin-bottom:.4rem}
  .sev{font-weight:600;padding:.1rem .55rem;border-radius:999px}
  .sev.e{background:#fef2f2;color:#b91c1c}
  .sev.w{background:#fffbeb;color:#92400e}
  .sev.i{background:#eff6ff;color:#1d4ed8}
  #d-explain .code{margin:.35rem 0;padding:.45rem .6rem;background:#eff6ff;
    border-left:3px solid #2563eb;border-radius:0 6px 6px 0}
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
        for r in records:
            cls = _row_class(r["type"]) if r["structured"] else _plain_class(r["msg"])
            when = (r["date"] + " " + r["time"]).strip()
            rows.append(
                f'<tr class="{cls}" data-c="{html_escape(r["component"])}">'
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
                f'<tr class="{cls}" data-c="">'
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
    for r in records:
        cls = _evtx_row_class(r["level"])
        rows.append(
            f'<tr class="{cls}" data-c="{html_escape(r["provider"])}">'
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
    <span class="legend"><span><span class="sw w"></span>Warning</span>
      <span><span class="sw e"></span>Error</span></span>
    <span class="count" id="count"></span>
  </div>
  %(note)s
  <table><thead><tr>%(head)s</tr></thead><tbody id="body">
  %(rows)s
  </tbody></table>
  <div id="detail" hidden>
    <div class="d-bar"><span id="d-sev" class="sev"></span>
      <button id="d-close" title="Close (Esc)">&times;</button></div>
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
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeDetail(); });
</script>
</body></html>""" % {
        "file": html_escape(filename), "css": _CMTRACE_CSS, "comp": comp_sel,
        "head": head, "note": note, "rows": "\n".join(rows),
        "codes": json.dumps(ERROR_CODES), "meta": json.dumps(meta_labels),
    }


# --- Routes ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(LANDING_PAGE % {
        "css": PAGE_CSS, "nav": NAV, "footer": FOOTER, "recent": HISTORY_SECTION,
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
        heading="Build a Win32App timeline",
        intro=("Upload your IME logs and get an interactive Win32App "
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
        "history": history_record_js(job_id, "diag", hist_state,
                                     upload_names(status, job_id)),
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
        "history": history_record_js(job_id, "diag", "done",
                                     upload_names(status, job_id)),
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
