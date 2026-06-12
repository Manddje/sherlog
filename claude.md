# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Sherlog — IME Log Analyzer

Webapp die Microsoft Intune Management Extension (IME) logs analyseert met het
upstream PowerShell-script `Get-IntuneManagementExtensionDiagnostics.ps1`
(Petri Paavola) en het HTML-timelinerapport in de browser toont. Eén container:
FastAPI/uvicorn (poort 8080) + PowerShell Core (`pwsh`) als analyse-engine.
Deployment: Coolify, build via Dockerfile in de repo-root. Productie:
sherlog.nl, publiek zonder login (basic auth optioneel via
`APP_USER`/`APP_PASSWORD`, beide gezet).

## Commands

```bash
# Tests (volledige suite; de echte-analyse-test wordt geskipt zonder pwsh)
.venv/bin/python -m pytest tests/test_e2e.py -q

# Eén test
.venv/bin/python -m pytest tests/test_e2e.py::test_extract_zip_members_nested_and_policy -q

# Lokaal draaien (volledig, incl. pwsh)
docker compose up --build          # → http://localhost:8080

# Alleen de weblaag lokaal (analyse faalt zonder pwsh, rest werkt)
JOBS_DIR=./data/jobs .venv/bin/uvicorn app:app --port 8080

# Analyse-engine direct, zonder weblaag (vereist pwsh)
scripts/run-analysis.sh testdata out
```

Tests draaien tegen `./testdata/` (echte, geanonimiseerde IME-logs).
Definitie van "werkt": het script produceert een HTML-rapport met
Win32App-events uit de testlogs, zonder errors.

## Architectuur

Alles zit in **`app.py`** (~2900 regels, één module, geen templates-map —
HTML is inline). Globale volgorde: config (env vars) → parsers → job-runner →
upload/extractie → auth/middleware → HTML-rendering → routes.

**State = bestandssysteem** (geen DB/Redis): `<JOBS_DIR>/<uuid>/` met
`input/` (geüpload), `output/` (rapport, `summary.json`, `dashboard.json`) en
`job.json` (status). `JOBS_DIR` default `/data/jobs`. Retentie via
achtergrondtaak (`JOB_RETENTION_HOURS`, default 24).

**Drie tools, drie jobkinds** (zelfde job-layout, ander `job.json`):

1. **Timeline** (`/timeline` → `POST /analyze`) — draait
   `scripts/run-analysis.sh` (wrapper die het upstream-script headless
   aanroept) als subprocess met timeout (`SCRIPT_TIMEOUT_SECONDS`) en
   concurrency-cap (`JOB_CONCURRENCY`, semafoor). States:
   queued|running|done|failed. Na afloop wordt `summary.json` uit het rapport
   geparst (samenvattingspaneel).
2. **CMTrace** (`/cmtrace`) — alleen raw logviewer, geen analyse.
3. **Diagnostics package** (`/diagnostics`) — zip van
   `Collect-IntuneDiagnostics.ps1`. Top-level state is direct `ready`; de
   timeline-analyse is een **sub-state** (`analysis`-dict in `job.json`) en
   mag de diag-job nooit laten falen. Dashboard-checks worden geparst uit
   o.a. `dsregcmd-status.txt`, `Apps-IME/service-status.txt`,
   `Network/endpoint-connectivity.txt` en het machinecert-overzicht; parsers
   zijn totaal: ontbrekend bestand → status `unknown`, nooit een error.
   File browser per extensie: `.log` → CMTrace-viewer; `.txt/.reg/.xml/...`
   → tekstviewer met UTF-16-tolerante decodering (PowerShell 5.1 Out-File en
   `reg export` schrijven UTF-16LE); `.html` → sandboxed iframe; `.evtx` →
   eventviewer (python-evtx, cap `EVTX_MAX_EVENTS`); `.cab/.etl` → niet
   uitgepakt, wel disabled in de tree.

**Achtergrondjobs:** start via `spawn_job()` — houdt een sterke referentie
vast (asyncio houdt alleen weak refs; anders kan een job mid-run GC'd worden
en blijft "running" hangen). Bij appstart markeert `fail_interrupted_jobs()`
jobs die door een restart zijn afgebroken als failed, incl. de
diag-`analysis`-substate.

**Zip-extractie** (`extract_zip_members`): zip-slip-guard, gedeeld
zip-bomb-budget over geneste zips (precies één niveau diep, voor de
mdmdiagnosticstool-output), en normalisatie van backslash-entrynamen
(Windows PowerShell 5.1 `Compress-Archive` schrijft `\` als separator —
zonder normalisatie extraheert het pakket plat en missen alle path-lookups).

**Security-model:** alle untrusted content (rapport, loginhoud, html uit
pakketten) wordt in een **sandboxed iframe** geserveerd
(`Content-Security-Policy: sandbox`). Bestandskeuze in viewers via
membership-check tegen de echte bestandslijst (geen path traversal).
Upload-limiet streaming afgedwongen (`MAX_UPLOAD_MB`). `/health` valt altijd
buiten auth en checkt of `pwsh` beschikbaar is.

## Harde kaders

- **GEEN** `-ShowLogViewerUI` (Out-GridView, Windows-only) en **GEEN**
  `-Online` (vereist Graph-credentials) bij het aanroepen van het upstream-script.
- Wijzigingen aan `Get-IntuneManagementExtensionDiagnostics.ps1`: alleen
  Linux/headless-compatibiliteit, minimaal houden, en **elke patch
  documenteren in `PATCHES.md`** (wat, waarom, functienaam) zodat
  upstream-updates gemerged kunnen worden. Analysegedrag en rapportformaat
  nooit veranderen. De headless aanroepvlaggen staan (met motivatie) in
  `scripts/run-analysis.sh`.
- IME-logs zijn vertrouwelijk: geen logbestand-inhoud naar stdout loggen.
- Geen externe services; alle configuratie via env vars met veilige defaults
  (zie de docstring boven in `app.py` en de tabel in `README.md`).

## Conventies

- Python: type hints; dependencies beperkt tot FastAPI, uvicorn,
  python-multipart, python-evtx (en httpx/pytest voor tests).
- Tests in `tests/test_e2e.py` gebruiken een fixture die env vars zet en
  `app` herlaadt (module-level config), met `TestClient`.
- Logging naar stdout. Commit per afgeronde fase met duidelijke message.
