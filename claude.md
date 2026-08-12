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

Alles zit in **`app.py`** (~5400 regels, één module, geen templates-map —
alle HTML is inline `%`-format string templates). Globale volgorde: config
(env vars) → parsers → job-runner → upload/extractie → auth/middleware →
HTML-rendering → routes.

**State = bestandssysteem** (geen DB/Redis): `<JOBS_DIR>/<uuid>/` met
`input/` (geüpload), `output/` (rapport, `summary.json`, `dashboard.json`) en
`job.json` (status). `JOBS_DIR` default `/data/jobs`. Retentie via
achtergrondtaak (`JOB_RETENTION_HOURS`, default 24). Eén niet-job-bestand staat
in de root: `<JOBS_DIR>/upload-count.json` — de cumulatieve upload-teller
(`bump_upload_count`/`read_upload_count`); het is een bestand, niet een dir,
dus `iter_job_dirs` en de retentie-sweep raken het nooit aan en de teller
overleeft job-expiry.

**Homepage** (`GET /`): tegels naar de twee upload-tools (CMTrace,
Diagnostics) plus — alleen met `ENABLE_UPLOAD_API` — een Inbox-tegel, een
client-side *recent*-lijst (browser-`localStorage`, geen serverstate) en een
all-time upload-teller in de hero (verborgen bij 0; opgehoogd in elk van de drie
upload-handlers). Géén demo-knop. `static/` (StaticFiles-mount op `/static`)
serveert de auteursfoto in de footer. `static/` en `testdata/` worden in de
Docker-image gekopieerd (Dockerfile); `testdata/` voedt de testsuite.

**Tools & jobkinds** (zelfde job-layout op schijf, ander `job.json`). De
timeline-analyse is géén losse tool/route meer — ze is de analyse-substap van
een diagnostics-job:

1. **CMTrace** (`/cmtrace` → `POST /cmtrace-view`) — alleen raw logviewer,
   geen analyse; job krijgt `state="logs"`. Op de viewerpagina kan de
   timeline-analyse alsnog on-demand gestart worden
   (`POST /result/{id}/analyze` → job wordt een gewone timeline-job).
2. **Diagnostics package** (`/diagnostics` → `POST /diagnostics-analyze`) — zip
   van `Collect-IntuneDiagnostics.ps1`: uitpakken, dashboard bouwen, én de
   **timeline-analyse** op de IME-logs erin draaien. Job `kind="diag"`,
   top-level `state` direct `ready`. De analyse draait `scripts/run-analysis.sh`
   (wrapper die het upstream-script headless aanroept) als subprocess met
   timeout (`SCRIPT_TIMEOUT_SECONDS`) en concurrency-cap (`JOB_CONCURRENCY`,
   semafoor); ze is een **sub-state** (`analysis`-dict in `job.json`, states
   queued|running|done|failed) die de diag-job nooit mag laten falen. Na afloop
   wordt `summary.json` uit het rapport geparst (samenvattingspaneel).
   Dashboard-checks worden geparst uit o.a. `dsregcmd-status.txt`,
   `Apps-IME/service-status.txt`, `Network/endpoint-connectivity.txt` en het
   machinecert-overzicht; parsers zijn totaal: ontbrekend bestand → status
   `unknown`, nooit een error. Eén check ("Enrollment certificate") is een
   read-only port van de `Get-EnrollmentRowHealth`-logica uit de Intune Sync
   Debug Tool (call4cloud): `parse_enrollments` haalt de
   `SslClientCertReference`-thumbprint per enrollment op (van de enrollment-key
   of de `DMClient\MS DM Server`-subkey) en `build_dashboard` kruist die met het
   machinecert-overzicht → healthy/missing/expired. **Geen** repair-acties: de
   tool zelf (live WPF-repair-GUI, admin/registry-schrijvend) hoort niet in
   Sherlog thuis; alleen de diagnose-logica + haar output. Draaide iemand die
   tool op een device, dan wordt een meegeüploade `Repair.log` als losse check
   ("Intune Sync Debug Tool") getoond (verder gewoon `.log` in de viewer). File browser per extensie: `.log` →
   CMTrace-viewer; `.txt/.reg/.xml/...` → tekstviewer met UTF-16-tolerante
   decodering (PowerShell 5.1 Out-File en `reg export` schrijven UTF-16LE);
   `.html` → sandboxed iframe; `.evtx` → eventviewer (python-evtx, cap
   `EVTX_MAX_EVENTS`); `.cab` → uitgepakt met `cabextract` (in Docker-image;
   zonder cabextract, of bij corrupte/over-budget cab → skipped/disabled in de
   tree, nooit een upload-fout); `.etl` → niet uitgepakt, wel disabled in de
   tree.
3. **Device drop-off** (`POST /api/diagnostics` + `/inbox`, alleen met
   `ENABLE_UPLOAD_API`) — zelfde diag-jobvorm, maar token-scoped: een
   Intune-collector POST't een zip met een self-chosen secret in de
   `X-Upload-Token`-header; alleen `sha256(token)` belandt op schijf. De inbox
   leest het token uit de header of POST-body, **nooit uit de URL-query**
   (lekt anders in access-logs/history/Referer).

**Dashboard-extra's:** `render_dashboard_panel` sorteert kaarten op ernst en
toont een verdict-banner; rode/amber kaarten krijgen een "wat nu"-hint uit de
`_ADVICE`-map (label → tekst, aangehecht in `build_dashboard`). Elke kaart
heeft daarnaast een "?"-toggle met uitleg wat de check inhoudt, uit de
`_WHAT`-map — die wordt **in de renderer** op label opgezocht (niet in
`dashboard.json` opgeslagen), zodat bestaande jobs de uitleg ook krijgen; een
test dwingt af dat elk `"label"` in app.py een `_WHAT`-entry heeft en omgekeerd.
De toggle-knop moet `stopPropagation()` doen: de kaart zelf is een deep-link. Naast de
basischecks: Autopilot-profiel + ESP-app-tracking (registry-hives), en een
content-delivery-correlatiekaart (delivery/netwerk-foutcodes + proxy of
onbereikbare endpoints). Context-bewust: "Entra PRT" wordt `unknown` (niet
rood) als dsregcmd onder SYSTEM draaide (machine-account in `Executing Account
Name` — de PRT is per-user); "Enrollment certificate" kiest de Intune-enrollment
mét `SslClientCertReference` (stale GUID's negeren) en degradeert naar warn
i.p.v. bad wanneer de referentie ontbreekt terwijl MDM sync gezond is
(collection gap, geen kapot device). Win32-app-GUID's worden verrijkt met displaynamen via
Graph (`refresh_app_names`, cache `APP_NAMES_CACHE`, zelfde `GRAPH_*`-creds als
de CSP-namen). Exports: `GET /result/{id}/dashboard.json` en `/summary.json`;
de "Copy findings"-knop bouwt client-side markdown uit `js_json(dash)`.
Pakket-brede zoek: `GET /result/{id}/search?q=` (`search_package`, begrensd
40/bestand + 300 totaal, regelnummers = viewer-nummering). Result-pagina's
tonen een expiry-hint (`created`-stamp in job.json + `JOB_RETENTION_HOURS`).
De inbox groepeert per device en dieft de nieuwste upload t.o.v. z'n voorganger
(`inbox_device_diff` op dashboard.json-statussen).

**Routes-conventies:** `_job_guard(job_id, ...)` is de gedeelde preamble
(isalnum + read_status); kale fouten renderen via `notice_response`
(NOTICE_PAGE met chrome) behálve binnen sandboxed viewer-iframes (blijven
plain text). Gedeelde CSS staat op `/assets/app.css` (cacheable; CSP heeft
daarvoor `style-src 'self'`), maar de sandboxed viewers houden hun CSS inline —
zonder allow-same-origin sturen ze geen credentials mee en zou de link onder
basic auth 401'en. Het dark-mode bootstrap-script staat één keer in `_THEME_JS`
en wordt via string-concatenatie in elke template gezet.

**Collector-contract:** `_DASH_SOURCES` (paden) en een paar hardcoded
`rglob`-namen (`Apps-IME/Logs`, `*-ErrorsWarnings.txt`,
`PushNotification-Platform`) moeten letterlijk overeenkomen met wat
`Collect-IntuneDiagnostics.ps1` schrijft — anders wordt een check stilletjes
"unknown" i.p.v. een fout. `test_collector_produces_every_dashboard_source`
bewaakt dit. `Remediate-CollectToSherlog.ps1` wordt **niet** meer inline
gedupliceerd in app.py: `load_remediation_template()` leest het bestand van
schijf (fallback bij ontbreken), zodat de twee nooit kunnen driften.
`/collect-script` is uitgezonderd van basic auth (de Intune-remediation
download het als SYSTEM zonder credentials). De collector-`Write-Host`/
`Write-Warning`-regels stromen niet door een PowerShell-pipe; automatisering
(de remediation-wrapper) leest daarom een aparte `Write-Output
"SHERLOG_RESULT=…"`/`"SHERLOG_ERROR=…"`-slotregel. Het upload-token wordt
altijd uit alle tekstbestanden geredigeerd (ook zonder `-Anonymize`) omdat
`Start-Transcript` de volledige commandline vastlegt; `-Anonymize` slaat
well-known SYSTEM-principals over (anders corrumpeert het `HKEY_LOCAL_
MACHINE\SYSTEM\…`-paden en breekt het de PRT-SYSTEM-detectie hierboven).
Firewall- en eventlog-checks prefereren een locale-onafhankelijke
JSON-sidecar (`parse_firewall_profiles_json`, `count_event_issues_json`) als
die in het pakket zit, met fallback op de Engelstalige tekstexport.

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
buiten auth en checkt of `pwsh` beschikbaar is. JSON die in een **niet**-
sandboxed inline `<script>` belandt (app-chrome) moet via `js_json()` —
escapet `< > & U+2028 U+2029` — nooit kale `json.dumps()` (alleen voor
on-disk). Footgun: de U+2028/U+2029-`replace()`-args in `js_json` moeten
ASCII-escapes blijven (de tekst `\u2028`/`\u2029`), niet de letterlijke
tekens; die renderen als blanks en verdwijnen bij paste → `replace("", …)`
inserteert tussen elk teken en corrumpeert álle js_json-output (regressie:
`test_js_json_neutralises_script_breakout`).

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
