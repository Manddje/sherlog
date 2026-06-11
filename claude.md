# IME Log Analyzer — Web App

## Doel

Een webapplicatie die Microsoft Intune Management Extension (IME) logbestanden
analyseert met het bestaande PowerShell-script
`Get-IntuneManagementExtensionDiagnostics.ps1` (auteur: Petri Paavola,
https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics)
en het gegenereerde HTML-timelinerapport in de browser toont.

Gebruiker uploadt logs (zip of losse .log-bestanden, bijv. uit
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs` of een Intune
"Collect Diagnostics" export), de server draait het script headless en
serveert het HTML-rapport.

Deployment-doel: **Coolify** (self-hosted PaaS), build via Dockerfile in de repo-root.

## Architectuur

- **Eén container** met twee lagen:
  1. **Weblaag**: Python 3 + FastAPI + uvicorn (poort 8080)
  2. **Analyse-engine**: PowerShell Core (`pwsh`) die het bestaande script aanroept
- Base image: `mcr.microsoft.com/powershell:lts-ubuntu-22.04`
- Het script wordt headless aangeroepen als subprocess:
  ```
  pwsh -NoProfile -NonInteractive ./Get-IntuneManagementExtensionDiagnostics.ps1 \
       -LogFilesFolder /data/jobs/<uuid>/input -AllLogEntries -AllLogFiles
  ```
  De parameters `-AllLogEntries -AllLogFiles` onderdrukken de interactieve selectie-UI's.

## Harde kaders

- **GEEN** `-ShowLogViewerUI` (gebruikt Out-GridView, Windows-only — werkt niet op Linux)
- **GEEN** `-Online` parameter in v1 (vereist Graph API credentials; komt later)
- Uploads: zip of losse `.log` bestanden, max 100 MB per upload
- Elke analyse is een job: `/data/jobs/<uuid>/input/` (logs) en
  `/data/jobs/<uuid>/output/` (HTML-rapport)
- Script-subprocess heeft een timeout van 300 seconden; bij timeout of
  non-zero exitcode wordt stderr/stdout aan de gebruiker getoond
- Achtergrondtaak verwijdert jobmappen ouder dan 24 uur (instelbaar via env var)
- Healthcheck-endpoint op `GET /health` (geen auth) dat 200 teruggeeft en
  controleert of `pwsh` beschikbaar is
- Geen externe services (geen database, geen Redis) in v1 — bestandssysteem is de state
- **CMTrace-viewer**: naast het timeline-rapport kan de gebruiker de ruwe
  geüploade `.log`-bestanden bekijken in een web-CMTrace-tabel (kolommen tekst,
  component, datum/tijd, thread; rijen gekleurd op `type` — geel=warning,
  rood=error; tekst-/componentfilter). Loginhoud is untrusted en wordt daarom in
  een sandboxed iframe (`Content-Security-Policy: sandbox`) geserveerd, net als het
  rapport. Bestandskeuze via membership-check (geen path traversal). Rendering
  gecapt op `CMTRACE_MAX_LINES` (default 50000) regels.
- **Diagnostics Package-tool**: upload van de zip die
  `Collect-IntuneDiagnostics.ps1` produceert (precies één `.zip`; Engelse én
  Nederlandse scriptvariant ondersteund via kandidaat-bestandsnamen). Drie
  onderdelen:
  1. **Diagnose-dashboard** — health checks geparst uit o.a.
     `dsregcmd-status.txt`, `endpoint-connectivity.txt`, `service-status.txt`
     en het machinecert-overzicht (Entra join/PRT/MDM-URL, IME-service,
     endpoint-bereikbaarheid, verlopen certs). Parsers zijn totaal:
     ontbrekend bestand → status `unknown`, nooit een error (het
     collect-script wrapt alles in Invoke-Safe).
  2. **Automatische timeline-analyse** op de IME-logs in het pakket
     (`Apps-IME/Logs`); de analyse is een sub-state (`analysis` in
     `job.json`, jobkind `diag`) en mag de diag-job nooit laten falen.
  3. **File browser** voor alle pakketbestanden. Extension policy:
     `.log` → CMTrace-viewer; `.txt/.reg/.xml/.json/.csv` → tekstviewer met
     UTF-16-tolerante decodering (PowerShell 5.1 Out-File en `reg export`
     schrijven UTF-16LE); `.html/.htm` → sandboxed iframe; `.evtx` →
     eventviewer (python-evtx, gecapt op `EVTX_MAX_EVENTS`); `.cab/.etl` →
     niet uitgepakt, wel als disabled entry in de tree zichtbaar. Nested
     zips (mdmdiagnosticstool-output) worden precies één niveau diep
     uitgepakt met een gedeeld zip-bomb-budget.

## Wijzigingen aan het originele script

- Het originele script is geschreven voor Windows. Patches voor Linux/headless
  zijn toegestaan, maar:
  - Houd wijzigingen **minimaal** en documenteer elke patch in `PATCHES.md`
    (wat, waarom, regelnummers/functienaam), zodat upstream-updates later
    gemerged kunnen worden
  - Verander het analysegedrag en rapportformaat niet, alleen compatibiliteit
    (paden, encoding, Windows-only cmdlets in het non-UI codepad)

## Testdata

- `./testdata/` bevat echte (geanonimiseerde) IME-logs, minimaal
  `IntuneManagementExtension.log` en `AgentExecutor.log`
- Gebruik deze data om elke fase end-to-end te verifiëren
- Definitie van "werkt": het script produceert een HTML-rapport met een
  timeline die Win32App-events uit de testlogs bevat, zonder errors

## Conventies

- Python: type hints, geen onnodige dependencies (FastAPI, uvicorn,
  python-multipart; python-evtx voor de .evtx-viewer)
- Alle configuratie via environment variables met veilige defaults:
  - `MAX_UPLOAD_MB` (default 100)
  - `JOB_RETENTION_HOURS` (default 24)
  - `SCRIPT_TIMEOUT_SECONDS` (default 300)
  - `CMTRACE_MAX_LINES` (default 50000)
  - `EVTX_MAX_EVENTS` (default 2000)
- Logging naar stdout (Coolify/Docker vangt dit op)
- Commit per afgeronde fase met duidelijke commit message

## Repo-structuur (doel)

```
/
├── CLAUDE.md
├── PATCHES.md
├── README.md                  # incl. Coolify-deployinstructies
├── Dockerfile
├── docker-compose.yml         # alternatief voor lokaal testen
├── Get-IntuneManagementExtensionDiagnostics.ps1
├── app.py                     # FastAPI-app
├── requirements.txt
├── templates/                 # upload- en resultaatpagina's (indien nodig)
├── tests/
│   └── test_e2e.py            # volledige flow tegen ./testdata
└── testdata/
    ├── IntuneManagementExtension.log
    └── AgentExecutor.log
```

## Security & privacy

- IME-logs bevatten gevoelige informatie (devicenamen, gebruikersnamen,
  app-GUID's, soms script-output). Behandel uploads als vertrouwelijk:
  korte retentie, geen logs van logbestand-inhoud naar stdout
- Valideer uploads: alleen .log en .zip, zip veilig uitpakken
  (bescherm tegen zip-slip/path traversal), grootte-limiet afdwingen
- Run de container niet als root waar mogelijk
