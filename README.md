# Sherlog

Webapplicatie ([sherlog.nl](https://sherlog.nl)) die Microsoft Intune Management
Extension (IME) logbestanden analyseert en het resultaat als
HTML-timelinerapport in de browser toont.

De homepage biedt drie losse tools: de **Timeline Analyzer** (`/timeline`),
de **CMTrace Viewer** (`/cmtrace`) en het **Diagnostics Package**
(`/diagnostics`). Je uploadt logs (een `.zip` of losse `.log`-bestanden,
bijvoorbeeld uit `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs` of
een Intune "Collect Diagnostics"-export). Voor de timeline draait de server
het analysescript headless en serveert het gegenereerde rapport.

Eén container, twee lagen:

- **Weblaag** — Python 3 + FastAPI + uvicorn op poort `8080`
- **Analyse-engine** — PowerShell Core (`pwsh`) die het script
  `Get-IntuneManagementExtensionDiagnostics.ps1` aanroept

De state staat volledig op het bestandssysteem (`/data`): geen database, geen
Redis.

Boven het timeline-rapport toont de resultpagina een inklapbaar
**samenvattingspaneel**: aantallen geslaagde/mislukte installaties per type
(Win32App, PowerShell-script, remediation), mislukte items, herkende
foutcodes met uitleg en downloadstatistieken per app. De samenvatting wordt
na de analyse uit het rapport afgeleid (`summary.json` in de jobmap).

Naast het timeline-rapport biedt de app een **CMTrace-logviewer**: bekijk de ruwe
geüploade `.log`-bestanden in een gekleurde tabel (warnings geel, errors rood) met
tekst- en componentfilter — een web-equivalent van het Windows-only CMTrace.exe.
Bereikbaar als eigen tool via de uploadpagina `/cmtrace` (geen analyse nodig) én
via "Raw logs (CMTrace)" op de rapportpagina. De (untrusted) loginhoud wordt in
een sandboxed iframe geserveerd.

De **Diagnostics Package**-tool neemt de zip die
`Collect-IntuneDiagnostics.ps1` op een device produceert (`IntuneDiag-*.zip`)
en biedt drie dingen in één resultaatpagina:

1. **Diagnose-dashboard** — health checks uit het pakket: Entra join- en
   PRT-status (`dsregcmd`), MDM-enrollment-URL, IME-servicestatus,
   bereikbaarheid van de Intune/Entra-endpoints en verlopen
   machinecertificaten. Ontbreekt een bronbestand, dan toont de check
   "unknown" (grijs) in plaats van een fout.
2. **Automatische timeline-analyse** — op de IME-logs in het pakket
   (`Apps-IME\Logs`) draait dezelfde analyse als de Timeline Analyzer; het
   rapport en het samenvattingspaneel verschijnen zodra de analyse klaar is.
3. **File browser** — alle bestanden in het pakket zijn direct te bekijken:
   `.log` in de CMTrace-viewer, tekstbestanden (`.txt`, `.reg`, `.xml`, …)
   met UTF-16-detectie, `.html` in een sandboxed frame en `.evtx` in een
   eventviewer (tijd, event-ID, level, provider; gecapt op
   `EVTX_MAX_EVENTS`). `.cab`-archieven (o.a. Defender `MpSupportFiles.cab`)
   worden met `cabextract` uitgepakt en de inhoud is per type te bekijken;
   binaire `.etl`-bestanden worden niet uitgepakt maar wel (grijs) in de
   bestandsboom getoond.

**Recente uploads** worden alleen in je eigen browser bewaard (localStorage) —
niet op de server, geen cookies of login. De lijst staat op de homepage en de
uploadpagina's; jobs die de server heeft opgeruimd (na `JOB_RETENTION_HOURS`)
verdwijnen er automatisch uit.

De homepage toont screenshots van de drie tools (statische assets in
`static/`) en heeft een **demo-knop** ("Try it with sample logs",
`POST /demo`) die de timeline-analyse draait op de meegeleverde
geanonimiseerde voorbeeldlogs uit `testdata/` — die map zit daarom ook in de
Docker-image. Een bestaande demo-job wordt hergebruikt zolang de retentie hem
niet heeft opgeruimd.

## Credits

Het analysescript `Get-IntuneManagementExtensionDiagnostics.ps1` is gemaakt door
**Petri Paavola** en is hier integraal opgenomen:

<https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics>

Het script is origineel voor Windows geschreven. Voor headless gebruik op
PowerShell Core / Linux zijn minimale compatibiliteitspatches aangebracht. Elke
wijziging is gedocumenteerd in [PATCHES.md](PATCHES.md), zodat upstream-updates
later opnieuw gemerged kunnen worden. Het analysegedrag en het rapportformaat
zijn ongewijzigd.

## Lokaal draaien

Vereist: Docker met Compose.

```bash
docker compose up --build
```

Open daarna <http://localhost:8080>. De homepage laat je kiezen tussen de
Timeline Analyzer en de CMTrace Viewer. De app draait standaard als **publieke
tool zonder login**: iedereen kan logs uploaden en het rapport bekijken.
Optioneel kun je er basic auth voor zetten (zie hieronder).

### Environment variables

Alle configuratie loopt via environment variables met veilige defaults:

| Variabele                | Default | Betekenis                                                                                     |
| ------------------------ | ------- | --------------------------------------------------------------------------------------------- |
| `MAX_UPLOAD_MB`          | `100`   | Maximale totale uploadgrootte per analyse (MB). Wordt streaming afgedwongen.                   |
| `JOB_RETENTION_HOURS`    | `24`    | Jobmappen (logs + rapport) ouder dan dit worden automatisch verwijderd.                       |
| `SCRIPT_TIMEOUT_SECONDS` | `300`   | Timeout voor het analyse-subprocess. Bij overschrijding wordt de job als `failed` gemarkeerd. |
| `JOB_CONCURRENCY`        | `2`     | Maximum aantal analyses dat tegelijk draait. Extra jobs wachten in de wachtrij.               |
| `CMTRACE_MAX_LINES`      | `50000` | Maximum aantal regels dat de CMTrace-logviewer per bestand rendert.                            |
| `EVTX_MAX_EVENTS`        | `2000`  | Maximum aantal events dat de eventviewer per `.evtx`-bestand parst en rendert.                 |
| `LONG_SCRIPT_THRESHOLD_SECONDS` | `180` | PowerShell-scripts die langer draaien dan dit worden in de timeline als waarschuwing gemarkeerd. |
| `APP_USER`               | *(leeg)*| Optionele gebruikersnaam voor basic auth.                                                     |
| `APP_PASSWORD`           | *(leeg)*| Optioneel wachtwoord voor basic auth.                                                         |
| `GRAPH_TENANT_ID`        | *(leeg)*| Zet samen met `GRAPH_CLIENT_ID`/`GRAPH_CLIENT_SECRET` aan: verrijkt de RSOP-settingtabel met de vriendelijke Intune-settingnaam uit de Microsoft Graph settings-catalog. |
| `GRAPH_CLIENT_ID`        | *(leeg)*| App-registratie client-id (scope `DeviceManagementConfiguration.Read.All`, app-permission). |
| `GRAPH_CLIENT_SECRET`    | *(leeg)*| Client secret van bovenstaande app-registratie.                                               |
| `CSP_NAMES_CACHE`        | `<JOBS_DIR>/../csp-names.json` | Cachebestand voor de (tenant-onafhankelijke) catalog. Mag ook vooraf gegenereerd worden. |
| `CSP_NAMES_TTL_HOURS`    | `720`   | Maximale leeftijd van de cache voordat de catalog opnieuw wordt opgehaald.                     |

De Graph-verrijking is **optioneel en uit by default**: zonder de drie `GRAPH_*`
vars doet de app geen externe call en blijft de RSOP-tabel zoals hij is (OMA-URI +
Learn-link). De catalog bevat alleen globale Microsoft-metadata (geen logdata) en
wordt één keer bij het starten opgehaald en gecached.

De app is **standaard zonder login** (publiek). Basic auth is optioneel: zet
**beide** `APP_USER` en `APP_PASSWORD` om de hele app achter een wachtwoord te
zetten. Zijn ze (allebei) leeg — de default — dan is de app open en logt hij
één waarschuwing bij het starten. `/health` valt altijd buiten auth.

## Coolify-deployment

Stap voor stap:

1. **Nieuwe Application aanmaken.** Maak in Coolify een nieuwe *Application* aan
   en koppel deze repository als Git-source.
2. **Build Pack: Dockerfile.** Kies build pack **Dockerfile** (de `Dockerfile`
   staat in de repo-root). Zet de **exposed port** op `8080`.
3. **Persistent volume.** Mount een persistent volume op `/data`. Daar staan de
   jobmappen (`/data/jobs/<uuid>/`) met geüploade logs en gegenereerde
   rapporten. Zonder dit volume gaat de state verloren bij elke redeploy.
4. **Environment variables.** De app is publiek zonder login; laat
   `APP_USER`/`APP_PASSWORD` leeg. Optioneel afstellen:
   `MAX_UPLOAD_MB`, `JOB_RETENTION_HOURS`, `SCRIPT_TIMEOUT_SECONDS`,
   `JOB_CONCURRENCY`. Wil je toch een wachtwoord, zet dan beide auth-vars.
5. **Domein + HTTPS.** Wijs het domein `sherlog.nl` toe; de Coolify-proxy
   (Traefik) regelt automatisch HTTPS via Let's Encrypt. Forceer HTTPS-redirect.
6. **Healthcheck.** Configureer het healthcheck-pad op `/health` (poort `8080`,
   geen auth). Dit endpoint geeft `200` terug en controleert of `pwsh`
   beschikbaar is; ontbreekt `pwsh`, dan `503`.
7. **Resource limits.** Aanbevolen: **1 CPU / 1–2 GB RAM**. Het parsen van grote
   logbestanden is geheugenintensief; te krap zetten leidt tot OOM-kills tijdens
   de analyse.

## Publieke deployment (zonder login)

De app is bedoeld als open, login-vrije tool. Wie de URL heeft kan logs
uploaden en het rapport bekijken. Dat is een bewuste keuze — houd er wel
rekening mee:

- **Privacy-afweging.** IME-logs bevatten gevoelige data (device-/gebruikers-
  namen, app-GUID's, soms script-output). Zonder login vertrouw je op de
  onraadbaarheid van de job-URL en op korte retentie. Wil je toch een drempel,
  zet dan `APP_USER`/`APP_PASSWORD` (basic auth over de hele app).
- **HTTPS afdwingen.** Laat de Coolify-proxy HTTPS regelen en forceer een
  redirect van HTTP.
- **Job-URL's = capability.** Een job-id is een 128-bits `uuid4` (niet te raden
  of op te sommen). Wie de link heeft, ziet het rapport — deel hem dus bewust.
- **Korte retentie.** Houd `JOB_RETENTION_HOURS` laag; rapporten en geüploade
  logs worden na die periode automatisch verwijderd.

Beveiligingen die al in de code zitten (geen config nodig):

- **Rapport-isolatie (XSS).** Het rapport wordt opgebouwd uit loginhoud en is
  dus niet te vertrouwen. De app serveert het in een `sandbox`-iframe
  (`/result/<id>/report`) met een `Content-Security-Policy: sandbox`-header,
  zodat kwaadaardige scripts in een geüploade log géén toegang krijgen tot de
  app-origin. De app-pagina's sturen restrictieve security-headers (`CSP`,
  `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`).
- **Concurrency-limiet.** `JOB_CONCURRENCY` (default 2) begrenst hoeveel
  analyses tegelijk draaien, zodat veel gelijktijdige uploads de container niet
  uitputten. Stem af op de toegewezen CPU/RAM.
- **Upload-validatie.** Alleen `.log`/`.zip`, harde groottelimiet (streaming),
  zip-slip- en zip-bom-bescherming.

## Beperkingen

- **Geen LogViewerUI.** De `-ShowLogViewerUI`-modus van het script gebruikt
  `Out-GridView` (Windows-only) en wordt nooit aangeroepen.
- **Geen `-Online` / Graph in v1.** De online-modus vereist Graph API-credentials
  en is bewust uitgeschakeld in deze versie.
- **Uploadgrootte.** Maximaal `MAX_UPLOAD_MB` (default 100 MB) per analyse; zips
  worden bovendien tegen zip-bombs en path-traversal (zip-slip) beschermd.
- **Retentie.** Jobmappen worden na `JOB_RETENTION_HOURS` (default 24 uur)
  automatisch verwijderd. Rapporten zijn dus tijdelijk; download wat je wilt
  bewaren.
- **Eenvoudige concurrency.** `JOB_CONCURRENCY` begrenst het aantal parallelle
  analyses (extra jobs wachten), maar er is nog geen volwaardige, persistente
  job-queue — bij een herstart gaan wachtende/lopende jobs verloren.

## Roadmap

- **Job-queue** voor gecontroleerde gelijktijdigheid in plaats van ongelimiteerd
  parallelle subprocessen.
- **Rapporthistorie** — een overzicht van eerdere analyses in plaats van losse
  job-URL's.
- **`-Online`-ondersteuning** via een Entra app registration (Graph API), zodat
  app- en toewijzingsnamen verrijkt worden in het rapport.
