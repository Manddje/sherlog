# Sherlog

Webapplicatie ([sherlog.nl](https://sherlog.nl)) die Microsoft Intune Management
Extension (IME) logbestanden analyseert en het resultaat als
HTML-timelinerapport in de browser toont.

De homepage biedt twee losse tools: de **Timeline Analyzer** (`/timeline`) en
de **CMTrace Viewer** (`/cmtrace`). Je uploadt logs (een `.zip` of losse
`.log`-bestanden, bijvoorbeeld uit
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs` of een Intune
"Collect Diagnostics"-export). Voor de timeline draait de server het
analysescript headless en serveert het gegenereerde rapport.

Eén container, twee lagen:

- **Weblaag** — Python 3 + FastAPI + uvicorn op poort `8080`
- **Analyse-engine** — PowerShell Core (`pwsh`) die het script
  `Get-IntuneManagementExtensionDiagnostics.ps1` aanroept

De state staat volledig op het bestandssysteem (`/data`): geen database, geen
Redis.

Naast het timeline-rapport biedt de app een **CMTrace-logviewer**: bekijk de ruwe
geüploade `.log`-bestanden in een gekleurde tabel (warnings geel, errors rood) met
tekst- en componentfilter — een web-equivalent van het Windows-only CMTrace.exe.
Bereikbaar als eigen tool via de uploadpagina `/cmtrace` (geen analyse nodig) én
via "Raw logs (CMTrace)" op de rapportpagina. De (untrusted) loginhoud wordt in
een sandboxed iframe geserveerd.

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
| `APP_USER`               | *(leeg)*| Optionele gebruikersnaam voor basic auth.                                                     |
| `APP_PASSWORD`           | *(leeg)*| Optioneel wachtwoord voor basic auth.                                                         |

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
