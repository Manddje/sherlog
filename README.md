# Sherlog

Webapplicatie ([sherlog.nl](https://sherlog.nl)) die Microsoft Intune Management
Extension (IME) logbestanden analyseert en het resultaat als
HTML-timelinerapport in de browser toont.

De homepage biedt het **Diagnostics Package** (`/diagnostics`) en de
**CMTrace Viewer** (`/cmtrace`). Je uploadt een diagnostics-`.zip` (→ device
health + analyse) of losse `.log`-bestanden (→ CMTrace-viewer), bijvoorbeeld uit
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs` of een Intune
"Collect Diagnostics"-export. De **timeline-analyse is geen losse tool meer** —
die draait automatisch op de IME-logs **binnen een diagnostics-pakket**: de
server draait het analysescript headless en toont het rapport bij
`/result/<id>/timeline`.

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
via de tab **Files** op elke resultaatpagina (`/result/<id>/files`; de oude URL
`/result/<id>/cmtrace` toont dezelfde tab). De (untrusted) loginhoud wordt in
een sandboxed iframe geserveerd. Losse logs alsnog analyseren kan met de tab
**Run timeline analysis**. `/errorcodes` biedt daarnaast een
doorzoekbare referentie van ~110 Intune/IME/MSI-foutcodes met uitleg — dezelfde
tabel die de viewers en het dashboard gebruiken voor hun verklaringen —
gegroepeerd per familie (Win32/IME, MDM, HTTP, Delivery Optimization, netwerk,
Windows, MSI) met een vaste zoekbalk en een kopieerknop per code. Vanaf een
resultaat (`/errorcodes?job=<id>`) markeert de pagina welke codes in dat pakket
voorkomen, met links naar de bewijsregel en naar een zoekopdracht in de
Files-tab (`/result/<id>/files?q=<code>`).
Resultaatpagina's tonen een "expires in ~Nh"-hint (retentie) en de hele app
heeft een dark mode; de homepage toont een cumulatieve uploadteller.

De **Diagnostics Package**-tool neemt de zip die
`Collect-IntuneDiagnostics.ps1` op een device produceert (`IntuneDiag-*.zip`)
en biedt drie dingen in één resultaatpagina. Naast de kern-collectie
verzamelt het script ook: `dsregcmd /status` in **interactieve
gebruikerscontext** (via een one-shot scheduled task — geeft de Entra
PRT-check een echt signaal i.p.v. altijd "unknown" onder SYSTEM), GPO-policies
(`HKLM\SOFTWARE\Policies`), co-management-status, Defender for
Endpoint-onboarding, Delivery Optimization, schijfruimte, tijdsynchronisatie,
TPM-status en een TLS-issuer-check (detecteert TLS-inspectie). Het schrijft
een `_MANIFEST.json` (collectorversie, profiel, per-stap resultaat en de
uitkomst van de redactie) en redigeert het upload-token altijd uit alle
tekstbestanden — ook zonder `-Anonymize` — omdat PowerShell's transcript de
volledige commandline (inclusief token) vastlegt. Die redactie is
**fail-closed**: een bestand dat niet geredigeerd kan worden gaat niet mee, en
na het zippen wordt elk bestand (ook binaries) op het token gescand; bij een
treffer wordt er niet geüpload. Standalone schrijft de collector naar een
beveiligde map `%ProgramData%\Sherlog\Collect` (SYSTEM/Administrators).

1. **Diagnose-dashboard** — ruim dertig health checks uit het pakket, met bovenaan
   een **verdict-banner** ("N problems and M warnings found") en de kaarten
   gesorteerd op ernst (rood eerst). Checks o.a.: Entra join- en **PRT-status**
   (bij voorkeur uit `dsregcmd` in **interactieve gebruikerscontext** — de
   collector draait die apart via een one-shot scheduled task, want de PRT is
   per-user en onzichtbaar onder SYSTEM), MDM-enrollment-URL,
   IME-servicestatus, bereikbaarheid van de Intune/Entra-endpoints, verlopen
   machinecertificaten, **MDM sync health** (herkent het "zombie
   device"-patroon: check-ins lopen door terwijl het MDM-certificaat verlopen
   is), **Win32-app-deploymentstatus** per app (foutcode + uitleg;
   app-namen via Graph als `GRAPH_*` gezet is), enrollment +
   **enrollment-certificaatbinding** (read-only port van de Intune Sync Debug
   Tool-logica), Policies/RSOP met Microsoft Learn-links per setting,
   scripts/remediations, het **push/remediation-kanaal** (WNS-events),
   geaggregeerde eventlog-fouten, herkende foutcodes in álle logs,
   WinHTTP-proxy, firewall-profielen, **Autopilot-profiel en
   ESP-app-tracking**, een **content-delivery-correlatie** (downloadfouten
   + proxy/endpoints), **GPO-policies** (conflictrisico met Intune),
   **co-management**- en **Defender for Endpoint**-status (alleen getoond als
   van toepassing), Delivery Optimization, **schijfruimte**,
   **tijdsynchronisatie**, **TPM**-status, een **TLS-inspectiedetectie**
   (certificate-issuer-check tegen login.microsoftonline.com), en een
   **Collection**-kaart die per collectorstap ok/mislukt toont (uit
   `_MANIFEST.json`) zodat "geen data" en "collectie mislukt" niet meer
   hetzelfde grijze "unknown" zijn. Elke rode/amber kaart draagt een korte
   "wat nu"-hint, elke kaart heeft een **"?"-knop met uitleg** wat die check
   precies controleert en waarom het uitmaakt, en elke kaart **deep-linkt naar
   de bewijsregel** in het bronbestand. Ontbreekt een bronbestand, dan toont de check "unknown"
   (grijs) in plaats van een fout. Via **Copy findings** kopieer je het
   dashboard als markdown; `/result/<id>/dashboard.json` en
   `/result/<id>/summary.json` leveren dezelfde data machine-leesbaar. Het
   apparaatlabel (device/tenant/datum) boven de kaarten komt nu altijd uit
   `_SUMMARY.txt`, ook als `dsregcmd` volledig geparst kon worden. De
   firewall- en eventlog-checks gebruiken een locale-onafhankelijke
   JSON-sidecar wanneer die in het pakket zit (nieuwere collector), en vallen
   anders terug op de Engelstalige tekstexport.
2. **Automatische timeline-analyse** — op de IME-logs in het pakket
   (`Apps-IME\Logs`) draait de timeline-analyse (alleen hier beschikbaar); het
   rapport en het samenvattingspaneel verschijnen zodra de analyse klaar is.
3. **File browser** (tab **Files**, `/result/<id>/files`, op volle hoogte) —
   alle bestanden in het pakket zijn direct te bekijken, met een breadcrumb
   en een Download-knop voor het geopende bestand. `?file=<pad>&line=<n>`
   opent direct een bestand op een regel; zo linken de bevindingen op het
   overzicht ("Open evidence") naar hun bewijs:
   `.log` in de CMTrace-viewer, tekstbestanden (`.txt`, `.reg`, `.xml`, …)
   met UTF-16-detectie, `.html` in een sandboxed frame en `.evtx` in een
   eventviewer (tijd, event-ID, level, provider; gecapt op
   `EVTX_MAX_EVENTS`). `.cab`-archieven (o.a. Defender `MpSupportFiles.cab`)
   worden met `cabextract` uitgepakt en de inhoud is per type te bekijken;
   binaire `.etl`-bestanden worden niet uitgepakt maar wel (grijs) in de
   bestandsboom getoond. Boven de bestandsboom zit een **pakket-brede
   zoekfunctie**: één zoekopdracht doorzoekt alle tekstbestanden en elk
   resultaat springt naar de exacte regel in de viewer.

**Recente uploads** worden alleen in je eigen browser bewaard (localStorage) —
niet op de server, geen cookies of login. De lijst staat op de homepage en de
uploadpagina's; jobs die de server heeft opgeruimd (na `JOB_RETENTION_HOURS`)
verdwijnen er automatisch uit.

De homepage heeft een drag-&-drop dropzone (een `.zip` → Diagnostics, losse
`.log`-bestanden → de Files-tab met de CMTrace-viewer) met de recente uploads
eronder, en "Get started"-kaarten voor de collector, de Intune-inbox en de
CMTrace-viewer. De kop bevat Upload, Inbox en Error codes; de losse tools,
About en PayloadKit staan in de footer. De
geanonimiseerde voorbeeldlogs uit `testdata/` worden door de tests gebruikt.

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

Tests en weblaag zonder Docker (Python 3.12, `pwsh` 7.6 optioneel — zonder
`pwsh` wordt de echte analyse-test overgeslagen):

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest tests -q
```

Open daarna <http://localhost:8080>. De homepage laat je een diagnostics-pakket
of losse logs uploaden (Diagnostics / CMTrace Viewer). De app draait standaard
als **publieke tool zonder login**: iedereen kan logs uploaden en het rapport
bekijken.
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
| `MAX_LOCAL_JOBS`         | `200`   | Globale rem op het aantal interactieve (web-form) jobs op schijf; daarboven `429`. Begrenst de ongeauthenticeerde uploadroutes zodat de schijf niet volloopt (drop-off heeft zijn eigen cap). |
| `EVTX_MAX_EVENTS`        | `2000`  | Maximum aantal events dat de eventviewer per `.evtx`-bestand parst en rendert.                 |
| `LONG_SCRIPT_THRESHOLD_SECONDS` | `180` | PowerShell-scripts die langer draaien dan dit worden in de timeline als waarschuwing gemarkeerd. |
| `APP_USER`               | *(leeg)*| Optionele gebruikersnaam voor basic auth.                                                     |
| `APP_PASSWORD`           | *(leeg)*| Optioneel wachtwoord voor basic auth.                                                         |
| `GRAPH_TENANT_ID`        | *(leeg)*| Zet samen met `GRAPH_CLIENT_ID`/`GRAPH_CLIENT_SECRET` aan: verrijkt de RSOP-settingtabel met de vriendelijke Intune-settingnaam uit de Microsoft Graph settings-catalog. |
| `GRAPH_CLIENT_ID`        | *(leeg)*| App-registratie client-id (scope `DeviceManagementConfiguration.Read.All`, app-permission). |
| `GRAPH_CLIENT_SECRET`    | *(leeg)*| Client secret van bovenstaande app-registratie.                                               |
| `CSP_NAMES_CACHE`        | `<JOBS_DIR>/../csp-names.json` | Cachebestand voor de (tenant-onafhankelijke) catalog. Mag ook vooraf gegenereerd worden. |
| `APP_NAMES_CACHE`        | `<JOBS_DIR>/../app-names.json` | Cachebestand voor Win32-app-displaynamen (Graph `mobileApps`, zelfde `GRAPH_*`-creds en TTL). |
| `CSP_NAMES_TTL_HOURS`    | `720`   | Maximale leeftijd van de cache voordat de catalog opnieuw wordt opgehaald.                     |
| `ENABLE_UPLOAD_API`      | *(uit)* | Zet de device drop-off API (`/api/diagnostics`) + `/inbox` aan. Default uit. Drop-off packages gebruiken dezelfde `JOBS_DIR` en `JOB_RETENTION_HOURS` als alle andere logs. |
| `UPLOAD_TOKEN_MIN_LEN`   | `24`    | Minimale lengte van een (zelfgekozen) upload-token.                                            |
| `UPLOAD_API_MAX_JOBS`    | `2000`  | Globale rem op het aantal drop-off-jobs (tegen disk-misbruik); daarboven `429`.                |
| `UPLOAD_API_MAX_JOBS_PER_TOKEN` | `200` | Per-inbox rem op het aantal drop-off-jobs per token; daarboven `429`. Voorkomt dat één token de globale cap vult. |
| `MAX_UNCOMPRESSED_MB`    | 20× `MAX_UPLOAD_MB` | Maximale uitgepakte grootte per upload (zip-bomb-budget, gedeeld over geneste zips en cabs). |
| `MAX_ZIP_MEMBERS`        | `20000` | Maximaal aantal bestanden per upload (zip + geneste zip + cab-inhoud); daarboven `413`. |
| `MIN_FREE_DISK_MB`       | `1024`  | Vrije-ruimtevloer op het `JOBS_DIR`-volume. Nieuwe uploads krijgen `507` als er minder dan dit plus `MAX_UPLOAD_MB` vrij is; uitpakken stopt ook op deze vloer. |
| `UPLOAD_RATE_PER_HOUR`   | `60`    | Web-uploads per client-IP per uur (`0` = uit); daarboven `429`. De drop-off API is per token begrensd. |
| `MAX_PENDING_FILES`      | `5000`  | Maximaal aantal collectie-statusbestanden (één per upload-token). |
| `HEAVY_WORKERS`          | cpu+1 (max 4) | Threads voor zwaar werk (logs parsen/renderen, zoeken, evtx, uitpakken), los van de pool die `/health` gebruikt. |
| `FORWARDED_ALLOW_IPS`    | `*` (image) | Welke proxy's `X-Forwarded-For` mogen zetten (uvicorn). `*` past bij Coolify/Traefik; publiceer je de poort direct, zet dan het proxy-adres of `127.0.0.1`, anders kan een client zijn IP spoofen en de rate limits omzeilen. |
| `COLLECT_PENDING_TTL_MINUTES` | `45` | Hoe lang een "collecting"-melding van een device in de inbox blijft staan zonder dat er een upload volgt. Een gemelde *fout* blijft `JOB_RETENTION_HOURS` staan. |

De Graph-verrijking is **optioneel en uit by default**: zonder de drie `GRAPH_*`
vars doet de app geen externe call en blijft de RSOP-tabel zoals hij is (OMA-URI +
Learn-link). De catalog bevat alleen globale Microsoft-metadata (geen logdata) en
wordt één keer bij het starten opgehaald en gecached.

De app is **standaard zonder login** (publiek). Basic auth is optioneel: zet
**beide** `APP_USER` en `APP_PASSWORD` om de hele app achter een wachtwoord te
zetten. Zijn ze (allebei) leeg — de default — dan is de app open en logt hij
één waarschuwing bij het starten. `/health` valt altijd buiten auth.

## Device drop-off via Intune

Een Intune-beheerder kan de collector via Intune op een device draaien en de
logs automatisch naar Sherlog laten uploaden, om ze daarna in een **inbox** op de
site door te nemen. Zet hiervoor `ENABLE_UPLOAD_API=1`.

**Twee geheimen: inbox-sleutel en upload-token.** Genereer op `/inbox` (knop
*Generate token*) een **inbox-sleutel** (`shk_…`). Sherlog leidt daaruit een
**upload-token** af (`shu_…` = HMAC-SHA256 van de sleutel) en zet alleen dát
token in het detection-script. Het upload-token kan uploaden en de
collectiestatus melden, maar kan de inbox niet openen of leegmaken; alleen de
inbox-sleutel kan dat. De HMAC is eenrichtingsverkeer: wie het script ziet
(Intune-console, ScriptBlock-logging, de IME-cache op het device) kan er de
sleutel niet uit afleiden. Sherlog bewaart alleen de **sha256** van het
upload-token op elke job — nooit een geheim zelf — en houdt geen register bij.
Een inbox-sleutel wordt op de upload-endpoints geweigerd, een upload-token op
de inbox.

> **Legacy tokens.** Tokens zonder `shk_`/`shu_`-prefix (van vóór deze
> splitsing) blijven werken als één geheim voor uploaden én lezen, zodat
> uitgerolde remediations niet breken. De inbox toont dan een waarschuwing:
> genereer een nieuwe sleutel en rol het nieuwe script uit.

> **Geheimen reizen nooit in de URL-query** — niet bij upload
> (`X-Upload-Token`-header) en niet bij het openen van de inbox (POST-body of
> `X-Inbox-Key`-header), dus ze komen niet in access-logs, browsergeschiedenis
> of de `Referer` terecht. Behandel de inbox-sleutel als een wachtwoord.

**Uitrollen (aanbevolen: Remediation on-demand):**

1. Genereer een inbox-sleutel op `<sherlog>/inbox` en bewaar hem.
2. Kopieer het detection-script dat de pagina toont: `$SherlogBase`,
   `$UploadToken` (het `shu_`-token) en `$CollectorSha256` zijn al ingevuld.
3. Intune-admincenter → **Devices → Scripts and remediations** → custom script
   package, **Run in 64-bit PowerShell: Yes**, **logged-on credentials: No**.
   Plak het script als **detection-script** — Intune vereist een
   detection-script; dit ene script doet de collectie, dus een
   remediation-script is niet nodig (leeg laten).
4. Wijs toe aan een device-groep (de detection draait op schema), of selecteer
   een device → **Run remediation** (on-demand). Draait als SYSTEM, verzamelt
   het slimme `-Remote`-profiel en POST't de zip.
5. Open `<sherlog>/inbox`, voer je inbox-sleutel in. De inbox toont één rij per
   device (actuele status, verschil met de vorige upload, "Open latest");
   klik op het aantal uploads om de losse uploads te zien of te verwijderen.

**Integriteit van de collector.** Het detection-script downloadt
`Collect-IntuneDiagnostics.ps1` van `/collect-script` en draait het als SYSTEM.
Het script bevat de **SHA-256 van de collector** die de server op dat moment
serveert (ook zichtbaar op `/inbox`) en weigert elke andere versie: bij een
mismatch wordt het gedownloade bestand verwijderd en eindigt de run met
exitcode 1. `$SherlogBase` moet `https://` zijn (alleen `localhost` mag `http`).
**Gevolg:** na een Sherlog-update die de collector wijzigt, moet je het script
opnieuw van `/inbox` kopiëren en in Intune bijwerken — tot dan melden de
devices "collector hash mismatch".

> **Live status.** Een collectie duurt minuten. De collector meldt daarom bij
> het starten "collecting" aan Sherlog (en meldt het ook als hij zelf ziet dat
> de run mislukte, bijv. een te groot pakket of een geweigerde upload), zodat
> het device meteen in de inbox staat met verstreken tijd. De inbox ververst
> zichzelf elke 30 s zolang er iets loopt. De melding verdwijnt zodra de zip
> binnen is, of vanzelf na `COLLECT_PENDING_TTL_MINUTES`. Deze seintjes maken
> géén job aan en tellen niet mee voor de jobcaps.

**Uitkomst in Intune.** Het script schrijft één korte regel naar de
remediation-output, bijvoorbeeld `Sherlog: uploaded (id 1a2b3c4d, mode full,
wrapper 1.4.0).` Exitcode **0** betekent geüpload (of bewust overgeslagen door
de throttle); elke fout (hash-mismatch, download, collectie, upload) geeft
**exitcode 1** en toont dus als "With issues" in het Intune-rapport. De
volledige resultaat-URL komt bewust niet in de Intune-output of het register:
hij geeft zonder verdere controle toegang tot het pakket.

**Throttle en backoff.** Het script bewaart in `HKLM\SOFTWARE\Sherlog` per
modus `LastRunUtc_<mode>` en `LastResultId` (8 tekens), en slaat een run over
als de vorige geslaagde run minder dan `$MinHoursBetweenRuns` (default 6 u)
geleden was, zodat een fleet-brede schedule de inbox-caps niet in één klap
opsoupeert. Na een mislukte run wacht het 1 u, daarna telkens het dubbele (tot
`$MinHoursBetweenRuns`), zodat een permanent geweigerd device niet elk uur
opnieuw minutenlang verzamelt. Zet `$Force = $true` om throttle en backoff te
negeren (handig voor een eenmalige on-demand run). Een tijdstempel in de
toekomst (klok teruggezet) telt als verlopen.

**Werkmap.** Download en zip staan in een nieuwe, willekeurige submap van
`%ProgramData%\Sherlog`. De ACL wordt op SID's gebouwd (SYSTEM en
Administrators, geen overerving, eigenaar Administrators) en gecontroleerd;
heeft een standaardgebruiker de map vooraf aangemaakt, dan wordt hij opnieuw
opgebouwd of stopt de run. Opruimen volgt nooit junctions of symlinks.

Direct vanaf de commandline kan ook:

```powershell
.\Collect-IntuneDiagnostics.ps1 -Remote `
    -UploadUrl 'https://sherlog.nl/api/diagnostics' -UploadToken '<shu_-token>'
```

**Anonimiseren (best-effort).** Voeg `-Anonymize` toe (of zet de toggle aan op
`/inbox`) om tenant- en company-gegevens te redigeren in **alle
tekstbestanden** (herkend op inhoud, niet op extensie): tenant-id/naam,
domein(en), UPN/e-mail, device- en gebruikersnaam (ook de interactieve
gebruiker als de collector onder SYSTEM draait), profielmappen, SID's,
device-id's (Entra `DeviceId`, Intune `EntDMID`), Defender `OrgId`,
serienummer, Wi-Fi-SSID's, IPv4/IPv6- en MAC-adressen. Namen worden alleen als
heel woord vervangen (`CORP` raakt `Corporation` niet), ook in `.reg`-hexwaarden
en in PowerShell-JSON-escapes. De zip-naam en `X-Device-Name` worden een
gezouten hash (`anon-<16 hex>`, zout per device in het register). Dit is
**best-effort, geen garantie**: binaries (event logs `.evtx`, Defender `.cab`,
de geneste mdmdiag-zip, `.etl`) worden **niet** gescrubd en kunnen nog
identifiers bevatten — controleer het pakket vóór delen. `_MANIFEST.json`
vermeldt of de anonimisering volledig lukte; de dashboard-kaart *Collection*
waarschuwt als er bestanden zijn weggelaten.

```powershell
.\Collect-IntuneDiagnostics.ps1 -Remote -Anonymize
```

**Opslag & retentie.** Drop-off packages worden net als alle andere logs in
`JOBS_DIR` opgeslagen en na `JOB_RETENTION_HOURS` (default 24u, gerekend vanaf
het uploadmoment) opgeruimd. Wil je ze langer bewaren én over redeploys
behouden: mount `JOBS_DIR` op een persistent Coolify-volume en zet
`JOB_RETENTION_HOURS` hoger (bijv. `720` voor 30 dagen).

**Maprechten.** De container draait als niet-root (uid 10001). De entrypoint
([`scripts/docker-entrypoint.sh`](scripts/docker-entrypoint.sh)) chownt `JOBS_DIR`
bij het starten en dropt daarna naar die user, dus een root-owned Coolify-volume
werkt **zonder handmatige `chown`**. Wel nodig: het volume moet schrijfbaar zijn
voor root bij het starten (standaard zo).

**Security & privacy.** Diagnostics-packages bevatten vertrouwelijke gegevens
(IME-logs, identity, certificaten). Voor vertrouwelijke logs heeft een
**self-hosted** Sherlog de voorkeur boven het publieke `sherlog.nl`. Het
upload-token staat leesbaar in het detection-script, maar geeft alleen
upload-rechten. Jobs worden na `JOB_RETENTION_HOURS` (default 24 u) opgeruimd.
Microsoft adviseert geen persoonsgegevens via scripts te verzamelen — beoordeel
zelf wat je ophaalt.

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
8. **Eén instantie per volume.** De app draait bewust met één uvicorn-worker
   (`--workers 1`): caps, de analyse-semafoor, de teller en het herstel na een
   herstart gaan uit van één proces per `JOBS_DIR` (lockfile
   `JOBS_DIR/.worker.lock`, met de hostnaam van de houder erin). Een tweede
   worker in dezelfde container weigert te starten. Een nieuwe container die
   de lock bezet vindt, zoals bij Coolify's rolling update (nieuwe container
   start vóór de oude stopt, op hetzelfde volume), start in **standby**: hij
   bedient verzoeken en `/health` is 200 (`"role": "standby"`), en neemt het
   herstel na een herstart en de retentie-sweep over zodra de oude container
   stopt (`"role": "primary"`). Schaal dus niet horizontaal op één volume.

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
  app-origin. Diezelfde sandbox-respons (en elke `.html` uit een diagnostics-
  pakket) krijgt bovendien `default-src 'none'`, zodat een kwaadaardig script de
  inhoud ook niet naar buiten kan exfiltreren. Onvertrouwde HTML (het rapport,
  `.html` uit een pakket) wordt alleen in een iframe geserveerd: wie de URL
  direct opent wordt teruggestuurd naar de resultaatpagina, zodat een pakket
  geen phishing- of redirectpagina op dit domein kan zijn.
- **CSP met nonces.** App-pagina's staan alleen scripts toe met een per
  respons willekeurige nonce (geen `'unsafe-inline'`), dus een escape-fout in
  een template leidt niet meer tot code-executie. Verder `HSTS`,
  `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`,
  `Cross-Origin-Opener-Policy` en `Cache-Control: no-store` op `/inbox`.
- **Concurrency-limiet.** `JOB_CONCURRENCY` (default 2) begrenst hoeveel
  analyses tegelijk draaien, zodat veel gelijktijdige uploads de container niet
  uitputten. Stem af op de toegewezen CPU/RAM.
- **Upload-validatie.** Alleen `.log`/`.zip`. De groottelimiet wordt per route
  afgedwongen terwijl de body binnenkomt (ook bij chunked uploads zonder
  `Content-Length`), plus zip-slip-, zip-bom- en bestandsaantalbescherming.
  Een upload die om welke reden dan ook faalt laat niets op schijf achter.
- **Rate limits.** Per client-IP op web-uploads (`UPLOAD_RATE_PER_HOUR`),
  inbox-lookups en mislukte basic-auth-pogingen.
- **Disk-limiet.** `MAX_LOCAL_JOBS` (default 200) begrenst hoeveel interactieve
  upload-jobs er tegelijk op schijf staan; daarboven krijgen nieuwe uploads
  `429` tot oude jobs verlopen. De drop-off API heeft zijn eigen caps
  (`UPLOAD_API_MAX_JOBS`, `UPLOAD_API_MAX_JOBS_PER_TOKEN`). Samen met korte
  retentie voorkomt dit dat anonieme uploads de schijf vullen. Omdat caps
  jobs tellen en geen bytes, weigert de app bovendien nieuwe uploads (`507`)
  zodra het volume onder `MIN_FREE_DISK_MB` vrije ruimte zakt.

## Dependencies bijwerken

- **Python:** pas `requirements.in` / `requirements-dev.in` aan en compileer de
  hash-locks opnieuw:
  `uv pip compile requirements.in --python-version 3.12 --generate-hashes --universal -o requirements.txt`
  (idem voor `requirements-dev.in`). Draai daarna `pip-audit -r requirements.txt`.
- **Base image:** `ubuntu:24.04` staat op digest in `Dockerfile` en
  `Dockerfile.test`; werk de digest bewust bij.
- **PowerShell:** `PWSH_VERSION` en `PWSH_SHA256` in beide Dockerfiles
  (package pool `packages.microsoft.com/ubuntu/24.04/prod/pool/main/p/powershell/`).

## Beperkingen

- **Geen LogViewerUI.** De `-ShowLogViewerUI`-modus van het script gebruikt
  `Out-GridView` (Windows-only) en wordt nooit aangeroepen.
- **Geen `-Online` bij het upstream-script.** De online-modus vereist
  Graph-credentials in de analyse-run en blijft uit. Wel optioneel:
  met `GRAPH_*`-env-vars verrijkt Sherlog zelf settingnamen (RSOP) en
  Win32-app-namen via een gecachte Graph-fetch (app-only, read-only).
- **Uploadgrootte.** Maximaal `MAX_UPLOAD_MB` (default 100 MB) per analyse; zips
  worden bovendien tegen zip-bombs en path-traversal (zip-slip) beschermd.
- **Retentie.** Jobmappen worden na `JOB_RETENTION_HOURS` (default 24 uur)
  automatisch verwijderd. Rapporten zijn dus tijdelijk; download wat je wilt
  bewaren.
- **Eenvoudige concurrency.** `JOB_CONCURRENCY` begrenst het aantal parallelle
  analyses (extra jobs wachten), maar er is nog geen volwaardige, persistente
  job-queue — bij een herstart gaan wachtende/lopende jobs verloren.

## Roadmap

- **Persistente job-queue** — de semafoor begrenst gelijktijdigheid al, maar
  wachtende jobs overleven een herstart nog niet (ze worden bij start als
  failed gemarkeerd).
- **Vergelijken over tijd** — de inbox toont al welke checks verslechterden
  t.o.v. de vorige upload van hetzelfde device; een volledige diff-weergave
  tussen twee willekeurige uploads staat nog open.
