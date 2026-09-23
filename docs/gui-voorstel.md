# Voorstel: een betere GUI voor Sherlog

Status: fase 1 is geïmplementeerd (zie "Fasering"), fase 2 tot 6 staan open. Klikbare mockup van de volledige
GUI (Home, Result met de tabs Overview/Timeline/Files, Inbox, Error codes),
met Engelse UI-teksten zoals de app zelf: `docs/gui-voorstel-mockup.html`
(open lokaal in een browser) of online op
<https://claude.ai/artifact/XYsustEmHeXVZ3rh5jvpMp>. De schermkiezer in de
blauwe balk bovenaan en de navigatie in de header wisselen tussen de schermen.

De mockup volgt de huisstijl van [payloadkit.app](https://payloadkit.app)
(zelfde maker), zodat beide tools als één familie lezen. Overgenomen uit de
stylesheet van PayloadKit:

- **Lettertypen** Inter (UI) en JetBrains Mono (identifiers, paden, codes).
- **Kleuren** licht: achtergrond `#fafafa`, kaarten `#ffffff`, tekst
  `#0a0a0a`, primair `#2d69ea`, muted `#f2f3f5` / `#6e7278`, rand `#e4e6ea`,
  sidebar `#f5f7f9`. Donker: achtergrond `#0c0d0f`, kaarten `#181b1e`,
  primair `#3e7cff`, rand `rgba(255,255,255,.08)`, sidebar `#14161a`.
- **Vormen** basisradius 14 px (kaarten 18 px, knoppen 12 px), `shadow-sm`
  op kaarten met `shadow-md` bij hover, dunne randen op 50 % opacity.
- **Patronen** sticky header van 3 rem met blur en pill-navigatie; een
  catalogus-layout met categorie-sidebar met tellers links en een kaartgrid
  van drie kolommen rechts; kaarten met titel, mono-identifier,
  omschrijving, badges en een voet met twee acties; tint-badges
  (green-50/200, blue-50/200, red-50/200) voor status.

In Sherlog wordt dat: bevindingen, recente uploads en foutcodes als
PayloadKit-kaarten; de resultaatpagina en de foutcodepagina als catalogus met
sidebar (status/gebied/tabellen met tellers, families met tellers). Voor de
fonts betekent dit óf de woff2-bestanden self-hosten onder `/static/fonts`
(past bij de huidige CSP zonder externe hosts), óf `fonts.googleapis.com` en
`fonts.gstatic.com` toevoegen aan `style-src`/`font-src`. Self-hosten heeft de
voorkeur.

De analyse is gedaan op de huidige `app.py` (commit `a465282`), met
screenshots van elke pagina op desktop (1366 px) en telefoon (390 px), licht en
donker, gemaakt met het testpakket uit de testsuite.

## Uitgangspunten die blijven

- Geen framework, geen SPA, geen build-stap. Alle HTML blijft server-side
  `%`-templates in `app.py`; het voorstel is een herindeling van HTML en CSS.
- CSP met nonces, sandboxed iframes voor rapport en viewers, `/assets/app.css`
  als enige stylesheet: allemaal ongewijzigd.
- Dark mode via `html.dark` en `_THEME_JS` blijft; de nieuwe layout wordt
  in beide thema's ontworpen.
- De teststrings die de suite controleert (`action="/diagnostics-analyze"`,
  "Download Collect-IntuneDiagnostics.ps1", "Max total upload", enz.)
  blijven bestaan.

## Wat er nu wringt

### 1. De resultaatpagina is een lange stapel, niet een werkblad

`/result/<id>` zet alles onder elkaar: apparaatkop, verdict-banner, dertig
health-kaarten in zeven groepen, de analysekaart, het samenvattingspaneel,
de detailtabellen, en helemaal onderaan de file browser in een vak van 75 vh.

- Op het testpakket staan 16 kaarten, waarvan 12 grijs ("not present in this
  package"). Een grijze kaart krijgt evenveel ruimte als een rode. De twee
  echte bevindingen zijn na één scroll uit beeld.
- Het `auto-fit`-grid geeft per groep een andere kolombreedte (3, 1, 3, 4,
  5, 2 kaarten per rij). Het leest rafelig.
- De file browser, met de pakket-brede zoekfunctie, is een van de sterkste
  functies en staat op de minst zichtbare plek. Een deep-link vanaf een kaart
  scrollt de gebruiker een schermhoogte naar beneden.
- De detailtabellen zijn `<details>` met `max-height:45vh; overflow:auto`:
  een scrollbox in een pagina die zelf ook scrollt.

### 2. Drie pagina's voor één upload, met drie verschillende koppen

Dashboard (`/result/<id>`), timeline (`/result/<id>/timeline`) en raw logs
(`/result/<id>/cmtrace`) hebben elk een eigen topbar met andere knoppen. De
CMTrace-pagina toont dezelfde bestandsboom nog een keer. Terug naar het
dashboard kan alleen via het logo of de browser.

### 3. Acties zonder hiërarchie

De topbar op de resultaatpagina bevat zes knoppen in dezelfde ghost-stijl:
Copy findings, Download file, Download package, Raw logs, Inbox, New upload.
Op een telefoon wrappen die naar vijf regels vóór de inhoud begint (zie de
mobiele screenshot). Niets is primair, "Download file" hoort bij de viewer
en niet bij de pagina.

### 4. Navigatie en shell

- De marketingpagina's hebben een `nav` (CMTrace, Diagnostics, Error codes,
  Inbox, PayloadKit, About, thema); de resultaatpagina's een `topbar`.
  Twee shells, twee sets afstanden.
- Op een telefoon wrapt de nav naar drie regels, met de thema-knop alleen op
  regel drie.
- De homepage heeft drie ingangen voor hetzelfde: de dropzone, de "Tools"-
  tegels en de nav-links. De tegels herhalen de nav.

### 5. Kleuren en componenten zijn niet als systeem vastgelegd

`app.py` bevat 30 hardcoded statuskleuren (`#16a34a`, `#dc2626`, `#d97706`,
`#1a7f37`, `#c33`, `#9a6700`) verspreid over elf `<style>`-blokken, met eigen
dark-mode-overrides per component. Groen is in de kaarten `#16a34a`, in de
summary-chips `#1a7f37`. Rood is `#dc2626` en `#c33`. Elke nieuwe check of
pagina kopieert die keuze opnieuw.

### 6. Inbox en foutcodes zijn functioneel maar kaal

- De inbox-setup (sleutel, upload-token, script, Intune-stappen) is één
  lange pagina na één klik op "Generate token". De lijst zelf is een tabel
  zonder health-samenvatting per device, terwijl de data (`dashboard.json`,
  de diff met de vorige upload) er wel is.
- `/errorcodes` is één tabel van 110 rijen met alleen een tekstfilter.

## Voorstel

### A. Eén app-shell voor alle pagina's

Eén header van 3,25 rem, overal gelijk: logo, drie hoofdlinks (Upload, Inbox,
Error codes), rechts de thema-knop. About en PayloadKit verhuizen naar de
footer. Op een telefoon klapt de nav in een menu-knop; de header wrapt nooit.

Resultaatpagina's krijgen daaronder een **contextbalk** die zegt waar je
naar kijkt: apparaatnaam met verdict-pill, tenant, verzameldatum,
collectorversie en profiel (uit `_MANIFEST.json`), en rechts de acties.

### B. Resultaatpagina als werkblad met drie tabs

Onder de contextbalk komt een tabstrip: **Overzicht · Timeline · Bestanden**,
met tellers (2 warnings, 1 failed, 14 bestanden). Elke tab is nog steeds een
server-gerenderde pagina op de bestaande routes; alleen de shell en de
tabstrip zijn gedeeld via één `render_result_shell()`-helper. Geen
client-side routing.

**Overzicht: bevindingen eerst.**

1. Een verdict-strook met de tekst ("2 waarschuwingen, geen blokkerende
   problemen") en een verhoudingsbalk warn/ok/niet-verzameld.
2. Alleen de checks met status `bad`/`warn` worden een kaart: linkerrand in
   de statuskleur, groepslabel, waarde, "Wat nu"-advies, een knop
   **Open bewijs →** met het bronbestand en regelnummer, en de "?"-uitleg
   als inklapbare regel in de kaart in plaats van een zwevende knop.
3. Gezonde checks worden één compacte lijst per groep (één regel per check,
   groene stip, waarde in grijs). Vier checks kosten dan vier regels, niet
   vier kaarten.
4. Niet-verzamelde checks worden één inklapbare regel: "Niet verzameld · 12
   checks · dit pakket is met het Remote-profiel gemaakt", met de namen als
   chips en de hint om zonder `-Remote` te draaien. De collectorkaart
   (`_MANIFEST.json`) voedt deze tekst.
5. De detailtabellen (Win32-apps, foutcodes, RSOP, enrollments) staan
   daaronder als secties met een eigen "bron →"-link; de tabel scrollt
   horizontaal in zijn eigen container, niet verticaal in een box.

**Timeline.** Vier stat-tegels (Win32App, scripts, waarschuwingen,
downloads), de tabel met mislukte items die naar de logregel linkt, en het
originele rapport in de bestaande sandboxed iframe eronder. De analysekaart
("Timeline analysis ready/failed") verdwijnt uit het overzicht; de tabteller
draagt de status.

**Bestanden.** De file browser krijgt de hele hoogte van de tab: boom links
met de zoekfunctie bovenaan en de treffers direct eronder, viewer rechts met
een breadcrumb, de filter- en ernst-controls en de knop **Download** voor het
geopende bestand. De losse CMTrace-pagina wordt dezelfde tab (een logs-only
upload heeft dan alleen de tabs Bestanden en, na "Run timeline analysis",
Timeline).

Deep-links van bevindingen en tabelcellen openen de Bestanden-tab met
`?file=…#L<n>`; het bestaande nonce-mechanisme voor de iframe-src blijft.

### C. Acties met hiërarchie

Op de contextbalk staan twee knoppen: **Copy findings** (de actie die het
vaakst nodig is bij een ticket) en **Meer ▾** met daarin Download pakket,
Download dit bestand, Open in inbox, dashboard.json / summary.json, Nieuwe
upload en, gescheiden, Verwijder van server. De verloopt-hint blijft als
tekst ernaast.

### D. Homepage en uploadpagina's

- De hero blijft: kop, dropzone, badges, teller. De "Tools"-tegels vervallen;
  onder de dropzone komt één regel die de routing uitlegt ("een `.zip` opent
  het dashboard, losse `.log`-bestanden de viewer").
- **Recent uploads** verhuist naar de hero, naast of direct onder de
  dropzone: voor een terugkerende gebruiker is dat de belangrijkste lijst
  en nu staat hij onderaan.
- `/diagnostics` en `/cmtrace` blijven bestaan (de tests en externe links
  wijzen ernaartoe) maar delen de shell; het "Don't have a package yet?"-
  paneel en het inbox-paneel worden twee kolommen onder de dropzone.

### E. Inbox als vloot-overzicht plus setup-wizard

- **Lijst.** Eén rij per device met verdict-pill, aantal uploads, laatste
  upload en de diff met de vorige ("+1 warning, −1 problem"), uitklapbaar
  naar de losse uploads. "Collecting…"-meldingen staan bovenaan met verstreken
  tijd. De legacy-token-waarschuwing wordt een gele banner met één knop
  ("Nieuwe sleutel genereren").
- **Setup.** "Generate token" opent een stappenpaneel: 1 sleutel bewaren, 2
  script kopiëren of downloaden (met de anonimiseer-toggle), 3 in Intune
  plakken. De lange scriptbox en de zes Intune-stappen staan in stap 2 en 3
  en niet meer onder elkaar op één scherm.

### F. Foutcodes

Sticky zoekveld, groepering per familie (Win32 `0x87D1…`, MSI `16xx`, HTTP,
Delivery Optimization, Windows `0x8007…`), een kopieerknop per code, en
wanneer de pagina vanuit een resultaat wordt geopend een link "zoek in dit
pakket" die de Bestanden-tab met die code als query opent.

### G. Ontwerptokens

Eén set semantische tokens in `PAGE_CSS`, in beide thema's gedefinieerd:

```css
--ok / --ok-bg      --warn / --warn-bg
--bad / --bad-bg    --unk / --unk-bg
--surface-2         --accent-soft
```

Alle 30 hardcoded statuskleuren en de per-component dark-overrides gaan
weg; kaarten, chips, verdict, inbox-stippen en de summary gebruiken dezelfde
tokens. Daarnaast: één typeschaal (0,78 / 0,86 / 0,92 / 1 / 1,25 rem),
`tabular-nums` op alle tabellen en tijden, en de componentstijlen uit de elf
`<style>`-blokken samengevoegd in `PAGE_CSS` (de sandboxed viewers houden hun
inline CSS, want daar is `style-src 'unsafe-inline'` de enige optie).

### H. Mobiel

- Header: nav achter een menu-knop, nooit wrappen.
- Contextbalk: acties onder de titel, volle breedte.
- Tabs scrollen horizontaal.
- Bevindingen: bewijsknop onder de tekst.
- Bestanden: boom als inklapbaar blok van maximaal 16 rem boven de viewer.

## Fasering

Elke fase is los te mergen en laat de suite groen.

| Fase | Inhoud | Raakt |
|------|--------|-------|
| 1 | Semantische tokens; hardcoded kleuren vervangen; ragged grid fixen (vaste 2/3-koloms grid); mobiele nav-menu; topbar-acties in "Meer"-menu | `PAGE_CSS`, `NAV`, `DIAG_PAGE`, `REPORT_PAGE`, `CMTRACE_PAGE` |
| 2 | `render_result_shell()` met contextbalk en tabstrip; timeline en cmtrace gebruiken de shell; analysekaart wordt tabteller | `render_diag_page`, `diag_timeline`, cmtrace-route, `render_analysis_card` |
| 3 | Overzicht "bevindingen eerst": `render_dashboard_cards` gesplitst in `render_findings`, `render_healthy`, `render_not_collected`; detailsecties zonder nested scroll | `render_dashboard_cards`, `render_dashboard_sections`, `_render_check_card` |
| 4 | Bestanden-tab op volle hoogte; viewer-breadcrumb en Download in de viewerbalk; CMTrace-pagina op de shell | `DIAG_PAGE`, `CMTRACE_PAGE`, `render_file_tree` |
| 5 | Homepage (tegels weg, recent omhoog); uploadpagina's op de shell | `LANDING_PAGE`, `UPLOAD_PAGE` |
| 6 | Inbox vloot-lijst en setup-wizard; foutcodes gegroepeerd met sticky zoek | inbox-templates, `/errorcodes` |

Fase 1 is puur CSS en template-tekst en kan in één PR.

**Fase 1 is uitgevoerd.** Wat er is gebeurd:

- `PAGE_CSS` heeft één tokenset in het PayloadKit-palet (`--page`, `--bg`,
  `--accent`, `--surface`, …) plus semantische statustokens
  `--ok/--warn/--bad/--unk/--info` met `-bg`- en `-bd`-varianten, in licht én
  donker. Alle status-hexwaarden in componentregels en de losse
  `html.dark`-overrides per component zijn weg; de sandboxed viewers
  gebruiken dezelfde palet-waarden.
- `--border2` en `--row-border` bestonden alleen in de viewer-CSS maar werden
  ook op de diagnostics-pagina gebruikt; ze zijn nu gedefinieerd.
- Het kaartgrid is 3, 2 of 1 kolom(men) per viewport, gelijk in elke groep.
- Navigatie: pill-links, de huidige pagina krijgt `aria-current`, en onder
  720 px verdwijnen de links achter een menuknop (thema-knop blijft zichtbaar).
- Diagnostics-topbar: zichtbaar blijven Copy findings, Raw logs en **More**
  (`<details class="menu">`) met Download this file, Download package, Open
  inbox (drop-off), dashboard.json, summary.json (als de timeline klaar is),
  New upload en Delete from server (niet voor drop-off-jobs). Esc of een klik
  buiten het menu sluit het.
- Topbar-CSS van de drie resultaatpagina's staat nu één keer in `PAGE_CSS`.
- Het lettertype staat als `Inter, system-ui, …` in de stack maar wordt nog
  niet geladen; self-hosten van Inter en JetBrains Mono volgt apart. Fase 2 en 3 zijn de
kern van het voorstel; fase 4 tot 6 kunnen los volgen.

## Bewust niet in dit voorstel

- Geen React, htmx of client-side router: de app is bewust één module zonder
  build-stap en de CSP-nonce-aanpak werkt daar goed mee.
- Geen wijziging aan het upstream timelinerapport in de iframe.
- Geen i18n: de UI blijft Engels, dit document is Nederlands omdat de rest
  van de documentatie dat ook is.
- Geen nieuwe serverstate: recent uploads blijven in `localStorage`.
