# Uitvoering reviewsuggesties (plan: kijk-naar-deze-app-resilient-boot.md)

Alle fases uitgevoerd op 2026-08-11, commit per fase, suite groen (128 passed).

## Gedaan
- [x] Fase 1 — safety: OOM-cap read_text_tolerant, extractie/scans/reads naar
      to_thread, procesgroep-kill bij timeout, gedeeld zip-bomb-budget,
      /health checkt JOBS_DIR-writability, package.zip gecachet, reject-logging
- [x] Fase 2 — dedup/cleanup: _THEME_JS (10 kopieën weg), _job_guard,
      records-cache in build_dashboard, dode code + ongebruikte pngs weg
- [x] Fase 3 — NOTICE_PAGE voor 413/429/404, stderr/stdout-clip (4000)
- [x] Fase 4 — timeline on demand voor losse logs (POST /result/{id}/analyze),
      verdict-banner + severity-sortering
- [x] Fase 5 — dashboard.json/summary.json exports, Copy findings,
      expiry-hint (created-stamp), installed-apps-sectie, inbox-link + prefill
- [x] Fase 6 — _ADVICE per faalstaat, Autopilot/ESP-checks,
      content-delivery-correlatie
- [x] Fase 7 — pakket-brede zoek (GET /result/{id}/search?q=)
- [x] Fase 8 — inbox: groepering per device + diff vs vorige upload
- [x] Fase 9 — mobile media queries, keyboard/sr-a11y
- [x] Fase 10 — auth/cleanup/timeout-tests, /assets/app.css (CSP style-src
      'self'; viewers inline), Graph app-namen (APP_NAMES_CACHE),
      Dockerfile python-notitie, README + CLAUDE.md bijgewerkt

## Bewust niet gedaan
- build_dashboard opsplitsen in _check_*-functies (risico/ruis vs. winst;
  records-cache + nieuwe checks als aparte blokken volstaan nu)
- lockfile/pip-tools (nieuwe tooling; alleen genoteerd)
- i18n en Dutch-fallback-opruiming (vestigiaal maar onschadelijk)

---

# Collector-scriptreview (2026-08-12, alle fases 1/2/3 uitgevoerd)

Suite groen (142 passed / 1 skipped) + ps-syntax + ASCII-check op beide .ps1's.

## Gedaan
- [x] A1 Write-Output SHERLOG_RESULT/SHERLOG_ERROR-slotregel (Write-Host/
      Write-Warning stromen niet door een pipe — Intune zag nooit de result-URL)
- [x] A2 upload-token altijd geredigeerd uit alle tekstbestanden (transcript
      bevatte de volledige commandline incl. token), ongeacht -Anonymize
- [x] A3 -Anonymize slaat well-known SYSTEM-principals over (anders
      corrumpeert het HKLM\SYSTEM-paden en breekt de PRT-SYSTEM-detectie)
- [x] A4 /collect-script uitgezonderd van basic auth
- [x] A5 remediation download+zip naar %ProgramData%\Sherlog met ACL i.p.v.
      user-writable %TEMP%
- [x] B6 Invoke-Safe: $ErrorActionPreference=Stop + $LASTEXITCODE-checks op
      native tools (mdmdiagnosticstool, wevtutil, reg export, w32tm)
- [x] B7 upload: TimeoutSec, retry+backoff (transient vs. permanent status),
      proxy-auto-detect, https-verplicht, size-preflight, serverfoutmelding
- [x] B8 en-US UI-culture; locale-onafhankelijke JSON-sidecars voor firewall
      en eventlog-Level (server prefereert JSON, valt terug op tekst)
- [x] B9 event-log query: FilterHashtable (Level+StartTime) i.p.v. eerst 200
      pakken en dan filteren — voorkomt "0 errors" op drukke logs
- [x] B10 -Remote: mdmdiag-allareas-zip + volledige evtx-export overgeslagen
      (14-dagen-query i.p.v.)
- [x] B11 try/finally rond packaging; oude zips (>7 dagen) opgeruimd
- [x] B12 (impliciet via B10) kleiner -Remote-pakket
- [x] 13 _MANIFEST.json (versie, profiel, per-stap ok/fout/duur) — alleen
      collector-kant; server toont het nog niet (zie "niet gedaan")
- [x] 14 $ScriptVersion + X-Collector-Version-upload-header
- [x] 15 user-context dsregcmd via one-shot scheduled task (PRT-signaal)
- [x] 16 (deels) GPO-policies-hive, co-management, MDE-onboarding, Delivery
      Optimization, WUfB-registry (ook in -Remote), schijfruimte, time-sync, TPM
- [x] 17 endpoints uitgebreid (WNS, Autopilot ztd/cs.dds), tenant-specifieke
      fef.msuc03-hardcode verwijderd; TLS-issuer-check toegevoegd
- [x] 18 (deels) LastRunUtc/LastResultUrl in HKLM\SOFTWARE\Sherlog,
      once-per-N-hours-guard in het remediation-script
- [x] 19 contract-test: elke _DASH_SOURCES-candidate + hardcoded rglob-namen
      moeten in het collector-script staan
- [x] 20 REMEDIATION_TEMPLATE-duplicaat weg: app.py leest
      Remediate-CollectToSherlog.ps1 van schijf (fallback bij ontbreken)
- [x] 21 server: _SUMMARY.txt altijd als lower-priority laag gemerged
      (device/datum stonden leeg op elk gezond pakket)
- [x] 22 (deels) firewall JSON-twin; eventlog JSON-twin

## Bewust niet gedaan
- Authenticode-signing / SHA-256-pin voor de gedownloade collector (zou bij
  elke serverupdate breken zonder distributiemechanisme) — ACL-restrictie op
  %ProgramData%\Sherlog is de gekozen, praktischere mitigatie
- Server toont manifest-velden (versie/profiel/context) nog niet op de
  diag-pagina — collector schrijft het al, server-integratie is vervolgwerk
- BitLocker, volledige cert-chain-audit, WUfB-log-collectie in -Remote
- Remediation cachet de collector niet op hash (downloadt altijd opnieuw)
- Format-Table -Width-buffer-nuance (A17, low-impact)
