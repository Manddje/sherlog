# Uitvoering reviewsuggesties (plan: kijk-naar-deze-app-resilient-boot.md)

## Fase 1 — technische safety-fixes
- [ ] A1.1 read_text_tolerant: cap vóór lezen (OOM)
- [ ] A1.2 zip-extractie + report_raw + html-view naar to_thread
- [ ] A1.3 timeout killt procesgroep (pwsh)
- [ ] A1.4 gedeeld zip-bomb-budget over losse zips
- [ ] A1.5 job-dir-scans naar to_thread
- [ ] A3.11 /health: JOBS_DIR-writability
- [ ] A3.16 package.zip cachen
- [ ] A3.14 logging bij upload-rejects

## Fase 2 — dedup & cleanup
- [ ] A2.6 themejs één placeholder
- [ ] A2.9 dode code weg (parse_eventlog_records, _wait_for_result, _attr-dup, .dockerignore, ongebruikte pngs)
- [ ] A2.8 job-guard helper
- [ ] A2.7 build_dashboard: records-cache

## Fase 3 — nette foutpagina's (413/429/404), stderr-truncatie
## Fase 4 — B1.1 timeline op losse logs; B1.2 verdict-banner + severity-sortering
## Fase 5 — B2.7 installed-apps sectie; B3.9 export/copy findings; B3.10 expiry; B3.12 inbox-link/prefill
## Fase 6 — B1.4 advies per check; B2.8 content-delivery-correlatie; B2.6 ESP/Autopilot-check
## Fase 7 — B1.5 package-brede zoekfunctie
## Fase 8 — B3.11 inbox: groepering per device + diff
## Fase 9 — B4.13 mobile + B4.14 a11y
## Fase 10 — README, tests (auth/cleanup/timeout), A2.10 static assets, B1.3 Graph app-namen, A3.15 python-versie
