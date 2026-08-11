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
