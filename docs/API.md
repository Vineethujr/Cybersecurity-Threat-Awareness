# REST API
Auth: `X-API-Key` header for write endpoints (`demo-analyst-key`, `demo-admin-key`; change in `.env`). Errors are JSON `{"error": "..."}`. Codes: 200/201 ok, 400 bad query, 401 no/invalid key, 403 role too low, 404 not found, 422 invalid body, 429 rate limited.

| Method | Endpoint | Auth | Request | Response / Validation |
|---|---|---|---|---|
| GET | /api/threats | none | `severity, category, indicator_type, status, min_risk, max_risk, min_confidence, date_from, date_to, q, sort(newest\|risk\|confidence\|observed), page, page_size` | `{items,total,page,page_size}`; enums validated (400) |
| GET | /api/threats/{id} | none | - | Full detail: scores, related, alerts, notes, ATT&CK, timeline (404) |
| POST | /api/threats | analyst | `threat_name, category, severity, indicator_value, [source_name, description, cve_id, campaign_id]` | 201 `{threat_id,risk_score,confidence_score}`; risk/confidence computed by server; duplicates become an observation (200) |
| PUT | /api/threats/{id} | analyst (`incident_confirmed`: admin) | `status, severity, description, incident_confirmed` | 200 / 403 / 404 / 422 |
| POST | /api/threats/{id}/notes | analyst | `{note}` (sanitized, max 2000) | 201 `{note_id}` |
| GET | /api/indicators/search?q= | none | IP/domain/URL/hash/CVE | Enrichment result; local lookup only |
| GET | /api/dashboard/stats | none | - | cards + 9 chart series |
| GET | /api/dashboard/trends | none | - | monthly counts, by category |
| GET | /api/dashboard/executive | none | - | management summary |
| GET | /api/alerts?status= | none | - | alerts by risk |
| PUT | /api/alerts/{id}/status | analyst | `{status}` NEW/INVESTIGATING/MONITORING/RESOLVED/FALSE_POSITIVE | 200 / 404 / 422 |
| GET | /api/vulnerabilities?severity=&sort= | none | - | list with priority score |
| GET | /api/attack/summary, /api/attack/techniques/{Txxxx} | none | - | tactic/technique counts, records |
| GET | /api/awareness/modules | none | - | 15 modules |
| GET | /api/quiz | none | - | questions without answers |
| POST | /api/quiz/submit | none | `{answers:{Q01:"C",...}}` | score, category scores, weakest, recommendations |
