# Project Report: Cybersecurity Awareness & Threat Intelligence Dashboard
**Abstract.** A defensive platform that unifies synthetic threat intelligence and security-awareness training. It validates, enriches, scores, correlates and visualizes indicators and vulnerabilities, and educates users through modules and quizzes.
**Introduction / Problem.** Feeds, CVE lists and training are siloed; teams over-trust indicators and suffer alert fatigue.
**Objectives.** Actionable, honest intelligence (risk vs confidence), contextual vulnerability priority, awareness measurement.
**Cybersecurity Awareness.** Modules on phishing, passwords, MFA, ransomware, privacy and more (see `awareness/modules.json`).
**Cyber Threat Intelligence & Types.** Strategic, tactical, operational, technical; focus technical + tactical + awareness (`docs/CONCEPTS.md`).
**IOC/IOA.** IOCs are artifacts; IOAs are behaviors; a match is not proof of compromise.
**Lifecycle.** Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Closed.
**Proposed System & Architecture.** Flask API, SQLite, engines in `backend/services`, static Chart.js frontend.
**Synthetic Dataset.** 2,400 records using RFC 5737/3849 IPs, example.* and .invalid domains, random SHA-256-style hashes; 60 synthetic CVEs.
**Validation / Enrichment.** Syntax-only validation; local-only enrichment.
**Scoring.** Risk (6 weighted factors), confidence (4 factors), source grades A-D.
**Correlation / ATT&CK.** Union-find clusters; evidence-gated technique mapping.
**Vulnerability Awareness.** Priority = CVSS + asset + exposure + exploitation + patch.
**Alerts / SOC workflow.** Threshold alerts merged by window; status workflow and notes.
**Awareness Center / Quiz / Executive Dashboard.** 15 modules, 31 questions, score bands, recommendations, plain-language summary.
**Testing.** 37 pytest tests with auto-generated report (`reports/test_report.md`).
**Security.** No indicator contact, sanitization, escaping, RBAC, rate limiting, audit log.
**Results.** All tests pass; demo scenario THR-2026-001 reproduces risk 78 / confidence 85.
**Limitations / Future Scope / Conclusion.** Synthetic scope and heuristic weights; future authorized feeds and SIEM/SOAR. The project shows how intelligence plus awareness supports better defensive decisions.
