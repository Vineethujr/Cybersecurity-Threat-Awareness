# GitHub, Screenshots, Resume & Interview

## Git commands
```bash
git init && git branch -M main
git add . && git commit -m "Initialize cybersecurity threat intelligence dashboard"
git remote add origin https://github.com/<you>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
git push -u origin main
```
Better proof of work: commit in stages using these messages: Add synthetic threat intelligence dataset · Implement IOC validation · Add threat enrichment engine · Implement risk and confidence scoring · Add threat correlation · Implement security alert engine · Add ATT&CK mapping module · Build vulnerability awareness module · Create SOC threat dashboard · Add IOC search functionality · Build threat investigation view · Create cybersecurity awareness center · Add security awareness quiz · Implement awareness scoring · Add executive cybersecurity summary · Implement automated tests · Complete README and documentation.

Repo description: *Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.*
Topics: cybersecurity threat-intelligence cti soc ioc mitre-attack security-awareness python flask vulnerability-management incident-response security-analytics defensive-security

## Screenshot filenames (save in `screenshots/`)
01_project_structure, 02_architecture, 03_synthetic_dataset, 04_threat_dashboard, 05_summary_cards, 06_severity_distribution, 07_category_chart, 08_ioc_distribution, 09_threat_timeline, 10_risk_distribution, 11_confidence_distribution, 12_ioc_search, 13_ioc_result, 14_threat_detail, 15_risk_score, 16_confidence_score, 17_related_indicators, 18_attack_mapping, 19_vulnerability_dashboard, 20_alert_dashboard, 21_alert_investigation, 22_analyst_notes, 23_awareness_center, 24_phishing_module, 25_password_mfa_module, 26_ransomware_module, 27_quiz, 28_quiz_result, 29_category_scores, 30_learning_recommendations, 31_executive_dashboard, 32_automated_tests, 33_api_response, 34_database, 35_github_commits, 36_github_repository, 37_readme_preview (all `.png`).

## Resume bullets
- Built a defensive threat-intelligence and awareness platform (Python, Flask, SQLite) processing 2,400 synthetic IOC records with validation, enrichment, and separate risk and confidence scoring.
- Implemented threat correlation, alert de-duplication, and evidence-gated MITRE ATT&CK mapping, plus context-based vulnerability prioritization beyond raw CVSS.
- Delivered a SOC-style dashboard, RBAC/rate-limited REST API, awareness center with 31-question quiz, and 37 automated tests.

**2-line description:** Defensive SOC dashboard that turns synthetic IOCs and CVEs into scored, correlated, ATT&CK-mapped alerts, paired with an awareness center, quiz and executive summary. Python/Flask/SQLite with 37 automated tests.

**LinkedIn:** I built a Cybersecurity Awareness & Threat Intelligence Dashboard that combines technical CTI workflows with user awareness training. It validates and enriches synthetic indicators (IP, domain, URL, hash, CVE), separates risk from confidence, correlates related indicators, reduces alert fatigue, maps behavior to MITRE ATT&CK only when evidence supports it, and prioritizes vulnerabilities using exposure and asset context. The awareness side offers 15 modules, a quiz, personalized recommendations and an executive summary. Everything is synthetic and defensive. Skills: CTI, SOC triage, IOC analysis, ATT&CK, vulnerability management, risk scoring, security awareness, Python, Flask, SQL, security analytics, incident-response concepts.

## Interview Q&A
1. **Explain your project.** I built a dashboard combining technical threat intelligence and awareness training. It validates synthetic indicators, enriches them locally, computes separate risk and confidence scores, correlates related observations, maps ATT&CK where evidence exists, tracks vulnerabilities, and gives analysts an alert/investigation workflow. Users get modules, quizzes and personalized recommendations. It is entirely defensive.
2. **What is CTI?** Analyzed information about threats that supports defensive decisions; raw data becomes intelligence after validation, context and relevance assessment.
3. **Does an IOC match prove compromise?** No. Indicators go stale, IPs are shared, feeds have false positives. I treat a match as evidence for investigation combined with confidence, risk, source reliability and related observations.
4. **Risk vs confidence?** Risk is how concerning; confidence is how strongly evidence supports it. Risk 90 with confidence 25 means potentially serious but unproven, so validate first.
5. **What is enrichment?** Adding context: type, first/last seen, category, scores, source reliability, related indicators/alerts, ATT&CK. It helps the analyst judge relevance. Mine uses only local data and never contacts the indicator.
6. **ATT&CK usage?** Tactic = objective, technique = method. I map only with confidence >= 60 and repeated observations, never from a bare IP or domain, and I tell the analyst to confirm.
7. **Vulnerability prioritization?** Weighted CVSS, asset criticality, exposure, exploitation evidence and patch availability. A 9.8 on an isolated test box scored lower than a 7.5 on an internet-facing, exploited system.
8. **Correlation?** Grouping records by shared campaign or CVE into clusters for context; it shows relationship, not attribution. I also merge repeated alerts (100 sightings -> 1 alert) to reduce alert fatigue.
9. **How would a SOC analyst use it?** Open the alert queue, sort by risk and confidence, search/validate the indicator, review enrichment and related indicators, check ATT&CK, add notes, set status (investigating/monitoring/resolved/false positive).
10. **Limitations and improvements?** Synthetic data, heuristic weights, simple correlation. Next: authorized STIX/TAXII feeds, KEV/EPSS, SIEM/SOAR, IOC expiry, better confidence models, ATT&CK Navigator, Docker/CI.

## Future improvements (defensive)
Authorized live feeds, STIX/TAXII, SIEM/SOAR, CVE/KEV feeds, EPSS-style prioritization, deduplication, IOC expiration, automated enrichment, clustering, ATT&CK Navigator, email/endpoint/cloud telemetry, threat-hunting views, executive reports, role-based dashboards, Docker, CI/CD, centralized logging.
