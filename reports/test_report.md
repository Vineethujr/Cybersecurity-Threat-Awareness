# Automated Test Report

| Test ID | Scenario | Input | Expected Result | Actual Result | Pass/Fail |
|---|---|---|---|---|---|
| T01 | Valid IPv4 | 198.51.100.25 | valid, IP_ADDRESS | As expected | Pass |
| T02 | Invalid IPv4 | 999.1.1.1 | invalid | As expected | Pass |
| T03 | Valid IPv6 | 2001:DB8 | 1 | As expected | Pass |
| T04 | Valid domain | Login-Check.INVALID | valid, lowercased | As expected | Pass |
| T05 | Invalid domain | bad..example.com | invalid | As expected | Pass |
| T06 | Valid URL | hxxps://login-check[.]invalid/verify | refanged https URL | As expected | Pass |
| T07 | MD5-format hash | 32 hex chars | FILE_HASH/MD5 | As expected | Pass |
| T08 | SHA1-format hash | 40 hex chars | SHA1 | As expected | Pass |
| T09 | SHA256-format hash | 64 hex chars | SHA256 | As expected | Pass |
| T10 | Valid CVE | cve-2026-90001 | CVE_ID uppercase | As expected | Pass |
| T11 | Invalid CVE | CVE-26-1 | invalid | As expected | Pass |
| T12 | Threat creation | valid payload | new id, risk/confidence computed server-side | As expected | Pass |
| T13 | Risk calculation | HIGH, conf 85, fresh, 14 obs, source A | score 0-100, level matches score | As expected | Pass |
| T14 | Confidence calculation | strong vs weak evidence | strong > weak, bounded | As expected | Pass |
| T15 | Source reliability | grades A-D | A > B > C > D | As expected | Pass |
| T16 | IOC enrichment | 198.51.100.25 | known, category PHISHING, no network note | As expected | Pass |
| T17 | Indicator search API | q=login-check.invalid | risk 78, HIGH, conf 85 | As expected | Pass |
| T18 | Threat correlation | shared campaign_id | one cluster of 3 | As expected | Pass |
| T19 | Duplicate observation | same indicator again | count incremented, no new record | As expected | Pass |
| T20 | Alert generation | high risk+confidence | RISK_THRESHOLD alert; low risk none; FP none | As expected | Pass |
| T21 | Alert correlation | 100 alerts in 5 min | 1 alert, observation_count 100 | As expected | Pass |
| T22 | Alert status update | PUT status with key | 200; without key 401; bad status 422 | As expected | Pass |
| T23 | Analyst notes | POST note with HTML | stored, tags stripped, visible in detail | As expected | Pass |
| T24 | ATT&CK mapping | strong vs weak evidence | mapped T1566 vs not mapped | As expected | Pass |
| T25 | Vulnerability priority | CVSS 9.8 isolated test vs CVSS 7.5 internet-facing exploited | second higher | As expected | Pass |
| T26 | Dashboard stats | GET | total 2400+, 9 chart series + trends | As expected | Pass |
| T27 | Severity filtering | severity=CRITICAL | all rows CRITICAL | As expected | Pass |
| T28 | Category filtering | category=RANSOMWARE | all rows RANSOMWARE | As expected | Pass |
| T29 | Threat sorting | sort=risk | descending risk | As expected | Pass |
| T30 | Awareness module retrieval | GET modules | 15 modules with required sections | As expected | Pass |
| T31 | Quiz scoring | all correct / all blank | 100 vs 0 | As expected | Pass |
| T32 | Learning recommendation | phishing 40, social 55, passwords 90 | complete / review / none | As expected | Pass |
| T33 | Empty dataset | stats on empty DB | zeros, no crash | As expected | Pass |
| T34 | API validation | bad indicator, bad filter, XSS-ish input | 4xx errors, no crash | As expected | Pass |
| T35 | Database persistence | create then reopen new connection | record present | As expected | Pass |
| T36 | Entity distinction | demo threat and low-confidence record | THREAT; incidents never automatic | As expected | Pass |
| T37 | RBAC | analyst tries incident_confirmed | 403; admin allowed | As expected | Pass |
