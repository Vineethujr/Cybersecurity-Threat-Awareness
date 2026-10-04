# Concepts & Design Notes
**Awareness vs CTI.** Awareness helps people recognize and avoid risk (phishing, passwords, MFA, updates, reporting). CTI is analyzed information about threats that supports defensive decisions. This project = human defense + technical intelligence.

## Glossary (simple / technical)
| Term | Simple | Technical |
|---|---|---|
| IOC | A clue that something bad may have happened (bad IP, domain, hash) | Artifact associated with malicious activity; reactive, can go stale |
| IOA | A suspicious *behavior* in progress | Indicator of Attack: behavior patterns regardless of specific artifacts |
| Vulnerability / CVE | A flaw / its public ID | CVE-YYYY-NNNN identifier from the CVE program |
| CVSS | 0-10 severity of a flaw | Standard scoring of technical characteristics; not business risk |
| Threat feed | A stream of indicators | Machine-readable intel (CSV/JSON/STIX via TAXII) |
| Threat actor / TTP | Who/how attackers work | Tactics, Techniques, Procedures; grouping is judgement, not proof |
| ATT&CK | Catalog of attacker behavior | Tactic = why, technique = how, sub-technique = specific how |
| Enrichment | Adding context | Attach first/last seen, category, scores, source, related items |
| Correlation | Connecting related items | Cluster by shared campaign/CVE/time; shows relationship, not attribution |
| Threat hunting | Proactively looking | Hypothesis-driven search of telemetry for undetected activity |
| SOC | Team watching security | Security Operations Center: monitoring, triage, response |

## Pipeline
Feed -> collect -> normalize -> validate -> extract IOC -> classify -> score -> ATT&CK (if justified) -> DB -> correlate -> dashboard -> awareness module -> analyst/user.

## Threat-intel types
Strategic (executive trends), Tactical (attacker TTPs), Operational (specific campaigns), Technical (IOCs). Focus: technical + tactical + awareness.

## IOC lifecycle
Observed -> Validated -> Enriched -> Scored -> Investigated -> Monitored -> Expired/Closed. **IOC match != confirmed compromise** (stale, shared, or context-free indicators).

## Risk vs confidence, source reliability
Risk = how concerning; confidence = trust in the evidence (risk 90 / confidence 25 = weak evidence; risk 70 / confidence 95 = solid, meaningful). Sources: A Highly Reliable (Internal SOC), B Usually (Security Vendor, Research Report), C Fairly (Public Feed, Community), D Unknown. Source reliability is one input; item confidence also depends on corroboration, freshness and context.

## Five labels
OBSERVATION (raw/weak sighting) < INDICATOR (valid, moderate confidence) < ALERT (open triage lead) < THREAT (high confidence + risk) < INCIDENT (only when an admin confirms).

## Threat categories
See `GET /api/categories` (description, common indicators, impact, controls, awareness, actions for all 10).

## Vulnerability prioritization
CVSS + asset criticality + exposure + exploitation evidence + patch actionability. A 9.8 on an isolated test box (~45) can rank below a 7.5 on an internet-facing, actively exploited system (~90).

## Alert fatigue
Analysts drown in duplicates. `correlate_alerts` merges same threat+type within 5 minutes: 100 sightings -> 1 alert with observation_count 100. Cluster alerts are raised only for the lead member.

## SOC Tier 1 workflow
Feed -> IOC -> validate -> enrich -> risk+confidence -> alert -> queue -> triage -> correlate -> investigate -> escalate / monitor / resolve / false positive -> document.

## Incident-response lifecycle (educational)
Preparation, Detection/Identification, Containment, Eradication, Recovery, Lessons learned (frameworks vary in wording). Checklist: know who to call; preserve evidence; record timeline; contain per policy; verify recovery; write lessons learned. No destructive actions.

## Limitations of intelligence
Shared IPs, reassigned domains, mixed-use cloud hosting, stale indicators, disagreeing feeds, variable confidence, correlation != attribution. Intelligence supports analyst judgement.

## Industry relevance
SOCs, banks, cloud, IT, government, e-commerce, healthcare, universities, MSSPs and consultancies blend external intel with internal telemetry. Roles demonstrated: SOC/cyber analyst (triage), CTI analyst (enrichment/scoring), IR analyst (workflow), security engineer (API/controls), vulnerability analyst (prioritization), awareness specialist (modules/quiz), threat hunter (correlation/ATT&CK pivots).
