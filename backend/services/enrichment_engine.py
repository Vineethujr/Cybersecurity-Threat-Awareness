"""
Local-only enrichment. LOOKUP IN THE LOCAL DATABASE ONLY - the searched IP/domain/URL is never contacted.
Optional future integrations (WHOIS, passive DNS, vendor APIs) are described in the docs, not implemented.
"""
from .ioc_validator import validate_indicator
from .risk_engine import RELIABILITY, interpret

PRIVACY_NOTE = "Lookup performed against the local synthetic dataset only. No connection was made to the indicator."


def enrich_indicator(conn, value: str) -> dict:
    v = validate_indicator(value)
    out = {"query": value, "validation": v, "known_in_demo_dataset": False, "note": PRIVACY_NOTE}
    if not v["valid"]:
        return out
    rows = [dict(r) for r in conn.execute(
        "SELECT t.*, i.indicator_type, i.indicator_value, s.source_name, s.reliability FROM indicators i "
        "JOIN threats t ON t.threat_id=i.threat_id LEFT JOIN sources s ON s.source_id=t.source_id "
        "WHERE i.indicator_value=? ORDER BY t.risk_score DESC", (v["normalized_value"],))]
    out["indicator_type"] = v["indicator_type"]
    if not rows:
        out["summary"] = "Not present in the demo dataset. Absence of data is NOT evidence that it is safe."
        return out
    top = rows[0]
    tids = [r["threat_id"] for r in rows]
    ph = ",".join("?" * len(tids))
    campaigns = {r["campaign_id"] for r in rows if r["campaign_id"]}
    related = []
    if campaigns:
        cph = ",".join("?" * len(campaigns))
        related = [dict(r) for r in conn.execute(
            f"SELECT i.indicator_type, i.indicator_value, t.threat_id FROM threats t JOIN indicators i ON i.threat_id=t.threat_id "
            f"WHERE t.campaign_id IN ({cph}) AND i.indicator_value!=? LIMIT 25", (*campaigns, v["normalized_value"]))]
    out.update({
        "known_in_demo_dataset": True,
        "threat_ids": tids, "threat_name": top["threat_name"],
        "associated_categories": sorted({r["category"] for r in rows}),
        "risk_score": top["risk_score"], "severity": top["severity"], "confidence": top["confidence_score"],
        "first_seen": min(r["first_seen"] for r in rows), "last_seen": max(r["last_seen"] for r in rows),
        "status": top["status"], "observation_count": sum(r["observation_count"] for r in rows),
        "source": top["source_name"], "source_reliability": f"{top['reliability']} - {RELIABILITY[top['reliability']]['label']}",
        "related_indicators": related,
        "related_alerts": [dict(r) for r in conn.execute(f"SELECT alert_id, alert_type, severity, status FROM alerts WHERE threat_id IN ({ph})", tids)],
        "mitre_mapping": [dict(r) for r in conn.execute(f"SELECT DISTINCT tactic, technique, technique_id_optional FROM attack_mappings WHERE threat_id IN ({ph})", tids)],
        "analyst_notes": [dict(r) for r in conn.execute(f"SELECT note, created_at FROM analyst_notes WHERE threat_id IN ({ph}) ORDER BY created_at", tids)],
        "interpretation": interpret(top["risk_score"], top["confidence_score"]),
        "summary": "IOC MATCH != CONFIRMED COMPROMISE. Treat as evidence for investigation.",
    })
    return out
