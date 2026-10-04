"""Dashboard statistics, ATT&CK summaries, vulnerability lists and the executive summary."""
import json
import pandas as pd
from .risk_engine import SEVERITIES

ACTIVE = "('NEW','UNDER_REVIEW','MONITORING')"


def _pairs(conn, sql, params=()):
    return [{"label": r[0], "count": r[1]} for r in conn.execute(sql, params)]


def dashboard_stats(conn) -> dict:
    one = lambda sql: conn.execute(sql).fetchone()[0]
    total = one("SELECT COUNT(*) FROM threats")
    cards = {
        "total_threats": total,
        "critical_threats": one("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'"),
        "high_threats": one("SELECT COUNT(*) FROM threats WHERE severity='HIGH'"),
        "active_indicators": one(f"SELECT COUNT(*) FROM threats WHERE status IN {ACTIVE}"),
        "open_investigations": one("SELECT COUNT(*) FROM alerts WHERE status='INVESTIGATING'"),
        "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
        "average_confidence": round(one("SELECT COALESCE(AVG(confidence_score),0) FROM threats"), 1),
        "vulnerabilities_tracked": one("SELECT COUNT(*) FROM vulnerabilities"),
    }
    sev = {r["label"]: r["count"] for r in _pairs(conn, "SELECT severity, COUNT(*) FROM threats GROUP BY severity")}
    bucket = lambda col: _pairs(conn, f"SELECT CASE WHEN {col}<=20 THEN '0-20' WHEN {col}<=40 THEN '21-40' "
                                      f"WHEN {col}<=60 THEN '41-60' WHEN {col}<=80 THEN '61-80' ELSE '81-100' END b, COUNT(*) "
                                      f"FROM threats GROUP BY b ORDER BY b")
    cats = _pairs(conn, "SELECT category, COUNT(*) c FROM threats GROUP BY category ORDER BY c DESC")
    return {
        "cards": cards,
        "charts": {
            "severity": [{"label": s, "count": sev.get(s, 0)} for s in SEVERITIES],
            "category": cats, "top_categories": cats[:5],
            "ioc_types": _pairs(conn, "SELECT indicator_type, COUNT(*) c FROM indicators GROUP BY indicator_type ORDER BY c DESC"),
            "tactics": _pairs(conn, "SELECT tactic, COUNT(*) c FROM attack_mappings GROUP BY tactic ORDER BY c DESC"),
            "risk_distribution": bucket("risk_score"), "confidence_distribution": bucket("confidence_score"),
            "vuln_severity": _pairs(conn, "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"),
            "status": _pairs(conn, "SELECT status, COUNT(*) FROM threats GROUP BY status"),
        },
    }


def dashboard_trends(conn) -> dict:
    df = pd.read_sql_query("SELECT first_seen, category, severity FROM threats", conn)
    if df.empty:
        return {"labels": [], "total": [], "by_category": {}}
    df["month"] = df["first_seen"].str[:7]
    total = df.groupby("month").size()
    by_cat = df.pivot_table(index="month", columns="category", values="severity", aggfunc="count", fill_value=0)
    return {"labels": list(total.index), "total": [int(x) for x in total.values],
            "by_category": {c: [int(x) for x in by_cat[c].values] for c in by_cat.columns}}


def attack_summary(conn) -> dict:
    return {
        "tactics": _pairs(conn, "SELECT tactic, COUNT(*) c FROM attack_mappings GROUP BY tactic ORDER BY c DESC"),
        "techniques": [dict(r) for r in conn.execute(
            "SELECT technique, technique_id_optional AS technique_id, tactic, COUNT(*) AS count FROM attack_mappings "
            "GROUP BY technique, technique_id_optional, tactic ORDER BY count DESC")],
        "unmapped_threats": conn.execute("SELECT COUNT(*) FROM threats WHERE threat_id NOT IN (SELECT threat_id FROM attack_mappings)").fetchone()[0],
        "note": "Only records with sufficient evidence are mapped; unmapped records are intentionally NOT forced into ATT&CK.",
    }


def threats_for_technique(conn, technique_id):
    return [dict(r) for r in conn.execute(
        "SELECT t.threat_id, t.threat_name, t.category, i.indicator_value, t.severity, t.risk_score, t.confidence_score, t.status "
        "FROM attack_mappings m JOIN threats t ON t.threat_id=m.threat_id JOIN indicators i ON i.threat_id=t.threat_id "
        "WHERE m.technique_id_optional=? ORDER BY t.risk_score DESC LIMIT 100", (technique_id,))]


def list_vulnerabilities(conn, severity=None, sort="priority"):
    order = {"priority": "priority_score DESC", "cvss": "cvss_score DESC", "published": "published_date DESC"}.get(sort)
    if not order:
        raise ValueError("sort must be priority, cvss or published")
    w, p = ("WHERE severity=?", [severity.upper()]) if severity else ("", [])
    return [dict(r) for r in conn.execute(f"SELECT * FROM vulnerabilities {w} ORDER BY {order}", p)]


def executive_summary(conn) -> dict:
    """Plain-language management view."""
    s = dashboard_stats(conn)
    c = s["cards"]
    vulns = list_vulnerabilities(conn)
    urgent = [v for v in vulns if v["priority_score"] >= 75]
    vcat = _pairs(conn, "SELECT product_category, COUNT(*) c FROM vulnerabilities WHERE priority_score>=60 GROUP BY product_category ORDER BY c DESC LIMIT 5")
    trend = _pairs(conn, "SELECT substr(created_at,1,7), ROUND(AVG(overall_score),1) FROM quiz_results GROUP BY 1 ORDER BY 1")
    cat_totals = {}
    for r in conn.execute("SELECT category_scores FROM quiz_results"):
        for k, v in json.loads(r[0]).items():
            cat_totals.setdefault(k, []).append(v)
    weak = sorted(({"label": k, "score": round(sum(v) / len(v))} for k, v in cat_totals.items()), key=lambda x: x["score"])[:3]
    top_cat = s["charts"]["category"][0]["label"].title() if s["charts"]["category"] else "n/a"
    priorities = []
    if c["critical_threats"]:
        priorities.append(f"Triage the highest-risk alerts first ({c['open_alerts']} open). Alerts are leads, not confirmed incidents.")
    if urgent:
        priorities.append(f"Patch or mitigate {len(urgent)} high-priority vulnerabilities (internet-facing / actively exploited in the demo data).")
    if weak:
        priorities.append(f"Run awareness refreshers on the weakest topics: {', '.join(w['label'] for w in weak)}.")
    priorities.append("Review closed and false-positive indicators regularly so stale intelligence does not add noise.")
    return {
        "headline": f"{c['active_indicators']} of {c['total_threats']} synthetic threat records are active; {c['critical_threats']} are rated critical severity.",
        "cards": c, "top_threat_categories": s["charts"]["top_categories"], "top_vulnerability_categories": vcat,
        "awareness_trend": trend, "top_awareness_weaknesses": weak, "priorities": priorities,
        "disclaimer": "All data is synthetic. Awareness scores are educational and are not an assessment of any person.",
    }
