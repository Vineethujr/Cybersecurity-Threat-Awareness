"""Threat records: normalization, seeding, CRUD, filtering, detail view, notes, timeline."""
import csv
from .. import db as _db  # noqa: F401  (kept for package clarity)
from ..utils.sanitize import sanitize_text
from ..utils.timeutil import iso, parse_ts, utcnow
from .alert_engine import ALERT_STATUSES, generate_threat_alert
from .attack_mapper import map_threat
from .correlation_engine import correlate_alerts, correlate_threats
from .ioc_validator import validate_indicator
from .risk_engine import (RELIABILITY, SEVERITIES, SOURCES, calculate_confidence,
                          calculate_threat_risk, interpret)
from .vulnerability_service import calculate_vulnerability_priority

CATEGORIES = ["PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS", "NETWORK THREATS",
              "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
INDICATOR_TYPES = ["IP_ADDRESS", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CVE_ID"]
ENTITY_TYPES = ["OBSERVATION", "INDICATOR", "ALERT", "THREAT", "INCIDENT"]

CATEGORY_KNOWLEDGE = {
    "PHISHING": {"description": "Deceptive messages that try to steal credentials or trick users into risky actions.",
        "common_indicators": "Look-alike sender domains, suspicious links, urgent wording",
        "impact": "Account takeover, fraud, initial foothold", "controls": "Email filtering, MFA, DMARC/SPF/DKIM, URL reputation checks",
        "awareness": "Verify sender and link before acting; report suspicious mail.",
        "actions": ["Review related internal logs", "Check for authorized sightings", "Review email-security telemetry", "Increase phishing awareness", "Monitor for related indicators"]},
    "MALWARE": {"description": "Malicious software activity (defensive, high-level view).", "common_indicators": "File hashes, command-and-control domains/IPs",
        "impact": "Data loss, persistence, system misuse", "controls": "Endpoint protection, application allow-listing, patching",
        "awareness": "Do not open unexpected attachments or run unknown files.",
        "actions": ["Search endpoint telemetry for the hash (do not execute the file)", "Confirm EDR coverage", "Monitor related network indicators"]},
    "RANSOMWARE": {"description": "Malware families associated with encrypting or extorting data.", "common_indicators": "Staging infrastructure, known-family hashes",
        "impact": "Downtime, data loss, extortion", "controls": "Offline backups, patching, least privilege, segmentation, MFA",
        "awareness": "Report odd files/slowdowns immediately; never pay or negotiate alone.",
        "actions": ["Verify backup health and restore tests", "Review privileged-account activity", "Confirm incident-response contacts"]},
    "CREDENTIAL THREATS": {"description": "Attempts to obtain or reuse passwords.", "common_indicators": "Repeated failed sign-ins from one source",
        "impact": "Account compromise", "controls": "MFA, lockout/rate limiting, breached-password checks",
        "awareness": "Use unique passphrases and a password manager.",
        "actions": ["Review authentication logs for the source", "Enforce MFA on exposed accounts", "Check for password reuse exposure"]},
    "WEB THREATS": {"description": "Risky or compromised web content.", "common_indicators": "Redirect URLs, compromised sites",
        "impact": "Drive-by infection, credential theft", "controls": "DNS/web filtering, browser updates",
        "awareness": "Keep browsers updated; avoid unexpected downloads.",
        "actions": ["Review web-proxy/DNS logs for lookups (data only)", "Confirm URL filtering policy", "Notify affected users"]},
    "NETWORK THREATS": {"description": "Suspicious network-level behaviour.", "common_indicators": "Scanning sources, beaconing patterns",
        "impact": "Reconnaissance, covert control channels", "controls": "Firewall rules, segmentation, IDS/NDR",
        "awareness": "Report unknown devices and odd connectivity.",
        "actions": ["Review firewall/IDS logs for the source", "Check for exposed services", "Consider time-boxed monitoring"]},
    "VULNERABILITY EXPOSURE": {"description": "Exposure related to known, unpatched vulnerabilities.", "common_indicators": "CVE identifiers, exposed products",
        "impact": "Unauthorized access via unpatched systems", "controls": "Patch management, asset inventory, exposure reduction",
        "awareness": "Install updates promptly and enable auto-update.",
        "actions": ["Identify affected assets", "Prioritize by exposure and criticality", "Patch or apply vendor mitigations"]},
    "SOCIAL ENGINEERING": {"description": "Manipulating people into unsafe actions.", "common_indicators": "Impersonation, pretexting sender domains",
        "impact": "Fraud, data disclosure", "controls": "Verification procedures, awareness training",
        "awareness": "Verify requests through a trusted second channel.",
        "actions": ["Alert likely targets", "Reinforce verification procedures", "Review related email telemetry"]},
    "DATA EXPOSURE": {"description": "Data that may be publicly or improperly accessible.", "common_indicators": "Public storage URLs, leaked-data references",
        "impact": "Privacy breach, regulatory impact", "controls": "Access reviews, DLP, encryption",
        "awareness": "Share the minimum data with the minimum people.",
        "actions": ["Confirm whether the data is yours", "Review access permissions", "Involve privacy/legal if confirmed"]},
    "ACCOUNT SECURITY": {"description": "Signals of risky account access.", "common_indicators": "Unusual sign-in sources, MFA prompt floods",
        "impact": "Account takeover", "controls": "MFA (phishing-resistant where possible), conditional access",
        "awareness": "Never approve MFA prompts you did not start.",
        "actions": ["Review sign-in history", "Reset credentials if abuse is confirmed", "Enable number-matching/passkeys"]},
}


# ---------------------------------------------------------------- normalization
def normalize_record(raw: dict) -> dict:
    """Validate + normalize a raw threat dict (CSV row or API payload). Raises ValueError."""
    v = validate_indicator(raw.get("indicator_value", ""), raw.get("indicator_type") or None)
    if not v["valid"]:
        raise ValueError("Invalid indicator: " + "; ".join(v["validation_notes"]))
    category = str(raw.get("threat_category") or raw.get("category") or "").strip().upper().replace("_", " ")
    if category not in CATEGORIES:
        raise ValueError(f"category must be one of {CATEGORIES}")
    severity = str(raw.get("severity", "")).strip().upper()
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    status = str(raw.get("status") or "NEW").strip().upper()
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    name = sanitize_text(raw.get("threat_name"), 120)
    if not name:
        raise ValueError("threat_name is required")
    source = str(raw.get("source_name") or "Unknown Source").strip()
    if source not in SOURCES:
        source = "Unknown Source"
    now = iso(utcnow())
    try:
        first = iso(parse_ts(raw.get("first_seen") or now))
        last = iso(parse_ts(raw.get("last_seen") or first))
    except ValueError:
        raise ValueError("first_seen/last_seen must be ISO-8601 timestamps")
    return {
        "threat_id": raw.get("threat_id"), "threat_name": name, "category": category,
        "description": sanitize_text(raw.get("description"), 1000), "severity": severity, "status": status,
        "risk_score": None if raw.get("risk_score") in (None, "") else max(0, min(100, int(float(raw["risk_score"])))),
        "confidence_score": None if raw.get("confidence_score") in (None, "") else max(0, min(100, int(float(raw["confidence_score"])))),
        "first_seen": first, "last_seen": last, "source_name": source,
        "campaign_id": sanitize_text(raw.get("campaign_id"), 40),
        "observation_count": max(1, int(float(raw.get("observation_count") or 1))),
        "country_or_region": sanitize_text(raw.get("country_or_region_optional") or raw.get("country_or_region"), 40),
        "cve_id": (raw.get("cve_id_optional") or raw.get("cve_id") or "").strip().upper(),
        "incident_confirmed": int(float(raw.get("incident_confirmed") or 0)),
        "indicator_type": v["indicator_type"], "indicator_value": v["normalized_value"],
    }


# ---------------------------------------------------------------- inserts
def _source(conn, name):
    row = conn.execute("SELECT source_id, reliability FROM sources WHERE source_name=?", (name,)).fetchone()
    return row["source_id"], row["reliability"]


def _insert(conn, r: dict):
    sid, _ = _source(conn, r["source_name"])
    conn.execute(
        "INSERT INTO threats(threat_id,threat_name,category,description,severity,risk_score,confidence_score,status,"
        "first_seen,last_seen,source_id,campaign_id,observation_count,country_or_region,cve_id,incident_confirmed) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (r["threat_id"], r["threat_name"], r["category"], r["description"], r["severity"], r["risk_score"],
         r["confidence_score"], r["status"], r["first_seen"], r["last_seen"], sid, r["campaign_id"],
         r["observation_count"], r["country_or_region"], r["cve_id"], r["incident_confirmed"]))
    conn.execute("INSERT INTO indicators(threat_id,indicator_type,indicator_value,first_seen,last_seen) VALUES (?,?,?,?,?)",
                 (r["threat_id"], r["indicator_type"], r["indicator_value"], r["first_seen"], r["last_seen"]))
    res = map_threat(r["category"], r["indicator_type"], r["confidence_score"], r["observation_count"], r["status"])
    for m in res["mappings"]:
        conn.execute("INSERT INTO attack_mappings(threat_id,tactic,technique,technique_id_optional) VALUES (?,?,?,?)",
                     (r["threat_id"], m["tactic"], m["technique"], m["technique_id"]))


def seed_database(conn, dataset_csv, vuln_csv):
    for name, grade in SOURCES.items():
        conn.execute("INSERT OR IGNORE INTO sources(source_name, reliability) VALUES (?,?)", (name, grade))
    with open(vuln_csv, newline="", encoding="utf-8") as f:
        for v in csv.DictReader(f):
            p = calculate_vulnerability_priority(float(v["cvss_score"]), int(v["asset_criticality"]), v["exposure"],
                                                 v["exploitation_status_demo"], bool(int(v["patch_available"])))
            conn.execute(
                "INSERT OR IGNORE INTO vulnerabilities(cve_id,product_category,severity,cvss_score,published_date,"
                "patch_available,exploitation_status_demo,description,asset_criticality,exposure,priority_score) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (v["cve_id"], v["product_category"], v["severity"], float(v["cvss_score"]), v["published_date"],
                 int(v["patch_available"]), v["exploitation_status_demo"], sanitize_text(v["description"]),
                 int(v["asset_criticality"]), v["exposure"], p["priority_score"]))
    with open(dataset_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            _insert(conn, normalize_record(row))
    build_alerts(conn)
    conn.commit()


def build_alerts(conn):
    """Generate alerts for every threat, then merge duplicates (alert-fatigue control)."""
    conn.execute("DELETE FROM alerts")
    rows = [dict(r) for r in conn.execute(
        "SELECT t.*, i.indicator_type FROM threats t JOIN indicators i ON i.threat_id=t.threat_id")]
    by_id = {r["threat_id"]: r for r in rows}
    lead = {}
    for c in correlate_threats(rows):
        top = max(c["members"], key=lambda m: by_id[m]["risk_score"])
        lead[top] = c["size"]
    vp = {r["cve_id"]: r["priority_score"] for r in conn.execute("SELECT cve_id, priority_score FROM vulnerabilities")}
    raw = [a for a in (generate_threat_alert(t, lead.get(t["threat_id"], 0), vp.get(t["cve_id"])) for t in rows) if a]
    for a in correlate_alerts(raw):
        conn.execute("INSERT INTO alerts(alert_id,threat_id,timestamp,alert_type,severity,risk_score,confidence_score,"
                     "description,status,observation_count,last_observed,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (a["alert_id"], a["threat_id"], a["timestamp"], a["alert_type"], a["severity"], a["risk_score"],
                      a["confidence_score"], a["description"], a["status"], a["observation_count"],
                      a["last_observed"], a["timestamp"]))


def next_threat_id(conn) -> str:
    n = conn.execute("SELECT COALESCE(MAX(CAST(SUBSTR(threat_id,10) AS INTEGER)),0) FROM threats").fetchone()[0]
    return f"THR-2026-{n + 1:03d}"


def record_observation(conn, indicator_value, seen_at=None):
    """A repeat sighting of a KNOWN indicator increments its count instead of creating a duplicate record."""
    v = validate_indicator(indicator_value)
    row = conn.execute("SELECT threat_id FROM indicators WHERE indicator_value=? LIMIT 1", (v["normalized_value"],)).fetchone()
    if not row:
        return None
    ts = iso(parse_ts(seen_at)) if seen_at else iso(utcnow())
    conn.execute("UPDATE threats SET observation_count=observation_count+1, last_seen=MAX(last_seen,?) WHERE threat_id=?",
                 (ts, row["threat_id"]))
    conn.execute("UPDATE indicators SET last_seen=MAX(last_seen,?) WHERE threat_id=?", (ts, row["threat_id"]))
    conn.commit()
    return row["threat_id"]


def create_threat(conn, payload: dict) -> dict:
    """Create a threat from an API payload. Risk and confidence are COMPUTED, never trusted from the client.
    Duplicate (same indicator + category) becomes a new observation of the existing record."""
    payload = dict(payload, risk_score=None, confidence_score=None)
    r = normalize_record(payload)
    dup = conn.execute("SELECT t.threat_id FROM threats t JOIN indicators i ON i.threat_id=t.threat_id "
                       "WHERE i.indicator_value=? AND t.category=?", (r["indicator_value"], r["category"])).fetchone()
    if dup:
        record_observation(conn, r["indicator_value"])
        return {"threat_id": dup["threat_id"], "duplicate": True}
    _, grade = _source(conn, r["source_name"])
    r["confidence_score"] = calculate_confidence(grade, 1, 0, 0.5)
    r["risk_score"] = calculate_threat_risk(r["severity"], r["confidence_score"], r["last_seen"],
                                            r["observation_count"], grade, 0, 20)["score"]
    r["incident_confirmed"] = 0                     # only admins/analyst workflow may confirm an incident
    r["threat_id"] = next_threat_id(conn)
    _insert(conn, r)
    row = conn.execute("SELECT t.*, i.indicator_type FROM threats t JOIN indicators i USING(threat_id) WHERE threat_id=?",
                       (r["threat_id"],)).fetchone()
    a = generate_threat_alert(dict(row))
    if a:
        conn.execute("INSERT INTO alerts(alert_id,threat_id,timestamp,alert_type,severity,risk_score,confidence_score,"
                     "description,status,observation_count,last_observed,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (a["alert_id"], a["threat_id"], a["timestamp"], a["alert_type"], a["severity"], a["risk_score"],
                      a["confidence_score"], a["description"], a["status"], a["observation_count"], a["timestamp"], a["timestamp"]))
    conn.commit()
    return {"threat_id": r["threat_id"], "duplicate": False, "risk_score": r["risk_score"],
            "confidence_score": r["confidence_score"]}


def update_threat(conn, threat_id, payload: dict, role="analyst") -> bool:
    if not conn.execute("SELECT 1 FROM threats WHERE threat_id=?", (threat_id,)).fetchone():
        return False
    sets, vals = [], []
    if "status" in payload:
        s = str(payload["status"]).upper()
        if s not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        sets.append("status=?"); vals.append(s)
    if "severity" in payload:
        s = str(payload["severity"]).upper()
        if s not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        sets.append("severity=?"); vals.append(s)
    if "description" in payload:
        sets.append("description=?"); vals.append(sanitize_text(payload["description"]))
    if "incident_confirmed" in payload:
        if role != "admin":
            raise PermissionError("Only an admin can mark a threat as a confirmed incident.")
        sets.append("incident_confirmed=?"); vals.append(1 if payload["incident_confirmed"] else 0)
    if not sets:
        raise ValueError("No updatable fields supplied (status, severity, description, incident_confirmed).")
    conn.execute(f"UPDATE threats SET {', '.join(sets)} WHERE threat_id=?", (*vals, threat_id))
    conn.commit()
    return True


def add_note(conn, threat_id, note, role="analyst"):
    note = sanitize_text(note, 2000)
    if not note:
        raise ValueError("note must not be empty")
    if not conn.execute("SELECT 1 FROM threats WHERE threat_id=?", (threat_id,)).fetchone():
        return None
    cur = conn.execute("INSERT INTO analyst_notes(threat_id,note,author_role,created_at) VALUES (?,?,?,?)",
                       (threat_id, note, role, iso(utcnow())))
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------- reading
def classify_entity(t: dict) -> str:
    """Distinguish OBSERVATION < INDICATOR < ALERT < THREAT < INCIDENT (never over-claim)."""
    if t.get("incident_confirmed"):
        return "INCIDENT"
    if t["status"] == "FALSE_POSITIVE":
        return "OBSERVATION"
    if t["confidence_score"] >= 70 and t["risk_score"] >= 61:
        return "THREAT"
    if t.get("open_alerts", 0) > 0:
        return "ALERT"
    if t["confidence_score"] >= 40:
        return "INDICATOR"
    return "OBSERVATION"


_SORTS = {"newest": "t.last_seen DESC", "risk": "t.risk_score DESC, t.last_seen DESC",
          "confidence": "t.confidence_score DESC, t.last_seen DESC", "observed": "t.observation_count DESC"}
_BASE = ("SELECT t.*, i.indicator_type, i.indicator_value, s.source_name, s.reliability, "
         "(SELECT COUNT(*) FROM alerts a WHERE a.threat_id=t.threat_id AND a.status IN ('NEW','INVESTIGATING')) AS open_alerts "
         "FROM threats t JOIN indicators i ON i.threat_id=t.threat_id LEFT JOIN sources s ON s.source_id=t.source_id")


def list_threats(conn, severity=None, category=None, indicator_type=None, status=None, min_risk=None, max_risk=None,
                 min_confidence=None, date_from=None, date_to=None, q=None, sort="newest", page=1, page_size=25):
    where, p = [], []
    for col, val, allowed in (("t.severity", severity, SEVERITIES), ("t.category", category, CATEGORIES),
                              ("i.indicator_type", indicator_type, INDICATOR_TYPES), ("t.status", status, STATUSES)):
        if val:
            val = str(val).upper()
            if val not in allowed:
                raise ValueError(f"Invalid filter value '{val}'.")
            where.append(f"{col}=?"); p.append(val)
    for col, op, val in (("t.risk_score", ">=", min_risk), ("t.risk_score", "<=", max_risk),
                         ("t.confidence_score", ">=", min_confidence)):
        if val not in (None, ""):
            where.append(f"{col}{op}?"); p.append(int(val))
    if date_from:
        where.append("t.last_seen>=?"); p.append(iso(parse_ts(date_from)))
    if date_to:
        where.append("t.last_seen<=?"); p.append(iso(parse_ts(date_to + "T23:59:59" if len(date_to) == 10 else date_to)))
    if q:
        like = f"%{q.strip().lower()}%"
        where.append("(LOWER(t.threat_id) LIKE ? OR LOWER(t.threat_name) LIKE ? OR LOWER(i.indicator_value) LIKE ?)")
        p += [like, like, like]
    if sort not in _SORTS:
        raise ValueError(f"sort must be one of {list(_SORTS)}")
    page, page_size = max(1, int(page)), max(1, min(200, int(page_size)))
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM threats t JOIN indicators i ON i.threat_id=t.threat_id{w}", p).fetchone()[0]
    rows = conn.execute(f"{_BASE}{w} ORDER BY {_SORTS[sort]} LIMIT ? OFFSET ?", (*p, page_size, (page - 1) * page_size)).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["entity_type"] = classify_entity(d)
        items.append(d)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def get_threat(conn, threat_id):
    row = conn.execute(_BASE + " WHERE t.threat_id=?", (threat_id,)).fetchone()
    if not row:
        return None
    t = dict(row)
    t["entity_type"] = classify_entity(t)
    t["reliability_label"] = RELIABILITY[t["reliability"] or "D"]["label"]
    t["interpretation"] = interpret(t["risk_score"], t["confidence_score"])
    t["attack_mappings"] = [dict(r) for r in conn.execute("SELECT tactic, technique, technique_id_optional FROM attack_mappings WHERE threat_id=?", (threat_id,))]
    t["attack_note"] = map_threat(t["category"], t["indicator_type"], t["confidence_score"], t["observation_count"], t["status"])["reason"] if not t["attack_mappings"] else \
        "Mapped only because evidence thresholds were met; an analyst should confirm."
    t["alerts"] = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE threat_id=? ORDER BY timestamp DESC", (threat_id,))]
    t["notes"] = [dict(r) for r in conn.execute("SELECT note, author_role, created_at FROM analyst_notes WHERE threat_id=? ORDER BY created_at", (threat_id,))]
    rel = []
    if t["campaign_id"] or t["cve_id"]:
        rel = [dict(r) for r in conn.execute(
            "SELECT t.threat_id, t.threat_name, i.indicator_type, i.indicator_value, t.risk_score, t.confidence_score "
            "FROM threats t JOIN indicators i ON i.threat_id=t.threat_id "
            "WHERE t.threat_id!=? AND ((t.campaign_id!='' AND t.campaign_id=?) OR (t.cve_id!='' AND t.cve_id=?)) LIMIT 25",
            (threat_id, t["campaign_id"], t["cve_id"]))]
    t["related_indicators"] = rel
    t["cluster_note"] = ("RELATED THREAT CLUSTER: shares campaign/CVE context. Correlation is not proof of attribution."
                         if rel else "No correlated records.")
    t["vulnerability"] = None
    if t["cve_id"]:
        v = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (t["cve_id"],)).fetchone()
        t["vulnerability"] = dict(v) if v else None
    k = CATEGORY_KNOWLEDGE[t["category"]]
    t["recommended_actions"] = k["actions"]
    t["category_guidance"] = {x: k[x] for x in ("description", "impact", "controls", "awareness")}
    t["timeline"] = build_timeline(t)
    return t


def build_timeline(t: dict) -> list:
    """Timeline is built ONLY from stored facts (no invented events)."""
    ev = [{"time": t["first_seen"], "event": "First seen", "detail": f"Indicator first recorded by {t['source_name']}."}]
    for a in t["alerts"]:
        ev.append({"time": a["created_at"] or a["timestamp"], "event": f"Alert {a['alert_id']}",
                   "detail": f"{a['alert_type']} ({a['status']}), observations: {a['observation_count']}"})
    for n in t["notes"]:
        ev.append({"time": n["created_at"], "event": "Analyst note", "detail": n["note"][:120]})
    if t["observation_count"] > 1:
        ev.append({"time": t["last_seen"], "event": "Latest observation", "detail": f"{t['observation_count']} total observations."})
    ev.append({"time": t["last_seen"], "event": f"Current status: {t['status']}", "detail": f"Risk {t['risk_score']}, confidence {t['confidence_score']}."})
    return sorted(ev, key=lambda e: e["time"])


def list_alerts(conn, status=None, limit=100):
    if status and status.upper() not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {ALERT_STATUSES}")
    w, p = ("WHERE a.status=?", [status.upper()]) if status else ("", [])
    rows = conn.execute(f"SELECT a.*, t.threat_name FROM alerts a JOIN threats t USING(threat_id) {w} "
                        "ORDER BY a.risk_score DESC, a.timestamp DESC LIMIT ?", (*p, int(limit))).fetchall()
    return [dict(r) for r in rows]


def update_alert_status(conn, alert_id, status):
    status = str(status).upper()
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {ALERT_STATUSES}")
    cur = conn.execute("UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id))
    conn.commit()
    return cur.rowcount > 0
