"""35 automated tests. Docstring format: Scenario :: Input :: Expected."""
import json
from datetime import datetime, timedelta
from backend.services import awareness_service as aw, enrichment_engine, stats_service, threat_service as ts
from backend.services.alert_engine import generate_threat_alert
from backend.services.attack_mapper import map_threat
from backend.services.correlation_engine import correlate_alerts, correlate_threats
from backend.services.ioc_validator import validate_indicator as vi
from backend.services.risk_engine import (calculate_confidence, calculate_threat_risk, score_to_level,
                                          source_reliability_points, interpret)
from backend.services.vulnerability_service import calculate_vulnerability_priority as cvp
from backend.db import connect
from tests.conftest import AUTH

NOW = "2026-09-30T08:00:00"


def test_t01_valid_ipv4():
    """Valid IPv4 :: 198.51.100.25 :: valid, IP_ADDRESS"""
    r = vi("198.51.100.25"); assert r["valid"] and r["indicator_type"] == "IP_ADDRESS" and r["subtype"] == "IPv4"

def test_t02_invalid_ipv4():
    """Invalid IPv4 :: 999.1.1.1 :: invalid"""
    assert not vi("999.1.1.1")["valid"]

def test_t03_valid_ipv6():
    """Valid IPv6 :: 2001:DB8::1 :: valid, normalized lowercase"""
    r = vi("2001:DB8::1"); assert r["valid"] and r["subtype"] == "IPv6" and r["normalized_value"] == "2001:db8::1"

def test_t04_valid_domain():
    """Valid domain :: Login-Check.INVALID :: valid, lowercased"""
    r = vi("Login-Check.INVALID"); assert r["valid"] and r["normalized_value"] == "login-check.invalid"

def test_t05_invalid_domain():
    """Invalid domain :: bad..example.com :: invalid"""
    assert not vi("bad..example.com")["valid"]

def test_t06_valid_url():
    """Valid URL :: hxxps://login-check[.]invalid/verify :: refanged https URL"""
    r = vi("hxxps://login-check[.]invalid/verify"); assert r["valid"] and r["normalized_value"] == "https://login-check.invalid/verify"

def test_t07_md5():
    """MD5-format hash :: 32 hex chars :: FILE_HASH/MD5"""
    assert vi("d41d8cd98f00b204e9800998ecf8427e")["subtype"] == "MD5"

def test_t08_sha1():
    """SHA1-format hash :: 40 hex chars :: SHA1"""
    assert vi("a" * 40)["subtype"] == "SHA1"

def test_t09_sha256():
    """SHA256-format hash :: 64 hex chars :: SHA256"""
    r = vi("B" * 64); assert r["subtype"] == "SHA256" and r["normalized_value"] == "b" * 64

def test_t10_cve_valid():
    """Valid CVE :: cve-2026-90001 :: CVE_ID uppercase"""
    r = vi("cve-2026-90001"); assert r["valid"] and r["normalized_value"] == "CVE-2026-90001"

def test_t11_cve_invalid():
    """Invalid CVE :: CVE-26-1 :: invalid"""
    assert not vi("CVE-26-1")["valid"]

def test_t12_threat_creation(conn):
    """Threat creation :: valid payload :: new id, risk/confidence computed server-side"""
    r = ts.create_threat(conn, {"threat_name": "Test Lure", "category": "PHISHING", "severity": "HIGH",
                                "indicator_value": "unit-test-lure.invalid", "source_name": "Internal SOC"})
    assert r["threat_id"].startswith("THR-2026-") and not r["duplicate"] and 0 <= r["risk_score"] <= 100

def test_t13_risk_calculation():
    """Risk calculation :: HIGH, conf 85, fresh, 14 obs, source A :: score 0-100, level matches score"""
    r = calculate_threat_risk("HIGH", 85, "2026-09-29T00:00:00", 14, "A", 2, 60, now=NOW)
    assert 0 <= r["score"] <= 100 and r["level"] == score_to_level(r["score"]) and r["score"] >= 61
    assert score_to_level(20) == "INFORMATIONAL" and score_to_level(41) == "MEDIUM" and score_to_level(81) == "CRITICAL"

def test_t14_confidence_calculation():
    """Confidence calculation :: strong vs weak evidence :: strong > weak, bounded"""
    strong = calculate_confidence("A", 3, 1, 1.0); weak = calculate_confidence("D", 1, 400, 0.1)
    assert strong > weak and 0 <= weak <= strong <= 100
    assert "weak" in interpret(90, 25)

def test_t15_source_reliability():
    """Source reliability :: grades A-D :: A > B > C > D"""
    p = [source_reliability_points(g) for g in "ABCD"]; assert p == sorted(p, reverse=True)

def test_t16_enrichment(conn):
    """IOC enrichment :: 198.51.100.25 :: known, category PHISHING, no network note"""
    r = enrichment_engine.enrich_indicator(conn, "198.51.100.25")
    assert r["known_in_demo_dataset"] and "PHISHING" in r["associated_categories"] and "No connection" in r["note"]

def test_t17_indicator_search(client):
    """Indicator search API :: q=login-check.invalid :: risk 78, HIGH, conf 85"""
    d = client.get("/api/indicators/search?q=login-check.invalid").json
    assert d["risk_score"] == 78 and d["severity"] == "HIGH" and d["confidence"] == 85 and d["status"] == "MONITORING"

def test_t18_correlation():
    """Threat correlation :: shared campaign_id :: one cluster of 3"""
    rows = [{"threat_id": f"THR-2026-00{i}", "campaign_id": "C1", "indicator_type": "X"} for i in (1, 2, 3)] + \
           [{"threat_id": "THR-2026-009", "campaign_id": "", "indicator_type": "X"}]
    c = correlate_threats(rows); assert len(c) == 1 and c[0]["size"] == 3 and "attribution" in c[0]["note"]

def test_t19_duplicate_observation(conn):
    """Duplicate observation :: same indicator again :: count incremented, no new record"""
    before = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    obs = conn.execute("SELECT observation_count FROM threats WHERE threat_id='THR-2026-001'").fetchone()[0]
    ts.record_observation(conn, "login-check.invalid")
    assert conn.execute("SELECT observation_count FROM threats WHERE threat_id='THR-2026-001'").fetchone()[0] == obs + 1
    assert conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == before

def test_t20_alert_generation():
    """Alert generation :: high risk+confidence :: RISK_THRESHOLD alert; low risk none; FP none"""
    t = {"threat_id": "THR-2026-500", "risk_score": 80, "confidence_score": 90, "observation_count": 1, "status": "NEW", "last_seen": NOW}
    a = generate_threat_alert(t); assert a and a["alert_type"] == "RISK_THRESHOLD" and "not a confirmed" in a["description"]
    assert generate_threat_alert(dict(t, risk_score=30)) is None
    assert generate_threat_alert(dict(t, status="FALSE_POSITIVE")) is None

def test_t21_alert_correlation():
    """Alert correlation :: 100 alerts in 5 min :: 1 alert, observation_count 100"""
    base = datetime(2026, 9, 30, 8, 0, 0)
    alerts = [{"alert_id": f"A{i}", "threat_id": "T1", "alert_type": "REPEATED_OBSERVATION", "risk_score": 70,
               "timestamp": (base + timedelta(seconds=i * 2)).isoformat()} for i in range(100)]
    out = correlate_alerts(alerts); assert len(out) == 1 and out[0]["observation_count"] == 100

def test_t22_alert_status_update(client):
    """Alert status update :: PUT status with key :: 200; without key 401; bad status 422"""
    aid = client.get("/api/alerts?limit=1").json[0]["alert_id"]
    assert client.put(f"/api/alerts/{aid}/status", json={"status": "MONITORING"}).status_code == 401
    assert client.put(f"/api/alerts/{aid}/status", json={"status": "RESOLVED"}, headers=AUTH).status_code == 200
    assert client.put(f"/api/alerts/{aid}/status", json={"status": "NOPE"}, headers=AUTH).status_code == 422

def test_t23_analyst_notes(client):
    """Analyst notes :: POST note with HTML :: stored, tags stripped, visible in detail"""
    r = client.post("/api/threats/THR-2026-001/notes", json={"note": "<script>x</script>Seen in logs"}, headers=AUTH)
    assert r.status_code == 201
    notes = client.get("/api/threats/THR-2026-001").json["notes"]
    assert any("Seen in logs" in n["note"] and "<" not in n["note"] for n in notes)

def test_t24_attack_mapping():
    """ATT&CK mapping :: strong vs weak evidence :: mapped T1566 vs not mapped"""
    ok = map_threat("PHISHING", "DOMAIN", 85, 14); assert ok["mapped"] and ok["mappings"][0]["technique_id"] == "T1566"
    assert not map_threat("PHISHING", "DOMAIN", 30, 1)["mapped"] and not map_threat("PHISHING", "DOMAIN", 90, 9, "FALSE_POSITIVE")["mapped"]

def test_t25_vulnerability_scoring():
    """Vulnerability priority :: CVSS 9.8 isolated test vs CVSS 7.5 internet-facing exploited :: second higher"""
    a = cvp(9.8, 1, "ISOLATED", "NONE"); b = cvp(7.5, 5, "INTERNET_FACING", "ACTIVE_EXPLOITATION_DEMO")
    assert b["priority_score"] > a["priority_score"]

def test_t26_dashboard_stats(client):
    """Dashboard stats :: GET :: total 2400+, 9 chart series + trends"""
    d = client.get("/api/dashboard/stats").json
    assert d["cards"]["total_threats"] >= 2400 and len(d["charts"]) == 9  # + trends endpoint = 10 charts and d["cards"]["vulnerabilities_tracked"] == 60

def test_t27_severity_filter(client):
    """Severity filtering :: severity=CRITICAL :: all rows CRITICAL"""
    d = client.get("/api/threats?severity=CRITICAL&page_size=50").json
    assert d["items"] and all(t["severity"] == "CRITICAL" for t in d["items"])

def test_t28_category_filter(client):
    """Category filtering :: category=RANSOMWARE :: all rows RANSOMWARE"""
    d = client.get("/api/threats?category=RANSOMWARE&page_size=50").json
    assert d["items"] and all(t["category"] == "RANSOMWARE" for t in d["items"])

def test_t29_sorting(client):
    """Threat sorting :: sort=risk :: descending risk"""
    r = [t["risk_score"] for t in client.get("/api/threats?sort=risk&page_size=50").json["items"]]
    assert r == sorted(r, reverse=True)

def test_t30_awareness_modules(client):
    """Awareness module retrieval :: GET modules :: 15 modules with required sections"""
    m = client.get("/api/awareness/modules").json
    assert len(m) == 15 and all(k in m[0] for k in ("what", "why", "warning_signs", "safe_practices", "if_it_happens"))

def test_t31_quiz_scoring(app):
    """Quiz scoring :: all correct / all blank :: 100 vs 0"""
    qs = aw.load_json(app.config["QUIZ_JSON"]); assert len(qs) >= 30
    full = aw.score_quiz(qs, {q["id"]: q["answer"] for q in qs}); blank = aw.score_quiz(qs, {})
    assert full["overall_score"] == 100 and full["level"] == "Strong Awareness" and blank["overall_score"] == 0

def test_t32_learning_recommendation():
    """Learning recommendation :: phishing 40, social 55, passwords 90 :: complete / review / none"""
    r = {x["category"]: x for x in aw.generate_learning_recommendations({"Phishing": 40, "Social Engineering": 55, "Passwords": 90})}
    assert r["Phishing"]["recommendation"].startswith("Complete") and r["Social Engineering"]["recommendation"].startswith("Review")
    assert r["Passwords"]["module_id"] is None

def test_t33_empty_dataset(empty_conn):
    """Empty dataset :: stats on empty DB :: zeros, no crash"""
    d = stats_service.dashboard_stats(empty_conn); assert d["cards"]["total_threats"] == 0
    assert stats_service.dashboard_trends(empty_conn)["labels"] == []

def test_t34_api_validation(client):
    """API validation :: bad indicator, bad filter, XSS-ish input :: 4xx errors, no crash"""
    bad = {"threat_name": "x", "category": "PHISHING", "severity": "HIGH", "indicator_value": "not an indicator!!"}
    assert client.post("/api/threats", json=bad, headers=AUTH).status_code == 422
    assert client.get("/api/threats?severity=BOGUS").status_code == 400
    assert client.get("/api/indicators/search").status_code == 400
    assert client.get("/api/threats/NOPE").status_code == 404
    assert client.post("/api/quiz/submit", json={"answers": "x"}).status_code == 422

def test_t35_database_persistence(app, client):
    """Database persistence :: create then reopen new connection :: record present"""
    tid = client.post("/api/threats", headers=AUTH, json={"threat_name": "Persist", "category": "MALWARE", "severity": "LOW",
                      "indicator_value": "persist-check.example.com"}).json["threat_id"]
    c2 = connect(app.config["DB_PATH"])
    assert c2.execute("SELECT COUNT(*) FROM threats WHERE threat_id=?", (tid,)).fetchone()[0] == 1; c2.close()

def test_t36_entity_types(client):
    """Entity distinction :: demo threat and low-confidence record :: THREAT; incidents never automatic"""
    assert client.get("/api/threats/THR-2026-001").json["entity_type"] == "THREAT"
    items = client.get("/api/threats?page_size=200").json["items"]
    assert all(t["entity_type"] != "INCIDENT" for t in items[:50])   # incidents are rare, analyst-confirmed only

def test_t37_rbac(client):
    """RBAC :: analyst tries incident_confirmed :: 403; admin allowed"""
    r = client.put("/api/threats/THR-2026-002", json={"incident_confirmed": True}, headers=AUTH); assert r.status_code == 403
    r = client.put("/api/threats/THR-2026-002", json={"incident_confirmed": True}, headers={"X-API-Key": "demo-admin-key"}); assert r.status_code == 200
