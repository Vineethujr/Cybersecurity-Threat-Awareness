"""
Synthetic threat-intelligence + vulnerability data generator.

SAFETY: every indicator uses reserved documentation/example space (RFC 5737 / RFC 3849 IPs,
example.com/.org/.net, *.invalid). Hashes are random SHA-256-style strings. NOTHING here is real
threat intelligence. Every description is tagged SYNTHETIC / DEMO ONLY.

Run from the project root:   python data/generate_threat_data.py
"""
import csv
import hashlib
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from backend.services.attack_mapper import map_threat                      # noqa: E402
from backend.services.ioc_validator import validate_indicator              # noqa: E402
from backend.services.risk_engine import (SOURCES, SEVERITIES,             # noqa: E402
                                          calculate_confidence, calculate_threat_risk)
from backend.services.vulnerability_service import severity_from_cvss      # noqa: E402

SEED, N_RECORDS, N_VULNS = 2026, 2400, 60
NOW = datetime(2026, 9, 30, 8, 0, 0)
START = datetime(2026, 1, 1)
TAG = "[SYNTHETIC / DEMO ONLY]"

CATEGORIES = {
    # category: (names, indicator-type weights, severity weights [INFO..CRIT])
    "PHISHING": (["Synthetic Credential Phishing Campaign", "Fake Invoice Lure Wave", "Synthetic Payroll Notice Lure"],
                 {"DOMAIN": .3, "URL": .3, "EMAIL_DOMAIN": .25, "IP_ADDRESS": .15}, [5, 20, 35, 30, 10]),
    "MALWARE": (["Synthetic Loader Family Sighting", "Demo Trojan Dropper Activity", "Synthetic Info-Stealer Sample"],
                {"FILE_HASH": .45, "DOMAIN": .2, "IP_ADDRESS": .2, "URL": .15}, [3, 15, 30, 35, 17]),
    "RANSOMWARE": (["Synthetic Ransomware Precursor Activity", "Demo Extortion Staging Infrastructure"],
                   {"FILE_HASH": .4, "IP_ADDRESS": .2, "DOMAIN": .2, "URL": .2}, [1, 5, 19, 40, 35]),
    "CREDENTIAL THREATS": (["Synthetic Password Spray Source", "Demo Credential Stuffing Infrastructure"],
                           {"IP_ADDRESS": .4, "DOMAIN": .2, "URL": .2, "EMAIL_DOMAIN": .2}, [3, 15, 35, 35, 12]),
    "WEB THREATS": (["Synthetic Malicious Redirect Chain", "Demo Compromised Site Indicator"],
                    {"URL": .5, "DOMAIN": .3, "IP_ADDRESS": .2}, [5, 25, 40, 25, 5]),
    "NETWORK THREATS": (["Synthetic Port-Scan Source", "Demo Beaconing Pattern Source"],
                        {"IP_ADDRESS": .7, "DOMAIN": .3}, [10, 30, 35, 20, 5]),
    "VULNERABILITY EXPOSURE": (["Synthetic Exposed Service Advisory", "Demo Unpatched Product Exposure"],
                               {"CVE_ID": .7, "IP_ADDRESS": .15, "URL": .15}, [5, 15, 30, 30, 20]),
    "SOCIAL ENGINEERING": (["Synthetic Pretexting Attempt", "Demo Impersonation Sender Domain"],
                           {"EMAIL_DOMAIN": .4, "DOMAIN": .3, "URL": .3}, [10, 35, 35, 15, 5]),
    "DATA EXPOSURE": (["Synthetic Public Storage Exposure", "Demo Leaked Credential Paste Reference"],
                      {"URL": .35, "DOMAIN": .3, "IP_ADDRESS": .2, "FILE_HASH": .15}, [10, 25, 35, 20, 10]),
    "ACCOUNT SECURITY": (["Synthetic Suspicious Sign-in Source", "Demo MFA Fatigue Pattern Source"],
                         {"IP_ADDRESS": .5, "EMAIL_DOMAIN": .2, "DOMAIN": .3}, [5, 20, 40, 25, 10]),
}
WORDS = ["login", "secure", "account", "verify", "portal", "update", "billing", "support", "mail", "cloud",
         "check", "auth", "docs", "invoice", "payroll", "reset", "safe", "office", "vpn", "share"]
PATHS = ["verify", "account", "update", "download", "portal", "login", "review", "confirm"]
REGIONS = ["North America", "Europe", "Asia-Pacific", "South Asia", "Latin America", "Middle East", "Africa", ""]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
RESERVED = {"login-check.invalid", "198.51.100.25", "https://login-check.invalid/verify/account"}

FIELDS = ["threat_id", "timestamp", "threat_name", "threat_category", "indicator_type", "indicator_value",
          "source_name", "confidence_score", "severity", "risk_score", "status", "first_seen", "last_seen",
          "country_or_region_optional", "description", "mitre_tactic_optional", "mitre_technique_optional",
          "cve_id_optional", "campaign_id", "observation_count", "incident_confirmed"]

rng = random.Random(SEED)


def wchoice(d):
    return rng.choices(list(d), weights=list(d.values()))[0]


def make_indicator(itype, cve_pool):
    for _ in range(50):
        if itype == "IP_ADDRESS":
            if rng.random() < .25:
                v = f"2001:db8:{rng.randint(0, 0xffff):x}::{rng.randint(1, 0xffff):x}"      # RFC 3849 doc range
            else:
                v = f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"
        elif itype == "DOMAIN":
            base = f"{rng.choice(WORDS)}-{rng.choice(WORDS)}"
            v = f"{base}.invalid" if rng.random() < .5 else f"{base}.{rng.choice(['example.com', 'example.org', 'example.net'])}"
        elif itype == "URL":
            v = f"https://{rng.choice(WORDS)}-{rng.choice(WORDS)}.invalid/{rng.choice(PATHS)}/{rng.randint(100, 999)}"
        elif itype == "FILE_HASH":
            v = hashlib.sha256(f"synthetic-{rng.random()}".encode()).hexdigest()           # random, NOT a real sample
        elif itype == "EMAIL_DOMAIN":
            v = f"{rng.choice(WORDS)}-{rng.choice(['notice', 'team', 'desk', 'alerts'])}.{rng.choice(['example.org', 'example.net', 'invalid'])}"
        else:  # CVE_ID
            v = rng.choice(cve_pool)
        if v not in RESERVED:
            return validate_indicator(v)["normalized_value"]
    raise RuntimeError("could not generate indicator")


def build_record(category, itype, campaign, campaign_size, cve_pool, source=None):
    names, _, sev_w = CATEGORIES[category]
    source = source or rng.choices(list(SOURCES), weights=[15, 20, 10, 25, 20, 10])[0]
    rel = SOURCES[source]
    first = START + timedelta(seconds=rng.randint(0, int((NOW - START).total_seconds()) - 86400))
    last = min(NOW, first + timedelta(hours=rng.randint(1, 24 * 90)))
    obs = min(500, int(rng.paretovariate(1.4)))
    conf = calculate_confidence(rel, rng.choices([1, 2, 3, 4], [40, 30, 20, 10])[0],
                                (NOW - last).days, rng.uniform(.2, 1))
    if rng.random() < .10:                                   # some weak-evidence items (risk >> confidence)
        conf = rng.randint(10, 38)
    sev = rng.choices(SEVERITIES, weights=sev_w)[0]
    age = (NOW - last).days
    status = rng.choices(STATUSES, weights=[25, 20, 25, 20, 10])[0]
    if age > 120 and rng.random() < .6:
        status = "CLOSED"
    if status == "FALSE_POSITIVE":
        conf = min(conf, 25)
    risk = calculate_threat_risk(sev, conf, last, obs, rel, campaign_size - 1 if campaign else 0,
                                 60 if campaign else 20, now=NOW)["score"]
    if status == "FALSE_POSITIVE":
        risk = min(risk, 20)
    value = make_indicator(itype, cve_pool)
    cve = value if itype == "CVE_ID" else (rng.choice(cve_pool) if category == "VULNERABILITY EXPOSURE" else "")
    m = map_threat(category, itype, conf, obs, status)["mappings"]
    return {
        "timestamp": last.isoformat(), "threat_name": rng.choice(names), "threat_category": category,
        "indicator_type": itype, "indicator_value": value, "source_name": source,
        "confidence_score": conf, "severity": sev, "risk_score": risk, "status": status,
        "first_seen": first.isoformat(), "last_seen": last.isoformat(),
        "country_or_region_optional": rng.choice(REGIONS),
        "description": f"Synthetic {category.lower()} observation for training. {itype.replace('_', ' ').title()} "
                       f"appears in demo telemetry; no real activity implied. {TAG}",
        "mitre_tactic_optional": m[0]["tactic"] if m else "",
        "mitre_technique_optional": f"{m[0]['technique']} ({m[0]['technique_id']})" if m else "",
        "cve_id_optional": cve, "campaign_id": campaign or "", "observation_count": obs, "incident_confirmed": 0,
    }


def generate_vulnerabilities(n=N_VULNS):
    products = ["Web Server", "Operating System", "VPN Appliance", "Email Gateway", "Database", "Browser",
                "Office Suite", "Network Device", "Cloud Service", "Mobile App"]
    rows = []
    for i in range(n):
        cvss = round(min(10, max(2.0, rng.gauss(7, 2))), 1)
        rows.append({
            "cve_id": f"CVE-2026-{90001 + i}",     # 9xxxx range = clearly synthetic
            "product_category": rng.choice(products), "severity": severity_from_cvss(cvss), "cvss_score": cvss,
            "published_date": (START + timedelta(days=rng.randint(0, 270))).date().isoformat(),
            "patch_available": rng.choice([1, 1, 1, 0]),
            "exploitation_status_demo": rng.choices(["NONE", "POC_PUBLISHED_DEMO", "ACTIVE_EXPLOITATION_DEMO"], [60, 25, 15])[0],
            "description": f"Synthetic vulnerability in a {rng.choice(products).lower()}. No technical or exploit "
                           f"details are included. {TAG}",
            "asset_criticality": rng.randint(1, 5),
            "exposure": rng.choices(["INTERNET_FACING", "INTERNAL", "ISOLATED"], [30, 50, 20])[0],
        })
    return rows


def main():
    vulns = generate_vulnerabilities()
    cve_pool = [v["cve_id"] for v in vulns]
    records = []
    # 1) correlated campaigns (multi-indicator clusters)
    for c in range(230):
        category = rng.choice(list(CATEGORIES))
        size = rng.randint(2, 6)
        cid = f"CMP-2026-{c + 1:03d}"
        for _ in range(size):
            records.append(build_record(category, wchoice(CATEGORIES[category][1]), cid, size, cve_pool))
    # 2) standalone records
    while len(records) < N_RECORDS - 3:
        category = rng.choice(list(CATEGORIES))
        records.append(build_record(category, wchoice(CATEGORIES[category][1]), "", 1, cve_pool))
    # 3) hand-crafted demo scenario (THR-2026-001) + its related indicators
    demo = dict(build_record("PHISHING", "DOMAIN", "CMP-2026-DEMO", 3, cve_pool, "Internal SOC"),
                threat_name="Synthetic Credential Phishing Campaign", indicator_value="login-check.invalid",
                confidence_score=85, severity="HIGH", risk_score=78, status="MONITORING",
                first_seen="2026-09-02T09:15:00", last_seen="2026-09-28T14:40:00", timestamp="2026-09-28T14:40:00",
                observation_count=14, cve_id_optional="", country_or_region_optional="Europe",
                description=f"Indicator appears in multiple synthetic phishing observations. {TAG}")
    demo_m = map_threat("PHISHING", "DOMAIN", 85, 14, "MONITORING")["mappings"][0]
    demo["mitre_tactic_optional"], demo["mitre_technique_optional"] = demo_m["tactic"], f"{demo_m['technique']} ({demo_m['technique_id']})"
    rel_ip = dict(demo, threat_name="Synthetic Phishing Infrastructure (IP)", indicator_type="IP_ADDRESS",
                  indicator_value="198.51.100.25", confidence_score=85, risk_score=78, observation_count=9,
                  first_seen="2026-09-03T11:00:00", last_seen="2026-09-27T16:20:00", timestamp="2026-09-27T16:20:00")
    rel_url = dict(demo, threat_name="Synthetic Phishing Landing URL", indicator_type="URL",
                   indicator_value="https://login-check.invalid/verify/account", confidence_score=80, risk_score=74,
                   observation_count=6, first_seen="2026-09-04T08:30:00", last_seen="2026-09-26T10:05:00",
                   timestamp="2026-09-26T10:05:00")
    for r in (rel_ip, rel_url):
        m = map_threat("PHISHING", r["indicator_type"], r["confidence_score"], r["observation_count"], "MONITORING")["mappings"][0]
        r["mitre_tactic_optional"], r["mitre_technique_optional"] = m["tactic"], f"{m['technique']} ({m['technique_id']})"
    others = records
    others.sort(key=lambda r: r["first_seen"])
    # 4) analyst-confirmed incidents are RARE and only from high-confidence internal SOC records
    n = 0
    for r in others:
        if n < 5 and r["source_name"] == "Internal SOC" and r["confidence_score"] >= 85 and r["status"] in ("UNDER_REVIEW", "MONITORING"):
            r["incident_confirmed"] = 1
            n += 1
    ordered = [demo, rel_ip, rel_url] + others   # demo scenario = 001-003, rest in first_seen order
    for i, r in enumerate(ordered, start=1):
        r["threat_id"] = f"THR-2026-{i:03d}"
    (ROOT / "data").mkdir(exist_ok=True)
    with open(ROOT / "data" / "threat_intelligence_dataset.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(ordered)
    with open(ROOT / "data" / "vulnerabilities.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(vulns[0]))
        w.writeheader()
        w.writerows(vulns)
    print(f"Wrote {len(ordered)} synthetic threat records and {len(vulns)} synthetic vulnerabilities to data/.")


if __name__ == "__main__":
    main()
