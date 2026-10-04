"""
MITRE ATT&CK mapping (conceptual, evidence-gated).

IOC tells us WHAT artifact was seen; ATT&CK describes HOW behaviour may relate to adversary
techniques. We only map when there is enough evidence - never from a bare IP/domain alone.
Technique IDs below are well-known ATT&CK IDs; ATT&CK is versioned, so verify names/IDs at
https://attack.mitre.org before publishing anything.
"""
MIN_CONFIDENCE = 60
MIN_OBSERVATIONS = 2

# (category, indicator_type) -> (tactic, technique, technique_id). "*" = any indicator type.
RULES = {
    ("PHISHING", "URL"): ("Initial Access", "Phishing: Spearphishing Link", "T1566.002"),
    ("PHISHING", "*"): ("Initial Access", "Phishing", "T1566"),
    ("MALWARE", "FILE_HASH"): ("Execution", "User Execution: Malicious File", "T1204.002"),
    ("MALWARE", "*"): ("Command and Control", "Application Layer Protocol", "T1071"),
    ("RANSOMWARE", "*"): ("Impact", "Data Encrypted for Impact", "T1486"),
    ("CREDENTIAL THREATS", "*"): ("Credential Access", "Brute Force", "T1110"),
    ("WEB THREATS", "*"): ("Initial Access", "Drive-by Compromise", "T1189"),
    ("NETWORK THREATS", "IP_ADDRESS"): ("Discovery", "Network Service Discovery", "T1046"),
    ("NETWORK THREATS", "*"): ("Command and Control", "Application Layer Protocol", "T1071"),
    ("VULNERABILITY EXPOSURE", "*"): ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    ("SOCIAL ENGINEERING", "*"): ("Reconnaissance", "Phishing for Information", "T1598"),
    ("DATA EXPOSURE", "*"): ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
    ("ACCOUNT SECURITY", "*"): ("Initial Access", "Valid Accounts", "T1078"),
}


def map_threat(category, indicator_type, confidence, observation_count, status="NEW") -> dict:
    """Return {'mapped': bool, 'mappings': [...], 'reason': str}."""
    if status == "FALSE_POSITIVE":
        return {"mapped": False, "mappings": [], "reason": "Marked false positive - no behaviour mapped."}
    if confidence < MIN_CONFIDENCE or observation_count < MIN_OBSERVATIONS:
        return {"mapped": False, "mappings": [],
                "reason": f"Insufficient evidence (need confidence >= {MIN_CONFIDENCE} and "
                          f">= {MIN_OBSERVATIONS} observations). An indicator alone does not prove a technique."}
    rule = RULES.get((category, indicator_type)) or RULES.get((category, "*"))
    if not rule:
        return {"mapped": False, "mappings": [], "reason": "No ATT&CK rule for this category."}
    tactic, technique, tid = rule
    return {"mapped": True, "reason": "Mapped by category/indicator rule with sufficient evidence "
                                      "(analyst should confirm).",
            "mappings": [{"tactic": tactic, "technique": technique, "technique_id": tid}]}
