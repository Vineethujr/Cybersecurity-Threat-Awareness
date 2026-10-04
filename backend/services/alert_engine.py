"""Alert generation. An ALERT is a lead for triage - not a confirmed incident."""
from .risk_engine import score_to_level

RISK_T, CONF_T, REPEAT_T = 70, 60, 10
ALERT_STATUSES = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]
_STATUS_MAP = {"NEW": "NEW", "UNDER_REVIEW": "INVESTIGATING", "MONITORING": "MONITORING"}


def generate_threat_alert(threat: dict, cluster_size: int = 0, vuln_priority=None):
    """Return one alert dict (or None) for a threat. Reasons: risk+confidence thresholds,
    high-priority vulnerability, repeated observations, correlated cluster (lead member only)."""
    if threat["status"] in ("CLOSED", "FALSE_POSITIVE"):
        return None
    risk, conf, obs = threat["risk_score"], threat["confidence_score"], threat.get("observation_count", 1)
    reasons = []
    if risk >= RISK_T and conf >= CONF_T:
        reasons.append(("RISK_THRESHOLD", f"Risk {risk} and confidence {conf} exceed thresholds ({RISK_T}/{CONF_T})."))
    if vuln_priority is not None and vuln_priority >= 75:
        reasons.append(("HIGH_PRIORITY_VULNERABILITY", f"Linked vulnerability priority is {vuln_priority}."))
    if obs >= REPEAT_T:
        reasons.append(("REPEATED_OBSERVATION", f"Indicator observed {obs} times."))
    if cluster_size >= 3 and risk >= 65 and conf >= 50:
        reasons.append(("CORRELATED_INDICATORS", f"Lead record of a {cluster_size}-indicator related cluster."))
    if not reasons:
        return None
    return {
        "alert_id": "ALR-" + threat["threat_id"][4:],
        "threat_id": threat["threat_id"],
        "timestamp": threat["last_seen"],
        "alert_type": reasons[0][0],
        "severity": score_to_level(risk),
        "risk_score": risk, "confidence_score": conf,
        "description": " ".join(r[1] for r in reasons) + " Triage lead only - not a confirmed compromise.",
        "status": _STATUS_MAP.get(threat["status"], "NEW"),
        "observation_count": obs,
    }
