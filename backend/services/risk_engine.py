"""
Risk scoring, confidence scoring and source reliability.

RISK       = how concerning the indicator/event may be.
CONFIDENCE = how much we trust the available intelligence.
HIGH RISK != CONFIRMED COMPROMISE.
"""
import math
from ..utils.timeutil import parse_ts, utcnow

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_POINTS = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 100}

# Source reliability grades (Admiralty-style, simplified). Reliability of the SOURCE is
# related to, but not the same as, confidence in a specific intelligence ITEM.
RELIABILITY = {
    "A": {"label": "Highly Reliable", "points": 100},
    "B": {"label": "Usually Reliable", "points": 75},
    "C": {"label": "Fairly Reliable", "points": 50},
    "D": {"label": "Reliability Unknown", "points": 25},
}
SOURCES = {
    "Internal SOC": "A", "Security Vendor": "B", "Research Report": "B",
    "Public Threat Feed": "C", "Community Submission": "C", "Unknown Source": "D",
}

WEIGHTS = {"severity": 0.30, "confidence": 0.25, "recency": 0.15,
           "observations": 0.10, "source": 0.10, "context": 0.10}


def score_to_level(score) -> str:
    s = round(score)
    if s <= 20: return "INFORMATIONAL"
    if s <= 40: return "LOW"
    if s <= 60: return "MEDIUM"
    if s <= 80: return "HIGH"
    return "CRITICAL"


def source_reliability_points(grade: str) -> int:
    return RELIABILITY.get(grade, RELIABILITY["D"])["points"]


def recency_points(last_seen, now=None) -> float:
    """100 today, halving every 30 days (stale indicators lose weight)."""
    now = parse_ts(now) if now else utcnow()
    days = max(0.0, (now - parse_ts(last_seen)).total_seconds() / 86400)
    return 100 * 0.5 ** (days / 30)


def observation_points(count: int) -> float:
    """Log scale: 1 sighting ~15, 10 ~50, 99+ = 100. Prevents one noisy indicator dominating."""
    return min(100.0, 100 * math.log10(max(count, 0) + 1) / 2)


def calculate_threat_risk(severity, confidence, last_seen, observation_count=1,
                          source_reliability="D", related_alerts=0, context=0, now=None) -> dict:
    """Weighted 0-100 risk score. Weights: severity 30, confidence 25, recency 15,
    observations 10, source 10, context/correlation 10."""
    ctx = min(100.0, max(0.0, context) + min(related_alerts, 4) * 15)
    comps = {
        "severity": SEVERITY_POINTS.get(str(severity).upper(), 10),
        "confidence": max(0, min(100, confidence)),
        "recency": recency_points(last_seen, now),
        "observations": observation_points(observation_count),
        "source": source_reliability_points(source_reliability),
        "context": ctx,
    }
    score = round(sum(WEIGHTS[k] * comps[k] for k in WEIGHTS))
    score = max(0, min(100, score))
    return {"score": score, "level": score_to_level(score),
            "components": {k: round(v, 1) for k, v in comps.items()},
            "note": "High risk does NOT mean confirmed compromise; check confidence and context."}


def calculate_confidence(source_reliability="D", corroborating_sources=1, age_days=0,
                         context_completeness=0.5) -> int:
    """0-100 confidence in the intelligence item: source grade 40%, corroboration 25%,
    freshness 20% (halves every 90 days), context completeness 15%."""
    rel = source_reliability_points(source_reliability)
    corr = min(100, 33.4 * max(1, corroborating_sources))
    fresh = 100 * 0.5 ** (max(0, age_days) / 90)
    ctx = max(0.0, min(1.0, context_completeness)) * 100
    return max(0, min(100, round(0.40 * rel + 0.25 * corr + 0.20 * fresh + 0.15 * ctx)))


def interpret(risk: int, confidence: int) -> str:
    if risk >= 61 and confidence < 40:
        return "Potentially serious, but evidence quality is weak - validate before acting."
    if risk >= 61 and confidence >= 70:
        return "High-confidence intelligence with meaningful risk - prioritize investigation."
    if risk <= 40 and confidence >= 70:
        return "Well-supported intelligence about a lower-risk item - monitor."
    return "Moderate risk/confidence - triage with additional context."
