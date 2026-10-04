"""
Correlation of threat records and of alerts.
Correlation shows RELATIONSHIP/EVIDENCE - it does NOT prove attribution.
"""
from collections import defaultdict
from datetime import timedelta
from ..utils.timeutil import parse_ts


def correlate_threats(threats: list) -> list:
    """Group threats sharing a campaign_id or CVE into RELATED THREAT CLUSTERS (union-find)."""
    parent = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_key = defaultdict(list)
    for t in threats:
        parent.setdefault(t["threat_id"], t["threat_id"])
        for k in ("campaign_id", "cve_id"):
            if t.get(k):
                by_key[(k, t[k])].append(t["threat_id"])
    for ids in by_key.values():
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])

    groups, basis = defaultdict(list), defaultdict(set)
    lookup = {t["threat_id"]: t for t in threats}
    for tid in parent:
        groups[find(tid)].append(tid)
    for (k, v), ids in by_key.items():
        if len(ids) > 1:
            basis[find(ids[0])].add(f"{k}={v}")
    clusters = []
    for root, members in groups.items():
        if len(members) < 2:
            continue
        members.sort()
        clusters.append({
            "cluster_id": "CLU-" + members[0][4:],
            "members": members, "size": len(members),
            "basis": sorted(basis[root]),
            "indicator_types": sorted({lookup[m].get("indicator_type", "") for m in members}),
            "note": "RELATED THREAT CLUSTER - shared context, not proof of common attribution.",
        })
    return sorted(clusters, key=lambda c: -c["size"])


def correlate_alerts(alerts: list, window_minutes: int = 5) -> list:
    """Merge repeated alerts (same threat + type inside a time window) into ONE alert with an
    observation_count. Prevents alert fatigue: 100 sightings in 5 min = 1 analyst alert, not 100."""
    open_groups, out = {}, []
    for a in sorted(alerts, key=lambda x: parse_ts(x["timestamp"])):
        key, ts = (a["threat_id"], a["alert_type"]), parse_ts(a["timestamp"])
        g = open_groups.get(key)
        if g and ts - g["_start"] <= timedelta(minutes=window_minutes):
            g["observation_count"] += a.get("observation_count", 1)
            g["last_observed"] = a["timestamp"]
            g["risk_score"] = max(g["risk_score"], a["risk_score"])
        else:
            g = dict(a)
            g["observation_count"] = a.get("observation_count", 1)
            g["_start"], g["last_observed"] = ts, a["timestamp"]
            open_groups[key] = g
            out.append(g)
    for g in out:
        g.pop("_start", None)
    return out
