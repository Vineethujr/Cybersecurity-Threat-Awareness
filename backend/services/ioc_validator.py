"""
IOC validation & normalization.

IMPORTANT: validation answers "is this SYNTACTICALLY valid?" - NOT "is this malicious?".
Nothing here ever connects to an IP, domain or URL. Indicators are treated purely as data.
"""
import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HASH_TYPES = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def refang(value: str) -> str:
    """Convert 'defanged' notation (hxxp://evil[.]example) back to plain data form for storage."""
    v = value.strip()
    for a, b in (("hxxps", "https"), ("hxxp", "http"), ("[://]", "://"),
                 ("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[@]", "@")):
        v = v.replace(a, b).replace(a.upper(), b)
    return v


def _result(valid, itype, norm, notes, **extra):
    d = {"valid": valid, "indicator_type": itype, "normalized_value": norm, "validation_notes": notes}
    d.update(extra)
    return d


def is_valid_domain(d: str) -> bool:
    d = d.rstrip(".").lower()
    if not d or len(d) > 253:
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL.match(x) for x in labels) and bool(_TLD.match(labels[-1]))


def _validate_url(v, notes):
    try:
        p = urlsplit(v)
        host, port = p.hostname, p.port
    except ValueError:
        return _result(False, None, v, notes + ["Malformed URL."])
    if p.scheme.lower() not in ("http", "https", "ftp"):
        return _result(False, None, v, notes + ["Unsupported URL scheme."])
    if not host:
        return _result(False, None, v, notes + ["URL has no host."])
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not is_valid_domain(host):
            return _result(False, None, v, notes + ["URL host is not a valid domain or IP."])
    host = host.lower().rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    norm = f"{p.scheme.lower()}://{netloc}{p.path}" + (f"?{p.query}" if p.query else "")
    extra = ["URL credentials/fragment removed during normalization."] if (p.username or p.fragment) else []
    return _result(True, "URL", norm, notes + extra + ["Valid URL syntax. The URL was NOT visited."])


def _detect(v, notes):
    if _CVE.match(v):
        return _result(True, "CVE_ID", v.upper(), notes + ["Valid CVE identifier format."])
    try:
        ip = ipaddress.ip_address(v)
        return _result(True, "IP_ADDRESS", str(ip), notes + [f"Valid IPv{ip.version} syntax. Not contacted."],
                       subtype=f"IPv{ip.version}")
    except ValueError:
        pass
    if _HEX.match(v) and len(v) in _HASH_TYPES:
        return _result(True, "FILE_HASH", v.lower(), notes + [f"Valid {_HASH_TYPES[len(v)]}-format hash."],
                       subtype=_HASH_TYPES[len(v)])
    if "://" in v:
        return _validate_url(v, notes)
    if "@" in v:
        local, _, dom = v.rpartition("@")
        if local and " " not in local and is_valid_domain(dom):
            return _result(True, "EMAIL_DOMAIN", dom.lower().rstrip("."),
                           notes + ["Email reduced to sender domain (data minimization)."])
        return _result(False, None, v, notes + ["Invalid email/sender format."])
    if is_valid_domain(v):
        return _result(True, "DOMAIN", v.lower().rstrip("."), notes + ["Valid domain syntax. Not resolved."])
    return _result(False, None, v, notes + ["Not a recognized indicator format."])


def validate_indicator(value, expected_type=None) -> dict:
    """Return {valid, indicator_type, normalized_value, validation_notes[, subtype]}."""
    if not isinstance(value, str) or not value.strip():
        return _result(False, None, "", ["Empty or non-text input."])
    raw = value.strip()
    v = refang(raw)
    notes = ["Defanged notation converted to plain data form (never visited)."] if v != raw else []
    res = _detect(v, notes)
    if expected_type and res["valid"]:
        want = str(expected_type).upper().replace(" ", "_")
        if want == "EMAIL_DOMAIN" and res["indicator_type"] == "DOMAIN":
            res["indicator_type"] = "EMAIL_DOMAIN"      # a bare sender domain is stored as EMAIL_DOMAIN
            res["validation_notes"].append("Treated as sender (email) domain.")
        elif res["indicator_type"] != want:
            res["valid"] = False
            res["validation_notes"].append(f"Expected {want} but detected {res['indicator_type']}.")
    return res
