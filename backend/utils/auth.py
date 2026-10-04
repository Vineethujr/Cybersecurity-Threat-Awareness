"""API-key authentication + simple RBAC (viewer < analyst < admin) and audit logging."""
from functools import wraps
from flask import current_app, jsonify, request, g
from ..db import get_db
from .timeutil import iso, utcnow

ROLE_LEVEL = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(minimum: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            key = request.headers.get("X-API-Key")
            if not key:
                return jsonify({"error": "Authentication required (X-API-Key header)."}), 401
            role = current_app.config["API_KEYS"].get(key)
            if role is None:
                return jsonify({"error": "Invalid API key."}), 401
            if ROLE_LEVEL[role] < ROLE_LEVEL[minimum]:
                return jsonify({"error": f"Role '{role}' is not allowed; '{minimum}' required."}), 403
            g.role = role
            return fn(*a, **kw)
        return wrapper
    return deco


def audit(action: str, target: str = ""):
    db = get_db()
    db.execute("INSERT INTO audit_log(ts, actor_role, action, target) VALUES (?,?,?,?)",
               (iso(utcnow()), getattr(g, "role", "unknown"), action, target))
    db.commit()
