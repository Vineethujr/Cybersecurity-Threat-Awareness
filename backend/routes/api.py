"""REST API. Reads are open in this demo; writes need an X-API-Key (RBAC: analyst/admin)."""
from flask import Blueprint, current_app, g, jsonify, request
from ..db import get_db
from ..services import (awareness_service as aw, enrichment_engine, stats_service, threat_service as ts)
from ..utils.auth import audit, require_role

bp = Blueprint("api", __name__, url_prefix="/api")


def err(msg, code=400):
    return jsonify({"error": msg}), code


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


@bp.get("/health")
def health():
    return jsonify({"status": "ok", "data": "synthetic / demo only"})


@bp.get("/threats")
def threats():
    a = request.args
    try:
        res = ts.list_threats(get_db(), a.get("severity"), a.get("category"), a.get("indicator_type"), a.get("status"),
                              a.get("min_risk"), a.get("max_risk"), a.get("min_confidence"), a.get("date_from"),
                              a.get("date_to"), a.get("q"), a.get("sort", "newest"), a.get("page", 1), a.get("page_size", 25))
    except (ValueError, TypeError) as e:
        return err(f"Invalid query parameter: {e}")
    return jsonify(res)


@bp.get("/threats/<threat_id>")
def threat_detail(threat_id):
    t = ts.get_threat(get_db(), threat_id)
    return jsonify(t) if t else err("Threat not found.", 404)


@bp.post("/threats")
@require_role("analyst")
def threat_create():
    data = body()
    if data is None:
        return err("JSON object body required.")
    try:
        res = ts.create_threat(get_db(), data)
    except (ValueError, TypeError) as e:
        return err(str(e), 422)
    audit("create_threat", res["threat_id"])
    return jsonify(res), 200 if res.get("duplicate") else 201


@bp.put("/threats/<threat_id>")
@require_role("analyst")
def threat_update(threat_id):
    data = body()
    if data is None:
        return err("JSON object body required.")
    try:
        ok = ts.update_threat(get_db(), threat_id, data, g.role)
    except PermissionError as e:
        return err(str(e), 403)
    except ValueError as e:
        return err(str(e), 422)
    if not ok:
        return err("Threat not found.", 404)
    audit("update_threat", threat_id)
    return jsonify({"updated": threat_id})


@bp.post("/threats/<threat_id>/notes")
@require_role("analyst")
def note_create(threat_id):
    data = body()
    if data is None:
        return err("JSON object body required.")
    try:
        nid = ts.add_note(get_db(), threat_id, data.get("note", ""), g.role)
    except ValueError as e:
        return err(str(e), 422)
    if nid is None:
        return err("Threat not found.", 404)
    audit("add_note", threat_id)
    return jsonify({"note_id": nid}), 201


@bp.get("/indicators/search")
def indicator_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return err("Query parameter 'q' is required.")
    if len(q) > 2048:
        return err("Query too long.", 414)
    return jsonify(enrichment_engine.enrich_indicator(get_db(), q))


@bp.get("/dashboard/stats")
def dash_stats():
    return jsonify(stats_service.dashboard_stats(get_db()))


@bp.get("/dashboard/trends")
def dash_trends():
    return jsonify(stats_service.dashboard_trends(get_db()))


@bp.get("/dashboard/executive")
def dash_exec():
    return jsonify(stats_service.executive_summary(get_db()))


@bp.get("/alerts")
def alerts():
    try:
        return jsonify(ts.list_alerts(get_db(), request.args.get("status"), request.args.get("limit", 100)))
    except (ValueError, TypeError) as e:
        return err(str(e))


@bp.put("/alerts/<alert_id>/status")
@require_role("analyst")
def alert_status(alert_id):
    data = body()
    if data is None:
        return err("JSON object body required.")
    try:
        ok = ts.update_alert_status(get_db(), alert_id, data.get("status", ""))
    except ValueError as e:
        return err(str(e), 422)
    if not ok:
        return err("Alert not found.", 404)
    audit("alert_status", alert_id)
    return jsonify({"updated": alert_id, "status": data["status"].upper()})


@bp.get("/vulnerabilities")
def vulns():
    try:
        return jsonify(stats_service.list_vulnerabilities(get_db(), request.args.get("severity"), request.args.get("sort", "priority")))
    except ValueError as e:
        return err(str(e))


@bp.get("/attack/summary")
def attack_summary():
    return jsonify(stats_service.attack_summary(get_db()))


@bp.get("/attack/techniques/<technique_id>")
def attack_technique(technique_id):
    return jsonify(stats_service.threats_for_technique(get_db(), technique_id.upper()))


@bp.get("/categories")
def categories():
    return jsonify(ts.CATEGORY_KNOWLEDGE)


@bp.get("/awareness/modules")
def modules():
    return jsonify(aw.load_json(current_app.config["MODULES_JSON"]))


@bp.get("/quiz")
def quiz():
    return jsonify(aw.public_quiz(current_app.config["QUIZ_JSON"]))


@bp.post("/quiz/submit")
def quiz_submit():
    data = body()
    if data is None or "answers" not in data:
        return err("JSON body with an 'answers' object is required.")
    try:
        result = aw.score_quiz(aw.load_json(current_app.config["QUIZ_JSON"]), data["answers"])
    except ValueError as e:
        return err(str(e), 422)
    aw.save_result(get_db(), result)      # anonymous: no personal data stored
    return jsonify(result)
