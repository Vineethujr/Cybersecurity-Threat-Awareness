"""SQLite database layer: schema, connections, seeding. Run `python -m backend.db --reset` to (re)build."""
import argparse
import os
import sqlite3
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  source_id INTEGER PRIMARY KEY AUTOINCREMENT, source_name TEXT UNIQUE NOT NULL,
  reliability TEXT NOT NULL CHECK(reliability IN ('A','B','C','D')));
CREATE TABLE IF NOT EXISTS threats(
  threat_id TEXT PRIMARY KEY, threat_name TEXT NOT NULL, category TEXT NOT NULL, description TEXT,
  severity TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence_score INTEGER NOT NULL,
  status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  source_id INTEGER REFERENCES sources(source_id), campaign_id TEXT, observation_count INTEGER DEFAULT 1,
  country_or_region TEXT, cve_id TEXT, incident_confirmed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS indicators(
  indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
  threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
  indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS attack_mappings(
  mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
  threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
  tactic TEXT NOT NULL, technique TEXT NOT NULL, technique_id_optional TEXT);
CREATE TABLE IF NOT EXISTS vulnerabilities(
  vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE NOT NULL, product_category TEXT,
  severity TEXT, cvss_score REAL, published_date TEXT, patch_available INTEGER,
  exploitation_status_demo TEXT, description TEXT, asset_criticality INTEGER, exposure TEXT, priority_score REAL);
CREATE TABLE IF NOT EXISTS alerts(
  alert_id TEXT PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
  timestamp TEXT, alert_type TEXT, severity TEXT, risk_score INTEGER, confidence_score INTEGER,
  description TEXT, status TEXT NOT NULL, observation_count INTEGER DEFAULT 1, last_observed TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS analyst_notes(
  note_id INTEGER PRIMARY KEY AUTOINCREMENT,
  threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
  note TEXT NOT NULL, author_role TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS awareness_modules(module_id TEXT PRIMARY KEY, title TEXT, category TEXT);
CREATE TABLE IF NOT EXISTS quiz_results(
  result_id INTEGER PRIMARY KEY AUTOINCREMENT, anonymous_user_id TEXT, overall_score INTEGER,
  category_scores TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor_role TEXT, action TEXT, target TEXT);
CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_ind_threat ON indicators(threat_id);
CREATE INDEX IF NOT EXISTS idx_thr_cat ON threats(category);
CREATE INDEX IF NOT EXISTS idx_thr_sev ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_thr_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_thr_last ON threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_thr_campaign ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_alert_threat ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_map_threat ON attack_mappings(threat_id);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(config: dict, reset: bool = False) -> None:
    """Create schema and seed it from the synthetic CSVs/JSON if the DB is empty."""
    from .services import threat_service, awareness_service
    path = config["DB_PATH"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if reset and os.path.exists(path):
        os.remove(path)
    conn = connect(path)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0:
        threat_service.seed_database(conn, config["DATASET_CSV"], config["VULN_CSV"])
        awareness_service.seed_modules(conn, config["MODULES_JSON"])
        awareness_service.seed_demo_quiz_history(conn)
    conn.close()


if __name__ == "__main__":
    from .config import Config
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete and rebuild the database")
    args = ap.parse_args()
    cfg = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
    init_db(cfg, reset=args.reset)
    c = connect(cfg["DB_PATH"])
    print("Database ready:", cfg["DB_PATH"])
    for t in ("threats", "indicators", "alerts", "vulnerabilities", "attack_mappings"):
        print(f"  {t}: {c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]}")
