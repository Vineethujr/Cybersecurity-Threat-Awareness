"""Central configuration. Secrets come from environment variables (.env), never from code."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


class Config:
    DB_PATH = os.getenv("DB_PATH", str(ROOT / "data" / "threat_intel.db"))
    if not os.path.isabs(DB_PATH):
        DB_PATH = str(ROOT / DB_PATH)
    DATASET_CSV = str(ROOT / "data" / "threat_intelligence_dataset.csv")
    VULN_CSV = str(ROOT / "data" / "vulnerabilities.csv")
    MODULES_JSON = str(ROOT / "awareness" / "modules.json")
    QUIZ_JSON = str(ROOT / "awareness" / "quiz_questions.json")
    FRONTEND_DIR = str(ROOT / "frontend")
    # API key -> role. Defaults are DEMO ONLY; override them in .env.
    API_KEYS = {
        os.getenv("ANALYST_API_KEY", "demo-analyst-key"): "analyst",
        os.getenv("ADMIN_API_KEY", "demo-admin-key"): "admin",
    }
    RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "240"))
    TESTING = False
