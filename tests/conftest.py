"""Fixtures + a hook that writes reports/test_report.md (Test ID, Scenario, Input, Expected, Actual, Pass/Fail)."""
import sqlite3
from pathlib import Path
import pytest
from backend.app import create_app
from backend.config import Config
from backend.db import SCHEMA, connect

REPORT, RESULTS = Path(__file__).resolve().parent.parent / "reports" / "test_report.md", []
AUTH = {"X-API-Key": "demo-analyst-key"}


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("db") / "test.db")
    return create_app({"DB_PATH": path, "TESTING": True, "RATE_LIMIT_PER_MIN": 0})


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def conn(app):
    c = connect(app.config["DB_PATH"])
    yield c
    c.close()


@pytest.fixture()
def empty_conn(tmp_path):
    c = connect(str(tmp_path / "empty.db"))
    c.executescript(SCHEMA)
    yield c
    c.close()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    rep = (yield).get_result()
    if rep.when == "call":
        parts = [p.strip() for p in (item.function.__doc__ or "").split("::")] + ["", "", ""]
        tid = item.name.split("_")[1].upper()
        RESULTS.append((tid, parts[0], parts[1], parts[2], "As expected" if rep.passed else "See failure output",
                        "Pass" if rep.passed else "FAIL"))


def pytest_sessionfinish(session, exitstatus):
    if not RESULTS:
        return
    REPORT.parent.mkdir(exist_ok=True)
    lines = ["# Automated Test Report", "", "| Test ID | Scenario | Input | Expected Result | Actual Result | Pass/Fail |",
             "|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in sorted(RESULTS)]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
