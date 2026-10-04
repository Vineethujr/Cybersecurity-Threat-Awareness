"""Small time helpers. All timestamps are naive UTC ISO-8601 strings."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "").split("+")[0])


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()
