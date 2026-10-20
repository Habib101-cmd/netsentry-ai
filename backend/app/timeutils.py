from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime) -> datetime:
    """Rend une date comparable (certaines bases renvoient des dates sans fuseau)."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
