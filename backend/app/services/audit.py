from fastapi import Request
from sqlalchemy.orm import Session

from app.models.auth import AuditLog


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def audit(
    db: Session,
    action: str,
    result: str,
    *,
    user_id: int | None = None,
    username: str | None = None,
    target: str | None = None,
    source_ip: str | None = None,
) -> None:
    db.add(
        AuditLog(action=action, result=result, user_id=user_id, username=username, target=target, source_ip=source_ip)
    )
    db.commit()
