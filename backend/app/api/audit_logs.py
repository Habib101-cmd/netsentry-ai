from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import AuditLog, User
from app.schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                    db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    return db.scalars(stmt).all()
