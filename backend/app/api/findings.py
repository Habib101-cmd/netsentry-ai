from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import User
from app.models.scan import Finding, Scan
from app.schemas import FindingOut, FindingUpdate
from app.services.audit import audit, client_ip

router = APIRouter(prefix="/findings", tags=["findings"])
ROLES = ("admin", "analyst")


def _latest_scan_id(db: Session) -> int | None:
    return db.scalar(select(Scan.id).where(Scan.status == "done").order_by(Scan.id.desc()).limit(1))


@router.get("/summary")
def summary(scan_id: int | None = None, db: Session = Depends(get_db),
            user: User = Depends(require_role(*ROLES))):
    scan_id = scan_id or _latest_scan_id(db)
    rows = db.execute(select(Finding.level, func.count()).where(Finding.scan_id == scan_id)
                      .group_by(Finding.level)).all()
    return {"scan_id": scan_id, "by_level": {lvl: n for lvl, n in rows}}


@router.get("", response_model=list[FindingOut])
def list_findings(scan_id: int | None = None, level: str | None = None, status: str | None = None,
                  host_id: int | None = None, q: str | None = Query(None, max_length=100),
                  limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                  db: Session = Depends(get_db), user: User = Depends(require_role(*ROLES))):
    scan_id = scan_id or _latest_scan_id(db)
    if scan_id is None:
        return []
    stmt = select(Finding).where(Finding.scan_id == scan_id).options(selectinload(Finding.host))
    if level:
        stmt = stmt.where(Finding.level == level)
    if status:
        stmt = stmt.where(Finding.status == status)
    if host_id:
        stmt = stmt.where(Finding.host_id == host_id)
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q}%"))
    stmt = stmt.order_by(Finding.score.desc(), Finding.id).limit(limit).offset(offset)
    return db.scalars(stmt).all()


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, request: Request,
                   db: Session = Depends(get_db), user: User = Depends(require_role(*ROLES))):
    f = db.scalar(select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.host)))
    if f is None:
        raise HTTPException(404, "Finding not found")
    if body.status == "accepted" and not (body.comment and body.comment.strip()):
        raise HTTPException(400, "Un commentaire est obligatoire pour accepter un risque")
    f.status = body.status
    if body.status == "accepted":
        f.accepted_comment, f.accepted_by = body.comment.strip(), user.id
    else:
        f.accepted_comment, f.accepted_by = None, None
    db.commit()
    audit(db, "finding_status", "success", user_id=user.id, username=user.username,
          target=f"{f.id}:{body.status}", source_ip=client_ip(request))
    return f
