from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import User
from app.models.scan import Host, Scan, Service
from app.schemas import HostOut, HostUpdate
from app.services.audit import audit, client_ip

router = APIRouter(prefix="/hosts", tags=["hosts"])


def _host_query():
    return select(Host).options(selectinload(Host.services).selectinload(Service.vulnerabilities))


@router.get("", response_model=list[HostOut])
def list_hosts(
    scan_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))
):
    if scan_id is None:  # par défaut : dernier scan terminé
        scan_id = db.scalar(select(Scan.id).where(Scan.status == "done").order_by(Scan.id.desc()).limit(1))
        if scan_id is None:
            return []
    return db.scalars(_host_query().where(Host.scan_id == scan_id).order_by(Host.id)).all()


@router.get("/{host_id}", response_model=HostOut)
def get_host(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    host = db.scalar(_host_query().where(Host.id == host_id))
    if host is None:
        raise HTTPException(404, "Host not found")
    return host


@router.patch("/{host_id}", response_model=HostOut)
def update_host(
    host_id: int,
    body: HostUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    host = db.scalar(_host_query().where(Host.id == host_id))
    if host is None:
        raise HTTPException(404, "Host not found")
    host.criticality = body.criticality
    db.commit()
    audit(
        db,
        "host_criticality",
        "success",
        user_id=user.id,
        username=user.username,
        target=f"{host.id}:{body.criticality}",
        source_ip=client_ip(request),
    )
    return host
