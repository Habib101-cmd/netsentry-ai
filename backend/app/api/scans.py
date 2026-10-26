from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.ai_engine.service import missing_reason
from app.auth.deps import require_role
from app.database import get_db
from app.models.anomaly import AnomalyResult
from app.models.auth import User
from app.models.scan import Scan, Scope
from app.schemas import AnomalyOut, ScanCreate, ScanOut
from app.services.audit import audit, client_ip
from app.services.compare import compare_scans
from app.services.netmap import build_map, build_timeline
from app.services.target_validation import TargetError, validate_target
from app.timeutils import utcnow

router = APIRouter(prefix="/scans", tags=["scans"])
MAX_QUEUE = 5  # SEC-09 : limite de scans en attente/en cours


@router.get("/{scan_id}/compare/{other_id}")
def compare(
    scan_id: int, other_id: int, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))
):
    """scan_id = scan de référence (avant), other_id = scan comparé (après)."""
    base, other = db.get(Scan, scan_id), db.get(Scan, other_id)
    if base is None or other is None:
        raise HTTPException(404, "Scan not found")
    if base.status != "done" or other.status != "done":
        raise HTTPException(409, "Les deux scans doivent être terminés")
    return compare_scans(db, base, other)


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(
    body: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    ip = client_ip(request)
    scopes = [(s.id, s.cidr, s.allow_public) for s in db.scalars(select(Scope).where(Scope.is_active))]
    try:
        net, scope_id = validate_target(body.target, scopes)
    except TargetError as e:
        audit(
            db,
            "scan_launch",
            "rejected",
            user_id=user.id,
            username=user.username,
            target=body.target[:200],
            source_ip=ip,
        )
        raise HTTPException(400, str(e))
    active = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["pending", "running"])))
    if active >= MAX_QUEUE:
        raise HTTPException(429, "Trop de scans en attente")
    scan = Scan(scope_id=scope_id, target=str(net), profile=body.profile, status="pending", created_by=user.id)
    db.add(scan)
    db.commit()
    audit(
        db,
        "scan_launch",
        "success",
        user_id=user.id,
        username=user.username,
        target=f"{scan.id}:{scan.target}:{scan.profile}",
        source_ip=ip,
    )
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    return db.scalars(select(Scan).order_by(Scan.id.desc()).limit(100)).all()


@router.get("/timeline")
def timeline(
    profile: Literal["discovery", "standard", "deep"] | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    return build_timeline(db, profile)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status == "pending":
        scan.status = "cancelled"
        scan.finished_at = utcnow()
    elif scan.status == "running":
        scan.cancel_requested = True  # le worker arrêtera Nmap
    else:
        raise HTTPException(409, "Scan déjà terminé")
    db.commit()
    audit(
        db,
        "scan_cancel",
        "success",
        user_id=user.id,
        username=user.username,
        target=str(scan.id),
        source_ip=client_ip(request),
    )
    return scan


@router.get("/{scan_id}/map")
def network_map(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status != "done":
        raise HTTPException(409, "Le scan n'est pas terminé")
    return build_map(db, scan)


@router.get("/{scan_id}/anomalies")
def scan_anomalies(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    rows = db.scalars(
        select(AnomalyResult)
        .where(AnomalyResult.scan_id == scan_id)
        .options(selectinload(AnomalyResult.host))
        .order_by(AnomalyResult.score.desc())
    ).all()
    return {
        "scan_id": scan_id,
        "model_version": rows[0].model_version if rows else None,
        "message": None if rows else missing_reason(db, scan),
        "results": [AnomalyOut.model_validate(r) for r in rows],
    }
