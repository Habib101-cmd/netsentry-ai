from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import User
from app.models.report import Report
from app.models.scan import Scan
from app.reports.builder import build_report_pdf
from app.schemas import ReportCreate, ReportOut
from app.services.audit import audit, client_ip

router = APIRouter(prefix="/reports", tags=["reports"])
ROLES = ("admin", "analyst")


@router.post("", response_model=ReportOut, status_code=201)
def create_report(
    body: ReportCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_role(*ROLES))
):
    scan = db.get(Scan, body.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status != "done":
        raise HTTPException(409, "Le scan n'est pas terminé")
    pdf = build_report_pdf(db, scan, user.username)
    report = Report(scan_id=scan.id, generated_by=user.id, content=pdf, size_bytes=len(pdf))
    db.add(report)
    db.commit()
    audit(
        db,
        "report_generate",
        "success",
        user_id=user.id,
        username=user.username,
        target=f"{report.id}:scan{scan.id}",
        source_ip=client_ip(request),
    )
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(db: Session = Depends(get_db), user: User = Depends(require_role(*ROLES))):
    stmt = select(Report).options(defer(Report.content)).order_by(Report.id.desc()).limit(100)
    return db.scalars(stmt).all()


@router.get("/{report_id}/download")
def download_report(
    report_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_role(*ROLES))
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "Report not found")
    audit(
        db,
        "report_download",
        "success",
        user_id=user.id,
        username=user.username,
        target=str(report.id),
        source_ip=client_ip(request),
    )
    name = f"netsentry-scan-{report.scan_id}-rapport-{report.id}.pdf"
    return Response(
        content=report.content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
    )
