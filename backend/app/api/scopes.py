from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import User
from app.models.scan import Scope
from app.schemas import ScopeCreate, ScopeOut
from app.services.audit import audit, client_ip
from app.services.target_validation import TargetError, validate_scope_cidr

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.get("", response_model=list[ScopeOut])
def list_scopes(db: Session = Depends(get_db), user: User = Depends(require_role("admin", "analyst"))):
    return db.scalars(select(Scope).order_by(Scope.id)).all()


@router.post("", response_model=ScopeOut, status_code=201)
def create_scope(body: ScopeCreate, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role("admin"))):
    ip = client_ip(request)
    if not body.authorization_confirmed:
        raise HTTPException(400, "Vous devez confirmer être autorisé à analyser ce périmètre")
    try:
        net = validate_scope_cidr(body.cidr, body.allow_public)
    except TargetError as e:
        audit(db, "scope_create", "rejected", user_id=admin.id, username=admin.username,
              target=body.cidr[:200], source_ip=ip)
        raise HTTPException(400, str(e))
    scope = Scope(name=body.name, cidr=str(net), description=body.description,
                  allow_public=body.allow_public, created_by=admin.id)
    db.add(scope)
    db.commit()
    audit(db, "legal_ack", "accepted", user_id=admin.id, username=admin.username,
          target=scope.cidr, source_ip=ip)
    audit(db, "scope_create", "success", user_id=admin.id, username=admin.username,
          target=scope.cidr, source_ip=ip)
    return scope
