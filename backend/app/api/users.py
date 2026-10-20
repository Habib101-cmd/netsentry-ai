from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models.auth import User
from app.schemas import UserCreate, UserOut
from app.security import hash_password, validate_password
from app.services.audit import audit, client_ip

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_role("admin"))):
    return db.scalars(select(User).order_by(User.id)).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_role("admin"))):
    try:
        validate_password(body.password, body.username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "Username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password),
                role=body.role, must_change_password=True)
    db.add(user)
    db.commit()
    audit(db, "user_create", "success", user_id=admin.id, username=admin.username,
          target=user.username, source_ip=client_ip(request))
    return user
