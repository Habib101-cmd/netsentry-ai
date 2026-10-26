from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.config import settings
from app.database import get_db
from app.models.auth import RefreshToken, User
from app.ratelimit import limiter
from app.schemas import ChangePasswordIn, LoginIn, RefreshIn, TokenOut, UserOut
from app.security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    hash_token,
    new_refresh_token,
    validate_password,
    verify_password,
)
from app.services.audit import audit, client_ip
from app.timeutils import as_utc, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])
MAX_FAILURES = 5
LOCK_MINUTES = 15


def _issue_tokens(db: Session, user: User) -> TokenOut:
    raw = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=utcnow() + timedelta(days=settings.refresh_token_days),
        )
    )
    db.commit()
    return TokenOut(
        access_token=create_access_token(user), refresh_token=raw, must_change_password=user.must_change_password
    )


@router.post("/login", response_model=TokenOut)
@limiter.limit(settings.login_rate_limit)
def login(request: Request, body: LoginIn, db: Session = Depends(get_db)):
    ip = client_ip(request)
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None:
        verify_password(body.password, DUMMY_HASH)
        audit(db, "login", "failure", username=body.username[:64], source_ip=ip)
        raise HTTPException(401, "Invalid credentials")

    now = utcnow()
    if user.locked_until and as_utc(user.locked_until) > now:
        audit(db, "login", "locked", user_id=user.id, username=user.username, source_ip=ip)
        raise HTTPException(429, "Account temporarily locked")

    if not user.is_active or not verify_password(body.password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILURES:
            user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
            user.failed_attempts = 0
        db.commit()
        audit(db, "login", "failure", user_id=user.id, username=user.username, source_ip=ip)
        raise HTTPException(401, "Invalid credentials")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()
    audit(db, "login", "success", user_id=user.id, username=user.username, source_ip=ip)
    return _issue_tokens(db, user)


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, body: RefreshIn, db: Session = Depends(get_db)):
    token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(body.refresh_token)))
    if token is None or token.revoked or as_utc(token.expires_at) < utcnow():
        raise HTTPException(401, "Invalid refresh token")
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "Invalid refresh token")
    token.revoked = True  # rotation : un refresh token ne sert qu'une fois
    db.commit()
    audit(db, "token_refresh", "success", user_id=user.id, username=user.username, source_ip=client_ip(request))
    return _issue_tokens(db, user)


@router.post("/logout")
def logout(request: Request, body: RefreshIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    token = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(body.refresh_token), RefreshToken.user_id == user.id
        )
    )
    if token:
        token.revoked = True
        db.commit()
    audit(db, "logout", "success", user_id=user.id, username=user.username, source_ip=client_ip(request))
    return {"status": "ok"}


@router.post("/change-password")
def change_password(
    request: Request, body: ChangePasswordIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    ip = client_ip(request)
    if not verify_password(body.current_password, user.password_hash):
        audit(db, "change_password", "failure", user_id=user.id, username=user.username, source_ip=ip)
        raise HTTPException(400, "Current password incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(400, "Le nouveau mot de passe doit être différent")
    try:
        validate_password(body.new_password, user.username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(revoked=True))
    db.commit()
    audit(db, "change_password", "success", user_id=user.id, username=user.username, source_ip=ip)
    return {"status": "ok", "detail": "Reconnectez-vous avec le nouveau mot de passe"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
