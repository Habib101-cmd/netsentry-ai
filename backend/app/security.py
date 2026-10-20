import hashlib
import secrets
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import settings
from app.timeutils import utcnow

ph = PasswordHasher()  # Argon2id par défaut
DUMMY_HASH = ph.hash("dummy-password-for-timing")  # évite de révéler si un compte existe

# À remplacer plus tard par une vraie liste (ex. top 1000 de SecLists)
COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiop12", "azertyuiop12",
    "administrator", "admin1234567", "motdepasse123", "letmein12345", "welcome12345",
    "changeme1234", "iloveyou1234", "123456123456", "passw0rd1234", "abcdefghijkl",
}


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def validate_password(password: str, username: str | None = None) -> None:
    if len(password) < 12:
        raise ValueError("Mot de passe trop court (12 caractères minimum)")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("Mot de passe trop courant")
    if username and username.lower() in password.lower():
        raise ValueError("Le mot de passe ne doit pas contenir l'identifiant")


def create_access_token(user) -> str:
    now = utcnow()
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
