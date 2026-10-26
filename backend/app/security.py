import hashlib
import re
import secrets
from datetime import timedelta
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import settings
from app.timeutils import utcnow

ph = PasswordHasher()  # Argon2id par défaut
DUMMY_HASH = ph.hash("dummy-password-for-timing")  # évite de révéler si un compte existe

_COMMON_FILE = Path(__file__).parent / "data" / "common_passwords.txt"  # SecLists : 10k-most-common (licence MIT)
_BUILTIN = {
    "password",
    "azerty",
    "azertyuiop",
    "qwerty",
    "qwertyuiop",
    "motdepasse",
    "administrator",
    "admin",
    "welcome",
    "bonjour",
    "letmein",
    "iloveyou",
    "changeme",
    "abcdefghijkl",
    "netsentry",
}
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t"})


def _load_common() -> frozenset[str]:
    words = set(_BUILTIN)
    if _COMMON_FILE.exists():
        text = _COMMON_FILE.read_text(encoding="utf-8", errors="ignore")
        words |= {w.strip().lower() for w in text.splitlines() if w.strip()}
    return frozenset(words)


COMMON_PASSWORDS = _load_common()


def _cores(password: str) -> set[str]:
    """Mots de base : sans chiffres/symboles de début et de fin, avec et sans substitutions (@ -> a, 0 -> o...)."""
    low = password.lower()
    letters_only = re.sub(r"[^a-z]", "", low)
    trimmed = re.sub(r"^[^a-z@$]+", "", re.sub(r"[^a-z]+$", "", low))
    leet = re.sub(r"[^a-z]", "", trimmed.translate(_LEET))
    return {letters_only, leet} - {""}


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
    if not re.search(r"[a-z]", password.lower()):
        raise ValueError("Le mot de passe doit contenir des lettres")
    if password.lower() in COMMON_PASSWORDS or _cores(password) & COMMON_PASSWORDS:
        raise ValueError("Mot de passe trop courant (ou variante d'un mot de passe courant)")
    if len(set(password)) < 5:
        raise ValueError("Mot de passe trop répétitif")
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
