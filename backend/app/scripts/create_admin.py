import getpass
import sys

from sqlalchemy import select

from app.database import SessionLocal
from app.models.auth import User
from app.security import hash_password, validate_password


def main():
    username = input("Identifiant admin : ").strip()
    password = getpass.getpass("Mot de passe temporaire (12+ caractères) : ")
    try:
        validate_password(password, username)
    except ValueError as e:
        print(f"Refusé : {e}")
        sys.exit(1)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            print("Cet utilisateur existe déjà.")
            sys.exit(1)
        db.add(User(username=username, password_hash=hash_password(password), role="admin", must_change_password=True))
        db.commit()
    print("Admin créé. Changement de mot de passe obligatoire à la première connexion.")


if __name__ == "__main__":
    main()
