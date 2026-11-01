from __future__ import annotations

import getpass
import sys

from sqlalchemy import select

from backend.app.auth import create_user
from backend.app.database import SessionLocal, UserRow, create_tables


def create_first_admin() -> int:
    create_tables()
    username = input("Administrator username: ").strip()
    password = getpass.getpass("Administrator password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    with SessionLocal() as session:
        if session.scalar(select(UserRow.id).where(UserRow.role.in_(["super_admin", "security_admin"]))) is not None:
            print("An administrator already exists; refusing first-admin setup.", file=sys.stderr)
            return 1
        try:
            user = create_user(session, username, password, "super_admin")
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 1
        session.commit()
        print(f"Created administrator account '{user.username}'.")
    return 0


def main() -> int:
    if sys.argv[1:] != ["create-admin"]:
        print("Usage: python -m backend.app.admin create-admin", file=sys.stderr)
        return 2
    return create_first_admin()


if __name__ == "__main__":
    raise SystemExit(main())
