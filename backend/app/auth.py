from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database import AuthSessionRow, UserRow


SESSION_COOKIE = "sentinelsoc_session"
SESSION_SECONDS = 8 * 60 * 60
PASSWORD_SCRYPT_N = 1 << 15
PASSWORD_SCRYPT_R = 8
PASSWORD_SCRYPT_P = 1
ROLES = {
    "super_admin",
    "security_admin",
    "soc_manager",
    "soc_analyst",
    "read_only_viewer",
}
READ_ROLES = ROLES
WRITE_ROLES = {"super_admin", "security_admin", "soc_manager", "soc_analyst"}
ADMIN_ROLES = {"super_admin", "security_admin"}
TEAM_ROLES = ADMIN_ROLES | {"soc_manager"}
ROLE_PERMISSIONS = {
    "super_admin": {"read", "write", "manage_users", "manage_settings"},
    "security_admin": {"read", "write", "manage_users", "manage_settings"},
    "soc_manager": {"read", "write", "manage_team"},
    "soc_analyst": {"read", "write"},
    "read_only_viewer": {"read"},
}


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("password must be between 12 and 1024 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_SCRYPT_N,
        r=PASSWORD_SCRYPT_R,
        p=PASSWORD_SCRYPT_P,
        dklen=64,
        maxmem=128 * 1024 * 1024,
    )
    return f"scrypt${PASSWORD_SCRYPT_N}${PASSWORD_SCRYPT_R}${PASSWORD_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = encoded_hash.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=128 * 1024 * 1024,
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session(session: Session, user: UserRow) -> tuple[str, str, AuthSessionRow]:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    record = AuthSessionRow(
        token_hash=token_hash(token),
        csrf_hash=token_hash(csrf_token),
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(seconds=SESSION_SECONDS),
    )
    session.add(record)
    return token, csrf_token, record


def verify_csrf(record: AuthSessionRow, candidate: str | None) -> bool:
    return bool(candidate) and hmac.compare_digest(record.csrf_hash, token_hash(candidate))


def role_dependency(
    get_current_user: Callable[..., UserRow],
    *allowed_roles: str,
) -> Callable[..., UserRow]:
    allowed = set(allowed_roles)

    def require_role(user: UserRow = Depends(get_current_user)) -> UserRow:
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return require_role


def create_user(session: Session, username: str, password: str, role: str) -> UserRow:
    normalized = username.strip().lower()
    if not normalized or len(normalized) > 64 or not normalized.replace("-", "").replace("_", "").isalnum():
        raise ValueError("username must contain only letters, numbers, underscores, or hyphens")
    if role not in ROLES:
        raise ValueError("unknown role")
    if session.scalar(select(UserRow).where(UserRow.username == normalized)) is not None:
        raise ValueError("username already exists")
    user = UserRow(
        id=str(uuid4()),
        username=normalized,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    return user
