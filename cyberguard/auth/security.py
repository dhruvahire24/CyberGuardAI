from datetime import datetime, timedelta, timezone
import secrets
from typing import Any, Dict
from uuid import uuid4

import jwt
from fastapi import HTTPException, status
from pwdlib import PasswordHash

from cyberguard.core.config import settings


password_hasher = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(32))
JWT_ISSUER = "cyberguardai"
JWT_AUDIENCE = "cyberguardai-api"


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_hasher.verify(password, password_hash)


def get_jwt_signing_key() -> str:
    secret = settings.jwt_secret_key
    if not secret or len(secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured.",
        )
    return secret


def create_access_token(user_id: int, session_id: str) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
    claims: Dict[str, Any] = {
        "sub": str(user_id),
        "sid": session_id,
        "iat": now,
        "exp": expires_at,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    token = jwt.encode(claims, get_jwt_signing_key(), algorithm="HS256")
    return token, expires_at


def decode_access_token(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        get_jwt_signing_key(),
        algorithms=["HS256"],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={"require": ["sub", "sid", "iat", "exp", "iss", "aud"]},
    )


def new_session_id() -> str:
    return str(uuid4())
