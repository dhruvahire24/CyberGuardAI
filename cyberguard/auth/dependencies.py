from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from cyberguard.db import get_db
from cyberguard.db.models import User, UserSession
from cyberguard.auth.security import decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_session(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> UserSession:
    if credentials is None:
        raise unauthorized()

    try:
        claims = decode_access_token(credentials.credentials)
        user_id = int(claims["sub"])
        session_id = str(claims["sid"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise unauthorized() from None

    user_session = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if user_session is None:
        raise unauthorized()

    expiry = user_session.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise unauthorized()

    return user_session


def get_current_user(
    user_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, user_session.user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    return user
