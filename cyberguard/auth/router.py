from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cyberguard.auth.dependencies import get_current_session, get_current_user
from cyberguard.auth.schemas import LoginRequest, RegistrationRequest, TokenResponse, UserProfile
from cyberguard.auth.security import (
    create_access_token,
    DUMMY_PASSWORD_HASH,
    get_jwt_signing_key,
    hash_password,
    new_session_id,
    verify_password,
)
from cyberguard.core.config import settings
from cyberguard.db import get_db
from cyberguard.db.models import User, UserSession


router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", response_model=UserProfile, status_code=status.HTTP_201_CREATED)
def register_user(request: RegistrationRequest, db: Session = Depends(get_db)) -> UserProfile:
    if db.query(User).filter(
        (User.email == request.email) | (User.username == request.username)
    ).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        )

    user = User(
        username=request.username,
        email=request.email,
        password_hash=hash_password(request.password.get_secret_value()),
        role="user",
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        ) from None

    db.refresh(user)
    return UserProfile.model_validate(user)


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == request.email).first()
    password_matches = verify_password(
        request.password.get_secret_value(),
        user.password_hash if user is not None else DUMMY_PASSWORD_HASH,
    )
    if (
        user is None
        or not user.is_active
        or not password_matches
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    get_jwt_signing_key()
    session_id = new_session_id()
    token, expires_at = create_access_token(user.id, session_id)
    user_session = UserSession(
        id=session_id,
        user_id=user.id,
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )
    db.add(user_session)
    db.commit()

    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserProfile)
def read_current_user(user: User = Depends(get_current_user)) -> UserProfile:
    return UserProfile.model_validate(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    user_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> None:
    user_session.revoked_at = datetime.now(timezone.utc)
    db.add(user_session)
    db.commit()
