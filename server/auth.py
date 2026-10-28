import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from db import SessionLocal
from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from models import APIKey, RefreshSession, RefreshTokenJti, User
from passlib.context import CryptContext
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in {"1", "true", "yes", "on"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def dummy_verify_password() -> None:
    """Burn the same bcrypt cycles as a real verify so login timing doesn't leak whether an email exists."""
    pwd_context.dummy_verify()


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix, hash)."""
    raw = secrets.token_urlsafe(32)
    full_key = f"m0sk_{raw}"
    prefix = full_key[:12]
    key_hash = pwd_context.hash(full_key)
    return full_key, prefix, key_hash


def verify_api_key_hash(plain_key: str, hashed: str) -> bool:
    return pwd_context.verify(plain_key, hashed)


def _get_secret() -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured.")
    return JWT_SECRET


def _credential_version(user: User) -> str:
    return hmac.new(_get_secret().encode(), user.password_hash.encode(), hashlib.sha256).hexdigest()


def verify_token_user(payload: dict, user: User | None) -> User:
    version = payload.get("auth_version")
    credential = payload.get("credential_version")
    if (
        user is None
        or type(version) is not int
        or version != user.auth_version
        or not isinstance(credential, str)
        or not hmac.compare_digest(credential, _credential_version(user))
    ):
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return user


def lock_current_user(user: User, db: Session) -> User:
    """Serialize credential changes with issuance and recheck detached authentication."""
    current = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if current is None or current.auth_version != user.auth_version or current.password_hash != user.password_hash:
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return current


def revoke_user_sessions(user: User, db: Session, *, revoke_api_keys: bool = False) -> None:
    """Caller holds the user lock and commits the credential change atomically."""
    user.auth_version += 1
    db.execute(delete(RefreshTokenJti).where(RefreshTokenJti.user_id == user.id))
    db.execute(delete(RefreshSession).where(RefreshSession.user_id == user.id))
    if revoke_api_keys:
        db.execute(
            update(APIKey)
            .where(APIKey.created_by == user.id, APIKey.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )


def create_access_token(user: User, session_id: uuid.UUID) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "sid": str(session_id),
        "exp": expire,
        "type": "access",
        "credential_version": _credential_version(user),
        "auth_version": user.auth_version,
    }
    return jwt.encode(payload, _get_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user: User, db: Session, session: RefreshSession | None = None) -> tuple[str, uuid.UUID]:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    if session is None:
        session = RefreshSession(id=uuid.uuid4(), user_id=user.id)
        db.add(session)
    jti = uuid.uuid4()
    db.add(RefreshTokenJti(jti=jti, user_id=user.id, session_id=session.id, expires_at=expire))
    payload = {
        "sub": str(user.id),
        "exp": expire,
        "jti": str(jti),
        "type": "refresh",
        "credential_version": _credential_version(user),
        "auth_version": user.auth_version,
    }
    token = jwt.encode(payload, _get_secret(), algorithm=JWT_ALGORITHM)
    return token, session.id


def lock_refresh_session(jti: str, db: Session) -> tuple[RefreshTokenJti, RefreshSession]:
    try:
        jti_uuid = uuid.UUID(jti)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    token = db.get(RefreshTokenJti, jti_uuid)
    if token is None or token.session_id is None:
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    session = db.scalar(select(RefreshSession).where(RefreshSession.id == token.session_id).with_for_update())
    if session is None:
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    # Re-read after acquiring the family lock: another rotation may have consumed it.
    db.refresh(token)
    return token, session


def rotate_refresh_token(jti: str, user: User, db: Session) -> tuple[str, uuid.UUID]:
    token, session = lock_refresh_session(jti, db)
    now = datetime.now(timezone.utc)
    if session.user_id != user.id or token.user_id != user.id or session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Refresh token is no longer valid.")
    if token.used_at is not None:
        session.revoked_at = now
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token reuse detected.")
    # Token expiry is verified from the signed JWT by decode_token.
    token.used_at = now
    return create_refresh_token(user, db, session)


def revoke_refresh_session(jti: str, db: Session) -> None:
    token, session = lock_refresh_session(jti, db)
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _get_secret(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _mark_auth_type(request: Request, auth_type: str) -> None:
    request.state.auth_type = auth_type


def _get_default_user(db: Session) -> User | None:
    return db.scalar(select(User).order_by(User.created_at.asc()))


def _resolve_user_from_jwt(token: str, db: Session) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type.")
    try:
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    user = verify_token_user(payload, db.get(User, user_id))
    session = db.get(RefreshSession, session_id)
    if session is None or session.user_id != user.id or session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return user


def _resolve_user_from_api_key(key: str, db: Session) -> User:
    prefix = key[:12] if len(key) >= 12 else key
    candidates = (
        db.execute(select(APIKey).where(APIKey.key_prefix == prefix, APIKey.revoked_at.is_(None))).scalars().all()
    )

    for candidate in candidates:
        # Recovery holds this same owner lock. Reload after acquiring it so an
        # earlier candidate scan cannot authenticate a key revoked during reset.
        user = db.scalar(select(User).where(User.id == candidate.created_by).with_for_update())
        if user is None:
            continue
        db.refresh(candidate)
        if candidate.revoked_at is not None:
            continue
        if verify_api_key_hash(key, candidate.key_hash):
            candidate.last_used_at = datetime.now(timezone.utc)
            db.commit()
            return user

    raise HTTPException(status_code=401, detail="Invalid API key.")


async def verify_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Depends(api_key_header),
) -> User | None:
    """Authenticate via JWT, X-API-Key, or legacy ADMIN_API_KEY. Returns User or None.

    A short-lived session is opened only on the branches that query the DB, so no
    pooled connection is held for the lifetime of the (possibly long-running) request.
    """
    if credentials is not None:
        _mark_auth_type(request, "bearer")
        with SessionLocal() as db:
            return _resolve_user_from_jwt(credentials.credentials, db)

    if x_api_key is not None:
        if ADMIN_API_KEY and secrets.compare_digest(x_api_key, ADMIN_API_KEY):
            _mark_auth_type(request, "admin_api_key")
            return None
        _mark_auth_type(request, "api_key")
        with SessionLocal() as db:
            return _resolve_user_from_api_key(x_api_key, db)

    if AUTH_DISABLED:
        _mark_auth_type(request, "disabled")
        return None

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_auth(
    request: Request,
    user: User | None = Depends(verify_auth),
) -> User:
    """Like verify_auth but guarantees a non-None User. Use for endpoints that require auth."""
    if user is None:
        if getattr(request.state, "auth_type", "none") in {"admin_api_key", "disabled"}:
            with SessionLocal() as db:
                default_user = _get_default_user(db)
            if default_user is not None:
                return default_user
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


_BOOTSTRAP_ADMIN = User(
    id=uuid.UUID(int=0),
    name="admin_api_key",
    email="",
    password_hash="",
    role="admin",
    created_at=datetime.min.replace(tzinfo=timezone.utc),
)


async def require_admin(
    request: Request,
    user: User | None = Depends(verify_auth),
) -> User:
    """Like require_auth but also enforces admin role.

    ADMIN_API_KEY and AUTH_DISABLED callers are treated as admin even when
    the users table is empty (fresh-deploy bootstrap).
    """
    auth_type = getattr(request.state, "auth_type", "none")
    if user is None:
        if auth_type in {"admin_api_key", "disabled"}:
            with SessionLocal() as db:
                default_user = _get_default_user(db)
            if default_user is not None:
                if default_user.role != "admin":
                    raise HTTPException(status_code=403, detail="Admin role required.")
                return default_user
            return _BOOTSTRAP_ADMIN
        raise HTTPException(status_code=401, detail="Authentication required.")
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required.")
    return user
