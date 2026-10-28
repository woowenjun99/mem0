import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth import generate_api_key, require_auth, verify_password
from db import get_db
from models import APIKey, User
from rate_limit import limiter
from schemas import MessageResponse

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class CreateKeyRequest(BaseModel):
    label: str
    password: str


class CreateKeyResponse(BaseModel):
    id: str
    key: str
    label: str
    key_prefix: str
    created_at: datetime


class KeyListItem(BaseModel):
    id: str
    label: str
    key_prefix: str
    created_at: datetime
    last_used_at: datetime | None

    model_config = {"from_attributes": True}


@router.get("", response_model=list[KeyListItem])
def list_keys(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    keys = (
        db.execute(
            select(APIKey)
            .where(APIKey.created_by == user.id, APIKey.revoked_at.is_(None))
            .order_by(APIKey.created_at.desc())
        )
        .scalars()
        .all()
    )
    return [
        KeyListItem(
            id=str(k.id),
            label=k.label,
            key_prefix=k.key_prefix,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.post("", response_model=CreateKeyResponse, status_code=201)
@limiter.limit("5/minute")
def create_key(
    request: Request, body: CreateKeyRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)
):
    if getattr(request.state, "auth_type", "none") != "bearer":
        raise HTTPException(status_code=403, detail="A password-confirmed session is required.")
    db_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if db_user is None or not verify_password(body.password, db_user.password_hash):
        raise HTTPException(status_code=403, detail="Password is incorrect.")
    full_key, prefix, key_hash = generate_api_key()
    api_key = APIKey(key_prefix=prefix, key_hash=key_hash, label=body.label, created_by=user.id)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return CreateKeyResponse(
        id=str(api_key.id),
        key=full_key,
        label=api_key.label,
        key_prefix=prefix,
        created_at=api_key.created_at,
    )


@router.delete("/{key_id}", response_model=MessageResponse)
def revoke_key(key_id: str, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    try:
        key_uuid = uuid.UUID(key_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="API key not found.")
    api_key = db.get(APIKey, key_uuid)
    if api_key is None or api_key.created_by != user.id:
        raise HTTPException(status_code=404, detail="API key not found.")
    if api_key.revoked_at is not None:
        raise HTTPException(status_code=400, detail="API key is already revoked.")

    api_key.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return MessageResponse(message="API key revoked.")
