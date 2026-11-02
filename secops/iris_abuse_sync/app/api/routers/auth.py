from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import log_audit_event
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import get_current_user, get_optional_user, require_role
from app.core.security import (
    generate_csrf_token,
    generate_session_token,
    hash_password,
    hash_session_token,
    verify_password,
)
from app.models.user import User, UserSession
from app.schemas.auth import LoginRequest, UserCreateRequest, UserResponse, UserUpdateRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = (
        db.query(User)
        .filter((User.username == payload.username.strip()) | (User.email == payload.username.strip()))
        .first()
    )
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        log_audit_event(
            db,
            action="auth.login_failed",
            module="auth",
            username=payload.username,
            ip_address=request.client.host if request.client else None,
            details="Intento de inicio de sesión fallido.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos.",
        )

    raw_token, token_hash = generate_session_token()
    csrf_token = generate_csrf_token(token_hash)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=settings.SESSION_TTL_HOURS)

    sess = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        csrf_token=csrf_token,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:500],
        expires_at=expires_at,
    )
    user.last_login_at = now
    db.add(sess)
    db.commit()

    log_audit_event(
        db,
        action="auth.login_success",
        module="auth",
        user=user,
        ip_address=request.client.host if request.client else None,
        details=f"Inicio de sesión exitoso (rol: {user.role}).",
    )

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        samesite="lax",
        max_age=settings.SESSION_TTL_HOURS * 3600,
        path="/",
    )

    return {
        "status": "ok",
        "token": raw_token,
        "csrf_token": csrf_token,
        "expires_at": expires_at.isoformat(),
        "user": UserResponse.model_validate(user).model_dump(mode="json"),
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw_token:
        auth_h = request.headers.get("authorization", "")
        if auth_h.lower().startswith("bearer "):
            raw_token = auth_h.split(" ", 1)[1].strip()
    if raw_token:
        t_hash = hash_session_token(raw_token)
        sess = db.query(UserSession).filter(UserSession.token_hash == t_hash).first()
        if sess:
            sess.revoked_at = datetime.now(timezone.utc)
            db.commit()

    if user:
        log_audit_event(
            db,
            action="auth.logout",
            module="auth",
            user=user,
            ip_address=request.client.host if request.client else None,
            details="Cierre de sesión.",
        )

    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    return {"status": "ok", "message": "Sesión cerrada correctamente."}


@router.get("/me")
def get_me(request: Request, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)):
    if not user:
        return {"authenticated": False, "user": None}
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_token = generate_csrf_token(hash_session_token(raw_token)) if raw_token else None
    return {
        "authenticated": True,
        "csrf_token": csrf_token,
        "user": UserResponse.model_validate(user).model_dump(mode="json"),
    }


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("supervisor")),
):
    users = db.query(User).order_by(User.id.asc()).all()
    return {
        "status": "ok",
        "users": [UserResponse.model_validate(u).model_dump(mode="json") for u in users],
    }


@router.post("/users")
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    existing = (
        db.query(User)
        .filter((User.username == payload.username.strip()) | (User.email == payload.email.strip()))
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario o correo ya está registrado.")
    new_user = User(
        username=payload.username.strip(),
        email=payload.email.strip(),
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        allowed_orgs=payload.allowed_orgs or ["NBX", "HP"],
        iris_user_id=payload.iris_user_id or 2,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db,
        action="user.created",
        module="admin",
        user=current_user,
        after_data={"username": new_user.username, "role": new_user.role, "allowed_orgs": new_user.allowed_orgs},
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "user": UserResponse.model_validate(new_user).model_dump(mode="json")}


@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    before = {"role": target.role, "is_active": target.is_active, "allowed_orgs": target.allowed_orgs}
    if payload.email is not None:
        target.email = payload.email.strip()
    if payload.full_name is not None:
        target.full_name = payload.full_name.strip()
    if payload.password:
        target.password_hash = hash_password(payload.password)
    if payload.role is not None:
        target.role = payload.role
    if payload.allowed_orgs is not None:
        target.allowed_orgs = payload.allowed_orgs
    if payload.is_active is not None:
        target.is_active = payload.is_active
    if payload.iris_user_id is not None:
        target.iris_user_id = payload.iris_user_id
    db.commit()
    db.refresh(target)

    log_audit_event(
        db,
        action="user.updated",
        module="admin",
        user=current_user,
        before_data=before,
        after_data={"role": target.role, "is_active": target.is_active, "allowed_orgs": target.allowed_orgs},
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "user": UserResponse.model_validate(target).model_dump(mode="json")}

