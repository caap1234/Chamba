from datetime import datetime, timezone
from typing import Callable, Optional
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import hash_session_token, verify_csrf_token
from app.models.user import User, UserSession

ROLE_HIERARCHY = {
    "readonly": 1,
    "analyst": 2,
    "supervisor": 3,
    "admin": 4,
}


def _extract_session(
    request: Request,
    db: Session,
    session_cookie: Optional[str] = None,
    auth_header: Optional[str] = None,
) -> tuple[Optional[User], Optional[UserSession]]:
    raw_token = session_cookie
    if not raw_token and auth_header and auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    if not raw_token:
        raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw_token:
        return None, None

    token_hash = hash_session_token(raw_token)
    sess = (
        db.query(UserSession)
        .filter(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if not sess:
        return None, None

    now = datetime.now(timezone.utc)
    exp = sess.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < now:
        return None, None

    user = db.query(User).filter(User.id == sess.user_id, User.is_active.is_(True)).first()
    if not user:
        return None, None
    return user, sess


def get_optional_user(
    request: Request,
    db: Session = Depends(get_db),
    soc_iris_session: Optional[str] = Cookie(default=None),
    authorization: Optional[str] = Header(default=None),
) -> Optional[User]:
    user, _ = _extract_session(request, db, soc_iris_session, authorization)
    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    soc_iris_session: Optional[str] = Cookie(default=None),
    authorization: Optional[str] = Header(default=None),
    x_csrf_token: Optional[str] = Header(default=None),
) -> User:
    user, sess = _extract_session(request, db, soc_iris_session, authorization)
    if not user or not sess:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión no válida o expirada. Inicia sesión en la consola SOC.",
        )
    # Si se autentica por cookie en métodos mutables, verificar token CSRF cuando se envíe o exigir cabecera
    if (
        soc_iris_session
        and not authorization
        and request.method in ("POST", "PUT", "PATCH", "DELETE")
        and x_csrf_token
    ):
        if not verify_csrf_token(sess.token_hash, x_csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token CSRF inválido.",
            )
    return user


def require_role(min_role: str) -> Callable:
    min_level = ROLE_HIERARCHY.get(min_role, 2)

    def _checker(user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Se requiere rol '{min_role}' o superior (tu rol actual es '{user.role}').",
            )
        return user

    return _checker


def check_org_access(user: User, organization: str) -> None:
    if user.role == "admin":
        return
    org = (organization or "NBX").upper()
    allowed = [o.upper() for o in (user.allowed_orgs or ["NBX", "HP"])]
    if "ALL" not in allowed and org not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No tienes permisos sobre la organización '{org}'.",
        )

