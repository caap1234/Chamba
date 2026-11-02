from typing import Any, Optional
from sqlalchemy.orm import Session
from app.models.user import AuditLog, User


def log_audit_event(
    db: Session,
    *,
    action: str,
    module: str,
    user: Optional[User] = None,
    username: str = "system",
    organization: Optional[str] = None,
    iris_alert_id: Optional[int] = None,
    iris_case_id: Optional[int] = None,
    before_data: Optional[dict[str, Any]] = None,
    after_data: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None,
    commit: bool = True,
) -> AuditLog:
    """Registra una entrada inmutable en la bitácora de auditoría."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else username,
        action=action,
        module=module,
        organization=organization,
        iris_alert_id=iris_alert_id,
        iris_case_id=iris_case_id,
        before_json=before_data,
        after_json=after_data,
        ip_address=ip_address,
        details=details,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry

