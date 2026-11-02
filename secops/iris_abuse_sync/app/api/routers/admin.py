from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai.gemini_service import GeminiService
from app.classification.taxonomy import get_taxonomy_catalogs
from app.core.audit import log_audit_event
from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.core.security import decrypt_secret, encrypt_secret
from app.ingestion.connectors.blacklist_master import BlacklistMasterConnector
from app.ingestion.connectors.imap_connector import ImapConnector
from app.ingestion.connectors.slack_connector import SlackEventsConnector
from app.ingestion.connectors.whmcs import WhmcsConnector
from app.ingestion.connectors.zammad import ZammadConnector
from app.models.classification import PlaybookTemplate
from app.models.connector import ConnectorConfig, EncryptedSecret, JobQueue
from app.models.user import AuditLog, User
from app.workers.job_runner import JobRunner

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class GeminiUpdateRequest(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_output_tokens: Optional[int] = None
    timeout_seconds: Optional[int] = None
    is_enabled: Optional[bool] = None


class ConnectorUpdateRequest(BaseModel):
    is_enabled: Optional[bool] = None
    organization: Optional[str] = None
    poll_interval_seconds: Optional[int] = None
    settings_json: Optional[Dict[str, Any]] = None
    secret_value: Optional[str] = None


class AiAssistantChatRequest(BaseModel):
    instruction: str
    context: Dict[str, Any] = {}


class PlaybookTemplateUpsertRequest(BaseModel):
    code: str = Field(..., min_length=2)
    name: str = Field(..., min_length=2)
    category_code: str = Field(..., min_length=2)
    description: Optional[str] = None
    is_active: bool = True
    steps_json: List[Dict[str, Any]] = []


@router.get("/catalogs")
def get_all_catalogs(db: Session = Depends(get_db)):
    playbooks = db.query(PlaybookTemplate).order_by(PlaybookTemplate.id.asc()).all()
    return {
        "status": "ok",
        **get_taxonomy_catalogs(),
        "playbooks": [
            {
                "id": p.id,
                "code": p.code,
                "name": p.name,
                "category_code": p.category_code,
                "description": p.description,
                "is_active": p.is_active,
                "steps": p.steps_json,
            }
            for p in playbooks
        ],
    }


@router.post("/playbooks")
def create_playbook_template(
    payload: PlaybookTemplateUpsertRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    existing = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == payload.code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Ya existe un playbook con código '{payload.code}'.")

    now = datetime.now(timezone.utc)
    pb = PlaybookTemplate(
        code=payload.code,
        name=payload.name,
        category_code=payload.category_code,
        description=payload.description,
        is_active=payload.is_active,
        steps_json=payload.steps_json,
        created_at=now,
        updated_at=now,
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)

    log_audit_event(
        db,
        action="playbook.template_created",
        module="admin",
        user=user,
        details=f"Procedimiento '{pb.name}' ({pb.code}) creado para categoría '{pb.category_code}'.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "playbook": {"id": pb.id, "code": pb.code, "name": pb.name}}


@router.put("/playbooks/{code}")
def update_playbook_template(
    code: str,
    payload: PlaybookTemplateUpsertRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    pb = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == code).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{code}' no encontrado.")

    pb.name = payload.name
    pb.category_code = payload.category_code
    pb.description = payload.description
    pb.is_active = payload.is_active
    pb.steps_json = payload.steps_json
    pb.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_audit_event(
        db,
        action="playbook.template_updated",
        module="admin",
        user=user,
        details=f"Procedimiento '{pb.name}' ({pb.code}) actualizado.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "playbook": {"id": pb.id, "code": pb.code, "name": pb.name}}


@router.get("/gemini")
def get_gemini_status(db: Session = Depends(get_db)):
    cfg, _, _ = GeminiService.get_config_and_key(db)
    return {"status": "ok", "gemini": cfg}


@router.get("/gemini/models")
def get_available_gemini_models(db: Session = Depends(get_db)):
    """Consulta y devuelve los modelos soportados y disponibles para la API Key configurada."""
    return GeminiService.list_available_models(db)


@router.put("/gemini")
def update_gemini_settings(
    payload: GeminiUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    cfg = GeminiService.update_config(
        db,
        api_key=payload.api_key,
        model=payload.model,
        temperature=payload.temperature,
        max_output_tokens=payload.max_output_tokens,
        timeout_seconds=payload.timeout_seconds,
        is_enabled=payload.is_enabled,
        updated_by=user.username if user else "admin",
    )
    log_audit_event(
        db,
        action="gemini.config_updated",
        module="admin",
        user=user,
        after_data={"model": cfg.get("model"), "is_enabled": cfg.get("is_enabled"), "key_hint": cfg.get("key_hint")},
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "gemini": cfg}


@router.post("/gemini/test")
def test_gemini_connection(db: Session = Depends(get_db)):
    return GeminiService.test_connection(db)


@router.post("/ai/chat")
@router.post("/gemini/assist")
def run_gemini_assistant(payload: AiAssistantChatRequest, db: Session = Depends(get_db)):
    return GeminiService.assist_analyst_chat(db, payload.instruction, payload.context)


@router.get("/connectors")
def list_connectors(db: Session = Depends(get_db)):
    rows = db.query(ConnectorConfig).order_by(ConnectorConfig.id.asc()).all()
    secrets = {s.id: s.key_hint for s in db.query(EncryptedSecret).all()}
    return {
        "status": "ok",
        "connectors": [
            {
                "id": c.id,
                "connector_type": c.connector_type,
                "name": c.name,
                "organization": c.organization,
                "is_enabled": c.is_enabled,
                "poll_interval_seconds": c.poll_interval_seconds,
                "settings_json": c.settings_json,
                "secret_hint": secrets.get(c.secret_id, "No configurada"),
                "sync_cursor_json": c.sync_cursor_json,
                "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
                "last_status": c.last_status,
                "last_error": c.last_error,
            }
            for c in rows
        ],
    }


@router.put("/connectors/{connector_id}")
def update_connector(
    connector_id: int,
    payload: ConnectorUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    conn = db.query(ConnectorConfig).filter(ConnectorConfig.id == connector_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conector no encontrado.")

    if payload.is_enabled is not None:
        conn.is_enabled = payload.is_enabled
    if payload.organization:
        conn.organization = payload.organization
    if payload.poll_interval_seconds is not None:
        conn.poll_interval_seconds = payload.poll_interval_seconds
    if payload.settings_json is not None:
        merged = dict(conn.settings_json or {})
        merged.update(payload.settings_json)
        conn.settings_json = merged

    if payload.secret_value and payload.secret_value.strip():
        ct, hint = encrypt_secret(payload.secret_value.strip())
        key_name = f"connector_{conn.connector_type}_{conn.id}_secret"
        sec = db.query(EncryptedSecret).filter(EncryptedSecret.secret_key_name == key_name).first()
        if not sec:
            sec = EncryptedSecret(
                secret_key_name=key_name,
                ciphertext=ct,
                key_hint=hint,
                updated_by=user.username if user else "admin",
            )
            db.add(sec)
            db.flush()
        else:
            sec.ciphertext = ct
            sec.key_hint = hint
        conn.secret_id = sec.id

    conn.last_status = "ready" if conn.is_enabled else "disabled"
    db.commit()

    log_audit_event(
        db,
        action="connector.updated",
        module="admin",
        user=user,
        details=f"Conector actualizado: {conn.name}",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "connector_id": conn.id, "is_enabled": conn.is_enabled}


@router.post("/connectors/{connector_id}/test")
def test_connector_endpoint(connector_id: int, db: Session = Depends(get_db)):
    conn = db.query(ConnectorConfig).filter(ConnectorConfig.id == connector_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Conector no encontrado.")

    if conn.connector_type == "gemini":
        return GeminiService.test_connection(db)

    secret_val = None
    if conn.secret_id:
        sec = db.query(EncryptedSecret).filter(EncryptedSecret.id == conn.secret_id).first()
        if sec:
            secret_val = decrypt_secret(sec.ciphertext)

    ctype = conn.connector_type
    if ctype == "zammad":
        res = ZammadConnector(conn.settings_json or {}, secret_val).test_connection()
    elif ctype == "whmcs":
        res = WhmcsConnector(conn.settings_json or {}, secret_val).test_connection()
    elif ctype == "imap":
        res = ImapConnector(conn.settings_json or {}, secret_val).test_connection()
    elif ctype == "slack":
        res = SlackEventsConnector(conn.settings_json or {}, secret_val).test_connection()
    elif ctype == "blacklist_master":
        res = BlacklistMasterConnector(conn.settings_json or {}, secret_val).test_connection()
    else:
        res = {"ok": False, "message": f"Tipo desconocido: {ctype}"}

    conn.last_status = "connected" if res.get("ok") else "error"
    conn.last_error = None if res.get("ok") else res.get("message")
    db.commit()
    return res


@router.post("/connectors/{connector_id}/poll")
def poll_connector_manually(connector_id: int, db: Session = Depends(get_db)):
    try:
        return JobRunner.poll_connector_by_id(db, connector_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/jobs")
def list_worker_jobs(db: Session = Depends(get_db)):
    rows = db.query(JobQueue).order_by(JobQueue.id.desc()).limit(40).all()
    return {
        "status": "ok",
        "jobs": [
            {
                "id": j.id,
                "job_type": j.job_type,
                "status": j.status,
                "attempts": j.attempts,
                "max_attempts": j.max_attempts,
                "last_error": j.last_error,
                "created_at": j.created_at.isoformat() if j.created_at else None,
            }
            for j in rows
        ],
    }


@router.post("/jobs/run-pending")
def run_pending_worker_jobs(db: Session = Depends(get_db)):
    return JobRunner.run_pending_jobs(db)


@router.get("/audit-logs")
def list_audit_logs(db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return {
        "status": "ok",
        "logs": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "username": r.username,
                "action": r.action,
                "module": r.module,
                "organization": r.organization,
                "iris_alert_id": r.iris_alert_id,
                "iris_case_id": r.iris_case_id,
                "details": r.details,
                "ip_address": r.ip_address,
            }
            for r in rows
        ],
    }

