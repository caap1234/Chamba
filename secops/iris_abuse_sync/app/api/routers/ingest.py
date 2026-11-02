from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import log_audit_event
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.core.security import decrypt_secret
from app.ingestion.connectors.blacklist_master import BlacklistMasterConnector
from app.ingestion.connectors.slack_connector import SlackEventsConnector
from app.ingestion.normalizer import ReportNormalizer
from app.ingestion.pipeline import IngestPipeline
from app.models.case_extended import RblEpisode
from app.models.connector import ConnectorConfig, EncryptedSecret, IngestEvent
from app.models.user import User

router = APIRouter(prefix="/api/v1", tags=["ingest"])


class TextIngestRequest(BaseModel):
    text: str = Field(..., min_length=5)
    title: Optional[str] = "Reporte Manual"
    organization: Optional[str] = "NBX"
    use_gemini: bool = True
    create_iris_alert: bool = True


class RblWebhookRequest(BaseModel):
    ip_address: str = Field(..., min_length=7)
    rbl_provider: str = Field(default="Spamhaus ZEN")
    server_name: Optional[str] = None
    organization: str = Field(default="NBX")
    event_status: str = Field(default="listed")  # listed | delisted
    reason: Optional[str] = None


@router.post("/ingest/upload")
async def ingest_uploaded_file(
    request: Request,
    file: UploadFile = File(...),
    organization: Optional[str] = Form(default=None),
    use_gemini: bool = Form(default=True),
    create_iris_alert: bool = Form(default=True),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    fname = file.filename or "reporte.pdf"
    ext = Path(fname).suffix.lower()
    if ext not in (".pdf", ".eml", ".txt", ".msg", ".log", ".json"):
        raise HTTPException(
            status_code=400,
            detail="Formato no soportado. Sube un archivo .pdf, .eml, .txt, .log o .json.",
        )

    raw_bytes = await file.read()
    temp_path = settings.SCRATCH_DIR / f"ingest_{fname}"
    temp_path.write_bytes(raw_bytes)

    payload, _, extra_atts = ReportNormalizer.from_file(
        temp_path,
        organization=organization,
        source_type="manual_file",
    )

    result = IngestPipeline.process_ingest(
        db,
        payload,
        raw_bytes=raw_bytes,
        original_filename=fname,
        extra_attachments=extra_atts,
        use_gemini=use_gemini,
        create_iris_alert=create_iris_alert,
    )

    log_audit_event(
        db,
        action="ingest.file_processed",
        module="ingest",
        user=user,
        organization=payload.organization,
        iris_alert_id=result.get("iris_alert_id"),
        details=f"Archivo: {fname} (SHA-256: {result['evidence_package']['primary_sha256'][:16]}...)",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", **result}


@router.post("/ingest/text")
def ingest_raw_text(
    body: TextIngestRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    payload = ReportNormalizer.normalize_text(
        text=body.text,
        filename=f"{body.title or 'texto_pegado'}.txt",
        organization=body.organization,
        source_type="manual_text",
        subject_override=body.title,
    )
    result = IngestPipeline.process_ingest(
        db,
        payload,
        raw_bytes=body.text.encode("utf-8"),
        original_filename="reporte_texto_pegado.txt",
        use_gemini=body.use_gemini,
        create_iris_alert=body.create_iris_alert,
    )

    log_audit_event(
        db,
        action="ingest.text_processed",
        module="ingest",
        user=user,
        organization=payload.organization,
        iris_alert_id=result.get("iris_alert_id"),
        details=f"Texto pegado ({len(body.text)} chars) -> Alerta #{result.get('iris_alert_id')}",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", **result}


@router.get("/ingest/sample/{sample_key}")
def load_reference_sample_ticket(
    sample_key: str,
    create_iris_alert: bool = False,
    db: Session = Depends(get_db),
):
    """Permite cargar cualquiera de los tickets PDF reales de referencia en scratch/ para pruebas rápidas."""
    sample_files = {
        "791092": "temp_Ticket 791092.pdf",
        "791233": "temp_Ticket 791233.pdf",
        "791255": "temp_Ticket 791255.pdf",
        "791328": "temp_Ticket 791328.pdf",
        "789810": "temp_Ticket_789810.pdf",
        "791634": "temp_Ticket_791634.pdf",
        "791804": "temp_Ticket_791804.pdf",
        "791833": "temp_Ticket_791833.pdf",
        "791842": "temp_Ticket_791842.pdf",
    }
    fname = sample_files.get(sample_key)
    if not fname:
        raise HTTPException(status_code=404, detail=f"Muestra '{sample_key}' no encontrada.")
    fpath = settings.SCRATCH_DIR / fname
    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"Archivo {fname} no existe en scratch/.")

    payload, raw_bytes, extra = ReportNormalizer.from_file(fpath, source_type="zammad")
    result = IngestPipeline.process_ingest(
        db,
        payload,
        raw_bytes=raw_bytes,
        original_filename=fname,
        extra_attachments=extra,
        use_gemini=True,
        create_iris_alert=create_iris_alert,
    )
    return {"status": "ok", **result}


@router.post("/webhooks/slack/events")
async def slack_events_webhook(
    request: Request,
    x_slack_signature: Optional[str] = Header(default=None),
    x_slack_request_timestamp: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    raw_body = await request.body()
    body_json = await request.json()

    # 1. Responder a url_verification challenge de Slack Events API
    if body_json.get("type") == "url_verification":
        return {"challenge": body_json.get("challenge")}

    # 2. Verificar firma HMAC-SHA256 si hay signing_secret configurado
    slack_conn = db.query(ConnectorConfig).filter(ConnectorConfig.connector_type == "slack").first()
    signing_secret = None
    if slack_conn and slack_conn.secret_id:
        sec = db.query(EncryptedSecret).filter(EncryptedSecret.id == slack_conn.secret_id).first()
        if sec:
            signing_secret = decrypt_secret(sec.ciphertext)

    if signing_secret:
        valid = SlackEventsConnector.verify_slack_signature(
            signing_secret=signing_secret,
            timestamp_header=x_slack_request_timestamp or "",
            signature_header=x_slack_signature or "",
            raw_body=raw_body,
        )
        if not valid:
            raise HTTPException(status_code=401, detail="Firma criptográfica de Slack inválida.")

    payload = SlackEventsConnector.parse_webhook_event(body_json)
    if not payload:
        return {"status": "ignored"}

    res = IngestPipeline.process_ingest(db, payload, create_iris_alert=True)
    return {"status": "ok", "iris_alert_id": res.get("iris_alert_id")}


@router.post("/webhooks/blacklist-master")
def blacklist_master_webhook(
    body: RblWebhookRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    episode, payload, is_new = BlacklistMasterConnector.process_rbl_event(
        db,
        ip_address=body.ip_address,
        rbl_provider=body.rbl_provider,
        server_name=body.server_name,
        organization=body.organization,
        event_status=body.event_status,
        reason=body.reason,
    )
    alert_id = episode.iris_alert_id
    if is_new and payload:
        res = IngestPipeline.process_ingest(db, payload, create_iris_alert=True)
        alert_id = res.get("iris_alert_id")
        if alert_id:
            episode.iris_alert_id = alert_id
            db.commit()

    log_audit_event(
        db,
        action=f"rbl.episode_{body.event_status}",
        module="blacklist_master",
        organization=body.organization,
        iris_alert_id=alert_id,
        details=f"IP {body.ip_address} en {body.rbl_provider} (nuevo episodio={is_new}, conteo={episode.check_count})",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "episode_id": episode.id,
        "episode_status": episode.status,
        "is_new_episode": is_new,
        "check_count": episode.check_count,
        "iris_alert_id": alert_id,
    }


@router.get("/ingest/history")
def list_ingest_events(
    organization: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(IngestEvent)
    if organization and organization.upper() in ("NBX", "HP"):
        query = query.filter(IngestEvent.organization == organization.upper())
    if status and status != "all":
        query = query.filter(IngestEvent.processing_status == status)

    rows = query.order_by(IngestEvent.id.desc()).limit(100).all()
    return {
        "status": "ok",
        "total": len(rows),
        "events": [
            {
                "id": r.id,
                "source_type": r.source_type,
                "source_id": r.source_id,
                "organization": r.organization,
                "reporter": r.reporter,
                "subject": r.subject,
                "evidence_sha256": r.evidence_sha256,
                "processing_status": r.processing_status,
                "iris_alert_id": r.iris_alert_id,
                "iris_case_id": r.iris_case_id,
                "error_message": r.error_message,
                "original_content": r.original_content[:600] if r.original_content else None,
                "normalized_payload": r.normalized_payload_json or {},
                "received_at": r.received_at.isoformat() if r.received_at else None,
            }
            for r in rows
        ],
    }


@router.post("/ingest/events/{event_id}/reprocess")
def reprocess_ingest_event(event_id: int, db: Session = Depends(get_db)):
    ev = db.query(IngestEvent).filter(IngestEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evento de ingesta no encontrado.")

    # Re-evaluar con HeuristicClassifier
    from app.ingestion.base import NormalizedIngestPayload
    from app.classification.heuristic_engine import HeuristicClassifier

    raw_text = ev.original_content or ev.subject or ""
    payload = NormalizedIngestPayload(
        source_type=ev.source_type,
        source_id=ev.source_id or f"reprocess-{ev.id}",
        organization=ev.organization,
        subject=ev.subject or "Reproceso",
        original_content=raw_text,
    )
    result = HeuristicClassifier.evaluate(payload)
    ev.normalized_payload_json = {
        **ev.normalized_payload_json,
        "reprocessed_at": datetime.now(timezone.utc).isoformat(),
        "heuristic_classification": result,
    }
    ev.processing_status = "processed"
    ev.error_message = None
    db.commit()
    return {"status": "ok", "message": "Evento reprocesado exitosamente.", "classification": result}


@router.get("/ingest/rbl-episodes")
def list_rbl_episodes(db: Session = Depends(get_db)):
    rows = db.query(RblEpisode).order_by(RblEpisode.last_seen_at.desc()).limit(50).all()
    return {
        "status": "ok",
        "episodes": [
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "server_name": r.server_name,
                "organization": r.organization,
                "rbl_provider": r.rbl_provider,
                "status": r.status,
                "reason": r.reason,
                "check_count": r.check_count,
                "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "delisted_at": r.delisted_at.isoformat() if r.delisted_at else None,
                "iris_alert_id": r.iris_alert_id,
                "iris_case_id": r.iris_case_id,
            }
            for r in rows
        ],
    }

