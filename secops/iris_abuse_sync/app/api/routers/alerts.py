from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.classification.taxonomy import SEVERITY_NAME_TO_IRIS_ID, SOC_CATEGORIES
from app.core.audit import log_audit_event
from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.iris.client import IrisApiClient
from app.models.case_extended import AlertExtension, CaseAction, CaseExtension, CaseFinding, CaseInvestigation
from app.models.connector import IngestEvent
from app.models.user import User

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


class AlertTriageUpdateRequest(BaseModel):
    alert_title: Optional[str] = None
    organization: Optional[str] = None
    primary_domain: Optional[str] = None
    abuse_ticket_id: Optional[str] = None
    reported_ip: Optional[str] = None
    hosting_ip: Optional[str] = None
    server_name: Optional[str] = None
    category_code: Optional[str] = None
    reported_activity: Optional[str] = None
    confirmed_incident_type: Optional[str] = None
    entry_vector: Optional[str] = None
    root_cause: Optional[str] = None
    severity: Optional[str] = None
    status_id: Optional[int] = None
    alert_note: Optional[str] = None


class AlertDiscardRequest(BaseModel):
    discard_reason: str = Field(..., min_length=5, description="Motivo obligatorio de descarte")
    verification_state: str = Field(default="falso_positivo")


class AlertEscalateRequest(BaseModel):
    case_title: Optional[str] = None
    note: str = Field(default="Alerta escalada a Caso desde Consola de Triage SOC v3.0")
    apply_default_playbook: bool = True


class AlertMergeRequest(BaseModel):
    target_case_id: int
    note: str = Field(default="Alerta correlacionada y fusionada en caso existente desde Triage SOC v3.0")


class AlertBulkMergeRequest(BaseModel):
    alert_ids: List[int]
    target_case_id: int
    note: str = Field(default="Vinculación masiva de alertas desde Centro de Alertas SOC")


class AlertBulkDiscardRequest(BaseModel):
    alert_ids: List[int]
    discard_reason: str = Field(..., min_length=3)
    verification_state: str = Field(default="descartada")


class AlertDeleteRequest(BaseModel):
    justification: str = Field(..., min_length=5)


@router.get("")
def list_alerts(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    organization: Optional[str] = None,
    status_id: Optional[int] = None,
    severity_id: Optional[int] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    client = IrisApiClient()
    customer_id = None
    if organization:
        if organization.upper() == "NBX":
            customer_id = 2
        elif organization.upper() == "HP":
            customer_id = 3

    try:
        iris_data = client.list_alerts(
            page=page,
            per_page=per_page,
            customer_id=customer_id,
            status_id=status_id,
            severity_id=severity_id,
            source=source,
            title=search,
        )
    except Exception as exc:
        return {"status": "error", "message": str(exc), "total": 0, "alerts": []}

    raw_alerts = iris_data.get("alerts") or []
    ext_map = {
        e.iris_alert_id: e
        for e in db.query(AlertExtension).all()
    }

    enriched = []
    for a in raw_alerts:
        aid = a.get("alert_id")
        ext = ext_map.get(aid)
        cust_id = a.get("alert_customer_id") or (a.get("customer") or {}).get("customer_id")
        org = ext.organization if ext else ("HP" if cust_id == 3 else "NBX")
        enriched.append(
            {
                "alert_id": aid,
                "alert_uuid": a.get("alert_uuid"),
                "alert_title": a.get("alert_title"),
                "alert_description": a.get("alert_description"),
                "alert_source": a.get("alert_source"),
                "alert_source_ref": a.get("alert_source_ref"),
                "alert_source_link": a.get("alert_source_link"),
                "alert_status_id": a.get("alert_status_id"),
                "status_name": (a.get("status") or {}).get("status_name") or "New",
                "alert_severity_id": a.get("alert_severity_id"),
                "severity_name": (a.get("severity") or {}).get("severity_name") or (ext.severity if ext else "Medium"),
                "alert_creation_time": a.get("alert_creation_time"),
                "alert_tags": a.get("alert_tags"),
                "organization": org,
                "customer_id": cust_id,
                "primary_domain": ext.primary_domain if ext else None,
                "abuse_ticket_id": ext.abuse_ticket_id if ext else a.get("alert_source_ref"),
                "reported_ip": ext.reported_ip if ext else None,
                "hosting_ip": ext.hosting_ip if ext else None,
                "server_name": ext.server_name if ext else None,
                "category_code": ext.category_code if ext else "abuse_phishing",
                "reported_activity": ext.reported_activity if ext else "unknown",
                "confirmed_incident_type": ext.confirmed_incident_type if ext else "pending_investigation",
                "entry_vector": ext.entry_vector if ext else "unknown",
                "root_cause": ext.root_cause if ext else "unknown",
                "confidence_score": ext.confidence_score if ext else 75,
                "correlated_case_ids": ext.correlated_case_ids_json if ext else [c.get("case_id") for c in (a.get("cases") or []) if isinstance(c, dict)],
                "escalated_case_id": ext.escalated_case_id if ext else None,
                "observation_count": ext.observation_count if (ext and ext.observation_count) else 1,
                "iocs_count": len(a.get("iocs") or []),
            }
        )

    return {
        "status": "ok",
        "total": iris_data.get("total", len(enriched)),
        "current_page": iris_data.get("current_page", page),
        "last_page": iris_data.get("last_page", 1),
        "alerts": enriched,
    }


@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    client = IrisApiClient()
    iris_alert = client.get_alert(alert_id)
    if not iris_alert:
        raise HTTPException(status_code=404, detail=f"Alerta #{alert_id} no encontrada en DFIR-IRIS.")

    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    ingest_ev = None
    if ext and ext.ingest_event_id:
        ingest_ev = db.query(IngestEvent).filter(IngestEvent.id == ext.ingest_event_id).first()

    return {
        "status": "ok",
        "iris_alert": iris_alert,
        "extension": {
            "organization": ext.organization if ext else "NBX",
            "source_type": ext.source_type if ext else iris_alert.get("alert_source"),
            "abuse_ticket_id": ext.abuse_ticket_id if ext else iris_alert.get("alert_source_ref"),
            "primary_domain": ext.primary_domain if ext else None,
            "reported_ip": ext.reported_ip if ext else None,
            "hosting_ip": ext.hosting_ip if ext else None,
            "server_name": ext.server_name if ext else None,
            "category_code": ext.category_code if ext else "abuse_phishing",
            "reported_activity": ext.reported_activity if ext else "unknown",
            "confirmed_incident_type": ext.confirmed_incident_type if ext else "pending_investigation",
            "entry_vector": ext.entry_vector if ext else "unknown",
            "root_cause": ext.root_cause if ext else "unknown",
            "severity": ext.severity if ext else "Medium",
            "confidence_score": ext.confidence_score if ext else 75,
            "verification_state": ext.verification_state if ext else "pendiente",
            "discard_reason": ext.discard_reason if ext else None,
            "heuristic_result": ext.heuristic_result_json if ext else {},
            "gemini_result": ext.gemini_result_json if ext else {},
            "field_provenance": ext.field_provenance_json if ext else {},
            "indicators_by_role": ext.indicators_by_role_json if ext else {},
            "correlated_alert_ids": ext.correlated_alert_ids_json if ext else [],
            "correlated_case_ids": ext.correlated_case_ids_json if ext else [],
            "escalated_case_id": ext.escalated_case_id if ext else None,
            "triaged_by": ext.triaged_by if ext else None,
            "triaged_at": ext.triaged_at.isoformat() if ext and ext.triaged_at else None,
        },
        "ingest_event": {
            "id": ingest_ev.id,
            "reporter": ingest_ev.reporter,
            "original_content": ingest_ev.original_content,
            "evidence_package_path": ingest_ev.evidence_package_path,
            "evidence_sha256": ingest_ev.evidence_sha256,
            "attachments": ingest_ev.attachments_json,
            "normalized_payload": ingest_ev.normalized_payload_json,
        }
        if ingest_ev
        else None,
    }


@router.put("/{alert_id}")
def update_alert_triage(
    alert_id: int,
    payload: AlertTriageUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if not ext:
        ext = AlertExtension(iris_alert_id=alert_id)
        db.add(ext)
        db.flush()

    prov = dict(ext.field_provenance_json or {})
    data_in = payload.model_dump(exclude_unset=True)
    for k, v in data_in.items():
        if hasattr(ext, k) and v is not None:
            setattr(ext, k, v)
            prov[k] = "manual"

    ext.field_provenance_json = prov
    ext.triaged_by = user.username if user else "analyst"
    ext.triaged_at = datetime.now(timezone.utc)

    iris_fields: Dict[str, Any] = {}
    if payload.alert_title:
        iris_fields["alert_title"] = payload.alert_title
    if payload.status_id:
        iris_fields["alert_status_id"] = payload.status_id
    if payload.severity:
        iris_fields["alert_severity_id"] = SEVERITY_NAME_TO_IRIS_ID.get(payload.severity, 1)
    if payload.organization:
        iris_fields["alert_customer_id"] = 3 if payload.organization.upper() == "HP" else 2
    if payload.category_code and payload.category_code in SOC_CATEGORIES:
        iris_fields["alert_classification_id"] = SOC_CATEGORIES[payload.category_code]["iris_classification_id"]
    if payload.alert_note is not None:
        iris_fields["alert_note"] = payload.alert_note

    iris_updated = client.update_alert(alert_id, iris_fields)
    db.commit()

    log_audit_event(
        db,
        action="alert.triage_updated",
        module="alerts",
        user=user,
        organization=ext.organization,
        iris_alert_id=alert_id,
        after_data=data_in,
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "iris_alert": iris_updated, "field_provenance": prov}


@router.post("/{alert_id}/discard")
def discard_alert(
    alert_id: int,
    payload: AlertDiscardRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if not ext:
        ext = AlertExtension(iris_alert_id=alert_id)
        db.add(ext)

    ext.discard_reason = payload.discard_reason.strip()
    ext.verification_state = payload.verification_state
    ext.confirmed_incident_type = "false_positive" if payload.verification_state == "falso_positivo" else "closed_no_technical_intervention"
    ext.triaged_by = user.username if user else "analyst"
    ext.triaged_at = datetime.now(timezone.utc)

    # Estado 6 en DFIR-IRIS = Closed ("Alert closed, no action taken")
    iris_updated = client.update_alert(
        alert_id,
        {
            "alert_status_id": 6,
            "alert_note": f"[DESCARTADA POR SOC] Motivo: {payload.discard_reason}",
        },
    )
    db.commit()

    log_audit_event(
        db,
        action="alert.discarded",
        module="alerts",
        user=user,
        organization=ext.organization,
        iris_alert_id=alert_id,
        details=f"Motivo: {payload.discard_reason}",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "alert_status_id": 6, "iris_alert": iris_updated}


@router.post("/{alert_id}/escalate")
def escalate_alert_to_case(
    alert_id: int,
    payload: Optional[AlertEscalateRequest] = None,
    request: Request = None,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Convierte una Alerta de DFIR-IRIS en un nuevo Caso (/alerts/escalate/{id}) e inicializa
    toda su estructura normalizada v3.0 (CaseExtension, Hallazgos, Acciones y Playbook)."""
    payload = payload or AlertEscalateRequest()
    client = IrisApiClient()
    iris_alert = client.get_alert(alert_id)
    if not iris_alert:
        raise HTTPException(status_code=404, detail=f"Alerta #{alert_id} no encontrada.")

    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if ext and ext.escalated_case_id:
        existing_case = client.get_case(ext.escalated_case_id)
        if existing_case:
            return {
                "status": "ok",
                "case_id": ext.escalated_case_id,
                "case": existing_case,
                "message": f"Alerta ya escalada previamente al Caso #{ext.escalated_case_id}",
            }

    case_title = payload.case_title or iris_alert.get("alert_title") or f"Caso desde Alerta #{alert_id}"

    escalated_case = client.escalate_alert(
        alert_id,
        case_title=case_title,
        note=payload.note,
        import_as_event=True,
    )
    new_case_id = escalated_case.get("case_id")
    if not new_case_id:
        raise HTTPException(status_code=500, detail="DFIR-IRIS no devolvió el ID del caso escalado.")

    if ext:
        ext.escalated_case_id = new_case_id
        ext.triaged_by = user.username if user else "analyst"
        ext.triaged_at = datetime.now(timezone.utc)

        ingest_ev = (
            db.query(IngestEvent).filter(IngestEvent.id == ext.ingest_event_id).first()
            if ext.ingest_event_id
            else None
        )
        norm_p = (ingest_ev.normalized_payload_json or {}) if ingest_ev else {}
        heur = ext.heuristic_result_json or {}

        c_ext = CaseExtension(
            iris_case_id=new_case_id,
            organization=ext.organization,
            customer_id=3 if ext.organization == "HP" else 2,
            source_channel=ext.source_type,
            abuse_ticket_id=ext.abuse_ticket_id,
            holder_ticket_id=norm_p.get("holder_ticket_id"),
            client_id=norm_p.get("client_id"),
            service_id=norm_p.get("service_id"),
            service_plan=norm_p.get("service_plan"),
            primary_domain=ext.primary_domain,
            server_name=ext.server_name,
            hosting_ip=ext.hosting_ip,
            reported_ip=ext.reported_ip,
            impersonated_brand=norm_p.get("impersonated_brand"),
            reporter_name=norm_p.get("reporter", "Reportante"),
            category_code=ext.category_code,
            reported_activity=ext.reported_activity,
            confirmed_incident_type=ext.confirmed_incident_type,
            entry_vector=ext.entry_vector,
            root_cause=ext.root_cause,
            verification_state=ext.verification_state,
            severity=ext.severity,
            is_technical_compromise=bool(heur.get("is_technical_compromise", False)),
            playbook_code=heur.get("playbook_code", "pb_phishing"),
            field_provenance_json=ext.field_provenance_json or {},
            initial_report_json={"summary": norm_p.get("report_summary", "")},
            indicators_by_role_json=ext.indicators_by_role_json or {},
        )
        db.add(c_ext)

        for f_item in heur.get("proposed_findings") or []:
            db.add(
                CaseFinding(
                    iris_case_id=new_case_id,
                    title=f_item.get("title", "Hallazgo inicial"),
                    description=f_item.get("description", ""),
                    finding_nature=f_item.get("finding_nature", "reported_allegation"),
                    verification_state=f_item.get("verification_state", "indicio"),
                    severity=ext.severity,
                    provenance="rule",
                )
            )
        for a_item in heur.get("proposed_actions") or []:
            db.add(
                CaseAction(
                    iris_case_id=new_case_id,
                    action_type=a_item.get("action_type", "general"),
                    title=a_item.get("title", "Acción propuesta"),
                    status=a_item.get("status", "propuesta"),
                    result_notes=a_item.get("result_notes", ""),
                    provenance="rule",
                )
            )
            client.ensure_task(
                new_case_id,
                title=a_item.get("title", "Acción"),
                description=a_item.get("result_notes", ""),
                action_status=a_item.get("status", "propuesta"),
            )

    db.commit()

    log_audit_event(
        db,
        action="alert.escalated_to_case",
        module="alerts",
        user=user,
        organization=ext.organization if ext else "NBX",
        iris_alert_id=alert_id,
        iris_case_id=new_case_id,
        details=f"Alerta #{alert_id} escalada al Caso #{new_case_id}",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "case_id": new_case_id, "case": escalated_case}


@router.post("/{alert_id}/merge")
def merge_alert_into_case(
    alert_id: int,
    payload: AlertMergeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    merged = client.merge_alert(
        alert_id,
        target_case_id=payload.target_case_id,
        note=payload.note,
        import_as_event=True,
    )
    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if ext:
        ext.escalated_case_id = payload.target_case_id
        ext.triaged_by = user.username if user else "analyst"
        ext.triaged_at = datetime.now(timezone.utc)
        db.commit()

    log_audit_event(
        db,
        action="alert.merged_into_case",
        module="alerts",
        user=user,
        iris_alert_id=alert_id,
        iris_case_id=payload.target_case_id,
        details=f"Alerta #{alert_id} fusionada en el Caso #{payload.target_case_id}",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "target_case_id": payload.target_case_id, "merged": merged}


@router.get("/{alert_id}/compatible-cases")
def get_compatible_cases_for_alert(
    alert_id: int,
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Busca casos compatibles para vincular la alerta, priorizando casos abiertos."""
    client = IrisApiClient()
    iris_alert = client.get_alert(alert_id)
    if not iris_alert:
        raise HTTPException(status_code=404, detail=f"Alerta #{alert_id} no encontrada.")

    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    alert_org = ext.organization if ext else "NBX"
    domain = ext.primary_domain if ext else None
    ip = ext.reported_ip or (ext.hosting_ip if ext else None)
    server = ext.server_name if ext else None

    # Obtener casos activos de DFIR-IRIS
    try:
        all_cases = client.list_cases()
    except Exception as e:
        all_cases = []

    ext_cases = {
        ce.iris_case_id: ce
        for ce in db.query(CaseExtension).all()
    }

    scored_cases = []
    for c in all_cases:
        cid = c.get("case_id")
        c_ext = ext_cases.get(cid)
        c_org = c_ext.organization if c_ext else ("HP" if c.get("case_customer") == "HP" else "NBX")
        if c_org != alert_org:
            continue

        c_name = c.get("case_name", "")
        c_state_id = c.get("state_id") or c.get("status_id") or 1
        is_closed = c_state_id == 9

        score = 0
        match_reasons = []

        if search:
            s_lower = search.lower()
            if s_lower in c_name.lower() or str(cid) == s_lower:
                score += 50
                match_reasons.append("Coincidencia con término de búsqueda")

        if domain and c_ext and c_ext.primary_domain and domain.lower() in c_ext.primary_domain.lower():
            score += 40
            match_reasons.append(f"Mismo dominio ({domain})")
        if ip and c_ext and (ip == c_ext.hosting_ip or ip == c_ext.reported_ip):
            score += 35
            match_reasons.append(f"Misma IP ({ip})")
        if server and c_ext and server.lower() == (c_ext.server_name or "").lower():
            score += 20
            match_reasons.append(f"Mismo servidor ({server})")

        # Penalizar casos cerrados para mostrar abiertos primero
        if not is_closed:
            score += 15
        else:
            score -= 30

        scored_cases.append({
            "case_id": cid,
            "case_name": c_name,
            "organization": c_org,
            "state_id": c_state_id,
            "state_name": c.get("state_name") or c.get("status_name") or ("Closed" if is_closed else "Open"),
            "is_closed": is_closed,
            "domain": c_ext.primary_domain if c_ext else None,
            "server": c_ext.server_name if c_ext else None,
            "relevance_score": score,
            "match_reasons": match_reasons,
        })

    scored_cases.sort(key=lambda x: (x["is_closed"], -x["relevance_score"], -x["case_id"]))
    return {"status": "ok", "alert_id": alert_id, "cases": scored_cases[:30]}


@router.post("/bulk/merge")
def bulk_merge_alerts_into_case(
    payload: AlertBulkMergeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Vincula masivamente un conjunto de alertas a un mismo caso DFIR-IRIS."""
    client = IrisApiClient()
    success_count = 0
    errors = []
    now = datetime.now(timezone.utc)

    for aid in payload.alert_ids:
        try:
            client.merge_alert(
                aid,
                target_case_id=payload.target_case_id,
                note=payload.note,
                import_as_event=True,
            )
            ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == aid).first()
            if not ext:
                ext = AlertExtension(iris_alert_id=aid)
                db.add(ext)
            ext.escalated_case_id = payload.target_case_id
            ext.triaged_by = user.username if user else "analyst"
            ext.triaged_at = now
            success_count += 1
        except Exception as e:
            errors.append({"alert_id": aid, "error": str(e)})

    db.commit()

    log_audit_event(
        db,
        action="alerts.bulk_merged",
        module="alerts",
        user=user,
        iris_case_id=payload.target_case_id,
        details=f"{success_count} alertas vinculadas al Caso #{payload.target_case_id}.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "merged_count": success_count, "errors": errors}


@router.post("/bulk/discard")
def bulk_discard_alerts(
    payload: AlertBulkDiscardRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Descarta masivamente alertas seleccionadas con motivo justificado y auditable."""
    client = IrisApiClient()
    success_count = 0
    now = datetime.now(timezone.utc)

    for aid in payload.alert_ids:
        ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == aid).first()
        if not ext:
            ext = AlertExtension(iris_alert_id=aid)
            db.add(ext)

        ext.discard_reason = payload.discard_reason.strip()
        ext.verification_state = payload.verification_state
        ext.confirmed_incident_type = (
            "false_positive" if payload.verification_state == "falso_positivo" else "closed_no_technical_intervention"
        )
        ext.triaged_by = user.username if user else "analyst"
        ext.triaged_at = now

        try:
            client.update_alert(
                aid,
                {
                    "alert_status_id": 6,
                    "alert_note": f"[DESCARTADA EN LOTE] Motivo: {payload.discard_reason}",
                },
            )
        except Exception:
            pass

        success_count += 1

    db.commit()

    log_audit_event(
        db,
        action="alerts.bulk_discarded",
        module="alerts",
        user=user,
        details=f"{success_count} alertas descartadas en lote. Motivo: {payload.discard_reason}",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "discarded_count": success_count}


@router.post("/{alert_id}/reopen")
def reopen_discarded_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Reabre una alerta previamente descartada cuando surgen nuevas evidencias."""
    client = IrisApiClient()
    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if ext:
        ext.verification_state = "pending_investigation"
        ext.discard_reason = None
        ext.updated_at = datetime.now(timezone.utc)

    try:
        client.update_alert(
            alert_id,
            {
                "alert_status_id": 2,  # New / Open
                "alert_note": f"[REABIERTA] Reabierta por {user.username if user else 'analista'} para re-evaluación.",
            },
        )
    except Exception:
        pass

    db.commit()

    log_audit_event(
        db,
        action="alert.reopened",
        module="alerts",
        user=user,
        iris_alert_id=alert_id,
        details=f"Alerta #{alert_id} reabierta para análisis.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "alert_id": alert_id, "verification_state": "pending_investigation"}


@router.post("/{alert_id}/unlink")
def unlink_alert_from_case(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Desvincula una alerta de su caso asociado."""
    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    prev_case = ext.escalated_case_id if ext else None

    if ext:
        ext.escalated_case_id = None
        ext.updated_at = datetime.now(timezone.utc)
        db.commit()

    log_audit_event(
        db,
        action="alert.unlinked",
        module="alerts",
        user=user,
        iris_alert_id=alert_id,
        iris_case_id=prev_case,
        details=f"Alerta #{alert_id} desvinculada del Caso #{prev_case}.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "alert_id": alert_id, "previous_case_id": prev_case}


@router.delete("/{alert_id}")
def delete_alert_permanently(
    alert_id: int,
    payload: AlertDeleteRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Operación administrativa restrictiva: elimina una alerta bajo justificación formal."""
    if not user or user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Operación restringida exclusivamente a usuarios con rol 'admin'.",
        )

    ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == alert_id).first()
    if ext:
        db.delete(ext)
        db.commit()

    log_audit_event(
        db,
        action="alert.deleted_permanently",
        module="alerts",
        user=user,
        iris_alert_id=alert_id,
        details=f"Alerta eliminada por administrador. Justificación: {payload.justification}",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "deleted_alert_id": alert_id}

