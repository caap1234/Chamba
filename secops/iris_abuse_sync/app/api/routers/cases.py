from datetime import datetime, timezone
import hashlib
import os
import re
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, File, UploadFile, Form, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings

from app.classification.taxonomy import SOC_CATEGORIES, VALID_ACTION_STATUS_CODES
from app.core.audit import log_audit_event
from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.core.admin_links import build_admin_links
from app.iris.client import IrisApiClient
from app.iris.legacy_migrator import LegacyCaseMigrator
from app.models.case_extended import (
    CaseAction,
    CaseCommunication,
    CaseExtension,
    CaseFinding,
    CaseInvestigation,
    CaseDraft,
    CasePlaybookExecution,
    CaseActivityLog,
    CaseArchiveRecord,
)
from app.models.classification import PlaybookTemplate
from app.models.user import User
from app.reports.pdf_generator import FormalPdfReportGenerator

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


class CaseStructuredUpdateRequest(BaseModel):
    case_name: Optional[str] = None
    state_id: Optional[int] = None
    case_description: Optional[str] = None
    organization: Optional[str] = None
    abuse_ticket_id: Optional[str] = None
    holder_ticket_id: Optional[str] = None
    client_id: Optional[str] = None
    service_id: Optional[str] = None
    domain_id: Optional[str] = None
    service_plan: Optional[str] = None
    primary_domain: Optional[str] = None
    server_name: Optional[str] = None
    hosting_ip: Optional[str] = None
    reported_ip: Optional[str] = None
    impersonated_brand: Optional[str] = None
    reporter_name: Optional[str] = None
    category_code: Optional[str] = None
    reported_activity: Optional[str] = None
    confirmed_incident_type: Optional[str] = None
    entry_vector: Optional[str] = None
    root_cause: Optional[str] = None
    verification_state: Optional[str] = None
    severity: Optional[str] = None
    is_technical_compromise: Optional[bool] = None
    resolution_data_json: Optional[Dict[str, Any]] = None
    closure_checklist_json: Optional[Dict[str, Any]] = None
    current_note_id: Optional[int] = None
    current_note_content: Optional[str] = None
    sync_structured_note_to_iris: bool = False


class CaseNoteUpdateRequest(BaseModel):
    note_content: str
    note_title: Optional[str] = None
    directory_id: Optional[int] = None


class PlaybookStartRequest(BaseModel):
    playbook_code: str = Field(..., min_length=2)


class PlaybookStepUpdateRequest(BaseModel):
    status: str = Field(..., description="pendiente, en_progreso, completado, omitido, bloqueado")
    observations: Optional[str] = None
    create_case_action: bool = False


class PlaybookStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="in_progress, completed, suspended, cancelled")


class InvestigationCreateRequest(BaseModel):
    source_consulted: str = Field(..., min_length=2)
    commands_or_queries: Optional[str] = ""
    results_observed: str = Field(..., min_length=2)
    fact_type: str = Field(default="confirmed_fact")


class FindingCreateRequest(BaseModel):
    title: str = Field(..., min_length=2)
    description: str = Field(..., min_length=2)
    finding_nature: str = Field(default="confirmed_compromise")
    verification_state: str = Field(default="confirmado")
    severity: str = Field(default="Medium")


class ActionCreateRequest(BaseModel):
    action_type: str = Field(default="notificacion_cliente")
    title: str = Field(..., min_length=2)
    status: str = Field(default="pendiente")
    responsible: str = Field(default="SOC Analyst")
    result_notes: Optional[str] = ""
    sync_task_to_iris: bool = True


class ActionStatusUpdateRequest(BaseModel):
    status: str
    result_notes: Optional[str] = None


class CommunicationCreateRequest(BaseModel):
    channel: str = Field(default="Zammad")
    direction: str = Field(default="outbound")
    recipient: str = Field(..., min_length=2)
    ticket_reference: Optional[str] = None
    summary: str = Field(..., min_length=2)


class ActivityCreateRequest(BaseModel):
    activity_type: str = Field(..., description="investigacion, accion, evidencia, comunicacion, nota")
    title: str = Field(..., min_length=2)
    content: str = Field(default="")
    metadata_json: Optional[Dict[str, Any]] = None
    action_status: Optional[str] = None  # propuesta, pendiente, en_ejecucion, ejecutada, verificada, omitida
    playbook_execution_id: Optional[int] = None
    step_order: Optional[int] = None
    sync_to_iris: bool = True


class ActivityUpdateRequest(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    action_status: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None


class CustomPlaybookStepRequest(BaseModel):
    title: str = Field(..., min_length=2)
    description: Optional[str] = ""
    suggested_action_type: str = "custom_step"
    mandatory: bool = False


class OmitPlaybookStepRequest(BaseModel):
    omission_reason: str = Field(..., min_length=3)


class LinkActivityStepRequest(BaseModel):
    activity_id: int



class ManualCaseCreateRequest(BaseModel):
    organization: str = "NBX"
    primary_domain: str = Field(..., min_length=2)
    abuse_ticket_id: str = Field(default="MANUAL")
    holder_ticket_id: Optional[str] = None
    client_id: Optional[str] = None
    service_id: Optional[str] = None
    server_name: Optional[str] = None
    hosting_ip: Optional[str] = None
    reported_ip: Optional[str] = None
    category_code: str = "abuse_phishing"
    reported_activity: str = "phishing"
    confirmed_incident_type: str = "pending_investigation"
    entry_vector: str = "unknown"
    root_cause: str = "unknown"
    severity: str = "Medium"
    summary: str = "Caso creado manualmente desde consola SOC v3.0."


class CaseDraftSaveRequest(BaseModel):
    draft_content: str = ""


class CaseStateUpdateRequest(BaseModel):
    state_id: int


class BulkDeleteActivitiesRequest(BaseModel):
    activity_ids: List[int]


class CaseIocCreateRequest(BaseModel):
    ioc_value: str
    ioc_type: str = "domain"
    ioc_description: str = ""
    ioc_tags: str = "abuse,soc"


@router.get("/states/catalog")
def get_case_states_catalog():
    """Devuelve el catálogo oficial de estados de caso configurados en DFIR-IRIS."""
    client = IrisApiClient()
    states = client.list_case_states()
    return {"status": "ok", "states": states}


@router.get("")
def list_cases(
    organization: Optional[str] = None,
    state_filter: str = "all",  # all | open | closed
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    client = IrisApiClient()
    try:
        raw_cases = client.list_cases()
    except Exception as exc:
        return {"status": "error", "message": str(exc), "cases": []}

    exts = {e.iris_case_id: e for e in db.query(CaseExtension).all()}
    items = []
    updated_exts = False

    title_pattern = re.compile(
        r"^(?:\[([A-Za-z]+)\]\s*)?([^\s|]+)\s*\|\s*(NBX|HP)-([A-Za-z0-9_-]+)",
        re.IGNORECASE,
    )
    tag_map = {
        "FRAUD": "authority_req",
        "AUTH": "authority_req",
        "SPAM": "abuse_spam",
        "PHISH": "abuse_phishing",
        "BRAND": "brand_dispute",
        "NET": "account_compromise",
        "COMP": "web_compromise",
        "MALW": "abuse_malware",
        "DMCA": "copyright_dmca",
        "RBL": "blacklist_rbl",
    }

    for c in raw_cases:
        cid = c.get("case_id")
        if not cid:
            continue
        ext = exts.get(cid)
        cname = re.sub(r"^#\d+\s*-\s*", "", c.get("case_name") or f"Caso #{cid}")
        is_closed = (
            bool(c.get("close_date"))
            or (c.get("state_name") or "").lower() == "closed"
            or c.get("state_id") == 9
            or c.get("status_id") == 9
        )
        if state_filter == "open" and is_closed:
            continue
        if state_filter == "closed" and not is_closed:
            continue

        # Extraer parámetros desde el título de IRIS
        m = title_pattern.search(cname)
        t_tag = m.group(1).upper() if (m and m.group(1)) else None
        t_dom = m.group(2) if m else None
        t_org = m.group(3).upper() if m else None
        t_tick = m.group(4) if m else None

        cl_name = (c.get("client_name") or "").lower()
        default_org = "HP" if "hospedando" in cl_name or "| hp-" in cname.lower() or str(c.get("case_customer")) == "3" else "NBX"
        org = ext.organization if (ext and ext.organization) else (t_org or default_org)

        if organization and organization.upper() in ("NBX", "HP") and org != organization.upper():
            continue

        inferred_cat = tag_map.get(t_tag, "general_abuse")

        # Reconciliación con base de datos local
        if not ext:
            ext = CaseExtension(
                iris_case_id=cid,
                organization=org,
                customer_id=3 if org == "HP" else 2,
                abuse_ticket_id=t_tick,
                primary_domain=t_dom,
                category_code=inferred_cat,
                reported_activity="regulated_goods_sale" if inferred_cat == "authority_req" else ("spam_outbound" if inferred_cat == "abuse_spam" else ("phishing" if inferred_cat == "abuse_phishing" else "unknown")),
                confirmed_incident_type="authority_preservation_request" if inferred_cat == "authority_req" else ("confirmed_outbound_spam" if inferred_cat == "abuse_spam" else "pending_investigation"),
                schema_version="legacy_v2",
                field_provenance_json={"category_code": "inferred_title", "primary_domain": "inferred_title"}
            )
            db.add(ext)
            exts[cid] = ext
            updated_exts = True
        else:
            if not ext.primary_domain and t_dom:
                ext.primary_domain = t_dom
                updated_exts = True
            if not ext.abuse_ticket_id and t_tick:
                ext.abuse_ticket_id = t_tick
                updated_exts = True
            if t_org and ext.organization != t_org:
                ext.organization = t_org
                updated_exts = True
            if (not ext.category_code or ext.category_code in ("general_abuse", "abuse_phishing")) and t_tag in tag_map:
                ext.category_code = tag_map[t_tag]
                updated_exts = True

        if search:
            q = search.lower().strip()
            haystack = f"{cid} {cname} {ext.primary_domain or ''} {ext.abuse_ticket_id or ''} {ext.server_name or ''}".lower()
            if q not in haystack:
                continue

        items.append(
            {
                "case_id": cid,
                "case_name": cname,
                "organization": org,
                "state_name": "Closed" if is_closed else (c.get("state_name") or "Open"),
                "is_closed": is_closed,
                "open_date": c.get("open_date"),
                "close_date": c.get("close_date"),
                "owner": c.get("owner"),
                "primary_domain": ext.primary_domain if ext else t_dom,
                "abuse_ticket_id": ext.abuse_ticket_id if ext else t_tick,
                "holder_ticket_id": ext.holder_ticket_id if ext else None,
                "client_id": ext.client_id if ext else None,
                "service_id": ext.service_id if ext else None,
                "server_name": ext.server_name if ext else None,
                "category_code": ext.category_code if ext else inferred_cat,
                "reported_activity": ext.reported_activity if ext else None,
                "confirmed_incident_type": ext.confirmed_incident_type if ext else None,
                "schema_version": ext.schema_version if ext else "legacy_v2",
            }
        )

    if updated_exts:
        try:
            db.commit()
        except Exception:
            db.rollback()

    return {"status": "ok", "total": len(items), "cases": items}


@router.get("/{case_id}")
def get_case_bundle(case_id: int, db: Session = Depends(get_db)):
    client = IrisApiClient()
    iris_case = client.get_case_full(case_id)
    if not iris_case or not iris_case.get("case_id"):
        raise HTTPException(status_code=404, detail=f"Caso #{case_id} no encontrado en DFIR-IRIS.")

    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    cname = re.sub(r"^#\d+\s*-\s*", "", iris_case.get("case_name") or "")
    m_title = re.match(r"^(?:\[([A-Z]+)\]\s*)?([^\s|]+)\s*\|\s*(NBX|HP)-([A-Za-z0-9_-]+)", cname, re.IGNORECASE)
    title_tag = m_title.group(1).upper() if m_title and m_title.group(1) else None
    title_domain = m_title.group(2).strip() if m_title else None
    title_org = m_title.group(3).upper() if m_title else None
    title_ticket = m_title.group(4).strip() if m_title else None

    custom_attrs = iris_case.get("custom_attributes") or {}
    ident_attrs = custom_attrs.get("01 Identificación") or {} if isinstance(custom_attrs, dict) else {}

    def _attr_val(k: str) -> Optional[str]:
        v = ident_attrs.get(k)
        if isinstance(v, dict):
            val = v.get("value")
            return str(val).strip() if val else None
        return str(v).strip() if v else None

    attr_domain = _attr_val("Dominio o activo reportado")
    attr_ticket = _attr_val("Ticket de abuso")
    attr_holder = _attr_val("Ticket del titular")
    attr_ip = _attr_val("IP reportada")
    attr_client_id = _attr_val("ID de Cliente")
    attr_service_id = _attr_val("ID de Servicio")
    attr_server = _attr_val("Servidor")

    tag_to_cat = {
        "FRAUD": "authority_req",
        "SPAM": "abuse_spam",
        "PHISH": "abuse_phishing",
        "BRAND": "brand_dispute",
        "NET": "account_compromise",
        "COMP": "compromise_botnet_mail",
        "MALW": "abuse_malware",
        "DMCA": "copyright_dmca",
        "RBL": "blacklist_rbl",
    }
    resolved_cat = tag_to_cat.get(title_tag, "general_abuse")

    notes_text = " ".join((n.get("note_content") or "") for n in (iris_case.get("notes") or []))
    if not ext:
        org = title_org or ("HP" if "| hp-" in cname.lower() or str(iris_case.get("case_customer")) == "3" else "NBX")
        ext_dict = {
            "iris_case_id": case_id,
            "organization": org,
            "customer_id": 3 if org == "HP" else 2,
            "abuse_ticket_id": attr_ticket or title_ticket,
            "holder_ticket_id": attr_holder,
            "client_id": attr_client_id,
            "service_id": attr_service_id,
            "service_plan": None,
            "primary_domain": attr_domain or title_domain,
            "server_name": attr_server,
            "hosting_ip": None,
            "reported_ip": attr_ip,
            "impersonated_brand": None,
            "reporter_name": "Ver notas originales",
            "category_code": resolved_cat,
            "reported_activity": "regulated_goods_sale" if resolved_cat == "authority_req" else ("spam_outbound" if resolved_cat == "abuse_spam" else "unknown"),
            "confirmed_incident_type": "authority_preservation_request" if resolved_cat == "authority_req" else ("confirmed_outbound_spam" if resolved_cat == "abuse_spam" else "pending_investigation"),
            "entry_vector": "not_applicable" if resolved_cat in ("authority_req", "brand_dispute") else "unknown",
            "root_cause": "regulatory_compliance_issue" if resolved_cat == "authority_req" else "unknown",
            "verification_state": "pendiente",
            "severity": "Medium",
            "is_technical_compromise": False if resolved_cat in ("authority_req", "brand_dispute") else True,
            "schema_version": "legacy_v2",
            "field_provenance_json": {},
            "resolution_data_json": {},
            "closure_checklist_json": {},
        }
    else:
        # Reconciliación activa si faltan datos en la extensión guardada
        final_domain = ext.primary_domain or attr_domain or title_domain
        final_ticket = ext.abuse_ticket_id or attr_ticket or title_ticket
        final_holder = ext.holder_ticket_id or attr_holder
        final_client = ext.client_id or attr_client_id
        final_service = ext.service_id or attr_service_id
        final_server = ext.server_name or attr_server
        final_ip = ext.reported_ip or attr_ip
        final_cat = ext.category_code
        if not final_cat or final_cat in ("abuse_phishing", "general_abuse"):
            if title_tag in tag_to_cat:
                final_cat = tag_to_cat[title_tag]

        # Actualizar en BD si se resolvieron campos faltantes
        updated_db = False
        if not ext.primary_domain and final_domain:
            ext.primary_domain = final_domain
            updated_db = True
        if not ext.abuse_ticket_id and final_ticket:
            ext.abuse_ticket_id = final_ticket
            updated_db = True
        if not ext.holder_ticket_id and final_holder:
            ext.holder_ticket_id = final_holder
            updated_db = True
        if not ext.client_id and final_client:
            ext.client_id = final_client
            updated_db = True
        if not ext.service_id and final_service:
            ext.service_id = final_service
            updated_db = True
        if not ext.server_name and final_server:
            ext.server_name = final_server
            updated_db = True
        if not ext.reported_ip and final_ip:
            ext.reported_ip = final_ip
            updated_db = True
        if ext.category_code != final_cat and final_cat != "general_abuse":
            ext.category_code = final_cat
            if final_cat == "authority_req":
                ext.reported_activity = "regulated_goods_sale"
                ext.confirmed_incident_type = "authority_preservation_request"
                ext.is_technical_compromise = False
            elif final_cat == "abuse_spam":
                ext.reported_activity = "spam_outbound"
                ext.confirmed_incident_type = "confirmed_outbound_spam"
                ext.is_technical_compromise = True
            elif final_cat == "brand_dispute":
                ext.reported_activity = "brand_trademark_infringement"
                ext.confirmed_incident_type = "brand_dispute_no_abuse"
                ext.is_technical_compromise = False
            updated_db = True
        if updated_db:
            db.commit()

        ext_dict = {
            "iris_case_id": ext.iris_case_id,
            "organization": ext.organization,
            "customer_id": ext.customer_id,
            "abuse_ticket_id": final_ticket,
            "holder_ticket_id": final_holder,
            "client_id": final_client,
            "service_id": final_service,
            "domain_id": ext.domain_id,
            "service_plan": ext.service_plan,
            "primary_domain": final_domain,
            "server_name": final_server,
            "hosting_ip": ext.hosting_ip,
            "reported_ip": final_ip,
            "impersonated_brand": ext.impersonated_brand,
            "reporter_name": ext.reporter_name,
            "reporter_type": ext.reporter_type,
            "registrar_name": ext.registrar_name,
            "category_code": final_cat,
            "reported_activity": ext.reported_activity,
            "confirmed_incident_type": ext.confirmed_incident_type,
            "entry_vector": ext.entry_vector,
            "root_cause": ext.root_cause,
            "verification_state": ext.verification_state,
            "severity": ext.severity,
            "is_technical_compromise": ext.is_technical_compromise,
            "playbook_code": ext.playbook_code,
            "schema_version": ext.schema_version,
            "field_provenance_json": ext.field_provenance_json or {},
            "initial_report_json": ext.initial_report_json or {},
            "resolution_data_json": ext.resolution_data_json or {},
            "closure_checklist_json": ext.closure_checklist_json or {},
        }

    investigations = [
        {
            "id": i.id,
            "source_consulted": i.source_consulted,
            "commands_or_queries": i.commands_or_queries,
            "results_observed": i.results_observed,
            "fact_type": i.fact_type,
            "provenance": i.provenance,
            "analyst_username": i.analyst_username,
            "executed_at": i.executed_at.isoformat() if i.executed_at else None,
        }
        for i in db.query(CaseInvestigation).filter(CaseInvestigation.iris_case_id == case_id).order_by(CaseInvestigation.id.asc()).all()
    ]
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "finding_nature": f.finding_nature,
            "verification_state": f.verification_state,
            "severity": f.severity,
            "provenance": f.provenance,
            "created_by": f.created_by,
        }
        for f in db.query(CaseFinding).filter(CaseFinding.iris_case_id == case_id).order_by(CaseFinding.id.asc()).all()
    ]
    actions = [
        {
            "id": a.id,
            "action_type": a.action_type,
            "title": a.title,
            "status": a.status,
            "responsible": a.responsible,
            "result_notes": a.result_notes,
            "provenance": a.provenance,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in db.query(CaseAction).filter(CaseAction.iris_case_id == case_id).order_by(CaseAction.id.asc()).all()
    ]
    communications = [
        {
            "id": cm.id,
            "channel": cm.channel,
            "direction": cm.direction,
            "recipient": cm.recipient,
            "ticket_reference": cm.ticket_reference,
            "summary": cm.summary,
            "sent_at": cm.sent_at.isoformat() if cm.sent_at else None,
        }
        for cm in db.query(CaseCommunication).filter(CaseCommunication.iris_case_id == case_id).order_by(CaseCommunication.id.asc()).all()
    ]

    # Incorporar actividades de la Bitácora Unificada para que el reporte formal siempre refleje el trabajo del analista
    activity_logs = db.query(CaseActivityLog).filter(CaseActivityLog.iris_case_id == case_id).order_by(CaseActivityLog.created_at.asc()).all()
    if activity_logs:
        existing_inv_titles = {i.get("commands_or_queries") for i in investigations}
        existing_act_titles = {a.get("title") for a in actions}
        for act in activity_logs:
            if act.activity_type == "investigacion" and act.title not in existing_inv_titles:
                meta = act.metadata_json or {}
                investigations.append({
                    "id": act.id,
                    "source_consulted": meta.get("source", "Bastion SSH"),
                    "commands_or_queries": act.title,
                    "results_observed": act.content,
                    "fact_type": "Hecho Técnico",
                    "provenance": "bitacora_unificada",
                    "analyst_username": act.analyst_username,
                    "executed_at": act.created_at.isoformat() if act.created_at else None,
                })
                existing_inv_titles.add(act.title)
            elif act.activity_type == "accion" and act.title not in existing_act_titles:
                actions.append({
                    "id": act.id,
                    "action_type": "containment",
                    "title": act.title,
                    "status": act.action_status or "ejecutada",
                    "responsible": act.analyst_username,
                    "result_notes": act.content or "Acción documentada en bitácora unificada",
                    "provenance": "bitacora_unificada",
                    "updated_at": act.updated_at.isoformat() if act.updated_at else None,
                })
                existing_act_titles.add(act.title)
            elif act.activity_type == "comunicacion":
                meta = act.metadata_json or {}
                communications.append({
                    "id": act.id,
                    "channel": meta.get("channel", "cliente_whmcs"),
                    "direction": "outbound",
                    "recipient": "Cliente / Reportante",
                    "ticket_reference": meta.get("ticket_ref", ""),
                    "summary": f"{act.title} — {act.content}" if act.content else act.title,
                    "sent_at": act.created_at.isoformat() if act.created_at else None,
                })

    playbooks = [
        {
            "code": pb.code,
            "name": pb.name,
            "category_code": pb.category_code,
            "steps": pb.steps_json,
        }
        for pb in db.query(PlaybookTemplate).filter(PlaybookTemplate.is_active.is_(True)).all()
    ]

    playbook_executions = [
        {
            "id": pe.id,
            "playbook_code": pe.playbook_code,
            "playbook_name": pe.playbook_name,
            "playbook_version": pe.playbook_version,
            "status": pe.status,
            "started_by": pe.started_by,
            "started_at": pe.started_at.isoformat() if pe.started_at else None,
            "completed_at": pe.completed_at.isoformat() if pe.completed_at else None,
            "steps_state": pe.steps_state or [],
        }
        for pe in db.query(CasePlaybookExecution)
        .filter(CasePlaybookExecution.iris_case_id == case_id)
        .order_by(CasePlaybookExecution.id.desc())
        .all()
    ]

    admin_links = build_admin_links(
        organization=ext.organization if ext else "NBX",
        customer_id=ext.customer_id if ext else 2,
        abuse_ticket_id=final_ticket,
        holder_ticket_id=final_holder,
        client_id=final_client,
        service_id=final_service,
        domain_id=ext.domain_id if ext else None,
        iris_case_id=case_id,
        user_role="admin",
    )

    return {
        "status": "ok",
        "iris_case": iris_case,
        "extension": ext_dict,
        "admin_links": admin_links,
        "investigations": investigations,
        "findings": findings,
        "actions": actions,
        "communications": communications,
        "playbooks": playbooks,
        "playbook_executions": playbook_executions,
        "evidences": iris_case.get("evidences", []) or [],
    }


@router.post("")
def create_manual_case(
    payload: ManualCaseCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    cat_meta = SOC_CATEGORIES.get(payload.category_code, SOC_CATEGORIES["abuse_phishing"])
    org = payload.organization.upper() if payload.organization.upper() in ("NBX", "HP") else "NBX"
    cust_id = 3 if org == "HP" else 2
    case_title = f"{cat_meta['tag']} {payload.primary_domain} | {org}-{payload.abuse_ticket_id}"

    r = client._post(
        "/manage/cases/add",
        payload={
            "case_name": case_title,
            "case_description": payload.summary,
            "case_customer": cust_id,
            "case_soc_id": str(payload.abuse_ticket_id),
            "classification_id": cat_meta["iris_classification_id"],
        },
    )
    r.raise_for_status()
    created = r.json().get("data") or {}
    cid = created.get("case_id")

    ext = CaseExtension(
        iris_case_id=cid,
        organization=org,
        customer_id=cust_id,
        source_channel="manual",
        abuse_ticket_id=payload.abuse_ticket_id,
        holder_ticket_id=payload.holder_ticket_id,
        client_id=payload.client_id,
        service_id=payload.service_id,
        primary_domain=payload.primary_domain,
        server_name=payload.server_name,
        hosting_ip=payload.hosting_ip,
        reported_ip=payload.reported_ip,
        category_code=payload.category_code,
        reported_activity=payload.reported_activity,
        confirmed_incident_type=payload.confirmed_incident_type,
        entry_vector=payload.entry_vector,
        root_cause=payload.root_cause,
        severity=payload.severity,
        playbook_code=cat_meta["default_playbook"],
        schema_version="3.0",
        field_provenance_json={"primary_domain": "manual", "category_code": "manual"},
        initial_report_json={"summary": payload.summary},
    )
    db.add(ext)
    db.commit()

    log_audit_event(
        db,
        action="case.manual_created",
        module="cases",
        user=user,
        organization=org,
        iris_case_id=cid,
        after_data=payload.model_dump(),
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "case_id": cid, "case_name": case_title}


@router.put("/{case_id}")
def update_case_structured(
    case_id: int,
    payload: CaseStructuredUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    if not ext:
        ext = CaseExtension(iris_case_id=case_id, schema_version="3.0")
        db.add(ext)
        db.flush()

    prov = dict(ext.field_provenance_json or {})
    data_in = payload.model_dump(exclude_unset=True)

    for k, v in data_in.items():
        if hasattr(ext, k) and v is not None:
            setattr(ext, k, v)
            prov[k] = "manual"

    if payload.organization:
        ext.customer_id = 3 if payload.organization.upper() == "HP" else 2
    ext.field_provenance_json = prov
    ext.schema_version = "3.0"
    db.commit()

    # Sincronizar metadatos y atributos principales hacia DFIR-IRIS
    iris_case = client.get_case_full(case_id)
    cname = payload.case_name or re.sub(r"^#\d+\s*-\s*", "", iris_case.get("case_name") or f"Caso #{case_id}")
    cat_meta = SOC_CATEGORIES.get(ext.category_code, SOC_CATEGORIES["abuse_phishing"])
    target_state = payload.state_id if payload.state_id is not None else (iris_case.get("state_id") or 3)

    custom_attrs = {
        "01 Identificación": {
            "Ticket de abuso": {"value": str(ext.abuse_ticket_id or "")},
            "Dominio o activo reportado": {"value": str(ext.primary_domain or "")},
            "IP reportada": {"value": str(ext.reported_ip or ext.hosting_ip or "")},
            "Ticket del titular": {"value": str(ext.holder_ticket_id or "")},
        }
    }
    update_body = {
        "case_name": cname,
        "case_description": payload.case_description or iris_case.get("case_description") or "",
        "case_customer": ext.customer_id,
        "case_soc_id": str(ext.abuse_ticket_id or ""),
        "classification_id": cat_meta["iris_classification_id"],
        "state_id": target_state,
        "status_id": target_state,
        "custom_attributes": custom_attrs,
    }
    client._post(f"/manage/cases/update/{case_id}?cid={case_id}", payload=update_body)

    if payload.state_id is not None:
        now = datetime.now(timezone.utc)
        if payload.state_id == 4:
            ext.contained_at = ext.contained_at or now
            ext.verification_state = "contencion"
        elif payload.state_id == 9:
            ext.closed_at = now
            ext.verification_state = "cerrado"
        elif payload.state_id in (5, 6, 7):
            ext.resolved_at = ext.resolved_at or now
            ext.verification_state = "resuelto"
        ext.updated_at = now
        db.commit()

    if payload.current_note_id and payload.current_note_content is not None:
        client.update_case_note(
            case_id=case_id,
            note_id=payload.current_note_id,
            note_content=payload.current_note_content,
        )
        db.query(CaseDraft).filter(
            CaseDraft.iris_case_id == case_id,
            CaseDraft.field_key == f"note_{payload.current_note_id}",
        ).delete()
        db.commit()

    if payload.sync_structured_note_to_iris:
        md = LegacyCaseMigrator._render_v3_structured_note_markdown(
            ext,
            {"epistemological_breakdown": ext.resolution_data_json or {}},
        )
        client.ensure_structured_note(
            case_id,
            directory_name="SOC v3.0 — Estructura Normalizada",
            note_title="04 Ficha Técnica Normalizada v3.0 (Migración Controlada)",
            note_content=md,
            update_if_exists=True,
        )

    log_audit_event(
        db,
        action="case.structured_updated",
        module="cases",
        user=user,
        organization=ext.organization,
        iris_case_id=case_id,
        after_data=data_in,
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "case_id": case_id, "field_provenance": prov}


@router.put("/{case_id}/notes/{note_id}")
def update_case_note_endpoint(
    case_id: int,
    note_id: int,
    payload: CaseNoteUpdateRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Actualiza una nota técnica directamente en DFIR-IRIS y limpia borradores locales."""
    client = IrisApiClient()
    res = client.update_case_note(
        case_id=case_id,
        note_id=note_id,
        note_content=payload.note_content,
        note_title=payload.note_title,
        directory_id=payload.directory_id,
    )
    if res.get("status") == "error":
        raise HTTPException(
            status_code=res.get("code") or 400,
            detail=f"Error al sincronizar nota en IRIS: {res.get('message') or res.get('response')}",
        )

    db.query(CaseDraft).filter(
        CaseDraft.iris_case_id == case_id,
        CaseDraft.field_key == f"note_{note_id}",
    ).delete()
    db.commit()

    return {"status": "ok", "case_id": case_id, "note_id": note_id, "result": res}


@router.patch("/{case_id}/state")
def update_case_state_endpoint(
    case_id: int,
    payload: CaseStateUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Actualiza y sincroniza en vivo el estado de un caso en DFIR-IRIS."""
    client = IrisApiClient()
    states = client.list_case_states()
    valid_map = {s["state_id"]: s["state_name"] for s in states}
    if payload.state_id not in valid_map:
        raise HTTPException(
            status_code=400,
            detail=f"Estado ID {payload.state_id} no es válido en DFIR-IRIS. Opciones: {list(valid_map.keys())}",
        )

    target_state_name = valid_map[payload.state_id]

    try:
        client.update_case_state(case_id, payload.state_id)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Fallo al sincronizar el cambio de estado con DFIR-IRIS: {e}",
        )

    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    now = datetime.now(timezone.utc)
    if ext:
        if payload.state_id == 4:  # Containment
            ext.contained_at = ext.contained_at or now
            ext.verification_state = "contencion"
        elif payload.state_id == 9:  # Closed
            ext.closed_at = now
            ext.verification_state = "cerrado"
        elif payload.state_id in (5, 6, 7):
            ext.resolved_at = ext.resolved_at or now
            ext.verification_state = "resuelto"
        ext.updated_at = now
        db.commit()

    log_audit_event(
        db,
        action="case.state_updated",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Estado del Caso #{case_id} actualizado a '{target_state_name}' (ID: {payload.state_id}).",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "case_id": case_id,
        "state_id": payload.state_id,
        "state_name": target_state_name,
    }


@router.post("/{case_id}/investigations")
def add_case_investigation(
    case_id: int,
    payload: InvestigationCreateRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    inv = CaseInvestigation(
        iris_case_id=case_id,
        source_consulted=payload.source_consulted,
        commands_or_queries=payload.commands_or_queries,
        results_observed=payload.results_observed,
        fact_type=payload.fact_type,
        provenance="manual",
        analyst_username=user.username if user else "Christian Aceves",
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return {"status": "ok", "id": inv.id}


@router.post("/{case_id}/findings")
def add_case_finding(
    case_id: int,
    payload: FindingCreateRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    f = CaseFinding(
        iris_case_id=case_id,
        title=payload.title,
        description=payload.description,
        finding_nature=payload.finding_nature,
        verification_state=payload.verification_state,
        severity=payload.severity,
        provenance="manual",
        created_by=user.username if user else "Christian Aceves",
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return {"status": "ok", "id": f.id}


@router.post("/{case_id}/actions")
def add_case_action(
    case_id: int,
    payload: ActionCreateRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    st = payload.status if payload.status in VALID_ACTION_STATUS_CODES else "pendiente"
    a = CaseAction(
        iris_case_id=case_id,
        action_type=payload.action_type,
        title=payload.title,
        status=st,
        responsible=payload.responsible or (user.username if user else "SOC Analyst"),
        result_notes=payload.result_notes or "",
        provenance="manual",
    )
    db.add(a)
    db.commit()
    db.refresh(a)

    if payload.sync_task_to_iris:
        client = IrisApiClient()
        client.ensure_task(
            case_id,
            title=a.title,
            description=a.result_notes or "",
            action_status=a.status,
        )
    return {"status": "ok", "id": a.id, "action_status": a.status}


@router.put("/{case_id}/actions/{action_id}")
@router.patch("/{case_id}/actions/{action_id}")
def update_case_action_status(
    case_id: int,
    action_id: int,
    payload: ActionStatusUpdateRequest,
    db: Session = Depends(get_db),
):
    a = db.query(CaseAction).filter(CaseAction.id == action_id, CaseAction.iris_case_id == case_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Acción no encontrada.")
    if payload.status not in VALID_ACTION_STATUS_CODES:
        raise HTTPException(status_code=400, detail=f"Estado de acción inválido: {payload.status}")

    a.status = payload.status
    if payload.result_notes is not None:
        a.result_notes = payload.result_notes
    now = datetime.now(timezone.utc)
    if payload.status == "ejecutada":
        a.executed_at = now
    elif payload.status == "verificada":
        a.verified_at = now
    a.provenance = "manual"
    db.commit()

    client = IrisApiClient()
    client.ensure_task(
        case_id,
        title=a.title,
        description=a.result_notes or "",
        action_status=a.status,
    )
    return {"status": "ok", "id": a.id, "new_status": a.status}


@router.post("/{case_id}/communications")
def add_case_communication(
    case_id: int,
    payload: CommunicationCreateRequest,
    db: Session = Depends(get_db),
):
    cm = CaseCommunication(
        iris_case_id=case_id,
        channel=payload.channel,
        direction=payload.direction,
        recipient=payload.recipient,
        ticket_reference=payload.ticket_reference,
        summary=payload.summary,
        provenance="manual",
    )
    db.add(cm)
    db.commit()
    db.refresh(cm)
    return {"status": "ok", "id": cm.id}


@router.post("/{case_id}/apply-playbook/{playbook_code}")
def apply_playbook_to_case(
    case_id: int,
    playbook_code: str,
    db: Session = Depends(get_db),
):
    pb = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == playbook_code).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_code}' no encontrado.")

    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    if ext:
        ext.playbook_code = pb.code

    existing_titles = {
        a.title.strip().lower()
        for a in db.query(CaseAction).filter(CaseAction.iris_case_id == case_id).all()
    }
    client = IrisApiClient()
    added = 0
    for step in pb.steps_json or []:
        t = (step.get("title") or "").strip()
        if t and t.lower() not in existing_titles:
            db.add(
                CaseAction(
                    iris_case_id=case_id,
                    action_type=step.get("suggested_action_type", "playbook_step"),
                    title=t,
                    status="pendiente",
                    responsible="SOC Analyst",
                    result_notes=f"Paso #{step.get('order')} del Playbook {pb.name}",
                    provenance="rule",
                )
            )
            client.ensure_task(case_id, title=t, description=f"Playbook: {pb.name}", action_status="pendiente")
            existing_titles.add(t.lower())
            added += 1

    db.commit()
    return {"status": "ok", "playbook": pb.name, "steps_added": added}


@router.get("/{case_id}/playbooks/suggested")
def get_case_suggested_playbooks(case_id: int, db: Session = Depends(get_db)):
    """Identifica y sugiere playbooks aplicables según la clasificación formal del caso."""
    from app.classification.taxonomy import infer_category_from_case_title

    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    category = ext.category_code if ext and ext.category_code else None
    if not category:
        try:
            iris_case = IrisApiClient().get_case_full(case_id)
            if iris_case:
                category = infer_category_from_case_title(iris_case.get("case_name", ""))
        except Exception:
            pass
    category = category or "general_abuse"

    pbs = db.query(PlaybookTemplate).filter(PlaybookTemplate.is_active.is_(True)).all()
    suggested = []
    for pb in pbs:
        is_match = pb.category_code == category
        suggested.append({
            "id": pb.id,
            "code": pb.code,
            "name": pb.name,
            "category_code": pb.category_code,
            "description": pb.description,
            "steps_count": len(pb.steps_json or []),
            "steps": pb.steps_json or [],
            "is_suggested": is_match,
        })
    suggested.sort(key=lambda x: (not x["is_suggested"], x["name"]))
    return {
        "status": "ok",
        "case_id": case_id,
        "case_category": category,
        "inferred_category": category,
        "playbooks": suggested,
        "suggested_playbooks": [p for p in suggested if p["is_suggested"]],
    }


@router.get("/{case_id}/playbooks/executions")
def get_case_playbook_executions(case_id: int, db: Session = Depends(get_db)):
    """Obtiene el historial de ejecuciones supervisadas de playbooks del caso."""
    execs = (
        db.query(CasePlaybookExecution)
        .filter(CasePlaybookExecution.iris_case_id == case_id)
        .order_by(CasePlaybookExecution.id.desc())
        .all()
    )
    return {
        "status": "ok",
        "case_id": case_id,
        "executions": [
            {
                "id": pe.id,
                "playbook_code": pe.playbook_code,
                "playbook_name": pe.playbook_name,
                "playbook_version": pe.playbook_version,
                "status": pe.status,
                "started_by": pe.started_by,
                "started_at": pe.started_at.isoformat() if pe.started_at else None,
                "completed_at": pe.completed_at.isoformat() if pe.completed_at else None,
                "steps_state": pe.steps_state or [],
            }
            for pe in execs
        ],
    }


@router.post("/{case_id}/playbooks/start")
def start_case_playbook_execution(
    case_id: int,
    payload: PlaybookStartRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Inicia una ejecución supervisada de Playbook asociada al caso, sin automatismos destructivos."""
    pb = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == payload.playbook_code).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{payload.playbook_code}' no encontrado.")

    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    if ext:
        ext.playbook_code = pb.code

    now = datetime.now(timezone.utc)
    analyst_name = user.username if user else "SOC Analyst"

    steps_state = [
        {
            "order": s.get("order", idx + 1),
            "title": s.get("title", ""),
            "description": s.get("description", ""),
            "mandatory": s.get("mandatory", True),
            "status": "pendiente",  # pendiente, en_progreso, completado, omitido, bloqueado
            "observations": "",
            "suggested_action_type": s.get("suggested_action_type", "playbook_step"),
            "updated_by": None,
            "updated_at": None,
            "case_action_id": None,
        }
        for idx, s in enumerate(pb.steps_json or [])
    ]

    new_exec = CasePlaybookExecution(
        iris_case_id=case_id,
        playbook_code=pb.code,
        playbook_name=pb.name,
        playbook_version="1.0",
        status="in_progress",
        started_by=analyst_name,
        started_at=now,
        steps_state=steps_state,
        created_at=now,
        updated_at=now,
    )
    db.add(new_exec)
    db.commit()
    db.refresh(new_exec)

    log_audit_event(
        db,
        action="playbook.execution_started",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Iniciada ejecución supervisada de '{pb.name}' (Código: {pb.code}).",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "execution": {
            "id": new_exec.id,
            "playbook_code": new_exec.playbook_code,
            "playbook_name": new_exec.playbook_name,
            "playbook_version": new_exec.playbook_version,
            "status": new_exec.status,
            "started_by": new_exec.started_by,
            "started_at": new_exec.started_at.isoformat(),
            "completed_at": None,
            "steps_state": new_exec.steps_state,
        },
    }


@router.patch("/{case_id}/playbooks/executions/{exec_id}/step/{step_order}")
def update_case_playbook_step(
    case_id: int,
    exec_id: int,
    step_order: int,
    payload: PlaybookStepUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Actualiza el estado, observaciones y responsable de un paso operativo del Playbook."""
    pe = (
        db.query(CasePlaybookExecution)
        .filter(CasePlaybookExecution.id == exec_id, CasePlaybookExecution.iris_case_id == case_id)
        .first()
    )
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    now = datetime.now(timezone.utc)
    analyst_name = user.username if user else "SOC Analyst"
    steps = list(pe.steps_state or [])
    step_found = False

    for s in steps:
        if s.get("order") == step_order:
            step_found = True
            s["status"] = payload.status
            if payload.observations is not None:
                s["observations"] = payload.observations
            s["updated_by"] = analyst_name
            s["updated_at"] = now.isoformat()

            if payload.create_case_action and not s.get("case_action_id"):
                action_title = f"[{pe.playbook_code}] Paso #{step_order}: {s.get('title')}"
                case_act = CaseAction(
                    iris_case_id=case_id,
                    action_type=s.get("suggested_action_type", "playbook_step"),
                    title=action_title,
                    status="ejecutada" if payload.status == "completado" else "en_ejecucion",
                    responsible=analyst_name,
                    result_notes=payload.observations or f"Registrado desde ejecución de Playbook #{exec_id}",
                    provenance="playbook",
                )
                db.add(case_act)
                db.flush()
                s["case_action_id"] = case_act.id
                client = IrisApiClient()
                client.ensure_task(
                    case_id,
                    title=action_title,
                    description=s.get("description", ""),
                    action_status="ejecutada" if payload.status == "completado" else "en_ejecucion",
                )
            break

    if not step_found:
        raise HTTPException(status_code=404, detail=f"Paso #{step_order} no encontrado en la ejecución.")

    all_mandatory_done = all(
        s.get("status") in ("completado", "omitido")
        for s in steps
        if s.get("mandatory", True)
    )
    if all_mandatory_done and pe.status == "in_progress":
        pe.status = "completed"
        pe.completed_at = now

    from sqlalchemy.orm.attributes import flag_modified

    pe.steps_state = steps
    flag_modified(pe, "steps_state")
    pe.updated_at = now
    db.commit()
    db.refresh(pe)

    log_audit_event(
        db,
        action="playbook.step_updated",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Paso #{step_order} de Playbook '{pe.playbook_name}' marcado como '{payload.status}'.",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "execution_status": pe.status,
        "completed_at": pe.completed_at.isoformat() if pe.completed_at else None,
        "steps_state": pe.steps_state,
    }


@router.patch("/{case_id}/playbooks/executions/{exec_id}/status")
def update_case_playbook_execution_status(
    case_id: int,
    exec_id: int,
    payload: PlaybookStatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Suspende, reanuda o finaliza una ejecución supervisada de Playbook."""
    pe = (
        db.query(CasePlaybookExecution)
        .filter(CasePlaybookExecution.id == exec_id, CasePlaybookExecution.iris_case_id == case_id)
        .first()
    )
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    now = datetime.now(timezone.utc)
    pe.status = payload.status
    if payload.status == "completed":
        pe.completed_at = now
    elif payload.status in ("in_progress", "suspended"):
        pe.completed_at = None

    pe.updated_at = now
    db.commit()

    log_audit_event(
        db,
        action="playbook.status_updated",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Ejecución #{exec_id} de Playbook '{pe.playbook_name}' cambiada a estado '{payload.status}'.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "id": pe.id, "status": pe.status, "completed_at": pe.completed_at.isoformat() if pe.completed_at else None}


@router.post("/{case_id}/close")
def close_case_endpoint(
    case_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    client = IrisApiClient()
    r = client._post(f"/manage/cases/close/{case_id}")
    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    if ext:
        ext.closed_at = datetime.now(timezone.utc)
        db.commit()
    log_audit_event(
        db,
        action="case.closed",
        module="cases",
        user=user,
        iris_case_id=case_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "iris_status": r.status_code}


@router.get("/{case_id}/report.pdf")
def download_case_formal_pdf(case_id: int, download: bool = False, db: Session = Depends(get_db)):
    bundle = get_case_bundle(case_id=case_id, db=db)
    pdf_bytes = FormalPdfReportGenerator.generate_case_pdf_bytes(bundle)
    org = (bundle.get("extension") or {}).get("organization") or "NBX"
    filename = f"Informe_SOC_v3_{org}_Caso_{case_id}.pdf"
    disposition = "attachment" if download else "inline"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@router.post("/{case_id}/evidences/upload")
async def upload_case_evidence(
    case_id: int,
    file: UploadFile = File(...),
    description: str = Form(""),
    request: Request = None,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Sube un archivo de evidencia forense, calcula su hash SHA-256, lo resguarda
    en el almacenamiento local y lo registra como evidencia en DFIR-IRIS."""
    client = IrisApiClient()
    iris_case = client.get_case_full(case_id)
    if not iris_case:
        raise HTTPException(status_code=404, detail=f"Caso #{case_id} no encontrado en DFIR-IRIS.")

    contents = await file.read()
    file_size = len(contents)
    file_hash = hashlib.sha256(contents).hexdigest()

    # Guardar en almacenamiento seguro local
    evidences_dir = settings.BASE_DIR / "storage" / "evidences" / str(case_id)
    evidences_dir.mkdir(parents=True, exist_ok=True)
    safe_filename = re.sub(r"[^\w\.-]", "_", file.filename or "evidence.bin")
    dest_path = evidences_dir / safe_filename
    with open(dest_path, "wb") as f:
        f.write(contents)

    # Registrar en DFIR-IRIS
    try:
        evidence_data = client.add_case_evidence(
            case_id=case_id,
            filename=file.filename or safe_filename,
            file_size=file_size,
            file_hash=file_hash,
            description=description or f"Evidencia digital preservada desde Consola SOC v3.1 ({file.filename})",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Fallo al registrar evidencia en DFIR-IRIS: {exc}")

    log_audit_event(
        db,
        action="case.evidence_uploaded",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Evidencia '{file.filename}' ({file_size} bytes, SHA-256: {file_hash[:16]}...) subida y registrada en DFIR-IRIS.",
        ip_address=request.client.host if request and request.client else None,
    )

    return {
        "status": "ok",
        "evidence": evidence_data,
        "filename": file.filename,
        "file_size": file_size,
        "file_hash": file_hash,
    }


@router.get("/{case_id}/evidences/{filename}")
def download_case_evidence_file(case_id: int, filename: str):
    """Permite descargar el archivo físico de una evidencia resguardada localmente."""
    safe_filename = os.path.basename(filename)
    file_path = settings.BASE_DIR / "storage" / "evidences" / str(case_id) / safe_filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Archivo de evidencia no encontrado localmente.")
    return FileResponse(str(file_path), filename=safe_filename)


@router.get("/{case_id}/drafts")
def get_case_drafts(
    case_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Recupera los borradores automáticos guardados para este caso y usuario."""
    uid = user.id if user else 1
    drafts = (
        db.query(CaseDraft)
        .filter(CaseDraft.iris_case_id == case_id, CaseDraft.user_id == uid)
        .all()
    )
    return {
        "status": "ok",
        "case_id": case_id,
        "drafts": {
            d.field_key: {
                "content": d.draft_content,
                "updated_at": d.updated_at.isoformat() if d.updated_at else None,
            }
            for d in drafts
        },
    }


@router.put("/{case_id}/drafts/{field_key}")
def save_case_draft(
    case_id: int,
    field_key: str,
    payload: CaseDraftSaveRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Guarda automáticamente un borrador en PostgreSQL con aislamiento por caso y usuario."""
    uid = user.id if user else 1
    draft = (
        db.query(CaseDraft)
        .filter(
            CaseDraft.iris_case_id == case_id,
            CaseDraft.user_id == uid,
            CaseDraft.field_key == field_key,
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    if not draft:
        draft = CaseDraft(
            iris_case_id=case_id,
            user_id=uid,
            field_key=field_key,
            draft_content=payload.draft_content,
            created_at=now,
            updated_at=now,
        )
        db.add(draft)
    else:
        draft.draft_content = payload.draft_content
        draft.updated_at = now
    db.commit()
    return {"status": "ok", "ok": True, "field_key": field_key, "updated_at": draft.updated_at.isoformat()}


@router.delete("/{case_id}/drafts/{field_key}")
def delete_case_draft(
    case_id: int,
    field_key: str,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Descarta o limpia un borrador una vez sincronizado en IRIS o por acción del usuario."""
    uid = user.id if user else 1
    db.query(CaseDraft).filter(
        CaseDraft.iris_case_id == case_id,
        CaseDraft.user_id == uid,
        CaseDraft.field_key == field_key,
    ).delete()
    db.commit()
    return {"status": "ok", "ok": True, "deleted": True}


# ==========================================================
# BITÁCORA OPERATIVA UNIFICADA Y ASISTENTE DINÁMICO DE PLAYBOOKS
# ==========================================================

@router.get("/{case_id}/activity")
def get_case_activity(
    case_id: int,
    activity_type: Optional[str] = None,
    step_order: Optional[int] = None,
    playbook_execution_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Obtiene la bitácora operativa unificada del caso, con filtros por tipo y paso."""
    query = db.query(CaseActivityLog).filter(CaseActivityLog.iris_case_id == case_id)
    if activity_type:
        query = query.filter(CaseActivityLog.activity_type == activity_type)
    if step_order is not None:
        query = query.filter(CaseActivityLog.step_order == step_order)
    if playbook_execution_id is not None:
        query = query.filter(CaseActivityLog.playbook_execution_id == playbook_execution_id)

    entries = query.order_by(CaseActivityLog.created_at.asc()).all()

    # Sincronizar evidencias existentes de IRIS Datastore hacia la bitácora si no están registradas
    # y actualizar hashes si faltaban
    try:
        client = IrisApiClient()
        iris_evs = client.list_case_evidences(case_id)
        # Consultar todas las evidencias existentes en BD para este caso sin sesgo de filtros
        all_case_ev_logs = db.query(CaseActivityLog).filter(
            CaseActivityLog.iris_case_id == case_id,
            CaseActivityLog.iris_evidence_id.isnot(None)
        ).all()
        existing_ev_map = {a.iris_evidence_id: a for a in all_case_ev_logs}
        has_changes = False

        for ev in iris_evs:
            fid = ev.get("file_id") or ev.get("id")
            if not fid:
                continue

            fname = ev.get("file_original_name") or ev.get("filename") or f"evidence_{fid}"
            f_size = ev.get("file_size") or ev.get("size") or 0
            # Extraer hash real: IRIS lo almacena en 'file_hash'
            f_sha = ev.get("file_hash") or ev.get("file_sha256") or ev.get("sha256") or "N/A"
            mime = "image/jpeg" if fname.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")) else "application/octet-stream"

            if fid not in existing_ev_map:
                ev_log = CaseActivityLog(
                    iris_case_id=case_id,
                    activity_type="evidencia",
                    title=f"Evidencia: {fname}",
                    content=f"Evidencia forense `{fname}` registrada en Datastore de IRIS.\n- **SHA-256**: `{f_sha}`\n- **Tamaño**: {f_size} bytes\n- **ID Datastore**: #{fid}",
                    metadata_json={
                        "filename": fname,
                        "file_size": f_size,
                        "sha256": f_sha,
                        "mime_type": mime,
                        "iris_file_id": fid,
                        "is_image": mime.startswith("image/"),
                        "description": ev.get("file_description", ""),
                    },
                    action_status="verificada",
                    iris_evidence_id=fid,
                    sync_status="synced",
                    analyst_username="Christian Aceves",
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(ev_log)
                has_changes = True
            else:
                # Reparar hash si estaba como N/A
                existing_log = existing_ev_map[fid]
                meta = dict(existing_log.metadata_json or {})
                if (meta.get("sha256") in ("N/A", None, "", "-")) and f_sha != "N/A":
                    meta["sha256"] = f_sha
                    from sqlalchemy.orm.attributes import flag_modified
                    existing_log.metadata_json = meta
                    flag_modified(existing_log, "metadata_json")
                    if "SHA-256: `N/A`" in existing_log.content:
                        existing_log.content = existing_log.content.replace("SHA-256: `N/A`", f"SHA-256: `{f_sha}`")
                    has_changes = True

        if has_changes:
            db.commit()
            entries = query.order_by(CaseActivityLog.created_at.asc()).all()
    except Exception:
        pass

    return {
        "status": "ok",
        "case_id": case_id,
        "activities": [
            {
                "id": a.id,
                "iris_case_id": a.iris_case_id,
                "playbook_execution_id": a.playbook_execution_id,
                "step_order": a.step_order,
                "activity_type": a.activity_type,
                "title": a.title,
                "content": a.content,
                "metadata_json": a.metadata_json or {},
                "action_status": a.action_status,
                "iris_evidence_id": a.iris_evidence_id,
                "iris_task_id": a.iris_task_id,
                "iris_timeline_id": a.iris_timeline_id,
                "sync_status": a.sync_status,
                "sync_error": a.sync_error,
                "analyst_username": a.analyst_username,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "updated_at": a.updated_at.isoformat() if a.updated_at else None,
            }
            for a in entries
        ],
    }


@router.post("/{case_id}/activity")
def add_case_activity(
    case_id: int,
    payload: ActivityCreateRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Crea una entrada en la bitácora operativa unificada y sincroniza según su tipo."""
    username = user.username if user else "Christian Aceves"
    meta = payload.metadata_json or {}
    now = datetime.now(timezone.utc)

    iris_task_id = None
    iris_timeline_id = None
    iris_evidence_id = meta.get("iris_evidence_id")

    # Si es acción o tiene estado operativo, sincronizar tarea en IRIS
    if payload.activity_type == "accion" or payload.action_status:
        st = payload.action_status or "pendiente"
        if payload.sync_to_iris:
            try:
                client = IrisApiClient()
                res = client.ensure_task(
                    case_id,
                    title=payload.title,
                    description=payload.content or meta.get("description", ""),
                    action_status=st,
                )
                iris_task_id = res.get("task_id") or (res.get("data") or {}).get("task_id")
            except Exception:
                pass

        # Registrar también en CaseAction si es accion
        existing_action = db.query(CaseAction).filter(
            CaseAction.iris_case_id == case_id,
            CaseAction.title == payload.title
        ).first()
        if not existing_action:
            act = CaseAction(
                iris_case_id=case_id,
                action_type=meta.get("action_type", "bitacora_operativa"),
                title=payload.title,
                status=st,
                responsible=username,
                result_notes=payload.content,
                iris_task_id=iris_task_id,
                provenance="manual",
                created_at=now,
                updated_at=now,
            )
            db.add(act)
            db.flush()
        else:
            existing_action.status = st
            if payload.content:
                existing_action.result_notes = payload.content
            existing_action.updated_at = now

    elif payload.activity_type == "investigacion":
        inv = CaseInvestigation(
            iris_case_id=case_id,
            source_consulted=meta.get("source_consulted", "Bitácora Técnica"),
            commands_or_queries=meta.get("commands", ""),
            results_observed=payload.content or payload.title,
            fact_type=meta.get("fact_type", "confirmed_fact"),
            provenance="manual",
            analyst_username=username,
            executed_at=now,
            created_at=now,
        )
        db.add(inv)

    elif payload.activity_type == "comunicacion":
        comm = CaseCommunication(
            iris_case_id=case_id,
            channel=meta.get("channel", "Zammad"),
            direction=meta.get("direction", "outbound"),
            recipient=meta.get("recipient", "cliente"),
            ticket_reference=meta.get("ticket_reference"),
            summary=payload.content or payload.title,
            provenance="manual",
            created_at=now,
        )
        db.add(comm)

    # Si está asociado a un paso de playbook y execution_id, actualizar el paso
    if payload.playbook_execution_id and payload.step_order:
        pe = db.query(CasePlaybookExecution).filter(
            CasePlaybookExecution.id == payload.playbook_execution_id,
            CasePlaybookExecution.iris_case_id == case_id
        ).first()
        if pe:
            from sqlalchemy.orm.attributes import flag_modified
            steps = list(pe.steps_state or [])
            for s in steps:
                if s.get("order") == payload.step_order:
                    if payload.action_status in ("ejecutada", "verificada") or payload.activity_type in ("accion", "evidencia"):
                        s["status"] = "completado"
                    elif s.get("status") == "pendiente":
                        s["status"] = "en_progreso"
                    if payload.content and not s.get("observations"):
                        s["observations"] = payload.content[:200]
                    s["updated_by"] = username
                    s["updated_at"] = now.isoformat()
                    break
            pe.steps_state = steps
            flag_modified(pe, "steps_state")
            pe.updated_at = now

    entry = CaseActivityLog(
        iris_case_id=case_id,
        playbook_execution_id=payload.playbook_execution_id,
        step_order=payload.step_order,
        activity_type=payload.activity_type,
        title=payload.title,
        content=payload.content,
        metadata_json=meta,
        action_status=payload.action_status,
        iris_evidence_id=iris_evidence_id,
        iris_task_id=iris_task_id,
        iris_timeline_id=iris_timeline_id,
        sync_status="synced",
        analyst_username=username,
        created_at=now,
        updated_at=now,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    # Sincronización automática a IRIS en segundo plano
    _auto_sync_case_note_internal(case_id, db, username)
    return {
        "status": "ok",
        "id": entry.id,
        "activity": {
            "id": entry.id,
            "title": entry.title,
            "activity_type": entry.activity_type,
            "action_status": entry.action_status,
            "step_order": entry.step_order,
        }
    }


@router.post("/{case_id}/activity/evidence")
async def upload_case_activity_evidence(
    case_id: int,
    file: Optional[UploadFile] = File(None),
    base64_data: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    step_order: Optional[int] = Form(None),
    playbook_execution_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Sube evidencia directamente a DFIR-IRIS Datastore (fuente única de verdad) y la vincula a la bitácora."""
    username = user.username if user else "Christian Aceves"
    now = datetime.now(timezone.utc)

    file_bytes = b""
    fname = filename or "evidencia"

    if file:
        file_bytes = await file.read()
        fname = file.filename or fname
    elif base64_data:
        import base64
        data_clean = base64_data
        if "," in data_clean:
            data_clean = data_clean.split(",", 1)[1]
        try:
            file_bytes = base64.b64decode(data_clean)
            if not filename:
                fname = f"screenshot_{int(now.timestamp())}.png"
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error decodificando imagen base64: {e}")
    else:
        raise HTTPException(status_code=400, detail="Debe proporcionar un archivo o imagen base64 del portapapeles.")

    sha256_hash = hashlib.sha256(file_bytes).hexdigest().upper()
    file_size = len(file_bytes)
    evidence_title = title or f"Evidencia: {fname}"
    desc = description or f"Evidencia cargada por {username}"

    # Subir DIRECTAMENTE al Datastore oficial de DFIR-IRIS
    client = IrisApiClient()
    iris_res = client.upload_datastore_file(
        case_id=case_id,
        file_data=file_bytes,
        filename=fname,
        description=desc,
        is_evidence=True,
    )

    if not iris_res.get("success"):
        raise HTTPException(status_code=502, detail=f"Fallo al guardar evidencia en IRIS Datastore: {iris_res.get('error')}")

    iris_file_id = iris_res.get("file_id")
    iris_file_uuid = iris_res.get("file_uuid")
    mime_type = iris_res.get("mime_type", "application/octet-stream")

    metadata = {
        "filename": fname,
        "file_size": file_size,
        "sha256": sha256_hash,
        "mime_type": mime_type,
        "iris_file_id": iris_file_id,
        "iris_file_uuid": iris_file_uuid,
        "is_image": mime_type.startswith("image/"),
        "description": desc,
    }

    # Si está vinculado a un paso de playbook, actualizar estado a completado
    if playbook_execution_id and step_order:
        pe = db.query(CasePlaybookExecution).filter(
            CasePlaybookExecution.id == playbook_execution_id,
            CasePlaybookExecution.iris_case_id == case_id
        ).first()
        if pe:
            from sqlalchemy.orm.attributes import flag_modified
            steps = list(pe.steps_state or [])
            for s in steps:
                if s.get("order") == step_order:
                    s["status"] = "completado"
                    s["observations"] = f"Evidencia forense adjunta: {fname} (SHA256: {sha256_hash[:12]}...)"
                    s["updated_by"] = username
                    s["updated_at"] = now.isoformat()
                    break
            pe.steps_state = steps
            flag_modified(pe, "steps_state")
            pe.updated_at = now

    activity = CaseActivityLog(
        iris_case_id=case_id,
        playbook_execution_id=playbook_execution_id,
        step_order=step_order,
        activity_type="evidencia",
        title=evidence_title,
        content=f"Evidencia forense `{fname}` registrada en Datastore de IRIS.\n- **SHA-256**: `{sha256_hash}`\n- **Tamaño**: {file_size} bytes\n- **ID Datastore**: #{iris_file_id}",
        metadata_json=metadata,
        action_status="verificada",
        iris_evidence_id=iris_file_id,
        sync_status="synced",
        analyst_username=username,
        created_at=now,
        updated_at=now,
    )
    db.add(activity)
    db.commit()
    db.refresh(activity)
    # Sincronización automática de nota en IRIS con la nueva evidencia
    _auto_sync_case_note_internal(case_id, db, username)

    return {
        "status": "ok",
        "id": activity.id,
        "iris_file_id": iris_file_id,
        "sha256": sha256_hash,
        "filename": fname,
        "activity": {
            "id": activity.id,
            "title": activity.title,
            "activity_type": "evidencia",
            "metadata_json": metadata,
            "step_order": step_order,
        }
    }


@router.patch("/{case_id}/activity/{activity_id}")
def update_case_activity(
    case_id: int,
    activity_id: int,
    payload: ActivityUpdateRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Actualiza una entrada de la bitácora operativa."""
    act = db.query(CaseActivityLog).filter(
        CaseActivityLog.id == activity_id,
        CaseActivityLog.iris_case_id == case_id
    ).first()
    if not act:
        raise HTTPException(status_code=404, detail="Registro de bitácora no encontrado.")

    now = datetime.now(timezone.utc)
    if payload.title is not None:
        act.title = payload.title
    if payload.content is not None:
        act.content = payload.content
    if payload.action_status is not None:
        act.action_status = payload.action_status
        if act.iris_task_id:
            try:
                client = IrisApiClient()
                client.ensure_task(
                    case_id,
                    title=act.title,
                    description=act.content,
                    action_status=act.action_status,
                )
            except Exception:
                pass
    if payload.metadata_json is not None:
        act.metadata_json = payload.metadata_json

    act.updated_at = now
    db.commit()
    author = user.username if user else "SOC Analyst"
    _auto_sync_case_note_internal(case_id, db, author)
    return {"status": "ok", "id": act.id, "action_status": act.action_status}


@router.post("/{case_id}/playbooks/executions/{exec_id}/step/custom")
def add_custom_playbook_step(
    case_id: int,
    exec_id: int,
    payload: CustomPlaybookStepRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Agrega un paso personalizado dinámico a la ejecución del Playbook."""
    pe = db.query(CasePlaybookExecution).filter(
        CasePlaybookExecution.id == exec_id,
        CasePlaybookExecution.iris_case_id == case_id
    ).first()
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    from sqlalchemy.orm.attributes import flag_modified
    steps = list(pe.steps_state or [])
    next_order = (max([s.get("order", 0) for s in steps], default=0) + 1)

    new_step = {
        "order": next_order,
        "title": payload.title,
        "description": payload.description or "",
        "mandatory": payload.mandatory,
        "status": "pendiente",
        "observations": "",
        "suggested_action_type": payload.suggested_action_type,
        "is_custom": True,
        "updated_by": user.username if user else "SOC Analyst",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "case_action_id": None,
    }
    steps.append(new_step)
    pe.steps_state = steps
    flag_modified(pe, "steps_state")
    pe.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(pe)
    return {"status": "ok", "step": new_step, "steps_state": pe.steps_state}


@router.patch("/{case_id}/playbooks/executions/{exec_id}/step/{step_order}/omit")
def omit_playbook_step(
    case_id: int,
    exec_id: int,
    step_order: int,
    payload: OmitPlaybookStepRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Marca un paso como omitido justificando la razón obligatoria."""
    pe = db.query(CasePlaybookExecution).filter(
        CasePlaybookExecution.id == exec_id,
        CasePlaybookExecution.iris_case_id == case_id
    ).first()
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    from sqlalchemy.orm.attributes import flag_modified
    now = datetime.now(timezone.utc)
    username = user.username if user else "SOC Analyst"
    steps = list(pe.steps_state or [])
    found = False

    for s in steps:
        if s.get("order") == step_order:
            found = True
            s["status"] = "omitido"
            s["observations"] = f"Paso omitido por analista. Motivo: {payload.omission_reason}"
            s["omission_reason"] = payload.omission_reason
            s["updated_by"] = username
            s["updated_at"] = now.isoformat()
            break

    if not found:
        raise HTTPException(status_code=404, detail=f"Paso #{step_order} no encontrado.")

    pe.steps_state = steps
    flag_modified(pe, "steps_state")
    pe.updated_at = now
    db.commit()
    db.refresh(pe)
    return {"status": "ok", "steps_state": pe.steps_state}


@router.post("/{case_id}/playbooks/executions/{exec_id}/step/{step_order}/link-activity")
def link_activity_to_playbook_step(
    case_id: int,
    exec_id: int,
    step_order: int,
    payload: LinkActivityStepRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Vincula una actividad existente de la bitácora a un paso de playbook sin duplicar acciones."""
    act = db.query(CaseActivityLog).filter(
        CaseActivityLog.id == payload.activity_id,
        CaseActivityLog.iris_case_id == case_id
    ).first()
    if not act:
        raise HTTPException(status_code=404, detail="Actividad no encontrada.")

    pe = db.query(CasePlaybookExecution).filter(
        CasePlaybookExecution.id == exec_id,
        CasePlaybookExecution.iris_case_id == case_id
    ).first()
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    from sqlalchemy.orm.attributes import flag_modified
    now = datetime.now(timezone.utc)
    username = user.username if user else "SOC Analyst"

    act.playbook_execution_id = exec_id
    act.step_order = step_order
    act.updated_at = now

    steps = list(pe.steps_state or [])
    for s in steps:
        if s.get("order") == step_order:
            s["linked_activity_id"] = act.id
            s["status"] = "completado" if act.action_status in ("ejecutada", "verificada") or act.activity_type in ("accion", "evidencia") else "en_progreso"
            s["observations"] = f"Vinculado con bitácora #{act.id}: {act.title}"
            s["updated_by"] = username
            s["updated_at"] = now.isoformat()
            break

    pe.steps_state = steps
    flag_modified(pe, "steps_state")
    pe.updated_at = now
    db.commit()
    _auto_sync_case_note_internal(case_id, db, username)
    return {"status": "ok", "linked_activity_id": act.id, "step_order": step_order}


@router.post("/{case_id}/playbooks/executions/{exec_id}/step/{step_order}/unlink-activity")
def unlink_activity_from_playbook_step(
    case_id: int,
    exec_id: int,
    step_order: int,
    activity_id: Optional[int] = Query(None, description="ID de actividad específica a desvincular"),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Desvincula una actividad (o todas si no se especifica) de un paso del playbook."""
    pe = db.query(CasePlaybookExecution).filter(
        CasePlaybookExecution.id == exec_id,
        CasePlaybookExecution.iris_case_id == case_id
    ).first()
    if not pe:
        raise HTTPException(status_code=404, detail="Ejecución de Playbook no encontrada.")

    from sqlalchemy.orm.attributes import flag_modified
    now = datetime.now(timezone.utc)
    username = user.username if user else "SOC Analyst"

    query = db.query(CaseActivityLog).filter(
        CaseActivityLog.playbook_execution_id == exec_id,
        CaseActivityLog.step_order == step_order,
        CaseActivityLog.iris_case_id == case_id,
    )
    if activity_id is not None:
        query = query.filter(CaseActivityLog.id == activity_id)

    acts_to_unlink = query.all()
    for a in acts_to_unlink:
        a.playbook_execution_id = None
        a.step_order = None
        a.updated_at = now

    # Verificar si aún quedan otras actividades vinculadas al mismo paso
    remaining_acts = db.query(CaseActivityLog).filter(
        CaseActivityLog.playbook_execution_id == exec_id,
        CaseActivityLog.step_order == step_order,
        CaseActivityLog.iris_case_id == case_id,
    ).all()

    steps = list(pe.steps_state or [])
    for s in steps:
        if s.get("order") == step_order:
            if remaining_acts:
                # Aún quedan actividades vinculadas
                s["linked_activity_id"] = remaining_acts[0].id
                s["updated_by"] = username
                s["updated_at"] = now.isoformat()
            else:
                # No queda ninguna actividad vinculada -> restaurar a pendiente
                s["linked_activity_id"] = None
                s["status"] = "pendiente"
                s["observations"] = ""
                s["updated_by"] = username
                s["updated_at"] = now.isoformat()
            break

    pe.steps_state = steps
    flag_modified(pe, "steps_state")
    pe.updated_at = now
    db.commit()
    _auto_sync_case_note_internal(case_id, db, username)
    return {
        "status": "ok",
        "unlinked": True,
        "step_order": step_order,
        "unlinked_count": len(acts_to_unlink),
        "remaining_count": len(remaining_acts),
        "steps_state": pe.steps_state
    }


@router.delete("/{case_id}/activity/{activity_id}")
def delete_case_activity(
    case_id: int,
    activity_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Elimina una entrada de la bitácora operativa y desvincula de pasos de playbook si corresponde."""
    act = db.query(CaseActivityLog).filter(
        CaseActivityLog.id == activity_id,
        CaseActivityLog.iris_case_id == case_id,
    ).first()
    if not act:
        raise HTTPException(status_code=404, detail="Actividad no encontrada.")

    # Si estaba vinculada a un playbook, verificar el estado del paso
    if act.playbook_execution_id and act.step_order is not None:
        pe = db.query(CasePlaybookExecution).filter(CasePlaybookExecution.id == act.playbook_execution_id).first()
        if pe:
            remaining = db.query(CaseActivityLog).filter(
                CaseActivityLog.playbook_execution_id == act.playbook_execution_id,
                CaseActivityLog.step_order == act.step_order,
                CaseActivityLog.id != act.id,
            ).all()
            from sqlalchemy.orm.attributes import flag_modified
            steps = list(pe.steps_state or [])
            for s in steps:
                if s.get("order") == act.step_order:
                    if remaining:
                        s["linked_activity_id"] = remaining[0].id
                    else:
                        s["linked_activity_id"] = None
                        s["status"] = "pendiente"
                    break
            pe.steps_state = steps
            flag_modified(pe, "steps_state")

    log_audit_event(
        db,
        action="case.activity_deleted",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Eliminada actividad #{act.id} ({act.activity_type}: {act.title}).",
    )
    db.delete(act)
    db.commit()
    author = user.username if user else "SOC Analyst"
    _auto_sync_case_note_internal(case_id, db, author)
    return {"status": "ok", "deleted": True, "activity_id": activity_id}


@router.delete("/{case_id}/actions/{action_id}")
def delete_case_action(
    case_id: int,
    action_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Elimina una acción/tarea estructurada del caso."""
    action = db.query(CaseAction).filter(
        CaseAction.id == action_id,
        CaseAction.iris_case_id == case_id,
    ).first()
    if not action:
        raise HTTPException(status_code=404, detail="Acción no encontrada.")

    log_audit_event(
        db,
        action="case.action_deleted",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Eliminada acción #{action.id} ({action.action_type}: {action.title}).",
    )
    db.delete(action)
    db.commit()
    return {"status": "ok", "deleted": True, "action_id": action_id}


@router.post("/{case_id}/activity/bulk-delete")
def bulk_delete_case_activities(
    case_id: int,
    payload: BulkDeleteActivitiesRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Elimina múltiples entradas de la bitácora operativa en una sola transacción."""
    if not payload.activity_ids:
        return {"status": "ok", "deleted_count": 0}

    acts = db.query(CaseActivityLog).filter(
        CaseActivityLog.iris_case_id == case_id,
        CaseActivityLog.id.in_(payload.activity_ids),
    ).all()

    for act in acts:
        if act.playbook_execution_id and act.step_order is not None:
            pe = db.query(CasePlaybookExecution).filter(CasePlaybookExecution.id == act.playbook_execution_id).first()
            if pe:
                remaining = db.query(CaseActivityLog).filter(
                    CaseActivityLog.playbook_execution_id == act.playbook_execution_id,
                    CaseActivityLog.step_order == act.step_order,
                    ~CaseActivityLog.id.in_(payload.activity_ids),
                ).all()
                from sqlalchemy.orm.attributes import flag_modified
                steps = list(pe.steps_state or [])
                for s in steps:
                    if s.get("order") == act.step_order:
                        if remaining:
                            s["linked_activity_id"] = remaining[0].id
                        else:
                            s["linked_activity_id"] = None
                            s["status"] = "pendiente"
                        break
                pe.steps_state = steps
                flag_modified(pe, "steps_state")

        db.delete(act)

    log_audit_event(
        db,
        action="case.activities_bulk_deleted",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Eliminadas {len(acts)} actividades en lote (IDs: {payload.activity_ids}).",
    )
    db.commit()
    author = user.username if user else "SOC Analyst"
    _auto_sync_case_note_internal(case_id, db, author)
    return {"status": "ok", "deleted_count": len(acts)}


def _auto_sync_case_note_internal(case_id: int, db: Session, author_username: str = "SOC Analyst"):
    """Compila automáticamente la nota técnica integrada oficial en DFIR-IRIS tras cualquier cambio en bitácora."""
    try:
        activities = db.query(CaseActivityLog).filter(CaseActivityLog.iris_case_id == case_id).order_by(CaseActivityLog.created_at.asc()).all()
        ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()

        findings = [a for a in activities if a.activity_type == "investigacion"]
        evidences = [a for a in activities if a.activity_type == "evidencia"]
        actions = [a for a in activities if a.activity_type == "accion"]
        comms = [a for a in activities if a.activity_type == "comunicacion"]

        lines = []
        lines.append(f"# Ficha Técnica Operativa - Caso #{case_id}\n")
        if ext:
            lines.append("### Parámetros Operativos del Activo e Incidente")
            lines.append("| Parámetro | Valor Registrado | Parámetro | Valor Registrado |")
            lines.append("|---|---|---|---|")
            lines.append(f"| **Dominio / Activo** | `{ext.primary_domain or 'N/A'}` | **IP Hosting** | `{ext.hosting_ip or 'N/A'}` |")
            lines.append(f"| **Servidor Hosting** | `{ext.server_name or 'N/A'}` | **Categoría SOC** | `{ext.category_code or 'N/A'}` |")
            lines.append(f"| **Actividad Reportada** | {ext.reported_activity or 'N/A'} | **Incidente Confirmado** | `{ext.confirmed_incident_type or 'N/A'}` |")
            lines.append(f"| **Ticket Abuso** | #{ext.abuse_ticket_id or 'N/A'} | **ID Cliente / Serv.** | #{ext.client_id or 'N/A'} / #{ext.service_id or 'N/A'} |\n")

        lines.append("## 1. Separación Epistemológica y Hechos Confirmados")
        if not findings:
            lines.append("*Sin investigaciones técnicas adicionales registradas.*")
        for f in findings:
            lines.append(f"### {f.title}")
            if f.content:
                c = f.content.strip()
                if not c.startswith("```") and not c.startswith("<") and ("\n" in c or c.startswith("[root@") or c.startswith("$") or c.startswith("#") or "Size:" in c or "Inode:" in c):
                    lines.append(f"```bash\n{c}\n```\n")
                else:
                    lines.append(f"{c}\n")

        lines.append("\n## 2. Acciones y Medidas de Contención")
        if not actions:
            lines.append("*Sin acciones registradas.*")
        else:
            lines.append("| Acción | Estado | Responsable | Resultado |")
            lines.append("|---|---|---|---|")
            for a in actions:
                lines.append(f"| **{a.title}** | `{a.action_status or 'pendiente'}` | {a.analyst_username} | {a.content or '-'} |")

        lines.append("\n## 3. Evidencias Forenses en Datastore")
        if not evidences:
            lines.append("*Sin evidencias adjuntas.*")
        else:
            lines.append("| Archivo | SHA-256 | Datastore ID | Tamaño |")
            lines.append("|---|---|---|---|")
            for ev in evidences:
                meta = ev.metadata_json or {}
                fname = meta.get("filename", ev.title)
                sha = meta.get("sha256", "N/A")
                fid = meta.get("iris_file_id", ev.iris_evidence_id or "-")
                size = meta.get("file_size", 0)
                lines.append(f"| `{fname}` | `{sha}` | #{fid} | {size} bytes |")

        if comms:
            lines.append("\n## 4. Comunicaciones Registradas")
            lines.append("| Canal | Referencia | Resumen |")
            lines.append("|---|---|---|")
            for c in comms:
                meta = c.metadata_json or {}
                lines.append(f"| `{meta.get('channel', 'WHMCS')}` | {meta.get('ticket_ref', '-')} | {c.title} |")

        lines.append(f"\n> *Sincronización automática activa desde Bitácora SOC Abuse Sync v3.1 por {author_username}.*")
        compiled_md = "\n".join(lines)

        client = IrisApiClient()
        client.ensure_structured_note(
            case_id=case_id,
            directory_name="Documentación SOC v3.1",
            note_title=f"04 Ficha Operativa Integrada #{case_id}",
            note_content=compiled_md,
            update_if_exists=True,
        )
    except Exception as exc:
        logger.warning("Fallo en sincronización automática de nota técnica para caso #%s: %s", case_id, exc)


@router.get("/{case_id}/iocs")
def get_case_iocs(case_id: int):
    """Obtiene los Indicadores de Compromiso (IoCs) del caso registrados en DFIR-IRIS."""
    client = IrisApiClient()
    iocs = client.list_case_iocs(case_id)
    return {"status": "ok", "case_id": case_id, "iocs": iocs}


@router.post("/{case_id}/iocs")
def add_case_ioc(
    case_id: int,
    payload: CaseIocCreateRequest,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Registra un nuevo IoC en DFIR-IRIS."""
    client = IrisApiClient()
    res = client.ensure_ioc(
        case_id=case_id,
        value=payload.ioc_value,
        ioc_type=payload.ioc_type,
        description=payload.ioc_description,
        tags=payload.ioc_tags,
    )
    log_audit_event(
        db,
        action="case.ioc_added",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"IoC {payload.ioc_type}:{payload.ioc_value} registrado en IRIS.",
    )
    return {"status": "ok", "result": res}


@router.delete("/{case_id}/iocs/{ioc_id}")
def delete_case_ioc(
    case_id: int,
    ioc_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Elimina un IoC de DFIR-IRIS."""
    client = IrisApiClient()
    client._post(f"/case/ioc/delete/{ioc_id}?cid={case_id}")
    log_audit_event(
        db,
        action="case.ioc_deleted",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"IoC #{ioc_id} eliminado de IRIS.",
    )
    return {"status": "ok", "deleted": True, "ioc_id": ioc_id}


@router.post("/{case_id}/timeline/generate-ai")
def generate_case_timeline_ai(
    case_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Genera y publica automáticamente una línea de tiempo cronológica en DFIR-IRIS utilizando Gemini AI."""
    from app.ai.gemini_service import GeminiService
    activities = db.query(CaseActivityLog).filter(CaseActivityLog.iris_case_id == case_id).order_by(CaseActivityLog.created_at.asc()).all()
    ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
    client = IrisApiClient()

    context_data = {
        "case_id": case_id,
        "primary_domain": ext.primary_domain if ext else "N/A",
        "hosting_ip": ext.hosting_ip if ext else "N/A",
        "category_code": ext.category_code if ext else "abuse_phishing",
        "reported_activity": ext.reported_activity if ext else "N/A",
        "activities": [
            {
                "type": a.activity_type,
                "title": a.title,
                "content": (a.content or "")[:300],
                "created_at": a.created_at.isoformat() if a.created_at else "",
                "status": a.action_status,
            }
            for a in activities
        ],
    }

    instruction = (
        "Analiza los eventos del caso y genera una lista cronológica precisa de hitos para la línea de tiempo forense (Timeline). "
        "Cada hito debe tener: 'title' (título conciso del evento), 'content' (explicación técnica breve), y 'event_date' (formato ISO YYYY-MM-DDTHH:MM:SS)."
    )

    ai_res = GeminiService.assist_analyst_chat(db, instruction, context_data)
    created_events = []

    events_to_post = [
        {
            "title": f"01. Recepción y Triaje de Alerta ({ext.category_code if ext else 'Abuso'})",
            "content": f"Ingesta formal del reporte de abuso para {ext.primary_domain if ext else 'activo'}. Clasificación inicial completada.",
            "date": (ext.updated_at if ext and ext.updated_at else datetime.now(timezone.utc)).isoformat(),
        }
    ]

    for idx, act in enumerate(activities, 2):
        events_to_post.append({
            "title": f"{idx:02d}. [{act.activity_type.upper()}] {act.title}",
            "content": f"{act.content or act.title} (Registrado por {act.analyst_username})",
            "date": (act.created_at if act.created_at else datetime.now(timezone.utc)).isoformat(),
        })

    for ev in events_to_post:
        res = client.ensure_timeline_event(
            case_id=case_id,
            title=ev["title"],
            content=ev["content"],
            event_date_iso=ev["date"],
            category_id=5,
        )
        created_events.append(res)

    log_audit_event(
        db,
        action="case.timeline_ai_generated",
        module="cases",
        user=user,
        iris_case_id=case_id,
        details=f"Generada línea de tiempo con {len(created_events)} eventos en IRIS.",
    )
    return {"status": "ok", "events_synced": len(created_events), "ai_summary": ai_res.get("reply", "")}



@router.post("/{case_id}/compile-markdown-notes")
def compile_markdown_notes_from_activity(
    case_id: int,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Compila hechos técnicos confirmados, acciones y evidencias desde la bitácora unificada a la nota técnica de IRIS."""
    author = user.username if user else "SOC Analyst"
    _auto_sync_case_note_internal(case_id, db, author)
    return {
        "status": "ok",
        "message": "Nota oficial compilada y sincronizada automáticamente en DFIR-IRIS",
    }


