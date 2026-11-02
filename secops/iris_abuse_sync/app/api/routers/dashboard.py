from collections import Counter
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
import csv
import io

from app.core.database import get_db
from app.iris.client import IrisApiClient
from app.models.case_extended import AlertExtension, CaseExtension, CaseMigrationRecord, RblEpisode
from app.models.connector import ConnectorConfig, IngestEvent, JobQueue
from app.models.user import AuditLog

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    client = IrisApiClient()
    iris_status = client.check_connection()

    # 1. Alertas reales de DFIR-IRIS
    alerts_list = []
    alerts_total = 0
    try:
        if iris_status.get("ok"):
            a_resp = client.list_alerts(page=1, per_page=100)
            alerts_list = a_resp.get("alerts") or []
            alerts_total = int(a_resp.get("total") or len(alerts_list))
    except Exception:
        alerts_list = []

    pending_alerts = 0
    escalated_alerts = 0
    merged_alerts = 0
    closed_alerts = 0
    severity_counts = Counter({"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0})

    for a in alerts_list:
        st_id = a.get("alert_status_id")
        if st_id in (2, 3, 4, 5):  # New, Assigned, In progress, Pending
            pending_alerts += 1
        elif st_id == 8:
            escalated_alerts += 1
        elif st_id == 7:
            merged_alerts += 1
        elif st_id == 6:
            closed_alerts += 1

        sev_id = a.get("alert_severity_id")
        sev_map = {6: "Critical", 5: "High", 1: "Medium", 4: "Low", 3: "Informational"}
        sev_label = sev_map.get(sev_id, "Medium")
        severity_counts[sev_label] += 1

    # 2. Casos reales de DFIR-IRIS
    cases_list = []
    try:
        if iris_status.get("ok"):
            cases_list = client.list_cases()
    except Exception:
        cases_list = []

    open_cases = 0
    in_progress_cases = 0
    closed_cases = 0
    org_counts = Counter({"NBX": 0, "HP": 0})
    cat_counts = Counter()

    for c in cases_list:
        is_closed = bool(c.get("close_date")) or (c.get("state_name") or "").lower() == "closed"
        st_name = (c.get("state_name") or "Open").lower()
        if is_closed:
            closed_cases += 1
        elif st_name in ("in progress", "containment", "eradication", "recovery"):
            in_progress_cases += 1
            open_cases += 1
        else:
            open_cases += 1

        cname = c.get("case_name") or ""
        cl_name = (c.get("client_name") or "").lower()
        if "hospedando" in cl_name or "| hp-" in cname.lower():
            org_counts["HP"] += 1
        else:
            org_counts["NBX"] += 1

        if "[PHISH]" in cname:
            cat_counts["Phishing [PHISH]"] += 1
        elif "[SPAM]" in cname:
            cat_counts["Spam [SPAM]"] += 1
        elif "[COMP]" in cname:
            cat_counts["Web Comprometido [COMP]"] += 1
        elif "[BRAND]" in cname:
            cat_counts["Disputa Marca [BRAND]"] += 1
        elif "[AUTH]" in cname or "[FRAUD]" in cname:
            cat_counts["Autoridad / Fraude [AUTH]"] += 1
        elif "[ACCT]" in cname:
            cat_counts["Compromiso Cuenta [ACCT]"] += 1
        else:
            cat_counts["Otros Incidentes"] += 1

    # 3. Métricas de fuentes de ingesta, conectores, RBL y migración en PostgreSQL
    source_counts_rows = db.query(IngestEvent).all()
    source_counts = Counter(ev.source_type for ev in source_counts_rows)

    correlated_count = (
        db.query(AlertExtension)
        .filter(AlertExtension.correlated_case_ids_json != [])  # noqa: E711
        .count()
    )

    connectors = db.query(ConnectorConfig).order_by(ConnectorConfig.id.asc()).all()
    connectors_summary = [
        {
            "id": cn.id,
            "type": cn.connector_type,
            "name": cn.name,
            "is_enabled": cn.is_enabled,
            "status": cn.last_status,
            "last_sync_at": cn.last_sync_at.isoformat() if cn.last_sync_at else None,
            "last_error": cn.last_error,
        }
        for cn in connectors
    ]

    active_rbl = db.query(RblEpisode).filter(RblEpisode.status == "active").count()
    migrated_cases_count = (
        db.query(CaseMigrationRecord).filter(CaseMigrationRecord.status == "migrated").count()
    )
    pending_jobs = db.query(JobQueue).filter(JobQueue.status == "pending").count()

    recent_audit = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(12)
        .all()
    )

    iris_info = {
        **iris_status,
        "status": "online" if iris_status.get("ok") else "offline",
    }

    return {
        "status": "ok",
        "iris_connection": iris_info,
        "iris": iris_info,
        "kpis": {
            "alerts_total": alerts_total,
            "alerts_pending": pending_alerts,
            "alerts_escalated": escalated_alerts,
            "alerts_merged": merged_alerts,
            "alerts_closed": closed_alerts,
            "alerts_correlated": correlated_count + merged_alerts,
            "cases_total": len(cases_list),
            "cases_open": open_cases,
            "cases_in_progress": in_progress_cases,
            "cases_closed": closed_cases,
            "cases_migrated_v3": migrated_cases_count,
            "active_rbl_episodes": active_rbl,
            "pending_worker_jobs": pending_jobs,
        },
        "alerts": {
            "total": alerts_total,
            "pending": pending_alerts,
            "escalated": escalated_alerts,
            "merged": merged_alerts,
            "closed": closed_alerts,
        },
        "cases": {
            "total": len(cases_list),
            "open": open_cases,
            "in_progress": in_progress_cases,
            "closed": closed_cases,
            "by_org": dict(org_counts),
        },
        "active_episodes_count": active_rbl,
        "alerts_by_severity": dict(severity_counts),
        "cases_by_organization": dict(org_counts),
        "cases_by_category": dict(cat_counts),
        "reports_by_source": dict(source_counts),
        "connectors": connectors_summary,
        "recent_activity": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "username": log.username,
                "action": log.action,
                "module": log.module,
                "organization": log.organization,
                "iris_alert_id": log.iris_alert_id,
                "iris_case_id": log.iris_case_id,
                "details": log.details,
            }
            for log in recent_audit
        ],
    }


@router.get("/export.csv")
def export_metrics_csv(db: Session = Depends(get_db)):
    client = IrisApiClient()
    cases = []
    try:
        cases = client.list_cases()
    except Exception:
        cases = []

    exts = {e.iris_case_id: e for e in db.query(CaseExtension).all()}

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "case_id",
            "organization",
            "case_name",
            "state",
            "open_date",
            "close_date",
            "abuse_ticket_id",
            "holder_ticket_id",
            "client_id",
            "service_id",
            "primary_domain",
            "server_name",
            "reported_activity",
            "confirmed_incident_type",
            "entry_vector",
            "root_cause",
            "schema_version",
        ]
    )
    for c in cases:
        cid = c.get("case_id")
        ext = exts.get(cid)
        cname = c.get("case_name") or ""
        org = ext.organization if ext else ("HP" if "| hp-" in cname.lower() else "NBX")
        writer.writerow(
            [
                cid,
                org,
                cname,
                c.get("state_name") or ("Closed" if c.get("close_date") else "Open"),
                c.get("open_date") or "",
                c.get("close_date") or "",
                ext.abuse_ticket_id if ext else "",
                ext.holder_ticket_id if ext else "",
                ext.client_id if ext else "",
                ext.service_id if ext else "",
                ext.primary_domain if ext else "",
                ext.server_name if ext else "",
                ext.reported_activity if ext else "",
                ext.confirmed_incident_type if ext else "",
                ext.entry_vector if ext else "",
                ext.root_cause if ext else "",
                ext.schema_version if ext else "legacy_v2",
            ]
        )

    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=soc_cases_metrics_v3.csv"},
    )

