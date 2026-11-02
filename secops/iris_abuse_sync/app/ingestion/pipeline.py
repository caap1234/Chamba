from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.ai.gemini_service import GeminiService
from app.classification.correlation import CorrelationEngine
from app.classification.heuristic_engine import HeuristicClassifier
from app.classification.taxonomy import SEVERITY_NAME_TO_IRIS_ID, SOC_CATEGORIES
from app.ingestion.base import NormalizedIngestPayload
from app.ingestion.evidence_packager import EvidencePackageBuilder
from app.iris.client import IOC_TYPE_MAP, IrisApiClient
from app.models.case_extended import AlertExtension
from app.models.connector import IngestEvent


class IngestPipeline:
    """Pipeline principal SOC v3.0:
    Fuente -> Ingesta -> Evidencia SHA-256 -> Heurísticas + Gemini -> Correlación -> Alerta IRIS."""

    @classmethod
    def process_ingest(
        cls,
        db: Session,
        payload: NormalizedIngestPayload,
        *,
        raw_bytes: Optional[bytes] = None,
        original_filename: Optional[str] = None,
        extra_attachments: Optional[List[Tuple[str, bytes, str]]] = None,
        use_gemini: bool = True,
        create_iris_alert: bool = True,
        iris_client: Optional[IrisApiClient] = None,
    ) -> Dict[str, Any]:
        # 1. Clave de idempotencia única por fuente + instancia + ID
        idem_key = f"{payload.source_type}:{payload.source_instance}:{payload.source_id}:{payload.organization}"
        existing_event = db.query(IngestEvent).filter(IngestEvent.idempotency_key == idem_key).first()

        # 2. Construir Paquete de Evidencia Inicial con SHA-256
        pkg_info = EvidencePackageBuilder.build_package(
            payload=payload,
            raw_bytes=raw_bytes,
            original_filename=original_filename,
            extra_attachments=extra_attachments,
        )

        # 3. Clasificación Heurística + Enriquecimiento con Google Gemini
        heur = HeuristicClassifier.evaluate(payload)
        ai_res = (
            GeminiService.analyze_ingest_payload(db, payload, heur)
            if use_gemini
            else {"ai_used": False, "analysis": GeminiService._build_fallback_analysis(payload, heur)}
        )
        analysis = ai_res.get("analysis") or {}

        # Determinar provenance campo por campo ("rule" vs "ai")
        provenance = dict(payload.field_provenance or {})
        for k in ("reported_activity", "confirmed_incident_type", "entry_vector", "root_cause", "category_code", "severity"):
            if ai_res.get("ai_used") and analysis.get(k) and analysis.get(k) != heur.get(k):
                provenance[k] = "ai"
            else:
                provenance[k] = "rule"

        final_cat_code = analysis.get("category_code") or heur["category_code"]
        cat_meta = SOC_CATEGORIES.get(final_cat_code, SOC_CATEGORIES["abuse_phishing"])
        final_severity = analysis.get("severity") or heur["severity"]
        iris_severity_id = SEVERITY_NAME_TO_IRIS_ID.get(final_severity, cat_meta["iris_severity_id"])

        ticket_label = payload.abuse_ticket_id or payload.source_id or "S/N"
        domain_label = payload.primary_domain or payload.reported_ip or "activo-desconocido"
        alert_title = f"{cat_meta['tag']} {domain_label} | {payload.organization}-{ticket_label}"

        # 4. Correlación contra alertas y casos existentes
        client = iris_client or IrisApiClient()
        live_cases = []
        try:
            if create_iris_alert:
                live_cases = client.list_cases()
        except Exception:
            live_cases = []

        corr = CorrelationEngine.find_correlations(db, payload, live_iris_cases=live_cases)

        # 5. Registrar o actualizar IngestEvent en PostgreSQL
        if not existing_event:
            existing_event = IngestEvent(
                idempotency_key=idem_key,
                source_type=payload.source_type,
                source_instance=payload.source_instance,
                source_id=payload.source_id,
                organization=payload.organization,
            )
            db.add(existing_event)
            db.flush()

        existing_event.reporter = payload.reporter
        existing_event.subject = alert_title
        existing_event.original_content = payload.original_content
        existing_event.attachments_json = [a.model_dump() for a in payload.attachments]
        existing_event.external_reference = payload.external_reference
        existing_event.source_url = payload.source_url
        existing_event.raw_metadata_json = payload.raw_metadata
        existing_event.normalized_payload_json = payload.model_dump(mode="json")
        existing_event.evidence_package_path = pkg_info["package_dir"]
        existing_event.evidence_sha256 = pkg_info["primary_sha256"]

        # 6. Crear Alerta en DFIR-IRIS (/alerts/add) si corresponde
        iris_alert_id = existing_event.iris_alert_id
        iris_alert_data = None
        customer_id = 3 if payload.organization.upper() == "HP" else 2

        alert_desc_lines = [
            f"### Resumen Ejecutivo SOC ({payload.organization})",
            analysis.get("executive_summary") or payload.report_summary,
            "",
            "### Identificación Extraída",
            f"- **Fuente**: `{payload.source_type}` | **Ticket**: `{payload.abuse_ticket_id or 'N/A'}`",
            f"- **Reportante**: {payload.reporter} (`{payload.reporter_type}`)",
            f"- **Dominio Primario**: `{payload.primary_domain or 'N/A'}`",
            f"- **Marca Suplantada (Referencia)**: `{payload.impersonated_brand or 'N/A'}`",
            f"- **Servidor**: `{payload.server_name or 'N/A'}` | **IP Hosting**: `{payload.hosting_ip or 'N/A'}` | **IP Reportada**: `{payload.reported_ip or 'N/A'}`",
            f"- **ID Cliente**: `{payload.client_id or 'N/A'}` | **ID Servicio**: `{payload.service_id or 'N/A'}`",
            f"- **SHA-256 Evidencia Inicial**: `{pkg_info['primary_sha256']}`",
            "",
            "### Clasificación Propuesta (4 Ejes)",
            f"- **Actividad Reportada**: `{analysis.get('reported_activity') or heur['reported_activity']}`",
            f"- **Incidente Confirmado**: `{analysis.get('confirmed_incident_type') or heur['confirmed_incident_type']}`",
            f"- **Vector de Entrada**: `{analysis.get('entry_vector') or heur['entry_vector']}`",
            f"- **Causa Raíz**: `{analysis.get('root_cause') or heur['root_cause']}`",
        ]
        if corr["reasons"]:
            alert_desc_lines.append("\n### Correlaciones Detectadas")
            for r_str in corr["reasons"]:
                alert_desc_lines.append(f"- {r_str}")

        alert_description = "\n".join(alert_desc_lines)

        if create_iris_alert and not iris_alert_id:
            iris_iocs = [
                {
                    "ioc_value": ind.value,
                    "ioc_description": ind.description,
                    "ioc_tlp_id": ind.tlp_id,
                    "ioc_type_id": IOC_TYPE_MAP.get(ind.ioc_type, 20),
                    "ioc_tags": f"abuse,{ind.role},{ind.provenance}",
                }
                for ind in payload.indicators
                if ind.is_affected_asset
            ]
            try:
                iris_alert_data = client.create_alert(
                    title=alert_title,
                    description=alert_description,
                    customer_id=customer_id,
                    severity_id=iris_severity_id,
                    status_id=2,  # New
                    classification_id=cat_meta["iris_classification_id"],
                    source=f"SOC v3.0 ({payload.source_type})",
                    source_ref=str(payload.abuse_ticket_id or payload.source_id),
                    source_link=payload.source_url or "",
                    source_content={
                        "sha256": pkg_info["primary_sha256"],
                        "organization": payload.organization,
                        "indicators_by_role": payload.indicators_by_role,
                    },
                    tags=f"abuse,{payload.organization.lower()},{final_cat_code}",
                    iocs=iris_iocs,
                    context={
                        "abuse_ticket_id": payload.abuse_ticket_id,
                        "holder_ticket_id": payload.holder_ticket_id,
                        "client_id": payload.client_id,
                        "service_id": payload.service_id,
                        "server_name": payload.server_name,
                        "evidence_sha256": pkg_info["primary_sha256"],
                    },
                )
                iris_alert_id = iris_alert_data.get("alert_id")
                existing_event.iris_alert_id = iris_alert_id
                existing_event.processing_status = "alert_created"
            except Exception as exc:
                existing_event.processing_status = "failed"
                existing_event.error_message = str(exc)[:500]
        else:
            existing_event.processing_status = "alert_created" if iris_alert_id else "normalized"

        # 7. Guardar o actualizar AlertExtension en PostgreSQL
        if iris_alert_id:
            a_ext = db.query(AlertExtension).filter(AlertExtension.iris_alert_id == iris_alert_id).first()
            if not a_ext:
                a_ext = AlertExtension(iris_alert_id=iris_alert_id)
                db.add(a_ext)

            a_ext.ingest_event_id = existing_event.id
            a_ext.organization = payload.organization
            a_ext.source_type = payload.source_type
            a_ext.abuse_ticket_id = payload.abuse_ticket_id
            a_ext.primary_domain = payload.primary_domain
            a_ext.reported_ip = payload.reported_ip
            a_ext.hosting_ip = payload.hosting_ip
            a_ext.server_name = payload.server_name
            a_ext.reported_activity = analysis.get("reported_activity") or heur["reported_activity"]
            a_ext.confirmed_incident_type = analysis.get("confirmed_incident_type") or heur["confirmed_incident_type"]
            a_ext.entry_vector = analysis.get("entry_vector") or heur["entry_vector"]
            a_ext.root_cause = analysis.get("root_cause") or heur["root_cause"]
            a_ext.category_code = final_cat_code
            a_ext.severity = final_severity
            a_ext.confidence_score = int(analysis.get("confidence_score") or heur["confidence_score"])
            a_ext.heuristic_result_json = heur
            a_ext.gemini_result_json = ai_res
            a_ext.field_provenance_json = provenance
            a_ext.indicators_by_role_json = payload.indicators_by_role
            a_ext.verification_state = heur.get("verification_state", "pendiente")
            a_ext.correlated_alert_ids_json = [aid for aid in corr["correlated_alert_ids"] if aid != iris_alert_id]
            a_ext.correlated_case_ids_json = corr["correlated_case_ids"]

        db.commit()

        return {
            "status": existing_event.processing_status,
            "ingest_event_id": existing_event.id,
            "iris_alert_id": iris_alert_id,
            "alert_title": alert_title,
            "organization": payload.organization,
            "customer_id": customer_id,
            "evidence_package": pkg_info,
            "normalized": payload.model_dump(mode="json"),
            "heuristics": heur,
            "gemini": ai_res,
            "field_provenance": provenance,
            "correlations": corr,
        }

