from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.ai.gemini_service import GeminiService
from app.classification.heuristic_engine import HeuristicClassifier
from app.classification.taxonomy import SOC_CATEGORIES, VALID_ACTION_STATUS_CODES
from app.core.config import settings
from app.ingestion.normalizer import ReportNormalizer
from app.iris.client import IrisApiClient
from app.models.case_extended import (
    CaseAction,
    CaseCommunication,
    CaseExtension,
    CaseFinding,
    CaseInvestigation,
    CaseMigrationRecord,
)


class LegacyCaseMigrator:
    """Subsistema de migración controlada, previsualización (Dry-Run) y normalización de casos históricos."""

    CURRENT_SCHEMA_VERSION = "3.0"

    @classmethod
    def scan_historical_cases(cls, db: Session, iris_client: Optional[IrisApiClient] = None) -> List[Dict[str, Any]]:
        """Consulta los casos existentes en DFIR-IRIS y devuelve su estado de migración hacia v3.0."""
        client = iris_client or IrisApiClient()
        live_cases = client.list_cases()
        results: List[Dict[str, Any]] = []

        for c in live_cases:
            cid = c.get("case_id")
            if not cid:
                continue
            cname = c.get("case_name") or f"Case #{cid}"
            cname_clean = re.sub(r"^#\d+\s*-\s*", "", cname)
            client_name = (c.get("client_name") or "").lower()
            org = "HP" if "hospedando" in client_name or "| hp-" in cname.lower() else "NBX"

            rec = db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == cid).first()
            ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == cid).first()

            status = rec.status if rec else ("migrated" if ext and ext.schema_version == cls.CURRENT_SCHEMA_VERSION else "pending")
            results.append(
                {
                    "case_id": cid,
                    "case_name": cname_clean,
                    "organization": org,
                    "state_name": c.get("state_name") or ("Closed" if c.get("close_date") else "Open"),
                    "open_date": c.get("open_date"),
                    "close_date": c.get("close_date"),
                    "migration_status": status,
                    "schema_version": ext.schema_version if ext else "legacy_v2",
                    "snapshot_taken": bool(rec and rec.snapshot_sha256),
                    "snapshot_sha256": rec.snapshot_sha256 if rec else None,
                    "reviewed_by": rec.reviewed_by if rec else None,
                    "executed_at": rec.executed_at.isoformat() if rec and rec.executed_at else None,
                }
            )
        return results

    @classmethod
    def generate_preview_and_snapshot(
        cls,
        db: Session,
        case_id: int,
        *,
        use_gemini: bool = True,
        iris_client: Optional[IrisApiClient] = None,
    ) -> Dict[str, Any]:
        """Paso 1..5: Toma snapshot inmutable del caso en IRIS, interpreta notas antiguas sin inventar
        compromisos y genera el reporte comparativo (Dry-Run) antes de aplicar cualquier cambio."""
        client = iris_client or IrisApiClient()
        full_case = client.get_case_full(case_id)
        if not full_case or not full_case.get("case_id"):
            raise ValueError(f"No se encontró el caso #{case_id} en DFIR-IRIS.")

        # 1. Guardar Snapshot inmutable en disco y en BD
        now = datetime.now(timezone.utc)
        snapshot_bytes = json.dumps(full_case, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        snapshot_sha = hashlib.sha256(snapshot_bytes).hexdigest()
        backup_file = settings.MIGRATION_BACKUP_DIR / f"case_{case_id}_snapshot_{now.strftime('%Y%m%d_%H%M%S')}.json"
        backup_file.write_bytes(snapshot_bytes)

        # 2. Extraer y consolidar contenido original (resumen, las 3 notas clásicas, custom_attributes e IOCs)
        cname = re.sub(r"^#\d+\s*-\s*", "", full_case.get("case_name") or "")
        desc = full_case.get("case_description") or ""
        notes = full_case.get("notes") or []
        custom_attrs = full_case.get("custom_attributes") or {}
        ident_attrs = (custom_attrs.get("01 Identificación") or {}) if isinstance(custom_attrs, dict) else {}

        notes_concat = "\n\n".join(
            f"=== NOTA: {n.get('note_title')} ===\n{n.get('note_content') or ''}" for n in notes
        )
        combined_legacy_text = f"TÍTULO: {cname}\n\nRESUMEN:\n{desc}\n\n{notes_concat}"

        client_str = str(full_case.get("case_customer") or full_case.get("client_name") or "").lower()
        org = "HP" if client_str in ("3", "hospedando") or "| hp-" in cname.lower() else "NBX"

        # 3. Parsear con ReportNormalizer + regex específicos de las 3 notas v2
        norm_payload = ReportNormalizer.normalize_text(
            text=combined_legacy_text,
            filename=f"legacy_case_{case_id}.txt",
            organization=org,
            source_type="legacy_iris_case",
            subject_override=cname,
        )

        # Enriquecer con atributos explícitos de IRIS y de las notas v2
        def _val_attr(field_dict: Any) -> Optional[str]:
            if isinstance(field_dict, dict):
                v = field_dict.get("value")
                return str(v).strip() if v else None
            return None

        attr_ticket = _val_attr(ident_attrs.get("Ticket de abuso"))
        attr_domain = _val_attr(ident_attrs.get("Dominio o activo reportado"))
        attr_ip = _val_attr(ident_attrs.get("IP reportada"))
        attr_holder = _val_attr(ident_attrs.get("Ticket del titular"))

        m_title = re.match(
            r"^(?:\[([A-Z]+)\]\s*)?([^\s|]+)\s*\|\s*(NBX|HP)-([A-Za-z0-9_-]+)",
            cname,
            re.IGNORECASE,
        )
        title_tag = m_title.group(1).upper() if m_title and m_title.group(1) else None
        title_dom = m_title.group(2).strip() if m_title else None
        title_org = m_title.group(3).upper() if m_title else None
        title_tkt = m_title.group(4).strip() if m_title else None

        if title_org in ("NBX", "HP"):
            norm_payload.organization = title_org
            org = title_org

        norm_payload.abuse_ticket_id = attr_ticket or title_tkt or norm_payload.abuse_ticket_id
        norm_payload.primary_domain = attr_domain or title_dom or norm_payload.primary_domain
        norm_payload.reported_ip = attr_ip or norm_payload.reported_ip
        norm_payload.holder_ticket_id = attr_holder or norm_payload.holder_ticket_id

        # Buscar ID del cliente, ID del servicio, Servidor y Ticket del titular en las notas antiguas
        m_cid = re.search(r"ID\s+(?:del\s+)?cliente:\s*#?([A-Za-z0-9_-]+)", combined_legacy_text, re.IGNORECASE)
        m_sid = re.search(r"ID\s+(?:del\s+)?servicio:\s*#?([A-Za-z0-9_-]+)", combined_legacy_text, re.IGNORECASE)
        m_srv = re.search(
            r"(?:Servidor(?:\s+Neubox)?|Alojado\s+en\s+servidor):\s*([A-Za-z0-9._-]+)",
            combined_legacy_text,
            re.IGNORECASE,
        )
        m_hld = re.search(
            r"Ticket\s+del\s+titular(?:\s*\([^)]*\))?:\s*#?([A-Za-z0-9_-]+)",
            combined_legacy_text,
            re.IGNORECASE,
        )
        if m_cid and not norm_payload.client_id:
            norm_payload.client_id = m_cid.group(1)
        if m_sid and not norm_payload.service_id:
            norm_payload.service_id = m_sid.group(1)
        if m_srv and not norm_payload.server_name:
            norm_payload.server_name = m_srv.group(1)
        if m_hld and not norm_payload.holder_ticket_id:
            norm_payload.holder_ticket_id = m_hld.group(1)

        # Extraer resumen limpio del reporte original desde las notas v2
        m_rep_desc = re.search(
            r"(?:Descripci[óo]n\s+breve\s+del\s+reporte|-\s*Reporte):\s*([^\n]+)",
            combined_legacy_text,
            re.IGNORECASE,
        )
        if m_rep_desc:
            clean_rep = m_rep_desc.group(1).strip()
            if clean_rep and len(clean_rep) > 8:
                norm_payload.report_summary = clean_rep

        m_hallazgo = re.search(
            r"(?:-\s*Hallazgo|-\s*Se\s+encontr[óo]):\s*([^\n]+)",
            combined_legacy_text,
            re.IGNORECASE,
        )
        confirmed_facts_text = (
            m_hallazgo.group(1).strip()
            if m_hallazgo
            else "Datos técnicos extraídos de las notas originales del caso."
        )

        # Revisar también si ya existe un CaseExtension con ediciones manuales previas (Regla 12: no sobrescribir ediciones manuales)
        existing_ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
        preserved_manual_fields: Dict[str, Any] = {}
        if existing_ext and isinstance(existing_ext.field_provenance_json, dict):
            for f_key, prov in existing_ext.field_provenance_json.items():
                if prov == "manual" and hasattr(existing_ext, f_key):
                    val = getattr(existing_ext, f_key)
                    if val is not None and val != "":
                        preserved_manual_fields[f_key] = val

        # 4. Clasificación heurística + interpretación epistemológica de las 3 notas antiguas
        heur = HeuristicClassifier.evaluate(norm_payload)
        if title_tag:
            for cat_code, cat_meta in SOC_CATEGORIES.items():
                if cat_meta["tag"].strip("[]").upper() == title_tag:
                    heur["category_code"] = cat_code
                    heur["tag"] = cat_meta["tag"]
                    heur["category_name"] = cat_meta["name"]
                    heur["iris_classification_id"] = cat_meta["iris_classification_id"]
                    heur["reported_activity"] = cat_meta["default_reported_activity"]
                    break

        # Analizar el estado documentado en Nota 02 y Nota 03 para NO dar por confirmado lo que esté "Pendiente"
        is_pending_eval = bool(
            re.search(
                r"Evaluaci[óo]n[^:\n]*:\s*Pendiente|Pendiente de confirmaci[óo]n|Pendiente de investigaci[óo]n|bajo investigaci[óo]n",
                combined_legacy_text,
                re.IGNORECASE,
            )
        )
        is_uncorroborated = bool(
            re.search(
                r"Evaluaci[óo]n[^:\n]*:\s*no\s+corroborado|no\s+hemos\s+identificado\s+contenido|sin\s+evidencia\s+de\s+compromiso",
                combined_legacy_text,
                re.IGNORECASE,
            )
        )
        if is_uncorroborated:
            heur["verification_state"] = "no_corroborado"
            heur["is_technical_compromise"] = False
            if heur["category_code"] == "brand_dispute":
                heur["confirmed_incident_type"] = "brand_dispute_no_abuse"
            else:
                heur["confirmed_incident_type"] = "uncorroborated_allegation"
            heur["entry_vector"] = "not_applicable"
        elif is_pending_eval and not norm_payload.analyst_actions_detected:
            heur["verification_state"] = "pendiente"
            heur["confirmed_incident_type"] = "pending_investigation"
            heur["is_technical_compromise"] = False

        # Extraer decisiones/acciones reales documentadas en Nota 03 ("03 Acciones y resolución")
        legacy_actions: List[Dict[str, Any]] = []
        m_dec = re.search(r"Decisi[óo]n y motivo:\s*([^\n]+)", combined_legacy_text, re.IGNORECASE)
        m_act = re.search(r"Acci[óo]n ejecutada \(o pendiente\):\s*([^\n]+)", combined_legacy_text, re.IGNORECASE)
        if m_act:
            act_txt = m_act.group(1).strip()
            act_status = "pendiente" if "pendiente" in act_txt.lower() or "según proceda" in act_txt.lower() else "ejecutada"
            legacy_actions.append(
                {
                    "action_type": "notificacion_cliente" if "notifica" in act_txt.lower() else "suspension_servicio",
                    "title": act_txt[:220],
                    "status": act_status,
                    "result_notes": m_dec.group(1).strip() if m_dec else "Extraído de 03 Acciones y resolución",
                    "provenance": "rule",
                }
            )
        for p_act in heur.get("proposed_actions", []):
            if not any(la["action_type"] == p_act["action_type"] for la in legacy_actions):
                legacy_actions.append(p_act)

        # 5. Enriquecimiento opcional con Gemini (si está habilitado)
        ai_res = (
            GeminiService.analyze_ingest_payload(db, norm_payload, heur)
            if use_gemini
            else {"ai_used": False, "analysis": GeminiService._build_fallback_analysis(norm_payload, heur)}
        )
        analysis = ai_res["analysis"]

        # Construir propuesta normalizada respetando campos manuales previos
        proposed = {
            "iris_case_id": case_id,
            "case_name": cname,
            "organization": preserved_manual_fields.get("organization") or org,
            "customer_id": 3 if (preserved_manual_fields.get("organization") or org) == "HP" else 2,
            "abuse_ticket_id": preserved_manual_fields.get("abuse_ticket_id") or norm_payload.abuse_ticket_id,
            "holder_ticket_id": preserved_manual_fields.get("holder_ticket_id") or norm_payload.holder_ticket_id,
            "client_id": preserved_manual_fields.get("client_id") or norm_payload.client_id,
            "service_id": preserved_manual_fields.get("service_id") or norm_payload.service_id,
            "primary_domain": preserved_manual_fields.get("primary_domain") or norm_payload.primary_domain,
            "server_name": preserved_manual_fields.get("server_name") or norm_payload.server_name,
            "hosting_ip": preserved_manual_fields.get("hosting_ip") or norm_payload.hosting_ip,
            "reported_ip": preserved_manual_fields.get("reported_ip") or norm_payload.reported_ip,
            "impersonated_brand": preserved_manual_fields.get("impersonated_brand") or norm_payload.impersonated_brand,
            "reporter_name": norm_payload.reporter,
            "category_code": preserved_manual_fields.get("category_code") or analysis.get("category_code") or heur["category_code"],
            "reported_activity": preserved_manual_fields.get("reported_activity") or heur["reported_activity"],
            "confirmed_incident_type": preserved_manual_fields.get("confirmed_incident_type") or heur["confirmed_incident_type"],
            "entry_vector": preserved_manual_fields.get("entry_vector") or heur["entry_vector"],
            "root_cause": preserved_manual_fields.get("root_cause") or heur["root_cause"],
            "verification_state": preserved_manual_fields.get("verification_state") or heur["verification_state"],
            "severity": preserved_manual_fields.get("severity") or heur["severity"],
            "is_technical_compromise": heur["is_technical_compromise"],
            "epistemological_breakdown": {
                "reported_information": (
                    analysis.get("reported_claims_summary")
                    if ai_res.get("ai_used")
                    else norm_payload.report_summary
                ),
                "confirmed_facts": (
                    analysis.get("confirmed_facts_summary")
                    if ai_res.get("ai_used")
                    else confirmed_facts_text
                ),
                "technical_indicators": [i.model_dump() for i in norm_payload.indicators],
                "executed_actions": [a for a in legacy_actions if a["status"] in ("ejecutada", "verificada")],
                "pending_or_proposed_actions": [a for a in legacy_actions if a["status"] not in ("ejecutada", "verificada")],
                "conclusions": analysis.get("conclusion") or (m_dec.group(1).strip() if m_dec else "En seguimiento."),
            },
            "investigations": [
                {
                    "source_consulted": "Notas históricas DFIR-IRIS (01 y 02)",
                    "commands_or_queries": "Revisión de reporte original y bloque Bastion/Helpdesk",
                    "results_observed": confirmed_facts_text,
                    "fact_type": "confirmed_fact" if not is_pending_eval else "reported_claim",
                    "provenance": "ai" if ai_res.get("ai_used") else "rule",
                }
            ],
            "findings": heur.get("proposed_findings", []),
            "actions": legacy_actions,
            "preserved_manual_fields": list(preserved_manual_fields.keys()),
            "ai_used": ai_res.get("ai_used", False),
        }

        # 6. Calcular resumen de diferencias (Dry-Run) contra lo que ya tiene IRIS
        existing_iocs_vals = {(i.get("ioc_value") or "").lower() for i in (full_case.get("iocs") or [])}
        existing_tasks_titles = {(t.get("task_title") or "").lower() for t in (full_case.get("tasks") or [])}
        existing_assets_names = {(a.get("asset_name") or "").lower() for a in (full_case.get("assets") or [])}

        new_iocs_to_add = [
            i.model_dump()
            for i in norm_payload.indicators
            if i.value.lower() not in existing_iocs_vals
        ]
        new_tasks_to_add = [
            a
            for a in legacy_actions
            if a["title"].lower() not in existing_tasks_titles
        ]
        new_assets_to_add = []
        if proposed["server_name"] and proposed["server_name"].lower() not in existing_assets_names:
            new_assets_to_add.append({"asset_name": proposed["server_name"], "type": "linux_server"})

        dry_run_report = {
            "case_id": case_id,
            "snapshot_file": str(backup_file),
            "snapshot_sha256": snapshot_sha,
            "original_notes_preserved_count": len(notes),
            "original_evidences_preserved_count": len(full_case.get("evidences") or []),
            "existing_iocs_count": len(existing_iocs_vals),
            "new_iocs_to_sync": new_iocs_to_add,
            "existing_tasks_count": len(existing_tasks_titles),
            "new_tasks_to_sync": new_tasks_to_add,
            "new_assets_to_sync": new_assets_to_add,
            "structured_note_to_create_or_update": "04 Documentación Estructurada SOC v3.0 (Normalizada)",
            "destructive_operations": 0,
        }

        # 7. Persistir registro de migración en estado preview_ready
        rec = db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == case_id).first()
        if not rec:
            rec = CaseMigrationRecord(
                iris_case_id=case_id,
                case_name=cname,
                organization=org,
                schema_version_target=cls.CURRENT_SCHEMA_VERSION,
            )
            db.add(rec)

        rec.status = "preview_ready"
        rec.snapshot_sha256 = snapshot_sha
        rec.snapshot_file_path = str(backup_file)
        rec.original_snapshot_json = {
            "case_id": case_id,
            "case_name": cname,
            "case_description": desc,
            "custom_attributes": custom_attrs,
            "notes": notes,
            "iocs": full_case.get("iocs") or [],
            "assets": full_case.get("assets") or [],
            "tasks": full_case.get("tasks") or [],
            "evidences": full_case.get("evidences") or [],
        }
        rec.proposed_normalized_json = proposed
        rec.dry_run_report_json = dry_run_report
        rec.sync_diff_summary_json = {
            "new_iocs": len(new_iocs_to_add),
            "new_tasks": len(new_tasks_to_add),
            "new_assets": len(new_assets_to_add),
        }
        db.commit()
        db.refresh(rec)

        return {
            "case_id": case_id,
            "status": rec.status,
            "snapshot_sha256": snapshot_sha,
            "original": rec.original_snapshot_json,
            "proposed": proposed,
            "dry_run": dry_run_report,
        }

    @classmethod
    def approve_and_execute_single_case(
        cls,
        db: Session,
        case_id: int,
        *,
        reviewed_data: Optional[Dict[str, Any]] = None,
        sync_to_iris: bool = True,
        username: str = "admin",
        iris_client: Optional[IrisApiClient] = None,
    ) -> Dict[str, Any]:
        """Paso 6..12: Aplica la migración aprobada para UN caso individual de forma idempotente,
        guardando la estructura normalizada en PostgreSQL y sincronizando elementos nuevos con IRIS
        sin eliminar ni sobrescribir las 3 notas originales ni las evidencias."""
        rec = db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == case_id).first()
        if not rec or not rec.proposed_normalized_json:
            # Si aún no tenía preview, generarlo primero con su snapshot obligatorio
            cls.generate_preview_and_snapshot(db, case_id, use_gemini=False, iris_client=iris_client)
            rec = db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == case_id).first()

        final_data = dict(rec.proposed_normalized_json or {})
        manual_overrides: Dict[str, str] = {}
        if reviewed_data and isinstance(reviewed_data, dict):
            for k, v in reviewed_data.items():
                if v is not None and final_data.get(k) != v:
                    final_data[k] = v
                    manual_overrides[k] = "manual"
            rec.analyst_reviewed_json = reviewed_data

        now = datetime.now(timezone.utc)
        rec.reviewed_by = username
        rec.reviewed_at = now
        rec.status = "approved"

        # 1. Guardar / Actualizar CaseExtension de forma idempotente y respetando provenance manual
        ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == case_id).first()
        if not ext:
            ext = CaseExtension(iris_case_id=case_id)
            db.add(ext)
            db.flush()

        prov_map = dict(ext.field_provenance_json or {})
        prov_map.update(manual_overrides)

        editable_fields = [
            "organization",
            "customer_id",
            "abuse_ticket_id",
            "holder_ticket_id",
            "client_id",
            "service_id",
            "primary_domain",
            "server_name",
            "hosting_ip",
            "reported_ip",
            "impersonated_brand",
            "reporter_name",
            "category_code",
            "reported_activity",
            "confirmed_incident_type",
            "entry_vector",
            "root_cause",
            "verification_state",
            "severity",
            "is_technical_compromise",
        ]
        for fld in editable_fields:
            if prov_map.get(fld) == "manual" and fld not in manual_overrides:
                # Preservar edición manual previa
                continue
            if fld in final_data and final_data[fld] is not None:
                setattr(ext, fld, final_data[fld])
                if fld not in prov_map:
                    prov_map[fld] = "ai" if final_data.get("ai_used") else "rule"

        ext.schema_version = cls.CURRENT_SCHEMA_VERSION
        ext.field_provenance_json = prov_map
        ext.resolution_data_json = final_data.get("epistemological_breakdown") or {}

        # 2. Guardar investigaciones, hallazgos y acciones en PostgreSQL sin duplicar
        existing_findings = {
            f.title.strip().lower()
            for f in db.query(CaseFinding).filter(CaseFinding.iris_case_id == case_id).all()
        }
        for f_item in final_data.get("findings") or []:
            t_clean = (f_item.get("title") or "").strip()
            if t_clean and t_clean.lower() not in existing_findings:
                db.add(
                    CaseFinding(
                        iris_case_id=case_id,
                        title=t_clean,
                        description=f_item.get("description") or "",
                        finding_nature=f_item.get("finding_nature", "reported_allegation"),
                        verification_state=f_item.get("verification_state", "indicio"),
                        severity=f_item.get("severity", "Medium"),
                        provenance=f_item.get("provenance", "rule"),
                        created_by=username,
                    )
                )
                existing_findings.add(t_clean.lower())

        existing_actions = {
            a.title.strip().lower()
            for a in db.query(CaseAction).filter(CaseAction.iris_case_id == case_id).all()
        }
        for a_item in final_data.get("actions") or []:
            t_clean = (a_item.get("title") or "").strip()
            st = a_item.get("status", "pendiente")
            if st not in VALID_ACTION_STATUS_CODES:
                st = "pendiente"
            if t_clean and t_clean.lower() not in existing_actions:
                db.add(
                    CaseAction(
                        iris_case_id=case_id,
                        action_type=a_item.get("action_type", "general"),
                        title=t_clean,
                        status=st,
                        responsible=username,
                        result_notes=a_item.get("result_notes", ""),
                        provenance=a_item.get("provenance", "rule"),
                    )
                )
                existing_actions.add(t_clean.lower())

        existing_inv = db.query(CaseInvestigation).filter(CaseInvestigation.iris_case_id == case_id).count()
        if existing_inv == 0:
            for inv in final_data.get("investigations") or []:
                db.add(
                    CaseInvestigation(
                        iris_case_id=case_id,
                        source_consulted=inv.get("source_consulted", "Notas históricas IRIS"),
                        commands_or_queries=inv.get("commands_or_queries", ""),
                        results_observed=inv.get("results_observed", ""),
                        fact_type=inv.get("fact_type", "confirmed_fact"),
                        provenance=inv.get("provenance", "rule"),
                        analyst_username=username,
                    )
                )

        # 3. Sincronización no destructiva e idempotente hacia DFIR-IRIS
        iris_sync_results: Dict[str, Any] = {"synced": False}
        if sync_to_iris:
            client = iris_client or IrisApiClient()
            iocs_synced = []
            tasks_synced = []
            assets_synced = []

            epist = final_data.get("epistemological_breakdown") or {}
            for ind in epist.get("technical_indicators") or []:
                if ind.get("is_affected_asset", True):
                    res_ioc = client.ensure_ioc(
                        case_id,
                        value=ind.get("value", ""),
                        ioc_type=ind.get("ioc_type", "domain"),
                        description=ind.get("description", ""),
                        tags=f"abuse,migrated_v3,{ind.get('role', 'ioc')}",
                    )
                    iocs_synced.append(res_ioc)

            if ext.server_name:
                res_asset = client.ensure_asset(
                    case_id,
                    asset_name=ext.server_name,
                    asset_type_key="linux_server",
                    description=f"Servidor asociado al dominio {ext.primary_domain or ''}",
                    domain=ext.primary_domain or "",
                    ip=ext.hosting_ip or ext.reported_ip or "",
                    compromised=bool(ext.is_technical_compromise),
                )
                assets_synced.append(res_asset)

            for a_item in final_data.get("actions") or []:
                res_task = client.ensure_task(
                    case_id,
                    title=a_item.get("title", ""),
                    description=a_item.get("result_notes", ""),
                    action_status=a_item.get("status", "pendiente"),
                )
                tasks_synced.append(res_task)

            # Crear o actualizar una nota adicional estructurada en un directorio separado sin tocar las 3 notas originales
            structured_md = cls._render_v3_structured_note_markdown(ext, final_data)
            note_res = client.ensure_structured_note(
                case_id,
                directory_name="SOC v3.0 — Estructura Normalizada",
                note_title="04 Ficha Técnica Normalizada v3.0 (Migración Controlada)",
                note_content=structured_md,
                update_if_exists=True,
            )

            iris_sync_results = {
                "synced": True,
                "iocs": iocs_synced,
                "assets": assets_synced,
                "tasks": tasks_synced,
                "structured_note": note_res,
            }

        rec.status = "migrated"
        rec.executed_by = username
        rec.executed_at = now
        rec.sync_diff_summary_json = iris_sync_results
        db.commit()

        return {
            "status": "migrated",
            "case_id": case_id,
            "schema_version": ext.schema_version,
            "snapshot_sha256": rec.snapshot_sha256,
            "iris_sync": iris_sync_results,
        }

    @staticmethod
    def _render_v3_structured_note_markdown(ext: CaseExtension, final_data: Dict[str, Any]) -> str:
        epist = final_data.get("epistemological_breakdown") or {}
        lines = [
            f"# Ficha Técnica Normalizada SOC v3.0 — Caso #{ext.iris_case_id}",
            "",
            "## 1. Identificación Estructurada",
            f"- **Organización**: {ext.organization} (Customer ID: {ext.customer_id})",
            f"- **Ticket de Abuso**: `{ext.abuse_ticket_id or 'N/A'}`",
            f"- **Ticket del Titular**: `{ext.holder_ticket_id or 'N/A'}`",
            f"- **ID de Cliente**: `{ext.client_id or 'N/A'}` | **ID de Servicio**: `{ext.service_id or 'N/A'}`",
            f"- **Dominio / Activo Primario**: `{ext.primary_domain or 'N/A'}`",
            f"- **Servidor**: `{ext.server_name or 'N/A'}` | **IP Hosting**: `{ext.hosting_ip or 'N/A'}` | **IP Reportada**: `{ext.reported_ip or 'N/A'}`",
            f"- **Marca Suplantada (Referencia)**: `{ext.impersonated_brand or 'N/A'}`",
            "",
            "## 2. Clasificación Multi-Eje (4 Dimensiones)",
            f"- **Categoría SOC**: `{ext.category_code}`",
            f"- **Eje 1 — Actividad Reportada**: `{ext.reported_activity}`",
            f"- **Eje 2 — Incidente Confirmado / Naturaleza Real**: `{ext.confirmed_incident_type}`",
            f"- **Eje 3 — Vector de Entrada**: `{ext.entry_vector}`",
            f"- **Eje 4 — Causa Raíz**: `{ext.root_cause}`",
            f"- **¿Compromiso Técnico Confirmado?**: `{'Sí' if ext.is_technical_compromise else 'No'}`",
            "",
            "## 3. Separación Epistemológica",
            f"### 3.1 Información Reportada (Alegación)\n{epist.get('reported_information') or 'N/A'}",
            "",
            f"### 3.2 Hechos Técnicos Confirmados\n{epist.get('confirmed_facts') or 'N/A'}",
            "",
            f"### 3.3 Conclusión y Resolución\n{epist.get('conclusions') or 'N/A'}",
            "",
            "> *Nota generada por el módulo de Migración Histórica v3.0. Las notas originales (01, 02, 03) y las evidencias previas se conservan intactas.*",
        ]
        return "\n".join(lines)
