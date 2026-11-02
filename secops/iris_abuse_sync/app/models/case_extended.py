from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AlertExtension(Base):
    __tablename__ = "alert_extensions"

    id = Column(Integer, primary_key=True, index=True)
    iris_alert_id = Column(Integer, unique=True, nullable=False, index=True)
    ingest_event_id = Column(Integer, ForeignKey("ingest_events.id", ondelete="SET NULL"), nullable=True, index=True)
    organization = Column(String(16), nullable=False, default="NBX", index=True)
    source_type = Column(String(48), nullable=False, default="manual")
    abuse_ticket_id = Column(String(64), nullable=True, index=True)
    primary_domain = Column(String(256), nullable=True, index=True)
    reported_ip = Column(String(64), nullable=True, index=True)
    hosting_ip = Column(String(64), nullable=True)
    server_name = Column(String(128), nullable=True)

    # 4 Ejes de clasificación
    reported_activity = Column(String(64), nullable=False, default="unknown", index=True)
    confirmed_incident_type = Column(String(64), nullable=False, default="pending_investigation", index=True)
    entry_vector = Column(String(64), nullable=False, default="unknown")
    root_cause = Column(String(64), nullable=False, default="unknown")
    category_code = Column(String(64), nullable=False, default="general_abuse", index=True)
    severity = Column(String(32), nullable=False, default="Medium")
    confidence_score = Column(Integer, nullable=False, default=70)  # 0-100

    heuristic_result_json = Column(JSON, nullable=False, default=dict)
    gemini_result_json = Column(JSON, nullable=False, default=dict)
    # Mapa campo -> "rule" | "ai" | "manual"
    field_provenance_json = Column(JSON, nullable=False, default=dict)
    indicators_by_role_json = Column(JSON, nullable=False, default=dict)
    verification_state = Column(String(48), nullable=False, default="pending_investigation")
    discard_reason = Column(Text, nullable=True)
    correlated_alert_ids_json = Column(JSON, nullable=False, default=list)
    correlated_case_ids_json = Column(JSON, nullable=False, default=list)
    escalated_case_id = Column(Integer, nullable=True, index=True)
    observation_count = Column(Integer, nullable=False, default=1)
    triaged_by = Column(String(64), nullable=True)
    triaged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class MonitoredIp(Base):
    """Direcciones IP bajo vigilancia continua de reputación en Blacklist Master / RBL."""
    __tablename__ = "monitored_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), unique=True, nullable=False, index=True)
    organization = Column(String(16), nullable=False, default="NBX", index=True)  # NBX, HP
    server_name = Column(String(128), nullable=True, index=True)
    description = Column(Text, nullable=True)
    # Estados de monitoreo: active, paused
    status = Column(String(32), nullable=False, default="active", index=True)
    # Último resultado: clean, listed, error, pending
    last_status = Column(String(32), nullable=False, default="pending", index=True)
    listed_providers = Column(JSON, nullable=False, default=list)
    listed_count = Column(Integer, nullable=False, default=0)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    next_check_at = Column(DateTime(timezone=True), nullable=True)
    check_interval_minutes = Column(Integer, nullable=False, default=60)
    last_rbl_hash = Column(String(64), nullable=True)
    last_alert_id = Column(Integer, nullable=True, index=True)
    last_case_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseExtension(Base):
    __tablename__ = "case_extensions"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, unique=True, nullable=False, index=True)
    organization = Column(String(16), nullable=False, default="NBX", index=True)
    customer_id = Column(Integer, nullable=False, default=2, index=True)
    source_channel = Column(String(48), nullable=False, default="zammad")
    abuse_ticket_id = Column(String(64), nullable=True, index=True)
    holder_ticket_id = Column(String(64), nullable=True, index=True)
    external_reference = Column(String(160), nullable=True)
    client_id = Column(String(64), nullable=True, index=True)
    service_id = Column(String(64), nullable=True, index=True)
    domain_id = Column(String(64), nullable=True, index=True)
    service_plan = Column(String(160), nullable=True)
    primary_domain = Column(String(256), nullable=True, index=True)
    subdomains_json = Column(JSON, nullable=False, default=list)
    reported_urls_json = Column(JSON, nullable=False, default=list)
    server_name = Column(String(128), nullable=True, index=True)
    hosting_ip = Column(String(64), nullable=True, index=True)
    reported_ip = Column(String(64), nullable=True, index=True)
    src_ip = Column(String(64), nullable=True)
    auth_ip = Column(String(64), nullable=True)
    rbl_ip = Column(String(64), nullable=True)
    authenticated_account = Column(String(160), nullable=True)
    cms_detected = Column(String(96), nullable=True)
    registrar_name = Column(String(160), nullable=True)
    nameservers_json = Column(JSON, nullable=False, default=list)
    impersonated_brand = Column(String(160), nullable=True)
    reporter_name = Column(String(160), nullable=True)
    reporter_email = Column(String(160), nullable=True)
    reporter_type = Column(String(64), nullable=False, default="external_reporter")

    # 4 Ejes de Clasificación Explícita
    reported_activity = Column(String(64), nullable=False, default="phishing", index=True)
    confirmed_incident_type = Column(String(64), nullable=False, default="pending_investigation", index=True)
    entry_vector = Column(String(64), nullable=False, default="unknown")
    root_cause = Column(String(64), nullable=False, default="unknown")
    category_code = Column(String(64), nullable=False, default="general_abuse", index=True)
    asset_type = Column(String(64), nullable=False, default="shared_hosting")
    verification_state = Column(String(64), nullable=False, default="pendiente")
    severity = Column(String(32), nullable=False, default="Medium")
    is_technical_compromise = Column(Boolean, nullable=False, default=False)
    playbook_code = Column(String(64), nullable=True)

    # Trazabilidad y versión de esquema (para migración y re-ejecución segura)
    schema_version = Column(String(16), nullable=False, default="3.0")
    field_provenance_json = Column(JSON, nullable=False, default=dict)
    initial_report_json = Column(JSON, nullable=False, default=dict)
    indicators_by_role_json = Column(JSON, nullable=False, default=dict)
    resolution_data_json = Column(JSON, nullable=False, default=dict)
    closure_checklist_json = Column(JSON, nullable=False, default=dict)

    # Tiempos operativos reales para métricas SLA
    reported_at = Column(DateTime(timezone=True), nullable=True)
    opened_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    first_action_at = Column(DateTime(timezone=True), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseInvestigation(Base):
    __tablename__ = "case_investigations"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    # Fuentes: DNS, WHOIS, Bastion, cPanel/DirectAdmin, WHMCS, Exim/Mail logs, Apache/Nginx logs, ClamAV/Imunify, Panel Login Logs
    source_consulted = Column(String(96), nullable=False)
    commands_or_queries = Column(Text, nullable=True)
    results_observed = Column(Text, nullable=False)
    # Tipos epistemológicos: reported_claim, confirmed_fact, indicator_clue, conclusion
    fact_type = Column(String(48), nullable=False, default="confirmed_fact")
    provenance = Column(String(24), nullable=False, default="manual")  # rule, ai, manual
    analyst_username = Column(String(64), nullable=False, default="Christian Aceves")
    executed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CaseFinding(Base):
    __tablename__ = "case_findings"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    # Naturaleza: reported_allegation, confirmed_compromise, technical_indicator, uncorroborated_claim,
    # brand_dispute_only, authority_request_only, rbl_listing_only, no_technical_intervention
    finding_nature = Column(String(64), nullable=False, default="confirmed_compromise")
    # Estados: confirmado, probable, indicio, no_corroborado, falso_positivo, solo_registro_dominio, alojado_externo, no_aplicable
    verification_state = Column(String(48), nullable=False, default="confirmado")
    severity = Column(String(32), nullable=False, default="Medium")
    evidence_refs_json = Column(JSON, nullable=False, default=list)
    provenance = Column(String(24), nullable=False, default="manual")
    created_by = Column(String(64), nullable=False, default="Christian Aceves")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class CaseAction(Base):
    __tablename__ = "case_actions"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    action_type = Column(String(96), nullable=False)
    title = Column(String(256), nullable=False)
    # 8 Estados requeridos: propuesta, autorizada, pendiente, en_ejecucion, ejecutada, verificada, cancelada, no_aplicable
    status = Column(String(32), nullable=False, default="pendiente", index=True)
    responsible = Column(String(96), nullable=False, default="SOC Analyst")
    proposed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    authorized_by = Column(String(64), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    result_notes = Column(Text, nullable=True)
    iris_task_id = Column(Integer, nullable=True, index=True)
    evidence_ref = Column(String(256), nullable=True)
    provenance = Column(String(24), nullable=False, default="manual")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseCommunication(Base):
    __tablename__ = "case_communications"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    channel = Column(String(48), nullable=False, default="Zammad")  # Zammad, WHMCS, Email, Autoridad, Reportante
    direction = Column(String(32), nullable=False, default="outbound")  # outbound, inbound, internal
    recipient = Column(String(160), nullable=False)
    ticket_reference = Column(String(96), nullable=True)
    summary = Column(Text, nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    response_received_at = Column(DateTime(timezone=True), nullable=True)
    provenance = Column(String(24), nullable=False, default="manual")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class RblEpisode(Base):
    __tablename__ = "rbl_episodes"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), nullable=False, index=True)
    server_name = Column(String(128), nullable=True, index=True)
    organization = Column(String(16), nullable=False, default="NBX", index=True)
    rbl_provider = Column(String(96), nullable=False, index=True)
    # Estados: active, delisting_requested, delisted
    status = Column(String(32), nullable=False, default="active", index=True)
    reason = Column(Text, nullable=True)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    delisted_at = Column(DateTime(timezone=True), nullable=True)
    check_count = Column(Integer, nullable=False, default=1)
    iris_alert_id = Column(Integer, nullable=True, index=True)
    iris_case_id = Column(Integer, nullable=True, index=True)


class CaseMigrationRecord(Base):
    __tablename__ = "case_migration_records"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, unique=True, nullable=False, index=True)
    case_name = Column(String(256), nullable=True)
    organization = Column(String(16), nullable=False, default="NBX")
    schema_version_target = Column(String(16), nullable=False, default="3.0")
    # Estados: pending, snapshot_taken, preview_ready, approved, migrated, failed, rolled_back
    status = Column(String(32), nullable=False, default="pending", index=True)
    snapshot_sha256 = Column(String(64), nullable=True)
    snapshot_file_path = Column(String(512), nullable=True)
    original_snapshot_json = Column(JSON, nullable=False, default=dict)
    proposed_normalized_json = Column(JSON, nullable=False, default=dict)
    analyst_reviewed_json = Column(JSON, nullable=True)
    sync_diff_summary_json = Column(JSON, nullable=False, default=dict)
    dry_run_report_json = Column(JSON, nullable=False, default=dict)
    reviewed_by = Column(String(64), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    executed_by = Column(String(64), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    error_log = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseDraft(Base):
    """Borradores automáticos en edición para evitar pérdidas de trabajo no guardadas en IRIS."""
    __tablename__ = "case_drafts"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    field_key = Column(String(64), nullable=False, index=True)  # e.g., 'case_summary', 'note_1', 'note_2', 'note_3'
    draft_content = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CasePlaybookExecution(Base):
    """Registro y trazabilidad de ejecuciones supervisadas de Playbooks asociadas a un caso."""
    __tablename__ = "case_playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    playbook_code = Column(String(64), nullable=False, index=True)
    playbook_name = Column(String(160), nullable=False)
    playbook_version = Column(String(16), nullable=False, default="1.0")
    # Estados: in_progress, completed, suspended, cancelled
    status = Column(String(32), nullable=False, default="in_progress", index=True)
    started_by = Column(String(64), nullable=False, default="SOC Analyst")
    started_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    steps_state = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseActivityLog(Base):
    """Bitácora Operativa Unificada para investigación técnica, acciones, evidencias, comandos y notas."""
    __tablename__ = "case_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, nullable=False, index=True)
    playbook_execution_id = Column(Integer, ForeignKey("case_playbook_executions.id", ondelete="SET NULL"), nullable=True, index=True)
    step_order = Column(Integer, nullable=True, index=True)

    # Tipo: 'investigacion', 'accion', 'evidencia', 'comunicacion', 'nota'
    activity_type = Column(String(32), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    content = Column(Text, nullable=False, default="")
    metadata_json = Column(JSON, nullable=False, default=dict)

    # Estado de acción: 'propuesta', 'pendiente', 'en_ejecucion', 'ejecutada', 'verificada', 'omitida'
    action_status = Column(String(32), nullable=True, index=True)

    # Referencias de persistencia oficial en DFIR-IRIS (repositorio principal)
    iris_evidence_id = Column(Integer, nullable=True, index=True)
    iris_task_id = Column(Integer, nullable=True, index=True)
    iris_timeline_id = Column(Integer, nullable=True, index=True)

    # Estado de sincronización: 'synced', 'pending_iris', 'error'
    sync_status = Column(String(32), nullable=False, default="synced", index=True)
    sync_error = Column(Text, nullable=True)

    analyst_username = Column(String(64), nullable=False, default="SOC Analyst")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class CaseArchiveRecord(Base):
    """Registro de ciclo de vida, retención y respaldo tar.gz para DFIR-IRIS Datastore."""
    __tablename__ = "case_archive_records"

    id = Column(Integer, primary_key=True, index=True)
    iris_case_id = Column(Integer, unique=True, nullable=False, index=True)
    # Estados: 'active', 'archived', 'pruned', 'exported'
    archive_status = Column(String(32), nullable=False, default="active", index=True)
    backup_type = Column(String(32), nullable=False, default="local")  # 'local', 'ftp', 'gdrive'
    backup_path = Column(String(512), nullable=True)
    backup_sha256 = Column(String(64), nullable=True)
    manifest_json = Column(JSON, nullable=False, default=dict)
    evidence_count = Column(Integer, nullable=False, default=0)
    evidence_total_bytes = Column(BigInteger, nullable=False, default=0)
    pruned_at = Column(DateTime(timezone=True), nullable=True)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
