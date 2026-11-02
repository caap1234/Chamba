from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EncryptedSecret(Base):
    __tablename__ = "encrypted_secrets"

    id = Column(Integer, primary_key=True, index=True)
    secret_key_name = Column(String(128), unique=True, nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)
    key_hint = Column(String(64), nullable=False, default="••••••")
    updated_by = Column(String(64), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class ConnectorConfig(Base):
    __tablename__ = "connector_configs"

    id = Column(Integer, primary_key=True, index=True)
    # Tipos: zammad, whmcs, imap, slack, blacklist_master, gemini, iris
    connector_type = Column(String(48), nullable=False, index=True)
    name = Column(String(120), unique=True, nullable=False)
    organization = Column(String(16), nullable=False, default="ALL")  # NBX, HP, ALL
    is_enabled = Column(Boolean, nullable=False, default=False)
    settings_json = Column(JSON, nullable=False, default=dict)
    secret_id = Column(Integer, ForeignKey("encrypted_secrets.id", ondelete="SET NULL"), nullable=True)
    poll_interval_seconds = Column(Integer, nullable=False, default=300)
    sync_cursor_json = Column(JSON, nullable=False, default=dict)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(32), nullable=False, default="unconfigured")
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class IngestEvent(Base):
    __tablename__ = "ingest_events"

    id = Column(Integer, primary_key=True, index=True)
    idempotency_key = Column(String(256), unique=True, nullable=False, index=True)
    source_type = Column(String(48), nullable=False, index=True)  # zammad, whmcs, imap, slack, blacklist_master, manual_file, manual_text
    source_instance = Column(String(120), nullable=False, default="default")
    source_id = Column(String(160), nullable=False, index=True)
    organization = Column(String(16), nullable=False, default="NBX", index=True)
    received_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    reported_at = Column(DateTime(timezone=True), nullable=True)
    reporter = Column(String(256), nullable=True)
    subject = Column(String(512), nullable=True)
    original_content = Column(Text, nullable=False, default="")
    attachments_json = Column(JSON, nullable=False, default=list)
    external_reference = Column(String(256), nullable=True)
    source_url = Column(String(512), nullable=True)
    raw_metadata_json = Column(JSON, nullable=False, default=dict)
    normalized_payload_json = Column(JSON, nullable=False, default=dict)
    evidence_package_path = Column(String(512), nullable=True)
    evidence_sha256 = Column(String(64), nullable=True, index=True)
    # Estados: queued, processing, alert_created, correlated, case_created, failed, discarded
    processing_status = Column(String(32), nullable=False, default="queued", index=True)
    iris_alert_id = Column(Integer, nullable=True, index=True)
    iris_case_id = Column(Integer, nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class JobQueue(Base):
    __tablename__ = "job_queue"

    id = Column(Integer, primary_key=True, index=True)
    job_type = Column(String(64), nullable=False, index=True)  # ingest_process, connector_poll, gemini_enrich, case_sync
    idempotency_key = Column(String(256), unique=True, nullable=True, index=True)
    payload_json = Column(JSON, nullable=False, default=dict)
    # Estados: pending, running, completed, failed, dead_letter
    status = Column(String(32), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=4)
    next_run_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    locked_by = Column(String(96), nullable=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    result_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

