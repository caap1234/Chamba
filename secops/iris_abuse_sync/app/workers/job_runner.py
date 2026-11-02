from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret
from app.ingestion.base import NormalizedIngestPayload
from app.ingestion.connectors.imap_connector import ImapConnector
from app.ingestion.connectors.whmcs import WhmcsConnector
from app.ingestion.connectors.zammad import ZammadConnector
from app.ingestion.pipeline import IngestPipeline
from app.models.connector import ConnectorConfig, EncryptedSecret, JobQueue


class JobRunner:
    """Gestor de cola de trabajos persistente con reintentos y backoff exponencial."""

    @staticmethod
    def enqueue_job(
        db: Session,
        *,
        job_type: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        max_attempts: int = 4,
    ) -> JobQueue:
        if idempotency_key:
            existing = db.query(JobQueue).filter(JobQueue.idempotency_key == idempotency_key).first()
            if existing and existing.status in ("pending", "running", "completed"):
                return existing

        job = JobQueue(
            job_type=job_type,
            idempotency_key=idempotency_key,
            payload_json=payload,
            status="pending",
            attempts=0,
            max_attempts=max_attempts,
            next_run_at=datetime.now(timezone.utc),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @classmethod
    def run_pending_jobs(cls, db: Session, limit: int = 10) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        jobs = (
            db.query(JobQueue)
            .filter(
                JobQueue.status.in_(["pending", "failed"]),
                JobQueue.next_run_at <= now,
            )
            .order_by(JobQueue.id.asc())
            .limit(limit)
            .all()
        )
        processed = 0
        succeeded = 0
        failed = 0

        for job in jobs:
            processed += 1
            job.status = "running"
            job.attempts = (job.attempts or 0) + 1
            job.locked_by = "soc_worker_1"
            job.locked_at = now
            db.commit()

            try:
                res = cls._execute_single_job(db, job)
                job.status = "completed"
                job.result_json = res
                job.last_error = None
                succeeded += 1
            except Exception as exc:
                failed += 1
                job.last_error = str(exc)[:600]
                if job.attempts >= job.max_attempts:
                    job.status = "dead_letter"
                else:
                    job.status = "failed"
                    backoff_sec = min(3600, 15 * (2 ** job.attempts))
                    job.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_sec)
            db.commit()

        return {"processed": processed, "succeeded": succeeded, "failed": failed}

    @classmethod
    def _execute_single_job(cls, db: Session, job: JobQueue) -> Dict[str, Any]:
        if job.job_type == "ingest_payload":
            p = NormalizedIngestPayload.model_validate(job.payload_json)
            return IngestPipeline.process_ingest(db, p, create_iris_alert=True)

        if job.job_type == "poll_connector":
            conn_id = job.payload_json.get("connector_id")
            return cls.poll_connector_by_id(db, int(conn_id))

        return {"status": "unknown_job_type", "job_type": job.job_type}

    @classmethod
    def poll_connector_by_id(cls, db: Session, connector_id: int) -> Dict[str, Any]:
        conn = db.query(ConnectorConfig).filter(ConnectorConfig.id == connector_id).first()
        if not conn:
            raise ValueError(f"Conector #{connector_id} no encontrado.")

        secret_val = None
        if conn.secret_id:
            sec = db.query(EncryptedSecret).filter(EncryptedSecret.id == conn.secret_id).first()
            if sec:
                secret_val = decrypt_secret(sec.ciphertext)

        ctype = conn.connector_type
        instance = None
        if ctype == "zammad":
            instance = ZammadConnector(conn.settings_json or {}, secret_val)
        elif ctype == "whmcs":
            instance = WhmcsConnector(conn.settings_json or {}, secret_val)
        elif ctype == "imap":
            instance = ImapConnector(conn.settings_json or {}, secret_val)
        else:
            return {"status": "passive_connector", "connector_type": ctype}

        try:
            events, new_cursor = instance.fetch_new_events(conn.sync_cursor_json or {})
            created_alerts = []
            for ev in events:
                out = IngestPipeline.process_ingest(db, ev, create_iris_alert=True)
                created_alerts.append(out.get("iris_alert_id"))
            conn.sync_cursor_json = new_cursor
            conn.last_sync_at = datetime.now(timezone.utc)
            conn.last_status = "ok"
            conn.last_error = None
            db.commit()
            return {
                "status": "ok",
                "events_fetched": len(events),
                "alerts_created": created_alerts,
            }
        except Exception as exc:
            conn.last_sync_at = datetime.now(timezone.utc)
            conn.last_status = "error"
            conn.last_error = str(exc)[:500]
            db.commit()
            raise


def run_worker_loop(interval_seconds: int = 15) -> None:
    """Bucle principal del worker para procesar trabajos en cola y conectores habilitados."""
    import time
    from app.core.bootstrap import init_db_and_seed
    from app.core.database import SessionLocal

    init_db_and_seed()
    while True:
        db = SessionLocal()
        try:
            JobRunner.run_pending_jobs(db, limit=10)
            now = datetime.now(timezone.utc)
            enabled_conns = (
                db.query(ConnectorConfig)
                .filter(
                    ConnectorConfig.is_enabled.is_(True),
                    ConnectorConfig.connector_type.in_(["zammad", "whmcs", "imap"]),
                )
                .all()
            )
            for c in enabled_conns:
                poll_sec = max(30, int(c.poll_interval_seconds or 120))
                if not c.last_sync_at or (now - c.last_sync_at.replace(tzinfo=timezone.utc)).total_seconds() >= poll_sec:
                    try:
                        JobRunner.poll_connector_by_id(db, c.id)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            db.close()
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run_worker_loop()

