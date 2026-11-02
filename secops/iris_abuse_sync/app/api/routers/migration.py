from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.audit import log_audit_event
from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.iris.legacy_migrator import LegacyCaseMigrator
from app.models.case_extended import CaseMigrationRecord
from app.models.user import User

router = APIRouter(prefix="/api/v1/migration", tags=["migration"])


class MigrationPreviewRequest(BaseModel):
    use_gemini: bool = True


class MigrationApproveExecuteRequest(BaseModel):
    reviewed_data: Optional[Dict[str, Any]] = None
    sync_to_iris: bool = True
    explicit_approval: bool = True


@router.get("/cases")
def list_historical_cases_migration_status(db: Session = Depends(get_db)):
    """Escanea los casos existentes en DFIR-IRIS y muestra cuáles están pendientes, con preview o migrados."""
    try:
        items = LegacyCaseMigrator.scan_historical_cases(db)
        return {"status": "ok", "total": len(items), "cases": items}
    except Exception as exc:
        return {"status": "error", "message": str(exc), "total": 0, "cases": []}


@router.get("/cases/{case_id}")
def get_case_migration_record(case_id: int, db: Session = Depends(get_db)):
    rec = db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == case_id).first()
    if not rec:
        return {"status": "not_started", "case_id": case_id}
    return {
        "status": rec.status,
        "case_id": case_id,
        "snapshot_sha256": rec.snapshot_sha256,
        "snapshot_file_path": rec.snapshot_file_path,
        "original": rec.original_snapshot_json,
        "proposed": rec.proposed_normalized_json,
        "reviewed": rec.analyst_reviewed_json,
        "dry_run": rec.dry_run_report_json,
        "sync_diff_summary": rec.sync_diff_summary_json,
        "reviewed_by": rec.reviewed_by,
        "executed_at": rec.executed_at.isoformat() if rec.executed_at else None,
        "error_log": rec.error_log,
    }


@router.post("/cases/{case_id}/preview")
def preview_historical_case_migration(
    case_id: int,
    payload: MigrationPreviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Toma un snapshot inmutable SHA-256 del caso en DFIR-IRIS y genera la previsualización
    comparativa Lado-a-Lado (Dry-Run) sin modificar nada en DFIR-IRIS."""
    try:
        result = LegacyCaseMigrator.generate_preview_and_snapshot(
            db,
            case_id=case_id,
            use_gemini=payload.use_gemini,
        )
        log_audit_event(
            db,
            action="migration.preview_generated",
            module="migration",
            user=user,
            iris_case_id=case_id,
            details=f"Snapshot SHA-256: {result.get('snapshot_sha256')}",
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "ok", **result}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error generando previsualización del caso #{case_id}: {exc}")


@router.post("/cases/{case_id}/execute")
def execute_single_historical_case_migration(
    case_id: int,
    payload: MigrationApproveExecuteRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    """Ejecuta la migración aprobada para UN ÚNICO caso histórico hacia PostgreSQL y DFIR-IRIS,
    conservando íntegramente las 3 notas originales y todas las evidencias previas."""
    if not payload.explicit_approval:
        raise HTTPException(
            status_code=400,
            detail="Se requiere confirmación explícita (explicit_approval=True) para ejecutar la migración del caso.",
        )
    try:
        username = user.username if user else "admin"
        result = LegacyCaseMigrator.approve_and_execute_single_case(
            db,
            case_id=case_id,
            reviewed_data=payload.reviewed_data,
            sync_to_iris=payload.sync_to_iris,
            username=username,
        )
        log_audit_event(
            db,
            action="migration.case_executed",
            module="migration",
            user=user,
            iris_case_id=case_id,
            after_data=result,
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "ok", **result}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error migrando caso #{case_id}: {exc}")

