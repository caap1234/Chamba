import os
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.rbac import get_optional_user
from app.core.audit import log_audit_event
from app.models.user import User
from app.retention.manager import (
    CaseRetentionManager,
    JOBS_REGISTRY,
    get_retention_config,
    save_retention_config,
    test_ftp_connection,
    test_gdrive_connection,
    test_github_connection,
)

router = APIRouter(prefix="/api/v1/retention", tags=["retention"])


class BackupCreateRequest(BaseModel):
    backup_type: str = Field(default="local", description="local, ftp, gdrive")


class PruneBinariesRequest(BaseModel):
    confirmation: str = Field(..., description="Escriba 'CONFIRMAR' para autorizar el purgado")


class BulkRotationRequest(BaseModel):
    scope: str = Field(default="all", description="all, closed_only, age_days")
    action: str = Field(default="backup_only", description="backup_only, backup_and_prune")
    min_age_days: int = Field(default=90)


class FtpTestRequest(BaseModel):
    host: str
    port: int = 21
    username: Optional[str] = ""
    password: Optional[str] = ""
    remote_path: Optional[str] = "/"
    use_tls: bool = False


class GDriveTestRequest(BaseModel):
    folder_id: Optional[str] = ""
    service_account_json: str = Field(..., description="Contenido JSON de la Service Account de Google Cloud")


class GitHubTestRequest(BaseModel):
    token: str = Field(..., description="Personal Access Token de GitHub con permisos repo")
    repo: str = Field(..., description="Nombre del repositorio en formato owner/repo")


@router.get("/summary")
def get_retention_capacity_summary(
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Obtiene el diagnóstico global de consumo de almacenamiento del Datastore de IRIS y candidatos a retención."""
    mgr = CaseRetentionManager()
    try:
        return mgr.get_capacity_summary(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analizando capacidad de Datastore: {str(e)}")


@router.get("/config")
def get_retention_configuration(
    user: Optional[User] = Depends(get_optional_user),
):
    """Obtiene la configuración actual de destinos de respaldo (local, ftp, gdrive) y cron nocturno."""
    return {"status": "ok", "config": get_retention_config()}


@router.post("/config")
def update_retention_configuration(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Guarda la configuración de destinos de respaldo y política programada."""
    updated = save_retention_config(payload)
    return {"status": "ok", "config": updated}


@router.post("/config/test-ftp")
def test_ftp_endpoint(
    payload: FtpTestRequest,
    user: Optional[User] = Depends(get_optional_user),
):
    """Prueba conectividad a servidor FTP/SFTP antes de activar el destino."""
    res = test_ftp_connection(payload.model_dump())
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@router.post("/config/test-gdrive")
def test_gdrive_endpoint(
    payload: GDriveTestRequest,
    user: Optional[User] = Depends(get_optional_user),
):
    """Prueba autenticación y acceso a carpeta en Google Drive usando Service Account."""
    res = test_gdrive_connection(payload.model_dump())
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@router.post("/config/test-github")
def test_github_endpoint(
    payload: GitHubTestRequest,
    user: Optional[User] = Depends(get_optional_user),
):
    """Prueba autenticación y acceso a repositorio en GitHub."""
    res = test_github_connection(payload.model_dump())
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@router.post("/cases/{case_id}/backup")
def create_case_backup(
    case_id: int,
    payload: BackupCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Genera un archivo .tar.gz con evidencias, hashes, notas y manifest.json del caso."""
    mgr = CaseRetentionManager()
    username = user.username if user else "SOC Analyst"
    try:
        res = mgr.create_case_backup(case_id, db, username=username, backup_type=payload.backup_type)
        log_audit_event(
            db,
            action="retention.case_backup_created",
            module="retention",
            user=user,
            iris_case_id=case_id,
            details=f"Generado respaldo .tar.gz para Caso #{case_id} ({res['backup_filename']}, SHA256: {res['backup_sha256'][:16]}...).",
            ip_address=request.client.host if request.client else None,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando respaldo del caso: {str(e)}")


@router.post("/cases/{case_id}/prune-binaries")
def prune_case_binaries(
    case_id: int,
    payload: PruneBinariesRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Purga los archivos binarios pesados del Datastore tras verificar el respaldo íntegro."""
    if payload.confirmation.strip().upper() != "CONFIRMAR":
        raise HTTPException(status_code=400, detail="Debe escribir exactamente 'CONFIRMAR' para autorizar el purgado forense.")

    mgr = CaseRetentionManager()
    username = user.username if user else "SOC Analyst"
    try:
        res = mgr.prune_case_binaries(case_id, db, username=username)
        log_audit_event(
            db,
            action="retention.binaries_pruned",
            module="retention",
            user=user,
            iris_case_id=case_id,
            details=f"Purgados {res['deleted_count']} binarios del Caso #{case_id} ({res['freed_bytes_human']} liberados) con respaldo verificado.",
            ip_address=request.client.host if request.client else None,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/jobs/bulk-rotation")
def start_bulk_rotation_job(
    payload: BulkRotationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Inicia una tarea asíncrona en segundo plano para respaldo masivo o purgado rotacional."""
    mgr = CaseRetentionManager()
    username = user.username if user else "SOC Analyst"
    job_id = mgr.start_background_bulk_rotation(
        scope=payload.scope,
        action=payload.action,
        min_age_days=payload.min_age_days,
        username=username,
    )
    log_audit_event(
        db,
        action="retention.bulk_rotation_started",
        module="retention",
        user=user,
        details=f"Iniciada tarea en segundo plano #{job_id} (Alcance: {payload.scope}, Acción: {payload.action}).",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "ok", "job_id": job_id, "job": JOBS_REGISTRY.get(job_id)}


@router.get("/jobs/{job_id}")
def get_job_status(
    job_id: str,
    user: Optional[User] = Depends(get_optional_user),
):
    """Consulta el progreso y estado en tiempo real de una tarea en segundo plano."""
    job = JOBS_REGISTRY.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Tarea no encontrada.")
    return {"status": "ok", "job": job}


@router.get("/jobs")
def list_retention_jobs(
    user: Optional[User] = Depends(get_optional_user),
):
    """Lista las tareas recientes de respaldo y rotación en segundo plano."""
    return {"status": "ok", "jobs": list(JOBS_REGISTRY.values())}


@router.get("/download/{filename}")
def download_backup_archive(
    filename: str,
    user: Optional[User] = Depends(get_optional_user),
):
    """Descarga el archivo .tar.gz generado para un caso."""
    safe_name = os.path.basename(filename)
    backup_file = Path("storage/backups") / safe_name
    if not backup_file.is_file():
        raise HTTPException(status_code=404, detail="Archivo de respaldo no encontrado.")

    return FileResponse(
        path=str(backup_file),
        filename=safe_name,
        media_type="application/gzip",
    )
