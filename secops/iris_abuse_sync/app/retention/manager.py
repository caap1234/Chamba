import base64
import ftplib
import hashlib
import json
import os
import requests
import shutil
import tarfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.iris.client import IrisApiClient
from app.models.case_extended import CaseArchiveRecord, CaseExtension, CaseActivityLog
from app.core.database import SessionLocal


def _format_bytes(size: int) -> str:
    power = 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size >= power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"


CONFIG_FILE_PATH = Path("storage/retention_config.json")

# In-memory background jobs registry
JOBS_REGISTRY: Dict[str, Dict[str, Any]] = {}


def get_retention_config() -> Dict[str, Any]:
    default_config = {
        "destination": "local",
        "local_path": "storage/backups",
        "ftp": {
            "host": "",
            "port": 21,
            "username": "",
            "password": "",
            "remote_path": "/backups/soc_iris",
            "use_tls": False,
        },
        "sftp": {
            "host": "",
            "port": 22,
            "username": "",
            "password": "",
            "remote_path": "/backups/soc_iris",
        },
        "gdrive": {
            "folder_id": "",
            "service_account_email": "",
            "enabled": False,
        },
        "github": {
            "token": "",
            "repo": "",
            "branch": "main",
            "path": "backups/cases",
            "enabled": False,
        },
        "schedule": {
            "enabled": True,
            "time_utc": "03:00",
            "prune_binaries_after_days": 90,
            "archive_cases_after_days": 365,
            "auto_prune_closed_cases": True,
        },
    }
    if CONFIG_FILE_PATH.is_file():
        try:
            stored = json.loads(CONFIG_FILE_PATH.read_text(encoding="utf-8"))
            default_config.update(stored)
        except Exception:
            pass
    return default_config


def save_retention_config(data: Dict[str, Any]) -> Dict[str, Any]:
    CONFIG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg = get_retention_config()
    cfg.update(data)
    CONFIG_FILE_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return cfg


def test_ftp_connection(ftp_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Prueba conectividad a servidor FTP remoto."""
    host = ftp_cfg.get("host", "").strip()
    port = int(ftp_cfg.get("port") or 21)
    username = ftp_cfg.get("username", "").strip()
    password = ftp_cfg.get("password", "").strip()
    remote_path = ftp_cfg.get("remote_path", "/").strip()
    use_tls = ftp_cfg.get("use_tls", False)

    if not host:
        return {"success": False, "error": "Debe especificar el host del servidor FTP."}

    try:
        ftp = ftplib.FTP_TLS() if use_tls else ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        if username:
            ftp.login(username, password)
        else:
            ftp.login()
        if use_tls and isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()

        # Try navigating to or creating remote path
        if remote_path and remote_path != "/":
            try:
                ftp.cwd(remote_path)
            except Exception:
                try:
                    ftp.mkd(remote_path)
                    ftp.cwd(remote_path)
                except Exception:
                    pass

        welcome = ftp.getwelcome()
        ftp.quit()
        return {"success": True, "message": f"Conexión exitosa a FTP {host}:{port}. {welcome}"}
    except Exception as e:
        return {"success": False, "error": f"Fallo al conectar a FTP: {str(e)}"}


def transfer_to_remote_ftp(file_path: Path, ftp_cfg: Dict[str, Any]) -> bool:
    """Sube un archivo de respaldo a FTP remoto."""
    host = ftp_cfg.get("host", "").strip()
    port = int(ftp_cfg.get("port") or 21)
    username = ftp_cfg.get("username", "").strip()
    password = ftp_cfg.get("password", "").strip()
    remote_path = ftp_cfg.get("remote_path", "/").strip()
    use_tls = ftp_cfg.get("use_tls", False)

    if not host or not file_path.is_file():
        return False

    try:
        ftp = ftplib.FTP_TLS() if use_tls else ftplib.FTP()
        ftp.connect(host, port, timeout=20)
        if username:
            ftp.login(username, password)
        else:
            ftp.login()
        if use_tls and isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()

        if remote_path and remote_path != "/":
            try:
                ftp.cwd(remote_path)
            except Exception:
                ftp.mkd(remote_path)
                ftp.cwd(remote_path)

        with open(file_path, "rb") as f:
            ftp.storbinary(f"STOR {file_path.name}", f)
        ftp.quit()
        return True
    except Exception:
        return False


def test_gdrive_connection(gdrive_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Valida credenciales de Service Account y acceso a carpeta de Google Drive."""
    sa_json = gdrive_cfg.get("service_account_json", "").strip()
    folder_id = gdrive_cfg.get("folder_id", "").strip()

    if not sa_json:
        return {"success": False, "error": "Debe proporcionar el JSON de credenciales de Service Account de Google Cloud."}

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        scopes = ["https://www.googleapis.com/auth/drive.file"]
        sa_info = json.loads(sa_json)
        creds = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
        service = build("drive", "v3", credentials=creds, cache_discovery=False)

        client_email = sa_info.get("client_email", "Service Account")

        if folder_id:
            folder = service.files().get(fileId=folder_id, fields="id, name, capabilities").execute()
            fname = folder.get("name", folder_id)
            return {
                "success": True,
                "message": f"Conexión exitosa a Google Drive como '{client_email}'. Carpeta destino verificada: '{fname}' (#{folder_id}).",
                "folder_name": fname,
                "client_email": client_email,
            }
        else:
            about = service.about().get(fields="user").execute()
            user_display = about.get("user", {}).get("displayName", client_email)
            return {
                "success": True,
                "message": f"Conexión exitosa a Google Drive como '{user_display}' ({client_email}). Se guardará en la raíz de la cuenta.",
                "client_email": client_email,
            }
    except Exception as e:
        return {"success": False, "error": f"Fallo en autenticación con Google Drive: {str(e)}"}


def transfer_to_remote_gdrive(file_path: Path, gdrive_cfg: Dict[str, Any]) -> bool:
    """Sube un archivo de respaldo .tar.gz a Google Drive usando Service Account."""
    sa_json = gdrive_cfg.get("service_account_json", "").strip()
    folder_id = gdrive_cfg.get("folder_id", "").strip()

    if not sa_json or not file_path.is_file():
        return False

    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaFileUpload

        scopes = ["https://www.googleapis.com/auth/drive.file"]
        sa_info = json.loads(sa_json)
        creds = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
        service = build("drive", "v3", credentials=creds, cache_discovery=False)

        file_metadata: Dict[str, Any] = {"name": file_path.name}
        if folder_id:
            file_metadata["parents"] = [folder_id]

        media = MediaFileUpload(str(file_path), mimetype="application/gzip", resumable=True)
        file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        return bool(file.get("id"))
    except Exception as e:
        print(f"[GDrive Upload Error] {e}")
        return False


def test_github_connection(github_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Prueba autenticación con GitHub API y acceso al repositorio destino."""
    token = (github_cfg.get("token") or "").strip()
    repo = (github_cfg.get("repo") or "").strip().strip("/")
    if not token:
        return {"success": False, "error": "Token de Acceso Personal (PAT) de GitHub no especificado."}
    if not repo or "/" not in repo:
        return {"success": False, "error": "Formato de repositorio inválido. Use 'usuario/repositorio' o 'organizacion/repositorio'."}

    try:
        url = f"https://api.github.com/repos/{repo}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SOC-DFIR-IRIS-Abuse-Sync",
        }
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "repo_name": data.get("full_name"),
                "is_private": data.get("private", False),
                "default_branch": data.get("default_branch", "main"),
                "permissions": data.get("permissions", {}),
            }
        elif resp.status_code == 404:
            return {"success": False, "error": f"Repositorio '{repo}' no encontrado o el token no tiene permisos de lectura/escritura."}
        elif resp.status_code == 401:
            return {"success": False, "error": "Token de GitHub no válido o expirado."}
        else:
            return {"success": False, "error": f"GitHub API error ({resp.status_code}): {resp.text[:200]}"}
    except Exception as e:
        return {"success": False, "error": f"Error de red contactando GitHub API: {str(e)}"}


def transfer_to_remote_github(file_path: Path, github_cfg: Dict[str, Any]) -> bool:
    """Sube un archivo de respaldo forense .tar.gz directamente a un repositorio de GitHub."""
    token = (github_cfg.get("token") or "").strip()
    repo = (github_cfg.get("repo") or "").strip().strip("/")
    branch = (github_cfg.get("branch") or "main").strip()
    target_dir = (github_cfg.get("path") or "backups/cases").strip().strip("/")

    if not token or not repo or not file_path.is_file():
        return False

    try:
        file_bytes = file_path.read_bytes()
        if len(file_bytes) > 95 * 1024 * 1024:
            print(f"[GitHub Upload Warning] Archivo {file_path.name} excede el límite de 100MB para API de contenido.")
            return False

        b64_content = base64.b64encode(file_bytes).decode("ascii")
        remote_file_path = f"{target_dir}/{file_path.name}" if target_dir else file_path.name
        url = f"https://api.github.com/repos/{repo}/contents/{remote_file_path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SOC-DFIR-IRIS-Abuse-Sync",
        }

        # Check if file already exists to get its sha (for updating if needed)
        sha = None
        check_resp = requests.get(f"{url}?ref={branch}", headers=headers, timeout=10)
        if check_resp.status_code == 200:
            sha = check_resp.json().get("sha")

        payload: Dict[str, Any] = {
            "message": f"chore(backup): forensic snapshot {file_path.name} [{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}]",
            "content": b64_content,
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha

        put_resp = requests.put(url, headers=headers, json=payload, timeout=60)
        return put_resp.status_code in (200, 201)
    except Exception as e:
        print(f"[GitHub Upload Error] {e}")
        return False


class CaseRetentionManager:
    """Gestor integral de capacidad, retención y respaldo tar.gz para DFIR-IRIS Datastore."""

    def __init__(self, storage_dir: str = "storage/backups"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.client = IrisApiClient()

    def get_capacity_summary(self, db: Session) -> Dict[str, Any]:
        """Calcula el consumo real del Datastore, identifica casos pesados y candidatos a retención."""
        cases = self.client.list_cases()
        total_evidences = 0
        total_bytes = 0
        case_stats = []

        now = datetime.now(timezone.utc)

        for c in cases:
            cid = c.get("case_id")
            if not cid:
                continue

            evs = self.client.list_case_evidences(cid)
            c_ev_count = len(evs)
            c_bytes = 0
            for ev in evs:
                sz = ev.get("file_size") or ev.get("size") or 0
                c_bytes += int(sz)

            total_evidences += c_ev_count
            total_bytes += c_bytes

            arc = db.query(CaseArchiveRecord).filter(CaseArchiveRecord.iris_case_id == cid).first()

            open_date_str = c.get("case_open_date")
            age_days = 0
            if open_date_str:
                try:
                    dt = datetime.fromisoformat(open_date_str.replace("Z", "+00:00"))
                    age_days = (now - dt).days
                except Exception:
                    pass

            state_name = c.get("state_name") or c.get("status_name") or "Open"
            is_closed = state_name.lower() in ("closed", "cerrado", "resolved", "post-incident")
            is_candidate = (is_closed and age_days >= 30) or (age_days >= 90 and c_bytes > 0)

            case_stats.append({
                "case_id": cid,
                "case_name": c.get("case_name"),
                "state_name": state_name,
                "customer_name": c.get("customer_name"),
                "evidence_count": c_ev_count,
                "total_bytes": c_bytes,
                "total_bytes_human": _format_bytes(c_bytes),
                "age_days": age_days,
                "is_closed": is_closed,
                "is_candidate": is_candidate,
                "archive_status": arc.archive_status if arc else "active",
                "backup_path": arc.backup_path if arc else None,
                "backup_sha256": arc.backup_sha256 if arc else None,
                "pruned_at": arc.pruned_at.isoformat() if arc and arc.pruned_at else None,
            })

        case_stats.sort(key=lambda x: x["total_bytes"], reverse=True)

        return {
            "status": "ok",
            "total_cases_analyzed": len(cases),
            "total_evidences": total_evidences,
            "total_bytes": total_bytes,
            "total_bytes_human": _format_bytes(total_bytes),
            "heavy_cases": case_stats[:10],
            "candidates": [cs for cs in case_stats if cs["is_candidate"] and cs["archive_status"] != "pruned"],
            "all_cases": case_stats,
            "config": get_retention_config(),
        }

    def create_case_backup(
        self,
        case_id: int,
        db: Session,
        username: str = "SOC Analyst",
        backup_type: str = "local",
    ) -> Dict[str, Any]:
        """Descarga evidencias y notas de DFIR-IRIS, genera manifest.json y empaqueta en .tar.gz verificado."""
        iris_case = self.client.get_case_full(case_id)
        if not iris_case:
            raise ValueError(f"No se pudo obtener información del Caso #{case_id} desde DFIR-IRIS")

        case_name = iris_case.get("case_name", f"case_{case_id}")
        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in case_name)[:40]
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        tmp_dir = self.storage_dir / f"tmp_case_{case_id}_{timestamp_str}"
        evidences_dir = tmp_dir / "evidences"
        evidences_dir.mkdir(parents=True, exist_ok=True)

        evidences = self.client.list_case_evidences(case_id)
        manifest_files = []
        total_bytes = 0

        try:
            for ev in evidences:
                fid = ev.get("file_id") or ev.get("id")
                fname = ev.get("file_original_name") or ev.get("filename") or f"evidence_{fid}"
                if not fid:
                    continue

                content = self.client.download_datastore_file(case_id, fid)
                if content:
                    fpath = evidences_dir / fname
                    fpath.write_bytes(content)
                    f_size = len(content)
                    total_bytes += f_size
                    f_sha256 = hashlib.sha256(content).hexdigest().upper()
                    manifest_files.append({
                        "file_id": fid,
                        "filename": fname,
                        "file_size": f_size,
                        "file_size_human": _format_bytes(f_size),
                        "sha256": f_sha256,
                        "description": ev.get("file_description", ""),
                        "tags": ev.get("file_tags", ""),
                        "date_added": ev.get("file_date_added", ""),
                    })

            notes = iris_case.get("notes") or []
            timeline = self.client.list_case_timeline(case_id)
            tasks = self.client.list_case_tasks(case_id)
            iocs = self.client.list_case_iocs(case_id)

            manifest = {
                "format_version": "DFIR-IRIS-SOC-BACKUP-v1.0",
                "case_id": case_id,
                "case_name": case_name,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "exported_by": username,
                "backup_type": backup_type,
                "case_metadata": {
                    "customer_id": iris_case.get("customer_id"),
                    "state_name": iris_case.get("state_name"),
                    "case_description": iris_case.get("case_description"),
                    "open_date": iris_case.get("case_open_date"),
                },
                "evidence_manifest": manifest_files,
                "notes": notes,
                "timeline": timeline,
                "tasks": tasks,
                "iocs": iocs,
            }

            manifest_path = tmp_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

            tar_filename = f"case_{case_id}_{clean_name}_{timestamp_str}.tar.gz"
            tar_path = self.storage_dir / tar_filename

            with tarfile.open(tar_path, "w:gz") as tar:
                tar.add(tmp_dir, arcname=f"case_{case_id}_{clean_name}")

            tar_bytes = tar_path.read_bytes()
            tar_sha256 = hashlib.sha256(tar_bytes).hexdigest().upper()
            tar_size = len(tar_bytes)

            # Check if remote transfer configured
            cfg = get_retention_config()
            remote_transferred = False
            if cfg.get("destination") == "ftp" and cfg.get("ftp", {}).get("host"):
                remote_transferred = transfer_to_remote_ftp(tar_path, cfg["ftp"])
            elif cfg.get("destination") == "gdrive" and cfg.get("gdrive", {}).get("service_account_json"):
                remote_transferred = transfer_to_remote_gdrive(tar_path, cfg["gdrive"])
            elif cfg.get("destination") == "github" and cfg.get("github", {}).get("token") and cfg.get("github", {}).get("repo"):
                remote_transferred = transfer_to_remote_github(tar_path, cfg["github"])

            arc = db.query(CaseArchiveRecord).filter(CaseArchiveRecord.iris_case_id == case_id).first()
            now_dt = datetime.now(timezone.utc)
            if not arc:
                arc = CaseArchiveRecord(
                    iris_case_id=case_id,
                    archive_status="exported",
                    backup_type=backup_type,
                    backup_path=str(tar_path),
                    backup_sha256=tar_sha256,
                    manifest_json=manifest,
                    evidence_count=len(manifest_files),
                    evidence_total_bytes=total_bytes,
                    archived_at=now_dt,
                    approved_by=username,
                    created_at=now_dt,
                    updated_at=now_dt,
                )
                db.add(arc)
            else:
                arc.archive_status = "exported"
                arc.backup_path = str(tar_path)
                arc.backup_sha256 = tar_sha256
                arc.manifest_json = manifest
                arc.evidence_count = len(manifest_files)
                arc.evidence_total_bytes = total_bytes
                arc.archived_at = now_dt
                arc.approved_by = username
                arc.updated_at = now_dt

            db.commit()

            return {
                "status": "ok",
                "case_id": case_id,
                "backup_filename": tar_filename,
                "backup_path": str(tar_path),
                "backup_sha256": tar_sha256,
                "backup_size": tar_size,
                "backup_size_human": _format_bytes(tar_size),
                "evidences_count": len(manifest_files),
                "evidences_total_bytes": total_bytes,
                "evidences_total_bytes_human": _format_bytes(total_bytes),
                "remote_transferred": remote_transferred,
                "verified": True,
            }
        finally:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

    def prune_case_binaries(
        self,
        case_id: int,
        db: Session,
        username: str = "SOC Analyst",
    ) -> Dict[str, Any]:
        """Elimina los archivos binarios pesados del Datastore de IRIS verificando el respaldo previo."""
        arc = db.query(CaseArchiveRecord).filter(CaseArchiveRecord.iris_case_id == case_id).first()
        if not arc or not arc.backup_path or not arc.backup_sha256:
            raise ValueError(f"No existe un respaldo verificado para el Caso #{case_id}. Debe generar el respaldo antes de purgar.")

        backup_file = Path(arc.backup_path)
        if not backup_file.is_file():
            raise ValueError(f"El archivo de respaldo {arc.backup_path} no se encuentra en el almacenamiento.")

        current_sha256 = hashlib.sha256(backup_file.read_bytes()).hexdigest().upper()
        if current_sha256 != arc.backup_sha256:
            raise ValueError("Fallo de integridad: El SHA-256 del archivo de respaldo no coincide con el registrado.")

        manifest = arc.manifest_json or {}
        files = manifest.get("evidence_manifest") or []
        deleted_count = 0
        freed_bytes = 0

        for f in files:
            fid = f.get("file_id")
            if not fid:
                continue
            res = self.client.delete_datastore_file(case_id, fid)
            if res.get("status") == "deleted":
                deleted_count += 1
                freed_bytes += f.get("file_size", 0)

        now_dt = datetime.now(timezone.utc)
        arc.archive_status = "pruned"
        arc.pruned_at = now_dt
        arc.approved_by = username
        arc.updated_at = now_dt
        db.commit()

        tombstone_content = (
            f"## Purgado Forense de Binarios del Datastore\n\n"
            f"- **Fecha de Operación**: {now_dt.isoformat()}\n"
            f"- **Analista Responsable**: `{username}`\n"
            f"- **Respaldo Verificado**: `{backup_file.name}`\n"
            f"- **SHA-256 Respaldo**: `{arc.backup_sha256}`\n"
            f"- **Archivos Purgados**: {deleted_count}\n"
            f"- **Espacio Liberado**: {_format_bytes(freed_bytes)}\n\n"
            f"> *Los metadatos, identificadores y hashes SHA-256 de cada archivo original se conservan íntegros en este expediente oficial.*"
        )
        self.client.ensure_structured_note(
            case_id=case_id,
            directory_name="Documentación SOC v3.1",
            note_title="05 Certificado de Purgado y Respaldo",
            note_content=tombstone_content,
            update_if_exists=True,
        )

        return {
            "status": "ok",
            "case_id": case_id,
            "deleted_count": deleted_count,
            "freed_bytes": freed_bytes,
            "freed_bytes_human": _format_bytes(freed_bytes),
            "backup_path": str(backup_file),
            "backup_sha256": arc.backup_sha256,
        }

    def start_background_bulk_rotation(
        self,
        scope: str = "all",  # "all", "closed_only", "age_days"
        action: str = "backup_only",  # "backup_only", "backup_and_prune"
        min_age_days: int = 90,
        username: str = "SOC Analyst",
    ) -> str:
        """Inicia una tarea asíncrona en segundo plano para respaldo y/o rotación masiva."""
        job_id = f"rot_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc)

        JOBS_REGISTRY[job_id] = {
            "job_id": job_id,
            "job_type": "bulk_rotation",
            "status": "running",
            "scope": scope,
            "action": action,
            "min_age_days": min_age_days,
            "username": username,
            "progress_pct": 0,
            "message": "Iniciando análisis de casos para rotación...",
            "processed_cases": 0,
            "total_cases": 0,
            "total_freed_bytes": 0,
            "created_backups": [],
            "started_at": now.isoformat(),
            "completed_at": None,
            "error": None,
        }

        # Run thread
        t = threading.Thread(
            target=self._run_bulk_rotation_worker,
            args=(job_id, scope, action, min_age_days, username),
            daemon=True,
        )
        t.start()
        return job_id

    def _run_bulk_rotation_worker(
        self,
        job_id: str,
        scope: str,
        action: str,
        min_age_days: int,
        username: str,
    ):
        db = SessionLocal()
        now = datetime.now(timezone.utc)
        try:
            cases = self.client.list_cases()
            target_cases = []

            for c in cases:
                cid = c.get("case_id")
                if not cid:
                    continue

                state_name = (c.get("state_name") or c.get("status_name") or "Open").lower()
                is_closed = state_name in ("closed", "cerrado", "resolved", "post-incident")

                age_days = 0
                open_date_str = c.get("case_open_date")
                if open_date_str:
                    try:
                        dt = datetime.fromisoformat(open_date_str.replace("Z", "+00:00"))
                        age_days = (now - dt).days
                    except Exception:
                        pass

                if scope == "all":
                    target_cases.append(cid)
                elif scope == "closed_only" and is_closed:
                    target_cases.append(cid)
                elif scope == "age_days" and age_days >= min_age_days:
                    target_cases.append(cid)

            total = len(target_cases)
            JOBS_REGISTRY[job_id]["total_cases"] = total

            if total == 0:
                JOBS_REGISTRY[job_id]["status"] = "completed"
                JOBS_REGISTRY[job_id]["progress_pct"] = 100
                JOBS_REGISTRY[job_id]["message"] = "No se encontraron casos que coincidan con el criterio seleccionado."
                JOBS_REGISTRY[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
                return

            created_backups = []
            total_freed = 0

            for idx, cid in enumerate(target_cases):
                pct = int(((idx) / total) * 90)
                JOBS_REGISTRY[job_id]["progress_pct"] = pct
                JOBS_REGISTRY[job_id]["message"] = f"Procesando Caso #{cid} ({idx + 1} de {total})..."

                try:
                    res_backup = self.create_case_backup(cid, db, username=username)
                    created_backups.append(res_backup.get("backup_path"))

                    if action == "backup_and_prune":
                        res_prune = self.prune_case_binaries(cid, db, username=username)
                        total_freed += res_prune.get("freed_bytes", 0)
                except Exception as e:
                    print(f"[Retention Job {job_id}] Error en Caso #{cid}: {e}")

                JOBS_REGISTRY[job_id]["processed_cases"] = idx + 1
                JOBS_REGISTRY[job_id]["total_freed_bytes"] = total_freed

            # Create Master Archive if scope is all
            if scope == "all" and created_backups:
                JOBS_REGISTRY[job_id]["message"] = "Empaquetando archivo maestro general..."
                master_tar_name = f"general_backup_all_{now.strftime('%Y%m%d_%H%M%S')}.tar.gz"
                master_tar_path = self.storage_dir / master_tar_name
                with tarfile.open(master_tar_path, "w:gz") as tar:
                    for b_path in created_backups:
                        p = Path(b_path)
                        if p.is_file():
                            tar.add(p, arcname=p.name)

                cfg = get_retention_config()
                if cfg.get("destination") == "ftp" and cfg.get("ftp", {}).get("host"):
                    transfer_to_remote_ftp(master_tar_path, cfg["ftp"])
                elif cfg.get("destination") == "gdrive" and cfg.get("gdrive", {}).get("service_account_json"):
                    transfer_to_remote_gdrive(master_tar_path, cfg["gdrive"])

            JOBS_REGISTRY[job_id]["status"] = "completed"
            JOBS_REGISTRY[job_id]["progress_pct"] = 100
            JOBS_REGISTRY[job_id]["message"] = f"Rotación completada exitosamente. {total} casos respaldados. {_format_bytes(total_freed)} liberados de Datastore."
            JOBS_REGISTRY[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            JOBS_REGISTRY[job_id]["status"] = "failed"
            JOBS_REGISTRY[job_id]["error"] = str(e)
            JOBS_REGISTRY[job_id]["message"] = f"Fallo en la ejecución de rotación: {str(e)}"
        finally:
            db.close()
