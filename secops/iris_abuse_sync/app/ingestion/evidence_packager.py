import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.ingestion.base import AttachmentItem, NormalizedIngestPayload


def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_slug(val: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", (val or "item").strip())
    return cleaned[:80] or "item"


class EvidencePackageBuilder:
    """Construye y preserva el paquete de evidencia forense inicial con hashes SHA-256."""

    @staticmethod
    def build_package(
        payload: NormalizedIngestPayload,
        raw_bytes: Optional[bytes] = None,
        original_filename: Optional[str] = None,
        extra_attachments: Optional[List[tuple[str, bytes, str]]] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        date_prefix = now.strftime("%Y%m%d_%H%M%S")
        org = (payload.organization or "NBX").upper()
        pkg_folder_name = f"{date_prefix}_{_safe_slug(payload.source_type)}_{_safe_slug(payload.source_id)}"
        pkg_dir = settings.EVIDENCE_STORAGE_DIR / org / pkg_folder_name
        pkg_dir.mkdir(parents=True, exist_ok=True)

        files_manifest: List[Dict[str, Any]] = []

        # 1. Guardar archivo original (PDF, EML, TXT) o volcado del texto original
        if raw_bytes is not None:
            fname = _safe_slug(original_filename or f"original_{payload.source_id}.bin")
            raw_path = pkg_dir / fname
            raw_path.write_bytes(raw_bytes)
            sha256_primary = compute_sha256_bytes(raw_bytes)
            files_manifest.append(
                {
                    "role": "primary_raw_report",
                    "filename": fname,
                    "path": str(raw_path),
                    "size_bytes": len(raw_bytes),
                    "sha256": sha256_primary,
                }
            )
        else:
            content_bytes = (payload.original_content or "").encode("utf-8")
            fname = f"original_report_{_safe_slug(payload.source_id)}.txt"
            raw_path = pkg_dir / fname
            raw_path.write_bytes(content_bytes)
            sha256_primary = compute_sha256_bytes(content_bytes)
            files_manifest.append(
                {
                    "role": "primary_text_report",
                    "filename": fname,
                    "path": str(raw_path),
                    "size_bytes": len(content_bytes),
                    "sha256": sha256_primary,
                }
            )

        # 2. Guardar adjuntos adicionales si existen (ej. adjuntos MIME de .eml o xarf.json)
        if extra_attachments:
            att_dir = pkg_dir / "attachments"
            att_dir.mkdir(parents=True, exist_ok=True)
            for att_name, att_bytes, att_ctype in extra_attachments:
                safe_att = _safe_slug(att_name)
                att_path = att_dir / safe_att
                att_path.write_bytes(att_bytes)
                att_sha = compute_sha256_bytes(att_bytes)
                files_manifest.append(
                    {
                        "role": "attachment",
                        "filename": safe_att,
                        "content_type": att_ctype,
                        "path": str(att_path),
                        "size_bytes": len(att_bytes),
                        "sha256": att_sha,
                    }
                )
                payload.attachments.append(
                    AttachmentItem(
                        filename=safe_att,
                        content_type=att_ctype,
                        size_bytes=len(att_bytes),
                        sha256=att_sha,
                        local_path=str(att_path),
                    )
                )

        # 3. Guardar snapshot normalizado JSON y manifiesto de cadena de custodia
        normalized_path = pkg_dir / "normalized_payload.json"
        normalized_bytes = json.dumps(payload.model_dump(mode="json"), indent=2, ensure_ascii=False).encode("utf-8")
        normalized_path.write_bytes(normalized_bytes)

        manifest = {
            "package_version": "3.0",
            "created_at": now.isoformat(),
            "organization": org,
            "source_type": payload.source_type,
            "source_id": payload.source_id,
            "abuse_ticket_id": payload.abuse_ticket_id,
            "primary_domain": payload.primary_domain,
            "primary_sha256": sha256_primary,
            "package_dir": str(pkg_dir),
            "files": files_manifest,
        }
        manifest_path = pkg_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        return {
            "package_dir": str(pkg_dir),
            "primary_file_path": str(raw_path),
            "primary_filename": fname,
            "primary_sha256": sha256_primary,
            "manifest_path": str(manifest_path),
            "files": files_manifest,
        }

