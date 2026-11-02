from datetime import datetime, timezone
import hashlib
import io
import json
import mimetypes
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import requests
import urllib3

from app.core.config import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IOC_TYPE_MAP = {
    "domain": 20,
    "ip-dst": 76,
    "ip-src": 79,
    "url": 141,
    "email-src": 28,
    "hostname": 67,
    "sha256": 114,
}

ASSET_TYPE_MAP = {
    "account": 1,
    "linux_server": 3,
    "linux_account": 5,
    "windows_server": 9,
    "waf": 15,
}

TASK_STATUS_MAP = {
    "propuesta": 1,      # To do
    "autorizada": 1,     # To do
    "pendiente": 1,      # To do
    "en_ejecucion": 2,   # In progress
    "ejecutada": 4,      # Done
    "verificada": 4,     # Done
    "cancelada": 5,      # Canceled
    "no_aplicable": 5,   # Canceled
}


class IrisApiClient:
    """Cliente completo para DFIR-IRIS v2.4.29 (API 2.0.5)."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or settings.IRIS_URL).rstrip("/")
        self.api_key = api_key or settings.IRIS_API_KEY
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = settings.VERIFY_SSL
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None, timeout: int = 12) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", params=params, timeout=timeout)

    def _post(self, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 15) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", json=payload or {}, timeout=timeout)

    def check_connection(self) -> Dict[str, Any]:
        if not self.api_key:
            return {"ok": False, "error": "IRIS_API_KEY no configurada."}
        try:
            r = self._get("/api/versions", timeout=8)
            if r.status_code == 200:
                v_data = r.json().get("data", {})
                return {
                    "ok": True,
                    "url": self.base_url,
                    "iris_version": v_data.get("iris_current", "v2.4.29"),
                    "api_version": v_data.get("api_current", "2.0.5"),
                }
            return {"ok": False, "status_code": r.status_code, "error": r.text[:250]}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ==========================================================
    # GESTIÓN DE ALERTAS DFIR-IRIS (/alerts/*)
    # ==========================================================
    def list_alerts(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
        customer_id: Optional[int] = None,
        status_id: Optional[int] = None,
        severity_id: Optional[int] = None,
        classification_id: Optional[int] = None,
        source: Optional[str] = None,
        title: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"page": page, "per_page": per_page, "sort": "desc"}
        if customer_id:
            params["alert_customer_id"] = customer_id
        if status_id:
            params["alert_status_id"] = status_id
        if severity_id:
            params["alert_severity_id"] = severity_id
        if classification_id:
            params["alert_classification_id"] = classification_id
        if source:
            params["alert_source"] = source
        if title:
            params["alert_title"] = title
        if tags:
            params["alert_tags"] = tags

        r = self._get("/alerts/filter", params=params)
        r.raise_for_status()
        data = r.json().get("data", {})
        if isinstance(data, dict):
            return data
        return {"total": 0, "alerts": [], "current_page": 1, "last_page": 1}

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        r = self._get(f"/alerts/{alert_id}")
        if r.status_code == 200:
            return r.json().get("data")
        # Fallback vía /alerts/filter?alert_ids=
        r2 = self._get("/alerts/filter", params={"alert_ids": str(alert_id)})
        if r2.status_code == 200:
            alerts = (r2.json().get("data") or {}).get("alerts") or []
            if alerts:
                return alerts[0]
        return None

    def create_alert(
        self,
        *,
        title: str,
        description: str,
        customer_id: int,
        severity_id: int = 1,
        status_id: int = 2,  # 2 = New
        classification_id: Optional[int] = 30,
        source: str = "SOC Abuse Intake",
        source_ref: str = "",
        source_link: str = "",
        source_content: Optional[Dict[str, Any]] = None,
        tags: str = "abuse,soc",
        iocs: Optional[List[Dict[str, Any]]] = None,
        assets: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "alert_title": title,
            "alert_description": description,
            "alert_customer_id": customer_id,
            "alert_severity_id": severity_id,
            "alert_status_id": status_id,
            "alert_source": source,
            "alert_source_ref": source_ref or title[:64],
            "alert_source_link": source_link or "",
            "alert_tags": tags,
            "alert_note": "",
            "alert_context": context or {},
            "alert_source_content": source_content or {},
        }
        if classification_id:
            payload["alert_classification_id"] = classification_id
        if iocs:
            payload["alert_iocs"] = iocs
        if assets:
            payload["alert_assets"] = assets

        r = self._post("/alerts/add", payload=payload)
        r.raise_for_status()
        return r.json().get("data", {})

    def update_alert(self, alert_id: int, fields: Dict[str, Any]) -> Dict[str, Any]:
        current = self.get_alert(alert_id) or {}
        payload = {
            "alert_title": fields.get("alert_title", current.get("alert_title", f"Alert #{alert_id}")),
            "alert_description": fields.get("alert_description", current.get("alert_description", "")),
            "alert_severity_id": fields.get("alert_severity_id", current.get("alert_severity_id", 1)),
            "alert_status_id": fields.get("alert_status_id", current.get("alert_status_id", 2)),
            "alert_customer_id": fields.get("alert_customer_id", current.get("alert_customer_id", 2)),
            "alert_classification_id": fields.get("alert_classification_id", current.get("alert_classification_id")),
            "alert_note": fields.get("alert_note", current.get("alert_note", "")),
            "alert_tags": fields.get("alert_tags", current.get("alert_tags", "abuse,soc")),
        }
        r = self._post(f"/alerts/update/{alert_id}", payload=payload)
        r.raise_for_status()
        return r.json().get("data", {})

    def escalate_alert(
        self,
        alert_id: int,
        *,
        case_title: str,
        iocs_import_list: Optional[List[str]] = None,
        assets_import_list: Optional[List[str]] = None,
        note: str = "",
        import_as_event: bool = True,
        case_tags: str = "abuse,soc,escalated",
        case_template_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        alert_data = self.get_alert(alert_id) or {}
        if iocs_import_list is None:
            iocs_import_list = [
                i.get("ioc_uuid")
                for i in (alert_data.get("iocs") or [])
                if isinstance(i, dict) and i.get("ioc_uuid")
            ]
        if assets_import_list is None:
            assets_import_list = [
                a.get("asset_uuid")
                for a in (alert_data.get("assets") or [])
                if isinstance(a, dict) and a.get("asset_uuid")
            ]

        payload: Dict[str, Any] = {
            "case_title": case_title,
            "iocs_import_list": iocs_import_list,
            "assets_import_list": assets_import_list,
            "note": note,
            "import_as_event": import_as_event,
            "case_tags": case_tags,
        }
        if case_template_id:
            payload["case_template_id"] = str(case_template_id)

        r = self._post(f"/alerts/escalate/{alert_id}", payload=payload)
        r.raise_for_status()
        return r.json().get("data", {})

    def merge_alert(
        self,
        alert_id: int,
        *,
        target_case_id: int,
        iocs_import_list: Optional[List[str]] = None,
        assets_import_list: Optional[List[str]] = None,
        note: str = "",
        import_as_event: bool = True,
    ) -> Dict[str, Any]:
        alert_data = self.get_alert(alert_id) or {}
        if iocs_import_list is None:
            iocs_import_list = [
                i.get("ioc_uuid")
                for i in (alert_data.get("iocs") or [])
                if isinstance(i, dict) and i.get("ioc_uuid")
            ]
        if assets_import_list is None:
            assets_import_list = [
                a.get("asset_uuid")
                for a in (alert_data.get("assets") or [])
                if isinstance(a, dict) and a.get("asset_uuid")
            ]

        payload = {
            "target_case_id": target_case_id,
            "iocs_import_list": iocs_import_list,
            "assets_import_list": assets_import_list,
            "note": note,
            "import_as_event": import_as_event,
        }
        r = self._post(f"/alerts/merge/{alert_id}", payload=payload)
        r.raise_for_status()
        return r.json().get("data", {})

    # ==========================================================
    # GESTIÓN INTEGRAL DE CASOS Y SUB-RECURSOS (/manage/cases/* y /case/*)
    # ==========================================================
    def list_cases(self) -> List[Dict[str, Any]]:
        r = self._get("/manage/cases/list")
        r.raise_for_status()
        cases = r.json().get("data", [])
        cases.sort(key=lambda c: c.get("case_id", 0), reverse=True)
        return cases

    def list_case_states(self) -> List[Dict[str, Any]]:
        """Devuelve el catálogo oficial de estados de caso configurados en DFIR-IRIS."""
        try:
            r = self._get("/manage/case-states/list")
            if r.status_code == 200:
                data = r.json()
                return data.get("data") or []
        except Exception:
            pass
        return [
            {"state_id": 1, "state_name": "Unspecified", "state_description": "Unspecified"},
            {"state_id": 2, "state_name": "In progress", "state_description": "Case is being investigated"},
            {"state_id": 3, "state_name": "Open", "state_description": "Case is open"},
            {"state_id": 4, "state_name": "Containment", "state_description": "Containment is in progress"},
            {"state_id": 5, "state_name": "Eradication", "state_description": "Eradication is in progress"},
            {"state_id": 6, "state_name": "Recovery", "state_description": "Recovery is in progress"},
            {"state_id": 7, "state_name": "Post-Incident", "state_description": "Post-incident phase"},
            {"state_id": 8, "state_name": "Reporting", "state_description": "Reporting is in progress"},
            {"state_id": 9, "state_name": "Closed", "state_description": "Case is closed"},
        ]

    def update_case_state(self, case_id: int, state_id: int) -> Dict[str, Any]:
        """Sincroniza el cambio de estado del caso en DFIR-IRIS vía /manage/cases/update/{cid}?cid={cid}."""
        r = self._post(
            f"/manage/cases/update/{case_id}?cid={case_id}",
            payload={"state_id": state_id, "status_id": state_id},
        )
        if r.status_code == 200:
            return {"status": "ok", "state_id": state_id, "data": r.json().get("data")}
        raise RuntimeError(f"Error actualizando estado en DFIR-IRIS ({r.status_code}): {r.text[:200]}")

    def delete_case(self, case_id: int) -> Dict[str, Any]:
        """Elimina un caso en DFIR-IRIS vía /manage/cases/delete/{cid}?cid={cid}."""
        r = self._post(f"/manage/cases/delete/{case_id}?cid={case_id}")
        if r.status_code == 200:
            return r.json().get("data", {})
        raise RuntimeError(f"Error eliminando caso {case_id} en IRIS ({r.status_code}): {r.text[:200]}")

    def get_case(self, case_id: int) -> Dict[str, Any]:
        """Alias para recuperar datos de caso en DFIR-IRIS."""
        return self.get_case_full(case_id)

    def get_case_full(self, case_id: int) -> Dict[str, Any]:
        """Recupera un caso completo de DFIR-IRIS: metadatos, notas, IOCs, activos, tareas, evidencias y timeline."""
        base_case: Dict[str, Any] = {}
        r = self._get(f"/manage/cases/{case_id}")
        if r.status_code == 200:
            base_case = r.json().get("data") or {}
        if not base_case:
            for c in self.list_cases():
                if c.get("case_id") == case_id:
                    base_case = dict(c)
                    break

        r_sum = self._get("/case/summary/fetch", params={"cid": case_id})
        if r_sum.status_code == 200:
            sum_data = r_sum.json().get("data") or {}
            if sum_data.get("case_description"):
                base_case["case_description"] = sum_data["case_description"]

        notes = self.list_case_notes(case_id)
        iocs = self.list_case_iocs(case_id)
        assets = self.list_case_assets(case_id)
        tasks = self.list_case_tasks(case_id)
        evidences = self.list_case_evidences(case_id)
        timeline = self.list_case_timeline(case_id)

        base_case["notes"] = notes
        base_case["iocs"] = iocs
        base_case["assets"] = assets
        base_case["tasks"] = tasks
        base_case["evidences"] = evidences
        base_case["timeline"] = timeline
        return base_case

    def list_case_notes(self, case_id: int) -> List[Dict[str, Any]]:
        notes: List[Dict[str, Any]] = []
        r_dirs = self._get("/case/notes/directories/filter", params={"cid": case_id})
        if r_dirs.status_code == 200:
            dirs = r_dirs.json().get("data") or []
            for d in dirs:
                dir_id = d.get("id")
                dir_name = d.get("name", "General")
                for n_meta in d.get("notes") or []:
                    nid = n_meta.get("id")
                    if not nid:
                        continue
                    rn = self._get(f"/case/notes/{nid}", params={"cid": case_id})
                    if rn.status_code == 200:
                        nd = rn.json().get("data") or {}
                        notes.append(
                            {
                                "note_id": nid,
                                "directory_id": dir_id,
                                "directory_name": dir_name,
                                "note_title": nd.get("note_title", n_meta.get("title", "")),
                                "note_content": nd.get("note_content", ""),
                                "note_lastupdate": nd.get("note_lastupdate"),
                            }
                        )
        return notes

    def list_case_iocs(self, case_id: int) -> List[Dict[str, Any]]:
        r = self._get("/case/ioc/list", params={"cid": case_id})
        if r.status_code == 200:
            return (r.json().get("data") or {}).get("ioc") or []
        return []

    def list_case_assets(self, case_id: int) -> List[Dict[str, Any]]:
        r = self._get("/case/assets/list", params={"cid": case_id})
        if r.status_code == 200:
            return (r.json().get("data") or {}).get("assets") or []
        return []

    def list_case_tasks(self, case_id: int) -> List[Dict[str, Any]]:
        r = self._get("/case/tasks/list", params={"cid": case_id})
        if r.status_code == 200:
            return (r.json().get("data") or {}).get("tasks") or []
        return []

    def list_case_evidences(self, case_id: int) -> List[Dict[str, Any]]:
        r = self._get("/case/evidences/list", params={"cid": case_id})
        if r.status_code == 200:
            return (r.json().get("data") or {}).get("evidences") or []
        return []

    def add_case_evidence(
        self,
        case_id: int,
        filename: str,
        file_size: int,
        file_hash: str,
        description: str = "",
        custom_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Registra metadatos de evidencia forense en DFIR-IRIS vía /case/evidences/add?cid={cid}."""
        body = {
            "filename": filename,
            "file_size": file_size,
            "file_description": description,
            "file_hash": file_hash,
            "custom_attributes": custom_attributes or {},
            "cid": case_id,
        }
        r = self._post(f"/case/evidences/add?cid={case_id}", payload=body)
        if r.status_code in (200, 201):
            return r.json().get("data", {})
        raise RuntimeError(f"Error registrando evidencia en IRIS ({r.status_code}): {r.text[:200]}")

    def list_case_timeline(self, case_id: int) -> List[Dict[str, Any]]:
        r = self._get("/case/timeline/events/list", params={"cid": case_id})
        if r.status_code == 200:
            return (r.json().get("data") or {}).get("timeline") or []
        return []

    # ==========================================================
    # SINCRONIZACIÓN IDEMPOTENTE (SIN DUPLICADOS NI BORRADO DESTRUCTIVO)
    # ==========================================================
    def ensure_ioc(
        self,
        case_id: int,
        *,
        value: str,
        ioc_type: str = "domain",
        description: str = "",
        tags: str = "abuse,soc",
        tlp_id: int = 2,
    ) -> Dict[str, Any]:
        clean_val = (value or "").strip()
        if not clean_val:
            return {"status": "skipped_empty"}
        existing = self.list_case_iocs(case_id)
        for item in existing:
            if (item.get("ioc_value") or "").strip().lower() == clean_val.lower():
                return {"status": "exists", "ioc_id": item.get("ioc_id"), "ioc_value": clean_val}

        type_id = IOC_TYPE_MAP.get(ioc_type, 20)
        payload = {
            "ioc_value": clean_val,
            "ioc_type_id": type_id,
            "ioc_description": description or f"IOC ({ioc_type})",
            "ioc_tlp_id": tlp_id,
            "ioc_tags": tags,
        }
        r = self._post(f"/case/ioc/add?cid={case_id}", payload=payload)
        if r.status_code in (200, 201):
            return {"status": "created", "data": r.json().get("data")}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}

    def ensure_asset(
        self,
        case_id: int,
        *,
        asset_name: str,
        asset_type_key: str = "linux_server",
        description: str = "",
        domain: str = "",
        ip: str = "",
        compromised: bool = False,
    ) -> Dict[str, Any]:
        clean_name = (asset_name or "").strip()
        if not clean_name:
            return {"status": "skipped_empty"}
        existing = self.list_case_assets(case_id)
        for item in existing:
            if (item.get("asset_name") or "").strip().lower() == clean_name.lower():
                return {"status": "exists", "asset_id": item.get("asset_id"), "asset_name": clean_name}

        asset_type_id = ASSET_TYPE_MAP.get(asset_type_key, 3)
        payload = {
            "asset_name": clean_name,
            "asset_type_id": asset_type_id,
            "asset_description": description or f"Activo registrado por SOC v3.0 ({clean_name})",
            "asset_domain": domain or "",
            "asset_ip": ip or "",
            "asset_compromise_status_id": 1 if compromised else 2,
            "asset_tags": "soc,asset",
            "analysis_status_id": 2,
        }
        r = self._post(f"/case/assets/add?cid={case_id}", payload=payload)
        if r.status_code in (200, 201):
            return {"status": "created", "data": r.json().get("data")}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}

    def ensure_task(
        self,
        case_id: int,
        *,
        title: str,
        description: str = "",
        action_status: str = "pendiente",
        assignees_id: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        clean_title = (title or "").strip()
        if not clean_title:
            return {"status": "skipped_empty"}
        status_id = TASK_STATUS_MAP.get(action_status, 1)
        existing = self.list_case_tasks(case_id)
        for t in existing:
            if (t.get("task_title") or "").strip().lower() == clean_title.lower():
                tid = t.get("id") or t.get("task_id")
                if t.get("task_status_id") != status_id and tid:
                    self._post(
                        f"/case/tasks/update/{tid}?cid={case_id}",
                        payload={
                            "task_title": clean_title,
                            "task_description": description or t.get("task_description", ""),
                            "task_status_id": status_id,
                            "task_assignees_id": assignees_id or [2],
                            "task_tags": "soc,playbook",
                        },
                    )
                    return {"status": "updated", "task_id": tid}
                return {"status": "exists", "task_id": tid}

        payload = {
            "task_title": clean_title,
            "task_description": description,
            "task_status_id": status_id,
            "task_assignees_id": assignees_id or [2],
            "task_tags": "soc,playbook",
        }
        r = self._post(f"/case/tasks/add?cid={case_id}", payload=payload)
        if r.status_code in (200, 201):
            return {"status": "created", "data": r.json().get("data")}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}

    def ensure_structured_note(
        self,
        case_id: int,
        *,
        directory_name: str,
        note_title: str,
        note_content: str,
        update_if_exists: bool = True,
    ) -> Dict[str, Any]:
        """Crea o actualiza una nota estructurada en un directorio dedicado sin tocar las notas históricas originales."""
        r_dirs = self._get("/case/notes/directories/filter", params={"cid": case_id})
        dirs = r_dirs.json().get("data") or [] if r_dirs.status_code == 200 else []
        target_dir_id = None
        existing_note_id = None

        for d in dirs:
            if (d.get("name") or "").strip().lower() == directory_name.strip().lower():
                target_dir_id = d.get("id")
                for nm in d.get("notes") or []:
                    if (nm.get("title") or "").strip().lower() == note_title.strip().lower():
                        existing_note_id = nm.get("id")
                        break
                break

        if not target_dir_id:
            r_add_dir = self._post(
                f"/case/notes/directories/add?cid={case_id}",
                payload={"name": directory_name, "parent_id": None},
            )
            if r_add_dir.status_code in (200, 201):
                target_dir_id = (r_add_dir.json().get("data") or {}).get("id")

        if existing_note_id:
            if update_if_exists:
                r_up = self._post(
                    f"/case/notes/update/{existing_note_id}?cid={case_id}",
                    payload={
                        "note_title": note_title,
                        "note_content": note_content,
                        "directory_id": target_dir_id,
                    },
                )
                return {"status": "updated", "note_id": existing_note_id, "code": r_up.status_code}
            return {"status": "exists", "note_id": existing_note_id}

        payload: Dict[str, Any] = {
            "note_title": note_title,
            "note_content": note_content,
        }
        if target_dir_id:
            payload["directory_id"] = target_dir_id
        r_new = self._post(f"/case/notes/add?cid={case_id}", payload=payload)
        if r_new.status_code in (200, 201):
            return {"status": "created", "data": r_new.json().get("data")}
        return {"status": "error", "code": r_new.status_code, "message": r_new.text[:200]}

    def update_case_note(
        self,
        case_id: int,
        note_id: int,
        note_content: str,
        note_title: Optional[str] = None,
        directory_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Actualiza el contenido y título de una nota existente en DFIR-IRIS."""
        payload: Dict[str, Any] = {
            "note_content": note_content,
        }
        if note_title is not None:
            payload["note_title"] = note_title
        if directory_id is not None:
            payload["directory_id"] = directory_id

        # Preservar note_title y directory_id si no se enviaron explícitamente
        if note_title is None or directory_id is None:
            r_cur = self._get(f"/case/notes/{note_id}", params={"cid": case_id})
            if r_cur.status_code == 200:
                cur_data = r_cur.json().get("data") or {}
                if note_title is None:
                    payload["note_title"] = cur_data.get("note_title", "")
                if directory_id is None:
                    cur_dir = cur_data.get("directory") or {}
                    if cur_dir.get("case_id") == case_id:
                        payload["directory_id"] = cur_dir.get("id")
                    else:
                        r_dirs = self._get("/case/notes/directories/filter", params={"cid": case_id})
                        dirs = r_dirs.json().get("data") or [] if r_dirs.status_code == 200 else []
                        if dirs:
                            payload["directory_id"] = dirs[0].get("id")

        r_up = self._post(f"/case/notes/update/{note_id}?cid={case_id}", payload=payload)
        if r_up.status_code in (200, 201):
            return {"status": "updated", "note_id": note_id, "code": r_up.status_code}
        return {"status": "error", "note_id": note_id, "code": r_up.status_code, "message": r_up.text[:200]}

    def ensure_timeline_event(
        self,
        case_id: int,
        *,
        title: str,
        content: str,
        event_date_iso: Optional[str] = None,
        category_id: int = 5,
    ) -> Dict[str, Any]:
        clean_title = (title or "").strip()
        if not clean_title:
            return {"status": "skipped_empty"}
        existing = self.list_case_timeline(case_id)
        for ev in existing:
            if (ev.get("event_title") or "").strip().lower() == clean_title.lower():
                return {"status": "exists", "event_id": ev.get("event_id")}

        dt_str = event_date_iso or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1]
        if "+" in dt_str:
            dt_str = dt_str.split("+")[0]
        if "." not in dt_str:
            dt_str = f"{dt_str}.000"

        payload = {
            "event_title": clean_title,
            "event_content": content,
            "event_date": dt_str,
            "event_tz": "+00:00",
            "event_category_id": category_id,
            "event_in_summary": True,
            "event_in_graph": True,
            "event_tags": "soc,timeline",
            "event_assets": [],
            "event_iocs": [],
        }
        r = self._post(f"/case/timeline/events/add?cid={case_id}", payload=payload)
        if r.status_code in (200, 201):
            return {"status": "created", "data": r.json().get("data")}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}

    # ==========================================================
    # DATASTORE FORENSE Y RETENCIÓN DE ARCHIVOS EN DFIR-IRIS
    # ==========================================================
    def get_datastore_folder_id(self, case_id: int, target_name: str = "Evidences") -> Optional[int]:
        """Obtiene el ID del directorio destino (ej. 'Evidences' o 'Images') en el árbol del datastore de IRIS."""
        try:
            r = self._get("/datastore/list/tree", params={"cid": case_id})
            if r.status_code != 200:
                return None
            tree = r.json().get("data", {})
            root_id = None

            def search_tree(nodes: dict) -> Optional[int]:
                nonlocal root_id
                for k, node in nodes.items():
                    if not isinstance(node, dict):
                        continue
                    nid = int(k.split("-")[1]) if "-" in k else None
                    if node.get("is_root") and root_id is None:
                        root_id = nid
                    if node.get("name", "").strip().lower() == target_name.strip().lower():
                        return nid
                    children = node.get("children", {})
                    if isinstance(children, dict) and children:
                        found = search_tree(children)
                        if found:
                            return found
                return None

            found_id = search_tree(tree)
            return found_id if found_id is not None else root_id
        except Exception:
            return None

    def upload_datastore_file(
        self,
        case_id: int,
        file_data: Any,
        filename: str,
        description: str = "",
        is_evidence: bool = True,
        is_ioc: bool = False,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Sube un archivo binario directamente al Datastore oficial de DFIR-IRIS."""
        if isinstance(file_data, (str, Path)):
            p = Path(file_data)
            if not p.is_file():
                return {"success": False, "error": f"Archivo no encontrado: {file_data}"}
            raw_bytes = p.read_bytes()
            if not filename:
                filename = p.name
        elif isinstance(file_data, io.BytesIO):
            raw_bytes = file_data.getvalue()
        elif isinstance(file_data, bytes):
            raw_bytes = file_data
        else:
            return {"success": False, "error": "Tipo de archivo no soportado"}

        file_size = len(raw_bytes)
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest().upper()
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or "application/octet-stream"

        target_folder = "Images" if mime_type.startswith("image/") else "Evidences"
        folder_id = self.get_datastore_folder_id(case_id, target_folder)
        if folder_id is None:
            folder_id = self.get_datastore_folder_id(case_id, "Evidences") or 0

        files = {
            "file_content": (filename, io.BytesIO(raw_bytes), mime_type)
        }
        data = {
            "file_original_name": filename,
            "file_password": "",
            "file_is_ioc": "y" if is_ioc else "n",
            "file_is_evidence": "y" if is_evidence else "n",
            "file_description": description or f"Evidencia forense ({filename})",
            "file_tags": ",".join(tags or ["evidence", "soc_v31"])
        }

        try:
            req_headers = {k: v for k, v in self.session.headers.items() if k.lower() != "content-type"}
            r = requests.post(
                f"{self.base_url}/datastore/file/add/{folder_id}?cid={case_id}",
                files=files,
                data=data,
                headers=req_headers,
                timeout=30,
            )
            if r.status_code in (200, 201):
                res_data = r.json().get("data", {})
                return {
                    "success": True,
                    "filename": filename,
                    "file_id": res_data.get("file_id"),
                    "file_uuid": res_data.get("file_uuid"),
                    "file_sha256": res_data.get("file_sha256") or sha256_hash,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "folder_id": folder_id,
                    "datastore_saved": True,
                    "message": "Archivo guardado exitosamente en el Datastore oficial de DFIR-IRIS"
                }
            return {
                "success": False,
                "error": f"Error subiendo a IRIS Datastore ({r.status_code}): {r.text[:200]}"
            }
        except Exception as e:
            return {"success": False, "error": f"Excepción en comunicación con IRIS Datastore: {str(e)}"}

    def delete_datastore_file(self, case_id: int, file_id: int) -> Dict[str, Any]:
        """Elimina un archivo del Datastore de IRIS vía endpoint oficial."""
        r = self.session.post(
            f"{self.base_url}/datastore/file/delete/{file_id}?cid={case_id}",
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            timeout=15,
        )
        if r.status_code in (200, 201):
            return {"status": "deleted", "file_id": file_id}
        return {"status": "error", "code": r.status_code, "message": r.text[:200]}

    def download_datastore_file(self, case_id: int, file_id: int) -> Optional[bytes]:
        """Descarga el contenido binario original de un archivo en IRIS Datastore."""
        r = self.session.get(
            f"{self.base_url}/datastore/file/view/{file_id}?cid={case_id}",
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            timeout=30,
        )
        if r.status_code == 200:
            return r.content
        return None

