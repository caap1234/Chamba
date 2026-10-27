import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import requests
import urllib3

import config

# Suppress insecure request warnings if user disabled SSL verification
if not config.IRIS_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("iris_abuse_sync.client")


class IrisClient:
    """
    Client for interacting with DFIR-IRIS REST API (v2 & legacy support).
    Supports dry-run mode for safe testing and debugging.
    """

    def __init__(
        self,
        base_url: str = config.IRIS_URL,
        api_key: str = config.IRIS_API_KEY,
        verify_ssl: bool = config.IRIS_VERIFY_SSL,
        customer_id: int = config.IRIS_CUSTOMER_ID
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.customer_id = customer_id
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    @property
    def headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def test_connection(self) -> Dict[str, Any]:
        """Tests connectivity and authentication against DFIR-IRIS."""
        if not self.api_key:
            return {
                "success": False,
                "error": "No IRIS_API_KEY configured. Please check your .env settings.",
                "url": self.base_url
            }

        endpoints = [
            f"{self.base_url}/api/v2/manage/case-templates",
            f"{self.base_url}/manage/cases/filter",
            f"{self.base_url}/api/v2/cases"
        ]

        for ep in endpoints:
            try:
                r = self.session.get(ep, headers=self.headers, timeout=5)
                if r.status_code in (200, 201):
                    return {"success": True, "status_code": r.status_code, "url": ep}
                elif r.status_code in (401, 403):
                    return {"success": False, "error": f"Authentication failed ({r.status_code}): Invalid API key.", "url": ep}
            except Exception as e:
                last_err = str(e)

        return {"success": False, "error": f"Could not connect to {self.base_url}: {last_err}", "url": self.base_url}

    def get_templates(self) -> Dict[str, Any]:
        """Fetches registered case templates from DFIR-IRIS."""
        endpoints = [
            f"{self.base_url}/api/v2/manage/case-templates",
            f"{self.base_url}/manage/case-templates/list"
        ]
        for ep in endpoints:
            try:
                r = self.session.get(ep, headers=self.headers, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    # IRIS returns {"status": "success", "data": [...]} or list directly
                    templates = data.get("data", data) if isinstance(data, dict) else data
                    template_map = {}
                    if isinstance(templates, list):
                        for tmpl in templates:
                            name = tmpl.get("name") or tmpl.get("template_name")
                            tid = tmpl.get("id") or tmpl.get("template_id")
                            if name and tid:
                                template_map[name] = str(tid)
                    return {"success": True, "templates": template_map, "raw": templates}
            except Exception as e:
                logger.warning(f"Error fetching templates from {ep}: {e}")

        return {"success": False, "templates": {}, "error": "Unable to fetch templates"}

    def create_case(
        self,
        case_payload: Dict[str, Any],
        pdf_path: Optional[Path] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Creates a case in DFIR-IRIS and populates description, notes, IOCs and evidence.
        """
        template_name = case_payload.get("template_name", "")
        
        # 1. Resolve template ID from DFIR-IRIS if available
        remote_templates = {}
        if not dry_run and self.api_key:
            res_tmpl = self.get_templates()
            if res_tmpl.get("success"):
                remote_templates = res_tmpl.get("templates", {})

        template_id = remote_templates.get(template_name)

        # 2. Prepare payload for POST /manage/cases/add or /api/v2/cases
        post_data = {
            "case_name": case_payload["case_name"],
            "case_description": case_payload["case_description"],
            "case_customer": case_payload.get("case_customer", self.customer_id),
            "case_soc_id": str(case_payload.get("case_soc_id", "")),
        }
        if template_id:
            # Note: pass as string per known DFIR-IRIS server validation
            post_data["case_template_id"] = str(template_id)

        if "custom_attributes" in case_payload:
            post_data["custom_attributes"] = case_payload["custom_attributes"]

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "case_id": 9999,
                "case_name": post_data["case_name"],
                "case_url": f"{self.base_url}/#/case?cid=9999",
                "template_applied": template_name,
                "template_id": template_id or "auto",
                "payload": post_data,
                "notes_count": len(case_payload.get("notes", [])),
                "iocs_count": len(case_payload.get("iocs", [])),
                "evidence_attached": str(pdf_path) if pdf_path else None
            }

        # 3. Execute POST to create case
        create_endpoints = [
            f"{self.base_url}/manage/cases/add",
            f"{self.base_url}/api/v2/manage/cases",
            f"{self.base_url}/api/v2/cases"
        ]

        case_id = None
        error_msg = ""

        for ep in create_endpoints:
            try:
                r = self.session.post(ep, headers=self.headers, json=post_data, timeout=10)
                if r.status_code in (200, 201):
                    res_json = r.json()
                    # IRIS response can be {"status": "success", "data": {"case_id": 123}}
                    data_obj = res_json.get("data", res_json)
                    if isinstance(data_obj, dict):
                        case_id = data_obj.get("case_id") or data_obj.get("cid") or data_obj.get("id")
                    if case_id:
                        break
                else:
                    error_msg = f"{r.status_code}: {r.text}"
            except Exception as e:
                error_msg = str(e)

        if not case_id:
            return {
                "success": False,
                "error": f"Failed to create case in DFIR-IRIS. Details: {error_msg}",
                "payload": post_data
            }

        # 4. Attach / Sync Notes
        notes_created = self.sync_case_notes(case_id, case_payload.get("notes", []))

        # 5. Attach IOCs
        iocs_created = []
        for ioc in case_payload.get("iocs", []):
            val = ioc.get("value")
            t = ioc.get("type", "other")
            d = ioc.get("description", "")
            if val and self._add_ioc(case_id, val, t, d):
                iocs_created.append(f"{t}:{val}")

        # 6. Upload PDF Evidence
        evidence_uploaded = False
        if pdf_path and Path(pdf_path).is_file():
            evidence_uploaded = self._upload_evidence(case_id, Path(pdf_path))

        case_url = f"{self.base_url}/#/case?cid={case_id}"

        return {
            "success": True,
            "dry_run": False,
            "case_id": case_id,
            "case_name": post_data["case_name"],
            "case_url": case_url,
            "template_applied": template_name,
            "template_id": template_id,
            "notes": notes_created,
            "iocs": iocs_created,
            "evidence_uploaded": evidence_uploaded
        }

    # Standard DFIR-IRIS IOC Type IDs mapping
    IOC_TYPE_MAP = {
        "domain": 20,
        "ip": 76,       # ip-any
        "ip-any": 76,
        "ip-dst": 77,
        "ip-src": 79,
        "url": 141,
        "uri": 140,
        "email": 22,
        "email-src": 31,
        "email-dst": 25,
        "md5": 90,
        "sha256": 113,
        "other": 96
    }

    def sync_case_notes(self, case_id: int, notes: List[Dict[str, Any]]) -> List[str]:
        """
        Synchronizes notes with DFIR-IRIS for the case.
        If a note with the given title already exists (e.g. created by case template), it updates it in place.
        If a note does not exist, it adds it under the case's directory.
        """
        if not notes:
            return []

        synced = []
        try:
            # 1. Fetch existing directories and notes
            r_dirs = self.session.get(
                f"{self.base_url}/case/notes/directories/filter?cid={case_id}",
                headers=self.headers,
                timeout=10
            )
            dirs = r_dirs.json().get("data", []) if r_dirs.status_code == 200 else []

            existing_notes_map: Dict[str, int] = {}
            default_dir_id = None

            if isinstance(dirs, list):
                for d in dirs:
                    if default_dir_id is None and d.get("id"):
                        default_dir_id = d.get("id")
                    for n in d.get("notes", []):
                        if n.get("title") and n.get("id"):
                            existing_notes_map[n["title"].strip().lower()] = n["id"]

            # If no directory exists, create standard incident directory
            if default_dir_id is None:
                try:
                    r_mkdir = self.session.post(
                        f"{self.base_url}/case/notes/directories/add",
                        headers=self.headers,
                        json={"cid": case_id, "name": "Seguimiento del incidente"},
                        timeout=8
                    )
                    if r_mkdir.status_code in (200, 201):
                        default_dir_id = r_mkdir.json().get("data", {}).get("directory_id")
                except Exception as err:
                    logger.warning(f"Could not create note directory for case {case_id}: {err}")

            # 2. Update existing notes or create new ones
            for note in notes:
                title = note.get("note_title") or note.get("title") or ""
                content = note.get("note_content") or note.get("content") or ""
                note_id = note.get("note_id") or note.get("id")

                if not title:
                    continue

                norm_title = title.strip().lower()
                target_note_id = note_id or existing_notes_map.get(norm_title)

                if target_note_id:
                    # Update existing note in IRIS
                    up_payload = {
                        "cid": case_id,
                        "note_title": title,
                        "note_content": content
                    }
                    r_up = self.session.post(
                        f"{self.base_url}/case/notes/update/{target_note_id}?cid={case_id}",
                        headers=self.headers,
                        json=up_payload,
                        timeout=10
                    )
                    if r_up.status_code in (200, 201):
                        synced.append(title)
                        logger.info(f"Updated note #{target_note_id} '{title}' in case #{case_id}")
                    else:
                        logger.warning(f"Failed to update note #{target_note_id} in case #{case_id}: {r_up.status_code} {r_up.text}")
                else:
                    # Create new note
                    add_payload = {
                        "cid": case_id,
                        "directory_id": default_dir_id,
                        "note_title": title,
                        "note_content": content
                    }
                    r_add = self.session.post(
                        f"{self.base_url}/case/notes/add?cid={case_id}",
                        headers=self.headers,
                        json=add_payload,
                        timeout=10
                    )
                    if r_add.status_code in (200, 201):
                        synced.append(title)
                        logger.info(f"Created note '{title}' in case #{case_id}")
                    else:
                        logger.warning(f"Failed to create note '{title}' in case #{case_id}: {r_add.status_code} {r_add.text}")

        except Exception as e:
            logger.error(f"Error syncing notes for case #{case_id}: {e}")

        return synced

    def _add_ioc(self, case_id: int, value: str, ioc_type: str, description: str = "") -> bool:
        """Adds an IOC indicator to the case in DFIR-IRIS."""
        if not value:
            return False

        norm_type = (ioc_type or "other").strip().lower()
        type_id = self.IOC_TYPE_MAP.get(norm_type)
        if not type_id:
            for k, v in self.IOC_TYPE_MAP.items():
                if k in norm_type:
                    type_id = v
                    break
        if not type_id:
            type_id = 96  # other

        payload = {
            "ioc_type_id": type_id,
            "ioc_tlp_id": 2,  # amber
            "ioc_value": value.strip(),
            "ioc_description": description or f"Indicador detectado ({norm_type})",
            "ioc_tags": "abuse,automated",
            "cid": case_id
        }

        try:
            r = self.session.post(
                f"{self.base_url}/case/ioc/add?cid={case_id}",
                headers=self.headers,
                json=payload,
                timeout=10
            )
            if r.status_code in (200, 201):
                res_data = r.json()
                if res_data.get("status") == "success":
                    logger.info(f"Added IOC '{value}' ({norm_type}) to case #{case_id}")
                    return True
                else:
                    logger.warning(f"IRIS returned non-success adding IOC: {res_data}")
            else:
                logger.warning(f"Failed to add IOC to case #{case_id}: HTTP {r.status_code} {r.text}")
        except Exception as e:
            logger.error(f"Exception adding IOC to case #{case_id}: {e}")

        return False

    def get_datastore_folder_id(self, case_id: int, target_name: str = "Evidences") -> Optional[int]:
        """
        Retrieves the node ID for a target folder (e.g. 'Evidences' or 'Images')
        inside the case's datastore tree. Returns root folder ID as fallback.
        """
        try:
            r = self.session.get(f"{self.base_url}/datastore/list/tree?cid={case_id}", headers=self.headers, timeout=8)
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
        except Exception as e:
            logger.warning(f"Error resolving datastore folder ID for case {case_id}: {e}")
            return None

    def upload_datastore_file(
        self,
        case_id: int,
        file_data: Any,
        filename: str,
        description: str = "",
        is_evidence: bool = True,
        is_ioc: bool = False,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Uploads a binary file or image directly into the DFIR-IRIS case datastore,
        automatically registering it as evidence with its SHA-256 hash.
        """
        import io
        import hashlib
        import mimetypes

        # Read bytes
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

        # Resolve datastore folder ID
        target_folder = "Images" if mime_type.startswith("image/") else "Evidences"
        folder_id = self.get_datastore_folder_id(case_id, target_folder)
        if folder_id is None:
            folder_id = self.get_datastore_folder_id(case_id, "Evidences") or 0

        headers_auth = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

        files = {
            "file_content": (filename, io.BytesIO(raw_bytes), mime_type)
        }
        data = {
            "file_original_name": filename,
            "file_password": "",
            "file_is_ioc": "y" if is_ioc else "n",
            "file_is_evidence": "y" if is_evidence else "n",
            "file_description": description or f"Evidencia agregada vía SOC Sync ({filename})",
            "file_tags": ",".join(tags or ["evidence", "soc_sync"])
        }

        try:
            r = self.session.post(
                f"{self.base_url}/datastore/file/add/{folder_id}?cid={case_id}",
                files=files,
                data=data,
                headers=headers_auth,
                timeout=20
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
                    "message": "Archivo guardado exitosamente en el datastore y registrado como evidencia"
                }
            else:
                logger.warning(f"Datastore upload returned HTTP {r.status_code}: {r.text}")
        except Exception as e:
            logger.warning(f"Exception uploading to datastore: {e}")

        # Fallback: Register metadata in case evidences directly
        try:
            ev_body = {
                "cid": case_id,
                "filename": filename,
                "file_size": file_size,
                "file_description": description or f"Evidencia externa ({filename})",
                "file_hash": sha256_hash,
                "custom_attributes": {}
            }
            r_ev = self.session.post(f"{self.base_url}/case/evidences/add", json=ev_body, headers=self.headers, timeout=10)
            if r_ev.status_code in (200, 201):
                return {
                    "success": True,
                    "filename": filename,
                    "file_id": r_ev.json().get("data", {}).get("id"),
                    "file_sha256": sha256_hash,
                    "file_size": file_size,
                    "mime_type": mime_type,
                    "datastore_saved": False,
                    "message": "Evidencia registrada como metadatos en DFIR-IRIS"
                }
        except Exception as e2:
            logger.warning(f"Fallback evidence registration failed: {e2}")

        return {"success": False, "error": f"No se pudo guardar la evidencia en IRIS para el caso #{case_id}"}

    def _upload_evidence(self, case_id: int, file_path: Path) -> bool:
        """Uploads a PDF evidence file or screenshot to the case datastore."""
        if not file_path or not file_path.is_file():
            return False
        res = self.upload_datastore_file(
            case_id=case_id,
            file_data=file_path,
            filename=file_path.name,
            description=f"Ticket original {file_path.name}",
            is_evidence=True
        )
        return res.get("success", False)

    def get_case_datastore_images(self, case_id: int, max_images: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves all image evidence files from the case's datastore,
        downloads their binary data, and prepares Base64 Data URIs for Markdown/PDF embedding.
        """
        import base64
        import mimetypes

        images = []
        try:
            r = self.session.get(f"{self.base_url}/datastore/list/tree?cid={case_id}", headers=self.headers, timeout=8)
            if r.status_code != 200:
                return []
            tree = r.json().get("data", {})

            def extract_files(node: dict) -> List[dict]:
                found = []
                if not isinstance(node, dict):
                    return found
                if node.get("type") == "file":
                    found.append(node)
                children = node.get("children", {})
                if isinstance(children, dict):
                    for child in children.values():
                        found.extend(extract_files(child))
                return found

            all_files = []
            for root in tree.values():
                all_files.extend(extract_files(root))

            image_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
            for f in all_files:
                fname = f.get("file_original_name") or ""
                fid = f.get("file_id")
                ext = Path(fname).suffix.lower()
                if ext in image_extensions and fid:
                    try:
                        r_img = self.session.get(f"{self.base_url}/datastore/file/view/{fid}?cid={case_id}", headers=self.headers, timeout=12)
                        if r_img.status_code == 200 and len(r_img.content) > 0:
                            mime = r_img.headers.get("content-type") or mimetypes.guess_type(fname)[0] or "image/png"
                            b64 = base64.b64encode(r_img.content).decode("utf-8")
                            images.append({
                                "file_id": fid,
                                "filename": fname,
                                "sha256": f.get("file_sha256") or "",
                                "description": f.get("file_description") or "",
                                "file_size": f.get("file_size") or len(r_img.content),
                                "data_uri": f"data:{mime};base64,{b64}"
                            })
                            if len(images) >= max_images:
                                break
                    except Exception as err:
                        logger.warning(f"Error downloading datastore image {fid}: {err}")
        except Exception as e:
            logger.warning(f"Error fetching case datastore images: {e}")
        return images

    def list_cases(self, filter_state: str = "open", limit: int = 100) -> Dict[str, Any]:
        """
        Lists cases from DFIR-IRIS, normalized with customer names, badges and state info.
        filter_state can be 'open' (excludes closed cases) or 'all'.
        """
        try:
            r = self.session.get(f"{self.base_url}/manage/cases/filter", headers=self.headers, timeout=8)
            if r.status_code != 200:
                return {"success": False, "error": f"Error fetching cases: HTTP {r.status_code}", "cases": []}

            data = r.json()
            raw_cases = data.get("data", {}).get("cases", []) if isinstance(data.get("data"), dict) else []

            normalized = []
            for c in raw_cases:
                cid = c.get("case_id")
                name = c.get("name") or c.get("case_name") or f"Caso #{cid}"
                client_id = c.get("client_id") or 2
                cust_name = "Hospedando" if client_id == 3 else "Neubox"
                cust_code = "HP" if client_id == 3 else "NBX"
                state_id = c.get("state_id") or 1
                state_name = c.get("state", {}).get("state_name") or ("Cerrado" if state_id == 9 else "Abierto")
                is_closed = (state_id == 9 or str(state_name).lower() == "closed")

                if filter_state == "open" and is_closed:
                    continue

                normalized.append({
                    "case_id": cid,
                    "case_name": name,
                    "customer_id": client_id,
                    "customer_name": cust_name,
                    "customer_code": cust_code,
                    "state_id": state_id,
                    "state_name": state_name,
                    "is_closed": is_closed,
                    "soc_id": c.get("soc_id", ""),
                    "open_date": str(c.get("open_date") or ""),
                    "close_date": str(c.get("close_date") or ""),
                    "description": c.get("description", ""),
                    "case_url": f"{self.base_url}/#/case?cid={cid}"
                })

            # Sort descending by case_id
            normalized.sort(key=lambda x: x["case_id"] or 0, reverse=True)
            if limit:
                normalized = normalized[:limit]

            return {"success": True, "cases": normalized, "total": len(normalized)}
        except Exception as e:
            logger.error(f"Error in list_cases: {e}")
            return {"success": False, "error": str(e), "cases": []}

    def get_case(self, case_id: int) -> Dict[str, Any]:
        """
        Fetches detailed information for a specific case including evidences and IOCs.
        """
        try:
            r = self.session.get(f"{self.base_url}/manage/cases/{case_id}", headers=self.headers, timeout=8)
            if r.status_code != 200:
                return {"success": False, "error": f"Caso #{case_id} no encontrado en DFIR-IRIS"}

            case_data = r.json().get("data", {})
            # Normalize field names so they match templates and client consumption
            case_data["name"] = case_data.get("name") or case_data.get("case_name") or f"Caso #{case_id}"
            case_data["description"] = case_data.get("description") or case_data.get("case_description") or ""
            case_data["soc_id"] = case_data.get("soc_id") or case_data.get("case_soc_id") or ""
            case_data["client_id"] = case_data.get("customer_id") or case_data.get("client_id") or 2
            case_data["customer_name"] = "Hospedando" if case_data["client_id"] == 3 else "Neubox"
            case_data["customer_code"] = "HP" if case_data["client_id"] == 3 else "NBX"
            case_data["case_url"] = f"{self.base_url}/#/case?cid={case_id}"

            # Fetch Evidences
            evidences = []
            try:
                r_ev = self.session.get(f"{self.base_url}/case/evidences/list?cid={case_id}", headers=self.headers, timeout=8)
                if r_ev.status_code == 200:
                    evidences = r_ev.json().get("data", {}).get("evidences", [])
            except Exception as e:
                logger.warning(f"Error fetching evidences for case {case_id}: {e}")

            # Fetch IOCs
            iocs = []
            try:
                r_ioc = self.session.get(f"{self.base_url}/case/ioc/list?cid={case_id}", headers=self.headers, timeout=8)
                if r_ioc.status_code == 200:
                    iocs = r_ioc.json().get("data", {}).get("ioc", [])
            except Exception as e:
                logger.warning(f"Error fetching IOCs for case {case_id}: {e}")

            # Fetch Notes
            notes = []
            try:
                r_notes = self.session.get(f"{self.base_url}/case/notes/search?search_input=&cid={case_id}", headers=self.headers, timeout=10)
                if r_notes.status_code == 200:
                    notes_data = r_notes.json().get("data", [])
                    if isinstance(notes_data, list):
                        for n in notes_data:
                            notes.append({
                                "note_id": n.get("note_id"),
                                "note_title": n.get("note_title") or "Sin título",
                                "note_content": n.get("note_content") or "",
                                "directory_id": n.get("directory_id"),
                                "directory_name": n.get("directory", {}).get("name") if isinstance(n.get("directory"), dict) else ""
                            })
            except Exception as e:
                logger.warning(f"Error fetching notes for case {case_id}: {e}")

            return {
                "success": True,
                "case": case_data,
                "notes": notes,
                "evidences": evidences,
                "iocs": iocs
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def close_case(self, case_id: int) -> Dict[str, Any]:
        """
        Closes a case in DFIR-IRIS.
        """
        try:
            # First try direct close endpoint
            r = self.session.post(f"{self.base_url}/manage/cases/close/{case_id}", headers=self.headers, json={}, timeout=8)
            if r.status_code in (200, 201):
                return {"success": True, "message": f"Caso #{case_id} cerrado exitosamente"}

            # Fallback to update state_id: 9
            r_up = self.session.post(
                f"{self.base_url}/manage/cases/update/{case_id}",
                headers=self.headers,
                json={"state_id": 9},
                timeout=8
            )
            if r_up.status_code in (200, 201):
                return {"success": True, "message": f"Caso #{case_id} cerrado exitosamente"}

            return {"success": False, "error": f"No se pudo cerrar el caso: HTTP {r.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def update_case(self, case_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates case details (name, description, state_id) and syncs notes in DFIR-IRIS.
        """
        try:
            # 1. Sync notes if provided
            synced_notes = []
            if "notes" in updates and isinstance(updates["notes"], list):
                synced_notes = self.sync_case_notes(case_id, updates["notes"])

            # 2. Update case metadata
            post_data = {}
            if "case_name" in updates or "name" in updates:
                post_data["case_name"] = updates.get("case_name") or updates.get("name")
            if "case_description" in updates or "description" in updates:
                post_data["case_description"] = updates.get("case_description") or updates.get("description")
            if "state_id" in updates:
                post_data["state_id"] = updates["state_id"]
            if "case_soc_id" in updates:
                post_data["case_soc_id"] = updates["case_soc_id"]

            if post_data:
                r = self.session.post(
                    f"{self.base_url}/manage/cases/update/{case_id}",
                    headers=self.headers,
                    json=post_data,
                    timeout=10
                )
                if r.status_code not in (200, 201):
                    return {"success": False, "error": f"Error actualizando metadatos del caso: HTTP {r.status_code} {r.text}"}

            return {
                "success": True,
                "message": f"Caso #{case_id} actualizado exitosamente",
                "notes_updated": synced_notes
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_case_report(
        self,
        case_id: int,
        template_filename: str = "Report_Template_Abuse_Lite.md"
    ) -> Dict[str, Any]:
        """
        Renders a Markdown incident report for the specified case using Jinja2 and templates.
        """
        import jinja2

        case_res = self.get_case(case_id)
        if not case_res.get("success"):
            return {"success": False, "error": case_res.get("error")}

        case_data = case_res["case"]
        evidences = case_res.get("evidences", [])
        iocs = case_res.get("iocs", [])

        template_path = config.BASE_DIR / "templates" / template_filename
        if not template_path.exists():
            # Fallback to any markdown template in templates/
            md_templates = list((config.BASE_DIR / "templates").glob("*.md"))
            if md_templates:
                template_path = md_templates[0]
            else:
                return {"success": False, "error": f"Template {template_filename} no encontrado"}

        try:
            evidences_images = self.get_case_datastore_images(case_id)
            template_content = template_path.read_text(encoding="utf-8")
            jinja_tmpl = jinja2.Template(template_content)
            rendered_md = jinja_tmpl.render(
                case=case_data,
                evidences=evidences,
                evidences_images=evidences_images,
                notes=[],
                iocs=iocs
            )

            return {
                "success": True,
                "markdown": rendered_md,
                "case": case_data,
                "template": template_path.name,
                "evidences_images_count": len(evidences_images)
            }
        except Exception as e:
            return {"success": False, "error": f"Error renderizando template: {e}"}
