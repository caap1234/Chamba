from datetime import datetime, timezone
import imaplib
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.base import BaseConnector, NormalizedIngestPayload
from app.ingestion.normalizer import ReportNormalizer


class ImapConnector(BaseConnector):
    """Conector multi-buzón IMAP con extracción MIME, cabeceras SMTP y control de UID."""

    connector_type = "imap"

    def test_connection(self) -> Dict[str, Any]:
        host = (self.config.get("host") or "").strip()
        port = int(self.config.get("port") or 993)
        username = (self.config.get("username") or "").strip()
        password = (self.secret or self.config.get("password") or "").strip()
        folder = (self.config.get("folder") or "INBOX").strip()

        if not host or not username or not password:
            return {
                "ok": False,
                "status": "missing_credentials",
                "message": "Falta servidor IMAP, usuario o contraseña en la configuración del buzón.",
            }
        try:
            conn = imaplib.IMAP4_SSL(host, port) if self.config.get("use_ssl", True) else imaplib.IMAP4(host, port)
            conn.login(username, password)
            status, count_data = conn.select(folder, readonly=True)
            msg_count = int(count_data[0].decode("utf-8")) if status == "OK" and count_data else 0
            conn.logout()
            return {
                "ok": True,
                "status": "connected",
                "host": host,
                "folder": folder,
                "messages_in_folder": msg_count,
            }
        except Exception as exc:
            return {"ok": False, "status": "imap_error", "message": str(exc)}

    def fetch_new_events(
        self,
        cursor: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        cursor = dict(cursor or {})
        host = (self.config.get("host") or "").strip()
        port = int(self.config.get("port") or 993)
        username = (self.config.get("username") or "").strip()
        password = (self.secret or self.config.get("password") or "").strip()
        folder = (self.config.get("folder") or "INBOX").strip()
        if not host or not username or not password:
            return [], cursor

        last_uid = int(cursor.get("last_uid") or 0)
        max_uid = last_uid
        events: List[NormalizedIngestPayload] = []

        conn = imaplib.IMAP4_SSL(host, port) if self.config.get("use_ssl", True) else imaplib.IMAP4(host, port)
        try:
            conn.login(username, password)
            conn.select(folder, readonly=True)
            search_crit = f"UID {last_uid + 1}:*" if last_uid > 0 else "UNSEEN"
            typ, data = conn.uid("search", None, search_crit)
            if typ == "OK" and data and data[0]:
                uids = [int(u) for u in data[0].split() if int(u) > last_uid][-20:]
                for uid in uids:
                    if uid > max_uid:
                        max_uid = uid
                    ftyp, fdata = conn.uid("fetch", str(uid), "(RFC822)")
                    if ftyp == "OK" and fdata and isinstance(fdata[0], tuple):
                        raw_eml = fdata[0][1]
                        payload, _ = ReportNormalizer.normalize_eml_bytes(
                            raw_bytes=raw_eml,
                            filename=f"imap_{uid}.eml",
                            organization=self.config.get("organization", "NBX"),
                            source_type="imap",
                        )
                        payload.source_instance = username
                        payload.source_id = f"{username}:{uid}"
                        events.append(payload)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

        cursor["last_uid"] = max_uid
        cursor["last_polled_at"] = datetime.now(timezone.utc).isoformat()
        return events, cursor

