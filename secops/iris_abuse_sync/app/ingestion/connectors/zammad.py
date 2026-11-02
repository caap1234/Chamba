from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple
import requests

from app.ingestion.base import BaseConnector, NormalizedIngestPayload
from app.ingestion.normalizer import ReportNormalizer


class ZammadConnector(BaseConnector):
    """Conector incremental para Zammad Helpdesk API (ej. Grupo 14 Soporte 2do Nivel)."""

    connector_type = "zammad"

    def _session(self) -> requests.Session:
        s = requests.Session()
        s.trust_env = False
        s.verify = bool(self.config.get("verify_ssl", False))
        token = (self.secret or self.config.get("api_token") or "").strip()
        if token:
            s.headers.update({"Authorization": f"Token token={token}"})
        s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        return s

    def test_connection(self) -> Dict[str, Any]:
        base_url = (self.config.get("base_url") or "https://helpdesk.neubox.com").rstrip("/")
        token = (self.secret or self.config.get("api_token") or "").strip()
        if not token:
            return {
                "ok": False,
                "status": "missing_credentials",
                "message": "Token API de Zammad no configurado. Ingrésalo en la configuración del conector.",
            }
        try:
            s = self._session()
            r = s.get(f"{base_url}/api/v1/users/me", timeout=10)
            if r.status_code == 200:
                me = r.json()
                return {
                    "ok": True,
                    "status": "connected",
                    "user": f"{me.get('firstname', '')} {me.get('lastname', '')}".strip(),
                    "login": me.get("login"),
                    "base_url": base_url,
                }
            return {"ok": False, "status": f"http_{r.status_code}", "message": r.text[:200]}
        except Exception as exc:
            return {"ok": False, "status": "connection_error", "message": str(exc)}

    def fetch_new_events(
        self,
        cursor: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        cursor = dict(cursor or {})
        base_url = (self.config.get("base_url") or "https://helpdesk.neubox.com").rstrip("/")
        token = (self.secret or self.config.get("api_token") or "").strip()
        if not token:
            return [], cursor

        group_id = self.config.get("group_id", 14)
        query = self.config.get("query_filter") or f"group_id:{group_id}"
        last_updated = cursor.get("last_updated_at")
        if last_updated:
            query = f"{query} AND updated_at:[{last_updated} TO *]"

        s = self._session()
        r = s.get(
            f"{base_url}/api/v1/tickets/search",
            params={"query": query, "limit": 25, "expand": "true"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        tickets = data if isinstance(data, list) else (data.get("tickets") or [])
        events: List[NormalizedIngestPayload] = []
        newest_ts = last_updated

        for t in tickets:
            tid = t if isinstance(t, int) else t.get("id")
            if not tid:
                continue
            rt = s.get(f"{base_url}/api/v1/tickets/{tid}", timeout=10)
            if rt.status_code != 200:
                continue
            t_obj = rt.json()
            t_num = str(t_obj.get("number") or tid)
            t_title = t_obj.get("title") or f"Ticket #{t_num}"
            t_updated = t_obj.get("updated_at")
            if t_updated and (not newest_ts or t_updated > newest_ts):
                newest_ts = t_updated

            ra = s.get(f"{base_url}/api/v1/ticket_articles/by_ticket/{tid}", timeout=12)
            articles = ra.json() if ra.status_code == 200 and isinstance(ra.json(), list) else []
            articles_text_blocks = [
                f"Ticket {t_num} | URL: {base_url}/#ticket/zoom/{tid}",
                f"Subject: {t_title}",
                f"Group {group_id} {self.config.get('group_name', 'Soporte 2do Nivel')}",
                f"State {t_obj.get('state', 'open')}",
            ]
            for art in articles:
                sender = art.get("from") or art.get("created_by") or "Usuario"
                vis = "Nota interna" if art.get("internal") else "Mensaje público"
                body = art.get("body") or ""
                if art.get("content_type") == "text/html":
                    body = re.sub(r"<[^>]+>", "\n", body)
                articles_text_blocks.append(f"{sender} — — {art.get('created_at', '')} — {vis}\n{body}")

            full_text = "\n\n".join(articles_text_blocks)
            payload = ReportNormalizer.normalize_text(
                text=full_text,
                filename=f"zammad_ticket_{t_num}.txt",
                organization=self.config.get("organization", "NBX"),
                source_type="zammad",
                subject_override=t_title,
            )
            payload.source_id = t_num
            payload.abuse_ticket_id = t_num
            payload.source_url = f"{base_url}/#ticket/zoom/{tid}"
            payload.raw_metadata = {"zammad_ticket_id": tid, "zammad_number": t_num, "state": t_obj.get("state")}
            events.append(payload)

        if newest_ts:
            cursor["last_updated_at"] = newest_ts
        cursor["last_polled_at"] = datetime.now(timezone.utc).isoformat()
        return events, cursor

