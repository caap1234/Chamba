from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import requests

from app.ingestion.base import BaseConnector, NormalizedIngestPayload
from app.ingestion.normalizer import ReportNormalizer


class WhmcsConnector(BaseConnector):
    """Conector desacoplado para WHMCS Billing & Support API."""

    connector_type = "whmcs"

    def test_connection(self) -> Dict[str, Any]:
        api_url = (self.config.get("base_url") or "").strip()
        identifier = (self.config.get("identifier") or "").strip()
        secret = (self.secret or self.config.get("secret") or "").strip()
        if not api_url or not identifier or not secret:
            return {
                "ok": False,
                "status": "missing_credentials",
                "message": "Falta URL de API WHMCS, Identifier o Secret en la configuración.",
            }
        try:
            s = requests.Session()
            s.trust_env = False
            r = s.post(
                api_url,
                data={
                    "action": "GetSupportDepartments",
                    "identifier": identifier,
                    "secret": secret,
                    "responsetype": "json",
                },
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("result") == "success":
                    return {"ok": True, "status": "connected", "departments": data.get("totalresults", 0)}
                return {"ok": False, "status": "api_error", "message": data.get("message", "Error WHMCS")}
            return {"ok": False, "status": f"http_{r.status_code}", "message": r.text[:200]}
        except Exception as exc:
            return {"ok": False, "status": "connection_error", "message": str(exc)}

    def fetch_new_events(
        self,
        cursor: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        cursor = dict(cursor or {})
        api_url = (self.config.get("base_url") or "").strip()
        identifier = (self.config.get("identifier") or "").strip()
        secret = (self.secret or self.config.get("secret") or "").strip()
        if not api_url or not identifier or not secret:
            return [], cursor

        s = requests.Session()
        s.trust_env = False
        r = s.post(
            api_url,
            data={
                "action": "GetTickets",
                "identifier": identifier,
                "secret": secret,
                "status": "Awaiting Reply",
                "limitnum": 25,
                "responsetype": "json",
            },
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        tickets = ((data.get("tickets") or {}).get("ticket")) or []
        events: List[NormalizedIngestPayload] = []
        last_tid = int(cursor.get("last_ticket_id") or 0)
        max_tid = last_tid

        for t in tickets:
            tid = int(t.get("id") or 0)
            if tid <= last_tid:
                continue
            if tid > max_tid:
                max_tid = tid
            t_num = str(t.get("tid") or tid)
            subj = t.get("subject") or f"WHMCS Ticket #{t_num}"
            msg = t.get("message") or ""
            client_id = str(t.get("userid") or "") or None
            service_id = str(t.get("service") or "") or None

            payload = ReportNormalizer.normalize_text(
                text=f"Ticket #{t_num}\nSubject: {subj}\nClient ID: {client_id}\nService ID: {service_id}\n\n{msg}",
                filename=f"whmcs_{t_num}.txt",
                organization=self.config.get("organization", "NBX"),
                source_type="whmcs",
                subject_override=subj,
                reporter_override=t.get("name") or t.get("email") or "Cliente WHMCS",
            )
            payload.source_id = t_num
            payload.abuse_ticket_id = t_num
            payload.client_id = client_id
            payload.service_id = service_id
            events.append(payload)

        cursor["last_ticket_id"] = max_tid
        cursor["last_polled_at"] = datetime.now(timezone.utc).isoformat()
        return events, cursor

