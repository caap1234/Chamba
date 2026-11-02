from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.ingestion.base import NormalizedIngestPayload
from app.models.case_extended import AlertExtension, CaseExtension


class CorrelationEngine:
    """Motor de deduplicación y correlación contra alertas y casos existentes."""

    @classmethod
    def find_correlations(
        cls,
        db: Session,
        payload: NormalizedIngestPayload,
        live_iris_cases: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        related_alert_ids: List[int] = []
        related_case_ids: List[int] = []
        match_reasons: List[str] = []

        ticket = (payload.abuse_ticket_id or "").strip()
        domain = (payload.primary_domain or "").strip().lower()
        rep_ip = (payload.reported_ip or "").strip()

        # 1. Buscar en AlertExtension (PostgreSQL)
        q_alerts = db.query(AlertExtension).all()
        for a in q_alerts:
            if ticket and a.abuse_ticket_id == ticket:
                related_alert_ids.append(a.iris_alert_id)
                match_reasons.append(f"Mismo ticket de abuso #{ticket} en Alerta #{a.iris_alert_id}")
            elif domain and (a.primary_domain or "").lower() == domain:
                related_alert_ids.append(a.iris_alert_id)
                match_reasons.append(f"Mismo dominio '{domain}' en Alerta #{a.iris_alert_id}")
            elif rep_ip and a.reported_ip == rep_ip:
                related_alert_ids.append(a.iris_alert_id)
                match_reasons.append(f"Misma IP reportada '{rep_ip}' en Alerta #{a.iris_alert_id}")

        # 2. Buscar en CaseExtension (PostgreSQL)
        q_cases = db.query(CaseExtension).all()
        for c in q_cases:
            if ticket and (c.abuse_ticket_id == ticket or c.holder_ticket_id == ticket):
                related_case_ids.append(c.iris_case_id)
                match_reasons.append(f"Ticket #{ticket} vinculado al Caso #{c.iris_case_id}")
            elif domain and (c.primary_domain or "").lower() == domain:
                related_case_ids.append(c.iris_case_id)
                match_reasons.append(f"Dominio '{domain}' coincide con el Caso #{c.iris_case_id}")

        # 3. Buscar en lista viva de Casos DFIR-IRIS (si se proporciona)
        if live_iris_cases:
            for ic in live_iris_cases:
                cid = ic.get("case_id")
                cname = (ic.get("case_name") or "").lower()
                if not cid:
                    continue
                if ticket and len(ticket) >= 5 and ticket in cname and cid not in related_case_ids:
                    related_case_ids.append(cid)
                    match_reasons.append(f"Ticket #{ticket} detectado en el título del Caso IRIS #{cid}")
                elif domain and len(domain) >= 4 and domain in cname and cid not in related_case_ids:
                    related_case_ids.append(cid)
                    match_reasons.append(f"Dominio '{domain}' detectado en el título del Caso IRIS #{cid}")

        related_alert_ids = list(dict.fromkeys(related_alert_ids))
        related_case_ids = list(dict.fromkeys(related_case_ids))

        return {
            "is_duplicate_ticket": any("Mismo ticket" in r or "detectado en el título" in r for r in match_reasons),
            "correlated_alert_ids": related_alert_ids,
            "correlated_case_ids": related_case_ids,
            "reasons": match_reasons,
        }

