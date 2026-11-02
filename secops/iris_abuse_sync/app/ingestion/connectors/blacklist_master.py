from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import httpx
from sqlalchemy.orm import Session

from app.ingestion.base import BaseConnector, IndicatorItem, NormalizedIngestPayload
from app.models.case_extended import RblEpisode


class SentinelXBlacklistMasterClient:
    """Cliente compatible con la API de Blacklist Master inspeccionada en SentinelX-SIEM."""

    def __init__(self, *, base_url: str, api_key: str, timeout_s: float = 15.0) -> None:
        self.base_url = (base_url or "https://blacklistmaster.com").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout_s

    def fetch_ipbl(self) -> List[Dict[str, Any]]:
        """GET /restapi/v1/ipbl?apikey=..."""
        if not self.api_key:
            return []
        url = f"{self.base_url}/restapi/v1/ipbl"
        params = {"apikey": self.api_key}
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(url, params=params)
            r.raise_for_status()
            data = r.json()
        if not isinstance(data, dict) or data.get("status") != "SUCCESS":
            raise RuntimeError(f"BlacklistMaster API error: {data}")
        return data.get("IPs", []) or []


class BlacklistMasterConnector(BaseConnector):
    """Conector e integrador de monitoreo RBL (Blacklist Master) con deduplicación de episodios."""

    connector_type = "blacklist_master"

    def test_connection(self) -> Dict[str, Any]:
        api_key = self.secret or self.config.get("api_key")
        base_url = self.config.get("base_url") or "https://blacklistmaster.com"
        if api_key:
            try:
                cli = SentinelXBlacklistMasterClient(base_url=base_url, api_key=api_key)
                items = cli.fetch_ipbl()
                return {
                    "ok": True,
                    "status": "connected",
                    "mode": "api_client",
                    "total_monitored_in_api": len(items),
                    "base_url": base_url,
                }
            except Exception as e:
                return {
                    "ok": False,
                    "status": "error",
                    "message": f"Fallo al conectar con Blacklist Master API: {e}",
                }
        return {
            "ok": True,
            "status": "ready",
            "mode": "builtin_dnsbl",
            "message": "Operando mediante motor DNSBL directo (6 zonas RBL estándar configuradas)",
            "monitored_rbls": ["Spamhaus ZEN", "Barracuda", "SpamCop", "SORBS", "SORBS DUL", "LashBack UBL"],
        }

    def fetch_new_events(
        self,
        cursor: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        return [], dict(cursor or {})

    @classmethod
    def process_rbl_event(
        cls,
        db: Session,
        *,
        ip_address: str,
        rbl_provider: str,
        server_name: Optional[str] = None,
        organization: str = "NBX",
        event_status: str = "listed",  # listed | delisted
        reason: Optional[str] = None,
    ) -> Tuple[RblEpisode, Optional[NormalizedIngestPayload], bool]:
        """Registra o actualiza un episodio RBL en PostgreSQL.
        Si ya existe un episodio activo para (ip_address + rbl_provider), incrementa check_count
        y NO crea una nueva alerta duplicada (`is_new_episode=False`)."""
        now = datetime.now(timezone.utc)
        ip_clean = ip_address.strip()
        rbl_clean = rbl_provider.strip()
        org_clean = (organization or "NBX").upper()

        active_ep = (
            db.query(RblEpisode)
            .filter(
                RblEpisode.ip_address == ip_clean,
                RblEpisode.rbl_provider == rbl_clean,
                RblEpisode.status.in_(["active", "delisting_requested"]),
            )
            .first()
        )

        if event_status == "delisted":
            if active_ep:
                active_ep.status = "delisted"
                active_ep.delisted_at = now
                active_ep.last_seen_at = now
                db.commit()
                db.refresh(active_ep)
                return active_ep, None, False
            ep = RblEpisode(
                ip_address=ip_clean,
                server_name=server_name,
                organization=org_clean,
                rbl_provider=rbl_clean,
                status="delisted",
                reason=reason,
                first_seen_at=now,
                last_seen_at=now,
                delisted_at=now,
            )
            db.add(ep)
            db.commit()
            db.refresh(ep)
            return ep, None, False

        # Si ya está activo, solo actualizar last_seen_at y contador sin disparar alerta repetida
        if active_ep:
            active_ep.last_seen_at = now
            active_ep.check_count = (active_ep.check_count or 1) + 1
            if reason:
                active_ep.reason = reason
            if server_name and not active_ep.server_name:
                active_ep.server_name = server_name
            db.commit()
            db.refresh(active_ep)
            return active_ep, None, False

        # Crear nuevo episodio RBL y su NormalizedIngestPayload para generar una única alerta
        new_ep = RblEpisode(
            ip_address=ip_clean,
            server_name=server_name,
            organization=org_clean,
            rbl_provider=rbl_clean,
            status="active",
            reason=reason or f"IP {ip_clean} detectada en lista negra {rbl_clean}",
            first_seen_at=now,
            last_seen_at=now,
            check_count=1,
        )
        db.add(new_ep)
        db.commit()
        db.refresh(new_ep)

        summary = (
            f"Blacklist Master detectó que la dirección IP {ip_clean} "
            f"(Servidor: {server_name or 'Por identificar'}) fue listada en el proveedor RBL {rbl_clean}. "
            f"Motivo reportado: {reason or 'Reputación SMTP / Envío de spam'}."
        )
        indicators = [
            IndicatorItem(
                value=ip_clean,
                ioc_type="ip-src",
                role="ip_rbl",
                description=f"IP listada en RBL ({rbl_clean})",
                is_affected_asset=True,
            )
        ]
        if server_name:
            indicators.append(
                IndicatorItem(
                    value=server_name,
                    ioc_type="hostname",
                    role="server_hostname",
                    description="Servidor afectado por listado RBL",
                    is_affected_asset=True,
                )
            )

        payload = NormalizedIngestPayload(
            source_type="blacklist_master",
            source_instance=rbl_clean,
            source_id=f"rbl_ep_{new_ep.id}",
            organization=org_clean,
            reporter=f"Blacklist Master ({rbl_clean})",
            reporter_type="rbl_monitor",
            subject=f"[RBL] {ip_clean} listada en {rbl_clean} ({server_name or org_clean})",
            original_content=summary,
            external_reference=f"rbl:{rbl_clean}:{ip_clean}",
            primary_domain=server_name or ip_clean,
            server_name=server_name,
            hosting_ip=ip_clean,
            reported_ip=ip_clean,
            rbl_ip=ip_clean,
            indicators=indicators,
            indicators_by_role={"ip_rbl": [ip_clean], "server_hostname": [server_name] if server_name else []},
            report_summary=summary,
            raw_metadata={"rbl_episode_id": new_ep.id, "rbl_provider": rbl_clean},
        )
        return new_ep, payload, True

