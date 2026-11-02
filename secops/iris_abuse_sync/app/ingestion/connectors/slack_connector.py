import hashlib
import hmac
import time
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.base import BaseConnector, NormalizedIngestPayload
from app.ingestion.normalizer import ReportNormalizer


class SlackEventsConnector(BaseConnector):
    """Conector para Slack Events API con verificación criptográfica HMAC-SHA256 y correlación de hilos."""

    connector_type = "slack"

    @staticmethod
    def verify_slack_signature(
        signing_secret: str,
        timestamp_header: str,
        signature_header: str,
        raw_body: bytes,
        tolerance_seconds: int = 300,
    ) -> bool:
        if not signing_secret or not timestamp_header or not signature_header:
            return False
        try:
            req_ts = int(timestamp_header)
        except ValueError:
            return False
        if abs(int(time.time()) - req_ts) > tolerance_seconds:
            return False
        sig_basestring = f"v0:{timestamp_header}:{raw_body.decode('utf-8', errors='replace')}"
        computed = (
            "v0="
            + hmac.new(
                signing_secret.encode("utf-8"),
                sig_basestring.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        )
        return hmac.compare_digest(computed, signature_header)

    def test_connection(self) -> Dict[str, Any]:
        signing_secret = (self.secret or self.config.get("signing_secret") or "").strip()
        return {
            "ok": bool(signing_secret),
            "status": "ready" if signing_secret else "missing_signing_secret",
            "webhook_endpoint": "/api/v1/webhooks/slack/events",
            "message": (
                "Endpoint de Slack Events API listo con verificación de firma HMAC-SHA256."
                if signing_secret
                else "Configura el Signing Secret de la Slack App para validar firmas de eventos."
            ),
        }

    def fetch_new_events(
        self,
        cursor: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        # Slack opera principalmente vía Webhook push (/api/v1/webhooks/slack/events)
        return [], dict(cursor or {})

    @classmethod
    def parse_webhook_event(
        cls,
        event_body: Dict[str, Any],
        default_org: str = "NBX",
    ) -> Optional[NormalizedIngestPayload]:
        ev = event_body.get("event") or {}
        if ev.get("type") not in ("message", "app_mention"):
            return None
        if ev.get("subtype") in ("message_deleted", "channel_join", "channel_leave"):
            return None

        text = ev.get("text") or ""
        channel = ev.get("channel") or "slack_channel"
        ts = ev.get("ts") or str(time.time())
        thread_ts = ev.get("thread_ts") or ts
        user = ev.get("user") or ev.get("bot_id") or "slack_user"

        payload = ReportNormalizer.normalize_text(
            text=text,
            filename=f"slack_{channel}_{ts}.txt",
            organization=default_org,
            source_type="slack",
            subject_override=f"Slack Alert ({channel}) — Hilo {thread_ts}",
            reporter_override=f"Slack User/Bot ({user})",
        )
        payload.source_instance = channel
        payload.source_id = f"{channel}:{ts}"
        payload.external_reference = f"slack_thread:{channel}:{thread_ts}"
        payload.raw_metadata = {
            "channel": channel,
            "ts": ts,
            "thread_ts": thread_ts,
            "is_thread_reply": bool(ev.get("thread_ts") and ev.get("thread_ts") != ts),
            "user": user,
        }
        return payload

