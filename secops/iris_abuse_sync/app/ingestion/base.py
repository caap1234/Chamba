from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttachmentItem(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: Optional[str] = None
    local_path: Optional[str] = None
    extracted_text: Optional[str] = None


class IndicatorItem(BaseModel):
    value: str
    ioc_type: str  # domain, url, ip-src, ip-dst, email-src, hostname, sha256
    role: str  # ip_hosting, ip_reported, ip_src, ip_auth, ip_rbl, domain_reported, domain_brand, url_reported, email_sender, server_hostname
    description: str = ""
    is_affected_asset: bool = False
    tlp_id: int = 2
    provenance: str = "rule"  # rule, ai, manual


class NormalizedIngestPayload(BaseModel):
    # Campos mínimos obligatorios del contrato de ingesta
    source_type: str = "manual_file"  # zammad, whmcs, imap, slack, blacklist_master, manual_file, manual_text
    source_instance: str = "default"
    source_id: str = "0"
    organization: str = "NBX"  # NBX | HP
    received_at: str = Field(default_factory=_utcnow_iso)
    reported_at: Optional[str] = None
    reporter: str = "No especificado"
    reporter_email: Optional[str] = None
    reporter_type: str = "external_reporter"  # authority, brand_protection, customer, internal_bot, rbl_monitor, external_reporter
    subject: str = ""
    original_content: str = ""
    attachments: List[AttachmentItem] = Field(default_factory=list)
    external_reference: Optional[str] = None
    source_url: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    processing_status: str = "normalized"

    # Identificación técnica normalizada
    abuse_ticket_id: Optional[str] = None
    holder_ticket_id: Optional[str] = None
    client_id: Optional[str] = None
    service_id: Optional[str] = None
    service_plan: Optional[str] = None
    primary_domain: Optional[str] = None
    subdomains: List[str] = Field(default_factory=list)
    reported_urls: List[str] = Field(default_factory=list)
    impersonated_brand: Optional[str] = None
    impersonated_Select_domain: Optional[str] = None
    registrar_name: Optional[str] = None
    is_internal_registrar: Optional[bool] = None
    is_hosted_internally: Optional[bool] = None
    nameservers: List[str] = Field(default_factory=list)
    server_name: Optional[str] = None
    hosting_ip: Optional[str] = None
    reported_ip: Optional[str] = None
    src_ip: Optional[str] = None
    auth_ip: Optional[str] = None
    rbl_ip: Optional[str] = None
    authenticated_account: Optional[str] = None

    # Indicadores separados por rol y análisis técnico extraído
    indicators: List[IndicatorItem] = Field(default_factory=list)
    indicators_by_role: Dict[str, List[str]] = Field(default_factory=dict)
    bastion_domains_summary: List[Dict[str, Any]] = Field(default_factory=list)
    smtp_analysis: Dict[str, Any] = Field(default_factory=dict)
    analyst_actions_detected: List[Dict[str, Any]] = Field(default_factory=list)
    report_summary: str = ""
    field_provenance: Dict[str, str] = Field(default_factory=dict)


class BaseConnector(ABC):
    """Interfaz común para todos los conectores de ingesta multicanal."""

    connector_type: str = "base"

    def __init__(self, config_dict: Dict[str, Any], secret_value: Optional[str] = None):
        self.config = config_dict or {}
        self.secret = secret_value

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Prueba conectividad y credenciales contra la fuente."""
        raise NotImplementedError

    @abstractmethod
    def fetch_new_events(self, cursor: Optional[Dict[str, Any]] = None) -> tuple[List[NormalizedIngestPayload], Dict[str, Any]]:
        """Obtiene eventos nuevos desde el cursor y devuelve (eventos, nuevo_cursor)."""
        raise NotImplementedError

