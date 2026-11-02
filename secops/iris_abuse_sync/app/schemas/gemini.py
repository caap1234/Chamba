from typing import List, Optional
from pydantic import BaseModel, Field


class GeminiFindingProposal(BaseModel):
    title: str = Field(..., description="Título conciso del hallazgo o alegación")
    description: str = Field(..., description="Descripción técnica basada estrictamente en la evidencia")
    finding_nature: str = Field(
        default="reported_allegation",
        description="Uno de: reported_allegation, confirmed_compromise, technical_indicator, uncorroborated_claim, brand_dispute_only, authority_request_only, rbl_listing_only, no_technical_intervention",
    )
    verification_state: str = Field(
        default="indicio",
        description="Uno de: confirmado, probable, indicio, no_corroborado, falso_positivo, solo_registro_dominio, alojado_externo, no_aplicable",
    )
    severity: str = Field(default="Medium", description="Low, Medium, High, Critical")


class GeminiActionProposal(BaseModel):
    action_type: str = Field(..., description="Código del catálogo de acciones SOC")
    title: str = Field(..., description="Nombre descriptivo de la acción")
    status: str = Field(
        default="propuesta",
        description="Uno de los 8 estados: propuesta, autorizada, pendiente, en_ejecucion, ejecutada, verificada, cancelada, no_aplicable",
    )
    result_notes: str = Field(default="", description="Evidencia o motivo documentado")


class GeminiIncidentAnalysis(BaseModel):
    category_code: str = Field(
        default="abuse_phishing",
        description="Uno de: abuse_phishing, abuse_malware, abuse_spam, web_compromise, account_compromise, authority_req, brand_dispute, copyright_dmca, blacklist_rbl, bruteforce_scan, dos_ddos",
    )
    reported_activity: str = Field(..., description="Actividad alegada por el reportante")
    confirmed_incident_type: str = Field(
        ...,
        description="Naturaleza real confirmada (no dar por confirmado lo que esté pendiente de revisión)",
    )
    entry_vector: str = Field(default="unknown", description="Vector de entrada o not_applicable")
    root_cause: str = Field(default="unknown", description="Causa raíz o not_applicable")
    severity: str = Field(default="Medium", description="Informational, Low, Medium, High, Critical")
    is_technical_compromise: bool = Field(default=False)
    confidence_score: int = Field(default=80, ge=0, le=100)
    primary_domain: Optional[str] = None
    impersonated_brand: Optional[str] = None
    reported_ip: Optional[str] = None
    hosting_ip: Optional[str] = None
    server_name: Optional[str] = None
    abuse_ticket_id: Optional[str] = None
    holder_ticket_id: Optional[str] = None
    client_id: Optional[str] = None
    service_id: Optional[str] = None
    executive_summary: str = Field(..., description="Resumen ejecutivo técnico en español neutro")
    reported_claims_summary: str = Field(..., description="Qué alega el reportante sin asumirlo como hecho probado")
    confirmed_facts_summary: str = Field(..., description="Qué hechos técnicos están probados en las notas/evidencia")
    conclusion: str = Field(..., description="Dictamen o estado actual de resolución")
    findings: List[GeminiFindingProposal] = Field(default_factory=list)
    actions: List[GeminiActionProposal] = Field(default_factory=list)
    ai_reasoning: str = Field(default="", description="Justificación breve de la clasificación")

