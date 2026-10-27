import json
from typing import Dict, Any, List, Optional
import config


class CaseBuilder:
    """
    Constructs the DFIR-IRIS case payload and note structures
    following the SOC Abuse Lite v2.0 format and Neubox/Hospedando standards.
    """

    @staticmethod
    def detect_customer(parsed: Dict[str, Any]) -> str:
        """
        Auto-detects whether the ticket belongs to Hospedando or Neubox.
        """
        raw_text = parsed.get("clean_text") or parsed.get("raw_text", "").lower()
        if "hospedando.com.mx" in raw_text or "hp:" in raw_text or parsed.get("client_ticket"):
            return "hospedando"
        return "neubox"

    @classmethod
    def build(
        cls,
        parsed: Dict[str, Any],
        classification: Dict[str, Any],
        customer_key: Optional[str] = None,
        overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        overrides = overrides or {}

        # 1. Resolve Customer & Code
        if not customer_key:
            customer_key = overrides.get("customer_key") or cls.detect_customer(parsed)

        cust_info = config.CUSTOMERS.get(customer_key.lower(), config.CUSTOMERS["neubox"])
        customer_id = cust_info["id"]
        customer_name = cust_info["name"]
        customer_code = cust_info["code"]  # NBX or HP

        # 2. Extract and allow overrides for IDs
        report_ticket = overrides.get("report_ticket") or parsed.get("ticket_id", "")
        client_ticket = overrides.get("client_ticket") or parsed.get("client_ticket", "")
        client_id = overrides.get("client_id", "")
        service_id = overrides.get("service_id", "")
        server = overrides.get("server") or parsed.get("primary_server", "")
        asset = overrides.get("affected_asset") or parsed.get("affected_asset", "")

        prefix = classification.get("title_prefix", "[ABUSE]")
        template_name = classification.get("template_name", "abuse_phishing")

        # In case title, use client_ticket if HP customer and present, else report_ticket
        title_ticket_num = ""
        if customer_code == "HP" and client_ticket:
            title_ticket_num = client_ticket
        elif report_ticket:
            title_ticket_num = report_ticket
        elif client_ticket:
            title_ticket_num = client_ticket
        else:
            title_ticket_num = "S/N"

        ticket_tag = f"{customer_code}-{title_ticket_num}"

        # Exact title format matching screenshot:
        # [BRAND] clip-pagos.com | NBX-31733334
        # [BRAND] agriculturaregenerativadonjulio.com | HP-247629
        if asset:
            case_name = f"{prefix} {asset} | {ticket_tag}"
        else:
            case_name = f"{prefix} {ticket_tag}"

        if overrides.get("case_name"):
            case_name = overrides["case_name"]

        # 3. Build Summary / Description
        findings = []
        if server:
            findings.append(f"Alojado en servidor {server}")
        if parsed.get("primary_account"):
            findings.append(f"Cuenta autenticada: {parsed['primary_account']}")
        if client_ticket:
            findings.append(f"Ticket del titular: #{client_ticket}")
        if client_id:
            findings.append(f"ID Cliente: #{client_id}")
        if service_id:
            findings.append(f"ID Servicio: #{service_id}")

        findings_text = "; ".join(findings) if findings else "Alojamiento / Servicio bajo investigación"

        summary_md = (
            f"## Resumen del caso\n"
            f"- Reporte: {parsed.get('brief_summary', 'Denuncia de abuso recibida')}\n"
            f"- Activo afectado: {asset} ({parsed.get('primary_ip', 'IP no especificada')})\n"
            f"- Hallazgo: {findings_text}\n"
            f"- Acción y resultado: Pendiente de investigación por analista SOC\n"
        )
        if overrides.get("case_description"):
            summary_md = overrides["case_description"]

        # 4. Custom Attributes
        if overrides.get("custom_attributes"):
            custom_attributes = overrides["custom_attributes"]
        else:
            custom_attributes = {
                "01 Identificación": {
                    "Ticket de abuso": report_ticket,
                    "Dominio o activo reportado": parsed.get("primary_domain") or asset,
                    "IP reportada": parsed.get("primary_ip", ""),
                    "Ticket del titular": client_ticket
                }
            }

        # 5. Build Notes (SOC Abuse Lite v2.0)
        reported_loc = ""
        if parsed.get("reported_urls"):
            reported_loc = parsed["reported_urls"][0]
        elif parsed.get("primary_ip"):
            reported_loc = f"IP {parsed['primary_ip']}"
        elif parsed.get("primary_domain"):
            reported_loc = parsed["primary_domain"]

        reporter_full = parsed.get("reporter", "")
        if parsed.get("reporter_org") and parsed.get("reporter_org") not in reporter_full:
            reporter_full = f"{reporter_full} ({parsed['reporter_org']})"

        # Note 01: Reporte inicial
        note1_content = (
            f"## Reporte recibido\n"
            f"- Ticket de abuso: {report_ticket or 'No disponible'}\n"
            f"- Reportante: {reporter_full or 'No especificado'}\n"
            f"- Dominio / activo: {parsed.get('primary_domain') or asset}\n"
            f"- IP / URL reportada: {reported_loc}\n"
            f"- Descripción breve del reporte: {parsed.get('brief_summary', '')}\n\n"
            f"> Registrar solo datos disponibles. Adjuntar el reporte original como evidencia."
        )

        # Note 02: Investigación y evidencia
        tech_findings = []
        if server:
            tech_findings.append(f"Servidor: {server}")
        if parsed.get("primary_ip"):
            tech_findings.append(f"IP asociada: {parsed['primary_ip']}")
        if parsed.get("auth_accounts"):
            tech_findings.append(f"Cuenta autenticada en logs: {', '.join(parsed['auth_accounts'])}")
        if client_ticket:
            tech_findings.append(f"Ticket del titular ({customer_name}): #{client_ticket}")
        if client_id:
            tech_findings.append(f"ID del cliente: #{client_id}")
        if service_id:
            tech_findings.append(f"ID del servicio: #{service_id}")

        findings_summary = "; ".join(tech_findings) if tech_findings else "En proceso de revisión"

        evidence_body = ""
        if parsed.get("bastion_analysis"):
            evidence_body = parsed["bastion_analysis"]
        elif parsed.get("email_headers"):
            evidence_body = parsed["email_headers"]
        else:
            evidence_body = f"Ticket Helpdesk URL: {parsed.get('ticket_url', '')}\nReporte original recibido vía Helpdesk."

        note2_content = (
            f"## Revisión\n"
            f"- Se revisó: {'Análisis Bastion / DNS' if parsed.get('bastion_analysis') else ('Cabeceras de correo Exim / Logs' if parsed.get('email_headers') else 'Detalles del ticket Helpdesk')}\n"
            f"- Se encontró: {findings_summary}\n"
            f"- Evaluación (confirmado / no corroborado / pendiente): Pendiente de confirmación\n\n"
            f"## Evidencia relevante\n"
            f"```text\n"
            f"{evidence_body}\n"
            f"```\n\n"
            f"- Adjuntos / capturas: PDF Ticket {report_ticket}"
        )

        # Note 03: Acciones y resolución
        comm_ticket = f"Ticket {customer_name} #{client_ticket}" if client_ticket else "Pendiente"
        note3_content = (
            f"## Gestión\n"
            f"- Decisión y motivo: Pendiente de resolución por analista SOC.\n"
            f"- Acción ejecutada (o pendiente): Notificación / suspensión según proceda.\n"
            f"- Comunicación / ticket (si aplica): {comm_ticket}\n"
            f"- Verificación y resultado: Pendiente\n"
            f"- Estado final / pendientes: Caso abierto para seguimiento."
        )

        # If user passed custom notes, apply them
        notes = overrides.get("notes") or [
            {"title": "01 Reporte inicial", "content": note1_content},
            {"title": "02 Investigación y evidencia", "content": note2_content},
            {"title": "03 Acciones y resolución", "content": note3_content}
        ]

        return {
            "case_name": case_name,
            "case_description": summary_md,
            "case_customer": customer_id,
            "case_soc_id": title_ticket_num,
            "customer_key": customer_key,
            "customer_name": customer_name,
            "customer_code": customer_code,
            "template_name": template_name,
            "title_prefix": prefix,
            "classification_confidence": classification.get("confidence", 1.0),
            "custom_attributes": custom_attributes,
            "notes": notes,
            "iocs": overrides.get("iocs") or parsed.get("iocs", []),
            "metadata": {
                "ticket_id": report_ticket,
                "client_ticket": client_ticket,
                "client_id": client_id,
                "service_id": service_id,
                "server": server,
                "ticket_url": parsed.get("ticket_url"),
                "affected_asset": asset,
                "customer_name": customer_name,
                "template_name": template_name,
                "reasons": classification.get("reasons", [])
            }
        }
