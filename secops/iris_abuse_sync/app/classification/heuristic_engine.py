import re
from typing import Any, Dict, List

from app.classification.taxonomy import SOC_CATEGORIES, SEVERITY_NAME_TO_IRIS_ID
from app.ingestion.base import NormalizedIngestPayload


class HeuristicClassifier:
    """Motor determinista de clasificación multi-eje con explicación de señales."""

    @classmethod
    def evaluate(cls, payload: NormalizedIngestPayload) -> Dict[str, Any]:
        text_lower = (payload.original_content or "").lower()
        signals: List[str] = []

        category_code = "abuse_phishing"
        reported_activity = "phishing"
        confirmed_incident_type = "pending_investigation"
        entry_vector = "unknown"
        root_cause = "unknown"
        verification_state = "pendiente"
        is_technical_compromise = False
        confidence = 75

        # 1. Requerimientos de autoridad (SSPC, COFEPRIS, Policía Cibernética)
        if payload.reporter_type == "authority" or re.search(
            r"\b(?:cofepris|sspc|secretar[íi]a de seguridad|polic[íi]a cibern[ée]tica|ciberpatrullaje)\b",
            text_lower,
        ):
            category_code = "authority_req"
            if "cofepris" in text_lower or "farmac" in text_lower or "tirzepatida" in text_lower or "sanitari" in text_lower:
                reported_activity = "regulated_goods_sale"
                signals.append("Oficio de SSPC / COFEPRIS sobre comercialización de productos sujetos a regulación sanitaria.")
                root_cause = "regulatory_compliance_issue"
            else:
                reported_activity = "fraud_scam_site"
                signals.append("Reporte oficial de Policía Cibernética por presunto sitio de fraude comercial.")
                root_cause = "malicious_customer_registration"
            confirmed_incident_type = "authority_preservation_request"
            entry_vector = "not_applicable"
            is_technical_compromise = False
            confidence = 94

        # 2. Cambio no autorizado de Nameservers / Secuestro DNS
        elif re.search(
            r"cambi[óo] sin autorizaci[óo]n los nameservers|cambio de nameservers|DNS::DNS - NameServers",
            payload.original_content or "",
            re.IGNORECASE,
        ):
            category_code = "account_compromise"
            reported_activity = "unauthorized_dns_change"
            confirmed_incident_type = "confirmed_client_panel_compromise"
            entry_vector = "compromised_panel_credentials"
            root_cause = "weak_or_leaked_credentials"
            verification_state = "confirmado"
            is_technical_compromise = True
            confidence = 92
            signals.append("Cliente reporta cambio no autorizado de Nameservers DNS y solicita bitácora de accesos al panel.")

        # 3. Disputa de dominio / Typosquatting sin phishing confirmado
        elif re.search(
            r"Disputa de Dominio|typosquatting|brand impersonation and misuse|not alleging confirmed phishing",
            payload.original_content or "",
            re.IGNORECASE,
        ):
            category_code = "brand_dispute"
            reported_activity = "brand_impersonation_typosquatting"
            if any(a["action_type"] == "orientacion_wipo" for a in payload.analyst_actions_detected):
                confirmed_incident_type = "brand_dispute_no_abuse"
                verification_state = "no_corroborado"
                signals.append("Revisión del analista concluyó disputa de marca sin suplantación activa (orientación WIPO).")
            else:
                confirmed_incident_type = "pending_investigation"
            entry_vector = "not_applicable"
            root_cause = "legitimate_domain_similarity"
            is_technical_compromise = False
            confidence = 90
            signals.append("Reporte de protección de marca / typosquatting sin alegación de phishing activo confirmado.")

        # 4. Envío de Spam con cabeceras SMTP o mención explícita de spam
        elif payload.smtp_analysis.get("has_smtp_headers") or re.search(
            r"\b(?:haciendo spam|unsolicited bulk|env[íi]o masivo de correo|received-spf:|dkim-signature:)\b",
            text_lower,
        ):
            category_code = "abuse_spam"
            reported_activity = "spam_outbound"
            confirmed_incident_type = "confirmed_outbound_spam" if payload.smtp_analysis.get("has_smtp_headers") else "pending_investigation"
            entry_vector = "compromised_smtp_credentials" if payload.authenticated_account else "unknown"
            root_cause = "weak_or_leaked_credentials" if payload.authenticated_account else "unknown"
            verification_state = "confirmado" if payload.smtp_analysis.get("has_smtp_headers") else "pendiente"
            is_technical_compromise = True
            confidence = 91
            signals.append("Presencia de cabeceras SMTP (Received-SPF / DKIM / envelope-from) o denuncia de envío de spam.")

        # 5. Sitio web comprometido / Redirección maliciosa (ej. redirecciona a página china / apuestas)
        elif re.search(
            r"re\s*direcciona a una p[áa]gina|p[áa]gina china|spam de apuestas|defacement|webshell",
            text_lower,
        ):
            category_code = "web_compromise"
            reported_activity = "web_defacement_redirect"
            confirmed_incident_type = "confirmed_cms_compromise"
            entry_vector = "vulnerable_cms_plugin"
            root_cause = "outdated_cms_or_plugin"
            verification_state = "confirmado" if payload.analyst_actions_detected else "pendiente"
            is_technical_compromise = True
            confidence = 90
            signals.append("Reporte de redirección anómala / modificación no autorizada en subdominio o sitio web alojado.")

        # 6. Listado en RBL / Blacklist Master
        elif payload.source_type == "blacklist_master" or re.search(
            r"\b(?:spamhaus|barracuda|spamcop|sorbs|listed in rbl|blacklist)\b",
            text_lower,
        ):
            category_code = "blacklist_rbl"
            reported_activity = "rbl_ip_listing"
            confirmed_incident_type = "rbl_reputation_episode"
            entry_vector = "not_applicable"
            root_cause = "shared_ip_neighbor_reputation"
            verification_state = "confirmado"
            is_technical_compromise = False
            confidence = 95
            signals.append("Detección de dirección IP listada en proveedor RBL.")

        # 7. Phishing / Suplantación de marca financiera o comercial (Netcraft, Axur, A3Sec, etc.)
        elif re.search(r"\b(?:phishing|steal user credentials|fraudulent content|x-arf|estafas, uso de marca)\b", text_lower):
            category_code = "abuse_phishing"
            reported_activity = "phishing"
            if payload.is_hosted_internally is False and payload.bastion_domains_summary:
                confirmed_incident_type = "domain_only_external_hosting"
                verification_state = "alojado_externo"
                entry_vector = "not_applicable"
                root_cause = "external_infrastructure_issue"
                is_technical_compromise = False
                signals.append("Reporte de phishing, pero Bastion indica nameservers/alojamiento externo a NEUBOX/Hospedando.")
            else:
                confirmed_incident_type = "confirmed_phishing_hosted" if payload.analyst_actions_detected else "pending_investigation"
                entry_vector = "vulnerable_cms_plugin" if "/wp-" in text_lower else "unknown"
                root_cause = "outdated_cms_or_plugin" if "/wp-" in text_lower else "unknown"
                verification_state = "confirmado" if payload.analyst_actions_detected else "pendiente"
                is_technical_compromise = True
                signals.append(f"Reporte de phishing / suplantación de identidad (Marca afectada: {payload.impersonated_brand or 'Detectada en texto'}).")
            confidence = 89

        cat_meta = SOC_CATEGORIES.get(category_code, SOC_CATEGORIES["abuse_phishing"])

        # Construir acciones iniciales propuestas + ejecutadas con los 8 estados oficiales
        proposed_actions: List[Dict[str, Any]] = []
        existing_types = {a["action_type"] for a in payload.analyst_actions_detected}
        for act in payload.analyst_actions_detected:
            proposed_actions.append(
                {
                    "action_type": act["action_type"],
                    "title": act["title"],
                    "status": act.get("status", "ejecutada"),
                    "result_notes": act.get("evidence", ""),
                    "provenance": "rule",
                }
            )

        if "verificacion_dns_bastion" not in existing_types:
            proposed_actions.append(
                {
                    "action_type": "verificacion_dns_bastion",
                    "title": "Verificación de resolución DNS, WHOIS y alojamiento (Bastion)",
                    "status": "ejecutada" if payload.bastion_domains_summary else "pendiente",
                    "result_notes": f"Se analizaron {len(payload.bastion_domains_summary)} dominio(s) en Bastion." if payload.bastion_domains_summary else "Pendiente de consulta.",
                    "provenance": "rule",
                }
            )

        if category_code == "brand_dispute" and "suspension_servicio" not in existing_types:
            proposed_actions.append(
                {
                    "action_type": "suspension_servicio",
                    "title": "Suspensión preventiva del servicio",
                    "status": "no_aplicable",
                    "result_notes": "No procede suspensión al tratarse de disputa de similitud de marca sin abuso técnico.",
                    "provenance": "rule",
                }
            )
        elif "suspension_servicio" not in existing_types and is_technical_compromise:
            proposed_actions.append(
                {
                    "action_type": "suspension_servicio",
                    "title": "Suspensión preventiva o contención del recurso reportado",
                    "status": "propuesta",
                    "result_notes": "Sugerida por heurística SOC tras corroboración técnica.",
                    "provenance": "rule",
                }
            )

        if "notificacion_cliente" not in existing_types:
            proposed_actions.append(
                {
                    "action_type": "notificacion_cliente",
                    "title": "Notificación al cliente titular del servicio",
                    "status": "propuesta",
                    "result_notes": "Pendiente de envío por analista.",
                    "provenance": "rule",
                }
            )

        # Hallazgos iniciales separados epistemológicamente (Alegación vs Hecho Confirmado)
        findings: List[Dict[str, Any]] = [
            {
                "title": f"Alegación del reportante ({payload.reporter})",
                "description": payload.report_summary[:450],
                "finding_nature": "reported_allegation",
                "verification_state": "indicio",
                "severity": cat_meta["severity_name"],
                "provenance": "rule",
            }
        ]
        if payload.bastion_domains_summary:
            for b in payload.bastion_domains_summary:
                if b.get("domain") == payload.primary_domain or b.get("base_domain") == payload.primary_domain:
                    findings.append(
                        {
                            "title": f"Verificación de infraestructura para {b['domain']}",
                            "description": (
                                f"Registrar: {b.get('registrar')}. "
                                f"Alojado en NEUBOX/HP: {'Sí' if b.get('hosted_internally') else 'No (Externo)'}. "
                                f"IP(s): {', '.join(b.get('hosting_ips') or ['N/A'])}. "
                                f"Servidor(es): {', '.join(b.get('servers') or ['N/A'])}."
                            ),
                            "finding_nature": "confirmed_compromise" if is_technical_compromise and b.get("hosted_internally") else "technical_indicator",
                            "verification_state": "confirmado" if b.get("hosted_internally") else "alojado_externo",
                            "severity": cat_meta["severity_name"],
                            "provenance": "rule",
                        }
                    )

        ticket_label = payload.abuse_ticket_id or payload.source_id or "S/N"
        domain_label = payload.primary_domain or payload.reported_ip or "activo-desconocido"
        official_title = f"{cat_meta['tag']} {domain_label} | {payload.organization}-{ticket_label}"

        return {
            "category_code": category_code,
            "tag": cat_meta["tag"],
            "category_name": cat_meta["name"],
            "iris_classification_id": cat_meta["iris_classification_id"],
            "iris_classification_name": cat_meta["iris_classification_name"],
            "iris_severity_id": cat_meta["iris_severity_id"],
            "severity": cat_meta["severity_name"],
            "reported_activity": reported_activity,
            "confirmed_incident_type": confirmed_incident_type,
            "entry_vector": entry_vector,
            "root_cause": root_cause,
            "verification_state": verification_state,
            "is_technical_compromise": is_technical_compromise,
            "confidence_score": confidence,
            "playbook_code": cat_meta["default_playbook"],
            "official_title": official_title,
            "signals": signals,
            "proposed_actions": proposed_actions,
            "proposed_findings": findings,
        }

