from typing import Any, Dict, List

# 8 Estados oficiales de acciones (requisito explícito de negocio)
ACTION_STATUSES = [
    {"code": "propuesta", "label": "Propuesta", "badge": "info"},
    {"code": "autorizada", "label": "Autorizada", "badge": "primary"},
    {"code": "pendiente", "label": "Pendiente", "badge": "warning"},
    {"code": "en_ejecucion", "label": "En ejecución", "badge": "accent"},
    {"code": "ejecutada", "label": "Ejecutada", "badge": "success"},
    {"code": "verificada", "label": "Verificada", "badge": "verified"},
    {"code": "cancelada", "label": "Cancelada", "badge": "muted"},
    {"code": "no_aplicable", "label": "No aplicable", "badge": "neutral"},
]

VALID_ACTION_STATUS_CODES = {s["code"] for s in ACTION_STATUSES}

# Catálogo de acciones reutilizables SOC
STANDARD_ACTIONS_CATALOG = [
    {"code": "verificacion_dns_bastion", "title": "Verificación de resolución DNS, WHOIS y alojamiento (Bastion)"},
    {"code": "preservacion_evidencia", "title": "Preservación forense del reporte y evidencia con hash SHA-256"},
    {"code": "notificacion_cliente", "title": "Notificación al cliente titular del servicio"},
    {"code": "suspension_servicio", "title": "Suspensión preventiva del servicio en WHMCS / servidor"},
    {"code": "cuarentena_archivos", "title": "Cuarentena o retiro de archivos / directorio malicioso"},
    {"code": "rotacion_credenciales", "title": "Rotación de contraseñas de correo / panel / FTP"},
    {"code": "sincronizacion_dns", "title": "Restablecimiento de Nameservers o sincronización de zona DNS"},
    {"code": "analisis_cabeceras_smtp", "title": "Análisis de cabeceras SMTP (SPF, DKIM, DMARC y client-ip)"},
    {"code": "revision_logs_exim", "title": "Revisión de cola Exim y bitácoras de envío saliente"},
    {"code": "auditoria_accesos_panel", "title": "Auditoría de accesos a área de clientes y panel de hosting"},
    {"code": "solicitud_delisting_rbl", "title": "Solicitud de delisting ante proveedor RBL"},
    {"code": "verificacion_delisting_rbl", "title": "Verificación de retiro efectivo en lista negra (RBL)"},
    {"code": "orientacion_wipo", "title": "Respuesta de orientación sobre disputa de marca (WIPO/UDRP)"},
    {"code": "respuesta_institucional", "title": "Respuesta formal a requerimiento de autoridad competente"},
    {"code": "sin_intervencion_tecnica", "title": "Cierre administrativo sin intervención técnica sobre el servicio"},
]

# Eje 1: Actividad reportada (lo que alega el denunciante)
REPORTED_ACTIVITIES = [
    {"code": "phishing", "label": "Phishing / Captura de credenciales"},
    {"code": "malware_distribution", "label": "Distribución de Malware / Troyano"},
    {"code": "web_defacement_redirect", "label": "Sitio Web Comprometido / Redirección Maliciosa"},
    {"code": "spam_outbound", "label": "Envío de Correo No Solicitado (Spam)"},
    {"code": "unauthorized_dns_change", "label": "Cambio No Autorizado de Nameservers / DNS"},
    {"code": "brand_impersonation_typosquatting", "label": "Disputa de Dominio / Uso de Marca / Typosquatting"},
    {"code": "copyright_dmca", "label": "Infracción de Derechos de Autor / DMCA"},
    {"code": "regulated_goods_sale", "label": "Comercialización Regulada / Requerimiento Sanitario (COFEPRIS/SSPC)"},
    {"code": "fraud_scam_site", "label": "Sitio de Fraude Comercial / Estafa"},
    {"code": "rbl_ip_listing", "label": "IP de Servidor Listada en Lista Negra (RBL)"},
    {"code": "bruteforce_scan", "label": "Fuerza Bruta / Escaneo de Red"},
    {"code": "dos_ddos", "label": "Ataque de Denegación de Servicio (DoS/DDoS)"},
    {"code": "unknown", "label": "Desconocida / En análisis"},
    {"code": "not_applicable", "label": "No aplicable"},
]

# Eje 2: Incidente confirmado / Naturaleza real dictaminada por el analista
CONFIRMED_INCIDENT_TYPES = [
    {"code": "pending_investigation", "label": "Pendiente de corroboración técnica", "is_compromise": False},
    {"code": "confirmed_phishing_hosted", "label": "Phishing alojado confirmado", "is_compromise": True},
    {"code": "confirmed_cms_compromise", "label": "Compromiso de aplicación web / CMS vulnerado", "is_compromise": True},
    {"code": "confirmed_email_account_compromise", "label": "Compromiso de cuenta de correo SMTP", "is_compromise": True},
    {"code": "confirmed_client_panel_compromise", "label": "Compromiso de cuenta de cliente / Secuestro DNS", "is_compromise": True},
    {"code": "confirmed_malicious_tenant_signup", "label": "Contratación maliciosa / Servicio dedicado a fraude", "is_compromise": True},
    {"code": "confirmed_outbound_spam", "label": "Envío masivo de spam confirmado", "is_compromise": True},
    {"code": "uncorroborated_allegation", "label": "Denuncia no corroborada (sin actividad maliciosa visible)", "is_compromise": False},
    {"code": "brand_dispute_no_abuse", "label": "Disputa de marca / Similitud de dominio sin abuso técnico", "is_compromise": False},
    {"code": "authority_preservation_request", "label": "Requerimiento de autoridad / Preservación y revisión legal", "is_compromise": False},
    {"code": "rbl_reputation_episode", "label": "Episodio de reputación RBL en IP compartida", "is_compromise": False},
    {"code": "domain_only_external_hosting", "label": "Dominio registrado en NBX/HP pero alojado con proveedor externo", "is_compromise": False},
    {"code": "closed_no_technical_intervention", "label": "Cerrado sin intervención técnica", "is_compromise": False},
    {"code": "false_positive", "label": "Falso positivo confirmado", "is_compromise": False},
    {"code": "unknown", "label": "Desconocido", "is_compromise": False},
    {"code": "not_applicable", "label": "No aplicable", "is_compromise": False},
]

# Eje 3: Vector de entrada
ENTRY_VECTORS = [
    {"code": "vulnerable_cms_plugin", "label": "Plugin / Tema o CMS vulnerable (WordPress/Joomla/etc.)"},
    {"code": "compromised_smtp_credentials", "label": "Credenciales de buzón SMTP comprometidas"},
    {"code": "compromised_panel_credentials", "label": "Credenciales de área de clientes / cPanel / DirectAdmin comprometidas"},
    {"code": "fraudulent_service_purchase", "label": "Registro de dominio / hosting por actor malicioso"},
    {"code": "unauthorized_nameserver_change", "label": "Modificación no autorizada de Nameservers"},
    {"code": "exposed_script_upload", "label": "Subida de script o mailer en directorio web"},
    {"code": "unknown", "label": "Desconocido (en investigación)"},
    {"code": "not_applicable", "label": "No aplicable (sin intrusión técnica)"},
]

# Eje 4: Causa raíz
ROOT_CAUSES = [
    {"code": "outdated_cms_or_plugin", "label": "Software web / CMS o plugins desactualizados"},
    {"code": "weak_or_leaked_credentials", "label": "Contraseñas débiles, reutilizadas o filtradas por infostealer"},
    {"code": "malicious_customer_registration", "label": "Uso intencional del servicio por el titular para fines ilícitos"},
    {"code": "compromised_end_user_device", "label": "Equipo local del cliente infectado"},
    {"code": "shared_ip_neighbor_reputation", "label": "Afectación colateral por IP compartida en RBL"},
    {"code": "legitimate_domain_similarity", "label": "Coincidencia o similitud de nombre comercial sin suplantación"},
    {"code": "regulatory_compliance_issue", "label": "Incumplimiento regulatorio / sanitario del contenido del cliente"},
    {"code": "external_infrastructure_issue", "label": "Contenido alojado en infraestructura ajena a NEUBOX/Hospedando"},
    {"code": "unknown", "label": "Desconocida / No determinada"},
    {"code": "not_applicable", "label": "No aplicable"},
]

# Mapeo de categorías SOC a Clasificaciones Nativas y Severidades de DFIR-IRIS v2.4.29
SOC_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "abuse_phishing": {
        "code": "abuse_phishing",
        "tag": "[PHISH]",
        "name": "Phishing / Suplantación de Identidad",
        "iris_classification_id": 30,
        "iris_classification_name": "fraud:phishing",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_phishing",
        "default_reported_activity": "phishing",
    },
    "abuse_malware": {
        "code": "abuse_malware",
        "tag": "[MALW]",
        "name": "Malware / Webshell / Distribución",
        "iris_classification_id": 7,
        "iris_classification_name": "malicious-code:trojan-malware",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_web_compromise",
        "default_reported_activity": "malware_distribution",
    },
    "abuse_spam": {
        "code": "abuse_spam",
        "tag": "[SPAM]",
        "name": "Spam / Envío Masivo No Solicitado",
        "iris_classification_id": 1,
        "iris_classification_name": "abusive-content:spam",
        "iris_severity_id": 1,  # Medium
        "severity_name": "Medium",
        "default_playbook": "pb_abuse_spam",
        "default_reported_activity": "spam_outbound",
    },
    "web_compromise": {
        "code": "web_compromise",
        "tag": "[COMP]",
        "name": "Sitio Web Comprometido / Redirección Maliciosa",
        "iris_classification_id": 21,
        "iris_classification_name": "intrusion:application-compromise",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_web_compromise",
        "default_reported_activity": "web_defacement_redirect",
    },
    "account_compromise": {
        "code": "account_compromise",
        "tag": "[ACCT]",
        "name": "Acceso No Autorizado / Compromiso de Cuenta",
        "iris_classification_id": 18,
        "iris_classification_name": "intrusion:unprivileged-account-compromise",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_account_compromise",
        "default_reported_activity": "unauthorized_dns_change",
    },
    "authority_req": {
        "code": "authority_req",
        "tag": "[AUTH]",
        "name": "Autoridades / Requerimiento u Oficio Formal",
        "iris_classification_id": 32,
        "iris_classification_name": "conformity:regulator",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_authority_req",
        "default_reported_activity": "regulated_goods_sale",
    },
    "brand_dispute": {
        "code": "brand_dispute",
        "tag": "[BRAND]",
        "name": "Disputa de Marca / Similitud de Dominio",
        "iris_classification_id": 29,
        "iris_classification_name": "fraud:masquerade",
        "iris_severity_id": 4,  # Low
        "severity_name": "Low",
        "default_playbook": "pb_brand_dispute",
        "default_reported_activity": "brand_impersonation_typosquatting",
    },
    "blacklist_rbl": {
        "code": "blacklist_rbl",
        "tag": "[RBL]",
        "name": "IP en Blacklist / Reputación RBL",
        "iris_classification_id": 1,
        "iris_classification_name": "abusive-content:spam",
        "iris_severity_id": 1,  # Medium
        "severity_name": "Medium",
        "default_playbook": "pb_blacklist_rbl",
        "default_reported_activity": "rbl_ip_listing",
    },
    "abuse_fraud": {
        "code": "abuse_fraud",
        "tag": "[FRAUD]",
        "name": "Fraude / Scam Comercial",
        "iris_classification_id": 29,
        "iris_classification_name": "fraud:masquerade",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_abuse_fraud",
        "default_reported_activity": "fraud_scam_site",
    },
    "regulated_products": {
        "code": "regulated_products",
        "tag": "[REG]",
        "name": "Productos Regulados / Sustancias",
        "iris_classification_id": 32,
        "iris_classification_name": "conformity:regulator",
        "iris_severity_id": 5,  # High
        "severity_name": "High",
        "default_playbook": "pb_regulated_products",
        "default_reported_activity": "regulated_goods_sale",
    },
    "network_abuse": {
        "code": "network_abuse",
        "tag": "[NET]",
        "name": "Abuso de Red / Fuerza Bruta / Ataques",
        "iris_classification_id": 15,
        "iris_classification_name": "intrusion-attempts:login-attempts",
        "iris_severity_id": 1,  # Medium
        "severity_name": "Medium",
        "default_playbook": "pb_network_abuse",
        "default_reported_activity": "bruteforce_scan",
    },
    "copyright_complaint": {
        "code": "copyright_complaint",
        "tag": "[COPYRIGHT]",
        "name": "Derechos de Autor / Reclamo de Contenido",
        "iris_classification_id": 28,
        "iris_classification_name": "fraud:copyright",
        "iris_severity_id": 4,  # Low
        "severity_name": "Low",
        "default_playbook": "pb_copyright_complaint",
        "default_reported_activity": "copyright_dmca",
    },
    "copyright_dmca": {
        "code": "copyright_dmca",
        "tag": "[DMCA]",
        "name": "Infracción de Derechos de Autor / DMCA",
        "iris_classification_id": 28,
        "iris_classification_name": "fraud:copyright",
        "iris_severity_id": 4,  # Low
        "severity_name": "Low",
        "default_playbook": "pb_copyright_complaint",
        "default_reported_activity": "copyright_dmca",
    },
    "bruteforce_scan": {
        "code": "bruteforce_scan",
        "tag": "[SCAN]",
        "name": "Fuerza Bruta / Escaneo / Explotación",
        "iris_classification_id": 15,
        "iris_classification_name": "intrusion-attempts:login-attempts",
        "iris_severity_id": 1,  # Medium
        "severity_name": "Medium",
        "default_playbook": "pb_network_abuse",
        "default_reported_activity": "bruteforce_scan",
    },
    "dos_ddos": {
        "code": "dos_ddos",
        "tag": "[DDOS]",
        "name": "Denegación de Servicio / Consumo Anómalo",
        "iris_classification_id": 23,
        "iris_classification_name": "availability:ddos",
        "iris_severity_id": 6,  # Critical
        "severity_name": "Critical",
        "default_playbook": "pb_network_abuse",
        "default_reported_activity": "dos_ddos",
    },
}

SEVERITY_NAME_TO_IRIS_ID = {
    "Informational": 3,
    "Low": 4,
    "Medium": 1,
    "High": 5,
    "Critical": 6,
    "Unspecified": 2,
}

IRIS_ID_TO_SEVERITY_NAME = {v: k for k, v in SEVERITY_NAME_TO_IRIS_ID.items()}


def infer_category_from_case_title(title: str) -> str:
    """Infiere la categoría SOC a partir del tag entre corchetes del título de DFIR-IRIS."""
    if not title:
        return "general_abuse"
    t_up = title.upper()
    if "[PHISH]" in t_up:
        return "abuse_phishing"
    if "[SPAM]" in t_up:
        return "abuse_spam"
    if "[FRAUD]" in t_up or "[SCAM]" in t_up:
        return "abuse_fraud"
    if "[REG]" in t_up or "[REGULATED]" in t_up:
        return "regulated_products"
    if "[NET]" in t_up or "[NETABUSE]" in t_up:
        return "network_abuse"
    if "[AUTH]" in t_up or "[OFICIO]" in t_up:
        return "authority_req"
    if "[BRAND]" in t_up:
        return "brand_dispute"
    if "[COMP]" in t_up:
        return "web_compromise"
    if "[ACCT]" in t_up:
        return "account_compromise"
    if "[MALW]" in t_up:
        return "web_compromise"
    if "[RBL]" in t_up or "[BLACKLIST]" in t_up:
        return "blacklist_rbl"
    if "[DMCA]" in t_up or "[COPYRIGHT]" in t_up:
        return "copyright_complaint"
    if "[SCAN]" in t_up or "[DDOS]" in t_up:
        return "network_abuse"
    return "general_abuse"


def get_taxonomy_catalogs() -> Dict[str, Any]:
    return {
        "categories": list(SOC_CATEGORIES.values()),
        "reported_activities": REPORTED_ACTIVITIES,
        "confirmed_incident_types": CONFIRMED_INCIDENT_TYPES,
        "entry_vectors": ENTRY_VECTORS,
        "root_causes": ROOT_CAUSES,
        "action_statuses": ACTION_STATUSES,
        "standard_actions": STANDARD_ACTIONS_CATALOG,
    }

