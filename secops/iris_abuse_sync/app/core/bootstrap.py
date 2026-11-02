import json
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.security import encrypt_secret, hash_password
from app.models.user import User
from app.models.connector import ConnectorConfig, EncryptedSecret
from app.models.classification import PlaybookTemplate
from app.models.case_extended import CaseExtension


DEFAULT_PLAYBOOKS = [
    {
        "code": "pb_phishing",
        "name": "Phishing",
        "category_code": "abuse_phishing",
        "description": "Investigación de páginas fraudulentas, suplantación y captura de información.",
        "steps": [
            {"order": 1, "title": "Verificar URL, DNS y alojamiento del recurso reportado.", "mandatory": True, "suggested_action_type": "verificacion_dns_bastion"},
            {"order": 2, "title": "Revisar contenido, formularios, redirecciones y elementos de suplantación.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 3, "title": "Preservar capturas, archivos o evidencias relevantes.", "mandatory": True, "suggested_action_type": "preservacion_evidencia"},
            {"order": 4, "title": "Evaluar si existe abuso deliberado, modificación no autorizada o compromiso del sitio.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 5, "title": "Considerar contención, notificación o solicitud de aclaraciones según los hallazgos.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
        ],
    },
    {
        "code": "pb_web_compromise",
        "name": "Sitio comprometido",
        "category_code": "web_compromise",
        "description": "Investigación de malware, web shells, redirecciones, defacement y modificaciones sospechosas.",
        "steps": [
            {"order": 1, "title": "Identificar archivos, rutas o contenido sospechoso.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 2, "title": "Revisar fechas, permisos, propietarios y contenido de archivos relevantes.", "mandatory": True, "suggested_action_type": "auditoria_archivos_cms"},
            {"order": 3, "title": "Consultar logs web, accesos a cPanel/DirectAdmin y alertas de seguridad.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 4, "title": "Buscar archivos relacionados, mecanismos de persistencia o indicios de acceso no autorizado.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 5, "title": "Evaluar cuarentena, corrección, protección de credenciales o suspensión si el riesgo lo requiere.", "mandatory": True, "suggested_action_type": "cuarentena_archivos"},
        ],
    },
    {
        "code": "pb_abuse_spam",
        "name": "Spam",
        "category_code": "abuse_spam",
        "description": "Investigación de envíos abusivos desde cuentas de correo, aplicaciones o scripts.",
        "steps": [
            {"order": 1, "title": "Revisar cabeceras, Message-ID y autenticación del mensaje reportado.", "mandatory": True, "suggested_action_type": "analisis_cabeceras_smtp"},
            {"order": 2, "title": "Consultar Exim para identificar origen, volumen, remitentes y destinatarios.", "mandatory": True, "suggested_action_type": "revision_logs_exim"},
            {"order": 3, "title": "Determinar si los envíos provienen de SMTP autenticado, webmail o scripts.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 4, "title": "Revisar autenticaciones, IP sospechosas y posibles cuentas adicionales.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 5, "title": "Evaluar bloqueo de envío, cambio de credenciales, notificación y verificación de mitigación.", "mandatory": True, "suggested_action_type": "rotacion_credenciales"},
        ],
    },
    {
        "code": "pb_account_compromise",
        "name": "Acceso no autorizado",
        "category_code": "account_compromise",
        "description": "Investigación de accesos sospechosos y modificaciones administrativas no reconocidas.",
        "steps": [
            {"order": 1, "title": "Revisar accesos al panel de cliente, cPanel, DirectAdmin o SSH, según corresponda.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 2, "title": "Correlacionar fechas, IP, usuarios, sesiones y autenticaciones.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 3, "title": "Investigar cambios DNS, nameservers, archivos o configuraciones.", "mandatory": True, "suggested_action_type": "sincronizacion_dns"},
            {"order": 4, "title": "Consultar al titular si reconoce las actividades y revisar posibles afectaciones adicionales.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
            {"order": 5, "title": "Evaluar reversión de cambios, rotación de contraseñas, 2FA y otras medidas de protección.", "mandatory": True, "suggested_action_type": "rotacion_credenciales"},
        ],
    },
    {
        "code": "pb_authority_req",
        "name": "Autoridades",
        "category_code": "authority_req",
        "description": "Atención de denuncias y requerimientos provenientes de autoridades u organismos reguladores.",
        "steps": [
            {"order": 1, "title": "Identificar autoridad, origen del reporte, folio y recursos denunciados.", "mandatory": True, "suggested_action_type": "validacion_autoridad"},
            {"order": 2, "title": "Determinar si se trata de una denuncia informativa o un requerimiento legal formal.", "mandatory": True, "suggested_action_type": "validacion_autoridad"},
            {"order": 3, "title": "Revisar la actividad denunciada y preservar evidencia relevante.", "mandatory": True, "suggested_action_type": "preservacion_evidencia"},
            {"order": 4, "title": "Evaluar medidas según los hallazgos y consultar Jurídico cuando corresponda.", "mandatory": True, "suggested_action_type": "respuesta_institucional"},
            {"order": 5, "title": "Preparar respuesta, registrar actuaciones y dar seguimiento a los pendientes.", "mandatory": True, "suggested_action_type": "respuesta_institucional"},
        ],
    },
    {
        "code": "pb_brand_dispute",
        "name": "Disputa de marca",
        "category_code": "brand_dispute",
        "description": "Reportes por similitud de dominios, uso de marca o posible typosquatting.",
        "steps": [
            {"order": 1, "title": "Comparar el dominio denunciado con la marca y revisar el contenido publicado.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 2, "title": "Identificar posibles elementos de suplantación, fraude o phishing.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 3, "title": "Revisar la evidencia y documentación presentada por el reportante.", "mandatory": True, "suggested_action_type": "preservacion_evidencia"},
            {"order": 4, "title": "Solicitar aclaraciones o autorización de uso de marca cuando corresponda.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
            {"order": 5, "title": "Evaluar si procede alguna medida o informar sobre mecanismos de controversia como OMPI/WIPO.", "mandatory": True, "suggested_action_type": "orientacion_wipo"},
        ],
    },
    {
        "code": "pb_blacklist_rbl",
        "name": "IP en blacklist",
        "category_code": "blacklist_rbl",
        "description": "Investigación de direcciones IP listadas por spam o actividad maliciosa.",
        "steps": [
            {"order": 1, "title": "Identificar IP, lista de bloqueo, motivo y fecha del listado.", "mandatory": True, "suggested_action_type": "verificacion_rbl"},
            {"order": 2, "title": "Revisar servidor, cuentas, logs de correo o tráfico relacionado.", "mandatory": True, "suggested_action_type": "revision_logs_exim"},
            {"order": 3, "title": "Identificar el origen de la actividad y verificar si continúa.", "mandatory": True, "suggested_action_type": "revision_logs_exim"},
            {"order": 4, "title": "Aplicar o solicitar las medidas necesarias para detener el abuso.", "mandatory": True, "suggested_action_type": "solicitud_delisting_rbl"},
            {"order": 5, "title": "Gestionar deslistado cuando corresponda y comprobar el resultado.", "mandatory": True, "suggested_action_type": "verificacion_delisting_rbl"},
        ],
    },
    {
        "code": "pb_abuse_fraud",
        "name": "Fraude / Scam",
        "category_code": "abuse_fraud",
        "description": "Denuncias sobre sitios o actividades comerciales presuntamente fraudulentas.",
        "steps": [
            {"order": 1, "title": "Revisar el funcionamiento del sitio, servicios ofrecidos y evidencia del denunciante.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 2, "title": "Identificar elementos de engaño, cobros, suplantación o incumplimientos denunciados.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 3, "title": "Consultar antigüedad de la cuenta, actividad administrativa y antecedentes relevantes.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 4, "title": "Solicitar al titular aclaraciones y documentación comercial cuando corresponda.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
            {"order": 5, "title": "Evaluar medidas según la evidencia, el riesgo y posibles reincidencias.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
        ],
    },
    {
        "code": "pb_regulated_products",
        "name": "Productos regulados",
        "category_code": "regulated_products",
        "description": "Reportes relacionados con medicamentos, sustancias y otros productos sujetos a regulación.",
        "steps": [
            {"order": 1, "title": "Identificar productos, contenido denunciado y mecanismos de comercialización.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 2, "title": "Revisar términos de servicio y restricciones aplicables.", "mandatory": True, "suggested_action_type": "validacion_autoridad"},
            {"order": 3, "title": "Determinar si existen indicios de incumplimiento o únicamente una denuncia.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 4, "title": "Solicitar autorizaciones, permisos o aclaraciones al titular cuando corresponda.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
            {"order": 5, "title": "Evaluar corrección, retiro de contenido, seguimiento o escalamiento jurídico.", "mandatory": True, "suggested_action_type": "respuesta_institucional"},
        ],
    },
    {
        "code": "pb_network_abuse",
        "name": "Abuso de red",
        "category_code": "network_abuse",
        "description": "Investigación de escaneos, fuerza bruta, tráfico malicioso y ataques originados desde infraestructura administrada.",
        "steps": [
            {"order": 1, "title": "Identificar IP de origen y destino, puertos, protocolo y periodo.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 2, "title": "Revisar logs de firewall, sistema, aplicaciones y tráfico.", "mandatory": True, "suggested_action_type": "auditoria_accesos_panel"},
            {"order": 3, "title": "Correlacionar eventos e identificar el servicio o proceso responsable.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 4, "title": "Determinar si existe actividad abusiva activa o posible compromiso.", "mandatory": True, "suggested_action_type": "analisis_vector_entrada"},
            {"order": 5, "title": "Evaluar bloqueo, aislamiento, notificación o suspensión según el riesgo.", "mandatory": True, "suggested_action_type": "suspension_servicio"},
        ],
    },
    {
        "code": "pb_copyright_complaint",
        "name": "Derechos de autor",
        "category_code": "copyright_complaint",
        "description": "Denuncias por uso presuntamente no autorizado de fotografías, textos, software u otros materiales protegidos.",
        "steps": [
            {"order": 1, "title": "Identificar URL, contenido denunciado y titular de los derechos alegados.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 2, "title": "Solicitar material original, evidencia y representación del reportante cuando sea necesario.", "mandatory": True, "suggested_action_type": "preservacion_evidencia"},
            {"order": 3, "title": "Revisar el contenido publicado y el alcance del servicio administrado.", "mandatory": True, "suggested_action_type": "inspeccion_contenido_web"},
            {"order": 4, "title": "Solicitar aclaraciones, licencias o autorización al titular cuando corresponda.", "mandatory": True, "suggested_action_type": "notificacion_cliente"},
            {"order": 5, "title": "Evaluar corrección, seguimiento o consulta jurídica según la evidencia.", "mandatory": True, "suggested_action_type": "respuesta_institucional"},
        ],
    },
]


DEFAULT_CONNECTORS = [
    {
        "connector_type": "zammad",
        "name": "Zammad Helpdesk — Soporte 2do Nivel",
        "organization": "ALL",
        "is_enabled": False,
        "poll_interval_seconds": 180,
        "settings_json": {
            "base_url": "https://helpdesk.neubox.com",
            "group_name": "Soporte 2do Nivel",
            "group_id": 14,
            "assigned_owner": "Christian Aceves",
            "states": ["new", "open", "pending reminder", "pending close"],
            "query_filter": "group_id:14",
        },
    },
    {
        "connector_type": "whmcs",
        "name": "WHMCS Billing & Services API",
        "organization": "ALL",
        "is_enabled": False,
        "poll_interval_seconds": 300,
        "settings_json": {
            "base_url": "https://clientes.neubox.com/includes/api.php",
            "department": "Abuse / Seguridad",
            "sync_services_metadata": True,
        },
    },
    {
        "connector_type": "imap",
        "name": "Buzón IMAP — abuse@neubox.com / abuse@hospedando.com.mx",
        "organization": "ALL",
        "is_enabled": False,
        "poll_interval_seconds": 120,
        "settings_json": {
            "host": "mail.neubox.com",
            "port": 993,
            "use_ssl": True,
            "folder": "INBOX",
            "processed_folder": "INBOX.Processed",
            "username": "abuse@neubox.com",
        },
    },
    {
        "connector_type": "slack",
        "name": "Slack Events API — Alertas SOC & Blacklist",
        "organization": "ALL",
        "is_enabled": False,
        "poll_interval_seconds": 60,
        "settings_json": {
            "webhook_path": "/api/v1/webhooks/slack/events",
            "allowed_channels": ["C0SOCABUSE", "C0BLACKLIST"],
            "correlate_threads": True,
        },
    },
    {
        "connector_type": "blacklist_master",
        "name": "Blacklist Master — Monitoreo RBL de Servidores",
        "organization": "ALL",
        "is_enabled": False,
        "poll_interval_seconds": 300,
        "settings_json": {
            "source_mode": "webhook_and_api",
            "deduplicate_active_episodes": True,
            "monitored_rbls": ["Spamhaus ZEN", "Barracuda", "SpamCop", "SORBS"],
        },
    },
    {
        "connector_type": "gemini",
        "name": "Google Gemini AI — Normalización, Clasificación y Asistencia SOC",
        "organization": "ALL",
        "is_enabled": bool(settings.GEMINI_API_KEY),
        "poll_interval_seconds": 0,
        "settings_json": {
            "model": settings.GEMINI_MODEL,
            "temperature": 0.1,
            "max_output_tokens": settings.GEMINI_MAX_TOKENS,
            "timeout_seconds": settings.GEMINI_TIMEOUT_SECONDS,
            "auto_analyze_ingest": True,
            "assist_triage": True,
            "assist_redaction": True,
        },
    },
]


def init_db_and_seed() -> None:
    """Inicializa esquemas si no existen y siembra datos iniciales de forma idempotente."""
    import app.models  # noqa: F401 - ensure all models are registered in Base.metadata
    Base.metadata.create_all(bind=engine)

    # Migración en caliente de columnas añadidas para SQLite
    try:
        with engine.begin() as conn:
            res_ext = conn.exec_driver_sql("PRAGMA table_info(case_extensions)").fetchall()
            col_names = [r[1] for r in res_ext]
            if col_names and "domain_id" not in col_names:
                conn.exec_driver_sql("ALTER TABLE case_extensions ADD COLUMN domain_id VARCHAR(64)")

            res_alt = conn.exec_driver_sql("PRAGMA table_info(alert_extensions)").fetchall()
            col_alt = [r[1] for r in res_alt]
            if col_alt and "observation_count" not in col_alt:
                conn.exec_driver_sql("ALTER TABLE alert_extensions ADD COLUMN observation_count INTEGER DEFAULT 1")

            # Limpiar episodios ficticios/demo de reputación
            conn.exec_driver_sql("DELETE FROM rbl_episodes WHERE ip_address = '209.59.180.250'")
    except Exception as e:
        print(f"Warning verifying columns / cleanups: {e}")

    db: Session = SessionLocal()
    try:
        _seed_users(db)
        _seed_playbooks(db)
        _seed_connectors(db)
        _import_legacy_case_params_store(db)
        db.commit()
    finally:
        db.close()


def _seed_users(db: Session) -> None:
    admin = db.query(User).filter(User.username == settings.BOOTSTRAP_ADMIN_USER).first()
    if not admin:
        db.add(
            User(
                username=settings.BOOTSTRAP_ADMIN_USER,
                email=settings.BOOTSTRAP_ADMIN_EMAIL,
                full_name=settings.BOOTSTRAP_ADMIN_NAME,
                password_hash=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
                role="admin",
                allowed_orgs=["NBX", "HP"],
                iris_user_id=2,
                is_active=True,
            )
        )


def _seed_playbooks(db: Session) -> None:
    valid_codes = {pb["code"] for pb in DEFAULT_PLAYBOOKS}
    old_code_aliases = {
        "pb_spam_outbound": "pb_abuse_spam",
        "pb_account_dns_hijack": "pb_account_compromise",
        "pb_rbl_blacklist": "pb_blacklist_rbl",
    }
    
    for old_c, new_c in old_code_aliases.items():
        old_item = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == old_c).first()
        if old_item:
            new_item = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == new_c).first()
            if not new_item:
                old_item.code = new_c
            else:
                db.delete(old_item)
            db.flush()

    for pb in DEFAULT_PLAYBOOKS:
        existing = db.query(PlaybookTemplate).filter(PlaybookTemplate.code == pb["code"]).first()
        if existing:
            existing.name = pb["name"]
            existing.category_code = pb["category_code"]
            existing.description = pb["description"]
            existing.is_active = True
            existing.steps_json = pb["steps"]
        else:
            db.add(
                PlaybookTemplate(
                    code=pb["code"],
                    name=pb["name"],
                    category_code=pb["category_code"],
                    description=pb["description"],
                    is_active=True,
                    steps_json=pb["steps"],
                )
            )

    for other in db.query(PlaybookTemplate).all():
        if other.code not in valid_codes:
            other.is_active = False

    db.commit()


def _seed_connectors(db: Session) -> None:
    for item in DEFAULT_CONNECTORS:
        existing = db.query(ConnectorConfig).filter(ConnectorConfig.name == item["name"]).first()
        if not existing:
            secret_id = None
            if item["connector_type"] == "gemini" and settings.GEMINI_API_KEY:
                ct, hint = encrypt_secret(settings.GEMINI_API_KEY)
                sec = EncryptedSecret(
                    secret_key_name="gemini_api_key",
                    ciphertext=ct,
                    key_hint=hint,
                    updated_by="system_bootstrap",
                )
                db.add(sec)
                db.flush()
                secret_id = sec.id
            db.add(
                ConnectorConfig(
                    connector_type=item["connector_type"],
                    name=item["name"],
                    organization=item["organization"],
                    is_enabled=item["is_enabled"],
                    settings_json=item["settings_json"],
                    secret_id=secret_id,
                    poll_interval_seconds=item["poll_interval_seconds"],
                    last_status="ready" if item["is_enabled"] else "disabled",
                )
            )


def _import_legacy_case_params_store(db: Session) -> None:
    """Importa de forma no destructiva los parámetros guardados en scratch/case_params_store.json."""
    store_file = settings.SCRATCH_DIR / "case_params_store.json"
    if not store_file.exists():
        return
    try:
        data = json.loads(store_file.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(data, dict):
        return

    for cid_str, params in data.items():
        if not str(cid_str).isdigit() or not isinstance(params, dict):
            continue
        cid = int(cid_str)
        ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == cid).first()

        # Extraer correctamente los campos según la estructura real de case_params_store.json
        affected_asset = (
            params.get("affected_asset")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("Dominio o activo reportado"))
            or params.get("domain")
        )
        report_ticket = (
            params.get("report_ticket")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("Ticket de abuso"))
            or params.get("ticket_id")
        )
        client_ticket = (
            params.get("client_ticket")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("Ticket del titular"))
            or params.get("holder_ticket")
        )
        client_id_val = (
            params.get("client_id")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("ID de Cliente"))
        )
        service_id_val = (
            params.get("service_id")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("ID de Servicio"))
        )
        server_val = (
            params.get("server")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("Servidor"))
        )
        primary_ip_val = (
            params.get("primary_ip")
            or (params.get("custom_attributes", {}).get("01 Identificación", {}).get("IP reportada"))
            or params.get("ip")
        )

        cust_key = str(params.get("customer_key") or "").lower()
        org = "HP" if cust_key in ("hospedando", "hp") else "NBX"
        cust_id = 3 if org == "HP" else 2

        prov_map = {
            "primary_domain": "manual" if affected_asset else "inferred",
            "abuse_ticket_id": "manual" if report_ticket else "inferred",
            "holder_ticket_id": "manual" if client_ticket else "inferred",
            "client_id": "manual" if client_id_val else "inferred",
            "service_id": "manual" if service_id_val else "inferred",
            "server_name": "manual" if server_val else "inferred",
            "reported_ip": "manual" if primary_ip_val else "inferred",
        }

        if not ext:
            ext = CaseExtension(
                iris_case_id=cid,
                organization=org,
                customer_id=cust_id,
                abuse_ticket_id=str(report_ticket or "") or None,
                holder_ticket_id=str(client_ticket or "") or None,
                client_id=str(client_id_val or "") or None,
                service_id=str(service_id_val or "") or None,
                primary_domain=str(affected_asset or "") or None,
                server_name=str(server_val or "") or None,
                reported_ip=str(primary_ip_val or "") or None,
                category_code="general_abuse",
                schema_version="legacy_v2_params",
                field_provenance_json=prov_map,
            )
            db.add(ext)
        else:
            # Reconciliar campos vacíos
            if not ext.primary_domain and affected_asset:
                ext.primary_domain = str(affected_asset)
            if not ext.abuse_ticket_id and report_ticket:
                ext.abuse_ticket_id = str(report_ticket)
            if not ext.holder_ticket_id and client_ticket:
                ext.holder_ticket_id = str(client_ticket)
            if not ext.client_id and client_id_val:
                ext.client_id = str(client_id_val)
            if not ext.service_id and service_id_val:
                ext.service_id = str(service_id_val)
            if not ext.server_name and server_val:
                ext.server_name = str(server_val)
            if not ext.reported_ip and primary_ip_val:
                ext.reported_ip = str(primary_ip_val)
            if ext.category_code == "abuse_phishing":
                ext.category_code = "general_abuse"
            ext.organization = org
            ext.customer_id = cust_id
            ext.field_provenance_json = {**(ext.field_provenance_json or {}), **prov_map}
