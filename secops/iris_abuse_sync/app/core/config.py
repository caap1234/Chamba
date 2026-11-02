import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Configuración centralizada de la plataforma SOC v3.0."""

    APP_NAME: str = "DFIR-IRIS Abuse Sync SOC Platform"
    APP_VERSION: str = "3.1.0"
    ENV: str = os.getenv("APP_ENV", "development")

    # Directorios de trabajo
    BASE_DIR: Path = BASE_DIR
    SCRATCH_DIR: Path = BASE_DIR / "scratch"
    EVIDENCE_STORAGE_DIR: Path = BASE_DIR / "storage" / "evidences"
    MIGRATION_BACKUP_DIR: Path = BASE_DIR / "storage" / "migration_backups"
    INCOMING_DIR: Path = BASE_DIR / os.getenv("WATCH_FOLDER", "incoming")
    PROCESSED_DIR: Path = BASE_DIR / os.getenv("PROCESSED_FOLDER", "processed")

    # Base de datos (Soporta PostgreSQL en producción/Docker y SQLite local por defecto si no se define DATABASE_URL)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'storage' / 'soc_platform.db'}",
    )

    # Seguridad, Sesiones y Baúl de Secretos Cifrados
    APP_SECRET_KEY: str = os.getenv(
        "APP_SECRET_KEY",
        "soc-iris-abuse-sync-v3-default-signing-key-change-in-prod-98a7f6e5",
    )
    APP_MASTER_KEY: str = os.getenv(
        "APP_MASTER_KEY",
        "soc-iris-abuse-sync-v3-master-encryption-key-32bytes-seed!",
    )
    SESSION_COOKIE_NAME: str = "soc_iris_session"
    SESSION_TTL_HOURS: int = int(os.getenv("SESSION_TTL_HOURS", "12"))

    # Bootstrap Admin Inicial
    BOOTSTRAP_ADMIN_USER: str = os.getenv("BOOTSTRAP_ADMIN_USER", "admin")
    BOOTSTRAP_ADMIN_PASSWORD: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "NeuboxSOC2026!")
    BOOTSTRAP_ADMIN_EMAIL: str = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "christianaceves@neubox.net")
    BOOTSTRAP_ADMIN_NAME: str = os.getenv("BOOTSTRAP_ADMIN_NAME", "Christian Aceves (SOC Admin)")

    # DFIR-IRIS Backend Principal
    IRIS_URL: str = os.getenv("IRIS_URL", "https://iris.tokyo-03.com").rstrip("/")
    IRIS_API_KEY: str = os.getenv("IRIS_API_KEY", "")
    VERIFY_SSL: bool = os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "yes")

    # Organizaciones soportadas y plantillas de enlaces administrativos
    ORGANIZATIONS = {
        "NBX": {
            "code": "NBX",
            "name": "NEUBOX",
            "legal_name": "NEUBOX Internet S.A. de C.V.",
            "iris_customer_id": 2,
            "helpdesk_system": "Zammad Helpdesk",
            "billing_system": "WHMCS Neubox Admin",
            "links": {
                "support_ticket": "https://helpdesk.neubox.com/#ticket/zoom/{ticket_id}",
                "client_summary": "https://clientes.neubox.com/NBX_4dmin/clientssummary.php?userid={client_id}",
                "hosting_service": "https://clientes.neubox.com/NBX_4dmin/clientsservices.php?userid={client_id}&id={service_id}",
                "registered_domain": "https://clientes.neubox.com/NBX_4dmin/clientsdomains.php?userid={client_id}&domainid={domain_id}",
            },
        },
        "HP": {
            "code": "HP",
            "name": "Hospedando",
            "legal_name": "Hospedando S.A. de C.V.",
            "iris_customer_id": 3,
            "helpdesk_system": "WHMCS Hospedando Admin",
            "billing_system": "WHMCS Hospedando Admin",
            "links": {
                "support_ticket": "https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/supporttickets.php?ticketid={ticket_id}",
                "client_summary": "https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientssummary.php?userid={client_id}",
                "hosting_service": "https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientsservices.php?userid={client_id}&id={service_id}",
                "registered_domain": "https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientsdomains.php?userid={client_id}&domainid={domain_id}",
            },
        },
    }

    # Google Gemini API (Configuración inicial por entorno, administrable en BD desde UI)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
    GEMINI_TIMEOUT_SECONDS: int = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "35"))
    GEMINI_MAX_TOKENS: int = int(os.getenv("GEMINI_MAX_TOKENS", "4096"))

    @classmethod
    def ensure_directories(cls) -> None:
        for folder in (
            cls.SCRATCH_DIR,
            cls.EVIDENCE_STORAGE_DIR,
            cls.MIGRATION_BACKUP_DIR,
            cls.INCOMING_DIR,
            cls.PROCESSED_DIR,
            cls.BASE_DIR / "storage",
        ):
            folder.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
