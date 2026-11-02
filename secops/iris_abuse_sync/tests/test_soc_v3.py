from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from app.ai.gemini_service import GeminiService
from app.classification.correlation import CorrelationEngine
from app.classification.heuristic_engine import HeuristicClassifier
from app.classification.taxonomy import (
    ACTION_STATUSES,
    CONFIRMED_INCIDENT_TYPES,
    ENTRY_VECTORS,
    REPORTED_ACTIVITIES,
    ROOT_CAUSES,
    SOC_CATEGORIES,
    VALID_ACTION_STATUS_CODES,
)
from app.core.bootstrap import init_db_and_seed
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import decrypt_secret, encrypt_secret, hash_password, verify_password
from app.ingestion.connectors.blacklist_master import BlacklistMasterConnector
from app.ingestion.connectors.slack_connector import SlackEventsConnector
from app.ingestion.evidence_packager import EvidencePackageBuilder
from app.ingestion.normalizer import ReportNormalizer
from app.iris.legacy_migrator import LegacyCaseMigrator
from app.main import app
from app.models.case_extended import CaseAction, CaseExtension, CaseMigrationRecord
from app.reports.pdf_generator import FormalPdfReportGenerator


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db_and_seed()


def test_argon2_password_and_fernet_secret_vault():
    """Verifica el hash Argon2id de contraseñas y el baúl de secretos cifrados Fernet."""
    pw = "SuperSecureSOC2026!"
    hashed = hash_password(pw)
    assert hashed.startswith("$argon2")
    assert verify_password(pw, hashed) is True
    assert verify_password("wrong", hashed) is False

    raw_secret = "AIzaSyTestGeminiSecretKey123456789"
    ct, hint = encrypt_secret(raw_secret)
    assert ct != raw_secret
    assert "789" in hint
    assert "•" in hint or "*" in hint
    recovered = decrypt_secret(ct)
    assert recovered == raw_secret


def test_taxonomy_four_axes_and_eight_action_states():
    """Verifica que los 4 ejes de clasificación y los 8 estados de acción obligatorios existan."""
    expected_states = {
        "propuesta",
        "autorizada",
        "pendiente",
        "en_ejecucion",
        "ejecutada",
        "verificada",
        "cancelada",
        "no_aplicable",
    }
    assert VALID_ACTION_STATUS_CODES == expected_states
    assert len(ACTION_STATUSES) == 8

    # Verificar que casos de no-compromiso estén explícitamente en confirmed_incident_type
    confirmed_codes = {item["code"] for item in CONFIRMED_INCIDENT_TYPES}
    entry_codes = {item["code"] for item in ENTRY_VECTORS}
    root_codes = {item["code"] for item in ROOT_CAUSES}

    non_compromise_types = {
        "uncorroborated_allegation",
        "brand_dispute_no_abuse",
        "authority_preservation_request",
        "rbl_reputation_episode",
        "domain_only_external_hosting",
        "closed_no_technical_intervention",
        "false_positive",
    }
    assert non_compromise_types.issubset(confirmed_codes)
    assert "unknown" in entry_codes and "not_applicable" in entry_codes
    assert "unknown" in root_codes and "not_applicable" in root_codes


def test_evidence_packager_sha256_and_manifest(tmp_path):
    """Verifica el empaquetado forense SHA-256 con manifest.json y cadena de custodia."""
    raw = b"From: abuse@netcraft.com\nSubject: Phishing Report #791092\n\nMalicious URL detected."
    norm = ReportNormalizer.normalize_text(
        text="Phishing Report #791092 Malicious URL detected at https://evil-login.com/bank",
        filename="report_791092.eml",
        organization="NBX",
    )
    pkg1 = EvidencePackageBuilder.build_package(
        payload=norm,
        raw_bytes=raw,
        original_filename="report_791092.eml",
    )
    assert len(pkg1["primary_sha256"]) == 64
    pkg_dir = Path(pkg1["package_dir"])
    assert (pkg_dir / "manifest.json").exists()
    assert (pkg_dir / "normalized_payload.json").exists()

    # Segunda llamada con los mismos bytes debe producir exactamente el mismo SHA-256
    pkg2 = EvidencePackageBuilder.build_package(
        payload=norm,
        raw_bytes=raw,
        original_filename="report_791092_dup.eml",
    )
    assert pkg2["primary_sha256"] == pkg1["primary_sha256"]


def test_normalizer_and_heuristics_on_real_reference_pdfs():
    """Prueba la normalización avanzada y separación de roles sobre los PDFs reales en scratch/."""
    scratch = settings.SCRATCH_DIR

    # 1. PDF #791233 (CHECK24 phishing en trucklinesfm.com suplantando check24.de)
    pdf_791233 = scratch / "temp_Ticket 791233.pdf"
    assert pdf_791233.exists()
    norm, _, _ = ReportNormalizer.from_file(pdf_791233, organization="HP")
    assert norm.abuse_ticket_id == "791233"
    assert norm.primary_domain == "trucklinesfm.com"
    assert norm.impersonated_brand == "CHECK24"
    roles = {i.value: i.role for i in norm.indicators}
    assert roles.get("trucklinesfm.com") == "domain_reported"
    assert roles.get("check24.de") == "domain_brand"
    # El dominio de la marca suplantada NUNCA debe marcarse como activo afectado
    brand_ind = next(i for i in norm.indicators if i.value == "check24.de")
    assert brand_ind.is_affected_asset is False

    # 2. PDF #791328 (CyberWipe / Spherion disputa de marca sin abuso corroborado: spheraion.com vs spherion.com)
    pdf_791328 = scratch / "temp_Ticket 791328.pdf"
    assert pdf_791328.exists()
    norm2, _, _ = ReportNormalizer.from_file(pdf_791328, organization="NBX")
    assert norm2.abuse_ticket_id == "791328"
    assert norm2.primary_domain == "spheraion.com"
    assert norm2.impersonated_brand == "Spherion"
    assert norm2.hosting_ip == "65.99.225.96"
    heur2 = HeuristicClassifier.evaluate(norm2)
    assert heur2["category_code"] == "brand_dispute"
    assert heur2["confirmed_incident_type"] == "brand_dispute_no_abuse"
    assert heur2["is_technical_compromise"] is False

    # 3. PDF #791255 (SSPC / COFEPRIS Requerimiento de autoridad: suplementosmayoreogdl.com)
    pdf_791255 = scratch / "temp_Ticket 791255.pdf"
    assert pdf_791255.exists()
    norm3, _, _ = ReportNormalizer.from_file(pdf_791255, organization="NBX")
    assert norm3.abuse_ticket_id == "791255"
    assert norm3.primary_domain == "suplementosmayoreogdl.com"
    heur3 = HeuristicClassifier.evaluate(norm3)
    assert heur3["category_code"] == "authority_req"
    assert heur3["confirmed_incident_type"] == "authority_preservation_request"
    assert heur3["is_technical_compromise"] is False

    # 4. PDF #791092 (Netcraft / Compromiso CMS en transparencia.uttlaxcala.edu.mx, IP 174.136.26.134)
    pdf_791092 = scratch / "temp_Ticket 791092.pdf"
    assert pdf_791092.exists()
    norm4, _, _ = ReportNormalizer.from_file(pdf_791092, organization="NBX")
    assert norm4.abuse_ticket_id == "791092"
    assert norm4.primary_domain == "transparencia.uttlaxcala.edu.mx"
    assert norm4.hosting_ip == "174.136.26.134"
    heur4 = HeuristicClassifier.evaluate(norm4)
    assert heur4["category_code"] == "web_compromise"
    assert heur4["confirmed_incident_type"] == "confirmed_cms_compromise"
    assert heur4["is_technical_compromise"] is True

    # 5. PDF #791842 (INVEX Dominio con subdominio fraudulento solicitala.invex.tarjeta.com.mx)
    pdf_791842 = scratch / "temp_Ticket_791842.pdf"
    assert pdf_791842.exists()
    norm5, _, _ = ReportNormalizer.from_file(pdf_791842, organization="NBX")
    assert norm5.abuse_ticket_id == "791842"
    assert "tarjeta.com.mx" in (norm5.primary_domain or "")
    heur5 = HeuristicClassifier.evaluate(norm5)
    assert heur5["confirmed_incident_type"] == "domain_only_external_hosting"
    assert heur5["is_technical_compromise"] is False


def test_blacklist_master_episode_deduplication():
    """Verifica que chequeos repetidos de Blacklist Master incrementen check_count sin duplicar episodios."""
    db = SessionLocal()
    try:
        ep1, payload1, is_new1 = BlacklistMasterConnector.process_rbl_event(
            db,
            ip_address="209.59.180.250",
            rbl_provider="Spamhaus ZEN",
            server_name="svgs999.serverneubox.com.mx",
            organization="NBX",
            event_status="listed",
            reason="Outbound spam burst detected",
        )
        ep_id = ep1.id
        c1 = ep1.check_count

        # Segundo evento sobre la misma IP + RBL debe actualizar el episodio activo sin crear alerta repetida
        ep2, payload2, is_new2 = BlacklistMasterConnector.process_rbl_event(
            db,
            ip_address="209.59.180.250",
            rbl_provider="Spamhaus ZEN",
            server_name="svgs999.serverneubox.com.mx",
            organization="NBX",
            event_status="listed",
            reason="Repeated check",
        )
        assert is_new2 is False
        assert payload2 is None
        assert ep2.id == ep_id
        assert ep2.check_count == c1 + 1

        # Evento de delisted debe cerrar el episodio
        ep3, payload3, is_new3 = BlacklistMasterConnector.process_rbl_event(
            db,
            ip_address="209.59.180.250",
            rbl_provider="Spamhaus ZEN",
            server_name="svgs999.serverneubox.com.mx",
            organization="NBX",
            event_status="delisted",
        )
        assert ep3.id == ep_id
        assert ep3.status == "delisted"
        assert is_new3 is False
        db.delete(ep3)
        db.commit()
    finally:
        db.close()


def test_slack_hmac_signature_verification():
    """Verifica la firma criptográfica HMAC-SHA256 de Slack Events API."""
    secret = "8f742231b10e8888abcd99yyyzzz85a5"
    ts = str(int(time.time()))
    body = b'{"type":"url_verification","challenge":"test_challenge_token"}'
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode("utf-8")
    valid_sig = "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    assert SlackEventsConnector.verify_slack_signature(
        signing_secret=secret,
        timestamp_header=ts,
        signature_header=valid_sig,
        raw_body=body,
    ) is True

    assert SlackEventsConnector.verify_slack_signature(
        signing_secret=secret,
        timestamp_header=ts,
        signature_header="v0=deadbeef",
        raw_body=body,
    ) is False


def test_historical_migration_dry_run_and_manual_provenance_preservation():
    """Verifica que el migrador histórico separe hechos de alegaciones, preserve ediciones manuales y genere PDF."""
    db = SessionLocal()
    try:
        class FakeIrisClient:
            def get_case_full(self, case_id: int) -> Dict[str, Any]:
                return {
                    "case_id": case_id,
                    "case_name": f"#{case_id} - [PHISH] demo-phishing-test.com | NBX-990123",
                    "case_description": "## Resumen del caso\n- Reporte: Denuncia de portal falso.\n- Hallazgo: Pendiente de investigación por analista SOC",
                    "case_customer": 2,
                    "state_name": "Open",
                    "open_date": "2026-10-28",
                    "custom_attributes": {
                        "01 Identificación": {
                            "Ticket de abuso": {"value": "990123"},
                            "Dominio o activo reportado": {"value": "demo-phishing-test.com"},
                            "IP reportada": {"value": "209.59.180.77"},
                        }
                    },
                    "notes": [
                        {
                            "note_id": 101,
                            "note_title": "01 Reporte inicial",
                            "note_content": "- Ticket de abuso: 990123\n- Dominio / activo: demo-phishing-test.com\n- Descripción breve del reporte: Posible phishing reportado por tercero.",
                        },
                        {
                            "note_id": 102,
                            "note_title": "02 Investigación y evidencia",
                            "note_content": "- Se encontró: Servidor: svgp777; ID del cliente: #44556; ID del servicio: #88990\n- Evaluación (confirmado / no corroborado / pendiente): Pendiente de confirmación",
                        },
                        {
                            "note_id": 103,
                            "note_title": "03 Acciones y resolución",
                            "note_content": "- Decisión y motivo: Se notifica al cliente para revisión.\n- Acción ejecutada (o pendiente): Notificación enviada al titular.",
                        },
                    ],
                    "iocs": [{"ioc_id": 1, "ioc_value": "demo-phishing-test.com", "ioc_type": "domain"}],
                    "assets": [],
                    "tasks": [],
                    "evidences": [{"id": 50, "filename": "Ticket_990123.pdf", "file_size": 12345}],
                    "timeline": [],
                }

        fake_case_id = 99991
        # Simular una edición manual previa del analista en client_id ("MANUAL-CLIENT-777")
        ext = db.query(CaseExtension).filter(CaseExtension.iris_case_id == fake_case_id).first()
        if not ext:
            ext = CaseExtension(
                iris_case_id=fake_case_id,
                organization="NBX",
                customer_id=2,
                client_id="MANUAL-CLIENT-777",
                field_provenance_json={"client_id": "manual"},
            )
            db.add(ext)
            db.commit()

        preview = LegacyCaseMigrator.generate_preview_and_snapshot(
            db,
            case_id=fake_case_id,
            use_gemini=False,
            iris_client=FakeIrisClient(),
        )
        assert preview["status"] == "preview_ready"
        assert len(preview["snapshot_sha256"]) == 64
        prop = preview["proposed"]
        # Verificar que NO se sobreescribió el campo manual client_id
        assert prop["client_id"] == "MANUAL-CLIENT-777"
        assert "client_id" in prop["preserved_manual_fields"]
        # Verificar que extraiga service_id y server_name de las notas antiguas
        assert prop["service_id"] == "88990"
        assert prop["server_name"] == "svgp777"
        # Verificar que NO dé por confirmado un compromiso cuando la nota dice "Pendiente de confirmación"
        assert prop["verification_state"] == "pendiente"
        assert prop["confirmed_incident_type"] == "pending_investigation"
        assert prop["is_technical_compromise"] is False
        assert preview["dry_run"]["destructive_operations"] == 0

        # Verificar generación del informe PDF de 15 secciones con el mismo modelo
        pdf_bytes = FormalPdfReportGenerator.generate_case_pdf_bytes(
            {
                "extension": prop,
                "iris_case": preview["original"],
                "investigations": prop["investigations"],
                "findings": prop["findings"],
                "actions": prop["actions"],
                "communications": [],
            }
        )
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 5000
        db.query(CaseMigrationRecord).filter(CaseMigrationRecord.iris_case_id == fake_case_id).delete()
        db.query(CaseExtension).filter(CaseExtension.iris_case_id == fake_case_id).delete()
        db.commit()
    finally:
        db.close()


def test_fastapi_auth_and_soc_endpoints():
    """Verifica el flujo de login, sesión, CSRF y endpoints principales de la API v3.0."""
    client = TestClient(app)

    # 1. Healthcheck público
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["version"] == "3.1.0"

    # 2. Login con el usuario administrador inicial
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    assert r_login.status_code == 200
    login_data = r_login.json()
    assert login_data["status"] == "ok"
    csrf_token = login_data["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 3. Consultar catálogos de taxonomía de 4 ejes y 8 estados de acción
    r_tax = client.get("/api/v1/admin/catalogs")
    assert r_tax.status_code == 200
    tax = r_tax.json()
    assert len(tax["action_statuses"]) == 8
    assert "reported_activities" in tax
    assert "confirmed_incident_types" in tax
    assert "entry_vectors" in tax
    assert "root_causes" in tax

    # 4. Ingesta y normalización en modo preview (sin tocar IRIS externo)
    r_ing = client.post(
        "/api/v1/ingest/text",
        headers=headers,
        json={
            "text": "Ticket #880011\nFrom: abuse@netcraft.com\nPhishing URL: https://login-banco-falso.com/auth\nIP: 209.59.180.66\nServidor: svgp261.serverneubox.com.mx\nID Cliente: #50269\nID Servicio: #14203",
            "title": "[Abuse #880011] Phishing URL detected",
            "organization": "NBX",
            "create_iris_alert": False,
            "use_gemini": False,
        },
    )
    assert r_ing.status_code == 200
    ing_res = r_ing.json()
    assert ing_res["status"] in ("ok", "normalized", "alert_created")
    assert ing_res["normalized"]["abuse_ticket_id"] == "880011"
    assert ing_res["normalized"]["primary_domain"] == "login-banco-falso.com"
    assert ing_res["heuristics"]["category_code"] == "abuse_phishing"
