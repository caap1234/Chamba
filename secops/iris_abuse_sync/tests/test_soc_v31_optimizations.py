import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.classification.taxonomy import infer_category_from_case_title

def test_infer_category_from_case_title():
    assert infer_category_from_case_title("[PHISH] tramitadores.com | HP-801587") == "abuse_phishing"
    assert infer_category_from_case_title("[SPAM] donotreply-portal | HP-962615") == "abuse_spam"
    assert infer_category_from_case_title("[FRAUD] servicioeasydf.com | NBX-789810") == "abuse_fraud"
    assert infer_category_from_case_title("[AUTH] requerimiento-fgr | NBX-789810") == "authority_req"
    assert infer_category_from_case_title("[BRAND] dispute.com | NBX-1234") == "brand_dispute"
    assert infer_category_from_case_title("[MALW] badsite.net | HP-555") == "web_compromise"
    assert infer_category_from_case_title("[RBL] blacklist-event | NBX-999") == "blacklist_rbl"
    assert infer_category_from_case_title("Uncategorized case without tag") == "general_abuse"

def test_autosave_drafts_crud_and_pdf_disposition():
    client = TestClient(app)

    # 1. Login
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    assert r_login.status_code == 200
    login_data = r_login.json()
    csrf_token = login_data["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 2. Save a draft
    put_res = client.put(
        "/api/v1/cases/21/drafts/note_1",
        headers=headers,
        json={"draft_content": "## Contenido borrador autoguardado de prueba"}
    )
    assert put_res.status_code == 200
    assert put_res.json()["ok"] is True
    assert put_res.json()["field_key"] == "note_1"

    # 3. Get drafts
    get_res = client.get("/api/v1/cases/21/drafts", headers=headers)
    assert get_res.status_code == 200
    drafts = get_res.json()["drafts"]
    assert "note_1" in drafts
    assert drafts["note_1"]["content"] == "## Contenido borrador autoguardado de prueba"

    # 4. Delete draft
    del_res = client.delete("/api/v1/cases/21/drafts/note_1", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["ok"] is True

    # 5. Verify deleted
    get_res2 = client.get("/api/v1/cases/21/drafts", headers=headers)
    assert "note_1" not in get_res2.json()["drafts"]

    # 6. Test PDF disposition with mocked IrisApiClient
    mock_case_data = {
        "case_id": 21,
        "case_name": "[PHISH] tramitadores.com | HP-801587",
        "case_customer": "HP",
        "case_description": "Caso de prueba",
        "notes": [{"note_id": 1, "note_title": "01 Reporte inicial", "note_content": "## Reporte"}],
        "custom_attributes": {},
    }

    with patch("app.iris.client.IrisApiClient.get_case_full", return_value=mock_case_data):
        # Test inline (default) PDF disposition
        res_inline = client.get("/api/v1/cases/21/report.pdf", headers=headers)
        assert res_inline.status_code == 200
        cd = res_inline.headers.get("content-disposition", "")
        assert "inline" in cd
        assert res_inline.headers.get("content-type") == "application/pdf"

        # Test download attachment PDF disposition
        res_down = client.get("/api/v1/cases/21/report.pdf?download=1", headers=headers)
        assert res_down.status_code == 200
        cd = res_down.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert res_down.headers.get("content-type") == "application/pdf"

def test_admin_links_generation():
    from app.core.admin_links import build_admin_links

    # 1. Hospedando (Customer ID 3 / HP)
    links_hp = build_admin_links(
        organization="HP",
        customer_id=3,
        abuse_ticket_id="801587",
        client_id="23190",
        service_id="14059",
        domain_id="5512",
        user_role="admin",
    )
    assert links_hp["organization"] == "HP"
    assert links_hp["organization_name"] == "Hospedando"
    assert "WHMCS" in links_hp["helpdesk_system"]
    assert "801587" in links_hp["abuse_ticket_url"]
    assert "supporttickets.php" in links_hp["abuse_ticket_url"]
    assert "clientssummary.php?userid=23190" in links_hp["client_summary_url"]
    assert "clientsservices.php?userid=23190&id=14059" in links_hp["hosting_service_url"]
    assert "clientsdomains.php?userid=23190&domainid=5512" in links_hp["registered_domain_url"]
    assert len(links_hp["actions"]) >= 4

    # 2. NEUBOX (Customer ID 2 / NBX)
    links_nbx = build_admin_links(
        organization="NBX",
        customer_id=2,
        abuse_ticket_id="31733831",
        client_id="98765",
        service_id="4321",
        domain_id="8877",
        user_role="analyst",
    )
    assert links_nbx["organization"] == "NBX"
    assert links_nbx["organization_name"] == "NEUBOX"
    assert "Zammad" in links_nbx["helpdesk_system"]
    assert "helpdesk.neubox.com/#ticket/zoom/31733831" in links_nbx["abuse_ticket_url"]
    assert "clientssummary.php?userid=98765" in links_nbx["client_summary_url"]
    assert "clientsservices.php?userid=98765&id=4321" in links_nbx["hosting_service_url"]
    assert "clientsdomains.php?userid=98765&domainid=8877" in links_nbx["registered_domain_url"]
    assert len(links_nbx["actions"]) >= 4


def test_playbook_lifecycle_and_blacklist_api():
    client = TestClient(app)

    # 1. Login
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    assert r_login.status_code == 200
    headers = {"X-CSRF-Token": r_login.json()["csrf_token"]}

    mock_case_data = {
        "case_id": 21,
        "case_name": "[PHISH] tramitadores.com | HP-801587",
        "case_customer": "HP",
        "case_description": "Caso de prueba",
        "notes": [],
        "custom_attributes": {},
    }

    with patch("app.iris.client.IrisApiClient.get_case_full", return_value=mock_case_data):
        # Suggestions
        sug_res = client.get("/api/v1/cases/21/playbooks/suggested", headers=headers)
        assert sug_res.status_code == 200
        data = sug_res.json()
        assert data["inferred_category"] == "abuse_phishing"
        assert len(data["suggested_playbooks"]) > 0

        # Start execution
        start_res = client.post(
            "/api/v1/cases/21/playbooks/start",
            headers=headers,
            json={"playbook_code": "pb_phishing"}
        )
        assert start_res.status_code == 200
        exec_record = start_res.json()["execution"]
        exec_id = exec_record["id"]
        assert exec_record["playbook_code"] == "pb_phishing"
        assert len(exec_record["steps_state"]) > 0

        # Update step
        step_res = client.patch(
            f"/api/v1/cases/21/playbooks/executions/{exec_id}/step/1",
            headers=headers,
            json={"status": "completado", "observations": "Evidencia corroborada vía DNS y URLScan"}
        )
        assert step_res.status_code == 200
        steps_state = step_res.json()["steps_state"]
        step1 = next(s for s in steps_state if s["order"] == 1)
        assert step1["status"] == "completado"
        assert "DNS y URLScan" in step1["observations"]

    # Test Blacklist Endpoints
    # Mocking _query_single_rbl for speed and offline reliability
    mock_rbl_result = {
        "status": "clean",
        "listed": False,
        "response_code": None,
        "query_host": "25.100.51.198.zen.spamhaus.org",
        "details": "Limpia (NXDOMAIN: La IP no figura en este listado)",
    }
    with patch("app.api.routers.blacklist._query_single_rbl", return_value=mock_rbl_result):
        bl_check = client.post(
            "/api/v1/blacklist/check",
            headers=headers,
            json={"target": "198.51.100.25", "rbl_zones": ["zen.spamhaus.org"]}
        )
        assert bl_check.status_code == 200
        res = bl_check.json()
        assert res["target"] == "198.51.100.25"
        assert res["summary"]["listed"] == 0
        assert res["summary"]["is_clean"] is True

    bl_episodes = client.get("/api/v1/blacklist/episodes", headers=headers)
    assert bl_episodes.status_code == 200
    assert "episodes" in bl_episodes.json()


def test_gemini_models_and_diagnosis():
    client = TestClient(app)
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    headers = {"X-CSRF-Token": r_login.json()["csrf_token"]}

    # Models list endpoint
    res = client.get("/api/v1/admin/gemini/models", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert any("gemini-3.5-flash" in m["id"] for m in data["models"])


def test_monitored_ips_crud_and_check():
    client = TestClient(app)
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    headers = {"X-CSRF-Token": r_login.json()["csrf_token"]}

    # Clean up test IP if pre-exists
    from app.core.database import SessionLocal
    from app.models.case_extended import MonitoredIp
    with SessionLocal() as db_session:
        db_session.query(MonitoredIp).filter(MonitoredIp.ip_address == "198.51.100.99").delete()
        db_session.commit()

    # 1. Create Monitored IP
    create_res = client.post(
        "/api/v1/blacklist/monitored-ips",
        headers=headers,
        json={
            "ip_address": "198.51.100.99",
            "organization": "NBX",
            "server_name": "svtest01",
            "description": "Servidor de pruebas automatizadas",
            "check_interval_minutes": 30,
        },
    )
    assert create_res.status_code == 200
    item = create_res.json()["item"]
    ip_id = item["id"]
    assert item["ip_address"] == "198.51.100.99"
    assert item["status"] == "active"

    # 2. Check IP (mock query single rbl as clean)
    mock_clean_res = {
        "status": "clean",
        "listed": False,
        "response_code": None,
        "query_host": "99.100.51.198.zen.spamhaus.org",
        "details": "Limpia",
    }
    with patch("app.api.routers.blacklist._query_single_rbl", return_value=mock_clean_res):
        chk_res = client.post(f"/api/v1/blacklist/monitored-ips/{ip_id}/check", headers=headers)
        assert chk_res.status_code == 200
        assert chk_res.json()["is_listed"] is False

    # 3. Patch IP
    patch_res = client.patch(
        f"/api/v1/blacklist/monitored-ips/{ip_id}",
        headers=headers,
        json={"status": "paused", "server_name": "svtest01-paused"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["item"]["status"] == "paused"

    # 4. Delete IP
    del_res = client.delete(f"/api/v1/blacklist/monitored-ips/{ip_id}", headers=headers)
    assert del_res.status_code == 200
    assert del_res.json()["ok"] is True


def test_case_state_catalog_and_update():
    client = TestClient(app)
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    headers = {"X-CSRF-Token": r_login.json()["csrf_token"]}

    # 1. Get States Catalog
    states_res = client.get("/api/v1/cases/states/catalog", headers=headers)
    assert states_res.status_code == 200
    states = states_res.json()["states"]
    assert len(states) >= 8
    state_ids = [s["state_id"] for s in states]
    assert 4 in state_ids  # Containment
    assert 9 in state_ids  # Closed

    # 2. Update Case State
    with patch("app.iris.client.IrisApiClient.update_case_state", return_value={"status": "success"}):
        upd_res = client.patch(
            "/api/v1/cases/21/state",
            headers=headers,
            json={"state_id": 4},
        )
        assert upd_res.status_code == 200
        assert upd_res.json()["state_id"] == 4
        assert upd_res.json()["state_name"] == "Containment"


def test_unified_activity_stream_and_retention():
    client = TestClient(app)

    # 1. Login
    r_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USER,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD,
        },
    )
    assert r_login.status_code == 200
    csrf_token = r_login.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 2. Add Activity
    with patch("app.iris.client.IrisApiClient.ensure_task", return_value={"status": "created", "task_id": 99}):
        act_res = client.post(
            "/api/v1/cases/24/activity",
            headers=headers,
            json={
                "activity_type": "accion",
                "title": "Suspensión de cuenta cPanel",
                "content": "Cuenta suspendida preventivamente por phishing activo",
                "action_status": "ejecutada",
            },
        )
        assert act_res.status_code == 200
        act_id = act_res.json()["id"]

    # 3. Get Activities
    list_res = client.get("/api/v1/cases/24/activity", headers=headers)
    assert list_res.status_code == 200
    activities = list_res.json()["activities"]
    assert any(a["id"] == act_id for a in activities)

    # 4. Update Activity Status
    upd_res = client.patch(
        f"/api/v1/cases/24/activity/{act_id}",
        headers=headers,
        json={"action_status": "verificada"},
    )
    assert upd_res.status_code == 200
    assert upd_res.json()["action_status"] == "verificada"



