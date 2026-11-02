import re
from typing import Any, Dict, Optional
from app.core.config import settings


def _clean_id(val: Any) -> Optional[str]:
    """Valida y limpia un identificador numérico/alfanumérico sin caracteres inválidos."""
    if not val:
        return None
    s = str(val).strip()
    if s.lower() in ("none", "null", "n/a", "na", "0", ""):
        return None
    # Eliminar posibles prefijos tipo '#' o espacios
    s = re.sub(r"^[#\s]+", "", s)
    # Validar formato seguro: alfanumérico, guiones y guión bajo
    if re.match(r"^[A-Za-z0-9_-]+$", s):
        return s
    return None


def build_admin_links(
    *,
    organization: str,
    customer_id: Optional[int] = None,
    abuse_ticket_id: Optional[str] = None,
    holder_ticket_id: Optional[str] = None,
    client_id: Optional[str] = None,
    service_id: Optional[str] = None,
    domain_id: Optional[str] = None,
    iris_case_id: Optional[int] = None,
    user_role: Optional[str] = "admin",
) -> Dict[str, Any]:
    """
    Genera de forma centralizada y segura el conjunto de accesos administrativos
    según la organización verificada (NEUBOX ID 2 vs Hospedando ID 3).
    Aplica validación estricta de identificadores y control de acceso (RBAC).
    """
    # 1. Determinación confiable de la organización
    org_key = "NBX"
    if customer_id == 3 or str(organization).upper() == "HP":
        org_key = "HP"
    elif customer_id == 2 or str(organization).upper() == "NBX":
        org_key = "NBX"

    org_config = settings.ORGANIZATIONS.get(org_key, settings.ORGANIZATIONS["NBX"])
    templates = org_config.get("links", {})
    helpdesk_system = org_config.get("helpdesk_system", "Helpdesk")
    billing_system = org_config.get("billing_system", "Panel de Clientes")

    # 2. Limpieza y validación de identificadores
    c_abuse_ticket = _clean_id(abuse_ticket_id)
    c_holder_ticket = _clean_id(holder_ticket_id)
    c_client_id = _clean_id(client_id)
    c_service_id = _clean_id(service_id)
    c_domain_id = _clean_id(domain_id)

    # 3. RBAC Check: Solo usuarios autorizados (analistas y admins)
    has_admin_access = user_role in ("admin", "analyst", "soc_analyst", "lead_analyst") if user_role else True

    links: Dict[str, Any] = {
        "organization": org_key,
        "organization_name": org_config.get("name", org_key),
        "helpdesk_system": helpdesk_system,
        "billing_system": billing_system,
        "actions": [],
    }

    if not has_admin_access:
        return links

    # A. Ticket de Abuso
    if c_abuse_ticket and "support_ticket" in templates:
        url = templates["support_ticket"].format(ticket_id=c_abuse_ticket)
        links["actions"].append({
            "key": "abuse_ticket",
            "label": f"Abrir Ticket de Abuso #{c_abuse_ticket}",
            "system": helpdesk_system,
            "url": url,
            "id_value": c_abuse_ticket,
        })
        links["abuse_ticket_url"] = url

    # B. Ticket del Titular (si existe y es diferente)
    if c_holder_ticket and "support_ticket" in templates:
        url = templates["support_ticket"].format(ticket_id=c_holder_ticket)
        links["actions"].append({
            "key": "holder_ticket",
            "label": f"Abrir Ticket del Titular #{c_holder_ticket}",
            "system": helpdesk_system,
            "url": url,
            "id_value": c_holder_ticket,
        })
        links["holder_ticket_url"] = url

    # C. Perfil del Cliente
    if c_client_id and "client_summary" in templates:
        url = templates["client_summary"].format(client_id=c_client_id)
        links["actions"].append({
            "key": "client_profile",
            "label": f"Ver Perfil del Cliente #{c_client_id}",
            "system": billing_system,
            "url": url,
            "id_value": c_client_id,
        })
        links["client_summary_url"] = url

    # D. Servicio de Hosting (requiere client_id y service_id)
    if c_client_id and c_service_id and "hosting_service" in templates:
        url = templates["hosting_service"].format(client_id=c_client_id, service_id=c_service_id)
        links["actions"].append({
            "key": "hosting_service",
            "label": f"Ver Servicio de Hosting #{c_service_id}",
            "system": billing_system,
            "url": url,
            "id_value": c_service_id,
        })
        links["hosting_service_url"] = url

    # E. Dominio Registrado (requiere client_id y domain_id)
    if c_client_id and c_domain_id and "registered_domain" in templates:
        url = templates["registered_domain"].format(
            client_id=c_client_id,
            domain_id=c_domain_id,
            domainid=c_domain_id,
        )
        links["actions"].append({
            "key": "registered_domain",
            "label": f"Ver Dominio Registrado #{c_domain_id}",
            "system": billing_system,
            "url": url,
            "id_value": c_domain_id,
        })
        links["registered_domain_url"] = url

    # F. Expediente Oficial en DFIR-IRIS
    if iris_case_id:
        iris_url = f"{settings.IRIS_URL}/case?cid={iris_case_id}"
        links["actions"].append({
            "key": "iris_official",
            "label": f"Ver Expediente Oficial en IRIS #{iris_case_id}",
            "system": "DFIR-IRIS",
            "url": iris_url,
            "id_value": str(iris_case_id),
        })
        links["iris_official_url"] = iris_url

    return links
