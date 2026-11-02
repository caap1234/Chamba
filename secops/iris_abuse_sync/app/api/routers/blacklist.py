import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.audit import log_audit_event
from app.core.rbac import get_optional_user
from app.iris.client import IrisApiClient
from app.models.user import User
from app.models.case_extended import RblEpisode, CaseExtension, MonitoredIp, AlertExtension

router = APIRouter(prefix="/api/v1/blacklist", tags=["Blacklist Master"])

# Proveedores RBL estándar de la industria configurados
STANDARD_RBL_PROVIDERS = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "category": "Reputación Global / Exploits / Spam"},
    {"name": "Barracuda Reputation Network", "zone": "b.barracudacentral.org", "category": "Filtro Antispam Barracuda"},
    {"name": "SpamCop Blocking List", "zone": "bl.spamcop.net", "category": "Reportes Activos SpamCop"},
    {"name": "SORBS DNSBL", "zone": "dnsbl.sorbs.net", "category": "Base Agregada SORBS"},
    {"name": "SORBS Dynamic / Dialup (DUL)", "zone": "dul.dnsbl.sorbs.net", "category": "IPs Dinámicas / Residenciales"},
    {"name": "LashBack Unsubscribe Blacklist (UBL)", "zone": "ubl.unsubscore.com", "category": "Violación de Unsubscribe"},
]


class BlacklistCheckRequest(BaseModel):
    target: str = Field(..., min_length=3, description="Dirección IP o Nombre de Dominio a consultar")
    server_name: Optional[str] = None
    organization: Optional[str] = "NBX"
    record_episode: bool = False


class MonitoredIpCreateRequest(BaseModel):
    ip_address: str = Field(..., min_length=7, max_length=64)
    organization: str = Field(default="NBX")
    server_name: Optional[str] = None
    description: Optional[str] = None
    check_interval_minutes: int = Field(default=60, ge=5, le=1440)


class MonitoredIpBulkRequest(BaseModel):
    raw_text: str = Field(..., min_length=3, description="IPs separadas por línea, coma o espacio")
    organization: str = Field(default="NBX")
    server_name: Optional[str] = None
    description: Optional[str] = None
    check_interval_minutes: int = Field(default=60, ge=5, le=1440)


class MonitoredIpUpdateRequest(BaseModel):
    server_name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None  # active, paused
    check_interval_minutes: Optional[int] = None


class DelistingRegisterRequest(BaseModel):
    episode_id: int
    delisting_reference: Optional[str] = None
    notes: Optional[str] = None


class LinkEpisodeCaseRequest(BaseModel):
    case_id: int


def _resolve_ip_from_target(target: str) -> Optional[str]:
    """Valida si target es IPv4 o resuelve el dominio a IPv4."""
    t = target.strip()
    try:
        ip_obj = ipaddress.ip_address(t)
        return str(ip_obj)
    except ValueError:
        pass
    try:
        return socket.gethostbyname(t)
    except Exception:
        return None


def _query_single_rbl(ip: str, zone: str, timeout: float = 2.5) -> Dict[str, Any]:
    parts = ip.strip().split(".")
    if len(parts) != 4:
        # Por ahora DNSBL inverso estándar aplica a IPv4
        return {
            "status": "clean",
            "listed": False,
            "response_code": None,
            "query_host": f"{ip}.{zone}",
            "details": "IPv6 no soportada en zona IPv4 reversa",
        }
    reversed_ip = ".".join(reversed(parts))
    query_host = f"{reversed_ip}.{zone}"

    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        addr = socket.gethostbyname(query_host)
        if addr.startswith("127.0.0."):
            return {
                "status": "listed",
                "listed": True,
                "response_code": addr,
                "query_host": query_host,
                "details": f"Listado confirmado por proveedor (código DNS: {addr})",
            }
        return {
            "status": "clean",
            "listed": False,
            "response_code": addr,
            "query_host": query_host,
            "details": "Respuesta neutra (No catalogada como listado)",
        }
    except socket.gaierror as e:
        err_str = str(e).lower()
        if "nodename nor servname provided" in err_str or "not known" in err_str or "nxdomain" in err_str:
            return {
                "status": "clean",
                "listed": False,
                "response_code": None,
                "query_host": query_host,
                "details": "Limpia (NXDOMAIN: La IP no figura en este listado)",
            }
        return {
            "status": "error",
            "listed": False,
            "response_code": None,
            "query_host": query_host,
            "details": f"Error de resolución DNS en consulta: {str(e)}",
        }
    except socket.timeout:
        return {
            "status": "error",
            "listed": False,
            "response_code": None,
            "query_host": query_host,
            "details": "Tiempo de espera agotado al consultar proveedor RBL",
        }
    except Exception as e:
        return {
            "status": "error",
            "listed": False,
            "response_code": None,
            "query_host": query_host,
            "details": f"Error inesperado al consultar RBL: {str(e)}",
        }
    finally:
        socket.setdefaulttimeout(orig_timeout)


def _correlate_rbl_detection(
    db: Session,
    *,
    monitored_ip: MonitoredIp,
    listed_providers: List[str],
    details: str,
    user: Optional[User] = None,
) -> Dict[str, Any]:
    """
    Motor de Correlación Inteligente SOC v3.1:
    - Deduplicación: Un solo incidente consolidado aunque figure en múltiples RBL simultáneamente.
    - Escenario A: IP detectada sin alerta ni caso abierto -> Generar nueva alerta en Centro de Alertas.
    - Escenario B: Ya existe una alerta activa para la misma condición -> Incrementar contador y actualizar sin duplicar.
    - Escenario C: Existe caso IRIS abierto relacionado -> Relacionar detección al caso abierto existente.
    - Escenario D: Caso relacionado cerrado -> Generar nueva alerta referenciando el caso anterior como antecedente.
    - Escenario E: La IP deja de aparecer en RBL -> Actualizar monitoreo a clean y marcar episodios delisted.
    """
    now = datetime.now(timezone.utc)
    ip_str = monitored_ip.ip_address

    # Escenario E: IP sin listados (Limpia)
    if len(listed_providers) == 0:
        if monitored_ip.last_status == "listed":
            active_eps = (
                db.query(RblEpisode)
                .filter(RblEpisode.ip_address == ip_str, RblEpisode.status.in_(["active", "delisting_requested"]))
                .all()
            )
            for ep in active_eps:
                ep.status = "delisted"
                ep.delisted_at = now
                ep.last_seen_at = now
            monitored_ip.last_status = "clean"
            monitored_ip.listed_providers = []
            monitored_ip.listed_count = 0
            monitored_ip.updated_at = now
            db.commit()
            return {"scenario": "E", "action": "delisted_clean", "ip": ip_str}
        monitored_ip.last_status = "clean"
        monitored_ip.listed_providers = []
        monitored_ip.listed_count = 0
        monitored_ip.updated_at = now
        db.commit()
        return {"scenario": "E", "action": "confirmed_clean", "ip": ip_str}

    # IP listada: Verificar si existe caso IRIS abierto o cerrado
    client = IrisApiClient()
    open_related_case_id: Optional[int] = None
    closed_related_case_id: Optional[int] = None

    candidates = (
        db.query(CaseExtension)
        .filter(
            (CaseExtension.hosting_ip == ip_str)
            | (CaseExtension.reported_ip == ip_str)
            | ((CaseExtension.server_name == monitored_ip.server_name) & (CaseExtension.server_name.isnot(None)))
        )
        .all()
    )

    for c in candidates:
        try:
            iris_c = client.get_case_full(c.iris_case_id)
            st_id = iris_c.get("state_id") or iris_c.get("status_id") or 1
            if st_id == 9:  # Closed en DFIR-IRIS
                if not closed_related_case_id:
                    closed_related_case_id = c.iris_case_id
            else:
                open_related_case_id = c.iris_case_id
                break
        except Exception:
            pass

    # Verificar alertas activas en AlertExtension
    active_alert = (
        db.query(AlertExtension)
        .filter(
            (AlertExtension.reported_ip == ip_str) | (AlertExtension.hosting_ip == ip_str),
            AlertExtension.verification_state.notin_(["descartada", "falso_positivo"]),
        )
        .order_by(AlertExtension.id.desc())
        .first()
    )

    # Escenario B: Alerta activa existente -> Actualizar sin duplicar
    if active_alert:
        active_alert.observation_count = (active_alert.observation_count or 1) + 1
        active_alert.updated_at = now
        active_alert.heuristic_result_json = {
            "listed_providers": listed_providers,
            "count": len(listed_providers),
            "details": details,
        }
        monitored_ip.last_status = "listed"
        monitored_ip.listed_providers = listed_providers
        monitored_ip.listed_count = len(listed_providers)
        monitored_ip.last_alert_id = active_alert.iris_alert_id
        monitored_ip.updated_at = now
        db.commit()
        return {
            "scenario": "B",
            "action": "alert_updated",
            "alert_id": active_alert.iris_alert_id,
            "observations": active_alert.observation_count,
        }

    # Escenario C: Caso IRIS abierto relacionado -> Relacionar al caso sin duplicar
    if open_related_case_id:
        try:
            client.ensure_timeline_event(
                open_related_case_id,
                title=f"[RBL Detection] {ip_str} en {len(listed_providers)} listas",
                content=f"Detección periódica Blacklist Master:\nProveedores: {', '.join(listed_providers)}\n{details}",
                category_id=5,
            )
        except Exception:
            pass

        monitored_ip.last_status = "listed"
        monitored_ip.listed_providers = listed_providers
        monitored_ip.listed_count = len(listed_providers)
        monitored_ip.last_case_id = open_related_case_id
        monitored_ip.updated_at = now
        db.commit()
        return {
            "scenario": "C",
            "action": "linked_to_open_case",
            "case_id": open_related_case_id,
        }

    # Escenario D (Caso cerrado como antecedente) o Escenario A (Nueva alerta)
    antecedent_str = f" [Antecedente: Caso cerrado #{closed_related_case_id}]" if closed_related_case_id else ""
    cust_id = 3 if monitored_ip.organization == "HP" else 2
    title = f"[RBL] {ip_str} detectada en {len(listed_providers)} listas ({monitored_ip.server_name or monitored_ip.organization}){antecedent_str}"
    desc = (
        f"Alerta automática de reputación y listas negras (Blacklist Master SOC):\n"
        f"- Dirección IP: {ip_str}\n"
        f"- Servidor: {monitored_ip.server_name or 'No especificado'}\n"
        f"- Organización: {monitored_ip.organization}\n"
        f"- Proveedores RBL confirmados ({len(listed_providers)}): {', '.join(listed_providers)}\n"
        f"- Detalles técnicos: {details}\n"
    )

    new_alert_id = None
    try:
        res_iris = client.create_alert(
            title=title,
            description=desc,
            customer_id=cust_id,
            severity_id=2,  # Medium
            status_id=2,    # New
            source="Blacklist Master",
            source_ref=f"rbl-{ip_str}-{now.strftime('%Y%m%d%H%M')}",
            tags="rbl,blacklist,reputation,soc",
        )
        new_alert_id = res_iris.get("alert_id")
    except Exception as e:
        print(f"Error creando alerta RBL en IRIS: {e}")

    if new_alert_id:
        alt_ext = AlertExtension(
            iris_alert_id=new_alert_id,
            organization=monitored_ip.organization,
            source_type="blacklist_master",
            reported_ip=ip_str,
            hosting_ip=ip_str,
            server_name=monitored_ip.server_name,
            category_code="blacklist_rbl",
            reported_activity="blacklist_rbl",
            severity="Medium",
            observation_count=1,
            correlated_case_ids_json=[closed_related_case_id] if closed_related_case_id else [],
            heuristic_result_json={"providers": listed_providers, "count": len(listed_providers)},
        )
        db.add(alt_ext)

    # Registrar episodios individuales en RBL Episodes
    for p in listed_providers:
        active_ep = (
            db.query(RblEpisode)
            .filter(
                RblEpisode.ip_address == ip_str,
                RblEpisode.rbl_provider == p,
                RblEpisode.status.in_(["active", "delisting_requested"]),
            )
            .first()
        )
        if active_ep:
            active_ep.last_seen_at = now
            active_ep.check_count = (active_ep.check_count or 1) + 1
        else:
            new_ep = RblEpisode(
                ip_address=ip_str,
                server_name=monitored_ip.server_name,
                organization=monitored_ip.organization,
                rbl_provider=p,
                status="active",
                reason=f"Listado RBL detectado por monitoreo ({details})",
                first_seen_at=now,
                last_seen_at=now,
                check_count=1,
                iris_alert_id=new_alert_id,
            )
            db.add(new_ep)

    monitored_ip.last_status = "listed"
    monitored_ip.listed_providers = listed_providers
    monitored_ip.listed_count = len(listed_providers)
    monitored_ip.last_alert_id = new_alert_id
    monitored_ip.updated_at = now
    db.commit()

    scenario_code = "D" if closed_related_case_id else "A"
    return {
        "scenario": scenario_code,
        "action": "alert_created",
        "alert_id": new_alert_id,
        "previous_case_id": closed_related_case_id,
    }


# ==============================================================================
# ENDPOINTS DE ADMINISTRACIÓN DE IPs MONITOREADAS
# ==============================================================================

@router.get("/monitored-ips")
def list_monitored_ips(
    organization: Optional[str] = Query(None, description="NBX, HP"),
    status: Optional[str] = Query(None, description="active, paused"),
    last_status: Optional[str] = Query(None, description="clean, listed, error, pending"),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Consulta la lista de direcciones IP bajo vigilancia continua de reputación."""
    q = db.query(MonitoredIp)
    if organization and organization.upper() in ("NBX", "HP"):
        q = q.filter(MonitoredIp.organization == organization.upper())
    if status:
        q = q.filter(MonitoredIp.status == status)
    if last_status:
        q = q.filter(MonitoredIp.last_status == last_status)
    if search:
        s = f"%{search.strip()}%"
        q = q.filter(
            (MonitoredIp.ip_address.ilike(s))
            | (MonitoredIp.server_name.ilike(s))
            | (MonitoredIp.description.ilike(s))
        )

    total = q.count()
    items = q.order_by(MonitoredIp.id.desc()).offset(offset).limit(limit).all()

    return {
        "status": "ok",
        "total": total,
        "ips": [
            {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "organization": ip.organization,
                "server_name": ip.server_name,
                "description": ip.description,
                "status": ip.status,
                "last_status": ip.last_status,
                "listed_providers": ip.listed_providers or [],
                "listed_count": ip.listed_count or 0,
                "last_checked_at": ip.last_checked_at.isoformat() if ip.last_checked_at else None,
                "next_check_at": ip.next_check_at.isoformat() if ip.next_check_at else None,
                "check_interval_minutes": ip.check_interval_minutes,
                "last_alert_id": ip.last_alert_id,
                "last_case_id": ip.last_case_id,
                "created_at": ip.created_at.isoformat() if ip.created_at else None,
            }
            for ip in items
        ],
    }


@router.post("/monitored-ips")
def create_monitored_ip(
    payload: MonitoredIpCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Registra una dirección IP individual para monitoreo automático de reputación."""
    clean_ip = payload.ip_address.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        clean_ip = str(ip_obj)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{payload.ip_address}' no es una dirección IPv4/IPv6 válida.")

    org = payload.organization.upper() if payload.organization else "NBX"
    if org not in ("NBX", "HP"):
        org = "NBX"

    existing = db.query(MonitoredIp).filter(MonitoredIp.ip_address == clean_ip).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"La IP {clean_ip} ya se encuentra registrada en monitoreo.")

    now = datetime.now(timezone.utc)
    new_ip = MonitoredIp(
        ip_address=clean_ip,
        organization=org,
        server_name=payload.server_name.strip() if payload.server_name else None,
        description=payload.description.strip() if payload.description else None,
        check_interval_minutes=payload.check_interval_minutes,
        status="active",
        last_status="pending",
        created_at=now,
        updated_at=now,
    )
    db.add(new_ip)
    db.commit()
    db.refresh(new_ip)

    log_audit_event(
        db,
        action="monitored_ip.created",
        module="blacklist_master",
        user=user,
        details=f"IP {clean_ip} ({org} - Servidor: {payload.server_name}) agregada al monitoreo.",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "monitored_ip_id": new_ip.id,
        "ip_address": new_ip.ip_address,
        "item": {
            "id": new_ip.id,
            "ip_address": new_ip.ip_address,
            "organization": new_ip.organization,
            "server_name": new_ip.server_name,
            "description": new_ip.description,
            "status": new_ip.status,
            "last_status": new_ip.last_status,
        },
    }


@router.post("/monitored-ips/bulk")
def bulk_create_monitored_ips(
    payload: MonitoredIpBulkRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Operación masiva para registrar múltiples direcciones IP en una sola acción."""
    raw = payload.raw_text or ""
    tokens = [t.strip() for t in re.split(r"[\r\n,\s;]+", raw) if t.strip()]

    org = payload.organization.upper() if payload.organization else "NBX"
    if org not in ("NBX", "HP"):
        org = "NBX"

    added = 0
    skipped_existing = 0
    invalid_ips = []
    now = datetime.now(timezone.utc)

    for tok in tokens:
        try:
            ip_obj = ipaddress.ip_address(tok)
            ip_str = str(ip_obj)
        except ValueError:
            invalid_ips.append(tok)
            continue

        existing = db.query(MonitoredIp).filter(MonitoredIp.ip_address == ip_str).first()
        if existing:
            skipped_existing += 1
            continue

        mip = MonitoredIp(
            ip_address=ip_str,
            organization=org,
            server_name=payload.server_name.strip() if payload.server_name else None,
            description=payload.description.strip() if payload.description else "Carga masiva",
            check_interval_minutes=payload.check_interval_minutes,
            status="active",
            last_status="pending",
            created_at=now,
            updated_at=now,
        )
        db.add(mip)
        added += 1

    db.commit()

    log_audit_event(
        db,
        action="monitored_ip.bulk_created",
        module="blacklist_master",
        user=user,
        details=f"Carga masiva ({org}): {added} agregadas, {skipped_existing} omitidas por existir, {len(invalid_ips)} inválidas.",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "added_count": added,
        "skipped_existing_count": skipped_existing,
        "invalid_ips": invalid_ips,
    }


@router.patch("/monitored-ips/{ip_id}")
def update_monitored_ip(
    ip_id: int,
    payload: MonitoredIpUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Actualiza configuración, servidor o pausa/reactiva el monitoreo de una IP."""
    mip = db.query(MonitoredIp).filter(MonitoredIp.id == ip_id).first()
    if not mip:
        raise HTTPException(status_code=404, detail="IP monitoreada no encontrada.")

    now = datetime.now(timezone.utc)
    if payload.server_name is not None:
        mip.server_name = payload.server_name.strip() or None
    if payload.description is not None:
        mip.description = payload.description.strip() or None
    if payload.status is not None:
        if payload.status in ("active", "paused"):
            mip.status = payload.status
    if payload.check_interval_minutes is not None:
        mip.check_interval_minutes = payload.check_interval_minutes

    mip.updated_at = now
    db.commit()
    db.refresh(mip)

    log_audit_event(
        db,
        action="monitored_ip.updated",
        module="blacklist_master",
        user=user,
        details=f"Monitoreo de IP {mip.ip_address} actualizado (Estado: {mip.status}).",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "monitored_ip": {"id": mip.id, "ip": mip.ip_address, "status": mip.status},
        "item": {"id": mip.id, "ip": mip.ip_address, "status": mip.status},
    }


@router.delete("/monitored-ips/{ip_id}")
def delete_monitored_ip(
    ip_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Retira definitivamente una IP del sistema de monitoreo continuo."""
    mip = db.query(MonitoredIp).filter(MonitoredIp.id == ip_id).first()
    if not mip:
        raise HTTPException(status_code=404, detail="IP monitoreada no encontrada.")

    ip_addr = mip.ip_address
    db.delete(mip)
    db.commit()

    log_audit_event(
        db,
        action="monitored_ip.deleted",
        module="blacklist_master",
        user=user,
        details=f"IP {ip_addr} retirada del monitoreo continuo.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "ok": True, "deleted_ip": ip_addr}


@router.post("/monitored-ips/{ip_id}/check")
def check_single_monitored_ip(
    ip_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Ejecuta una consulta en vivo inmediata para una IP monitoreada y aplica correlación inteligente."""
    mip = db.query(MonitoredIp).filter(MonitoredIp.id == ip_id).first()
    if not mip:
        raise HTTPException(status_code=404, detail="IP monitoreada no encontrada.")

    now = datetime.now(timezone.utc)
    results = []
    listed_providers = []

    for prov in STANDARD_RBL_PROVIDERS:
        res = _query_single_rbl(mip.ip_address, prov["zone"])
        res["provider_name"] = prov["name"]
        res["provider_zone"] = prov["zone"]
        results.append(res)
        if res.get("status") == "listed":
            listed_providers.append(prov["name"])

    details = f"Consulta inmediata realizada por {user.username if user else 'analista SOC'}."
    correlation_res = _correlate_rbl_detection(
        db,
        monitored_ip=mip,
        listed_providers=listed_providers,
        details=details,
        user=user,
    )

    mip.last_checked_at = now
    mip.next_check_at = now + timedelta(minutes=mip.check_interval_minutes or 60)
    db.commit()

    return {
        "status": "ok",
        "ip_address": mip.ip_address,
        "last_status": mip.last_status,
        "is_listed": len(listed_providers) > 0,
        "listed_count": len(listed_providers),
        "listed_providers": listed_providers,
        "correlation": correlation_res,
        "providers_checked": results,
    }


@router.post("/monitored-ips/run-checks")
def run_all_monitored_ips_checks(
    request: Request,
    force_all: bool = Query(False, description="Forzar chequeo sin importar la próxima fecha"),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Tarea programable para ejecutar chequeos automáticos en lote sobre las IPs activas."""
    now = datetime.now(timezone.utc)
    q = db.query(MonitoredIp).filter(MonitoredIp.status == "active")
    if not force_all:
        q = q.filter((MonitoredIp.next_check_at.is_(None)) | (MonitoredIp.next_check_at <= now))

    due_ips = q.all()
    results_summary = []

    for mip in due_ips:
        listed_providers = []
        for prov in STANDARD_RBL_PROVIDERS:
            res = _query_single_rbl(mip.ip_address, prov["zone"])
            if res.get("status") == "listed":
                listed_providers.append(prov["name"])

        corr = _correlate_rbl_detection(
            db,
            monitored_ip=mip,
            listed_providers=listed_providers,
            details="Chequeo automático programado Blacklist Master.",
            user=user,
        )
        mip.last_checked_at = now
        mip.next_check_at = now + timedelta(minutes=mip.check_interval_minutes or 60)
        results_summary.append({
            "ip": mip.ip_address,
            "listed_count": len(listed_providers),
            "scenario": corr.get("scenario"),
            "action": corr.get("action"),
        })

    db.commit()

    log_audit_event(
        db,
        action="monitored_ips.batch_checked",
        module="blacklist_master",
        user=user,
        details=f"Monitoreo en lote ejecutado sobre {len(due_ips)} direcciones IP.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "total_checked": len(due_ips), "summary": results_summary}


# ==============================================================================
# CONSULTA MANUAL Y GESTIÓN DE EPISODIOS RBL
# ==============================================================================

@router.post("/check")
def check_ip_or_domain_rbl(
    payload: BlacklistCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """
    Realiza una consulta en vivo a los proveedores RBL configurados.
    Distingue claramente entre 'clean' (no listada), 'listed' (confirmada) y 'error' (fallo de consulta).
    """
    resolved_ip = _resolve_ip_from_target(payload.target)
    if not resolved_ip:
        raise HTTPException(
            status_code=400,
            detail=f"No se pudo determinar una dirección IPv4 válida para '{payload.target}'.",
        )

    results = []
    listed_count = 0
    clean_count = 0
    error_count = 0
    now = datetime.now(timezone.utc)

    for prov in STANDARD_RBL_PROVIDERS:
        res = _query_single_rbl(resolved_ip, prov["zone"])
        res["provider_name"] = prov["name"]
        res["provider_zone"] = prov["zone"]
        res["category"] = prov["category"]
        results.append(res)

        if res.get("status") == "listed":
            listed_count += 1
            if payload.record_episode:
                active_ep = (
                    db.query(RblEpisode)
                    .filter(
                        RblEpisode.ip_address == resolved_ip,
                        RblEpisode.rbl_provider == prov["name"],
                        RblEpisode.status.in_(["active", "delisting_requested"]),
                    )
                    .first()
                )
                if active_ep:
                    active_ep.last_seen_at = now
                    active_ep.check_count = (active_ep.check_count or 1) + 1
                    if payload.server_name:
                        active_ep.server_name = payload.server_name
                else:
                    new_ep = RblEpisode(
                        ip_address=resolved_ip,
                        server_name=payload.server_name,
                        organization=(payload.organization or "NBX").upper(),
                        rbl_provider=prov["name"],
                        status="active",
                        reason=res["details"],
                        first_seen_at=now,
                        last_seen_at=now,
                        check_count=1,
                    )
                    db.add(new_ep)
        elif res.get("status") == "clean":
            clean_count += 1
        else:
            error_count += 1

    if payload.record_episode:
        db.commit()

    log_audit_event(
        db,
        action="blacklist.queried",
        module="blacklist_master",
        user=user,
        details=f"Consulta RBL para {resolved_ip} (Target: {payload.target}): {listed_count} listados, {clean_count} limpios, {error_count} errores.",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "target": payload.target,
        "resolved_ip": resolved_ip,
        "query_timestamp": now.isoformat(),
        "summary": {
            "total_queried": len(STANDARD_RBL_PROVIDERS),
            "listed": listed_count,
            "clean": clean_count,
            "errors": error_count,
            "is_clean": listed_count == 0 and error_count == 0,
        },
        "providers": results,
    }


@router.get("/episodes")
def list_rbl_episodes(
    status: Optional[str] = Query(None, description="active, delisting_requested, delisted"),
    organization: Optional[str] = Query(None, description="NBX, HP"),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Consulta la bitácora histórica de episodios de reputación y delisting en Blacklist Master."""
    q = db.query(RblEpisode)
    if status:
        q = q.filter(RblEpisode.status == status)
    if organization and organization.upper() in ("NBX", "HP"):
        q = q.filter(RblEpisode.organization == organization.upper())
    if search:
        s = f"%{search.strip()}%"
        q = q.filter(
            (RblEpisode.ip_address.ilike(s))
            | (RblEpisode.server_name.ilike(s))
            | (RblEpisode.rbl_provider.ilike(s))
            | (RblEpisode.reason.ilike(s))
        )

    total = q.count()
    items = q.order_by(RblEpisode.last_seen_at.desc()).offset(offset).limit(limit).all()

    return {
        "status": "ok",
        "total": total,
        "episodes": [
            {
                "id": ep.id,
                "ip_address": ep.ip_address,
                "server_name": ep.server_name,
                "organization": ep.organization,
                "rbl_provider": ep.rbl_provider,
                "status": ep.status,
                "reason": ep.reason,
                "check_count": ep.check_count,
                "first_seen_at": ep.first_seen_at.isoformat() if ep.first_seen_at else None,
                "last_seen_at": ep.last_seen_at.isoformat() if ep.last_seen_at else None,
                "delisted_at": ep.delisted_at.isoformat() if ep.delisted_at else None,
                "iris_alert_id": ep.iris_alert_id,
                "iris_case_id": ep.iris_case_id,
            }
            for ep in items
        ],
    }


@router.post("/delisting")
def register_delisting_request(
    payload: DelistingRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Registra una solicitud de delisting ante el proveedor RBL para seguimiento."""
    ep = db.query(RblEpisode).filter(RblEpisode.id == payload.episode_id).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Episodio RBL no encontrado.")

    now = datetime.now(timezone.utc)
    ep.status = "delisting_requested"
    ep.last_seen_at = now
    notes = f"Solicitud de delisting iniciada por {user.username if user else 'analista'}."
    if payload.delisting_reference:
        notes += f" Ref: {payload.delisting_reference}."
    if payload.notes:
        notes += f" {payload.notes}."

    ep.reason = f"{ep.reason} | {notes}" if ep.reason else notes
    db.commit()

    log_audit_event(
        db,
        action="blacklist.delisting_requested",
        module="blacklist_master",
        user=user,
        details=f"Delisting solicitado para IP {ep.ip_address} en {ep.rbl_provider}.",
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "episode_id": ep.id, "current_status": ep.status}


@router.post("/episodes/{episode_id}/link-case")
def link_episode_to_case(
    episode_id: int,
    payload: LinkEpisodeCaseRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Vincula un episodio de lista negra con un caso de investigación DFIR-IRIS existente."""
    ep = db.query(RblEpisode).filter(RblEpisode.id == episode_id).first()
    if not ep:
        raise HTTPException(status_code=404, detail="Episodio RBL no encontrado.")

    ep.iris_case_id = payload.case_id
    db.commit()

    log_audit_event(
        db,
        action="blacklist.linked_case",
        module="blacklist_master",
        user=user,
        details=f"Episodio #{episode_id} ({ep.ip_address}) vinculado al Caso IRIS #{payload.case_id}.",
        iris_case_id=payload.case_id,
        ip_address=request.client.host if request.client else None,
    )

    return {"status": "ok", "episode_id": ep.id, "iris_case_id": payload.case_id}


@router.get("/stats")
def get_blacklist_stats(db: Session = Depends(get_db)):
    """Métricas operativas del estado de reputación y listas negras."""
    total = db.query(RblEpisode).count()
    active = db.query(RblEpisode).filter(RblEpisode.status == "active").count()
    delisting = db.query(RblEpisode).filter(RblEpisode.status == "delisting_requested").count()
    delisted = db.query(RblEpisode).filter(RblEpisode.status == "delisted").count()

    nbx_count = db.query(RblEpisode).filter(RblEpisode.organization == "NBX").count()
    hp_count = db.query(RblEpisode).filter(RblEpisode.organization == "HP").count()

    total_monitored = db.query(MonitoredIp).count()
    active_monitored = db.query(MonitoredIp).filter(MonitoredIp.status == "active").count()
    listed_monitored = db.query(MonitoredIp).filter(MonitoredIp.last_status == "listed").count()

    return {
        "status": "ok",
        "total_episodes": total,
        "active_listings": active,
        "delisting_in_progress": delisting,
        "resolved_clean": delisted,
        "by_organization": {"NBX": nbx_count, "HP": hp_count},
        "monitored_providers_count": len(STANDARD_RBL_PROVIDERS),
        "total_monitored_ips": total_monitored,
        "active_monitored_ips": active_monitored,
        "listed_monitored_ips": listed_monitored,
    }
