import email
from email import policy
from email.parser import BytesParser
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from pypdf import PdfReader

from app.ingestion.base import IndicatorItem, NormalizedIngestPayload

# Dominios propios, de herramientas internas o de reportantes conocidos que NUNCA son el activo afectado
INFRA_AND_REPORTER_DOMAINS = {
    "neubox.com",
    "neubox.net",
    "serverneubox.com.mx",
    "hospedando.com.mx",
    "hospedando.mx",
    "controldns.mx",
    "cloud-mx-ns.net",
    "nlab.mx",
    "shots.nlab.mx",
    "helpdesk.neubox.com",
    "clientes.neubox.com",
    "netcraft.com",
    "incident.netcraft.com",
    "xarf.org",
    "www.xarf.org",
    "axur.com",
    "cyberwipe.co",
    "www.cyberwipe.co",
    "a3sec.com",
    "zohomail.com",
    "mx.zohomail.com",
    "google.com",
    "gmail.com",
    "aol.com",
    "cloudflare.com",
    "amazonaws.com",
    "godaddy.com",
    "www.godaddy.com",
    "markmonitor.com",
    "www.markmonitor.com",
    "dynadot.com",
    "www.dynadot.com",
    "cscdbs.com",
    "mailchannels.net",
    "relay.mailchannels.net",
    "digicertdns.com",
    "digicertdns.net",
    "domaincontrol.com",
    "dns-parking.com",
    "w3.org",
    "schemas.microsoft.com",
}

PRIVATE_IP_PREFIXES = (
    "10.",
    "127.",
    "192.168.",
    "169.254.",
    "0.",
    "255.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)


def defang_to_normal(text: str) -> str:
    """Desofusca URLs, dominios e IPs (hxxps, [.], [://], etc.)."""
    if not text:
        return ""
    out = text
    out = re.sub(r"\bhxxps\b", "https", out, flags=re.IGNORECASE)
    out = re.sub(r"\bhxxp\b", "http", out, flags=re.IGNORECASE)
    out = out.replace("[://]", "://").replace("[:]", ":")
    out = out.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    return out


def is_valid_public_ipv4(ip: str) -> bool:
    if not ip or any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(x) for x in parts]
        if any(n < 0 or n > 255 for n in nums):
            return False
        # Evitar falsos positivos de números de versión tipo 6.2.0.1
        if nums[0] in (0, 127, 255):
            return False
        return True
    except ValueError:
        return False


def clean_domain_candidate(raw: str) -> Optional[str]:
    if not raw:
        return None
    d = raw.strip().lower().strip(".,;:()[]<>\"'/#?")
    if d.startswith("http://") or d.startswith("https://"):
        parsed = urlparse(d)
        d = parsed.hostname or ""
    if d.startswith("www.") and d.count(".") >= 2:
        # conservar subdominio real cuando no es www, quitar www.
        d = d[4:]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,15}$", d):
        return None
    if any(
        d.endswith(ext)
        for ext in (".php", ".html", ".jpg", ".png", ".webp", ".pdf", ".json", ".txt", ".js", ".css")
    ):
        return None
    return d


class ReportNormalizer:
    """Motor unificado de extracción, desofuscación y normalización de reportes de abuso."""

    @classmethod
    def from_file(
        cls,
        file_path: str | Path,
        organization: Optional[str] = None,
        source_type: str = "manual_file",
    ) -> Tuple[NormalizedIngestPayload, bytes, List[Tuple[str, bytes, str]]]:
        p = Path(file_path)
        raw_bytes = p.read_bytes()
        ext = p.suffix.lower()
        extra_attachments: List[Tuple[str, bytes, str]] = []

        if ext == ".pdf":
            reader = PdfReader(io.BytesIO(raw_bytes))
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
            payload = cls.normalize_text(
                text=text,
                filename=p.name,
                organization=organization,
                source_type=source_type,
            )
            return payload, raw_bytes, extra_attachments

        if ext == ".eml":
            payload, extra_attachments = cls.normalize_eml_bytes(
                raw_bytes=raw_bytes,
                filename=p.name,
                organization=organization,
                source_type=source_type,
            )
            return payload, raw_bytes, extra_attachments

        text = raw_bytes.decode("utf-8", errors="replace")
        payload = cls.normalize_text(
            text=text,
            filename=p.name,
            organization=organization,
            source_type=source_type,
        )
        return payload, raw_bytes, extra_attachments

    @classmethod
    def normalize_eml_bytes(
        cls,
        raw_bytes: bytes,
        filename: str = "correo.eml",
        organization: Optional[str] = None,
        source_type: str = "imap",
    ) -> Tuple[NormalizedIngestPayload, List[Tuple[str, bytes, str]]]:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(msg.get("subject", "") or "")
        from_hdr = str(msg.get("from", "") or "")
        to_hdr = str(msg.get("to", "") or "")
        date_hdr = str(msg.get("date", "") or "")
        msg_id = str(msg.get("message-id", "") or "").strip("<>")
        return_path = str(msg.get("return-path", "") or "").strip("<>")
        received_spf = str(msg.get("received-spf", "") or "")
        auth_results = str(msg.get("authentication-results", "") or "")
        received_headers = [str(r) for r in msg.get_all("received", [])]

        body_parts: List[str] = []
        extra_attachments: List[Tuple[str, bytes, str]] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", "") or "")
                att_name = part.get_filename()
                if att_name or "attachment" in disp.lower():
                    try:
                        att_bytes = part.get_payload(decode=True) or b""
                        extra_attachments.append((att_name or "attachment.bin", att_bytes, ctype))
                        if ctype in ("application/json", "text/plain") or (att_name and att_name.endswith(".json")):
                            body_parts.append(att_bytes.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
                elif ctype == "text/plain":
                    try:
                        body_parts.append(part.get_content())
                    except Exception:
                        pass
                elif ctype == "text/html" and not body_parts:
                    try:
                        html_raw = part.get_content()
                        body_parts.append(re.sub(r"<[^>]+>", " ", html_raw))
                    except Exception:
                        pass
        else:
            try:
                body_parts.append(msg.get_content())
            except Exception:
                body_parts.append(raw_bytes.decode("utf-8", errors="replace"))

        headers_text = "\n".join(
            [
                f"Subject: {subject}",
                f"From: {from_hdr}",
                f"To: {to_hdr}",
                f"Date: {date_hdr}",
                f"Message-ID: {msg_id}",
                f"Return-Path: {return_path}",
                f"Received-SPF: {received_spf}",
                f"Authentication-Results: {auth_results}",
            ]
            + [f"Received: {r}" for r in received_headers]
        )
        combined = headers_text + "\n\n" + "\n".join(body_parts)
        payload = cls.normalize_text(
            text=combined,
            filename=filename,
            organization=organization,
            source_type=source_type,
            subject_override=subject,
            reporter_override=from_hdr,
        )
        if msg_id and (not payload.source_id or payload.source_id == "0"):
            payload.source_id = msg_id[:120]
        return payload, extra_attachments

    @classmethod
    def normalize_text(
        cls,
        text: str,
        filename: str = "reporte.txt",
        organization: Optional[str] = None,
        source_type: str = "manual_text",
        subject_override: Optional[str] = None,
        reporter_override: Optional[str] = None,
    ) -> NormalizedIngestPayload:
        raw_text = text or ""
        norm_text = defang_to_normal(raw_text)
        provenance: Dict[str, str] = {}

        # 1.Separar el reporte inicial (antes de "Análisis Bastion") de las notas internas
        bastion_split = re.split(r"🔍\s*Análisis Bastion", norm_text, maxsplit=1)
        initial_complaint_section = bastion_split[0] if bastion_split else norm_text
        bastion_and_after = bastion_split[1] if len(bastion_split) > 1 else ""

        # 2. Extraer Ticket de Abuso
        ticket_id = None
        m_ticket = re.search(r"Ticket\s*#?(\d{5,8})", norm_text, re.IGNORECASE)
        if not m_ticket:
            m_ticket = re.search(r"Ticket[_\s-]+(\d{5,8})", filename, re.IGNORECASE)
        if m_ticket:
            ticket_id = m_ticket.group(1)
            provenance["abuse_ticket_id"] = "rule"

        # 3. Extraer URL de origen en Helpdesk
        source_url = None
        m_url = re.search(r"URL:\s*(https?://\S+)", norm_text)
        if m_url:
            source_url = m_url.group(1).strip()
        elif ticket_id:
            source_url = f"https://helpdesk.neubox.com/#ticket/zoom/{ticket_id}"

        # 4. Extraer Servicio / Service ID en cabecera de Zammad (ej. Servicio Reseller Premium - uttlaxcala.edu.mx (#283561))
        service_plan = None
        service_id = None
        client_id = None
        header_service_domain = None
        m_srv = re.search(
            r"Servicio\s+([^\n#]+?)\s*-\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*\(#(\d+)\)",
            norm_text,
        )
        if m_srv:
            service_plan = m_srv.group(1).strip()
            header_service_domain = clean_domain_candidate(m_srv.group(2))
            service_id = m_srv.group(3).strip()
            provenance["service_id"] = "rule"
            provenance["service_plan"] = "rule"

        # Extraer client_id y service_id de enlaces administrativos WHMCS (clientsservices.php?userid=251974&id=357137)
        m_whmcs = re.search(r"clientsservices\.php\?userid=(\d+)&(?:amp;)?id=(\d+)", norm_text, re.IGNORECASE)
        if m_whmcs:
            client_id = m_whmcs.group(1)
            service_id = m_whmcs.group(2)
            provenance["client_id"] = "rule"
            provenance["service_id"] = "rule"

        # 5. Extraer Ticket del titular (si el analista documentó otro ticket zoom distinto al de abuso)
        holder_ticket_id = None
        for m_zoom in re.finditer(r"helpdesk\.neubox\.com/#ticket/zoom/(\d{5,8})", norm_text):
            cand_t = m_zoom.group(1)
            if cand_t != ticket_id:
                holder_ticket_id = cand_t
                provenance["holder_ticket_id"] = "rule"
                break

        # 6. Extraer Reportante y Tipo de Reportante
        reporter = reporter_override or "No especificado"
        reporter_email = None
        reporter_type = "external_reporter"

        if re.search(r"Secretar[íi]a de Seguridad y Protecci[óo]n Ciudadana|SSPC|COFEPRIS", initial_complaint_section, re.IGNORECASE):
            reporter = "SSPC / COFEPRIS (Dirección General de Investigación Cibernética)"
            reporter_type = "authority"
        elif re.search(r"Polic[íi]a Cibern[ée]tica", initial_complaint_section, re.IGNORECASE):
            m_pol = re.search(r"(Polic[íi]a Cibern[ée]tica[^\n.]+)", initial_complaint_section, re.IGNORECASE)
            reporter = m_pol.group(1).strip() if m_pol else "Policía Cibernética"
            reporter_type = "authority"
        elif re.search(r"\bNetcraft\b", initial_complaint_section, re.IGNORECASE):
            reporter = "Netcraft Takedown / X-ARF"
            reporter_email = "support@netcraft.com"
            reporter_type = "brand_protection"
        elif re.search(r"\bAxur\b|abuse\.efc@axur\.com", initial_complaint_section, re.IGNORECASE):
            reporter = "Axur Digital Protection"
            reporter_email = "abuse.efc@axur.com"
            reporter_type = "brand_protection"
        elif re.search(r"\bCyberWipe\b|hello@cyberwipe\.co", initial_complaint_section, re.IGNORECASE):
            reporter = "CyberWipe Legal / Brand Protection"
            reporter_email = "hello@cyberwipe.co"
            reporter_type = "brand_protection"
        else:
            m_correo_form = re.search(r"Nombre:\s*([^\n]+)\s+Correo:\s*([^\s\n]+)", initial_complaint_section, re.IGNORECASE)
            if m_correo_form:
                reporter = f"{m_correo_form.group(1).strip()} ({m_correo_form.group(2).strip()})"
                reporter_email = m_correo_form.group(2).strip()
            else:
                m_pub = re.search(r"\n([^\n—]+?)\s+—\s+—\s+\d{1,2}/\d{1,2}/\d{4}[^\n]+Mensaje p[úu]blico", initial_complaint_section)
                if m_pub:
                    reporter = m_pub.group(1).strip()
                    if header_service_domain:
                        reporter_type = "customer"
        provenance["reporter"] = "rule"

        # 7. Referencia externa (ej. Netcraft Issue Number: 97541882, #EFC4870486)
        external_ref = None
        m_ext = re.search(
            r"(?:Netcraft Issue Number:\s*(\d+)|tracking code\s*(#[A-Z0-9-]+)|Issue\s*#?(\d{6,12}))",
            initial_complaint_section,
            re.IGNORECASE,
        )
        if m_ext:
            external_ref = next((g for g in m_ext.groups() if g), None)
            provenance["external_reference"] = "rule"

        # 8. Parsear bloques de Análisis Bastion (si existen)
        bastion_domains: List[Dict[str, Any]] = []
        hosted_domains: List[str] = []
        internal_reg_domains: List[str] = []
        hosting_ip = None
        server_name = None
        registrar_name = None
        is_internal_registrar = None
        is_hosted_internally = False
        nameservers: List[str] = []

        for block in re.split(r"={20,}", bastion_and_after):
            m_dom = re.search(r"DOMAIN:\s*([a-zA-Z0-9.-]+)", block)
            if not m_dom:
                continue
            b_dom = clean_domain_candidate(m_dom.group(1))
            if not b_dom:
                continue
            m_sub = re.search(r"Subdomain:\s*([a-zA-Z0-9.-]+)", block)
            b_sub = m_sub.group(1).strip().lower() if m_sub else None
            full_dom = f"{b_sub}.{b_dom}" if b_sub and b_sub != "www" else b_dom

            m_reg = re.search(r"Registrar:\s*([^\n]+)", block)
            reg_raw = m_reg.group(1).strip() if m_reg else ""
            internal_reg = "internal" in reg_raw.lower() or "neubox" in reg_raw.lower() or "hospedando" in reg_raw.lower()

            hosted_here = "✅" in block and "Hosted on NEUBOX" in block
            block_ips: List[str] = []
            block_servers: List[str] = []
            for m_rec in re.finditer(
                r"Record\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*→\s*([a-zA-Z0-9.-]+)?([^\n]*)",
                block,
            ):
                rec_ip = m_rec.group(1)
                rec_ptr = (m_rec.group(2) or "").rstrip(".")
                rec_rest = m_rec.group(3) or ""
                if is_valid_public_ipv4(rec_ip):
                    if "Hosted on NEUBOX" in rec_rest or "serverneubox.com.mx" in rec_ptr or "hospedando" in rec_ptr:
                        hosted_here = True
                        block_ips.append(rec_ip)
                        if rec_ptr and rec_ptr.lower() != "no":
                            block_servers.append(rec_ptr)

            b_ns = re.findall(r"\b(?:ns\d+\.[a-z0-9.-]+|[a-z0-9-]+\.ns\.cloudflare\.com|[a-z0-9-]+\.dns-parking\.com)\b", block.lower())

            bastion_domains.append(
                {
                    "domain": full_dom,
                    "base_domain": b_dom,
                    "registrar": reg_raw,
                    "internal_registrar": internal_reg,
                    "hosted_internally": hosted_here,
                    "hosting_ips": list(dict.fromkeys(block_ips)),
                    "servers": list(dict.fromkeys(block_servers)),
                    "nameservers": list(dict.fromkeys(b_ns)),
                }
            )

            if full_dom not in INFRA_AND_REPORTER_DOMAINS and b_dom not in INFRA_AND_REPORTER_DOMAINS:
                if hosted_here:
                    hosted_domains.append(full_dom)
                    is_hosted_internally = True
                    if block_ips and not hosting_ip:
                        hosting_ip = block_ips[0]
                        provenance["hosting_ip"] = "rule"
                    if block_servers and not server_name:
                        server_name = block_servers[0]
                        provenance["server_name"] = "rule"
                if internal_reg:
                    internal_reg_domains.append(full_dom)
                    if not registrar_name:
                        registrar_name = reg_raw.split("✅")[0].strip()
                        is_internal_registrar = True
                        provenance["registrar_name"] = "rule"
                if b_ns and not nameservers:
                    nameservers = list(dict.fromkeys(b_ns))[:6]

        # 9. Identificar explícitamente Dominio Afectado vs Marca Suplantada en la denuncia inicial
        explicit_reported_domain = None
        impersonated_brand = None
        impersonated_domain = None

        # Patrones explícitos de reporte ("Reported domain:", "Fraudulent Domain/URL -", "Sitio Web:", "revisión del dominio", "dominio https://...")
        explicit_patterns = [
            r"(?:Reported domain|Fraudulent Domain/URL|Sitio Web|URL reportada|revisi[óo]n del dominio|titular del dominio|sub\s*dominio|hosting a phishing attack on your network)\s*[:\-]?\s*(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"el sitio web con el dominio\s+(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"regarding the domain\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"domain of\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s+designates",
        ]
        for pat in explicit_patterns:
            m_exp = re.search(pat, initial_complaint_section, re.IGNORECASE)
            if m_exp:
                cand = clean_domain_candidate(m_exp.group(1))
                if cand and cand not in INFRA_AND_REPORTER_DOMAINS:
                    explicit_reported_domain = cand
                    break

        # Patrones de marca suplantada ("targets our customer, CHECK24, website URL https://www.check24.de/", "Official website: https://www.spherion.com", "copies the Stori brand (official site - https://storicard.com)", "marca Banco Invex")
        m_brand1 = re.search(
            r"targets our customer,\s*([^,\n]+),\s*website URL\s*https?://([a-zA-Z0-9.-]+)",
            initial_complaint_section,
            re.IGNORECASE,
        )
        m_brand2 = re.search(
            r"copies the\s+([A-Za-z0-9_-]+)\s+brand\s*\(official site\s*-\s*https?://([a-zA-Z0-9.-]+)\)",
            initial_complaint_section,
            re.IGNORECASE,
        )
        m_brand3 = re.search(
            r"on behalf of our client,\s*([^,\n]+),.*?Official website:\s*https?://([a-zA-Z0-9.-]+)",
            initial_complaint_section,
            re.IGNORECASE | re.DOTALL,
        )
        m_brand4 = re.search(
            r"copyright de la marca\s+([^\n.]+)",
            initial_complaint_section,
            re.IGNORECASE,
        )
        if m_brand1:
            impersonated_brand = m_brand1.group(1).strip()
            impersonated_domain = clean_domain_candidate(m_brand1.group(2))
        elif m_brand2:
            impersonated_brand = m_brand2.group(1).strip()
            impersonated_domain = clean_domain_candidate(m_brand2.group(2))
        elif m_brand3:
            impersonated_brand = m_brand3.group(1).strip()
            impersonated_domain = clean_domain_candidate(m_brand3.group(2))
        elif m_brand4:
            impersonated_brand = m_brand4.group(1).strip()

        if impersonated_brand:
            provenance["impersonated_brand"] = "rule"

        # Selección de primary_domain con prioridad jerárquica
        primary_domain = (
            explicit_reported_domain
            or header_service_domain
            or (hosted_domains[0] if hosted_domains else None)
            or (internal_reg_domains[0] if internal_reg_domains else None)
        )
        if not primary_domain:
            # Buscar en el texto de la denuncia inicial excluyendo marca suplantada y dominios de infraestructura
            for m_any in re.finditer(r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b", initial_complaint_section):
                cand = clean_domain_candidate(m_any.group(1))
                if (
                    cand
                    and cand not in INFRA_AND_REPORTER_DOMAINS
                    and cand != impersonated_domain
                ):
                    primary_domain = cand
                    break

        if primary_domain:
            provenance["primary_domain"] = "rule"

        # 10. Extraer URLs reportadas (en la denuncia inicial, excluyendo URLs de netcraft/helpdesk/oficiales)
        reported_urls: List[str] = []
        for m_u in re.finditer(r"https?://[^\s<>\"'\]]+", initial_complaint_section):
            u = m_u.group(0).rstrip(".,;)")
            parsed_u = urlparse(u)
            u_host = clean_domain_candidate(parsed_u.hostname or "")
            if not u_host or u_host in INFRA_AND_REPORTER_DOMAINS or u_host == impersonated_domain:
                continue
            if u not in reported_urls:
                reported_urls.append(u)

        # 11. Extraer IPs separadas estrictamente por Rol Semántico
        reported_ip = None
        src_ip = None
        auth_ip = None
        rbl_ip = None
        authenticated_account = None

        # 11.a IP explícitamente reportada en la denuncia inicial (ej. Fraudulent IP - 174.136.25.186 o [65.99.225.168])
        m_rep_ip = re.search(
            r"(?:Fraudulent IP|IP reportada|Reported IP|IP address)\s*[:\-]?\s*(\d{1,3}(?:\.\d{1,3}){3})",
            initial_complaint_section,
            re.IGNORECASE,
        )
        if not m_rep_ip:
            m_rep_ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", initial_complaint_section)
        if m_rep_ip and is_valid_public_ipv4(m_rep_ip.group(1)):
            reported_ip = m_rep_ip.group(1)
            provenance["reported_ip"] = "rule"

        # 11.b Cabeceras SMTP (client-ip=, Received: from, envelope-from)
        m_client_ip = re.search(r"client-ip=(\d{1,3}(?:\.\d{1,3}){3})", initial_complaint_section, re.IGNORECASE)
        if m_client_ip and is_valid_public_ipv4(m_client_ip.group(1)):
            src_ip = m_client_ip.group(1)
            provenance["src_ip"] = "rule"

        m_env_from = re.search(
            r"(?:envelope-from|smtp\.mailfrom|Return-Path)\s*[=:]\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?",
            initial_complaint_section,
            re.IGNORECASE,
        )
        if m_env_from:
            authenticated_account = m_env_from.group(1).lower()
            provenance["authenticated_account"] = "rule"

        smtp_analysis: Dict[str, Any] = {}
        if "received-spf:" in initial_complaint_section.lower() or "authentication-results:" in initial_complaint_section.lower():
            m_spf = re.search(r"spf=(pass|fail|softfail|neutral)", initial_complaint_section, re.IGNORECASE)
            m_dkim = re.search(r"dkim=(pass|fail|none)", initial_complaint_section, re.IGNORECASE)
            m_dmarc = re.search(r"dmarc=(pass|fail|none)", initial_complaint_section, re.IGNORECASE)
            smtp_analysis = {
                "has_smtp_headers": True,
                "spf": m_spf.group(1).lower() if m_spf else "unknown",
                "dkim": m_dkim.group(1).lower() if m_dkim else "unknown",
                "dmarc": m_dmarc.group(1).lower() if m_dmarc else "unknown",
                "client_ip": src_ip,
                "envelope_from": authenticated_account,
            }

        # Si no hubo reported_ip explícita, usar src_ip o hosting_ip
        if not reported_ip:
            reported_ip = src_ip or hosting_ip
            if reported_ip:
                provenance["reported_ip"] = "rule"

        # 12. Servidor Neubox/Hospedando si no salió de Bastion
        if not server_name:
            m_srv_host = re.search(
                r"\b((?:svgp|svgr|svgt|svgs|svghp|vps|ded| host)\d*[a-z0-9.-]*)\b",
                norm_text,
                re.IGNORECASE,
            )
            if m_srv_host and ("serverneubox" in m_srv_host.group(1).lower() or re.match(r"^svg[a-z]+\d+", m_srv_host.group(1).lower())):
                server_name = m_srv_host.group(1).lower().rstrip(".")
                provenance["server_name"] = "rule"

        # 13. Detectar acciones del analista ya documentadas en el ticket (para migración o tickets cerrados)
        analyst_actions: List[Dict[str, Any]] = []
        if re.search(r"le suspend[íi] el servicio|servicio suspendido|se suspende", norm_text, re.IGNORECASE):
            analyst_actions.append(
                {
                    "action_type": "suspension_servicio",
                    "title": "Suspensión de servicio en WHMCS / servidor",
                    "status": "ejecutada",
                    "evidence": f"userid={client_id}&id={service_id}" if client_id and service_id else "Documentado en nota interna",
                }
            )
        if re.search(r"Syncing\s+\S+\s+\.\.\.\.Done|Synchronization Complete", norm_text, re.IGNORECASE):
            analyst_actions.append(
                {
                    "action_type": "sincronizacion_dns",
                    "title": "Sincronización de zona DNS en servidor",
                    "status": "verificada",
                    "evidence": "Synchronization Complete",
                }
            )
        if re.search(r"no hemos identificado contenido que utilice la marca|en esta etapa no tomaremos medidas restrictivas", norm_text, re.IGNORECASE):
            analyst_actions.append(
                {
                    "action_type": "orientacion_wipo",
                    "title": "Revisión sin abuso corroborado y orientación WIPO al reportante",
                    "status": "ejecutada",
                    "evidence": "Respuesta pública enviada por Christian Aceves",
                }
            )
        if holder_ticket_id or re.search(r"se le inform[óo] al cliente", norm_text, re.IGNORECASE):
            analyst_actions.append(
                {
                    "action_type": "notificacion_cliente",
                    "title": f"Notificación al titular del servicio (Ticket #{holder_ticket_id or 'vinculado'})",
                    "status": "ejecutada",
                    "evidence": f"https://helpdesk.neubox.com/#ticket/zoom/{holder_ticket_id}" if holder_ticket_id else "Nota interna",
                }
            )

        # 14. Construir lista tipada de Indicadores (IOCs) por rol
        indicators: List[IndicatorItem] = []
        indicators_by_role: Dict[str, List[str]] = {
            "domain_reported": [],
            "domain_brand": [],
            "url_reported": [],
            "ip_hosting": [],
            "ip_reported": [],
            "ip_src": [],
            "ip_auth": [],
            "ip_rbl": [],
            "email_sender": [],
            "server_hostname": [],
        }

        if primary_domain:
            indicators_by_role["domain_reported"].append(primary_domain)
            indicators.append(
                IndicatorItem(
                    value=primary_domain,
                    ioc_type="domain",
                    role="domain_reported",
                    description="Dominio / subdominio principal reportado",
                    is_affected_asset=True,
                )
            )

        if impersonated_domain and impersonated_domain != primary_domain:
            indicators_by_role["domain_brand"].append(impersonated_domain)
            indicators.append(
                IndicatorItem(
                    value=impersonated_domain,
                    ioc_type="domain",
                    role="domain_brand",
                    description=f"Dominio oficial de la marca afectada ({impersonated_brand or 'Referencia'}) — NO bloquear",
                    is_affected_asset=False,
                )
            )

        for u in reported_urls[:5]:
            indicators_by_role["url_reported"].append(u)
            indicators.append(
                IndicatorItem(
                    value=u,
                    ioc_type="url",
                    role="url_reported",
                    description="URL específica reportada en la denuncia",
                    is_affected_asset=True,
                )
            )

        if hosting_ip:
            indicators_by_role["ip_hosting"].append(hosting_ip)
            indicators.append(
                IndicatorItem(
                    value=hosting_ip,
                    ioc_type="ip-dst",
                    role="ip_hosting",
                    description=f"IP de alojamiento en NEUBOX/Hospedando ({server_name or 'Servidor interno'})",
                    is_affected_asset=True,
                )
            )

        if reported_ip and reported_ip != hosting_ip:
            indicators_by_role["ip_reported"].append(reported_ip)
            indicators.append(
                IndicatorItem(
                    value=reported_ip,
                    ioc_type="ip-dst",
                    role="ip_reported",
                    description="IP señalada en el reporte de abuso",
                    is_affected_asset=True,
                )
            )

        if src_ip and src_ip not in (hosting_ip, reported_ip):
            indicators_by_role["ip_src"].append(src_ip)
            indicators.append(
                IndicatorItem(
                    value=src_ip,
                    ioc_type="ip-src",
                    role="ip_src",
                    description="IP origen en cabeceras SMTP (client-ip)",
                    is_affected_asset=True,
                )
            )

        if authenticated_account:
            indicators_by_role["email_sender"].append(authenticated_account)
            indicators.append(
                IndicatorItem(
                    value=authenticated_account,
                    ioc_type="email-src",
                    role="email_sender",
                    description="Remitente / cuenta en cabeceras SMTP (envelope-from)",
                    is_affected_asset=True,
                )
            )

        if server_name:
            indicators_by_role["server_hostname"].append(server_name)
            indicators.append(
                IndicatorItem(
                    value=server_name,
                    ioc_type="hostname",
                    role="server_hostname",
                    description="Servidor de hosting identificado",
                    is_affected_asset=True,
                )
            )

        # 15. Determinar Organización (NBX vs HP)
        org = (organization or "").upper()
        if org not in ("NBX", "HP"):
            if "hospedando" in norm_text.lower() or "svghp" in (server_name or "").lower():
                org = "HP"
            else:
                org = "NBX"

        # 16. Resumen limpio del reporte inicial
        clean_lines = []
        for line in initial_complaint_section.splitlines():
            s = line.strip()
            if not s:
                continue
            if any(
                s.startswith(prefix)
                for prefix in (
                    "Ticket ",
                    "TIPIFICACIÓN",
                    "Tipo ",
                    "Group ",
                    "Owner ",
                    "State ",
                    "Pending till",
                    "Priority ",
                    "Servicio ",
                    "about:blank",
                    "📎",
                )
            ):
                continue
            if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4},\s*\d{1,2}:\d{2}\s*(?:AM|PM)", s):
                continue
            if "Mensaje público" in s:
                continue
            clean_lines.append(s)

        report_summary = " ".join(clean_lines)[:600] or "Reporte de abuso recibido para análisis SOC."
        subject = subject_override or f"Ticket #{ticket_id or 'Manual'} — {primary_domain or 'Reporte de Abuso'}"

        return NormalizedIngestPayload(
            source_type=source_type,
            source_instance="default",
            source_id=ticket_id or filename,
            organization=org,
            reporter=reporter,
            reporter_email=reporter_email,
            reporter_type=reporter_type,
            subject=subject,
            original_content=raw_text,
            external_reference=external_ref,
            source_url=source_url,
            abuse_ticket_id=ticket_id,
            holder_ticket_id=holder_ticket_id,
            client_id=client_id,
            service_id=service_id,
            service_plan=service_plan,
            primary_domain=primary_domain,
            reported_urls=reported_urls,
            impersonated_brand=impersonated_brand,
            impersonated_Select_domain=impersonated_domain,
            registrar_name=registrar_name,
            is_internal_registrar=is_internal_registrar,
            is_hosted_internally=is_hosted_internally,
            nameservers=nameservers,
            server_name=server_name,
            hosting_ip=hosting_ip,
            reported_ip=reported_ip,
            src_ip=src_ip,
            auth_ip=auth_ip,
            rbl_ip=rbl_ip,
            authenticated_account=authenticated_account,
            indicators=indicators,
            indicators_by_role=indicators_by_role,
            bastion_domains_summary=bastion_domains,
            smtp_analysis=smtp_analysis,
            analyst_actions_detected=analyst_actions,
            report_summary=report_summary,
            field_provenance=provenance,
        )

