import io
import re
from typing import Dict, Any, List, Optional
from pathlib import Path
from pypdf import PdfReader


def undefang(text: str) -> str:
    """Removes defanging like [.] -> . and hxxp -> http."""
    t = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = re.sub(r'hxxp(s?)://', r'http\1://', t, flags=re.IGNORECASE)
    t = re.sub(r'\[at\]|\[@\]|\(@\)', '@', t, flags=re.IGNORECASE)
    return t


def extract_text_from_pdf(pdf_source: Any) -> str:
    """
    Extracts plain text from a PDF path, bytes, or file-like object using pypdf.
    """
    if isinstance(pdf_source, (str, Path)):
        reader = PdfReader(str(pdf_source))
    elif isinstance(pdf_source, bytes):
        reader = PdfReader(io.BytesIO(pdf_source))
    else:
        reader = PdfReader(pdf_source)

    pages_text = []
    for page in reader.pages:
        text = page.extract_text() or ""
        pages_text.append(text)

    return "\n".join(pages_text)


class TicketParser:
    """
    Intelligent parser for Neubox Helpdesk ticket exports and PDFs.
    Extracts metadata, timeline messages, Bastion analysis, email headers,
    and security indicators (IOCs).
    """

    def __init__(self, raw_text: str):
        self.raw_text = raw_text
        self.clean_text = undefang(raw_text)

    def parse(self) -> Dict[str, Any]:
        ticket_id = self._extract_ticket_id()
        ticket_url = self._extract_ticket_url(ticket_id)
        owner = self._extract_field(r"Owner\s+(?:AsignarmeDesasignar\s+)?([^\n]+)")
        group = self._extract_field(r"Group\s+([^\n]+)")
        state = self._extract_field(r"State\s+([^\n]+)")
        priority = self._extract_field(r"Priority\s+([^\n]+)")

        messages = self._extract_messages()
        bastion_text = self._extract_bastion()
        email_headers = self._extract_email_headers()

        reporter_info = self._extract_reporter_info(messages)
        domains = self._extract_domains()
        urls = self._extract_urls()
        ips = self._extract_ips()
        neubox_servers = self._extract_neubox_servers()
        auth_accounts = self._extract_auth_accounts()
        client_ticket = self._extract_client_ticket()
        brief_summary = self._extract_brief_summary(messages)

        # Primary reported entity resolution
        primary_domain = domains[0] if domains else ""
        primary_ip = ips[0] if ips else ""
        primary_server = neubox_servers[0] if neubox_servers else ""
        primary_account = auth_accounts[0] if auth_accounts else ""

        # Determine main asset
        if primary_domain:
            affected_asset = primary_domain
        elif primary_account:
            affected_asset = primary_account
        elif primary_ip:
            affected_asset = primary_ip
        else:
            affected_asset = "No especificado"

        # IOC list prepared for IRIS
        iocs = []
        for d in set(domains):
            iocs.append({"type": "domain", "value": d, "description": "Dominio reportado en ticket"})
        for u in set(urls):
            iocs.append({"type": "url", "value": u, "description": "URL de abuso reportada"})
        for ip in set(ips):
            # Exclude loopback or local IPs
            if not ip.startswith("127.") and not ip.startswith("192.168."):
                iocs.append({"type": "ip", "value": ip, "description": "Dirección IP relacionada"})
        for acc in set(auth_accounts):
            iocs.append({"type": "email", "value": acc, "description": "Cuenta autenticada / remitente"})

        return {
            "ticket_id": ticket_id,
            "ticket_url": ticket_url,
            "owner": owner,
            "group": group,
            "state": state,
            "priority": priority,
            "reporter": reporter_info["name"],
            "reporter_email": reporter_info["email"],
            "reporter_org": reporter_info["org"],
            "report_date": reporter_info["date"],
            "messages": messages,
            "bastion_analysis": bastion_text,
            "email_headers": email_headers,
            "reported_domains": domains,
            "reported_urls": urls,
            "reported_ips": ips,
            "neubox_servers": neubox_servers,
            "auth_accounts": auth_accounts,
            "client_ticket": client_ticket,
            "affected_asset": affected_asset,
            "primary_domain": primary_domain,
            "primary_ip": primary_ip,
            "primary_server": primary_server,
            "primary_account": primary_account,
            "brief_summary": brief_summary,
            "iocs": iocs,
            "raw_text": self.raw_text,
        }

    def _extract_ticket_id(self) -> str:
        # Match Ticket 789034
        m = re.search(r"Ticket\s*#?\s*(\d{5,8})", self.raw_text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"ticket/zoom/(\d{5,8})", self.raw_text)
        if m:
            return m.group(1)
        return ""

    def _extract_ticket_url(self, ticket_id: str) -> str:
        m = re.search(r"https?://helpdesk\.neubox\.com/#ticket/zoom/\d+", self.raw_text)
        if m:
            return m.group(0)
        if ticket_id:
            return f"https://helpdesk.neubox.com/#ticket/zoom/{ticket_id}"
        return ""

    def _extract_field(self, pattern: str) -> str:
        m = re.search(pattern, self.raw_text)
        return m.group(1).strip() if m else ""

    def _extract_messages(self) -> List[Dict[str, str]]:
        """
        Splits ticket conversation into individual entries.
        Pattern matches: Author — — Date/Time — Mensaje público / Nota interna
        """
        pattern = r"([^\n—]+)\s*—\s*—\s*([\d/]+ [\d:]+\s*(?:am|pm)?)\s*—\s*(Mensaje público|Nota interna)"
        splits = list(re.finditer(pattern, self.raw_text))
        messages = []

        for i, match in enumerate(splits):
            author = match.group(1).strip()
            date_str = match.group(2).strip()
            msg_type = match.group(3).strip()

            start_idx = match.end()
            end_idx = splits[i + 1].start() if i + 1 < len(splits) else len(self.raw_text)
            body = self.raw_text[start_idx:end_idx].strip()

            # Clean UI artifacts from page headers/footers
            body = re.sub(r"\d{1,2}/\d{1,2}/\d{2,4},?\s*\d{1,2}:\d{2}\s*(?:AM|PM)?\s*Ticket \d+", "", body)
            body = re.sub(r"about:blank\s*\d/\d", "", body)
            body = re.sub(r"See (?:more|less)", "", body)

            messages.append({
                "author": author,
                "date": date_str,
                "type": msg_type,
                "body": body.strip()
            })

        return messages

    def _extract_bastion(self) -> str:
        """Extracts the automated Bastion analysis section if present."""
        m = re.search(r"(?:🔍\s*Análisis Bastion|DOMAIN:\s*[a-zA-Z0-9.-]+)[\s\S]*?(?:⏱️\s*Execution time[^\n]*|={20,})", self.raw_text)
        if m:
            return m.group(0).strip()
        return ""

    def _extract_email_headers(self) -> str:
        """Extracts email header block if present in the ticket."""
        m = re.search(r"(?:Header info:|Return-Path:)[\s\S]*?(?:DKIM-Signature|X-Authenticated-Id|X-CMAE-Envelope)[\s\S]*?(?=\n\n(?:From:|Sent:|Subject:)|$)", self.raw_text)
        if m:
            return m.group(0).strip()
        return ""

    def _extract_reporter_info(self, messages: List[Dict[str, str]]) -> Dict[str, str]:
        info = {"name": "", "email": "", "org": "", "date": ""}
        for msg in messages:
            if msg["type"] == "Mensaje público":
                author = msg["author"]
                info["date"] = msg["date"]
                info["name"] = author

                # Check if author has email
                email_m = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", author)
                if email_m:
                    info["email"] = email_m.group(1)

                # Check body for signature or organization
                body = msg["body"]
                if "PhishFort" in author or "PhishFort" in body:
                    info["org"] = "PhishFort Threat Resolution"
                    if not info["name"]:
                        info["name"] = "PhishFort Takedowns"
                elif "BrutalRx" in body:
                    info["org"] = "BrutalRx"
                    m_sign = re.search(r"Saludos,\s*\n+([^\n]+)", body)
                    if m_sign:
                        info["name"] = m_sign.group(1).strip()
                elif "CTIR Gov" in body or "cert.br" in body:
                    info["org"] = "CTIR Gov BR Team (Cyber Incident Prevention, Handling and Response Center)"
                    info["name"] = "CTIR Gov BR Team <ctir@ctir.gov.br>"
                    info["email"] = "ctir@ctir.gov.br"
                elif "Rachel Green" in body:
                    info["name"] = "Rachel Green (Reportado vía abuso)"

                break

        return info

    def _extract_domains(self) -> List[str]:
        domains = []
        text = self.clean_text

        # 1. Look for Bastion DOMAIN field
        for m in re.finditer(r"DOMAIN:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text, re.IGNORECASE):
            d = m.group(1).lower().rstrip(".")
            if d not in domains and not d.endswith("neubox.com") and not d.endswith("neubox.net"):
                domains.append(d)

        # 2. Look for reported domain in abuse body
        patterns = [
            r"suspend\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"sitio\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"concerning\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        ]
        for p in patterns:
            for m in re.finditer(p, text, re.IGNORECASE):
                d = m.group(1).lower().rstrip(".,;:)'\"")
                # Filter out known infrastructure / portal domains
                if d and d not in domains and not self._is_infra_domain(d):
                    domains.append(d)

        # 3. Check for domains in email addresses (e.g. @mni.com.mx, @vicsan.com.mx)
        auths = self._extract_auth_accounts()
        for a in auths:
            if "@" in a:
                d = a.split("@", 1)[1].lower()
                if d not in domains and not self._is_infra_domain(d):
                    domains.append(d)

        return domains

    def _extract_urls(self) -> List[str]:
        urls = []
        # Match http/https URLs
        matches = re.findall(r"https?://[^\s<>\"',;)]+", self.clean_text)
        for u in matches:
            u_clean = u.rstrip(".,;)>'\"")
            # Exclude helpdesk, nlab shot, hospedando, etc.
            if not any(x in u_clean for x in ["helpdesk.neubox.com", "shots.nlab.mx", "neubox.com/Soporte", "domains2.squarespace.com", "gov.br/ctir"]):
                if u_clean not in urls:
                    urls.append(u_clean)
        return urls

    def _extract_ips(self) -> List[str]:
        ips = []
        # Explicit IP mentions
        for m in re.finditer(r"(?:IP\s*|A Record\s*:\s*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", self.clean_text):
            ip = m.group(1)
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)

        # General IP matches
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", self.clean_text):
            ip = m.group(1)
            # Filter out version numbers like 4.98 or 2026.10
            parts = [int(p) for p in ip.split(".")]
            if all(0 <= p <= 255 for p in parts) and parts[0] not in (0, 10, 127) and ip not in ips:
                # Exclude comcast or internal resolvers if possible, keep primary
                ips.append(ip)

        return ips

    def _extract_neubox_servers(self) -> List[str]:
        servers = []
        for m in re.finditer(r"\b((?:svgp|svgs|svds|svdh|pmg)\d+\.serverneubox\.com\.mx)\b", self.clean_text, re.IGNORECASE):
            s = m.group(1).lower()
            if s not in servers:
                servers.append(s)
        return servers

    def _extract_auth_accounts(self) -> List[str]:
        accounts = []
        patterns = [
            r"X-Authenticated-Id:\s*([^\s\r\n]+)",
            r"Phishing sender:\s*([^\s\r\n]+)",
            r"(?:from|de)\s+(?:Rachel Green|remitente)\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"envelope-from\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>"
        ]
        for p in patterns:
            for m in re.finditer(p, self.clean_text, re.IGNORECASE):
                acc = m.group(1).strip().strip("<>\"'")
                if "@" in acc and acc not in accounts and not acc.endswith("comcast.net") and not acc.endswith("aol.com") and not acc.endswith("ctir.gov.br"):
                    accounts.append(acc)
        return accounts

    def _extract_client_ticket(self) -> str:
        m = re.search(r"supporttickets\.php\?[^\s]*id=(\d+)", self.raw_text)
        if m:
            return m.group(1)
        return ""

    def _extract_brief_summary(self, messages: List[Dict[str, str]]) -> str:
        for msg in messages:
            if msg["type"] == "Mensaje público":
                body = msg["body"]
                # Clean up lines
                lines = [l.strip() for l in body.splitlines() if l.strip()]
                # If PhishFort
                if "reporting no substantiated abuse" in body or "Don Julio" in body:
                    return "Reporte de marca PhishFort sobre campaña Don Julio / Diageo en sitio web."
                # If BrutalRx
                if "esteroides anabólicos" in body or "COFEPRIS" in body:
                    return "Venta de catálogo de esteroides anabólicos y prescripción médica sin receta (COFEPRIS)."
                # If dating spam / outbound spam
                if "Getting attention - by women" in body or "dating site" in body:
                    return "Envío de correo no deseado (spam de citas) desde cuenta autenticada vulnerada."
                # If CTIR Gov phishing
                if "CTIR Gov" in body or "phishing mess" in body:
                    return "Notificación TLP:AMBER de CTIR Gov BR por envíos de phishing desde cuenta de correo."
                # Fallback to first 2 informative lines
                meaningful = [l for l in lines if not l.startswith("Ticket") and not l.startswith("TIPIFICACIÓN") and len(l) > 20]
                if meaningful:
                    return meaningful[0][:150] + ("..." if len(meaningful[0]) > 150 else "")
        return "Reporte de abuso recibido para investigación."

    def _is_infra_domain(self, d: str) -> bool:
        infra = [
            "neubox.com", "neubox.net", "serverneubox.com.mx",
            "nlab.mx", "hospedando.com.mx", "comcast.net",
            "aol.com", "gov.br", "ctir.gov.br", "squarespace.com",
            "google.com", "letsencrypt.org", "first.org", "globalsign.com"
        ]
        return any(d == x or d.endswith("." + x) for x in infra)
