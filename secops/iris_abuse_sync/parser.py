import io
import re
import html
import email
from email import policy
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


def _html_to_PlainText(html_str: str) -> str:
    """Converts HTML email body to readable plain text while keeping links."""
    if not html_str:
        return ""
    # Remove style and script blocks
    cleaned = re.sub(r'<(script|style)[^>]*>[\s\S]*?</\1>', ' ', html_str, flags=re.IGNORECASE)
    # Preserve href links if they look like http/https URLs
    def _replace_anchor(match):
        href = match.group(1).strip()
        inner = re.sub(r'<[^>]+>', '', match.group(2)).strip()
        if href.startswith(("http://", "https://")) and href not in inner:
            return f"{inner} ({href})" if inner else href
        return inner
    cleaned = re.sub(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>([\s\S]*?)</a>', _replace_anchor, cleaned, flags=re.IGNORECASE)
    # Replace block tags with newlines
    cleaned = re.sub(r'</?(br|p|div|tr|li|h[1-6]|blockquote|pre)[^>]*>', '\n', cleaned, flags=re.IGNORECASE)
    # Strip remaining HTML tags
    cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
    cleaned = html.unescape(cleaned)
    # Normalize whitespace per line
    lines = [re.sub(r'[ \t]+', ' ', ln).strip() for ln in cleaned.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def extract_text_from_eml(eml_source: Any) -> str:
    """
    Extracts headers, metadata, plain/HTML body, and nested attachments from a .eml file or bytes.
    """
    if isinstance(eml_source, Path):
        raw_bytes = eml_source.read_bytes()
    elif isinstance(eml_source, str):
        p = Path(eml_source)
        if p.exists() and p.is_file():
            raw_bytes = p.read_bytes()
        else:
            raw_bytes = eml_source.encode("utf-8", errors="ignore")
    elif isinstance(eml_source, bytes):
        raw_bytes = eml_source
    else:
        raw_bytes = eml_source.read()
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8", errors="ignore")

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sections: List[str] = []

    # 1. Key metadata summary at top
    from_hdr = str(msg.get("From", "")).strip()
    to_hdr = str(msg.get("To", "")).strip()
    subject_hdr = str(msg.get("Subject", "")).strip()
    date_hdr = str(msg.get("Date", "")).strip()
    msgid_hdr = str(msg.get("Message-ID", "")).strip()

    meta_lines = []
    if subject_hdr:
        meta_lines.append(f"Subject: {subject_hdr}")
    if from_hdr:
        meta_lines.append(f"From: {from_hdr}")
    if to_hdr:
        meta_lines.append(f"To: {to_hdr}")
    if date_hdr:
        meta_lines.append(f"Date: {date_hdr}")
    if msgid_hdr:
        meta_lines.append(f"Message-ID: {msgid_hdr}")
    if meta_lines:
        sections.append("\n".join(meta_lines))

    # 2. Collect full security/routing headers for Note 02 evidence & auth account detection
    interesting_headers = [
        "Return-Path", "Received", "Authentication-Results", "Received-SPF",
        "DKIM-Signature", "X-Authenticated-Id", "X-Originating-IP",
        "X-Sender-IP", "X-PHP-Originating-Script", "X-Spam-Status",
        "X-CMAE-Envelope", "From", "To", "Subject", "Date", "Message-ID", "Reply-To"
    ]
    header_dump = ["Header info:"]
    for k, v in msg.items():
        if any(k.lower() == ih.lower() for ih in interesting_headers) or k.lower().startswith("x-"):
            header_dump.append(f"{k}: {str(v).strip()}")
    if len(header_dump) > 1:
        sections.append("\n".join(header_dump))

    # 3. Walk parts to extract plain text, HTML fallback, and nested messages/PDFs
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachment_parts: List[str] = []

    def _walk_message(m_obj):
        if m_obj.is_multipart():
            for part in m_obj.iter_parts():
                ctype = part.get_content_type()
                disp = str(part.get_content_disposition() or "")
                fname = part.get_filename() or ""

                if ctype == "message/rfc822":
                    try:
                        payload_msg = part.get_payload(0)
                        if payload_msg:
                            nested_bytes = payload_msg.as_bytes()
                            attachment_parts.append(f"--- Correo Reenviado Adjunto ({fname or 'message.eml'}) ---\n" + extract_text_from_eml(nested_bytes))
                    except Exception:
                        pass
                elif fname.lower().endswith(".pdf") or ctype == "application/pdf":
                    try:
                        pdf_bytes = part.get_payload(decode=True)
                        if pdf_bytes:
                            attachment_parts.append(f"--- Adjunto PDF ({fname}) ---\n" + extract_text_from_pdf(pdf_bytes))
                    except Exception:
                        pass
                elif ctype == "text/plain" and "attachment" not in disp:
                    try:
                        plain_parts.append(part.get_content())
                    except Exception:
                        raw_p = part.get_payload(decode=True)
                        if raw_p:
                            plain_parts.append(raw_p.decode("utf-8", errors="ignore"))
                elif ctype == "text/html" and "attachment" not in disp:
                    try:
                        html_parts.append(part.get_content())
                    except Exception:
                        raw_h = part.get_payload(decode=True)
                        if raw_h:
                            html_parts.append(raw_h.decode("utf-8", errors="ignore"))
                elif ctype.startswith("text/") or fname.lower().endswith((".txt", ".log", ".csv", ".json")):
                    try:
                        raw_t = part.get_payload(decode=True)
                        if raw_t:
                            attachment_parts.append(f"--- Adjunto ({fname}) ---\n" + raw_t.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                elif part.is_multipart():
                    _walk_message(part)
        else:
            ctype = m_obj.get_content_type()
            try:
                content_str = m_obj.get_content()
            except Exception:
                raw_b = m_obj.get_payload(decode=True)
                content_str = raw_b.decode("utf-8", errors="ignore") if raw_b else ""

            if ctype == "text/html":
                html_parts.append(content_str)
            else:
                plain_parts.append(content_str)

    _walk_message(msg)

    body_text = "\n\n".join(p.strip() for p in plain_parts if p and p.strip())
    if html_parts:
        html_converted = "\n\n".join(_html_to_PlainText(h) for h in html_parts if h and h.strip())
        if not body_text:
            body_text = html_converted
        else:
            # Also include any URLs from HTML that were not in plain text
            html_urls = re.findall(r"https?://[^\s<>\"',;)]+", html_converted)
            missing_urls = [u for u in html_urls if u not in body_text]
            if missing_urls:
                body_text += "\n\nEnlaces adicionales en cuerpo HTML:\n" + "\n".join(missing_urls)

    if body_text:
        sections.append("Cuerpo del mensaje:\n" + body_text)

    if attachment_parts:
        sections.append("\n\n".join(attachment_parts))

    return "\n\n".join(sections).strip()


def extract_text_from_any(source: Any, filename: str = "") -> str:
    """
    Unified text extractor supporting .pdf, .eml, and plain text / raw pasted content.
    """
    fname_lower = (filename or "").lower()
    if fname_lower.endswith(".pdf"):
        return extract_text_from_pdf(source)
    if fname_lower.endswith(".eml"):
        return extract_text_from_eml(source)

    # Read as text first
    if isinstance(source, Path):
        raw_bytes = source.read_bytes()
    elif isinstance(source, bytes):
        raw_bytes = source
    elif isinstance(source, str):
        raw_bytes = source.encode("utf-8", errors="ignore")
    else:
        raw_bytes = source.read()
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8", errors="ignore")

    text = raw_bytes.decode("utf-8", errors="ignore")

    # Detect if raw pasted text or .txt is actually a raw RFC822 .eml message with MIME parts
    if re.search(r"^(?:Return-Path|Received|MIME-Version|Content-Type):\s+", text, re.IGNORECASE | re.MULTILINE) and (
        "Content-Transfer-Encoding:" in text or "multipart/" in text
    ):
        try:
            eml_extracted = extract_text_from_eml(raw_bytes)
            if eml_extracted.strip():
                return eml_extracted
        except Exception:
            pass

    return text


class TicketParser:
    """
    Intelligent parser for Neubox Helpdesk ticket exports, PDFs, .EML emails,
    and free-form pasted abuse reports/messages.
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
        domains = self._extract_domains(reporter_info.get("email", ""))
        urls = self._extract_urls()
        ips = self._extract_ips()
        neubox_servers = self._extract_neubox_servers()
        auth_accounts = self._extract_auth_accounts(reporter_info.get("email", ""))
        client_ticket = self._extract_client_ticket()
        client_id = self._extract_field(r"Client\s*ID\s*:\s*([^\n\r]+)")
        service_id = self._extract_field(r"Service\s*ID\s*:\s*([^\n\r]+)")
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
            "client_id": client_id,
            "service_id": service_id,
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
        # Match Ticket 789034 or Ticket #789034 or [Ticket#...]
        patterns = [
            r"Ticket\s*(?:de\s*abuso)?\s*[:#-]?\s*(\d{5,9})",
            r"ticket/zoom/(\d{5,9})",
            r"\[Ticket#?(\d{5,12})\]",
            r"(?:NBX|HP)-(\d{5,9})"
        ]
        for p in patterns:
            m = re.search(p, self.raw_text, re.IGNORECASE)
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
        Pattern matches: Author — [—] Date/Time — Mensaje público / Nota interna
        """
        pattern = r"([^\n—]+?)\s*—(?:\s*—)?\s*([\d/]+,?\s*[\d:]+\s*(?:am|pm|AM|PM)?)\s*—\s*(Mensaje público|Nota interna)"
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
        """Extracts email header block if present in the ticket or .eml."""
        m = re.search(
            r"(?:Header info:|Return-Path:)[\s\S]*?(?:DKIM-Signature|X-Authenticated-Id|X-CMAE-Envelope|Message-ID:[^\n]+)[\s\S]*?(?=\n\n(?:Cuerpo del mensaje:|From:|Sent:|Subject:)|$)",
            self.raw_text
        )
        if m:
            return m.group(0).strip()[:4000]
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
                self._enrich_org_from_text(info, author + "\n" + body)
                break

        # Fallback for .EML files or pasted emails / messages without Zammad markers
        if not info["name"]:
            # Try From: / Reportante: / De:
            m_from = re.search(r"^(?:From|De|Reportante|Reporter|Reported by)\s*:\s*([^\r\n]+)", self.raw_text, re.IGNORECASE | re.MULTILINE)
            if m_from:
                from_val = m_from.group(1).strip()
                info["name"] = from_val
                email_m = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", from_val)
                if email_m:
                    info["email"] = email_m.group(1)

            m_date = re.search(r"^(?:Date|Fecha|Sent|Enviado)\s*:\s*([^\r\n]+)", self.raw_text, re.IGNORECASE | re.MULTILINE)
            if m_date:
                info["date"] = m_date.group(1).strip()

            self._enrich_org_from_text(info, self.raw_text)

        return info

    def _enrich_org_from_text(self, info: Dict[str, str], text_block: str):
        if "PhishFort" in text_block:
            info["org"] = "PhishFort Threat Resolution"
            if not info["name"]:
                info["name"] = "PhishFort Takedowns"
        elif "Netcraft" in text_block or "netcraft.com" in text_block.lower():
            info["org"] = "Netcraft Takedown Service"
            if not info["name"]:
                info["name"] = "Netcraft"
        elif "BrutalRx" in text_block:
            info["org"] = "BrutalRx"
            m_sign = re.search(r"Saludos,\s*\n+([^\n]+)", text_block)
            if m_sign:
                info["name"] = m_sign.group(1).strip()
        elif "CTIR Gov" in text_block or "cert.br" in text_block or "ctir.gov.br" in text_block:
            info["org"] = "CTIR Gov BR Team (Cyber Incident Prevention, Handling and Response Center)"
            if not info["name"]:
                info["name"] = "CTIR Gov BR Team <ctir@ctir.gov.br>"
            if not info["email"]:
                info["email"] = "ctir@ctir.gov.br"
        elif "SpamCop" in text_block or "spamcop.net" in text_block.lower():
            info["org"] = "SpamCop Abuse Service"
            if not info["name"]:
                info["name"] = "SpamCop"
        elif "AbuseIPDB" in text_block:
            info["org"] = "AbuseIPDB"
            if not info["name"]:
                info["name"] = "AbuseIPDB Reporter"
        elif "Rachel Green" in text_block:
            info["name"] = "Rachel Green (Reportado vía abuso)"

    def _extract_domains(self, reporter_email: str = "") -> List[str]:
        domains = []
        text = self.clean_text
        reporter_domain = reporter_email.split("@", 1)[1].lower() if "@" in (reporter_email or "") else ""

        def _add_candidate(d_raw: str):
            d = d_raw.lower().strip().rstrip(".,;:)'\"]>")
            d = re.sub(r"^https?://", "", d)
            d = d.split("/")[0].split(":")[0]
            if d.startswith("www."):
                d = d[4:]
            if not d or "." not in d or len(d) < 4:
                return
            if self._is_infra_domain(d):
                return
            if reporter_domain and d == reporter_domain:
                return
            if d not in domains:
                domains.append(d)

        # 1. Look for Bastion DOMAIN field or explicit labels
        label_patterns = [
            r"DOMAIN\s*:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"(?:Dominio|Domain|Host|Hostname|Activo|Sitio\s+web|Target)\s*(?:reportado|afectado)?\s*[:=-]\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        ]
        for lp in label_patterns:
            for m in re.finditer(lp, text, re.IGNORECASE):
                _add_candidate(m.group(1))

        # 2. Look for reported domain in abuse body / URLs
        patterns = [
            r"suspend\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"sitio\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"concerning\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        ]
        for p in patterns:
            for m in re.finditer(p, text, re.IGNORECASE):
                _add_candidate(m.group(1))

        # 3. Check for domains in authenticated email accounts
        auths = self._extract_auth_accounts(reporter_email)
        for a in auths:
            if "@" in a:
                _add_candidate(a.split("@", 1)[1])

        # 4. General standalone domain mentions in free-form text/emails if none found yet (or in body)
        body_part = text.split("Cuerpo del mensaje:")[-1] if "Cuerpo del mensaje:" in text else text
        tld_regex = (
            r"(?<![@a-zA-Z0-9.-])\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\."
            r"(?:com\.mx|gob\.mx|org\.mx|net\.mx|edu\.mx|mx|com|net|org|info|biz|xyz|online|site|store|shop|club|top|vip|io|co|ai|app|dev|tech|me|tv|cc|br|es|lat))\b"
        )
        for m in re.finditer(tld_regex, body_part, re.IGNORECASE):
            cand = m.group(1).lower()
            # Skip common file extensions mistaken for domains
            if cand.endswith((".php", ".html", ".htm", ".txt", ".pdf", ".png", ".jpg", ".js", ".css", ".eml")):
                continue
            _add_candidate(cand)

        return domains

    def _extract_urls(self) -> List[str]:
        urls = []
        # Match http/https URLs
        matches = re.findall(r"https?://[^\s<>\"',;)]+", self.clean_text)
        for u in matches:
            u_clean = u.rstrip(".,;)>'\"")
            # Exclude helpdesk, nlab shot, hospedando, etc.
            if not any(x in u_clean for x in [
                "helpdesk.neubox.com", "shots.nlab.mx", "neubox.com/Soporte",
                "domains2.squarespace.com", "gov.br/ctir", "w3.org", "schemas.microsoft.com"
            ]):
                if u_clean not in urls:
                    urls.append(u_clean)
        return urls

    def _extract_ips(self) -> List[str]:
        ips = []
        # Explicit IP mentions
        for m in re.finditer(r"(?:IP(?:\s+reportada|\s+address)?\s*[:=-]?|A Record\s*:\s*|X-Originating-IP:\s*\[?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", self.clean_text, re.IGNORECASE):
            ip = m.group(1)
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)

        # General IP matches
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", self.clean_text):
            ip = m.group(1)
            parts = [int(p) for p in ip.split(".")]
            if all(0 <= p <= 255 for p in parts) and parts[0] not in (0, 10, 127) and ip not in ips:
                ips.append(ip)

        return ips

    def _extract_neubox_servers(self) -> List[str]:
        servers = []
        for m in re.finditer(r"\b((?:svgp|svgs|svds|svdh|svde|pmg|vps|ded)\d+[a-z0-9.-]*\.(?:serverneubox\.com\.mx|neubox\.net))\b", self.clean_text, re.IGNORECASE):
            s = m.group(1).lower()
            if s not in servers:
                servers.append(s)
        # Also allow shorthand like svgp261 if preceded by Servidor: or Server:
        for m in re.finditer(r"(?:Servidor|Server)\s*[:=-]\s*(?:cPanel\s+WebHost\s*/\s*)?((?:svgp|svgs|svds|svdh|svde|pmg)\d+(?:\.(?:serverneubox\.com\.mx|neubox\.net))?)", self.clean_text, re.IGNORECASE):
            s = m.group(1).lower()
            if s not in servers:
                servers.append(s)
        return servers

    def _extract_auth_accounts(self, reporter_email: str = "") -> List[str]:
        accounts = []
        patterns = [
            r"X-Authenticated-Id:\s*([^\s\r\n]+)",
            r"Phishing sender:\s*([^\s\r\n]+)",
            r"(?:Cuenta|Account|Remitente|Sender|Usuario)\s*(?:autenticada|comprometida|vulnerada)?\s*[:=-]\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"(?:from|de)\s+(?:Rachel Green|remitente)\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"envelope-from\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>",
            r"Return-Path:\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?"
        ]
        ignore_Endings = (
            "comcast.net", "aol.com", "ctir.gov.br", "neubox.com",
            "hospedando.com.mx", "phishfort.com", "netcraft.com", "spamcop.net"
        )
        for p in patterns:
            for m in re.finditer(p, self.clean_text, re.IGNORECASE):
                acc = m.group(1).strip().strip("<>\"'")
                if (
                    "@" in acc
                    and acc not in accounts
                    and acc.lower() != (reporter_email or "").lower()
                    and not any(acc.lower().endswith(ext) for ext in ignore_Endings)
                ):
                    accounts.append(acc)
        return accounts

    def _extract_client_ticket(self) -> str:
        m = re.search(r"supporttickets\.php\?[^\s]*id=(\d+)", self.raw_text)
        if m:
            return m.group(1)
        m2 = re.search(r"Ticket\s+(?:del\s+)?titular\s*[:#-]?\s*(\d{4,9})", self.raw_text, re.IGNORECASE)
        if m2:
            return m2.group(1)
        return ""

    def _extract_brief_summary(self, messages: List[Dict[str, str]]) -> str:
        # Check messages first if Zammad/Helpdesk format
        bodies_to_check = [msg["body"] for msg in messages if msg["type"] == "Mensaje público"]
        if not bodies_to_check:
            # For .eml or pasted free-form text
            if "Cuerpo del mensaje:" in self.raw_text:
                bodies_to_check.append(self.raw_text.split("Cuerpo del mensaje:", 1)[1])
            else:
                bodies_to_check.append(self.raw_text)

        # Check explicit Subject header if present in .eml or pasted email
        m_subj = re.search(r"^(?:Subject|Asunto)\s*:\s*([^\r\n]+)", self.raw_text, re.IGNORECASE | re.MULTILINE)
        subject_line = m_subj.group(1).strip() if m_subj else ""

        for body in bodies_to_check:
            if "reporting no substantiated abuse" in body or "Don Julio" in body:
                return "Reporte de marca PhishFort sobre campaña Don Julio / Diageo en sitio web."
            if "esteroides anabólicos" in body or "COFEPRIS" in body:
                return "Venta de catálogo de esteroides anabólicos y prescripción médica sin receta (COFEPRIS)."
            if "Getting attention - by women" in body or "dating site" in body:
                return "Envío de correo no deseado (spam de citas) desde cuenta autenticada vulnerada."
            if "CTIR Gov" in body or "phishing mess" in body:
                return "Notificación TLP:AMBER de CTIR Gov BR por envíos de phishing desde cuenta de correo."

            if subject_line and len(subject_line) > 8:
                return subject_line[:160]

            # Fallback to first meaningful line skipping raw email headers and Zammad UI fields
            header_prefixes = (
                "ticket", "tipificación", "tipo ", "group ", "owner ", "state ",
                "pending till", "priority ", "header info:", "return-path:", "received:",
                "from:", "to:", "date:", "message-id:", "mime-version:", "content-type:",
                "dkim-signature:", "authentication-results:", "received-spf:", "x-",
                "estimado", "hola", "buen día", "buenas tardes", "dear ", "hello"
            )
            lines = [l.strip() for l in body.splitlines() if l.strip()]
            meaningful = [
                l for l in lines
                if len(l) > 25 and not any(l.lower().startswith(hp) for hp in header_prefixes)
            ]
            if meaningful:
                return meaningful[0][:160] + ("..." if len(meaningful[0]) > 160 else "")

        if subject_line:
            return subject_line[:160]
        return "Reporte de abuso recibido para investigación."

    def _is_infra_domain(self, d: str) -> bool:
        infra = [
            "neubox.com", "neubox.net", "serverneubox.com.mx",
            "nlab.mx", "hospedando.com.mx", "comcast.net",
            "aol.com", "gov.br", "ctir.gov.br", "squarespace.com",
            "google.com", "gmail.com", "outlook.com", "hotmail.com",
            "yahoo.com", "protonmail.com", "icloud.com", "live.com",
            "letsencrypt.org", "first.org", "globalsign.com",
            "phishfort.com", "netcraft.com", "spamcop.net", "abuseipdb.com",
            "cloudflare.com", "w3.org", "microsoft.com"
        ]
        return any(d == x or d.endswith("." + x) for x in infra)
