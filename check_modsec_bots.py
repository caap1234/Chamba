#!/usr/bin/env python3
"""
check_modsec_bots.py
--------------------
Busca y reporta transacciones en el log de ModSecurity (modsec_audit.log)
realizadas por IPs pertenecientes a bots de Inteligencia Artificial y motores
de búsqueda conocidos (OpenAI, Anthropic, Perplexity, Googlebot, Bingbot, Meta, etc.).

Uso:
  python3 check_modsec_bots.py <dominio> [ticket] [opciones]
  python3 check_modsec_bots.py --all [opciones]

Ejemplos:
  python3 check_modsec_bots.py kivae.com.mx 31705330
  python3 check_modsec_bots.py kivae.com.mx --bot Anthropic
  python3 check_modsec_bots.py --all --logfile /var/log/modsec_audit.log
"""

import argparse
import bisect
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime

DEFAULT_LOGFILE = "/usr/local/apache/logs/modsec_audit.log"

SOURCES = {
    "Googlebot": {
        "type": "json",
        "url": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    },
    "FacebookMeta": {
        "type": "static",
        "ranges": [
            "31.13.24.0/21", "31.13.64.0/18", "45.64.40.0/22", "57.144.0.0/14",
            "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19", "74.119.76.0/22",
            "102.132.96.0/20", "103.4.96.0/22", "129.134.0.0/17", "157.240.0.0/17",
            "157.240.192.0/18", "163.70.128.0/17", "173.252.64.0/18", "179.60.192.0/22",
            "185.60.216.0/22", "185.89.216.0/22", "204.15.20.0/22",
        ],
    },
    "Bingbot": {
        "type": "json",
        "url": "https://www.bing.com/toolbox/bingbot.json",
    },
    "PerplexityBot": {
        "type": "json",
        "url": "https://www.perplexity.com/perplexitybot.json",
    },
    "GPTBot": {
        "type": "json",
        "url": "https://openai.com/gptbot.json",
        "static_fallback": ["20.15.240.64/28", "20.15.240.80/28", "20.171.206.0/24"],
    },
    "ChatGPT-User": {
        "type": "json",
        "url": "https://openai.com/chatgpt-user.json",
        "static_fallback": ["20.15.240.96/28"],
    },
    "OAI-SearchBot": {
        "type": "json",
        "url": "https://openai.com/searchbot.json",
        "static_fallback": ["20.15.240.112/28"],
    },
    "Anthropic": {
        "type": "static",
        "ranges": [
            "160.79.104.0/23",
            "160.79.104.0/21",
        ],
    },
    "Cloudflare": {
        "type": "text",
        "url": "https://www.cloudflare.com/ips-v4/",
    },
}

ALL_BOTS = list(SOURCES.keys())

BOT_USER_AGENTS = {
    "GPTBot": re.compile(r"GPTBot", re.IGNORECASE),
    "ChatGPT-User": re.compile(r"ChatGPT-User", re.IGNORECASE),
    "OAI-SearchBot": re.compile(r"OAI-SearchBot", re.IGNORECASE),
    "Anthropic": re.compile(r"(ClaudeBot|Claude-Web|anthropic-ai)", re.IGNORECASE),
    "PerplexityBot": re.compile(r"PerplexityBot", re.IGNORECASE),
    "Googlebot": re.compile(r"(Googlebot|Google-Extended)", re.IGNORECASE),
    "Bingbot": re.compile(r"bingbot", re.IGNORECASE),
    "FacebookMeta": re.compile(r"(FacebookBot|meta-externalagent)", re.IGNORECASE),
    "Bytespider": re.compile(r"Bytespider", re.IGNORECASE),
    "CCBot": re.compile(r"CCBot", re.IGNORECASE),
}


def match_user_agent(ua_str):
    if not ua_str:
        return None
    for bot_name, pattern in BOT_USER_AGENTS.items():
        if pattern.search(ua_str):
            return bot_name
    return None


def download_json(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def download_text(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.read().decode("utf-8")


def load_bot_ranges(bot_name):
    source = SOURCES[bot_name]
    ranges = []

    if source["type"] == "static":
        for cidr in source["ranges"]:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                ranges.append(network)
            except ValueError:
                pass
        return ranges

    if source["type"] == "text":
        try:
            data = download_text(source["url"])
            for cidr in data.splitlines():
                cidr = cidr.strip()
                if cidr:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        ranges.append(network)
                    except ValueError:
                        pass
            return ranges
        except Exception:
            return []

    if source["type"] == "json":
        try:
            data = download_json(source["url"])
            prefixes = data.get("prefixes", [])
            for prefix in prefixes:
                cidr = prefix.get("ipv4Prefix") or prefix.get("prefix")
                if cidr:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        ranges.append(network)
                    except ValueError:
                        pass
        except Exception:
            if "static_fallback" in source:
                for cidr in source["static_fallback"]:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        ranges.append(network)
                    except ValueError:
                        pass

    return ranges


class BotLookup:
    def __init__(self, selected_bots=None):
        self.intervals_v4 = []
        self.starts_v4 = []
        self.intervals_v6 = []
        self.starts_v6 = []

        bots_to_load = ALL_BOTS
        if selected_bots:
            terms = [b.strip().lower() for b in selected_bots if b.strip()]
            matched_bots = [
                s_name for s_name in SOURCES
                if any(t in s_name.lower() for t in terms)
            ]
            if matched_bots:
                bots_to_load = matched_bots

        v4_temp = []
        v6_temp = []

        for bot_name in bots_to_load:
            if bot_name not in SOURCES:
                continue
            ranges = load_bot_ranges(bot_name)
            for network in ranges:
                start = int(network.network_address)
                end = int(network.broadcast_address)
                cidr_str = str(network)
                if network.version == 4:
                    v4_temp.append((start, end, bot_name, cidr_str))
                elif network.version == 6:
                    v6_temp.append((start, end, bot_name, cidr_str))

        v4_temp.sort(key=lambda x: x[0])
        v6_temp.sort(key=lambda x: x[0])

        self.intervals_v4 = v4_temp
        self.starts_v4 = [item[0] for item in v4_temp]
        self.intervals_v6 = v6_temp
        self.starts_v6 = [item[0] for item in v6_temp]

    def match(self, ip_str):
        if not ip_str:
            return None
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        ip_int = int(addr)
        if addr.version == 4:
            intervals = self.intervals_v4
            starts = self.starts_v4
        else:
            intervals = self.intervals_v6
            starts = self.starts_v6

        if not intervals:
            return None

        pos = bisect.bisect_right(starts, ip_int)
        i = pos - 1
        while i >= 0:
            start, end, bot_name, cidr_str = intervals[i]
            if end < ip_int:
                break
            if start <= ip_int <= end:
                return bot_name, cidr_str
            i -= 1

        return None


def normalize_host(host_str):
    if not host_str:
        return ""
    host = host_str.strip().lower()
    if ":" in host:
        host = host.split(":")[0]
    return host.rstrip(".")


def get_endpoint(uri):
    if not uri:
        return "/"
    endpoint = uri.split("?")[0]
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return endpoint


def regex_escape(val):
    return re.sub(r'([\[\]\(\)\{\}\.\^\$\*\+\?\\-])', r'\\\1', val)


def parse_modsec_audit_log(logfile, bot_lookup, target_domain=None, target_bot=None):

    if not os.path.exists(logfile):
        print(f"[ERROR] No existe el archivo de log: {logfile}")
        sys.exit(1)

    matches = []
    total_tx_parsed = 0

    tx_ip = ""
    tx_host = ""
    tx_method = ""
    tx_uri = ""
    tx_endpoint = ""
    tx_status = ""
    tx_ua = ""
    tx_messages = []

    in_a = in_b = in_f = in_h = False

    def flush_transaction():
        nonlocal total_tx_parsed, tx_ip, tx_host, tx_method, tx_uri, tx_endpoint, tx_status, tx_ua, tx_messages
        total_tx_parsed += 1

        if tx_ip or tx_ua:
            ip_match = bot_lookup.match(tx_ip) if tx_ip else None
            ua_bot = match_user_agent(tx_ua)

            bot_name = None
            cidr_str = "N/A"
            detection = "NONE"

            if ip_match and ua_bot:
                bot_name = ip_match[0]
                cidr_str = ip_match[1]
                detection = "IP+UA"
            elif ip_match:
                bot_name = ip_match[0]
                cidr_str = ip_match[1]
                detection = "IP_OFICIAL"
            elif ua_bot:
                bot_name = ua_bot
                cidr_str = "Desconocida (Sólo UA)"
                detection = "USER_AGENT"

            if bot_name:
                norm_host = normalize_host(tx_host)

                domain_matches = True
                if target_domain:
                    norm_target = normalize_host(target_domain)
                    domain_matches = (norm_host == norm_target or norm_host.endswith("." + norm_target))

                bot_matches = True
                if target_bot:
                    bot_terms = [b.strip().lower() for b in target_bot.split(",") if b.strip()]
                    bot_matches = any(t in bot_name.lower() for t in bot_terms)

                if domain_matches and bot_matches:
                    rules_to_report = tx_messages if tx_messages else [("-", "-", "-")]
                    for rule_id, severity, msg_desc in rules_to_report:
                        matches.append({
                            "bot": bot_name,
                            "detection": detection,
                            "range": cidr_str,
                            "ip": tx_ip,
                            "user_agent": tx_ua or "-",
                            "host": norm_host or "desconocido",
                            "method": tx_method or "-",
                            "uri": tx_uri or "-",
                            "endpoint": tx_endpoint or "/",
                            "status": tx_status or "-",
                            "rule_id": rule_id,
                            "severity": severity,
                            "rule_msg": msg_desc,
                        })

        tx_ip = ""
        tx_host = ""
        tx_method = ""
        tx_uri = ""
        tx_endpoint = ""
        tx_status = ""
        tx_ua = ""
        tx_messages = []

    header_pattern = re.compile(r'^--[0-9a-fA-F]+-([A-Z])--$')

    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = header_pattern.match(line.strip())
            if m:
                sec = m.group(1)
                if sec == 'A':
                    if tx_ip or tx_host or tx_method or tx_status or tx_ua or tx_messages:
                        flush_transaction()
                    in_a, in_b, in_f, in_h = True, False, False, False
                elif sec == 'Z':
                    flush_transaction()
                    in_a, in_b, in_f, in_h = False, False, False, False
                else:
                    in_a = (sec == 'A')
                    in_b = (sec == 'B')
                    in_f = (sec == 'F')
                    in_h = (sec == 'H')
                continue

            if in_a and not tx_ip:
                parts = line.strip().split()
                if len(parts) >= 4:
                    tx_ip = parts[3]

            elif in_b:
                clean_line = line.rstrip("\r\n")
                if not tx_method:
                    req_parts = clean_line.split()
                    if len(req_parts) >= 3 and req_parts[0].isupper() and req_parts[-1].startswith("HTTP/"):
                        tx_method = req_parts[0]
                        tx_uri = req_parts[1]
                        tx_endpoint = get_endpoint(tx_uri)
                if clean_line.lower().startswith("host:"):
                    raw_host = clean_line.split(":", 1)[1]
                    tx_host = normalize_host(raw_host)
                if clean_line.lower().startswith("user-agent:"):
                    tx_ua = clean_line.split(":", 1)[1].strip()

            elif in_f and not tx_status:
                clean_line = line.rstrip("\r\n")
                resp_parts = clean_line.split()
                if len(resp_parts) >= 2 and resp_parts[0].startswith("HTTP/"):
                    tx_status = resp_parts[1]

            elif in_h:
                if line.startswith("Message:"):
                    rule_id = "-"
                    severity = "-"
                    msg_desc = "-"
                    m_id = re.search(r'\[id "([^"]+)"\]', line)
                    if m_id:
                        rule_id = m_id.group(1)
                    m_sev = re.search(r'\[severity "([^"]+)"\]', line)
                    if m_sev:
                        severity = m_sev.group(1)
                    m_msg = re.search(r'\[msg "([^"]+)"\]', line)
                    if m_msg:
                        msg_desc = m_msg.group(1)
                    else:
                        clean_msg = re.sub(r'\[.*?\]', '', line).replace("Message:", "").strip()
                        if clean_msg:
                            msg_desc = clean_msg[:70]
                    tx_messages.append((rule_id, severity, msg_desc))

        if tx_ip or tx_host or tx_method or tx_status or tx_messages:
            flush_transaction()

    return matches, total_tx_parsed


def print_and_format_report(matches, target_domain, logfile, total_tx_parsed, ticket="0000000"):
    lines = []

    def out(text=""):
        print(text)
        lines.append(text)

    domain_label = target_domain if target_domain else "TODOS LOS DOMINIOS"
    out(f"=== REPORTE DE BOTS EN MODSECURITY ===")
    out(f"Dominio analizado:        {domain_label}")
    out(f"Archivo de log:           {logfile}")
    out(f"Transacciones procesadas: {total_tx_parsed}")
    out(f"Coincidencias de Bots:   {len(matches)}")
    out("")

    if not matches:
        out("No se encontraron peticiones/bloqueos de bots en el log.")
        return "\n".join(lines)

    combo_counts = defaultdict(int)
    endpoint_rules = defaultdict(set)
    endpoint_seen = set()

    for m in matches:
        key = (m["endpoint"], m["bot"], m["ip"], m["detection"], m["rule_id"], m["severity"], m["status"])
        combo_counts[key] += 1
        if m["rule_id"] != "-":
            endpoint_rules[m["endpoint"]].add(m["rule_id"])
        endpoint_seen.add(m["endpoint"])

    out(f"{'Endpoint':<45} {'Bot':<15} {'IP':<16} {'Detección':<12} {'Rule ID':<10} {'Severity':<10} {'Status':<8} {'Veces':<6}")
    out("-" * 126)

    sorted_combos = sorted(combo_counts.items(), key=lambda x: (x[0][0], x[0][1], x[0][2]))
    for (ep, bot, ip, det, rid, sev, stat), cnt in sorted_combos:
        ep_disp = ep if len(ep) <= 45 else ep[:42] + "..."
        out(f"{ep_disp:<45} {bot:<15} {ip:<16} {det:<12} {rid:<10} {sev:<10} {stat:<8} {cnt:<6}")

    out("")

    bot_counts = defaultdict(int)
    bot_ips = defaultdict(set)
    for m in matches:
        bot_counts[m["bot"]] += 1
        bot_ips[m["bot"]].add(m["ip"])

    out("Total por Bot:")
    out(f"{'Bot':<20} {'Peticiones':<12} {'IPs Únicas':<10}")
    out("-" * 44)
    for b_name, b_cnt in sorted(bot_counts.items(), key=lambda x: x[1], reverse=True):
        out(f"{b_name:<20} {b_cnt:<12} {len(bot_ips[b_name]):<10}")

    out("")

    rule_counts = defaultdict(int)
    rule_descs = {}
    for m in matches:
        r_id = m["rule_id"]
        rule_counts[r_id] += 1
        r_msg = m.get("rule_msg", "-")
        if r_id not in rule_descs or (rule_descs[r_id] == "-" and r_msg != "-"):
            rule_descs[r_id] = r_msg

    out("Total por Regla ModSecurity:")
    out(f"{'Rule ID':<12} {'Veces':<8} {'Descripción de la Regla'}")
    out("-" * 80)
    for r_id, r_cnt in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
        r_msg = rule_descs.get(r_id, "-")
        out(f"{r_id:<12} {r_cnt:<8} {r_msg}")

    out("")

    out("Reglas sugeridas de deshabilitación (Excepciones ModSecurity):")

    dom_for_rule = target_domain if target_domain else "dominio.com"
    dom_rx = regex_escape(dom_for_rule)

    for ep in sorted(endpoint_seen):
        rules = sorted(list(endpoint_rules[ep]), key=lambda x: int(x) if x.isdigit() else 0)
        if not rules:
            continue
        ctl_str = ",".join([f"ctl:ruleRemoveById={r}" for r in rules])
        ep_rx = regex_escape(ep)

        out(f"# Excepción ModSecurity para bots en {dom_for_rule}")
        out(f"# ticket {ticket}")
        out(f'SecRule REQUEST_HEADERS:Host "@rx ^{dom_rx}(:[0-9]+)?$" "id:20000120,phase:1,nolog,pass,chain"')
        out(f'    SecRule REQUEST_URI "@rx ^{ep_rx}(\\?.*)?$" "t:none,{ctl_str}"')
        out("")

    return "\n".join(lines)


def export_txt(report_text):
    output_dir = "/var/www/html"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"coincidencias_modsec_bots_{timestamp}.txt"
    filepath = os.path.join(output_dir, filename)

    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)
        os.chmod(filepath, 0o644)
    except Exception as e:
        print(f"\n[ERROR] No se pudo exportar el reporte TXT: {e}")
        return None, None

    http_host = os.environ.get("SERVER_HTTP_HOST", "").strip()
    if not http_host:
        try:
            http_host = socket.gethostbyname(socket.gethostname())
        except Exception:
            http_host = ""

    if http_host and not http_host.startswith(("http://", "https://")):
        url = f"http://{http_host}/{filename}"
    elif http_host:
        url = f"{http_host.rstrip('/')}/{filename}"
    else:
        url = f"http://IP_DEL_SERVIDOR/{filename}"

    return filepath, url


def main():
    parser = argparse.ArgumentParser(
        description="Analiza el log de ModSecurity buscando bloqueos y peticiones de bots de IA y buscadores (OpenAI, Anthropic, Google, etc.)."
    )
    parser.add_argument("dominio", nargs="?", default=None, help="Dominio objetivo a filtrar (ej: kivae.com.mx)")
    parser.add_argument("ticket", nargs="?", default="0000000", help="Número de ticket para los comentarios de reglas sugeridas")
    parser.add_argument("--all", action="store_true", help="Analizar todos los dominios presentes en el log de ModSecurity")
    parser.add_argument("--bot", help="Filtrar por un bot específico (ej: Anthropic, GPTBot, Googlebot)")
    parser.add_argument("--logfile", default=DEFAULT_LOGFILE, help=f"Ruta al archivo de log de ModSecurity (defecto: {DEFAULT_LOGFILE})")
    parser.add_argument("--export", action="store_true", help="Exportar el resultado a un archivo TXT en /var/www/html (desactivado por defecto)")

    args = parser.parse_args()

    if not args.dominio and not args.all:
        parser.print_help()
        print("\n[ERROR] Debes especificar un dominio (ej: kivae.com.mx) o usar la opción --all")
        sys.exit(1)

    target_domain = None if args.all else args.dominio

    print("Cargando rangos de IPs de bots (OpenAI, Anthropic, Google, Bing, Perplexity, etc.)...")
    bot_list = [b.strip() for b in args.bot.split(",")] if args.bot else None
    bot_lookup = BotLookup(selected_bots=bot_list)

    print(f"Analizando log: {args.logfile} ...")
    matches, total_tx_parsed = parse_modsec_audit_log(
        args.logfile,
        bot_lookup,
        target_domain=target_domain,
        target_bot=args.bot
    )

    report_text = print_and_format_report(matches, target_domain, args.logfile, total_tx_parsed, ticket=args.ticket)

    if matches and args.export:
        filepath, url = export_txt(report_text)
        if filepath:
            print("-" * 60)
            print(f"Reporte exportado exitosamente:")
            print(f"  Archivo: {filepath}")
            print(f"  URL:     {url}")
            print("-" * 60)


if __name__ == "__main__":
    main()
