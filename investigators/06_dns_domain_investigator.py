#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
06. DNS & Domain Investigator
Plataformas: Multiplataforma (Linux, Windows Server, macOS)
Uso:
  python3 06_dns_domain_investigator.py
  python3 06_dns_domain_investigator.py --domain misitio.com
  python3 06_dns_domain_investigator.py --domain misitio.com --check-local-ip
  python3 06_dns_domain_investigator.py --domain misitio.com --resolvers 8.8.8.8,1.1.1.1

Resuelve registros A, AAAA, NS, MX, TXT (SPF/DMARC) y SOA.
Identifica IP de hosting, proveedor ASN/CDN (Cloudflare, etc.),
compara si el dominio apunta al servidor actual o es externo,
y analiza discrepancias de propagación entre resolvers.
Incluye sección de evidencia con líneas de resolución DNS crudas para Iris.
"""

import argparse
import datetime as dt
import io
import json
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.request

KNOWN_CDNS = {
    'cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '172.67.', '162.159.'],
    'sucuri': ['192.88.134.', '192.88.135.', '185.93.228.', '185.93.229.', '185.93.230.', '185.93.231.'],
    'akamai': ['23.', '104.'],
    'fastly': ['151.101.']
}


def get_local_server_ips():
    """Obtiene todas las IPs locales asociadas a las interfaces del servidor."""
    ips = set()
    try:
        hostname = socket.gethostname()
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        ips.update(host_ips)
    except Exception:
        pass

    # Intentar leer ip addr o ifconfig en Linux
    if platform.system() != 'Windows':
        try:
            res = subprocess.run(['ip', 'addr'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode == 0:
                for match in re.finditer(r'inet\s+([0-9.]+)/\d+', res.stdout):
                    ips.add(match.group(1))
        except Exception:
            pass
    return ips


def execute_dns_query(domain, qtype, server=None):
    """Ejecuta consulta DNS utilizando dig o nslookup nativo."""
    cmd = []
    is_windows = platform.system() == 'Windows'
    has_dig = False

    if not is_windows:
        try:
            check_dig = subprocess.run(['which', 'dig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            has_dig = (check_dig.returncode == 0)
        except Exception:
            has_dig = False

    if has_dig:
        cmd = ['dig', '+nocmd', '+noall', '+answer']
        if server:
            cmd.append('@' + server)
        cmd.extend([domain, qtype])
    else:
        cmd = ['nslookup', '-type=' + qtype, domain]
        if server:
            cmd.append(server)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        raw_output = proc.stdout.strip()
        return raw_output, cmd
    except Exception as e:
        return ("ERROR ejecutando DNS: %s" % e, cmd)


def query_ip_info(ip_addr):
    """Consulta información de ASN, ISP y País usando API ligera pública."""
    if not ip_addr or ip_addr.startswith('127.') or ip_addr.startswith('10.') or ip_addr.startswith('192.168.'):
        return {'isp': 'IP Privada / Local', 'org': 'Local', 'country': 'N/A'}
    try:
        url = "http://ip-api.com/json/%s?fields=status,country,isp,org,as,query" % ip_addr
        req = urllib.request.Request(url, headers={'User-Agent': 'Neubox-Abuse-Investigator/1.0'})
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('status') == 'success':
                return data
    except Exception:
        pass
    return {}


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/06_dns_domain_investigator.py) --domain misitio.com\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/06_dns_domain_investigator.py) --domain misitio.com --resolvers 8.8.8.8,1.1.1.1\n"
    )
    parser = argparse.ArgumentParser(
        description='06. DNS & Domain Investigator — Resolución Forense, MX, SPF, Hosting y Evidencia IRIS',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--domain', help='Nombre de dominio a auditar (ej. empresa.com)')
    parser.add_argument('--resolvers', default='8.8.8.8,1.1.1.1', help='Lista de resolvers DNS separados por coma')
    parser.add_argument('--output', help='Ruta para guardar el reporte')
    parser.add_argument('--interactive', action='store_true', help='Modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  06. DNS & Domain Investigator — Asistente de Inicio")
        print("=" * 70)
        print("Selecciona cómo deseas ejecutar:")
        print("  1) Asistente interactivo guiado (Ingresar dominio) [Recomendado]")
        print("  2) Ver ayuda completa y opciones de comando (--help)")
        opt = input("Opción [1-2, def: 1]: ").strip()
        if opt == '2':
            parser.print_help()
            sys.exit(0)
        else:
            sys.argv.append('--interactive')

    args = parser.parse_args()

    domain = args.domain
    if not domain:
        if sys.stdin.isatty():
            domain = input("Ingresa el dominio a investigar (ej. cliente.com): ").strip()
        else:
            print("[!] Debes especificar --domain", file=sys.stderr)
            sys.exit(1)

    domain = domain.lower().strip().rstrip('/')

    resolvers = [r.strip() for r in args.resolvers.split(',') if r.strip()]
    local_ips = get_local_server_ips()
    now = dt.datetime.now()

    # Tipos de registro a auditar
    qtypes = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA']
    dns_results = {}
    raw_evidence_lines = []

    # Consultar primer resolver
    primary_resolver = resolvers[0] if resolvers else None
    for qt in qtypes:
        out_text, cmd_used = execute_dns_query(domain, qt, server=primary_resolver)
        dns_results[qt] = out_text
        if out_text:
            raw_evidence_lines.append("# Consulta: %s" % " ".join(cmd_used))
            for l in out_text.splitlines():
                if l.strip():
                    raw_evidence_lines.append(l.strip())

    # También verificar TXT específico de DMARC (_dmarc.dominio)
    dmarc_out, dmarc_cmd = execute_dns_query('_dmarc.' + domain, 'TXT', server=primary_resolver)
    if dmarc_out:
        raw_evidence_lines.append("# Consulta DMARC: %s" % " ".join(dmarc_cmd))
        for l in dmarc_out.splitlines():
            if l.strip():
                raw_evidence_lines.append(l.strip())

    # Extraer IPs tipo A
    resolved_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', dns_results.get('A', ''))
    # Filtrar IPs que no sean el resolver
    hosting_ips = [ip for ip in resolved_ips if ip != primary_resolver]

    # Verificar si apunta a este servidor
    is_pointing_local = any(ip in local_ips for ip in hosting_ips)

    # Detectar CDN
    detected_cdn = None
    for ip in hosting_ips:
        for cdn, prefixes in KNOWN_CDNS.items():
            if any(ip.startswith(pref) for pref in prefixes):
                detected_cdn = cdn.upper()
                break

    # Obtener ASN/ISP de la primera IP
    ip_info = {}
    if hosting_ips:
        ip_info = query_ip_info(hosting_ips[0])

    # Comparación entre múltiples resolvers para detectar inconsistencias de propagación
    discrepancies = []
    if len(resolvers) > 1:
        base_a = dns_results.get('A', '')
        for alt_res in resolvers[1:]:
            alt_out, _ = execute_dns_query(domain, 'A', server=alt_res)
            alt_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alt_out)
            alt_hosting_ips = [ip for ip in alt_ips if ip != alt_res]
            if set(alt_hosting_ips) != set(hosting_ips):
                discrepancies.append(
                    "Diferencia en registro A con %s: %s (vs %s en %s)" % (
                        alt_res, ",".join(alt_hosting_ips), ",".join(hosting_ips), primary_resolver
                    )
                )

    # Construir Reporte
    out = []
    out.append("=" * 80)
    out.append("06. DNS & DOMAIN INVESTIGATOR — REPORTE DE AUDITORÍA DE DOMINIO")
    out.append("=" * 80)
    out.append("Dominio auditado: %s" % domain)
    out.append("Fecha de consulta: %s" % now.strftime('%Y-%m-%d %H:%M:%S'))
    out.append("Resolver primario: %s" % (primary_resolver or 'Sistema Local'))
    out.append("-" * 80)
    out.append("ANÁLISIS DE INFRAESTRUCTURA Y HOSTING:")
    out.append("  IP(s) A de Hosting:   %s" % (", ".join(hosting_ips) if hosting_ips else "No resuelto"))
    if ip_info:
        out.append("  Proveedor / ASN:      %s (%s)" % (ip_info.get('isp', 'N/A'), ip_info.get('as', 'N/A')))
        out.append("  País de Servidor:     %s" % ip_info.get('country', 'N/A'))
    if detected_cdn:
        out.append("  [!] Servicio Proxy/CDN: DETECTADO (%s)" % detected_cdn)
        out.append("      La IP real del servidor de origen está oculta detrás de la CDN.")
    if hosting_ips:
        if is_pointing_local:
            out.append("  [OK] El dominio APUNTA a este servidor local (%s)." % hosting_ips[0])
        else:
            out.append("  [!] ALERTA: El dominio NO apunta a las IPs de este servidor local.")
            out.append("      (¿Cuenta migrada, DNS externo o sitio alojado en otro proveedor?)")
    out.append("=" * 80)

    # Secciones detalladas de registros
    out.append("\nREGISTROS DE SERVIDORES DE NOMBRE (NS):")
    out.append("-" * 80)
    out.append(dns_results.get('NS', 'Sin registros NS encontrados').strip() or 'Sin datos')

    out.append("\nREGISTROS DE CORREO (MX):")
    out.append("-" * 80)
    out.append(dns_results.get('MX', 'Sin registros MX encontrados').strip() or 'Sin datos')

    out.append("\nREGISTROS TXT (POLÍTICAS SPF / VERIFICACIONES):")
    out.append("-" * 80)
    txt_content = dns_results.get('TXT', '').strip()
    out.append(txt_content if txt_content else 'Sin registros TXT')

    if dmarc_out:
        out.append("\nREGISTRO DMARC (_dmarc):")
        out.append("-" * 80)
        out.append(dmarc_out.strip())

    if discrepancies:
        out.append("\n" + "=" * 80)
        out.append("[!] DISCREPANCIAS O FALTA DE PROPAGACIÓN ENTRE RESOLVERS:")
        out.append("-" * 80)
        for d in discrepancies:
            out.append("  * " + d)

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE RESOLUCIÓN DNS)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (RESOLUCIÓN DNS CRUDA / RAW OUTPUT)")
    out.append("Copiar y pegar las siguientes líneas directamente en el ticket de IRIS:")
    out.append("=" * 80)
    if raw_evidence_lines:
        for idx, line in enumerate(raw_evidence_lines[:25], 1):
            out.append("[%02d] %s" % (idx, line))
    else:
        out.append("(No se obtuvieron líneas crudas de DNS)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de DNS guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

