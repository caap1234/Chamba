#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
02. Web Access Investigator
Plataformas: Apache / Nginx / LiteSpeed en cPanel, DirectAdmin o Linux Genérico
Uso:
  python3 02_web_access_investigator.py
  python3 02_web_access_investigator.py --server cpanel --domain midominio.com --file wso.php
  python3 02_web_access_investigator.py --server directadmin --domain midominio.com --post-only
  python3 02_web_access_investigator.py --domain midominio.com --time "2026-11-02 14:30:00" --window-minutes 60
  python3 02_web_access_investigator.py --ip 185.220.101.5

Investiga accesos web a archivos sospechosos (webshells, uploader, wp-login, xmlrpc),
analiza métodos POST, códigos HTTP, IPs atacantes, User-Agents y reconstruye la
actividad antes y después de una hora de modificación o compromiso.
Incluye sección de evidencia con líneas completas de logs listas para Iris.
"""

import argparse
import collections
import datetime as dt
import glob
import gzip
import io
import os
import re
import sys

# Patrones comunes de peticiones en logs Apache/Nginx (Combined Log Format)
# 127.0.0.1 - - [10/Oct/2026:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://..." "Mozilla/..."
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[0-9.]+)?(?:.*)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

SUSPICIOUS_NAMES = [
    'wso', 'c99', 'r57', 'b374k', 'alfa', 'shell', 'uploader', 'up.php', 'mini.php',
    'wp-login.php', 'xmlrpc.php', 'admin-ajax.php', 'eval-stdin.php', 'alfashell',
    'marv', 'vuln', 'backdoor', 'cmd.php', 'sh.php', 'system.php', 'radio.php'
]


def detect_server_type():
    """Detecta si el servidor es cPanel, DirectAdmin o Genérico."""
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/usr/local/directadmin'):
        return 'directadmin'
    return 'generic'


def prompt_server_type():
    detected = detect_server_type()
    print("=" * 70)
    print("  02. Web Access Investigator — Selección de Servidor")
    print("=" * 70)
    if detected != 'generic':
        print("[*] Servidor detectado automáticamente: %s" % detected.upper())
        choice = input("¿Deseas continuar con '%s'? [S/n]: " % detected).strip().lower()
        if choice in ('', 's', 'si', 'y', 'yes'):
            return detected

    while True:
        print("\nSelecciona el entorno:")
        print("  1) cPanel / WHM (/etc/apache2/logs/domlogs/...)")
        print("  2) DirectAdmin (/var/log/httpd/domains/...)")
        print("  3) Linux Genérico (/var/log/apache2/ o /var/log/nginx/)")
        sel = input("Opción [1-3]: ").strip()
        if sel == '1':
            return 'cpanel'
        elif sel == '2':
            return 'directadmin'
        elif sel == '3':
            return 'generic'
        print("[!] Opción inválida. Intenta nuevamente.")


def parse_clf_date(date_str):
    """Parsea fecha en formato Common Log Format: 10/Oct/2026:13:55:36 -0700"""
    try:
        core = date_str.split(' ')[0]
        day, month_str, rest = core.split('/', 2)
        year, time_str = rest.split(':', 1)
        month = MONTHS.get(month_str.capitalize(), 1)
        return dt.datetime.strptime(
            '%04d-%02d-%02d %s' % (int(year), month, int(day), time_str),
            '%Y-%m-%d %H:%M:%S'
        )
    except Exception:
        return None


def get_domlog_files(server, domain=None, custom_path=None):
    """Obtiene la lista de archivos de log según el servidor y dominio."""
    if custom_path:
        files = glob.glob(custom_path + '*')
        return sorted([f for f in files if os.path.isfile(f)])

    targets = []
    if server == 'cpanel':
        bases = [
            '/etc/apache2/logs/domlogs',
            '/usr/local/apache/domlogs',
            '/var/log/nginx/domains'
        ]
        for base in bases:
            if not os.path.isdir(base):
                continue
            if domain:
                pattern = os.path.join(base, domain + '*')
                targets.extend(glob.glob(pattern))
                # También subcarpetas de usuario en domlogs
                pattern_sub = os.path.join(base, '*', domain + '*')
                targets.extend(glob.glob(pattern_sub))
            else:
                targets.extend(glob.glob(os.path.join(base, '*')))

    elif server == 'directadmin':
        bases = ['/var/log/httpd/domains', '/var/log/nginx/domains']
        for base in bases:
            if not os.path.isdir(base):
                continue
            if domain:
                targets.extend(glob.glob(os.path.join(base, domain + '*')))
            else:
                targets.extend(glob.glob(os.path.join(base, '*')))

    else:  # generic
        generic_logs = [
            '/var/log/apache2/access.log*',
            '/var/log/httpd/access_log*',
            '/var/log/nginx/access.log*'
        ]
        for g in generic_logs:
            targets.extend(glob.glob(g))

    valid = set()
    for f in targets:
        if os.path.isfile(f) and not f.endswith('.bytes') and not f.endswith('.offset'):
            valid.add(f)
    return sorted(valid, key=lambda x: (os.path.getmtime(x) if os.path.exists(x) else 0, x))


def is_suspicious_uri(uri):
    """Determina si la URI solicitada contiene patrones sospechosos."""
    uri_lower = uri.lower()
    for s in SUSPICIOUS_NAMES:
        if s in uri_lower:
            return True
    if '/wp-content/uploads/' in uri_lower and uri_lower.endswith('.php'):
        return True
    if re.search(r'\.(?:ico|png|jpg|gif|css|txt)\.php\b', uri_lower):
        return True
    return False


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/02_web_access_investigator.py) --domain cliente.com --file wso.php\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/02_web_access_investigator.py) --domain cliente.com --post-only\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/02_web_access_investigator.py) --ip 185.220.101.5\n"
    )
    parser = argparse.ArgumentParser(
        description='02. Web Access Investigator — Análisis Forense de Logs Apache, Nginx y LiteSpeed',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', choices=['cpanel', 'directadmin', 'generic', 'auto'], default='auto')
    parser.add_argument('--domain', help='Dominio a investigar (ej. midominio.com)')
    parser.add_argument('--file', help='Nombre de archivo o endpoint sospechoso (ej. wso.php, wp-login.php, shell.php)')
    parser.add_argument('--ip', help='Filtrar peticiones originadas por una IP específica')
    parser.add_argument('--post-only', action='store_true', help='Filtrar exclusivamente peticiones con método POST')
    parser.add_argument('--status', help='Filtrar por código HTTP específico (ej. 200, 403, 500 o lista 200,403)')
    parser.add_argument('--time', help='Marca de tiempo central de referencia (formato: "YYYY-MM-DD HH:MM:SS")')
    parser.add_argument('--window-minutes', type=int, default=60, help='Ventana en minutos antes y después del tiempo de referencia (def: 60)')
    parser.add_argument('--days', type=int, default=3, help='Días hacia atrás a inspeccionar si no se especifica --time (def: 3)')
    parser.add_argument('--log-path', help='Ruta personalizada directa a un archivo o patrón de domlog')
    parser.add_argument('--top', type=int, default=20, help='Cantidad de resultados por sección (def: 20)')
    parser.add_argument('--output', help='Ruta para guardar el reporte en un archivo')
    parser.add_argument('--interactive', action='store_true', help='Ejecución en modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  02. Web Access Investigator — Asistente de Inicio")
        print("=" * 70)
        print("Selecciona cómo deseas ejecutar:")
        print("  1) Asistente interactivo guiado (Paso a paso) [Recomendado]")
        print("  2) Ver ayuda completa y opciones de comando (--help)")
        opt = input("Opción [1-2, def: 1]: ").strip()
        if opt == '2':
            parser.print_help()
            sys.exit(0)
        else:
            sys.argv.append('--interactive')

    args = parser.parse_args()

    # Selección de servidor
    server = args.server
    if args.interactive or server == 'auto':
        detected = detect_server_type()
        if args.interactive:
            server = prompt_server_type()
        else:
            server = detected if detected != 'unknown' else 'generic'

    domain = args.domain.strip().lower() if args.domain else None
    if not domain and not args.log_path and sys.stdin.isatty() and args.interactive:
        domain_input = input("Ingresa el dominio a investigar (o Enter para analizar todos los disponibles): ").strip().lower()
        if domain_input:
            domain = domain_input

    # Ventana temporal
    now = dt.datetime.now()
    ref_time = None
    window_delta = dt.timedelta(minutes=args.window_minutes)
    if args.time:
        try:
            ref_time = dt.datetime.strptime(args.time, '%Y-%m-%d %H:%M:%S')
            time_start = ref_time - window_delta
            time_end = ref_time + window_delta
        except ValueError:
            print("[!] Formato de fecha inválido para --time. Usa: 'YYYY-MM-DD HH:MM:SS'", file=sys.stderr)
            sys.exit(1)
    else:
        time_end = now
        time_start = now - dt.timedelta(days=args.days)

    target_file = args.file.lower().strip() if args.file else None
    target_ip = args.ip.strip() if args.ip else None
    target_statuses = set(args.status.split(',')) if args.status else None

    log_files = get_domlog_files(server, domain=domain, custom_path=args.log_path)
    if not log_files:
        print("[!] No se encontraron archivos de log para el dominio o servidor indicado.", file=sys.stderr)
        print("    Verifica con --log-path /ruta/al/access_log", file=sys.stderr)
        sys.exit(1)

    # Contadores y colecciones
    ip_counter = collections.Counter()
    uri_counter = collections.Counter()
    post_uris = collections.Counter()
    status_counter = collections.Counter()
    user_agents = collections.Counter()
    before_activity = collections.Counter()
    after_activity = collections.Counter()
    hourly_activity = collections.Counter()

    suspicious_hits = 0
    total_parsed = 0
    raw_evidence = []
    seen_raw = set()

    for path in log_files:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    m = LOG_PATTERN.match(line)
                    if not m:
                        continue

                    ip, ident, date_str, method, uri, status, size, referer, uagent = m.groups()
                    t_req = parse_clf_date(date_str)
                    if not t_req:
                        continue

                    if not (time_start <= t_req <= time_end):
                        continue

                    total_parsed += 1

                    # Filtros de búsqueda
                    if target_ip and ip != target_ip:
                        continue
                    if args.post_only and method != 'POST':
                        continue
                    if target_statuses and status not in target_statuses:
                        continue
                    if target_file and target_file not in uri.lower():
                        continue

                    # Análisis de contenido sospechoso
                    is_susp = is_suspicious_uri(uri) or (target_file and target_file in uri.lower())
                    if is_susp:
                        suspicious_hits += 1

                    ip_counter[ip] += 1
                    uri_counter[uri.split('?')[0]] += 1
                    status_counter[status] += 1
                    if method == 'POST':
                        post_uris[uri.split('?')[0]] += 1
                    if uagent:
                        user_agents[uagent[:90]] += 1

                    hourly_activity[t_req.strftime('%Y-%m-%d %H:00')] += 1

                    if ref_time:
                        if t_req < ref_time:
                            before_activity["[ANTES %s] %s %s (%s)" % (t_req.strftime('%H:%M:%S'), method, uri, ip)] += 1
                        else:
                            after_activity["[DESPUÉS %s] %s %s (%s)" % (t_req.strftime('%H:%M:%S'), method, uri, ip)] += 1

                    # Recolectar evidencia cruda completa
                    # Priorizar peticiones a archivos sospechosos, POSTs o peticiones con status 200
                    if line not in seen_raw and len(raw_evidence) < 25:
                        if is_susp or method == 'POST' or target_ip or target_file:
                            seen_raw.add(line)
                            raw_evidence.append(line.rstrip('\n'))

        except (OSError, EOFError):
            continue

    # Si la lista de evidencia es corta, rellenar con las primeras líneas encontradas
    if len(raw_evidence) < 5 and total_parsed > 0:
        # Volver a pasar para obtener al menos 5 líneas
        for path in log_files[:2]:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        if line not in seen_raw and len(raw_evidence) < 5:
                            seen_raw.add(line)
                            raw_evidence.append(line.rstrip('\n'))
            except Exception:
                pass

    # Generación de reporte
    out = []
    out.append("=" * 80)
    out.append("02. WEB ACCESS INVESTIGATOR — REPORTE FORENSE DE ACCESOS WEB")
    out.append("=" * 80)
    out.append("Servidor: %s" % server.upper())
    if domain:
        out.append("Dominio investigado: %s" % domain)
    if target_file:
        out.append("Filtro de archivo/endpoint: %s" % target_file)
    if target_ip:
        out.append("Filtro de IP origen: %s" % target_ip)
    if args.post_only:
        out.append("Modo: Exclusivamente peticiones POST")
    out.append("Ventana temporal: %s a %s" % (
        time_start.strftime('%Y-%m-%d %H:%M:%S'),
        time_end.strftime('%Y-%m-%d %H:%M:%S')
    ))
    out.append("Archivos de log procesados: %d" % len(log_files))
    out.append("Peticiones analizadas en rango: %d" % total_parsed)
    out.append("Peticiones sospechosas detectadas: %d" % suspicious_hits)
    out.append("-" * 80)

    # Tablas de resumen
    def add_table(title, counter, top_n=args.top, unit='peticiones'):
        out.append("\n" + title)
        out.append("-" * len(title))
        if not counter:
            out.append("Sin registros.")
            return
        for k, v in counter.most_common(top_n):
            out.append("{0:>8} {1} {2}".format(v, unit, k))

    add_table("TOP IPs CON MÁS ACCESOS", ip_counter)
    add_table("TOP RECURSOS / ENDPOINTS SOLICITADOS", uri_counter)
    add_table("TOP PETICIONES CON MÉTODO POST (Potencial explotación/subida)", post_uris)
    add_table("CÓDIGOS DE RESPUESTA HTTP", status_counter)
    add_table("TOP USER-AGENTS", user_agents)
    add_table("DISTRIBUCIÓN HORARIA DE PETICIONES", hourly_activity)

    if ref_time:
        out.append("\n" + "=" * 80)
        out.append("CRONOLOGÍA ALREDEDOR DEL EVENTO (%s):" % ref_time.strftime('%Y-%m-%d %H:%M:%S'))
        out.append("=" * 80)
        add_table("ACTIVIDAD PREVIA AL EVENTO (ANTES)", before_activity, top_n=10)
        add_table("ACTIVIDAD POSTERIOR AL EVENTO (DESPUÉS)", after_activity, top_n=10)

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOG)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS / LOG SNIPPETS COMPLETOS)")
    out.append("Copiar y pegar las siguientes líneas directamente en el ticket de IRIS:")
    out.append("=" * 80)
    if raw_evidence:
        for idx, line in enumerate(raw_evidence, 1):
            out.append("[%02d] %s" % (idx, line))
    else:
        out.append("(No se encontraron líneas que coincidan con los criterios)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de accesos web guardado exitosamente en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

