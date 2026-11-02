#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
04. Account Access Investigator
Plataformas: cPanel, WHM, DirectAdmin y SSH (Linux)
Uso:
  python3 04_account_access_investigator.py
  python3 04_account_access_investigator.py --server cpanel --user cuenta1 --days 3
  python3 04_account_access_investigator.py --server directadmin --ip 198.51.100.25
  python3 04_account_access_investigator.py --user root --days 1

Investiga accesos exitosos y fallidos a paneles de control (cPanel, WHM, Webmail, DirectAdmin)
y accesos SSH. Correlaciona acciones administrativas (File Manager, creación de correos,
cambios de contraseña) con IPs y marcas de tiempo exactas.
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
import subprocess
import sys

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

CPANEL_LOGIN_REGEX = re.compile(
    r'^\[([^\]]+)\]\s+info\s+\[(\w+)\]\s+([0-9a-fA-F:.]+)\s+-\s+(\S+)\s+"(?:[A-Z]+\s+)?([^"\s]+)?(?:[^"]*)?"\s+(FAILED|SUCCESS|LOGIN|AUTHENTICATED)\s*(.*)$',
    re.I
)

# Línea típica de cPanel access_log:
# 127.0.0.1 - seguric1 [11/02/2026:16:04:03 -0000] "POST /cpsess1985652696/execute/ResourceUsage/get_usages HTTP/1.1" 200 0 ... "X-Forwarded-For: 72.249.55.58" 2083
CPANEL_ACCESS_REGEX = re.compile(
    r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[0-9.]+)?(?:.*)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?(?:\s+"([^"]*)")?(?:\s+"([^"]*)"\s+(\d+))?'
)

DA_LOGIN_REGEX = re.compile(
    r'^(\d{4}:\d\d:\d\d-\d\d:\d\d:\d\d)\s+ip=([0-9a-fA-F:.]+)\s+user=(\S+)\s+result=(successful|failed|success)',
    re.I
)

SSH_ACCEPTED_REGEX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)\s+port\s+\d+'
)
SSH_FAILED_REGEX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*sshd\[\d+\]:\s+(?:Failed password|Invalid user)\s+(?:invalid user\s+)?for\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)\s+port\s+\d+'
)


def detect_server_type():
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/usr/local/directadmin'):
        return 'directadmin'
    return 'generic'


def prompt_server_type():
    detected = detect_server_type()
    print("=" * 70)
    print("  04. Account Access Investigator — Selección de Servidor")
    print("=" * 70)
    if detected != 'generic':
        print("[*] Servidor detectado automáticamente: %s" % detected.upper())
        choice = input("¿Deseas continuar con '%s'? [S/n]: " % detected).strip().lower()
        if choice in ('', 's', 'si', 'y', 'yes'):
            return detected

    while True:
        print("\nSelecciona el entorno de logs:")
        print("  1) cPanel & WHM (/usr/local/cpanel/logs/)")
        print("  2) DirectAdmin (/var/log/directadmin/)")
        print("  3) SSH / Linux Genérico (/var/log/secure o /var/log/auth.log)")
        sel = input("Opción [1-3]: ").strip()
        if sel == '1':
            return 'cpanel'
        elif sel == '2':
            return 'directadmin'
        elif sel == '3':
            return 'generic'
        print("[!] Opción inválida. Intenta nuevamente.")


def get_log_files(patterns, since_dt=None):
    cutoff = (since_dt - dt.timedelta(hours=6)).timestamp() if since_dt else None
    matched = set()
    for pat in patterns:
        for f in glob.glob(pat + '*'):
            if os.path.isfile(f) and not f.endswith('.offset'):
                if cutoff:
                    try:
                        if os.path.getmtime(f) < cutoff:
                            continue
                    except OSError:
                        pass
                matched.add(f)
    return sorted(matched, key=lambda x: (os.path.getmtime(x) if os.path.exists(x) else 0, x))


def parse_syslog_date(date_str, now):
    try:
        parts = date_str.split()
        month = MONTHS.get(parts[0].capitalize(), 1)
        day = int(parts[1])
        clock = parts[2]
        cand = dt.datetime.strptime('%04d-%02d-%02d %s' % (now.year, month, day, clock), '%Y-%m-%d %H:%M:%S')
        if cand > now + dt.timedelta(days=1):
            cand = cand.replace(year=cand.year - 1)
        return cand
    except Exception:
        return None


def parse_cpanel_date(date_str):
    # Formato: 2026-11-02 16:04:03 o 11/Feb/2026:16:04:03
    m_iso = re.search(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', date_str)
    if m_iso:
        try:
            return dt.datetime.strptime(m_iso.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    m_clf = re.search(r'(\d{1,2})/(\w{3})/(\d{4}):(\d\d:\d\d:\d\d)', date_str)
    if m_clf:
        day, mon, year, clock = m_clf.groups()
        month = MONTHS.get(mon.capitalize(), 1)
        try:
            return dt.datetime.strptime('%04d-%02d-%02d %s' % (int(year), month, int(day), clock), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    return None


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/04_account_access_investigator.py) --user cliente1 --days 7\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/04_account_access_investigator.py) --ip 198.51.100.25\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/04_account_access_investigator.py) --user root --days 3\n"
    )
    parser = argparse.ArgumentParser(
        description='04. Account Access Investigator — Auditoría Forense de Logins en cPanel, WHM, DirectAdmin y SSH',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', choices=['cpanel', 'directadmin', 'generic', 'auto'], default='auto')
    parser.add_argument('--user', help='Filtrar por usuario cPanel / DirectAdmin / SSH')
    parser.add_argument('--ip', help='Filtrar por IP de origen')
    parser.add_argument('--days', type=int, default=7, help='Días hacia atrás a investigar (def: 7)')
    parser.add_argument('--output', help='Ruta para guardar el reporte')
    parser.add_argument('--interactive', action='store_true', help='Ejecutar en modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  04. Account Access Investigator — Asistente de Inicio")
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

    server = args.server
    if args.interactive or server == 'auto':
        detected = detect_server_type()
        if args.interactive:
            server = prompt_server_type()
        else:
            server = detected if detected != 'unknown' else 'generic'

    target_user = args.user.strip() if args.user else None
    target_ip = args.ip.strip() if args.ip else None

    now = dt.datetime.now()
    since = now - dt.timedelta(days=args.days)

    # Identificar rutas de logs
    panel_login_logs = []
    panel_access_logs = []
    ssh_logs = []

    # SSH logs
    for s_path in ['/var/log/secure', '/var/log/auth.log']:
        ssh_logs.extend(get_log_files([s_path], since_dt=since))

    if server == 'cpanel':
        panel_login_logs = get_log_files(['/usr/local/cpanel/logs/login_log'], since_dt=since)
        panel_access_logs = get_log_files(['/usr/local/cpanel/logs/access_log'], since_dt=since)
    elif server == 'directadmin':
        panel_login_logs = get_log_files(['/var/log/directadmin/login.log'], since_dt=since)
        panel_access_logs = get_log_files(['/var/log/directadmin/system.log'], since_dt=since)

    # Estadísticas
    successful_panel_logins = collections.Counter()
    failed_panel_logins = collections.Counter()
    successful_ssh_logins = collections.Counter()
    failed_ssh_logins = collections.Counter()
    admin_actions = collections.Counter()
    ip_activity = collections.Counter()

    # Evidencia Cruda
    raw_panel_logins = []
    raw_panel_actions = []
    raw_ssh_logins = []

    # 1. Parsear Panel Logins (cPanel o DirectAdmin)
    if server == 'cpanel':
        for path in panel_login_logs:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        if target_user and target_user.lower() not in line.lower():
                            continue
                        if target_ip and target_ip not in line:
                            continue

                        # Extraer fecha
                        m_date = re.search(r'\[([^\]]+)\]', line)
                        if m_date:
                            t_log = parse_cpanel_date(m_date.group(1))
                            if t_log and not (since <= t_log <= now):
                                continue

                        is_success = bool(re.search(r'\b(?:SUCCESS|LOGIN|AUTHENTICATED)\b', line, re.I))
                        is_fail = bool(re.search(r'\b(?:FAILED|FAILURE)\b', line, re.I))

                        # Extraer IP y usuario
                        m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        ip_found = m_ip.group(0) if m_ip else 'N/A'

                        m_u = re.search(r'\s-\s+(\S+)\s+"', line)
                        u_found = m_u.group(1) if m_u else '(desconocido)'

                        ip_activity[ip_found] += 1
                        if is_success:
                            successful_panel_logins["%s (desde %s)" % (u_found, ip_found)] += 1
                            if len(raw_panel_logins) < 10:
                                raw_panel_logins.append(line.strip())
                        elif is_fail:
                            failed_panel_logins["%s (desde %s)" % (u_found, ip_found)] += 1
                            if len(raw_panel_logins) < 10:
                                raw_panel_logins.append(line.strip())

            except (OSError, EOFError):
                continue

    elif server == 'directadmin':
        for path in panel_login_logs:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        m = DA_LOGIN_REGEX.search(line)
                        if not m:
                            continue
                        date_str, ip_found, u_found, res = m.groups()
                        # Formato 2026:11:02-16:04:03
                        try:
                            t_log = dt.datetime.strptime(date_str, '%Y:%m:%d-%H:%M:%S')
                        except ValueError:
                            continue
                        if not (since <= t_log <= now):
                            continue

                        if target_user and u_found.lower() != target_user.lower():
                            continue
                        if target_ip and ip_found != target_ip:
                            continue

                        ip_activity[ip_found] += 1
                        if 'success' in res.lower():
                            successful_panel_logins["%s (desde %s)" % (u_found, ip_found)] += 1
                        else:
                            failed_panel_logins["%s (desde %s)" % (u_found, ip_found)] += 1

                        if len(raw_panel_logins) < 10:
                            raw_panel_logins.append(line.strip())
            except (OSError, EOFError):
                continue

    # 2. Parsear Acciones Administrativas (access_log cPanel o system.log DA)
    if server == 'cpanel':
        for path in panel_access_logs:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        if target_user and target_user.lower() not in line.lower():
                            continue
                        if target_ip and target_ip not in line:
                            continue

                        # Detectar acciones sensibles: filemanager, email creation, passwd, terminal
                        sensitive = bool(re.search(
                            r'(?:fileman|upload|email|passwd|password|mysql|cron|terminal|backup|cpsess)',
                            line, re.I
                        ))
                        if not sensitive and not target_user and not target_ip:
                            continue

                        m_acc = CPANEL_ACCESS_REGEX.search(line)
                        if m_acc:
                            ip_client, user_acc, date_str, method, uri = m_acc.groups()[:5]
                            t_acc = parse_cpanel_date(date_str)
                            if t_acc and not (since <= t_acc <= now):
                                continue

                            # Detectar X-Forwarded-For
                            fwd_ip = ''
                            m_fwd = re.search(r'X-Forwarded-For:\s*([0-9a-fA-F:.]+)', line, re.I)
                            if m_fwd:
                                fwd_ip = m_fwd.group(1)
                                ip_activity[fwd_ip] += 1

                            actor_ip = fwd_ip or ip_client
                            clean_uri = uri.split('?')[0]
                            admin_actions["[%s] %s %s (%s)" % (user_acc, method, clean_uri, actor_ip)] += 1

                            if len(raw_panel_actions) < 15:
                                raw_panel_actions.append(line.strip())
            except (OSError, EOFError):
                continue

    elif server == 'directadmin':
        for path in panel_access_logs:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        if target_user and target_user.lower() not in line.lower():
                            continue
                        if target_ip and target_ip not in line:
                            continue
                        if re.search(r'(?:CMD_FILE_MANAGER|CMD_EMAIL|CMD_PASSWD|CMD_ACCOUNT)', line, re.I):
                            admin_actions[line[:90].strip()] += 1
                            if len(raw_panel_actions) < 15:
                                raw_panel_actions.append(line.strip())
            except (OSError, EOFError):
                continue

    # 3. Parsear SSH Logins (secure / auth.log)
    for path in ssh_logs:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    m_acc = SSH_ACCEPTED_REGEX.search(line)
                    if m_acc:
                        date_str, auth_type, u_ssh, ip_ssh = m_acc.groups()
                        t_ssh = parse_syslog_date(date_str, now)
                        if t_ssh and not (since <= t_ssh <= now):
                            continue
                        if target_user and u_ssh.lower() != target_user.lower():
                            continue
                        if target_ip and ip_ssh != target_ip:
                            continue

                        ip_activity[ip_ssh] += 1
                        successful_ssh_logins["%s vía %s (desde %s)" % (u_ssh, auth_type, ip_ssh)] += 1
                        if len(raw_ssh_logins) < 10:
                            raw_ssh_logins.append(line.strip())
                        continue

                    m_fail = SSH_FAILED_REGEX.search(line)
                    if m_fail:
                        date_str, u_ssh, ip_ssh = m_fail.groups()
                        t_ssh = parse_syslog_date(date_str, now)
                        if t_ssh and not (since <= t_ssh <= now):
                            continue
                        if target_user and u_ssh.lower() != target_user.lower():
                            continue
                        if target_ip and ip_ssh != target_ip:
                            continue

                        ip_activity[ip_ssh] += 1
                        failed_ssh_logins["%s (desde %s)" % (u_ssh, ip_ssh)] += 1
                        if len(raw_ssh_logins) < 10:
                            raw_ssh_logins.append(line.strip())

        except (OSError, EOFError):
            continue

    # Capturar sesiones activas actuales (w / last)
    current_sessions = []
    try:
        w_proc = subprocess.run(['w', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if w_proc.returncode == 0:
            current_sessions = [l.strip() for l in w_proc.stdout.splitlines() if l.strip()]
    except Exception:
        pass

    # Construir Reporte
    out = []
    out.append("=" * 80)
    out.append("04. ACCOUNT ACCESS INVESTIGATOR — REPORTE DE AUDITORÍA DE ACCESOS")
    out.append("=" * 80)
    out.append("Servidor: %s" % server.upper())
    if target_user:
        out.append("Filtro de usuario objetivo: %s" % target_user)
    if target_ip:
        out.append("Filtro de IP objetivo: %s" % target_ip)
    out.append("Período analizado: %s a %s" % (since.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S')))
    out.append("Logs de Panel auditados: %d | Logs de SSH auditados: %d" % (
        len(panel_login_logs) + len(panel_access_logs), len(ssh_logs)
    ))
    out.append("-" * 80)
    out.append("RESUMEN DE SESIONES:")
    out.append("  Logins Exitosos a Panel (cPanel/WHM/DA):  %d" % sum(successful_panel_logins.values()))
    out.append("  Logins Fallidos a Panel:                 %d" % sum(failed_panel_logins.values()))
    out.append("  Logins Exitosos SSH:                     %d" % sum(successful_ssh_logins.values()))
    out.append("  Logins Fallidos SSH:                     %d" % sum(failed_ssh_logins.values()))
    out.append("  Acciones administrativas registradas:    %d" % sum(admin_actions.values()))
    out.append("=" * 80)

    def print_section(title, counter, unit='accesos'):
        out.append("\n" + title)
        out.append("-" * len(title))
        if not counter:
            out.append("Sin registros.")
            return
        for k, v in counter.most_common(20):
            out.append("{0:>8} {1} {2}".format(v, unit, k))

    print_section("LOGINS EXITOSOS A PANEL (cPanel / WHM / DirectAdmin)", successful_panel_logins)
    print_section("LOGINS FALLIDOS A PANEL", failed_panel_logins, unit='fallos')
    print_section("LOGINS EXITOSOS SSH", successful_ssh_logins)
    print_section("INTENTOS FALLIDOS SSH", failed_ssh_logins, unit='intentos')
    print_section("ACCIONES ADMINISTRATIVAS Y PETICIONES AL PANEL", admin_actions, unit='acciones')
    print_section("TOP IPs REGISTRADAS EN ACCESOS", ip_activity, unit='eventos')

    if current_sessions:
        out.append("\n" + "=" * 80)
        out.append("SESIONES ACTIVAS EN ESTE MOMENTO (comando 'w'):")
        out.append("-" * 80)
        for s in current_sessions:
            out.append("  " + s)

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOG)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOGIN Y PANEL ACCESS)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso de IRIS:")
    out.append("=" * 80)

    # 1. Logins Panel
    out.append("\n--- [EVIDENCIA 1/3] REGISTROS DE LOGIN DE PANEL (login_log) ---")
    if raw_panel_logins:
        for idx, l in enumerate(raw_panel_logins[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros de login_log para los filtros indicados)")

    # 2. Acciones Administrativas con X-Forwarded-For
    out.append("\n--- [EVIDENCIA 2/3] ACCIONES ADMINISTRATIVAS CON X-FORWARDED-FOR (access_log) ---")
    if raw_panel_actions:
        for idx, l in enumerate(raw_panel_actions[:10], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros de acciones administrativas en access_log)")

    # 3. Logins SSH
    out.append("\n--- [EVIDENCIA 3/3] REGISTROS DE ACCESO SSH (secure / auth.log) ---")
    if raw_ssh_logins:
        for idx, l in enumerate(raw_ssh_logins[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros SSH relevantes)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de accesos de cuenta guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

