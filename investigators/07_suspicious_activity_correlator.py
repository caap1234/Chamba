#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
07. Suspicious Activity Correlator
Plataformas: cPanel, DirectAdmin y Linux Genérico
Uso:
  python3 07_suspicious_activity_correlator.py
  python3 07_suspicious_activity_correlator.py --server cpanel --ip 198.51.100.2 --hours 12
  python3 07_suspicious_activity_correlator.py --server directadmin --user cliente1 --domain cliente.com --hours 24
  python3 07_suspicious_activity_correlator.py --ip 198.51.100.2 --user cliente1 --time "2026-11-02 15:30:00"

Cruza y correlaciona en una misma línea de tiempo (timeline forense unificado):
1. Accesos Web (Apache/Nginx domlogs)
2. Envíos y scripts de Correo (Exim mainlog y cwd)
3. Autenticaciones Dovecot (IMAP/POP3)
4. Sesiones administrativas de Panel (cPanel/WHM/DirectAdmin login y access_log)
5. Intentos y accesos SSH (secure/auth.log)
6. Modificaciones de archivos en el sistema de archivos
Incluye sección de evidencia con líneas de log completas listas para Iris.
"""

import argparse
import datetime as dt
import glob
import gzip
import io
import os
import re
import sys

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def detect_server_type():
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/usr/local/directadmin'):
        return 'directadmin'
    return 'generic'


def prompt_server_type():
    detected = detect_server_type()
    print("=" * 70)
    print("  07. Suspicious Activity Correlator — Selección de Servidor")
    print("=" * 70)
    if detected != 'generic':
        print("[*] Servidor detectado automáticamente: %s" % detected.upper())
        choice = input("¿Deseas continuar con '%s'? [S/n]: " % detected).strip().lower()
        if choice in ('', 's', 'si', 'y', 'yes'):
            return detected

    while True:
        print("\nSelecciona el entorno:")
        print("  1) cPanel / WHM")
        print("  2) DirectAdmin")
        print("  3) Linux Genérico")
        sel = input("Opción [1-3]: ").strip()
        if sel == '1':
            return 'cpanel'
        elif sel == '2':
            return 'directadmin'
        elif sel == '3':
            return 'generic'
        print("[!] Opción inválida. Intenta nuevamente.")


def get_files_for(stems, since_dt=None):
    cutoff = (since_dt - dt.timedelta(hours=6)).timestamp() if since_dt else None
    result = set()
    for stem in stems:
        for f in glob.glob(stem + '*'):
            if os.path.isfile(f) and not f.endswith('.offset'):
                if cutoff:
                    try:
                        if os.path.getmtime(f) < cutoff:
                            continue
                    except OSError:
                        pass
                result.add(f)
    return sorted(result, key=lambda x: (os.path.getmtime(x) if os.path.exists(x) else 0, x))


def parse_clf_date(date_str):
    try:
        core = date_str.split(' ')[0]
        day, mon_str, rest = core.split('/', 2)
        year, time_str = rest.split(':', 1)
        month = MONTHS.get(mon_str.capitalize(), 1)
        return dt.datetime.strptime('%04d-%02d-%02d %s' % (int(year), month, int(day), time_str), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def parse_syslog_date(line, now):
    m_iso = re.search(r'^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)', line)
    if m_iso:
        try:
            return dt.datetime.strptime(m_iso.group(1).replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    m = re.match(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)', line)
    if not m or m.group(1) not in MONTHS:
        return None
    month, day, clock = MONTHS[m.group(1)], int(m.group(2)), m.group(3)
    try:
        cand = dt.datetime.strptime('%04d-%02d-%02d %s' % (now.year, month, day, clock), '%Y-%m-%d %H:%M:%S')
        if cand > now + dt.timedelta(days=1):
            cand = cand.replace(year=cand.year - 1)
        return cand
    except ValueError:
        return None


def parse_cpanel_date(line):
    m_iso = re.search(r'\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', line)
    if m_iso:
        try:
            return dt.datetime.strptime(m_iso.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    m_clf = re.search(r'\[(\d{1,2})/(\w{2,3})/(\d{4}):(\d\d:\d\d:\d\d)', line)
    if m_clf:
        day, mon, year, clock = m_clf.groups()
        month = int(mon) if mon.isdigit() else MONTHS.get(mon.capitalize(), 1)
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
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/07_suspicious_activity_correlator.py) --ip 198.51.100.2 --hours 24\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/07_suspicious_activity_correlator.py) --user cliente1 --domain cliente.com\n"
    )
    parser = argparse.ArgumentParser(
        description='07. Suspicious Activity Correlator — Cruzar IP, Cuenta, Archivos y Logs en una Misma Ventana',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', choices=['cpanel', 'directadmin', 'generic', 'auto'], default='auto')
    parser.add_argument('--ip', help='Dirección IP sospechosa a correlacionar')
    parser.add_argument('--user', help='Usuario de la cuenta (cPanel / DirectAdmin / SSH)')
    parser.add_argument('--domain', help='Dominio involucrado')
    parser.add_argument('--hours', type=int, default=24, help='Ventana temporal en horas hacia atrás (def: 24)')
    parser.add_argument('--time', help='Marca de tiempo central de referencia ("YYYY-MM-DD HH:MM:SS")')
    parser.add_argument('--window-minutes', type=int, default=120, help='Ventana en minutos alrededor de --time (def: 120)')
    parser.add_argument('--docroot', help='Ruta del docroot de la cuenta para auditar mtime de archivos')
    parser.add_argument('--output', help='Ruta para guardar el reporte')
    parser.add_argument('--interactive', action='store_true', help='Modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  07. Suspicious Activity Correlator — Asistente de Inicio")
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

    ip_filter = args.ip.strip() if args.ip else None
    user_filter = args.user.strip() if args.user else None
    domain_filter = args.domain.lower().strip() if args.domain else None

    if not ip_filter and not user_filter and not domain_filter:
        if args.interactive and sys.stdin.isatty():
            ip_in = input("Ingresa la IP sospechosa (o Enter si filtrarás por usuario): ").strip()
            if ip_in:
                ip_filter = ip_in
            u_in = input("Ingresa el usuario de la cuenta (o Enter): ").strip()
            if u_in:
                user_filter = u_in
            d_in = input("Ingresa el dominio (o Enter): ").strip()
            if d_in:
                domain_filter = d_in

    now = dt.datetime.now()
    if args.time:
        try:
            t_ref = dt.datetime.strptime(args.time, '%Y-%m-%d %H:%M:%S')
            delta = dt.timedelta(minutes=args.window_minutes)
            t_start = t_ref - delta
            t_end = t_ref + delta
        except ValueError:
            print("[!] Formato de fecha inválido para --time. Usa: 'YYYY-MM-DD HH:MM:SS'", file=sys.stderr)
            sys.exit(1)
    else:
        t_end = now
        t_start = now - dt.timedelta(hours=args.hours)

    print("[*] Iniciando correlación cruzada multilog...")
    print("[*] Rango temporal: %s a %s" % (t_start.strftime('%Y-%m-%d %H:%M:%S'), t_end.strftime('%Y-%m-%d %H:%M:%S')))

    timeline_events = []
    # timeline_events tendrá tuplas: (timestamp, origen, descripción, raw_line)

    # 1. Logs de Exim
    exim_stem = '/var/log/exim_mainlog' if server == 'cpanel' else '/var/log/exim/mainlog'
    exim_files = get_files_for([exim_stem], since_dt=t_start)
    for path in exim_files:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    # Chequear filtro rápido
                    if ip_filter and ip_filter not in line:
                        pass
                    if user_filter and user_filter.lower() not in line.lower():
                        pass
                    if domain_filter and domain_filter not in line.lower():
                        pass
                    # Si no coincide ninguno de los filtros especificados, saltar
                    matches = False
                    if ip_filter and ip_filter in line:
                        matches = True
                    if user_filter and user_filter.lower() in line.lower():
                        matches = True
                    if domain_filter and domain_filter in line.lower():
                        matches = True
                    if not matches and (ip_filter or user_filter or domain_filter):
                        continue

                    # Extraer timestamp
                    m_time = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', line)
                    if not m_time:
                        continue
                    try:
                        t_event = dt.datetime.strptime(m_time.group(1), '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        continue
                    if not (t_start <= t_event <= t_end):
                        continue

                    if 'cwd=' in line:
                        timeline_events.append((t_event, 'EXIM_CWD', "Ejecución de script PHP/Sendmail: %s" % line[35:120], line.strip()))
                    elif '<=' in line:
                        timeline_events.append((t_event, 'EXIM_ENVIO', "Recepción de correo saliente: %s" % line[35:130], line.strip()))
                    elif 'authenticator failed' in line.lower():
                        timeline_events.append((t_event, 'EXIM_AUTH_FAIL', "Fallo de autenticación SMTP: %s" % line[20:110], line.strip()))
                    elif '**' in line:
                        timeline_events.append((t_event, 'EXIM_REBOTE', "Rebote / Rechazo de correo: %s" % line[35:120], line.strip()))
        except Exception:
            continue

    # 2. Logs de Web (Domlogs Apache / Nginx)
    web_stems = []
    if server == 'cpanel':
        if domain_filter:
            web_stems.append('/etc/apache2/logs/domlogs/' + domain_filter)
            web_stems.append('/usr/local/apache/domlogs/' + domain_filter)
        else:
            web_stems.extend(['/etc/apache2/logs/domlogs/*', '/usr/local/apache/domlogs/*'])
    elif server == 'directadmin':
        if domain_filter:
            web_stems.append('/var/log/httpd/domains/' + domain_filter + '.log')
        else:
            web_stems.append('/var/log/httpd/domains/*')
    else:
        web_stems.extend(['/var/log/apache2/access.log', '/var/log/nginx/access.log'])

    web_files = get_files_for(web_stems, since_dt=t_start)
    for path in web_files[:8]:  # Limitar para rendimiento si son muchos domlogs
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    matches = False
                    if ip_filter and ip_filter in line:
                        matches = True
                    if user_filter and user_filter.lower() in line.lower():
                        matches = True
                    if not matches and (ip_filter or user_filter):
                        continue

                    m_clf = re.search(r'\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)', line)
                    if not m_clf:
                        continue
                    date_str, method, uri = m_clf.groups()
                    t_event = parse_clf_date(date_str)
                    if not t_event or not (t_start <= t_event <= t_end):
                        continue

                    # Resaltar peticiones POST o a php
                    is_post = method == 'POST'
                    tag = 'WEB_POST' if is_post else 'WEB_ACCESS'
                    timeline_events.append((t_event, tag, "%s %s" % (method, uri[:90]), line.strip()))
        except Exception:
            continue

    # 3. Logs de Panel y SSH (cPanel / DA / secure)
    panel_stems = []
    if server == 'cpanel':
        panel_stems.extend(['/usr/local/cpanel/logs/login_log', '/usr/local/cpanel/logs/access_log'])
    elif server == 'directadmin':
        panel_stems.extend(['/var/log/directadmin/login.log', '/var/log/directadmin/system.log'])
    panel_stems.extend(['/var/log/secure', '/var/log/auth.log', '/var/log/maillog'])

    panel_files = get_files_for(panel_stems, since_dt=t_start)
    for path in panel_files:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    matches = False
                    if ip_filter and ip_filter in line:
                        matches = True
                    if user_filter and user_filter.lower() in line.lower():
                        matches = True
                    if not matches and (ip_filter or user_filter):
                        continue

                    t_event = parse_cpanel_date(line) or parse_syslog_date(line, now)
                    if not t_event or not (t_start <= t_event <= t_end):
                        continue

                    tag = 'LOG'
                    if 'cpanel' in path.lower() or 'directadmin' in path.lower():
                        tag = 'PANEL_ACTION' if 'access' in path or 'system' in path else 'PANEL_LOGIN'
                    elif 'secure' in path or 'auth' in path:
                        tag = 'SSH_AUTH'
                    elif 'maillog' in path:
                        tag = 'DOVECOT'

                    timeline_events.append((t_event, tag, line[:110].strip(), line.strip()))
        except Exception:
            continue

    # 4. Modificaciones en sistema de archivos si se especificó docroot o usuario
    docroot_path = args.docroot
    if not docroot_path and user_filter:
        if server == 'cpanel':
            candidate = os.path.join('/home', user_filter, 'public_html')
            if os.path.isdir(candidate):
                docroot_path = candidate
        elif server == 'directadmin':
            candidate = os.path.join('/home', user_filter)
            if os.path.isdir(candidate):
                docroot_path = candidate

    if docroot_path and os.path.isdir(docroot_path):
        for root, dirs, files in os.walk(docroot_path):
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    mtime = dt.datetime.fromtimestamp(os.path.getmtime(fpath))
                    if t_start <= mtime <= t_end:
                        timeline_events.append((
                            mtime,
                            'FILE_MODIFIED',
                            "Archivo modificado: %s (%d bytes)" % (fpath, os.path.getsize(fpath)),
                            "MTIME: %s | PATH: %s | SIZE: %d" % (mtime.strftime('%Y-%m-%d %H:%M:%S'), fpath, os.path.getsize(fpath))
                        ))
                except Exception:
                    continue

    # Ordenar cronológicamente
    timeline_events.sort(key=lambda x: x[0])

    # Generar Reporte
    out = []
    out.append("=" * 80)
    out.append("07. SUSPICIOUS ACTIVITY CORRELATOR — TIMELINE FORENSE UNIFICADO")
    out.append("=" * 80)
    out.append("Servidor: %s" % server.upper())
    out.append("Filtros aplicados:")
    if ip_filter:
        out.append("  * IP:      %s" % ip_filter)
    if user_filter:
        out.append("  * Usuario: %s" % user_filter)
    if domain_filter:
        out.append("  * Dominio: %s" % domain_filter)
    out.append("Ventana temporal: %s a %s" % (t_start.strftime('%Y-%m-%d %H:%M:%S'), t_end.strftime('%Y-%m-%d %H:%M:%S')))
    out.append("Total de eventos correlacionados: %d" % len(timeline_events))
    out.append("-" * 80)

    out.append("\nLÍNEA DE TIEMPO DE EVENTOS CORRELACIONADOS (CRONOLÓGICO):")
    out.append("-" * 80)
    if timeline_events:
        for t_stamp, tag, summary, _ in timeline_events[:50]:
            out.append("[%s] [%-13s] %s" % (t_stamp.strftime('%Y-%m-%d %H:%M:%S'), tag, summary))
        if len(timeline_events) > 50:
            out.append("... [Se omiten %d eventos intermedios. Mostrando primeros 50]" % (len(timeline_events) - 50))
    else:
        out.append("No se detectaron eventos cruzados para los criterios y ventana indicados.")

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE CADA COMPONENTE)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS / LOG SNIPPETS MULTICANAL)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso de IRIS:")
    out.append("=" * 80)

    events_by_tag = collections.defaultdict(list)
    for ev in timeline_events:
        events_by_tag[ev[1]].append(ev[3])

    if events_by_tag:
        for tag, lines in events_by_tag.items():
            out.append("\n--- [EVIDENCIA %s] ---" % tag)
            for idx, l in enumerate(lines[:6], 1):
                out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros de evidencia cruda disponibles)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de correlación guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

