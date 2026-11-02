#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
01. Abuse Mail Investigator
Plataformas: cPanel & DirectAdmin
Uso:
  python3 01_abuse_mail_investigator.py
  python3 01_abuse_mail_investigator.py --server cpanel --email usuario@dominio.com --days 3
  python3 01_abuse_mail_investigator.py --server directadmin --domain dominio.com --days 7
  python3 01_abuse_mail_investigator.py --days 1 --top 25

Investigación de spam, autenticaciones SMTP/Dovecot, remitentes, destinatarios,
volumen de envíos, scripts PHP (cwd) y correlación de envíos Webmail (127.0.0.1)
con X-Forwarded-For en logs de cPanel/DirectAdmin.
Incluye sección de evidencia con líneas completas listas para Iris.
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
from email.header import decode_header, make_header

# Expresiones regulares de Exim y logs del sistema
EXIM_LINE = re.compile(
    r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?:\[\d+\]\s+)?(\S+)\s+(<=|=>|->|\*\*|==|Completed)\s*(.*)$'
)
EXIM_CWD = re.compile(
    r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?:\[\d+\]\s+)?(?:\S+\s+)?cwd=(\S+)\s+\d+\s+args:\s*(.*)$'
)
SYSLOG_LINE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+')
ISOLOG_LINE = re.compile(r'^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?\s+')
IP_BRACKETS = re.compile(r'\[([0-9a-fA-F:.]+)\]')
IP_SIMPLE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
X_FORWARDED_FOR = re.compile(r'X-Forwarded-For:\s*([0-9a-fA-F:.]+)', re.IGNORECASE)

AUTH_PROTOCOLS = {'esmtpa', 'esmtpsa', 'smtpa', 'smtpsa', 'utf8esmtpa', 'utf8esmtpsa'}
LOCAL_PROTOCOLS = {'local', 'local-bsmtp', 'local-esmtp'}
FILTER_USERS = {'mail', 'exim', 'mailnull', 'debian-exim', 'dovecot'}
IGNORE_CWD = {'/var/spool/exim', '/etc/csf', '/var/spool/cron', '/usr/local/cpanel/whostmgr/docroot'}
MONTHS = {m: i for i, m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1)}


def detect_server_type():
    """Detecta automáticamente si el servidor es cPanel o DirectAdmin."""
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/usr/local/directadmin') or os.path.isfile('/usr/local/directadmin/directadmin'):
        return 'directadmin'
    return 'unknown'


def prompt_server_type():
    """Pregunta de forma interactiva el tipo de servidor si no se detectó o se requiere confirmación."""
    detected = detect_server_type()
    print("=" * 70)
    print("  01. Abuse Mail Investigator — Selección de Servidor")
    print("=" * 70)
    if detected != 'unknown':
        print("[*] Servidor detectado automáticamente: %s" % detected.upper())
        choice = input("¿Deseas continuar con '%s'? [S/n]: " % detected).strip().lower()
        if choice in ('', 's', 'si', 'y', 'yes'):
            return detected

    while True:
        print("\nSelecciona el entorno de trabajo:")
        print("  1) cPanel / WHM (/var/log/exim_mainlog)")
        print("  2) DirectAdmin (/var/log/exim/mainlog)")
        sel = input("Opción [1-2]: ").strip()
        if sel == '1':
            return 'cpanel'
        elif sel == '2':
            return 'directadmin'
        print("[!] Opción inválida. Intenta nuevamente.")


def field(key, line):
    """Extrae el valor de un campo clave (T=, P=, A=, U=) en la línea de Exim."""
    m = re.search(r'(?<!\S)' + re.escape(key) + r'=("(?:\\.|[^"\\])*"|<[^>]*>|\S+)', line)
    if not m:
        return ''
    val = m.group(1)
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1].replace(r'\"', '"').replace(r'\\', '\\')
    return val


def clean_address(addr):
    """Limpia una dirección de correo quitando signos de menor/mayor y comillas."""
    if not addr:
        return ''
    m = re.search(r'<([^>\s]+)>', addr)
    if m:
        return m.group(1).lower().strip()
    return addr.strip().strip('<>"\'').lower()


def extract_addr(rest):
    """Extrae la dirección destinataria de las líneas => o **."""
    prefix = rest.split(' R=', 1)[0].split(' T=', 1)[0]
    m = re.search(r'<([^>\s]+)>', prefix)
    if m:
        return m.group(1)
    return rest.split(' ', 1)[0] or '(desconocido)'


def clean_subject(value):
    """Decodifica encabezados MIME encoded-word en asuntos."""
    if not value:
        return '(asunto no registrado)'
    try:
        decoded = str(make_header(decode_header(value)))
    except (ValueError, UnicodeError, LookupError):
        decoded = value
    return re.sub(r'\s+', ' ', decoded).strip()[:160]


def is_outbound_arrival(sender, protocol, auth, user_field, ip):
    """Determina si un correo recibido por Exim corresponde a un envío local/saliente."""
    if sender == '<>':
        return False
    if protocol == 'spam-scanned':
        return False
    if auth or protocol in AUTH_PROTOCOLS:
        return True
    if protocol in LOCAL_PROTOCOLS:
        return True
    if user_field and user_field.lower() not in FILTER_USERS:
        return True
    if ip in ('127.0.0.1', '::1'):
        return True
    return False


def get_log_files(stems, since=None):
    """Localiza los archivos de log actuales y rotados (incluidos .gz)."""
    cutoff = (since - dt.timedelta(hours=4)).timestamp() if since else None
    result = set()
    for stem in stems:
        for name in glob.glob(stem + '*'):
            if os.path.isfile(name) and (
                name == stem
                or re.search(r'^' + re.escape(stem) + r'(?:\.\d+|[-.]\d{8}|-\d{4}-\d\d-\d\d)(?:\.gz)?\Z', name)
            ):
                if cutoff is not None:
                    try:
                        if os.path.getmtime(name) < cutoff:
                            continue
                    except OSError:
                        pass
                result.add(name)
    return sorted(result, key=lambda p: (os.path.getmtime(p) if os.path.exists(p) else 0, p))


def read_lines(paths, counter_dict):
    """Generador que lee líneas de múltiples archivos (texto plano o gzip)."""
    for path in paths:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                counter_dict['files_read'] += 1
                for line in fh:
                    yield line.rstrip('\n')
        except (OSError, EOFError) as exc:
            print('AVISO: No se pudo leer %s: %s' % (path, exc), file=sys.stderr)


def parse_syslog_time(line, now):
    """Convierte timestamp clásico de syslog o ISO8601 a datetime."""
    m = ISOLOG_LINE.match(line)
    if m:
        try:
            return dt.datetime.strptime(m.group(1).replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None
    m = SYSLOG_LINE.match(line)
    if not m or m.group(1) not in MONTHS:
        return None
    month, day, clock = MONTHS[m.group(1)], int(m.group(2)), m.group(3)
    try:
        candidate = dt.datetime.strptime('%04d-%02d-%02d %s' % (now.year, month, day, clock), '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None
    if candidate > now + dt.timedelta(days=1):
        try:
            candidate = candidate.replace(year=candidate.year - 1)
        except ValueError:
            return None
    return candidate


def parse_cpanel_access_time(time_str):
    """Convierte timestamp de cPanel access_log ej [11/02/2026:16:04:03 -0000] a datetime."""
    # [11/Feb/2026:16:04:03 -0000] o [11/02/2026:16:04:03 -0000]
    m = re.search(r'\[(\d{1,2})/(\w{2,3})/(\d{4}):(\d\d:\d\d:\d\d)', time_str)
    if not m:
        return None
    day, month_str, year, clock = m.groups()
    if month_str.isdigit():
        month = int(month_str)
    else:
        month = MONTHS.get(month_str.capitalize(), None)
        if not month:
            return None
    try:
        return dt.datetime.strptime('%04d-%02d-%02d %s' % (int(year), month, int(day), clock), '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None


def search_webmail_forwarder(access_logs, target_user, target_emails, send_times, window_seconds=120):
    """
    Busca en los logs de acceso web (cPanel / DirectAdmin) la línea correspondiente
    a peticiones hechas desde 127.0.0.1 en torno a la hora de envío, y extrae X-Forwarded-For.
    Devuelve diccionario: {ip_real: count} y lista de líneas de evidencia completas.
    """
    matched_forwarders = collections.Counter()
    raw_evidence = []
    seen_lines = set()

    for path in access_logs:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    # Nos interesan accesos con X-Forwarded-For
                    if 'X-Forwarded-For:' not in line and 'X-Forwarded-For' not in line:
                        continue

                    # Verificamos si coincide usuario o cuenta
                    line_matches_target = False
                    if target_user and target_user.lower() in line.lower():
                        line_matches_target = True
                    if not line_matches_target and target_emails:
                        for em in target_emails:
                            if em.lower() in line.lower():
                                line_matches_target = True
                                break
                    if not line_matches_target and not target_user and not target_emails:
                        # Modo general: considerar accesos relevantes
                        line_matches_target = True

                    if not line_matches_target:
                        continue

                    # Extraer timestamp de la línea
                    time_stamp = parse_cpanel_access_time(line)
                    if time_stamp and send_times:
                        # Verificar si cae dentro de la ventana de alguno de los envíos
                        is_near_send = False
                        for st in send_times:
                            if abs((time_stamp - st).total_seconds()) <= window_seconds:
                                is_near_send = True
                                break
                        if not is_near_send and len(send_times) > 0:
                            continue

                    # Extraer IP de X-Forwarded-For
                    m_fwd = X_FORWARDED_FOR.search(line)
                    if m_fwd:
                        real_ip = m_fwd.group(1)
                        matched_forwarders[real_ip] += 1
                        if line not in seen_lines and len(raw_evidence) < 15:
                            seen_lines.add(line)
                            raw_evidence.append(line)
        except (OSError, EOFError):
            continue

    return matched_forwarders, raw_evidence


def build_report_section(out, title, counter, top=20, unit=''):
    out.append('\n' + title)
    out.append('-' * len(title))
    if not counter:
        out.append('Sin registros.')
        return
    for item, count in counter.most_common(top):
        out.append('{0:>8} {1} {2}'.format(count, unit, item))


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/01_abuse_mail_investigator.py)\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/01_abuse_mail_investigator.py) --email cuenta@dominio.com --days 5\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/01_abuse_mail_investigator.py) --domain dominio.com --top 30\n"
        "  python3 <(curl -sL https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/01_abuse_mail_investigator.py) --server directadmin\n"
    )
    parser = argparse.ArgumentParser(
        description='01. Abuse Mail Investigator — Auditoría Forense de Exim, Dovecot y Webmail (cPanel & DirectAdmin)',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', choices=['cpanel', 'directadmin', 'auto'], default='auto',
                        help='Tipo de servidor (cpanel o directadmin). Auto por defecto.')
    parser.add_argument('--email', help='Filtrar específicamente por cuenta de correo (ej. info@empresa.com)')
    parser.add_argument('--domain', help='Filtrar por dominio completo (ej. empresa.com)')
    parser.add_argument('--days', type=int, default=3, help='Días hacia atrás a investigar (por defecto 3)')
    parser.add_argument('--top', type=int, default=20, help='Límite de elementos por sección (por defecto 20)')
    parser.add_argument('--output', help='Ruta para guardar el reporte en un archivo')
    parser.add_argument('--exim-log', help='Ruta personalizada de log de Exim')
    parser.add_argument('--mail-log', help='Ruta personalizada de log de Dovecot/Mail')
    parser.add_argument('--cpanel-access-log', help='Ruta personalizada de access_log de cPanel')
    parser.add_argument('--interactive', action='store_true', help='Iniciar en modo interactivo')

    # Si se ejecuta sin parámetros en una terminal interactiva, guiar al analista
    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  01. Abuse Mail Investigator — Asistente de Inicio")
        print("=" * 70)
        print("Selecciona cómo deseas ejecutar:")
        print("  1) Asistente interactivo guiado (Paso a paso) [Recomendado]")
        print("  2) Auditoría general del servidor (últimos 3 días)")
        print("  3) Ver opciones y ejemplos de comando (--help)")
        opt = input("Opción [1-3, def: 1]: ").strip()
        if opt == '3':
            parser.print_help()
            sys.exit(0)
        elif opt == '1' or opt == '':
            sys.argv.append('--interactive')

    args = parser.parse_args()

    # Selección de servidor
    server = args.server
    if args.interactive or server == 'auto':
        detected = detect_server_type()
        if args.interactive:
            server = prompt_server_type()
            # Preguntar por objetivo
            print("\n¿Qué objetivo deseas auditar?")
            print("  1) Auditoría general del servidor")
            print("  2) Una cuenta de correo específica")
            print("  3) Todo un dominio")
            obj_sel = input("Opción [1-3, def: 1]: ").strip()
            if obj_sel == '2':
                args.email = input("Ingresa la cuenta de correo (ej. info@empresa.com): ").strip()
            elif obj_sel == '3':
                args.domain = input("Ingresa el dominio (ej. empresa.com): ").strip()

            days_in = input("Días hacia atrás a analizar [por defecto 3]: ").strip()
            if days_in.isdigit():
                args.days = int(days_in)
        else:
            if detected != 'unknown':
                server = detected
            else:
                if sys.stdin.isatty():
                    server = prompt_server_type()
                else:
                    server = 'cpanel'  # Fallback si no es tty

    # Configuración de rutas según servidor
    if server == 'cpanel':
        exim_stem = args.exim_log or '/var/log/exim_mainlog'
        mail_stems = [args.mail_log or '/var/log/maillog', '/var/log/secure']
        cpanel_access_stems = [
            args.cpanel_access_log or '/usr/local/cpanel/logs/access_log',
            '/var/cpanel/roundcube/log/sendmail.log',
            '/var/cpanel/roundcube/log/errors.log'
        ]
    else:  # directadmin
        exim_stem = args.exim_log or '/var/log/exim/mainlog'
        mail_stems = [args.mail_log or '/var/log/maillog', '/var/log/dovecot.log', '/var/log/messages']
        cpanel_access_stems = [
            '/var/log/directadmin/system.log',
            '/var/log/roundcube/sendmail.log',
            '/var/log/roundcube/errors.log'
        ]

    target_email = clean_address(args.email) if args.email else None
    target_domain = args.domain.lower().strip() if args.domain else None

    # Si se especificó email pero no domain, deducir domain
    if target_email and '@' in target_email and not target_domain:
        target_domain = target_email.split('@', 1)[-1]

    now = dt.datetime.now()
    since = now - dt.timedelta(days=args.days)

    exim_files = get_log_files([exim_stem], since=since)
    mail_files = get_log_files(mail_stems, since=since)
    access_files = get_log_files(cpanel_access_stems, since=since)

    if not exim_files:
        print("[!] ERROR: No se encontraron archivos de log de Exim en la ruta '%s'." % exim_stem, file=sys.stderr)
        print("    Verifica la ruta o utiliza --exim-log /ruta/al/log", file=sys.stderr)
        sys.exit(1)

    counters = collections.Counter()
    arrivals = {}  # msgid -> dict
    failures = []  # list of dicts
    deferred = []
    deliveries = collections.Counter()
    send_times = []

    # Métricas y agrupaciones
    senders = collections.Counter()
    subjects = collections.Counter()
    subject_details = collections.defaultdict(list)
    ips = collections.Counter()
    auth_users = collections.Counter()
    cwd_dirs = collections.Counter()
    php_scripts = collections.Counter()
    recipients = collections.Counter()
    fail_reasons = collections.Counter()
    defer_reasons = collections.Counter()

    # Evidencia cruda para Iris
    raw_evidence_exim_arrivals = []
    raw_evidence_exim_deliveries = []
    raw_evidence_exim_failures = []
    raw_evidence_cwd = []
    raw_evidence_dovecot = []

    has_localhost_sender = False

    # 1. Procesar Exim Mainlog
    for line in read_lines(exim_files, counters):
        # Captura de cwd= (ejecución de scripts php/cgi)
        m_cwd = EXIM_CWD.match(line)
        if m_cwd:
            stamp, cwd, cmd_args = m_cwd.groups()
            try:
                t_cwd = dt.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
            if since <= t_cwd <= now:
                # Filtrar si hay objetivo específico
                match_target = True
                if target_domain and target_domain not in cwd and target_domain not in cmd_args:
                    match_target = False
                if match_target and cwd not in IGNORE_CWD and not re.search(r'(?<!\S)-(?:Mc|q\S*)\b', cmd_args):
                    cwd_dirs[cwd] += 1
                    counters['cwd_events'] += 1
                    if len(raw_evidence_cwd) < 10:
                        raw_evidence_cwd.append(line)
            continue

        m = EXIM_LINE.match(line)
        if not m:
            continue

        stamp, msgid, flag, rest = m.groups()
        try:
            timestamp = dt.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue

        if not (since <= timestamp <= now):
            continue

        if flag == '<=':
            # Llegada de mensaje
            sender = clean_address(rest.split(' ', 1)[0])
            protocol = field('P', rest).lower()
            auth = field('A', rest)
            user_field = field('U', rest)
            subj = clean_subject(field('T', rest))

            h_field = re.search(r'(?<!\S)H=(.*?)(?=\s(?:[A-Z]|id|T)=|$)', rest)
            ipmatch = IP_BRACKETS.search(h_field.group(1)) if h_field else None
            ip_val = ipmatch.group(1) if ipmatch else ''

            # Filtros por cuenta o dominio
            if target_email and sender != target_email and auth.lower() != target_email:
                continue
            if target_domain and (target_domain not in sender and target_domain not in auth.lower()):
                continue

            if ip_val in ('127.0.0.1', '::1'):
                has_localhost_sender = True

            arrivals[msgid] = {
                'timestamp': timestamp,
                'sender': sender,
                'auth': auth,
                'user': user_field,
                'ip': ip_val,
                'subject': subj,
                'raw': line
            }
            send_times.append(timestamp)
            counters['accepted'] += 1
            senders[sender or '(desconocido)'] += 1
            if subj != '(asunto no registrado)':
                subjects[subj] += 1
                subject_details[subj].append((timestamp.strftime('%Y-%m-%d %H:%M:%S'), sender, ip_val))
            if ip_val:
                ips[ip_val] += 1
            if auth:
                auth_users[auth] += 1

            if len(raw_evidence_exim_arrivals) < 10:
                raw_evidence_exim_arrivals.append(line)

        elif flag in ('=>', '->'):
            # Entrega realizada
            if msgid not in arrivals and (target_email or target_domain):
                continue
            dest = clean_address(extract_addr(rest))
            recipients[dest] += 1
            counters['delivery_ok'] += 1
            if len(raw_evidence_exim_deliveries) < 10:
                raw_evidence_exim_deliveries.append(line)

        elif flag == '**':
            # Fallo permanente (Rebote / Rechazo)
            if msgid not in arrivals and (target_email or target_domain):
                continue
            dest = clean_address(extract_addr(rest))
            reason = rest.split(' SMTP error from remote mail server', 1)
            detail = 'SMTP error from remote mail server' if len(reason) > 1 else (rest[-120:] or '(sin detalle)')
            fail_reasons[detail] += 1
            counters['delivery_fail'] += 1
            failures.append({'msgid': msgid, 'dest': dest, 'detail': detail, 'raw': line})
            if len(raw_evidence_exim_failures) < 10:
                raw_evidence_exim_failures.append(line)

        elif flag == '==':
            # Diferimiento
            if msgid not in arrivals and (target_email or target_domain):
                continue
            detail = rest[-120:] or '(sin detalle)'
            defer_reasons[detail] += 1
            counters['delivery_defer'] += 1

    # 2. Correlación Dovecot (IMAP/POP3)
    dovecot_logins_ok = collections.Counter()
    dovecot_logins_fail = collections.Counter()
    dovecot_ips = collections.Counter()
    dovecot_ip_match_sender = collections.Counter()

    sender_ips_set = set(ips.keys())

    if mail_files:
        for line in read_lines(mail_files, counters):
            ts = parse_syslog_time(line, now)
            if not ts or not (since <= ts <= now):
                continue
            if 'dovecot' not in line.lower():
                continue

            failed = bool(re.search(r'auth(?:entication)? failed|authentication failure|password mismatch|unknown user|user not found|auth_failed', line, re.I))
            success = bool(re.search(r'\b(?:Login:|Logged in:)\s*user=', line, re.I))
            if not failed and not success:
                continue

            u_match = re.search(r'\buser=<([^>]*)>|\buser=([^\s,;]+)', line)
            user_found = clean_address(u_match.group(1) or u_match.group(2)) if u_match else ''
            ip_match = re.search(r'\brip=([^,\s]+)', line)
            ip_found = ip_match.group(1) if ip_match else ''

            # Filtro por usuario o dominio
            if target_email and user_found and user_found != target_email:
                continue
            if target_domain and user_found and target_domain not in user_found:
                continue

            if ip_found:
                dovecot_ips[ip_found] += 1
                if ip_found in sender_ips_set:
                    dovecot_ip_match_sender[ip_found] += 1

            if success:
                counters['dovecot_ok'] += 1
                dovecot_logins_ok[user_found or '(desconocido)'] += 1
                if len(raw_evidence_dovecot) < 10:
                    raw_evidence_dovecot.append(line)
            if failed:
                counters['dovecot_fail'] += 1
                dovecot_logins_fail[user_found or '(desconocido)'] += 1
                if len(raw_evidence_dovecot) < 10:
                    raw_evidence_dovecot.append(line)

    # 3. Detección Webmail & X-Forwarded-For si hubo envíos desde 127.0.0.1
    forwarder_ips = collections.Counter()
    raw_evidence_forwarders = []

    if has_localhost_sender or (target_email and '127.0.0.1' in ips):
        target_emails = [target_email] if target_email else list(senders.keys())[:10]
        # Determinar usuario de cPanel si es posible
        cpanel_user = target_email.split('@')[0] if target_email else None
        forwarder_ips, raw_evidence_forwarders = search_webmail_forwarder(
            access_files,
            target_user=cpanel_user,
            target_emails=target_emails,
            send_times=send_times,
            window_seconds=180
        )

    # Construcción del Reporte
    out = []
    out.append("=" * 80)
    out.append("01. ABUSE MAIL INVESTIGATOR — REPORTE DE AUDITORÍA FORENSE")
    out.append("=" * 80)
    out.append("Servidor: %s" % server.upper())
    out.append("Período analizado: %s a %s (hora local)" % (
        since.strftime('%Y-%m-%d %H:%M:%S'),
        now.strftime('%Y-%m-%d %H:%M:%S')
    ))
    if target_email:
        out.append("Filtro específico por cuenta: %s" % target_email)
    elif target_domain:
        out.append("Filtro específico por dominio: %s" % target_domain)
    else:
        out.append("Modo: Análisis general del servidor")
    out.append("Archivos leídos: Exim (%d) | Dovecot/Syslog (%d) | Web/Paneles (%d)" % (
        len(exim_files), len(mail_files), len(access_files)
    ))
    out.append("-" * 80)
    out.append("RESUMEN OPERATIVO:")
    out.append("  Envíos contabilizados (<=):        %d" % counters['accepted'])
    out.append("  Entregas realizadas (=> / ->):     %d" % counters['delivery_ok'])
    out.append("  Fallos / Rebotes permanentes (**): %d" % counters['delivery_fail'])
    out.append("  Diferimientos / Retrasos (==):     %d" % counters['delivery_defer'])
    out.append("  Ejecuciones de script (cwd=):      %d" % counters['cwd_events'])
    out.append("  Logins Dovecot exitosos:           %d" % counters['dovecot_ok'])
    out.append("  Fallos autenticación Dovecot:      %d" % counters['dovecot_fail'])
    out.append("=" * 80)

    # Secciones detalladas
    build_report_section(out, "TOP REMITENTES (From / <=)", senders, args.top, unit='correos')
    build_report_section(out, "TOP CUENTAS AUTENTICADAS (A= en Exim)", auth_users, args.top, unit='envíos')
    build_report_section(out, "TOP IPs ORIGEN EN EXIM (H=)", ips, args.top, unit='envíos')

    if '127.0.0.1' in ips or '::1' in ips:
        out.append("\n[!] ALERTA: Se detectaron envíos originados desde localhost (127.0.0.1 / Webmail).")
        if forwarder_ips:
            build_report_section(
                out,
                "IPs REALES DETECTADAS VÍA X-FORWARDED-FOR (Webmail / cPanel Access Log)",
                forwarder_ips,
                args.top,
                unit='solicitudes'
            )
        else:
            out.append("    No se localizaron registros correlacionados en access_log para la ventana de tiempo.")

    build_report_section(out, "TOP ASUNTOS REPETIDOS (T=)", subjects, args.top, unit='repeticiones')
    build_report_section(out, "TOP DESTINATARIOS (=> / ->)", recipients, args.top, unit='recibidos')
    build_report_section(out, "TOP DIRECTORIOS DE EJECUCIÓN (cwd= scripts PHP/CGI)", cwd_dirs, args.top, unit='invocaciones')
    build_report_section(out, "TOP MOTIVOS DE RECHAZO / REBOTE (**)", fail_reasons, args.top, unit='eventos')
    build_report_section(out, "TOP MOTIVOS DE DIFERIMIENTO (==)", defer_reasons, args.top, unit='eventos')

    # Correlación Dovecot
    out.append("\n" + "=" * 80)
    out.append("CORRELACIÓN DOVECOT (IMAP / POP3):")
    out.append("=" * 80)
    if dovecot_ip_match_sender:
        build_report_section(
            out,
            "[!] COINCIDENCIAS: IPs que enviaron correos y registraron accesos IMAP/POP3",
            dovecot_ip_match_sender,
            args.top,
            unit='coincidencias'
        )
    else:
        out.append("[i] No se encontraron IPs de envío que coincidan exactamente con logins IMAP/POP3 en este período.")

    build_report_section(out, "Logins Dovecot Exitosos por Usuario", dovecot_logins_ok, args.top, unit='logins')
    build_report_section(out, "Intentos Fallidos Dovecot por Usuario", dovecot_logins_fail, args.top, unit='fallos')
    build_report_section(out, "IPs con Accesos Dovecot", dovecot_ips, args.top, unit='conexiones')

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOG)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS / LOG SNIPPETS COMPLETOS)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso de IRIS:")
    out.append("=" * 80)

    # 1. Snippets de Llegada Exim
    out.append("\n--- [EVIDENCIA 1/5] REGISTROS DE RECEPCIÓN / ENVÍO EN EXIM (<=) ---")
    if raw_evidence_exim_arrivals:
        for line in raw_evidence_exim_arrivals[:8]:
            out.append(line)
    else:
        out.append("(Sin registros de recepción disponibles)")

    # 2. Snippets de Entrega
    out.append("\n--- [EVIDENCIA 2/5] REGISTROS DE ENTREGA EN EXIM (=>) ---")
    if raw_evidence_exim_deliveries:
        for line in raw_evidence_exim_deliveries[:6]:
            out.append(line)
    else:
        out.append("(Sin entregas registradas)")

    # 3. Snippets de Rebotes/Fallos
    out.append("\n--- [EVIDENCIA 3/5] REGISTROS DE RECHAZO / REBOTE EN EXIM (**) ---")
    if raw_evidence_exim_failures:
        for line in raw_evidence_exim_failures[:6]:
            out.append(line)
    else:
        out.append("(Sin rebotes ni fallos registrados)")

    # 4. Snippets de X-Forwarded-For Webmail
    out.append("\n--- [EVIDENCIA 4/5] CORRELACIÓN WEBMAIL / X-FORWARDED-FOR (cPanel / DA Access Log) ---")
    if raw_evidence_forwarders:
        for line in raw_evidence_forwarders[:8]:
            out.append(line)
    else:
        out.append("(No se registraron líneas de X-Forwarded-For o no aplicó para este caso)")

    # 5. Snippets de Dovecot y Scripts cwd
    out.append("\n--- [EVIDENCIA 5/5] REGISTROS DOVECOT / SCRIPTS CWD ---")
    if raw_evidence_cwd:
        out.append("[Scripts CWD detectados]")
        for line in raw_evidence_cwd[:5]:
            out.append(line)
    if raw_evidence_dovecot:
        out.append("[Logins Dovecot detectados]")
        for line in raw_evidence_dovecot[:5]:
            out.append(line)
    if not raw_evidence_cwd and not raw_evidence_dovecot:
        out.append("(Sin eventos de cwd ni logins Dovecot destacados)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    final_report = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(final_report)
            print("[+] Reporte de auditoría guardado exitosamente en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar el reporte: %s" % e, file=sys.stderr)
            print(final_report)
    else:
        print(final_report)


if __name__ == '__main__':
    main()

