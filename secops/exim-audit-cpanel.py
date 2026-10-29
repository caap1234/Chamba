#!/usr/bin/env python3
"""Auditoría de envíos salientes en Exim y Dovecot para cPanel/WHM (/var/log/exim_mainlog). Solo lectura.

Compatible con Python 3.4+ (sin f-strings ni subíndices de Match).
Por defecto filtra únicamente CORREO SALIENTE / LOCAL (autenticado por SMTP,
generado por scripts/procesos locales o desde localhost), ignorando correo entrante.

Ejecución directa:
  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/secops/exim-audit-cpanel.py)
  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/secops/exim-audit-cpanel.py) --days 3 --top 30
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

EXIM = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?:\[\d+\]\s+)?(\S+)\s+(<=|=>|->|\*\*|==|Completed)\s*(.*)$')
EXIM_CWD = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?:\[\d+\]\s+)?(?:\S+\s+)?cwd=(\S+)\s+\d+\s+args:\s*(.*)$')
SYSLOG = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+')
ISOLOG = re.compile(r'^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?\s+')
IP = re.compile(r'\[([0-9a-fA-F:.]+)\]')
HOME_USER = re.compile(r'^/home\d*/([^/\s]+)')
MONTHS = {m: i for i, m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1)}
AUTH_PROTOCOLS = {'esmtpa', 'esmtpsa', 'smtpa', 'smtpsa', 'utf8esmtpa', 'utf8esmtpsa'}
LOCAL_PROTOCOLS = {'local', 'local-bsmtp', 'local-esmtp'}
FILTER_USERS = {'mail', 'exim', 'mailnull', 'debian-exim', 'dovecot'}
SYSTEM_USERS = {'root', 'mailnull', 'exim', 'cpanel', 'nobody', 'dovecot', 'mailman'}
IGNORE_CWD = {'/var/spool/exim', '/etc/csf', '/var/spool/cron', '/usr/local/cpanel/whostmgr/docroot'}


def field(key, line):
    m = re.search(r'(?<!\S)' + re.escape(key) + r'=("(?:\\.|[^"\\])*"|<[^>]*>|\S+)', line)
    if not m:
        return ''
    val = m.group(1)
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1].replace(r'\"', '"').replace(r'\\', '\\')
    return val


def extract_addr(rest):
    prefix = rest.split(' R=', 1)[0].split(' T=', 1)[0]
    m = re.search(r'<([^>\s]+)>', prefix)
    if m:
        return m.group(1)
    return rest.split(' ', 1)[0] or '(desconocido)'


def is_outbound_arrival(sender, protocol, auth, user_field, ip):
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


def load_userdomains(path='/etc/userdomains'):
    mapping = {}
    if not os.path.isfile(path):
        return mapping
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                if ':' not in line:
                    continue
                dom, user = line.split(':', 1)
                dom = dom.strip().lower()
                user = user.strip()
                if dom and user and dom != '*':
                    mapping[dom] = user
    except OSError:
        pass
    return mapping


def resolve_cpuser(auth_user, local_user, sender, userdomains):
    if local_user and local_user not in SYSTEM_USERS:
        return local_user
    for candidate in (auth_user, sender):
        if '@' in candidate:
            dom = candidate.rsplit('@', 1)[-1].lower().strip('>')
            if dom in userdomains:
                return userdomains[dom]
    if auth_user and '@' not in auth_user and auth_user not in SYSTEM_USERS:
        return auth_user
    return ''


def files_for(stems, since=None):
    cutoff = (since - dt.timedelta(hours=2)).timestamp() if since else None
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
    # Ordenar del más antiguo al más reciente para registrar '<=' antes de '=>', '**' o '=='
    return sorted(result, key=lambda p: (os.path.getmtime(p) if os.path.exists(p) else 0, p))


def lines_from(paths, counters):
    for path in paths:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                counters['files_read'] += 1
                for line in fh:
                    yield line.rstrip('\n')
        except (OSError, EOFError) as exc:
            print('AVISO: no se pudo leer %s: %s' % (path, exc), file=sys.stderr)


def subject(value):
    if not value:
        return '(asunto no registrado)'
    try:
        decoded = str(make_header(decode_header(value)))
    except (ValueError, UnicodeError, LookupError):
        decoded = value
    return re.sub(r'\s+', ' ', decoded).strip()[:160]


def time_syslog(line, now):
    m = ISOLOG.match(line)
    if m:
        try:
            return dt.datetime.strptime(m.group(1).replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None
    m = SYSLOG.match(line)
    if not m or m.group(1) not in MONTHS:
        return None
    month, day, clock = MONTHS[m.group(1)], int(m.group(2)), m.group(3)
    try:
        candidate = dt.datetime.strptime('%04d-%02d-%02d %s' % (now.year, month, day, clock), '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None
    # Syslog clásico carece de año: inferir el último día coincidente no futuro.
    if candidate > now + dt.timedelta(days=1):
        try:
            candidate = candidate.replace(year=candidate.year - 1)
        except ValueError:
            return None
    return candidate


def report_section(out, title, counter, top, unit=''):
    out.append('\n' + title)
    out.append('-' * len(title))
    if not counter:
        out.append('Sin datos disponibles.')
    for name, count in counter.most_common(top):
        out.append('{0:>8} {1} {2}'.format(count, unit, name))


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    epilog = (
        'Ejemplos de uso:\n'
        '  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/secops/exim-audit-cpanel.py)\n'
        '  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/secops/exim-audit-cpanel.py) --days 3 --top 30\n'
    )
    parser = argparse.ArgumentParser(
        description='Reporte de auditoría de envíos salientes y abuso en Exim + Dovecot para cPanel/WHM (solo lectura)',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--days', type=int, default=7, help='Días hacia atrás (por defecto 7)')
    parser.add_argument('--top', type=int, default=20, help='Líneas por ranking (por defecto 20)')
    parser.add_argument('--output', help='Archivo de salida; si se omite, imprime en pantalla')
    parser.add_argument('--exim-log', default='/var/log/exim_mainlog', help='Ruta base de log Exim en cPanel (por defecto /var/log/exim_mainlog)')
    parser.add_argument('--mail-log', default='/var/log/maillog', help='Base de log Dovecot (por defecto /var/log/maillog)')
    parser.add_argument('--include-inbound', action='store_true', help='Incluir también correos entrantes externos (por defecto solo analiza envíos salientes/locales)')
    args = parser.parse_args()
    if not (1 <= args.days <= 3660 and 1 <= args.top <= 1000):
        parser.error('--days o --top fuera de rango')
    now = dt.datetime.now()
    since = now - dt.timedelta(days=args.days)
    exim_files = files_for([args.exim_log], since=since)
    mail_files = files_for([args.mail_log, '/var/log/mail.log', '/var/log/secure'], since=since)
    if not exim_files:
        parser.error('No se encontró exim_mainlog en el rango solicitado (ruta normal: /var/log/exim_mainlog)')

    userdomains = load_userdomains()
    stats = collections.Counter()
    arrivals = {}  # ID -> info (solo mensajes contabilizados: salientes o todos si --include-inbound)
    failures = set()
    deferred = set()
    recipients = collections.Counter()
    cwd_dirs = collections.Counter()
    cpanel_accounts = collections.Counter()
    auth_smtp_fail = collections.Counter()
    auth_smtp_ips = collections.Counter()
    auth_dovecot_user = collections.Counter()
    auth_dovecot_ip = collections.Counter()
    auth_dovecot_success = collections.Counter()
    hourly = collections.Counter()
    fail_reason = collections.Counter()
    deferrals_reason = collections.Counter()

    for line in lines_from(exim_files, stats):
        m = EXIM.match(line)
        if not m:
            # Detectar directorios de ejecución (cwd=) de scripts PHP / sendmail en cPanel
            mcwd = EXIM_CWD.match(line)
            if mcwd:
                stamp, cwd, cmd_args = mcwd.groups()
                try:
                    timestamp = dt.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                if since <= timestamp <= now:
                    if cwd not in IGNORE_CWD and not re.search(r'(?<!\S)-(?:Mc|q\S*)\b', cmd_args):
                        cwd_dirs[cwd] += 1
                        stats['cwd_events'] += 1
                        hm = HOME_USER.match(cwd)
                        if hm and hm.group(1) not in SYSTEM_USERS:
                            cpanel_accounts['%s (vía cwd=/home/...)' % hm.group(1)] += 1
                continue

            # Rechazos de autenticación SMTP (dovecot_login / dovecot_plain)
            if 'authenticator failed' in line.lower() or re.search(r'(?:authentication|auth) failed', line, re.I):
                try:
                    timestamp = dt.datetime.strptime(line[:19], '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                if since <= timestamp <= now:
                    stats['smtp_auth_fail'] += 1
                    ip = IP.search(line)
                    if ip:
                        auth_smtp_ips[ip.group(1)] += 1
                    user = re.search(r'(?:set_id|user(?:name)?)[=:]\s*<?([^>\s,]+)', line, re.I)
                    if user:
                        auth_smtp_fail[user.group(1).rstrip(')')] += 1
            continue

        stamp, msgid, flag, rest = m.groups()
        try:
            timestamp = dt.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
        if not (since <= timestamp <= now):
            continue
        if flag == '<=':
            sender = rest.split(' ', 1)[0] or '(desconocido)'
            if msgid in arrivals:
                continue
            protocol = field('P', rest).lower()
            auth = field('A', rest)
            user_field = field('U', rest)
            # IP origen en H=, evitando confundirla con el campo I= (IP del servidor).
            h = re.search(r'(?<!\S)H=(.*?)(?=\s(?:[A-Z]|id|T)=|$)', rest)
            ipmatch = IP.search(h.group(1)) if h else None
            ip_val = ipmatch.group(1) if ipmatch else ''
            if sender == '<>':
                stats['bounces_generated'] += 1
            outbound = is_outbound_arrival(sender, protocol, auth, user_field, ip_val)
            if not outbound and not args.include_inbound:
                if sender != '<>':
                    stats['inbound_ignored'] += 1
                continue
            arrivals[msgid] = dict(
                sender=sender,
                auth=auth,
                user=user_field,
                ip=ip_val,
                subject=subject(field('T', rest)),
                local=protocol in LOCAL_PROTOCOLS or (bool(user_field) and user_field.lower() not in FILTER_USERS),
            )
            stats['accepted'] += 1
            hourly[timestamp.strftime('%Y-%m-%d %H:00')] += 1
        elif flag in ('=>', '->'):
            if not args.include_inbound and msgid not in arrivals:
                continue
            dest = extract_addr(rest)
            recipients[dest] += 1
            stats['delivery_ok'] += 1
        elif flag == '**':
            if not args.include_inbound and msgid not in arrivals:
                continue
            dest = extract_addr(rest)
            failures.add((msgid, dest))
            stats['delivery_fail'] += 1
            reason = rest.split(' SMTP error from remote mail server', 1)
            fail_reason['SMTP error from remote mail server' if len(reason) > 1 else (rest[-110:] or '(sin detalle)')] += 1
        elif flag == '==':
            if not args.include_inbound and msgid not in arrivals:
                continue
            dest = extract_addr(rest)
            deferred.add((msgid, dest))
            stats['delivery_defer_events'] += 1
            deferrals_reason[rest[-110:] or '(sin detalle)'] += 1

    senders = collections.Counter()
    subjects = collections.Counter()
    subject_actors = collections.defaultdict(collections.Counter)
    ips = collections.Counter()
    local_users = collections.Counter()
    mail_auth = collections.Counter()
    auth_ips_by_user = collections.defaultdict(set)
    failed_by_sender = collections.Counter()
    deferred_by_sender = collections.Counter()
    bounced_messages = set()

    for msgid, data in arrivals.items():
        senders[data['sender']] += 1
        auth_user = data['auth'].split(':', 1)[-1] if data['auth'] else ''
        cpuser = resolve_cpuser(auth_user, data['user'], data['sender'], userdomains)
        if cpuser:
            cpanel_accounts['%s (envíos <=)' % cpuser] += 1
        actor = auth_user or ('U=%s' % data['user'] if data['local'] and data['user'] else data['sender'])
        if data['subject'] != '(asunto no registrado)':
            subjects[data['subject']] += 1
            subject_actors[data['subject']][actor] += 1
        if data['ip']:
            ips[data['ip']] += 1
        if data['local']:
            local_users[data['user'] or '(usuario no identificado)'] += 1
        if auth_user:
            mail_auth[auth_user] += 1
            if data['ip']:
                auth_ips_by_user[auth_user].add(data['ip'])

    subjects_annotated = collections.Counter()
    for subj_text, total_count in subjects.items():
        top_actor, actor_count = subject_actors[subj_text].most_common(1)[0]
        subjects_annotated['%s  [principal: %s (%d)]' % (subj_text, top_actor, actor_count)] = total_count

    auth_multi_ip = collections.Counter()
    for user, ip_set in auth_ips_by_user.items():
        if len(ip_set) > 1:
            auth_multi_ip['%s (%d envíos)' % (user, mail_auth[user])] = len(ip_set)

    for msgid, dest in failures:
        if msgid in arrivals:
            failed_by_sender[arrivals[msgid]['sender']] += 1
            bounced_messages.add(msgid)
    for msgid, dest in deferred:
        if msgid in arrivals:
            deferred_by_sender[arrivals[msgid]['sender']] += 1

    if mail_files:
        for line in lines_from(mail_files, stats):
            timestamp = time_syslog(line, now)
            if not timestamp or not (since <= timestamp <= now):
                continue
            if 'dovecot' not in line.lower():
                continue
            failed = bool(re.search(r'auth(?:entication)? failed|authentication failure|password mismatch|unknown user|user not found|auth_failed', line, re.I))
            success = bool(re.search(r'\b(?:Login:|Logged in:)\s*user=', line, re.I))
            if not failed and not success:
                continue
            user = re.search(r'\buser=<([^>]*)>|\buser=([^\s,;]+)', line)
            ip = re.search(r'\brip=([^,\s]+)', line)
            username = (user.group(1) or user.group(2)) if user else '(usuario no indicado)'
            if failed:
                stats['dovecot_auth_fail'] += 1
                auth_dovecot_user[username] += 1
                if ip:
                    auth_dovecot_ip[ip.group(1)] += 1
            if success:
                stats['dovecot_login_ok'] += 1
                auth_dovecot_success[username] += 1

    modo = 'SALIENTE + ENTRANTE (--include-inbound)' if args.include_inbound else 'SOLO ENVÍOS SALIENTES / LOCALES (entrantes filtrados)'
    out = [
        'REPORTE DE AUDITORÍA EXIM / DOVECOT (cPanel/WHM)',
        'Modo de análisis: %s' % modo,
        'Período: %s a %s (hora local del servidor)' % (
            since.strftime('%Y-%m-%d %H:%M:%S'),
            now.strftime('%Y-%m-%d %H:%M:%S'),
        ),
        'Archivos Exim (%s): %d | registros mail/secure: %d' % (args.exim_log, len(exim_files), len(mail_files)),
        'Envíos salientes/locales contabilizados (<=): %d' % stats['accepted'],
        'Correos entrantes externos ignorados: %d' % stats['inbound_ignored'],
        'Rebotes del sistema (<>) detectados: %d' % stats['bounces_generated'],
        'Invocaciones de scripts/directorios (cwd=): %d' % stats['cwd_events'],
        'Entregas de envíos contabilizados (=> / ->): %d' % stats['delivery_ok'],
        'Fallos permanentes de envíos (**): %d' % stats['delivery_fail'],
        'Diferimientos de envíos (==): %d' % stats['delivery_defer_events'],
        'Envíos con rebote atribuible: %d' % len(bounced_messages),
        'Fallos autenticación SMTP: %d' % stats['smtp_auth_fail'],
        'Fallos autenticación Dovecot: %d' % stats['dovecot_auth_fail'],
        'Accesos Dovecot correctos: %d' % stats['dovecot_login_ok'],
    ]
    report_section(out, 'HORAS CON MÁS ENVÍOS SALIENTES', hourly, args.top)
    report_section(out, 'TOP CUENTAS CPANEL ASOCIADAS (U=, /etc/userdomains o cwd=)', cpanel_accounts, args.top)
    report_section(out, 'TOP REMITENTES DE ENVÍOS SALIENTES (From <=)', senders, args.top)
    report_section(out, 'TOP ASUNTOS DE ENVÍOS Y EMISOR PRINCIPAL (T=)', subjects_annotated, args.top)
    report_section(out, 'TOP DIRECTORIOS DE EJECUCIÓN DE SCRIPTS (cwd= en Exim)', cwd_dirs, args.top)
    report_section(out, 'TOP USUARIOS SMTP AUTENTICADOS (dovecot_login / dovecot_plain)', mail_auth, args.top)
    report_section(out, 'TOP USUARIOS SMTP DESDE MÚLTIPLES IPs (posible cuenta comprometida)', auth_multi_ip, args.top, unit='IPs')
    report_section(out, 'TOP PROCESOS/USUARIOS DEL SISTEMA (U= en envíos)', local_users, args.top)
    report_section(out, 'TOP DESTINATARIOS DE ENVÍOS SALIENTES (=> / ->)', recipients, args.top)
    report_section(out, 'TOP IP ORIGEN DE ENVÍOS SALIENTES', ips, args.top)
    report_section(out, 'TOP REMITENTES POR DESTINATARIOS CON FALLO PERMANENTE (**)', failed_by_sender, args.top)
    report_section(out, 'TOP REMITENTES POR DESTINATARIOS DIFERIDOS (==)', deferred_by_sender, args.top)
    report_section(out, 'TOP USUARIOS CON FALLOS DOVECOT', auth_dovecot_user, args.top)
    report_section(out, 'TOP IP CON FALLOS DOVECOT', auth_dovecot_ip, args.top)
    report_section(out, 'TOP IP CON FALLOS SMTP AUTH', auth_smtp_ips, args.top)
    report_section(out, 'TOP USUARIOS CON FALLOS SMTP AUTH (si se registra usuario)', auth_smtp_fail, args.top)
    report_section(out, 'TOP USUARIOS CON LOGIN DOVECOT EXITOSO', auth_dovecot_success, args.top)
    report_section(out, 'TOP MOTIVOS DE FALLO EN ENVÍOS (**)', fail_reason, args.top)
    report_section(out, 'TOP MOTIVOS DE DIFERIMIENTO EN ENVÍOS (==)', deferrals_reason, args.top)
    if not subjects:
        out.append('\nAVISO: No se encontraron asuntos T= en envíos salientes. Revisar log_selector +subject en configuración Exim.')
    out.append('\nNOTA: Los correos entrantes externos fueron excluidos automáticamente. Use --include-inbound si desea incluirlos.')
    output = '\n'.join(out) + '\n'
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(output)
        print('Reporte guardado en ' + args.output)
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
