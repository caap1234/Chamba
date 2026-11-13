#!/usr/bin/env python3
"""Auditoría local y de solo lectura de enlaces (phishing/malware) en correos procesados por Exim (cPanel y DirectAdmin).

Extrae dominios alojados afectados y URLs de phishing cruzando /var/log/exim_mainlog con buzones Maildir.
Por defecto opera 100% en memoria con salida limpia y directa en terminal.

Ejecución directa One-Liner en terminal:
  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/secops/exim_phishing_links.py)
  o
  python3 <(curl -sL https://caap1234.github.io/tools/scripts/exim_phishing_links.py)
"""
import argparse
import csv
import datetime as dt
import glob
import gzip
import html
import os
import re
import socket
import subprocess
import sys
from collections import Counter
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_SUBJECT_RE = r'(Aviso de expiraci(?:\\363|ó|=F3|=C3=B3|o)n|expiraci[óo\\363]n de dominios|renovaci[óo\\363]n.*dominio|suspensi[óo\\363]n.*dominio|\bNeubox\b)'
ENTRY_RE = re.compile(r'^\S+\s+\S+\s+(?:\[\d+\]\s+)?([A-Za-z0-9]{5,}-[A-Za-z0-9]+-[A-Za-z0-9]+|\S+)\s+<=\s+(\S+)\s+(.*)$')
STATUS_RE = re.compile(r'^\S+\s+\S+\s+(?:\[\d+\]\s+)?([A-Za-z0-9]{5,}-[A-Za-z0-9]+-[A-Za-z0-9]+)\s+(=>|->|\*\*|==)\s+(.*)$')
EXIM_RE = re.compile(r'\bid\s*=?\s*([A-Za-z0-9]{5,}-[A-Za-z0-9]+-[A-Za-z0-9]+)\b')
IP_RE = re.compile(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]')
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
ACTION_RE = re.compile(r'renov|pagar|pago|payment|pay now|factura|actualizar|continuar|verificar|renew|expire|reactiv|soporte|acceso|login|iniciar|cuenta|desbloque', re.I)
CSV_FIELDS = ['server', 'exim_id', 'sender', 'recipient', 'subject', 'source_ip', 'url', 'url_host', 'anchor_text', 'action_link', 'mail_file']


def decode_subject(val):
    """Decodifica asuntos de Exim manejando escapes octales (\363) y encabezados MIME RFC 2047."""
    if not val:
        return ''
    try:
        val = re.sub(r'\\([0-7]{3})', lambda m: bytes([int(m.group(1), 8)]).decode('latin1', errors='replace'), val)
    except Exception:
        pass
    try:
        val = str(make_header(decode_header(val)))
    except Exception:
        pass
    return re.sub(r'\s+', ' ', val).strip()


class Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = []
        self.found = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            href = dict(attrs).get('href', '')
            self.active.append([href, ''])

    def handle_data(self, data):
        if self.active:
            self.active[-1][1] += data

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self.active:
            self.found.append(tuple(self.active.pop()))


def clean_url(raw_url):
    """Limpia y valida un enlace extraído."""
    if not raw_url:
        return ''
    u = html.unescape(raw_url).strip('\'" \t\r\n').rstrip('.,;)>]')
    if u.lower().startswith(('http://', 'https://')):
        return u
    return ''


def links_from_message(raw):
    """Extrae enlaces y texto de anclaje de un correo electrónico en bytes (soporta Base64/Quoted-Printable)."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    found = set()

    for part in message.walk():
        ctype = part.get_content_type()
        if ctype not in ('text/html', 'text/plain'):
            continue

        try:
            text = part.get_content()
            if not isinstance(text, str):
                text = str(text)
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b''
                text = payload.decode('utf-8', errors='replace')
            except Exception:
                continue

        if not text:
            continue

        if ctype == 'text/html' or '<a ' in text.lower():
            parser = Anchors()
            try:
                parser.feed(text)
                for url, label in parser.found:
                    u = clean_url(url)
                    if u:
                        anchor_text = ' '.join(label.split())[:180]
                        found.add((u, anchor_text or '(enlace web)'))
            except Exception:
                pass

            known_urls = {u for u, _ in found}
            for url in URL_RE.findall(text):
                u = clean_url(url)
                if u and u not in known_urls:
                    found.add((u, 'texto plano'))
        else:
            for url in URL_RE.findall(text):
                u = clean_url(url)
                if u:
                    found.add((u, 'texto plano'))

    return message, sorted(found)


def extract_ip_from_message(message):
    """Extrae la IP pública origen desde los encabezados Received si no estaba en el log."""
    for r in message.get_all('Received', []) or []:
        for ip in IP_RE.findall(str(r)):
            if not ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                  '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                  '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '0.')):
                return ip
    return ''


def read_log(fp):
    """Lee un archivo de log soportando compresión gzip."""
    op = gzip.open if fp.endswith('.gz') else open
    try:
        with op(fp, 'rt', encoding='utf-8', errors='replace') as f:
            yield from f
    except (OSError, EOFError):
        pass


def load_userdomains():
    """Carga mapeo dominio -> usuario cPanel desde /etc/userdomains."""
    ud = {}
    if os.path.exists('/etc/userdomains'):
        try:
            with open('/etc/userdomains', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line and not line.startswith('#'):
                        dom, user = line.split(':', 1)
                        ud[dom.strip().lower()] = user.strip()
        except OSError:
            pass
    return ud


def load_userhomes():
    """Carga mapeo usuario -> directorio home desde /etc/passwd."""
    homes = {}
    if os.path.exists('/etc/passwd'):
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 6:
                        homes[parts[0]] = parts[5]
        except OSError:
            pass
    return homes


def parse_recipient(rcpt):
    """Extrae usuario local, dominio y subcarpeta (ej. ventas+spam@dom.com -> ventas, dom.com, spam)."""
    clean = rcpt.strip('<> ').split()[0] if rcpt else ''
    if '@' not in clean:
        return '', '', ''
    local_part, domain = clean.rsplit('@', 1)
    folder = ''
    if '+' in local_part:
        local_part, folder = local_part.split('+', 1)
    return local_part.lower(), domain.lower(), folder.lower()


def select_ids(logs, allowed_senders, subject_pattern, cutoff_str=None, verbose=False):
    """Escanea los logs de Exim y selecciona los IDs que coinciden con los filtros, analizando estados de entrega."""
    raw_messages = {}
    source_ips = {}
    delivery_status = {}
    delivery_recipients = {}
    subject_re = re.compile(subject_pattern, re.I)

    for fp in logs:
        if verbose:
            print(f'[LOG] Analizando {fp}...', flush=True)
        for line in read_log(fp):
            if cutoff_str and len(line) >= 10 and line[:4].isdigit():
                if line[:10] < cutoff_str:
                    continue

            # 1. Rastrear eventos de llegada / reinyección (<=)
            m = ENTRY_RE.match(line)
            if m:
                exim_id, sender, rest = m.groups()

                ip_m = IP_RE.search(rest)
                if ip_m:
                    source_ips[exim_id] = ip_m.group(1)

                if allowed_senders:
                    domain = sender.lower().rsplit('@', 1)[-1]
                    if domain not in allowed_senders:
                        continue

                t = re.search(r'\bT="([^"]*)"', rest)
                if not t:
                    continue

                raw_subject = t.group(1)
                decoded_subj = decode_subject(raw_subject)

                if not subject_re.search(decoded_subj) and not subject_re.search(raw_subject):
                    continue

                parent_m = re.search(r'\bR=([A-Za-z0-9]{5,}-[A-Za-z0-9]+-[A-Za-z0-9]+)\b', rest)
                parent_id = parent_m.group(1) if parent_m else ''
                msgid_m = re.search(r'\bid=([^\s]+)', rest)
                msg_id = msgid_m.group(1).strip('<>') if msgid_m else ''
                src_ip = ip_m.group(1) if ip_m else source_ips.get(parent_id, '')
                r_m = re.search(r'\bfor\s+(.+)$', rest)

                raw_messages[exim_id] = {
                    'sender': sender,
                    'subject': decoded_subj or raw_subject,
                    'source_ip': src_ip,
                    'recipient': r_m.group(1).strip() if r_m else '',
                    'parent_id': parent_id,
                    'msg_id': msg_id
                }
                continue

            # 2. Rastrear estado de entrega (=>, **, ==)
            sm = STATUS_RE.match(line)
            if sm:
                eid, flag, rest = sm.groups()
                rcpt_m = re.search(r'<([^>]+)>', rest)
                if rcpt_m:
                    delivery_recipients[eid] = rcpt_m.group(1)

                if flag == '**':
                    reason = rest.split(':', 1)[-1].strip() if ':' in rest else rest
                    delivery_status[eid] = ('RECHAZADO', reason[:60])
                elif flag in ('=>', '->'):
                    if '/dev/null' in rest or 'blackhole' in rest:
                        delivery_status[eid] = ('DESCARTADO_FILTRO', '/dev/null (antispam)')
                    elif 'dovecot' in rest or 'virtual_delivery' in rest or 'mail_spool' in rest:
                        delivery_status[eid] = ('ENTREGADO_BUZON', rest.split()[0])
                    elif 'spamcheck' in rest or 'spam-scanner' in rest:
                        delivery_status[eid] = ('EN_ESCANER', 'spamcheck_pipe')
                    else:
                        delivery_status[eid] = ('ENTREGADO_OTRO', rest.split()[0])
                elif flag == '==':
                    delivery_status[eid] = ('DIFERIDO_COLA', rest[:50])

    messages = {}
    parent_ids = {info['parent_id'] for info in raw_messages.values() if info.get('parent_id')}

    for eid, info in raw_messages.items():
        if eid in parent_ids:
            continue
        if not info.get('source_ip') and info.get('parent_id') in source_ips:
            info['source_ip'] = source_ips[info['parent_id']]

        st = delivery_status.get(eid) or delivery_status.get(info.get('parent_id'), ('DESCONOCIDO', 'sin datos'))
        info['delivery_status'] = st
        info['delivery_rcpt'] = delivery_recipients.get(eid) or delivery_recipients.get(info.get('parent_id')) or info.get('recipient')
        messages[eid] = info

    stats = Counter(info['delivery_status'][0] for info in messages.values())

    return messages, raw_messages, stats


def find_mail_dirs():
    """Detecta los directorios base de correo compatibles con cPanel (/home, /home2...), DirectAdmin y vmail."""
    base_dirs = []
    home_roots = sorted(glob.glob('/home*') + glob.glob('/usr/home*'))
    for hroot in home_roots:
        if not os.path.isdir(hroot):
            continue
        bname = os.path.basename(hroot)
        if bname.startswith(('home.bak', 'home_bak', 'home-bak')):
            continue
        for udir in glob.glob(os.path.join(hroot, '*')):
            if not os.path.isdir(udir):
                continue
            for sub in ('mail', 'imap', 'Maildir'):
                p = os.path.join(udir, sub)
                if os.path.isdir(p):
                    base_dirs.append(p)
    if os.path.isdir('/var/vmail'):
        base_dirs.append('/var/vmail')
    return sorted(set(base_dirs))


def header_identifiers(path, byte_limit=131072):
    """Extrae IDs de Exim y Message-ID del encabezado de un correo."""
    try:
        with open(path, 'rb') as f:
            buf = bytearray()
            for line in f:
                buf.extend(line)
                if line in (b'\n', b'\r\n') or len(buf) > byte_limit:
                    break
    except (OSError, PermissionError):
        return set(), set()
    head = bytes(buf).decode('latin1', errors='replace')
    eids = set(EXIM_RE.findall(head))
    msg_ids = set(re.findall(r'(?i)\bmessage-id:\s*<?([^>\s]+)>?', head))
    return eids, msg_ids


def find_message_file_targeted(info, eid, userdomains, userhomes):
    """Busca directamente en el buzón físico correspondiente al destinatario del correo."""
    rcpt = info.get('delivery_rcpt') or info.get('recipient') or ''
    local_part, domain, folder = parse_recipient(rcpt)
    if not domain or not local_part:
        return None

    candidate_homes = []
    user = userdomains.get(domain)
    if user and user in userhomes:
        candidate_homes.append(userhomes[user])

    if not candidate_homes:
        for p in glob.glob(f'/home*/mail/{domain}') + glob.glob(f'/home*/*/mail/{domain}'):
            candidate_homes.append(os.path.dirname(os.path.dirname(p)))

    search_dirs = []
    for chome in candidate_homes:
        mbox_base = os.path.join(chome, 'mail', domain, local_part)
        if not os.path.isdir(mbox_base):
            mbox_base = os.path.join(chome, 'imap', domain, local_part, 'Maildir')
        if not os.path.isdir(mbox_base):
            continue

        subfolders = ['', '.spam', '.Junk', '.Spam', '.Trash', '.INBOX.spam', '.INBOX.junk']
        for sub in subfolders:
            fpath = os.path.join(mbox_base, sub) if sub else mbox_base
            for leaf in ('new', 'cur'):
                leaf_path = os.path.join(fpath, leaf)
                if os.path.isdir(leaf_path):
                    search_dirs.append(leaf_path)

    target_eids = {eid}
    if info.get('parent_id'):
        target_eids.add(info['parent_id'])
    target_msgid = info.get('msg_id', '').lower()

    for sdir in search_dirs:
        try:
            for fname in os.listdir(sdir):
                fpath = os.path.join(sdir, fname)
                if not os.path.isfile(fpath):
                    continue
                eids, msg_ids = header_identifiers(fpath)
                if (eids & target_eids) or (target_msgid and target_msgid in {m.lower() for m in msg_ids}):
                    return fpath
        except OSError:
            continue

    return None


def maildir_files(base_dirs, cutoff_ts, progress, verbose=False):
    """Genera rutas de archivos en Maildir recientes en cur/, new/ y subcarpetas."""
    scanned = 0
    for base in base_dirs:
        for root, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            if os.path.basename(root) not in ('cur', 'new'):
                continue

            for name in files:
                path = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(path)
                    if mtime < cutoff_ts:
                        name_ts = int(name.split('.', 1)[0]) if name.split('.', 1)[0].isdigit() else 0
                        if name_ts < cutoff_ts:
                            continue
                except (OSError, ValueError):
                    continue
                scanned += 1
                if verbose and scanned % progress == 0:
                    print(f'[PROGRESO] {scanned:,} archivos revisados en buzones...', flush=True)
                yield path

            dirs.clear()


def parse_extracted_rows(info, exim_id, raw, path):
    """Parsea el mensaje y devuelve las filas estructuradas con enlaces y metadatos."""
    message, links = links_from_message(raw)
    recipients = info.get('delivery_rcpt') or info.get('recipient', '') or ', '.join(filter(None, [message.get('To'), message.get('Delivered-To')]))
    subj = str(info.get('subject') or message.get('Subject') or '')
    src_ip = info.get('source_ip') or extract_ip_from_message(message)

    rows = []
    for url, text in links:
        try:
            host = (urlsplit(url).hostname or '').lower()
        except ValueError:
            host = ''
        rows.append({
            'server': socket.gethostname(),
            'exim_id': exim_id,
            'sender': info.get('sender') or message.get('Return-Path', ''),
            'recipient': recipients,
            'subject': subj,
            'source_ip': src_ip,
            'url': url,
            'url_host': host,
            'anchor_text': text,
            'action_link': 'SI' if ACTION_RE.search(text) or ACTION_RE.search(url) else 'NO',
            'mail_file': path
        })
    return rows


def main():
    ap = argparse.ArgumentParser(
        description='Extrae dominios afectados y enlaces de phishing recibidos en Exim/Maildir (solo lectura).'
    )
    ap.add_argument('--days', type=int, default=5, help='Antigüedad máxima en días para analizar (por defecto: 5)')
    ap.add_argument('--subject', default=DEFAULT_SUBJECT_RE, help='Expresión regular para filtrar por asunto del correo')
    ap.add_argument('--sender-domain', action='append', help='Filtrar por dominio del remitente')
    ap.add_argument('--all-senders', action='store_true', default=False, help='Evaluar todos los remitentes sin filtrar')
    ap.add_argument('--verbose', action='store_true', help='Mostrar progreso detallado de lectura de logs y buzones')
    ap.add_argument('--csv', action='store_true', help='Exportar resultados a archivos CSV')
    ap.add_argument('--out', default=None, help='Prefijo para los archivos CSV de salida (activa --csv)')
    ap.add_argument('--eml', help='Modo de prueba local con archivo .eml individual')
    ap.add_argument('--progress', type=int, default=2000, help='Frecuencia de notificación en modo verbose')
    ap.add_argument('--queue-limit', type=int, default=200, help='Máximo de mensajes en cola a consultar')
    args = ap.parse_args()

    if args.days < 1 or args.progress < 1:
        ap.error('--days y --progress deben ser enteros positivos')

    export_csv = args.csv or bool(args.out)
    if export_csv and not args.out:
        args.out = '/root/phishing_links' if (hasattr(os, 'geteuid') and os.geteuid() == 0) else './phishing_links'

    counts = Counter()
    hosts = Counter()
    found_ids = set()
    matches = {}
    all_extracted_rows = []

    if args.eml:
        try:
            raw = Path(args.eml).read_bytes()
        except OSError as err:
            print(f'[ERROR] No se pudo abrir {args.eml}: {err}', file=sys.stderr)
            return 1

        ids = EXIM_RE.findall(raw.decode('latin1', errors='replace').split('\n\n', 1)[0])
        eid = ids[-1] if ids else 'EML_TEST'
        messages = {eid: {'sender': '', 'recipient': '', 'subject': '', 'source_ip': '', 'delivery_status': ('EML', 'prueba local')}}
        delivery_stats = Counter({'EML': 1})
        matches[eid] = (raw, args.eml)
    else:
        log_patterns = [
            '/var/log/exim_mainlog*',
            '/var/log/exim/mainlog*',
            '/var/log/exim4/mainlog*'
        ]
        logs = []
        for pat in log_patterns:
            logs.extend(glob.glob(pat))
        logs = sorted(set(logs))

        if not logs:
            print('[ERROR] No se encontraron logs de Exim. Usa --eml para pruebas locales.', file=sys.stderr)
            return 2

        cutoff_date = dt.datetime.now() - dt.timedelta(days=args.days)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d')
        cutoff_ts = (dt.datetime.now() - dt.timedelta(days=args.days + 1)).timestamp()

        allowed_senders = {s.lower().lstrip('@') for s in args.sender_domain} if args.sender_domain else set()
        messages, raw_messages, delivery_stats = select_ids(logs, allowed_senders, args.subject, cutoff_str, args.verbose)

        if not messages:
            print('=' * 75)
            print('  AUDITORÍA DE PHISHING EN EXIM')
            print('=' * 75)
            print(f'[*] No se detectaron correos coincidentes en los últimos {args.days} días.')
            print('=' * 75)
            return 0

        # 1. Cola de Exim
        checked_queue = 0
        for eid in list(messages):
            if checked_queue >= args.queue_limit:
                break
            checked_queue += 1
            try:
                result = subprocess.run(
                    ['exim', '-Mvb', eid],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3
                )
                if result.returncode == 0 and result.stdout:
                    matches[eid] = (result.stdout, f'COLA:{eid}')
            except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # 2. Búsqueda Dirigida en Buzones
        userdomains = load_userdomains()
        userhomes = load_userhomes()

        pending_eids = [eid for eid in messages if eid not in matches and messages[eid]['delivery_status'][0] == 'ENTREGADO_BUZON']
        for eid in pending_eids:
            fpath = find_message_file_targeted(messages[eid], eid, userdomains, userhomes)
            if fpath:
                try:
                    raw = Path(fpath).read_bytes()
                    matches[eid] = (raw, fpath)
                except OSError:
                    pass

        # 3. Barrido General en Maildirs (fallback)
        target_eids = set(messages.keys()) - set(matches.keys())
        if target_eids:
            mail_bases = find_mail_dirs()
            if mail_bases:
                id_to_main_eid = {}
                msgid_to_main_eid = {}
                for eid in target_eids:
                    info = messages[eid]
                    id_to_main_eid[eid] = eid
                    if info.get('parent_id'):
                        id_to_main_eid[info['parent_id']] = eid
                    if info.get('msg_id'):
                        msgid_to_main_eid[info['msg_id']] = eid

                for path in maildir_files(mail_bases, cutoff_ts, args.progress, args.verbose):
                    if not target_eids:
                        break

                    eids, msg_ids = header_identifiers(path)
                    candidate_eids = set()
                    for eid in eids:
                        if eid in id_to_main_eid:
                            candidate_eids.add(id_to_main_eid[eid])
                    for mid in msg_ids:
                        if mid in msgid_to_main_eid:
                            candidate_eids.add(msgid_to_main_eid[mid])

                    matched_now = candidate_eids & target_eids
                    if not matched_now:
                        continue

                    try:
                        raw = Path(path).read_bytes()
                    except OSError:
                        continue

                    for meid in matched_now:
                        if meid not in matches:
                            matches[meid] = (raw, path)
                            target_eids.discard(meid)

    # 4. Extracción de enlaces de correos recuperados
    for eid, (raw, path) in matches.items():
        try:
            rows = parse_extracted_rows(messages.get(eid, {}), eid, raw, path)
        except Exception:
            continue

        for r in rows:
            all_extracted_rows.append(r)
            counts[r['url']] += 1
            if r['url_host']:
                hosts[r['url_host']] += 1
        found_ids.add(eid)

    # 5. Agrupación de dominios alojados afectados
    domain_counter = Counter()
    for info in messages.values():
        rcpt = info.get('delivery_rcpt') or info.get('recipient') or ''
        _, domain, _ = parse_recipient(rcpt)
        if domain:
            domain_counter[domain] += 1

    # ==========================
    # SALIDA FINAL LIMPIA
    # ==========================
    total_emails = len(messages)
    total_domains = len(domain_counter)

    print('=' * 75)
    print(f'  DOMINIOS ALOJADOS AFECTADOS ({total_emails:,} correos dirigidos a {total_domains:,} dominios)')
    print('=' * 75)
    for dom, count in domain_counter.most_common():
        print(f'  • {dom:<40} ({count:>3} correos recibidos)')

    print('\n' + '=' * 75)
    print('  ENLACES Y DOMINIOS DE PHISHING')
    print('=' * 75)
    if counts:
        print('DOMINIOS DE PHISHING DETECTADOS:')
        for host, n in hosts.most_common():
            print(f'  • {host:<40} ({n} apariciones)')

        print('\nENLACES (URLs):')
        for url, n in counts.most_common():
            print(f'  • {url}')

        print('\nDETALLE DE CORREOS RECUPERADOS:')
        for i, r in enumerate(all_extracted_rows, 1):
            print(f'  [{i}] Destinatario: {r["recipient"]}')
            print(f'      Asunto:       {r["subject"]}')
            print(f'      Texto Enlace: {r["anchor_text"]} [Acción: {r["action_link"]}]')
            print(f'      URL:          {r["url"]}')
            print(f'      Archivo:      {r["mail_file"]}')
            if i < len(all_extracted_rows):
                print('      ' + '-' * 60)
    else:
        print('[!] Los archivos de los correos ya no se encuentran en los buzones del servidor')
        print('    (fueron descargados por POP3, eliminados por el usuario o purgados por antispam).')
    print('=' * 75)

    if export_csv and all_extracted_rows:
        prefix = Path(args.out)
        try:
            prefix.parent.mkdir(parents=True, exist_ok=True)
            details_csv = str(prefix) + '_detalle.csv'
            urls_csv = str(prefix) + '_urls.csv'
            doms_csv = str(prefix) + '_dominios.csv'

            with open(details_csv, 'w', encoding='utf-8', newline='') as out:
                writer = csv.DictWriter(out, fieldnames=CSV_FIELDS)
                writer.writeheader()
                for r in all_extracted_rows:
                    writer.writerow(r)

            with open(urls_csv, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f)
                w.writerow(['mensajes', 'url'])
                for url, count in counts.most_common():
                    w.writerow([count, url])

            with open(doms_csv, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f)
                w.writerow(['apariciones', 'dominio_enlace'])
                for host, count in hosts.most_common():
                    w.writerow([count, host])

            print(f'\n[✓] Reportes CSV exportados en: {details_csv}')
        except Exception:
            pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
