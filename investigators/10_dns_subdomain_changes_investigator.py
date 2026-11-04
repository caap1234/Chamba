#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
10. DNS & Subdomain Changes Investigator
Plataformas: cPanel & WHM (y DirectAdmin)
Uso:
  python3 10_dns_subdomain_changes_investigator.py
  python3 10_dns_subdomain_changes_investigator.py --domain misitio.com
  python3 10_dns_subdomain_changes_investigator.py --user wikumxco --date 2026-10-15
  python3 10_dns_subdomain_changes_investigator.py --search telsurpagos
  python3 10_dns_subdomain_changes_investigator.py --days 30 --exclude-ip 72.249.55.

Audita cambios en zonas DNS (creación, edición y borrado de registros A, CNAME, TXT, MX),
creación de subdominios, dominios adicionales y alias en logs de cPanel (access_log actuales y rotados en archive/).
Extrae la IP real del actor desde la cabecera X-Forwarded-For (omitiendo por defecto la IP del analista 72.249.55.*).
Si los cambios se realizaron en fechas sin registros en los logs (rotación o retención expirada),
o si se solicita explícitamente, consulta /home/usuario/.lastlogin para correlacionar quién accedió
a la cuenta en esas fechas, cruzando además con el archivo de zona física /var/named/<dominio>.db.
Incluye sección de snippets crudos lista para adjuntar en tickets y expedientes de IRIS.
"""

import argparse
import collections
import datetime as dt
import glob
import gzip
import io
import json
import os
import platform
import re
import subprocess
import sys
import urllib.parse
import urllib.request

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

CPANEL_LOG_REGEX = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[0-9.]+)?(?:.*)?"\s+(\d{3})\s+(\S+)'
)

DNS_KEYWORDS_REGEX = re.compile(
    r'(?:mass_edit_zone|add_zone_record|edit_zone_record|remove_zone_record|delete_zone_record|'
    r'edit_zone|savezone|resetzone|addsubdomain|create_subdomain|delsubdomain|delete_subdomain|'
    r'addaddondomain|create_addon_domain|adddomain|deladdondomain|delete_addon_domain|'
    r'addparkeddomain|create_parked_domain|park|unpark|fetchzone_records|dumpzone|'
    r'ZoneEdit|execute/DNS/|execute/SubDomain/|execute/AddonDomain/|execute/ParkedDomain/|'
    r'CMD_SUBDOMAIN|CMD_DNS_ADMIN|CMD_DNS_CONTROL)',
    re.I
)

# Cache de Geo/ISP para no saturar API pública
GEO_CACHE = {}


def query_ip_info(ip_addr):
    """Consulta información ligera de ASN, ISP y País para enriquecer el peritaje."""
    if not ip_addr or ip_addr.startswith('127.') or ip_addr.startswith('10.') or ip_addr.startswith('192.168.'):
        return {'isp': 'IP Privada / Local', 'org': 'Local', 'country': 'N/A'}
    if ip_addr in GEO_CACHE:
        return GEO_CACHE[ip_addr]
    try:
        url = "http://ip-api.com/json/%s?fields=status,country,countryCode,isp,org,as,query" % ip_addr
        req = urllib.request.Request(url, headers={'User-Agent': 'Neubox-DNS-Investigator/1.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                GEO_CACHE[ip_addr] = data
                return data
    except Exception:
        pass
    GEO_CACHE[ip_addr] = {}
    return {}


def detect_server_type():
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/var/log/directadmin') or os.path.isdir('/usr/local/directadmin'):
        return 'directadmin'
    return 'cpanel'


def parse_cpanel_date(date_str):
    """
    Parsea fechas típicas de cPanel access_log:
    - 10/21/2026:00:13:11 -0000 (Mes/Día/Año o Día/Mes/Año)
    - 21/Oct/2026:00:13:11 -0000
    - 2026-10-21 00:13:11
    """
    if not date_str:
        return None

    # Formato ISO: YYYY-MM-DD HH:MM:SS
    m_iso = re.search(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)', date_str)
    if m_iso:
        try:
            return dt.datetime.strptime(m_iso.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    # Formato cPanel numérico: MM/DD/YYYY:HH:MM:SS (o DD/MM/YYYY)
    m_num = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4}):(\d\d:\d\d:\d\d)', date_str)
    if m_num:
        p1, p2, year, clock = m_num.groups()
        # En cPanel access_log el primer campo suele ser mes (ej. 10/21/2026)
        # Si p1 > 12, es día/mes
        v1, v2 = int(p1), int(p2)
        if v1 > 12:
            day, mon = v1, v2
        elif v2 > 12:
            mon, day = v1, v2
        else:
            mon, day = v1, v2  # default cPanel: MM/DD/YYYY
        try:
            return dt.datetime.strptime('%04d-%02d-%02d %s' % (int(year), mon, day, clock), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    # Formato CLF Apache: 21/Oct/2026:00:13:11
    m_clf = re.search(r'(\d{1,2})/(\w{3})/(\d{4}):(\d\d:\d\d:\d\d)', date_str)
    if m_clf:
        day, mon, year, clock = m_clf.groups()
        month = MONTHS.get(mon.capitalize(), 1)
        try:
            return dt.datetime.strptime('%04d-%02d-%02d %s' % (int(year), month, int(day), clock), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    return None


def get_log_files(include_archive=True, since_dt=None):
    """Obtiene la lista ordenada de archivos de log activos y rotados."""
    paths = []
    # 1. Logs activos de cPanel
    cpanel_dir = '/usr/local/cpanel/logs'
    if os.path.isdir(cpanel_dir):
        for f in glob.glob(os.path.join(cpanel_dir, 'access_log*')):
            if os.path.isfile(f) and not f.endswith(('.offset', '.lock', '.state')):
                paths.append(f)
        for f in glob.glob(os.path.join(cpanel_dir, 'dnsadmin_log*')):
            if os.path.isfile(f) and not f.endswith(('.offset', '.lock', '.state')):
                paths.append(f)

        # 2. Logs archivados de cPanel (archive/access_log-*.gz)
        if include_archive:
            archive_dir = os.path.join(cpanel_dir, 'archive')
            if os.path.isdir(archive_dir):
                for f in glob.glob(os.path.join(archive_dir, 'access_log*')):
                    if os.path.isfile(f) and not f.endswith(('.offset', '.lock')):
                        paths.append(f)
                for f in glob.glob(os.path.join(archive_dir, 'dnsadmin_log*')):
                    if os.path.isfile(f) and not f.endswith(('.offset', '.lock')):
                        paths.append(f)

    # 3. DirectAdmin si aplica
    da_dir = '/var/log/directadmin'
    if os.path.isdir(da_dir):
        for f in glob.glob(os.path.join(da_dir, 'system.log*')):
            if os.path.isfile(f):
                paths.append(f)

    # Filtrar por cutoff de fecha si se solicita y el archivo es muy antiguo
    if since_dt:
        cutoff = (since_dt - dt.timedelta(days=2)).timestamp()
        filtered = []
        for p in paths:
            try:
                if os.path.getmtime(p) >= cutoff:
                    filtered.append(p)
                else:
                    # Si el archivo está en archive, verificar si el nombre sugiere fecha reciente
                    fname = os.path.basename(p)
                    # 1. YYYY-MM-DD o YYYY-MM
                    m_ym = re.search(r'access_log-(\d{4})-(\d{1,2})(?:-(\d{1,2}))?', fname)
                    if m_ym:
                        yr, mo = int(m_ym.group(1)), int(m_ym.group(2))
                        if (yr > since_dt.year) or (yr == since_dt.year and mo >= since_dt.month):
                            filtered.append(p)
                            continue
                    # 2. MM-DD-YYYY o MM-YYYY
                    m_mdy = re.search(r'access_log-(\d{1,2})(?:-(\d{1,2}))?-(\d{4})', fname)
                    if m_mdy:
                        mo, yr = int(m_mdy.group(1)), int(m_mdy.group(3))
                        if (yr > since_dt.year) or (yr == since_dt.year and mo >= since_dt.month):
                            filtered.append(p)
                            continue
                    # 3. Mon-YYYY (ej. Nov-2026)
                    m_txt = re.search(r'access_log-([A-Za-z]{3})-(\d{4})', fname)
                    if m_txt:
                        mon_str, yr_str = m_txt.groups()
                        mo = MONTHS.get(mon_str.capitalize(), 0)
                        if mo > 0 and ((int(yr_str) > since_dt.year) or (int(yr_str) == since_dt.year and mo >= since_dt.month)):
                            filtered.append(p)
                            continue
            except OSError:
                filtered.append(p)
        paths = filtered

    # Ordenar por fecha de modificación
    return sorted(list(set(paths)), key=lambda x: (os.path.getmtime(x) if os.path.exists(x) else 0, x))


def classify_action(uri):
    """Clasifica la operación DNS o de dominio en una etiqueta legible."""
    u = uri.lower()
    if 'add_zone_record' in u:
        return 'CREACIÓN REGISTRO DNS (ZoneEdit)'
    if 'edit_zone_record' in u:
        return 'EDICIÓN REGISTRO DNS'
    if 'remove_zone_record' in u or 'delete_zone_record' in u:
        return 'ELIMINACIÓN REGISTRO DNS'
    if 'mass_edit_zone' in u:
        return 'EDICIÓN MASIVA DE ZONA DNS (Zone Editor)'
    if 'savezone' in u or 'edit_zone' in u:
        return 'GUARDAR / MODIFICAR ZONA DNS'
    if 'resetzone' in u:
        return 'RESTABLECER ZONA DNS (RESET)'
    if 'addsubdomain' in u or 'create_subdomain' in u:
        return 'CREACIÓN DE SUBDOMINIO'
    if 'delsubdomain' in u or 'delete_subdomain' in u:
        return 'ELIMINACIÓN DE SUBDOMINIO'
    if 'addaddondomain' in u or 'create_addon_domain' in u or 'adddomain' in u:
        return 'CREACIÓN DE DOMINIO ADICIONAL'
    if 'deladdondomain' in u or 'delete_addon_domain' in u:
        return 'ELIMINACIÓN DOMINIO ADICIONAL'
    if 'addparkeddomain' in u or 'create_parked_domain' in u or 'park' in u:
        return 'CREACIÓN DOMINIO APARCADO (ALIAS)'
    if 'unpark' in u:
        return 'ELIMINACIÓN DOMINIO APARCADO'
    if 'fetchzone_records' in u or 'dumpzone' in u:
        return 'CONSULTA / RECONOCIMIENTO DE ZONA'
    if 'CMD_SUBDOMAIN' in uri:
        return 'DIRECTADMIN: SUBDOMINIO'
    if 'CMD_DNS' in uri:
        return 'DIRECTADMIN: DNS CONTROL'
    return 'MODIFICACIÓN DNS / DOMINIO'


def extract_parameters(uri):
    """Extrae parámetros clave como dominio, subdominio, tipo, dirección IP de destino y TTL."""
    params = {}
    if '?' in uri:
        try:
            qs = urllib.parse.parse_qs(uri.split('?', 1)[1])
            for k in ['domain', 'name', 'type', 'address', 'ttl', 'subdomain', 'rootdomain', 'cname', 'txtdata', 'exchange']:
                if k in qs and qs[k]:
                    params[k] = qs[k][0]
        except Exception:
            pass
    return params


def domain_matches_target(target, line_lower, dom, rec_name, fqdn):
    """
    Comprueba si un evento coincide con el target_domain especificado.
    Soporta:
    - Dominio exacto o en línea (ej. acap.com.mx en line)
    - Subdominios (ej. target: 'telsurpagos.acap.com.mx', con dom='acap.com.mx', rec_name='telsurpagos')
    - Registro / prefijo solo (ej. target: 'telsurpagos', rec_name='telsurpagos')
    """
    if not target:
        return True

    target = target.lower().strip().rstrip('.')
    dom = (dom or '').lower().strip().rstrip('.')
    rec_name = (rec_name or '').lower().strip().rstrip('.')
    fqdn = (fqdn or '').lower().strip().rstrip('.')

    # 1. Coincidencia directa textual en la línea
    if target in line_lower:
        return True

    # 2. Coincidencia exacta con FQDN, dominio base o nombre de registro
    if target in (fqdn, dom, rec_name):
        return True

    # 3. Si target es un FQDN (ej. telsurpagos.acap.com.mx)
    if '.' in target:
        if fqdn and (fqdn == target or fqdn.endswith('.' + target) or target.endswith('.' + fqdn)):
            return True
        if dom and rec_name:
            reconstructed = ('%s.%s' % (rec_name, dom)).rstrip('.')
            if reconstructed == target or target == reconstructed:
                return True
        if dom and target.endswith('.' + dom):
            prefix = target[:-len(dom)-1]
            if prefix and (prefix == rec_name or prefix in line_lower):
                return True
    else:
        if target == rec_name or (dom and target == dom):
            return True

    return False


def lookup_domain_owner(domain):
    """Busca el usuario de cPanel dueño de un dominio en /etc/userdomains."""
    if not domain:
        return None
    domain = domain.lower().strip()
    userdomains_path = '/etc/userdomains'
    if os.path.isfile(userdomains_path):
        try:
            with open(userdomains_path, 'r', encoding='utf-8', errors='replace') as fh:
                mapping = {}
                for line in fh:
                    line = line.strip()
                    if line.startswith('#') or ':' not in line:
                        continue
                    d, u = line.split(':', 1)
                    mapping[d.strip().lower()] = u.strip()

                # 1. Búsqueda directa exacta
                if domain in mapping:
                    return mapping[domain]

                # 2. Si es subdominio (ej. telsurpagos.acap.com.mx), buscar zona padre
                parts = domain.split('.')
                for i in range(1, len(parts) - 1):
                    parent = '.'.join(parts[i:])
                    if parent in mapping:
                        return mapping[parent]
        except OSError:
            pass
    return None


def inspect_physical_zone_file(domain, target_search=None):
    """
    Inspecciona el archivo de zona física en /var/named/<domain>.db para
    obtener fecha de modificación en disco, serial SOA y registros clave.
    """
    info = {'file_exists': False, 'path': None, 'mtime': None, 'serial': None, 'serial_date': None, 'records': []}
    if not domain:
        return info

    cand_domains = [domain]
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        cand_domains.append('.'.join(parts[i:]))

    found_path = None
    for d in cand_domains:
        for p in ['/var/named/%s.db' % d, '/var/named/chroot/var/named/%s.db' % d]:
            if os.path.isfile(p):
                found_path = p
                break
        if found_path:
            break

    if not found_path:
        return info

    info['file_exists'] = True
    info['path'] = found_path
    try:
        st = os.stat(found_path)
        info['mtime'] = dt.datetime.fromtimestamp(st.st_mtime)

        with open(found_path, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read()

        # Extraer serial SOA: típicamente YYYYMMDDNN (ej. 2026101501)
        m_ser = re.search(r'(\d{8,10})\s*;\s*[Ss]erial', content)
        if m_ser:
            serial_str = m_ser.group(1)
            info['serial'] = serial_str
            if len(serial_str) >= 8:
                try:
                    s_yr = int(serial_str[0:4])
                    s_mo = int(serial_str[4:6])
                    s_dy = int(serial_str[6:8])
                    info['serial_date'] = "%04d-%02d-%02d (Rev %s)" % (s_yr, s_mo, s_dy, serial_str[8:])
                except Exception:
                    pass

        # Buscar si el subdominio o término existe en el archivo de zona física
        search_terms = []
        if len(parts) > 2:
            search_terms.append(parts[0])
        if target_search:
            search_terms.append(target_search)

        if search_terms:
            for zline in content.splitlines():
                zline_s = zline.strip()
                if not zline_s or zline_s.startswith(';') or zline_s.startswith('$'):
                    continue
                if any(re.search(r'\b' + re.escape(sterm) + r'\b', zline_s, re.I) for sterm in search_terms):
                    info['records'].append(zline_s)
    except Exception:
        pass

    return info


def check_user_lastlogin(username, date_filter=None, exclude_ips=None):
    """
    Lee /home/<usuario>/.lastlogin para auditar quién accedió a la interfaz
    de cPanel cuando las fechas ya no tienen registros en access_log rotados.
    """
    exclude_ips = exclude_ips or []
    results = []
    if not username:
        return results

    # Posibles rutas de home (soportando /home, /home2, /home3...)
    cand_homes = glob.glob('/home*/%s/.lastlogin' % username)
    if not cand_homes:
        cand_homes = ['/home/%s/.lastlogin' % username]

    for lastlogin_path in cand_homes:
        if not os.path.isfile(lastlogin_path):
            continue
        try:
            with open(lastlogin_path, 'r', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue

                    # Extraer IP
                    m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if not m_ip:
                        continue
                    ip = m_ip.group(0)

                    # Excluir IPs de analista
                    if any(ip.startswith(ex) for ex in exclude_ips):
                        continue

                    # Extraer fecha / timestamp
                    m_date = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line)
                    date_val = m_date.group(1) if m_date else None

                    # Filtrar por fecha si se solicitó
                    if date_filter and date_val:
                        if date_filter not in date_val:
                            continue

                    results.append({
                        'user': username,
                        'ip': ip,
                        'date_str': date_val or 'Fecha no disponible',
                        'raw': line,
                        'source_file': lastlogin_path
                    })
        except OSError:
            pass

    return results


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/10_dns_subdomain_changes_investigator.py)\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/10_dns_subdomain_changes_investigator.py) --domain misitio.com\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/10_dns_subdomain_changes_investigator.py) --user wikumxco --date 2026-10-15\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/10_dns_subdomain_changes_investigator.py) --search telsurpagos\n"
        "  python3 <(curl -sL https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/10_dns_subdomain_changes_investigator.py) --days 15\n"
    )

    parser = argparse.ArgumentParser(
        description='10. DNS & Subdomain Changes Investigator — Auditoría Forense de Zonas DNS, Subdominios, Alias y .lastlogin',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--domain', help='Dominio o subdominio objetivo (ej. empresa.com o sub.empresa.com)')
    parser.add_argument('--user', help='Usuario de cPanel a auditar (ej. wikumxco)')
    parser.add_argument('--ip', help='Filtrar por IP sospechosa de origen')
    parser.add_argument('--search', help='Buscar término libre en logs (ej. telsurpagos, mass_edit_zone)')
    parser.add_argument('--date', help='Filtrar por fecha específica (ej. 2026-10-15 o 10/15/2026 o 10/15)')
    parser.add_argument('--days', type=int, default=30, help='Días hacia atrás a investigar (def: 30, 0 para todo el historial)')
    parser.add_argument('--exclude-ip', default='72.249.55.', help='IPs o prefijos a omitir separados por coma (def: 72.249.55.)')
    parser.add_argument('--no-archive', action='store_true', help='No inspeccionar logs archivados en /usr/local/cpanel/logs/archive/')
    parser.add_argument('--check-lastlogin', action='store_true', help='Consultar siempre /home/usuario/.lastlogin')
    parser.add_argument('--limit', type=int, default=200, help='Límite de fragmentos de log a mostrar (def: 200)')
    parser.add_argument('--output', help='Ruta para guardar el reporte en disco')
    parser.add_argument('--interactive', action='store_true', help='Ejecutar en modo interactivo guiado')

    # Asistente interactivo si se corre sin argumentos en terminal interactivo
    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 75)
        print("  10. DNS & Subdomain Changes Investigator — Asistente de Inicio")
        print("=" * 75)
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

    # Procesar excluidos
    raw_exclude = args.exclude_ip.strip()
    if raw_exclude.lower() in ('none', 'no', '0', ''):
        exclude_ips = []
    else:
        exclude_ips = [x.strip() for x in raw_exclude.split(',') if x.strip()]

    target_domain = (args.domain or '').strip().lower().rstrip('/')
    target_user = (args.user or '').strip().lower()
    target_ip = (args.ip or '').strip()
    search_term = (args.search or '').strip()
    date_filter = (args.date or '').strip()

    if args.interactive:
        print("\n" + "-" * 75)
        print(" CONFIGURACIÓN INTERACTIVA DE AUDITORÍA FORENSE:")
        print("-" * 75)
        inp_dom = input("Dominio o subdominio objetivo [Enter para todos]: ").strip()
        if inp_dom:
            target_domain = inp_dom.lower().rstrip('/')

        inp_user = input("Usuario cPanel [Enter para todos]: ").strip()
        if inp_user:
            target_user = inp_user.lower()

        inp_srch = input("Término o registro a buscar (ej. telsurpagos) [Enter para omitir]: ").strip()
        if inp_srch:
            search_term = inp_srch

        inp_ip = input("IP específica a rastrear [Enter para omitir]: ").strip()
        if inp_ip:
            target_ip = inp_ip

        inp_date = input("Fecha específica (ej. 2026-10-15 o 10/15) [Enter para usar días]: ").strip()
        if inp_date:
            date_filter = inp_date

        if not date_filter:
            inp_days = input("Días hacia atrás a investigar [def: 30, 0 para todo el historial]: ").strip()
            if inp_days.isdigit():
                args.days = int(inp_days)

        inp_ex = input("IPs a excluir [def: 72.249.55.]: ").strip()
        if inp_ex:
            if inp_ex.lower() in ('none', 'no'):
                exclude_ips = []
            else:
                exclude_ips = [x.strip() for x in inp_ex.split(',') if x.strip()]

        print("-" * 75)

    now = dt.datetime.now()
    since_dt = (now - dt.timedelta(days=args.days)) if args.days > 0 and not date_filter else None

    # Si se pasó dominio pero no usuario, intentar resolver el usuario dueño
    if target_domain and not target_user:
        detected_owner = lookup_domain_owner(target_domain)
        if detected_owner:
            target_user = detected_owner

    include_archive = not args.no_archive
    log_files = get_log_files(include_archive=include_archive, since_dt=since_dt)

    # Contenedores de resultados
    matched_events = []
    raw_snippets = []
    ip_counter = collections.Counter()
    user_counter = collections.Counter()
    domain_counter = collections.Counter()
    action_counter = collections.Counter()
    type_counter = collections.Counter()

    # Normalizar date_filter
    norm_date_terms = []
    if date_filter:
        norm_date_terms.append(date_filter)
        # Convertir 2026-10-15 a 10/15/2026
        m_ymd = re.match(r'^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$', date_filter)
        if m_ymd:
            yr, mo, dy = m_ymd.groups()
            norm_date_terms.append("%02d/%02d/%s" % (int(mo), int(dy), yr))
            norm_date_terms.append("%d/%d/%s" % (int(mo), int(dy), yr))
            norm_date_terms.append("%02d/%02d" % (int(mo), int(dy)))

    # 1. Escaneo de logs
    for log_path in log_files:
        try:
            opener = gzip.open if log_path.endswith('.gz') else open
            with opener(log_path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    # Filtro rápido de keywords DNS antes de regex pesado
                    if not DNS_KEYWORDS_REGEX.search(line):
                        if search_term and search_term.lower() in line.lower():
                            pass
                        else:
                            continue

                    # Filtro de exclusión de IPs de analista
                    if any(ex in line for ex in exclude_ips):
                        # Verificar si está al inicio (client IP) o en X-Forwarded-For
                        m_ex_start = re.search(r'^(?:' + '|'.join(re.escape(x) for x in exclude_ips) + ')', line)
                        m_ex_fwd = re.search(r'X-Forwarded-For:\s*(?:' + '|'.join(re.escape(x) for x in exclude_ips) + ')', line, re.I)
                        if m_ex_start or m_ex_fwd:
                            continue

                    # Filtro de búsqueda libre si se especificó
                    if search_term and search_term.lower() not in line.lower():
                        continue

                    # Filtro de usuario si se especificó
                    if target_user and target_user not in line.lower():
                        continue

                    # Pre-filtro rápido de dominio / subdominio
                    if target_domain:
                        if target_domain not in line.lower():
                            dom_parts = target_domain.split('.')
                            sub_prefix = dom_parts[0]
                            has_part = False
                            if sub_prefix and len(sub_prefix) >= 3 and sub_prefix in line.lower():
                                has_part = True
                            else:
                                for i in range(1, len(dom_parts) - 1):
                                    parent_candidate = '.'.join(dom_parts[i:])
                                    if parent_candidate in line.lower():
                                        has_part = True
                                        break
                            if not has_part:
                                continue

                    # Filtro de IP objetivo si se especificó
                    if target_ip and target_ip not in line:
                        continue

                    # Parsear estructura cPanel
                    m_clf = CPANEL_LOG_REGEX.search(line)
                    if m_clf:
                        client_ip, auth_flag, log_user, date_str, method, uri, status, _ = m_clf.groups()

                        # Extraer X-Forwarded-For si existe
                        fwd_ip = None
                        m_fwd = re.search(r'X-Forwarded-For:\s*([0-9a-fA-F:.]+)', line, re.I)
                        if m_fwd:
                            fwd_ip = m_fwd.group(1).strip()

                        # Determinar IP real
                        if fwd_ip and fwd_ip not in ('-', '127.0.0.1', '::1'):
                            real_ip = fwd_ip
                        elif client_ip and client_ip not in ('-', '127.0.0.1', '::1'):
                            real_ip = client_ip
                        else:
                            real_ip = fwd_ip or client_ip

                        # Re-comprobar IP real contra exclusiones
                        if any(real_ip.startswith(ex) for ex in exclude_ips):
                            continue

                        # Parsear fecha
                        event_dt = parse_cpanel_date(date_str)
                        if event_dt:
                            if since_dt and event_dt < since_dt:
                                continue
                            if norm_date_terms:
                                dt_fmt1 = event_dt.strftime('%Y-%m-%d')
                                dt_fmt2 = event_dt.strftime('%m/%d/%Y')
                                dt_fmt3 = event_dt.strftime('%m/%d')
                                if not any(term in (dt_fmt1, dt_fmt2, dt_fmt3, date_str) for term in norm_date_terms):
                                    continue
                        else:
                            # Si no se pudo parsear fecha completa pero hay filtro de fecha por texto
                            if norm_date_terms and not any(term in date_str for term in norm_date_terms):
                                continue

                        # Extraer Referer
                        referer = '-'
                        m_ref = re.search(r'"(https?://[^"]+)"', line)
                        if m_ref:
                            referer = m_ref.group(1)

                        # Extraer parámetros de cambio DNS
                        params = extract_parameters(uri)
                        action_label = classify_action(uri)

                        # Identificar dominio y subdominio
                        dom = params.get('domain') or params.get('rootdomain') or ''
                        if not dom and referer != '-':
                            m_ref_host = re.search(r'https?://([^/:]+)', referer)
                            if m_ref_host:
                                dom = m_ref_host.group(1)

                        rec_name = params.get('name') or params.get('subdomain') or ''
                        rec_type = params.get('type') or ''
                        rec_dest = params.get('address') or params.get('cname') or params.get('txtdata') or ''

                        # Armar FQDN
                        fqdn = ""
                        if rec_name and dom:
                            fqdn = ("%s.%s" % (rec_name, dom)).rstrip('.') if not rec_name.endswith(dom) else rec_name
                        elif dom:
                            fqdn = dom
                        elif rec_name:
                            fqdn = rec_name

                        # Filtro exacto de dominio / subdominio
                        if target_domain and not domain_matches_target(target_domain, line.lower(), dom, rec_name, fqdn):
                            continue

                        # Armar resumen de acción
                        summary_detail = ""
                        if rec_name and dom:
                            summary_detail = "%s (%s) -> %s" % (fqdn, rec_type or 'A', rec_dest or '?')
                        elif dom:
                            summary_detail = "Zona: %s" % dom
                        else:
                            summary_detail = uri[:70]

                        # Actualizar contadores
                        ip_counter[real_ip] += 1
                        user_counter[log_user] += 1
                        if dom:
                            domain_counter[dom] += 1
                        action_counter[action_label] += 1
                        if rec_type:
                            type_counter[rec_type.upper()] += 1

                        matched_events.append({
                            'dt': event_dt,
                            'date_str': date_str,
                            'user': log_user,
                            'real_ip': real_ip,
                            'client_ip': client_ip,
                            'action': action_label,
                            'domain': dom,
                            'record_name': rec_name,
                            'record_type': rec_type,
                            'record_dest': rec_dest,
                            'detail': summary_detail,
                            'status': status,
                            'method': method,
                            'referer': referer,
                            'raw': line.strip()
                        })

                        if len(raw_snippets) < args.limit:
                            raw_snippets.append(line.strip())

        except (OSError, EOFError, gzip.BadGzipFile):
            continue

    # Inspección de Zona Física en disco si se indicó un dominio o se detectaron
    domains_to_check = set()
    if target_domain:
        domains_to_check.add(target_domain)
    for d, _ in domain_counter.most_common(3):
        domains_to_check.add(d)

    physical_zones = {}
    for dom in domains_to_check:
        p_info = inspect_physical_zone_file(dom, target_search=search_term)
        if p_info['file_exists']:
            physical_zones[dom] = p_info

    # 2. Comprobación de .lastlogin (cuando no hay logs o cuando se pide explícitamente)
    users_to_check_lastlogin = set()
    if target_user:
        users_to_check_lastlogin.add(target_user)
    if not users_to_check_lastlogin:
        for u, _ in user_counter.most_common(5):
            users_to_check_lastlogin.add(u)

    lastlogin_records = []
    should_check_lastlogin = args.check_lastlogin or (len(matched_events) == 0) or bool(date_filter)

    if should_check_lastlogin and users_to_check_lastlogin:
        for u in users_to_check_lastlogin:
            # Buscar accesos en .lastlogin
            ll_res = check_user_lastlogin(u, date_filter=date_filter, exclude_ips=exclude_ips)
            lastlogin_records.extend(ll_res)

    # ==============================================================================
    # GENERACIÓN DEL REPORTE
    # ==============================================================================
    out = []
    out.append("=" * 80)
    out.append("  10. DNS & SUBDOMAIN CHANGES INVESTIGATOR — REPORTE FORENSE")
    out.append("=" * 80)
    out.append("Generado el:            %s" % now.strftime('%Y-%m-%d %H:%M:%S'))
    out.append("Servidor detectado:     %s" % detect_server_type().upper())
    out.append("Filtros aplicados:")
    out.append("  - Dominio objetivo:   %s" % (target_domain or '(Cualquiera)'))
    out.append("  - Usuario cPanel:     %s" % (target_user or '(Cualquiera)'))
    out.append("  - IP objetivo:        %s" % (target_ip or '(Cualquiera)'))
    out.append("  - Término búsqueda:   %s" % (search_term or '(Ninguno)'))
    out.append("  - Fecha filtro:       %s" % (date_filter or '(Ninguna)'))
    out.append("  - Días hacia atrás:   %s" % (args.days if args.days > 0 and not date_filter else 'Historial Completo'))
    out.append("  - IPs Excluidas:      %s" % (", ".join(exclude_ips) if exclude_ips else '(Ninguna)'))
    out.append("  - Logs analizados:    %d archivos (incluyendo archive/ rotados: %s)" % (len(log_files), include_archive))
    out.append("=" * 80)

    out.append("\n" + "=" * 80)
    out.append("RESUMEN EJECUTIVO DE EVENTOS DNS Y SUBDOMINIOS")
    out.append("=" * 80)
    out.append("  Total de eventos detectados:             %d" % len(matched_events))
    out.append("  Usuarios cPanel involucrados:            %d" % len(user_counter))
    out.append("  IPs operadoras únicas (excluyendo analista): %d" % len(ip_counter))
    out.append("  Dominios / Zonas involucradas:           %d" % len(domain_counter))
    out.append("  Tipos de registros modificados:          %s" % (", ".join("%s (%d)" % (k, v) for k, v in type_counter.items()) or 'N/A'))
    out.append("=" * 80)

    # Si hay inspección física de zona DNS
    if physical_zones:
        out.append("\n" + "=" * 80)
        out.append("ESTADO FÍSICO DE ZONAS DNS EN DISCO (/var/named/<dominio>.db)")
        out.append("=" * 80)
        for dom, p_info in physical_zones.items():
            out.append("  Dominio / Zona:       %s" % dom)
            out.append("  Archivo en disco:     %s" % p_info['path'])
            out.append("  Última modificación:  %s" % (p_info['mtime'].strftime('%Y-%m-%d %H:%M:%S') if p_info['mtime'] else 'N/A'))
            out.append("  Serial SOA:           %s (%s)" % (p_info.get('serial') or 'N/A', p_info.get('serial_date') or 'N/A'))
            if p_info.get('records'):
                out.append("  Registros coincidentes en archivo de zona:")
                for r in p_info['records'][:10]:
                    out.append("    -> %s" % r)
            out.append("-" * 80)

    # Tabla cronológica de eventos encontrados en logs
    out.append("\n" + "=" * 80)
    out.append("TIMELINE CRONOLÓGICO DE CAMBIOS DNS Y SUBDOMINIOS (LOGS DE ACCESO)")
    out.append("=" * 80)

    if matched_events:
        for idx, ev in enumerate(matched_events[:args.limit], 1):
            geo = query_ip_info(ev['real_ip'])
            geo_desc = "%s - %s" % (geo.get('countryCode', '??'), geo.get('isp', 'ISP desconocido')) if geo else 'ISP N/A'
            out.append("[%03d] %s" % (idx, ev['date_str']))
            out.append("      Usuario: %-12s | IP Real: %-15s [%s]" % (ev['user'], ev['real_ip'], geo_desc))
            out.append("      Acción:  %-35s | Status HTTP: %s" % (ev['action'], ev['status']))
            if ev['detail']:
                out.append("      Detalle: %s" % ev['detail'])
            if ev['referer'] != '-':
                out.append("      Referer: %s" % ev['referer'])
            out.append("-" * 80)
    else:
        out.append("  [!] No se encontraron registros de ZoneEdit / Subdominios en los logs de acceso.")
        out.append("      Esto ocurre frecuentemente cuando los cambios se realizaron en fechas anteriores")
        out.append("      al período de retención de los logs o si los archivos ya fueron rotados/depurados.")

    # TOP RANKINGS
    def print_counter(title, counter, unit='eventos'):
        out.append("\n" + title)
        out.append("-" * len(title))
        if not counter:
            out.append("Sin registros.")
            return
        for k, v in counter.most_common(15):
            geo_str = ""
            if unit == 'operaciones' and re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', k):
                geo = query_ip_info(k)
                if geo:
                    geo_str = " (%s - %s)" % (geo.get('countryCode', '??'), geo.get('isp', ''))
            out.append("{0:>8} {1} : {2}{3}".format(v, unit, k, geo_str))

    print_counter("TOP ACCIONES Y OPERACIONES DNS REALIZADAS", action_counter, unit='acciones')
    print_counter("TOP IPs DE ORIGEN (ACTORES)", ip_counter, unit='operaciones')
    print_counter("TOP USUARIOS DE CPANEL CON CAMBIOS DNS", user_counter, unit='cambios')
    print_counter("TOP DOMINIOS / ZONAS AFECTADAS", domain_counter, unit='cambios')

    # SECCIÓN .lastlogin
    out.append("\n" + "=" * 80)
    out.append("CORRELACIÓN CON HISTORIAL PERSISTENTE DE ACCESOS (/home/usuario/.lastlogin)")
    out.append("Útil cuando la modificación ocurrió en fechas sin logs o para identificar accesos a la cuenta:")
    out.append("=" * 80)

    if lastlogin_records:
        for idx, ll in enumerate(lastlogin_records[:30], 1):
            geo = query_ip_info(ll['ip'])
            geo_desc = "%s - %s" % (geo.get('countryCode', '??'), geo.get('isp', 'ISP desconocido')) if geo else 'ISP N/A'
            out.append("  [%02d] Fecha: %-20s | Usuario: %-12s | IP: %-15s [%s]" % (
                idx, ll['date_str'], ll['user'], ll['ip'], geo_desc
            ))
            out.append("       Archivo: %s" % ll['source_file'])
            out.append("       Línea cruda: %s" % ll['raw'])
            out.append("-" * 80)
    else:
        if users_to_check_lastlogin:
            out.append("  No se registraron accesos en .lastlogin para los usuarios %s (con los filtros dados)." % list(users_to_check_lastlogin))
        else:
            out.append("  No se especificó usuario o dominio para comprobar .lastlogin.")
            out.append("  Consejo: Ejecuta con --user <usuario> o --domain <dominio> para verificar su .lastlogin.")

    # SECCIÓN DE EVIDENCIA PARA IRIS (SNIPPETS CRUDOS DE LOG)
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (FRAGMENTOS CRUDOS DE LOG LISTOS PARA COPIAR)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso o ticket de IRIS:")
    out.append("=" * 80)

    if raw_snippets:
        for idx, l in enumerate(raw_snippets[:args.limit], 1):
            out.append("[%03d] %s" % (idx, l))
    else:
        out.append("(Sin líneas de log crudo que coincidan con los filtros indicados)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte forense guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

