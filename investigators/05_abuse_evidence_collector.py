#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
05. Abuse Evidence Collector
Plataformas: Multiplataforma (Linux & Windows Server)
Uso:
  python3 05_abuse_evidence_collector.py
  python3 05_abuse_evidence_collector.py --case-id IRIS-9821 --domain cliente.com --abuse-type malware \
      --files /home/cliente/public_html/shell.php --log-files /etc/apache2/logs/domlogs/cliente.com --grep shell.php
  python3 05_abuse_evidence_collector.py --case-id INC-4412 --abuse-type spam --ip 198.51.100.2 \
      --log-files /var/log/exim_mainlog --grep 198.51.100.2

Recolector forense técnico para generar el expediente de evidencia listo para IRIS.
Extrae metadatos del sistema, timestamps (UTC y Local), hashes MD5/SHA256,
permisos, dueños y fragmentos completos de logs como prueba fehaciente.
"""

import argparse
import datetime as dt
import glob
import gzip
import hashlib
import io
import os
import platform
import re
import socket
import stat
import sys

try:
    import pwd
except ImportError:
    pwd = None


def get_system_info():
    """Obtiene metadatos del entorno y del servidor."""
    info = {}
    info['hostname'] = socket.gethostname()
    info['os'] = platform.system()
    info['release'] = platform.release()
    info['version'] = platform.version()
    info['architecture'] = platform.machine()
    info['python_version'] = platform.python_version()

    # Intentar obtener IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        info['primary_ip'] = s.getsockname()[0]
        s.close()
    except Exception:
        info['primary_ip'] = '127.0.0.1'

    return info


def hash_file(filepath):
    """Calcula MD5, SHA-1 y SHA-256 de un archivo."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                buf = f.read(65536)
                if not buf:
                    break
                md5.update(buf)
                sha1.update(buf)
                sha256.update(buf)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception as e:
        return ('ERROR: %s' % e, 'ERROR', 'ERROR')


def get_file_metadata(filepath):
    """Obtiene metadatos completos y hashes de un archivo de evidencia."""
    if not os.path.exists(filepath):
        return None

    try:
        st = os.lstat(filepath)
    except Exception as e:
        return {'path': filepath, 'error': str(e)}

    # Propietario en Linux
    owner = 'N/A'
    if pwd:
        try:
            owner = "%s (%d)" % (pwd.getpwuid(st.st_uid).pw_name, st.st_uid)
        except Exception:
            owner = str(st.st_uid)
    else:
        owner = "UID:%s" % getattr(st, 'st_uid', 'Windows')

    mtime_local = dt.datetime.fromtimestamp(st.st_mtime)
    mtime_utc = dt.datetime.utcfromtimestamp(st.st_mtime)
    ctime_local = dt.datetime.fromtimestamp(st.st_ctime)
    ctime_utc = dt.datetime.utcfromtimestamp(st.st_ctime)

    md5_h, sha1_h, sha256_h = hash_file(filepath)

    # Extraer las primeras 10 líneas de texto
    head_content = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            for _ in range(12):
                l = fh.readline()
                if not l:
                    break
                head_content.append(l.rstrip('\r\n'))
    except Exception:
        head_content = ['[Contenido binario o no legible]']

    return {
        'path': os.path.abspath(filepath),
        'size': st.st_size,
        'mode_octal': oct(stat.S_IMODE(st.st_mode)),
        'owner': owner,
        'mtime_local': mtime_local.strftime('%Y-%m-%d %H:%M:%S'),
        'mtime_utc': mtime_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'ctime_local': ctime_local.strftime('%Y-%m-%d %H:%M:%S'),
        'ctime_utc': ctime_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'md5': md5_h,
        'sha1': sha1_h,
        'sha256': sha256_h,
        'head': head_content
    }


def extract_log_snippets(log_paths, search_term, max_lines=20):
    """Extrae líneas completas sin truncar de los logs especificados."""
    snippets = []
    seen = set()

    expanded_paths = []
    for lp in log_paths:
        for f in glob.glob(lp + '*'):
            if os.path.isfile(f) and not f.endswith('.offset'):
                expanded_paths.append(f)

    for path in expanded_paths:
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    line_clean = line.rstrip('\r\n')
                    if search_term and search_term.lower() in line_clean.lower():
                        if line_clean not in seen:
                            seen.add(line_clean)
                            snippets.append(line_clean)
                            if len(snippets) >= max_lines:
                                return snippets
                    elif not search_term:
                        # Si no hay término, tomar primeras líneas
                        if line_clean not in seen:
                            seen.add(line_clean)
                            snippets.append(line_clean)
                            if len(snippets) >= max_lines:
                                return snippets
        except Exception:
            continue

    return snippets


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/05_abuse_evidence_collector.py) --case-id IRIS-9821 --domain cliente.com --abuse-type malware\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/05_abuse_evidence_collector.py) --case-id INC-4412 --abuse-type spam --ip 198.51.100.2\n"
    )
    parser = argparse.ArgumentParser(
        description='05. Abuse Evidence Collector — Recolector Forense Multiplataforma para Casos IRIS',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--case-id', default='TICKET-PENDING', help='ID del Caso o Ticket en IRIS')
    parser.add_argument('--abuse-type', choices=['spam', 'phishing', 'malware', 'bruteforce', 'defacement', 'unauthorized_access', 'other'],
                        default='malware', help='Tipo de abuso investigado')
    parser.add_argument('--domain', help='Dominio involucrado en el caso')
    parser.add_argument('--account', help='Cuenta de usuario / hosting involucrada')
    parser.add_argument('--ip', help='Dirección IP sospechosa o atacante')
    parser.add_argument('--files', help='Lista de rutas de archivos sospechosos separadas por coma')
    parser.add_argument('--log-files', help='Rutas de archivos de log separadas por coma')
    parser.add_argument('--grep', help='Término de búsqueda o patrón a extraer de los logs')
    parser.add_argument('--output', help='Ruta para guardar el reporte (def: evidencia_<case_id>.txt)')
    parser.add_argument('--interactive', action='store_true', help='Modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  05. Abuse Evidence Collector — Asistente de Inicio")
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

    # Preguntas interactivas si se solicita
    case_id = args.case_id
    abuse_type = args.abuse_type
    domain = args.domain
    account = args.account
    ip_target = args.ip
    files_input = args.files
    log_files_input = args.log_files
    grep_term = args.grep

    if args.interactive and sys.stdin.isatty():
        print("=" * 70)
        print("  05. Abuse Evidence Collector — Recolección Forense para IRIS")
        print("=" * 70)
        c_in = input("ID de Caso o Ticket de IRIS [%s]: " % case_id).strip()
        if c_in:
            case_id = c_in
        d_in = input("Dominio investigado (ej. victima.com): ").strip()
        if d_in:
            domain = d_in
        a_in = input("Usuario / Cuenta de hosting: ").strip()
        if a_in:
            account = a_in
        ip_in = input("Dirección IP atacante / origen: ").strip()
        if ip_in:
            ip_target = ip_in
        f_in = input("Rutas de archivos sospechosos (separadas por coma): ").strip()
        if f_in:
            files_input = f_in
        lf_in = input("Rutas de logs para extraer evidencia (separadas por coma): ").strip()
        if lf_in:
            log_files_input = lf_in
        g_in = input("Término de búsqueda para logs (grep): ").strip()
        if g_in:
            grep_term = g_in

    now_local = dt.datetime.now()
    now_utc = dt.datetime.utcnow()
    sys_info = get_system_info()

    # Procesar archivos sospechosos
    file_list = [f.strip() for f in files_input.split(',')] if files_input else []
    file_records = []
    for fp in file_list:
        if fp:
            meta = get_file_metadata(fp)
            if meta:
                file_records.append(meta)

    # Procesar logs y extraer snippets crudos
    log_paths = [lp.strip() for lp in log_files_input.split(',')] if log_files_input else []
    search_term = grep_term or ip_target or domain or account
    log_snippets = extract_log_snippets(log_paths, search_term, max_lines=25) if log_paths else []

    # Construir Expediente de Evidencia
    out = []
    out.append("=" * 80)
    out.append("EXPEDIENTE TÉCNICO DE EVIDENCIA DE ABUSO — SISTEMA IRIS")
    out.append("=" * 80)
    out.append("ID DE CASO / TICKET: %s" % case_id)
    out.append("TIPO DE INCIDENTE:   %s" % abuse_type.upper())
    out.append("FECHA DE PERITAJE:   %s (Local) | %s (UTC)" % (
        now_local.strftime('%Y-%m-%d %H:%M:%S'),
        now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
    ))
    out.append("SERVIDOR / HOST:     %s (%s)" % (sys_info['hostname'], sys_info['primary_ip']))
    out.append("SISTEMA OPERATIVO:   %s %s (%s)" % (sys_info['os'], sys_info['release'], sys_info['architecture']))
    if domain:
        out.append("DOMINIO AFECTADO:    %s" % domain)
    if account:
        out.append("CUENTA DE USUARIO:   %s" % account)
    if ip_target:
        out.append("IP SOSPECHOSA / ATACANTE: %s" % ip_target)
    out.append("=" * 80)

    # Detalle de archivos
    out.append("\n" + "=" * 80)
    out.append("1. METADATOS Y HASHES CRIPTOGRÁFICOS DE ARCHIVOS COMPROMETIDOS")
    out.append("=" * 80)
    if file_records:
        for idx, rec in enumerate(file_records, 1):
            out.append("[ITEM %02d] %s" % (idx, rec['path']))
            out.append("  Tamaño:        %d bytes" % rec['size'])
            out.append("  Permisos:      %s" % rec['mode_octal'])
            out.append("  Propietario:   %s" % rec['owner'])
            out.append("  Modificación:  %s (Local) / %s" % (rec['mtime_local'], rec['mtime_utc']))
            out.append("  Creación/Meta: %s (Local) / %s" % (rec['ctime_local'], rec['ctime_utc']))
            out.append("  Hash MD5:      %s" % rec['md5'])
            out.append("  Hash SHA-1:    %s" % rec['sha1'])
            out.append("  Hash SHA-256:  %s" % rec['sha256'])
            out.append("  --- Extracto inicial de contenido ---")
            for hl in rec['head']:
                out.append("  | " + hl)
            out.append("  --------------------------------------\n")
    else:
        out.append("No se indicaron archivos específicos o los archivos no existen en disco.")

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOG)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("2. EVIDENCIA DE LOGS EN FORMATO CRUDO (RAW SNIPPETS PARA IRIS)")
    out.append("Líneas exactas extraídas de los logs del servidor como sustento del incidente:")
    out.append("=" * 80)
    if log_snippets:
        out.append("Término de búsqueda aplicado: '%s'" % (search_term or 'TODAS'))
        out.append("-" * 80)
        for idx, s in enumerate(log_snippets, 1):
            out.append("[%02d] %s" % (idx, s))
    else:
        out.append("(No se especificaron rutas de logs o no hubo coincidencias con '%s')" % search_term)

    # Recomendaciones inmediatas de remediación
    out.append("\n" + "=" * 80)
    out.append("3. ACCIONES DE MITIGACIÓN RECOMENDADAS PARA EL OPERADOR:")
    out.append("=" * 80)
    if abuse_type == 'spam':
        out.append("  [ ] Resetear contraseña de la cuenta de correo / cPanel.")
        out.append("  [ ] Purgar cola de correos salientes en Exim para esa cuenta (exiqgrep / exim -Mrm).")
        out.append("  [ ] Bloquear IP atacante en CSF / Firewall del servidor.")
    elif abuse_type == 'malware':
        out.append("  [ ] Aislar o poner en cuarentena los archivos identificados con permisos 000.")
        out.append("  [ ] Auditar base de datos en busca de usuarios administradores añadidos.")
        out.append("  [ ] Cambiar credenciales de base de datos, cPanel y FTP.")
        out.append("  [ ] Revisar tareas programadas en crontab de la cuenta.")
    elif abuse_type == 'phishing':
        out.append("  [ ] Suspender la cuenta afectada inmediatamente para detener la recolección de credenciales.")
        out.append("  [ ] Notificar a los administradores del dominio.")
    out.append("=" * 80)
    out.append("FIN DEL EXPEDIENTE DE EVIDENCIA")
    out.append("=" * 80)

    final_content = "\n".join(out) + "\n"

    # Determinar ruta de salida
    target_output = args.output
    if not target_output:
        clean_cid = re.sub(r'[^a-zA-Z0-9_-]', '_', case_id)
        target_output = "evidencia_%s_%s.txt" % (clean_cid, now_local.strftime('%Y%m%d_%H%M%S'))

    try:
        with open(target_output, 'w', encoding='utf-8') as fh:
            fh.write(final_content)
        print("[+] Expediente técnico generado con éxito en: %s" % os.path.abspath(target_output))
    except Exception as e:
        print("[!] No se pudo guardar en archivo: %s" % e, file=sys.stderr)

    print(final_content)


if __name__ == '__main__':
    main()

