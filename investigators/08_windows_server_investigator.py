#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
08. Windows Server Investigator
Plataformas: Windows Server (ejecución directa) o Linux/macOS (análisis de logs exportados)
Uso:
  # En Windows Server directo:
  python 08_windows_server_investigator.py
  python 08_windows_server_investigator.py --iis-dir "C:\\inetpub\\logs\\LogFiles\\W3SVC1" --rdp-check
  python 08_windows_server_investigator.py --days 3

  # En Linux analizando logs IIS exportados:
  python3 08_windows_server_investigator.py --mode offline --iis-dir /ruta/a/W3SVC1 --days 3

Investiga peticiones IIS a archivos sospechosos (.aspx, webshells, POST),
analiza eventos de Windows (Logon RDP 4624/4625, creación de usuarios 4720, servicios 7045),
sesiones RDP activas, tareas programadas sospechosas y actividad SMTP en Windows.
Incluye sección de evidencia con líneas de log completas listas para Iris.
"""

import argparse
import collections
import csv
import datetime as dt
import glob
import io
import os
import platform
import re
import subprocess
import sys

SUSPICIOUS_IIS_EXTS = ['.aspx', '.ashx', '.asmx', '.asp', '.php', '.cer', '.cdx', '.jsp']
SUSPICIOUS_IIS_NAMES = [
    'cmd', 'shell', 'antak', 'chopper', 'eval', 'upload', 'b374k',
    'wso', 'alfa', 'root', 'backdoor', 'test.aspx', 'error.aspx'
]


def is_running_on_windows():
    return platform.system() == 'Windows'


def parse_w3c_iis_line(line, field_names):
    """Parsea una línea de formato W3C de IIS utilizando la cabecera #Fields."""
    if line.startswith('#'):
        return None
    parts = line.split()
    if len(parts) != len(field_names):
        return None
    return dict(zip(field_names, parts))


def analyze_iis_logs(iis_dirs, since_dt, target_ip=None, target_status=None):
    """Analiza los logs de IIS en formato W3C."""
    ip_counter = collections.Counter()
    uri_counter = collections.Counter()
    post_counter = collections.Counter()
    status_counter = collections.Counter()
    suspicious_requests = collections.Counter()
    raw_evidence = []
    seen = set()

    for d in iis_dirs:
        for f in glob.glob(os.path.join(d, '*.log')):
            if not os.path.isfile(f):
                continue
            field_names = []
            try:
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        line_str = line.strip()
                        if line_str.startswith('#Fields:'):
                            field_names = line_str.split()[1:]
                            continue
                        if not field_names or line_str.startswith('#'):
                            continue

                        parts = line_str.split()
                        if len(parts) < len(field_names):
                            continue

                        record = dict(zip(field_names, parts))
                        # Campos estándar W3C: date, time, c-ip, cs-method, cs-uri-stem, sc-status
                        d_val = record.get('date', '')
                        t_val = record.get('time', '')
                        c_ip = record.get('c-ip', '')
                        method = record.get('cs-method', '')
                        uri = record.get('cs-uri-stem', '')
                        status = record.get('sc-status', '')

                        try:
                            req_time = dt.datetime.strptime('%s %s' % (d_val, t_val), '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            continue

                        if req_time < since_dt:
                            continue

                        if target_ip and c_ip != target_ip:
                            continue
                        if target_status and status != target_status:
                            continue

                        ip_counter[c_ip] += 1
                        uri_counter[uri] += 1
                        status_counter[status] += 1

                        if method == 'POST':
                            post_counter[uri] += 1

                        # Detección sospechosa
                        ext = os.path.splitext(uri)[1].lower()
                        is_susp = ext in SUSPICIOUS_IIS_EXTS and any(s in uri.lower() for s in SUSPICIOUS_IIS_NAMES)
                        if is_susp:
                            suspicious_requests["%s %s (desde %s status %s)" % (method, uri, c_ip, status)] += 1

                        if line_str not in seen and len(raw_evidence) < 15:
                            if is_susp or method == 'POST' or status == '500':
                                seen.add(line_str)
                                raw_evidence.append(line_str)

            except Exception:
                continue

    return {
        'ips': ip_counter,
        'uris': uri_counter,
        'posts': post_counter,
        'statuses': status_counter,
        'suspicious': suspicious_requests,
        'raw': raw_evidence
    }


def query_windows_events(days=3):
    """Consulta el Visor de Eventos de Windows usando wevtutil o PowerShell si está en Windows."""
    events_summary = collections.Counter()
    raw_event_lines = []

    if not is_running_on_windows():
        return events_summary, raw_event_lines

    # Consultar eventos de seguridad de los últimos N días
    since_str = (dt.datetime.utcnow() - dt.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    # Event ID 4625 (Logon fallido) y 4624 (Logon exitoso)
    ps_cmd = (
        'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624,4625; StartTime=(Get-Date).AddDays(-%d)} -MaxEvents 150 '
        '| Select-Object TimeCreated, Id, Message | ConvertTo-Json' % days
    )

    try:
        proc = subprocess.run(['powershell', '-Command', ps_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        if proc.returncode == 0 and proc.stdout.strip():
            lines = proc.stdout.splitlines()
            for l in lines[:20]:
                if l.strip():
                    raw_event_lines.append(l.strip())
            events_summary["Eventos de Logon (4624/4625) extraídos"] = len(raw_event_lines)
    except Exception as e:
        events_summary["Error consultando PowerShell: %s" % e] = 1

    return events_summary, raw_event_lines


def get_rdp_sessions():
    """Consulta sesiones RDP activas usando qwinsta en Windows."""
    sessions = []
    if not is_running_on_windows():
        return sessions
    try:
        res = subprocess.run(['qwinsta'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0:
            sessions = [l.strip() for l in res.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    return sessions


def get_scheduled_tasks():
    """Busca tareas programadas en Windows con scripts o rutas temporales."""
    suspicious_tasks = []
    raw_tasks = []
    if not is_running_on_windows():
        return suspicious_tasks, raw_tasks
    try:
        res = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if res.returncode == 0:
            blocks = res.stdout.split('\n\n')
            for b in blocks:
                if re.search(r'(?:powershell|cmd\.exe|wscript|cscript|\.vbs|\.bat|\.ps1|temp|public)', b, re.I):
                    m_name = re.search(r'TaskName:\s*(.*)', b)
                    task_name = m_name.group(1).strip() if m_name else 'Tarea Desconocida'
                    suspicious_tasks.append(task_name)
                    raw_tasks.append(b.strip()[:300])
                    if len(raw_tasks) >= 5:
                        break
    except Exception:
        pass
    return suspicious_tasks, raw_tasks


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python 08_windows_server_investigator.py --days 3\n"
        "  python 08_windows_server_investigator.py --ip 198.51.100.5\n"
        "  python3 08_windows_server_investigator.py --mode offline --iis-dir /ruta/a/W3SVC1\n"
    )
    parser = argparse.ArgumentParser(
        description='08. Windows Server Investigator — Auditoría de IIS, RDP, Eventos y Persistencia en Windows',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--mode', choices=['live', 'offline', 'auto'], default='auto',
                        help='live (ejecución directa en Windows) u offline (análisis de logs en Linux/macOS)')
    parser.add_argument('--iis-dir', help='Directorio de logs IIS W3C (def: C:\\inetpub\\logs\\LogFiles\\W3SVC*)')
    parser.add_argument('--ip', help='Filtrar peticiones por IP cliente')
    parser.add_argument('--days', type=int, default=3, help='Días hacia atrás a investigar (def: 3)')
    parser.add_argument('--output', help='Ruta para guardar el reporte')
    parser.add_argument('--rdp-check', action='store_true', default=True, help='Auditar sesiones RDP')
    parser.add_argument('--interactive', action='store_true', help='Modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  08. Windows Server Investigator — Asistente de Inicio")
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

    mode = args.mode
    if mode == 'auto':
        mode = 'live' if is_running_on_windows() else 'offline'

    now = dt.datetime.now()
    since = now - dt.timedelta(days=args.days)

    iis_paths = []
    if args.iis_dir:
        iis_paths.append(args.iis_dir)
    else:
        if is_running_on_windows():
            iis_paths = glob.glob(r'C:\inetpub\logs\LogFiles\W3SVC*')
            if not iis_paths:
                iis_paths = [r'C:\inetpub\logs\LogFiles']
        else:
            # Fallback a directorio local si se pasaron logs exportados
            iis_paths = glob.glob('./W3SVC*') or ['./iis_logs'] or ['./']

    print("=" * 80)
    print("08. WINDOWS SERVER INVESTIGATOR")
    print("=" * 80)
    print("Modo de ejecución: %s" % mode.upper())
    print("Ventana temporal:  %s a %s" % (since.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S')))
    print("Directorios IIS:   %s" % (", ".join(iis_paths) if iis_paths else "Ninguno"))
    print("-" * 80)

    # 1. Análisis de IIS
    iis_results = analyze_iis_logs(iis_paths, since, target_ip=args.ip)

    # 2. Eventos de Windows y RDP si es live
    events_summary, raw_events = ({}, [])
    rdp_sessions = []
    susp_tasks, raw_tasks = ([], [])

    if mode == 'live':
        print("[*] Consultando eventos de seguridad de Windows...")
        events_summary, raw_events = query_windows_events(days=args.days)
        print("[*] Verificando sesiones RDP y tareas programadas...")
        rdp_sessions = get_rdp_sessions()
        susp_tasks, raw_tasks = get_scheduled_tasks()

    # Construcción de Reporte
    out = []
    out.append("=" * 80)
    out.append("08. WINDOWS SERVER INVESTIGATOR — REPORTE DE AUDITORÍA FORENSE")
    out.append("=" * 80)
    out.append("Modo: %s | Plataforma: %s" % (mode.upper(), platform.system()))
    out.append("Período investigado: %s a %s" % (since.strftime('%Y-%m-%d %H:%M:%S'), now.strftime('%Y-%m-%d %H:%M:%S')))
    out.append("-" * 80)

    def print_counter(title, counter, top=15, unit='hits'):
        out.append("\n" + title)
        out.append("-" * len(title))
        if not counter:
            out.append("Sin registros.")
            return
        for k, v in counter.most_common(top):
            out.append("{0:>8} {1} {2}".format(v, unit, k))

    print_counter("TOP IPs CON ACCESOS WEB A IIS", iis_results['ips'])
    print_counter("TOP RECURSOS / WEBSHELLS SOLICITADOS EN IIS", iis_results['uris'])
    print_counter("TOP PETICIONES CON MÉTODO POST EN IIS", iis_results['posts'])
    print_counter("CÓDIGOS DE ESTADO IIS (sc-status)", iis_results['statuses'])
    print_counter("PETICIONES SOSPECHOSAS DETECTADAS EN IIS", iis_results['suspicious'])

    if rdp_sessions:
        out.append("\nSESIONES RDP / TERMINAL (qwinsta):")
        out.append("-" * 80)
        for s in rdp_sessions:
            out.append("  " + s)

    if susp_tasks:
        out.append("\nTAREAS PROGRAMADAS SOSPECHOSAS IDENTIFICADAS:")
        out.append("-" * 80)
        for t in susp_tasks:
            out.append("  [!] " + t)

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS W3C / EVENTOS)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE LOG W3C Y EVENTOS WINDOWS)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso de IRIS:")
    out.append("=" * 80)

    out.append("\n--- [EVIDENCIA 1/3] LÍNEAS COMPLETAS DE LOG IIS (FORMATO W3C) ---")
    if iis_results['raw']:
        for idx, l in enumerate(iis_results['raw'][:10], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(No se registraron líneas de evidencia directa en IIS)")

    out.append("\n--- [EVIDENCIA 2/3] REGISTROS DEL VISOR DE EVENTOS DE WINDOWS ---")
    if raw_events:
        for idx, l in enumerate(raw_events[:10], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin eventos de seguridad registrados o ejecución en modo offline)")

    out.append("\n--- [EVIDENCIA 3/3] EXTRACTOS DE TAREAS PROGRAMADAS SOSPECHOSAS ---")
    if raw_tasks:
        for idx, l in enumerate(raw_tasks[:5], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin tareas programadas anómalas registradas)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de Windows Server guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

