#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
09. Service Health & Exposure Check
Plataformas: Linux (cPanel, DirectAdmin, Genérico) y Windows Server
Uso:
  python3 09_service_health_check.py
  python3 09_service_health_check.py --server cpanel
  python3 09_service_health_check.py --server directadmin
  python3 09_service_health_check.py --check-miners

Audita salud de procesos, puertos abiertos, conexiones salientes de spam (puerto 25),
consumo de CPU/RAM, inodos/disco y servicios esenciales para descartar anomalías
que impacten o deriven de incidentes de seguridad.
Incluye sección de evidencia con líneas completas listas para Iris.
"""

import argparse
import collections
import io
import os
import platform
import re
import socket
import subprocess
import sys

SUSPICIOUS_PROC_PATHS = ['/tmp', '/dev/shm', '/var/tmp', 'c:\\temp', 'c:\\users\\public']
KNOWN_MINER_NAMES = ['xmrig', 'minerd', 'kdevtmpfsi', 'kinsing', 'watchdog', 'stratum', 'monero']


def is_windows():
    return platform.system() == 'Windows'


def detect_server_type():
    if is_windows():
        return 'windows'
    if os.path.isdir('/usr/local/cpanel'):
        return 'cpanel'
    if os.path.isdir('/usr/local/directadmin'):
        return 'directadmin'
    return 'generic'


def prompt_server_type():
    detected = detect_server_type()
    print("=" * 70)
    print("  09. Service Health & Exposure Check — Selección de Servidor")
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
        print("  4) Windows Server")
        sel = input("Opción [1-4]: ").strip()
        if sel == '1':
            return 'cpanel'
        elif sel == '2':
            return 'directadmin'
        elif sel == '3':
            return 'generic'
        elif sel == '4':
            return 'windows'
        print("[!] Opción inválida. Intenta nuevamente.")


def run_cmd(cmd_list, timeout=8):
    try:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.stdout.strip()
    except Exception:
        return ''


def get_disk_health():
    """Obtiene uso de espacio e inodos."""
    disk_info = []
    disk_alerts = []
    if is_windows():
        out = run_cmd(['wmic', 'logicaldisk', 'get', 'Caption,FreeSpace,Size'])
        disk_info.append(out)
    else:
        out_df = run_cmd(['df', '-h'])
        out_inodes = run_cmd(['df', '-i'])
        disk_info.append(out_df)
        disk_info.append("\nINODOS:\n" + out_inodes)

        for line in out_df.splitlines():
            m = re.search(r'(\d+)%\s+(/.*)', line)
            if m:
                percent = int(m.group(1))
                mount = m.group(2)
                if percent >= 90:
                    disk_alerts.append("[!] Espacio en disco crítico (%d%%) en %s" % (percent, mount))

        for line in out_inodes.splitlines():
            m = re.search(r'(\d+)%\s+(/.*)', line)
            if m:
                percent = int(m.group(1))
                mount = m.group(2)
                if percent >= 90:
                    disk_alerts.append("[!] Inodos críticos (%d%%) en %s" % (percent, mount))

    return "\n".join(disk_info), disk_alerts


def get_system_load():
    """Obtiene load average y memoria."""
    load_str = 'N/A'
    mem_str = 'N/A'
    if hasattr(os, 'getloadavg'):
        try:
            l1, l5, l15 = os.getloadavg()
            load_str = "%.2f, %.2f, %.2f (1, 5, 15 min)" % (l1, l5, l15)
        except Exception:
            pass

    if not is_windows():
        mem_str = run_cmd(['free', '-h'])
    else:
        mem_str = run_cmd(['systeminfo'])

    return load_str, mem_str


def get_running_processes():
    """Analiza procesos en busca de anomalías, miners o rutas en /tmp."""
    suspicious_procs = []
    raw_ps_lines = []
    top_cpu_procs = []

    if is_windows():
        out = run_cmd(['tasklist', '/v'])
        for l in out.splitlines():
            raw_ps_lines.append(l)
    else:
        out = run_cmd(['ps', 'aux', '--sort=-%cpu'])
        lines = out.splitlines()
        if lines:
            header = lines[0]
            top_cpu_procs = lines[1:11]

            for l in lines[1:]:
                # Detectar mineros o rutas temporales
                l_lower = l.lower()
                is_miner = any(m in l_lower for m in KNOWN_MINER_NAMES)
                is_temp_path = any(tp in l_lower for tp in SUSPICIOUS_PROC_PATHS)
                if is_miner or is_temp_path:
                    suspicious_procs.append(l)
                if len(raw_ps_lines) < 15:
                    raw_ps_lines.append(l)

    return top_cpu_procs, suspicious_procs, raw_ps_lines


def get_network_exposure():
    """Analiza puertos abiertos y conexiones salientes (especialmente SMTP port 25)."""
    raw_netstat_lines = []
    listening_ports = []
    smtp_connections = []
    remote_ip_counter = collections.Counter()

    if is_windows():
        out = run_cmd(['netstat', '-ano'])
        for l in out.splitlines():
            if 'LISTENING' in l:
                listening_ports.append(l.strip())
            raw_netstat_lines.append(l.strip())
    else:
        # Linux ss o netstat
        out = run_cmd(['ss', '-tulpn']) or run_cmd(['netstat', '-tulpn'])
        for l in out.splitlines():
            if 'LISTEN' in l:
                listening_ports.append(l.strip())
            raw_netstat_lines.append(l.strip())

        # Revisar conexiones salientes al puerto 25 (spam directo)
        out_smtp = run_cmd(['ss', '-tn', 'state', 'established', 'dport = :25']) or run_cmd(['netstat', '-tn'])
        for l in out_smtp.splitlines():
            if ':25 ' in l or ':25\t' in l:
                smtp_connections.append(l.strip())

        # Conexiones establecidas para conteo de IPs
        out_est = run_cmd(['ss', '-tn', 'state', 'established']) or out_smtp
        for l in out_est.splitlines():
            m_ip = re.search(r'([0-9a-fA-F:.]+):(?:\d+)\s+([0-9a-fA-F:.]+):(?:\d+)', l)
            if m_ip:
                rem_ip = m_ip.group(2)
                if not rem_ip.startswith('127.') and rem_ip != '::1':
                    remote_ip_counter[rem_ip] += 1

    return listening_ports, smtp_connections, remote_ip_counter, raw_netstat_lines


def check_essential_services(server_type):
    """Verifica estado de los servicios clave para el entorno."""
    services = []
    if server_type == 'cpanel':
        services = ['httpd', 'nginx', 'exim', 'dovecot', 'mysqld', 'named', 'cpanel', 'crond', 'csf']
    elif server_type == 'directadmin':
        services = ['directadmin', 'httpd', 'nginx', 'exim', 'dovecot', 'mysqld', 'named', 'crond', 'csf']
    elif server_type == 'windows':
        services = ['W3SVC', 'MSSQLSERVER', 'SMTPSVC', 'WinDefend']
    else:
        services = ['apache2', 'httpd', 'nginx', 'postfix', 'exim4', 'dovecot', 'mariadb', 'mysql', 'ssh']

    status_dict = {}
    if not is_windows():
        for s in services:
            out = run_cmd(['systemctl', 'is-active', s])
            if out:
                status_dict[s] = out.strip()
    else:
        for s in services:
            out = run_cmd(['sc', 'query', s])
            state = 'STOPPED'
            if 'RUNNING' in out:
                state = 'RUNNING'
            status_dict[s] = state

    return status_dict


def main():
    if (getattr(sys.stdout, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if (getattr(sys.stderr, 'encoding', None) or '').lower() != 'utf-8' and hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    epilog = (
        "Ejemplos de ejecución directa en terminal (One-liner):\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/09_service_health_check.py) --server cpanel\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/09_service_health_check.py) --server directadmin\n"
        "  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/09_service_health_check.py) --check-miners\n"
    )
    parser = argparse.ArgumentParser(
        description='09. Service Health & Exposure Check — Diagnóstico de Procesos, Red, Puertos y Salud Operativa',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', choices=['cpanel', 'directadmin', 'generic', 'windows', 'auto'], default='auto')
    parser.add_argument('--check-miners', action='store_true', default=True, help='Escanear procesos en búsqueda de crypto-miners')
    parser.add_argument('--output', help='Ruta para guardar el reporte')
    parser.add_argument('--interactive', action='store_true', help='Modo interactivo')

    if len(sys.argv) == 1 and sys.stdin.isatty():
        print("=" * 70)
        print("  09. Service Health & Exposure Check — Asistente de Inicio")
        print("=" * 70)
        print("Selecciona cómo deseas ejecutar:")
        print("  1) Asistente interactivo guiado (Paso a paso) [Recomendado]")
        print("  2) Auditoría rápida con valores por defecto")
        print("  3) Ver ayuda completa y opciones de comando (--help)")
        opt = input("Opción [1-3, def: 1]: ").strip()
        if opt == '3':
            parser.print_help()
            sys.exit(0)
        elif opt == '1' or opt == '':
            sys.argv.append('--interactive')

    args = parser.parse_args()

    server = args.server
    if args.interactive or server == 'auto':
        detected = detect_server_type()
        if args.interactive:
            server = prompt_server_type()
        else:
            server = detected

    print("=" * 80)
    print("09. SERVICE HEALTH & EXPOSURE CHECK")
    print("=" * 80)
    print("Servidor: %s | Plataforma: %s" % (server.upper(), platform.system()))

    load_avg, mem_info = get_system_load()
    disk_text, disk_alerts = get_disk_health()
    top_procs, susp_procs, raw_ps = get_running_processes()
    ports, smtp_conns, rem_ips, raw_net = get_network_exposure()
    srv_status = check_essential_services(server)

    # Cola de correo Exim si aplica
    mail_queue_count = 'N/A'
    if server in ('cpanel', 'directadmin'):
        exim_bpc = run_cmd(['exim', '-bpc'])
        if exim_bpc and exim_bpc.isdigit():
            mail_queue_count = exim_bpc.strip()

    # Construcción de Reporte
    out = []
    out.append("=" * 80)
    out.append("09. SERVICE HEALTH & EXPOSURE CHECK — DIAGNÓSTICO OPERATIVO Y FORENSE")
    out.append("=" * 80)
    out.append("Servidor: %s | OS: %s" % (server.upper(), platform.system()))
    out.append("Carga del Sistema (Load Average): %s" % load_avg)
    if mail_queue_count != 'N/A':
        out.append("Correos en cola de Exim (exim -bpc): %s" % mail_queue_count)
    out.append("-" * 80)

    # Alertas operativas
    out.append("ALERTAS OPERATIVAS QUE PUEDEN AFECTAR LA INVESTIGACIÓN:")
    out.append("-" * 80)
    has_alerts = False
    if disk_alerts:
        has_alerts = True
        for a in disk_alerts:
            out.append("  " + a)
    if susp_procs:
        has_alerts = True
        out.append("  [!] PROCESOS SOSPECHOSOS DETECTADOS (%d procesos en /tmp o con firmas de miners)" % len(susp_procs))
    if smtp_conns:
        has_alerts = True
        out.append("  [!] CONEXIONES SALIENTES AL PUERTO 25 DETECTADAS (%d activas - potencial bot de spam)" % len(smtp_conns))
    if not has_alerts:
        out.append("  [OK] No se detectaron alertas operativas críticas en disco, memoria o procesos.")

    # Servicios
    out.append("\nESTADO DE SERVICIOS CRÍTICOS:")
    out.append("-" * 80)
    for srv, st in srv_status.items():
        icon = "[OK]" if st in ('active', 'RUNNING') else "[!]"
        out.append("  %-16s : %-10s %s" % (srv, st, icon))

    # Procesos sospechosos
    if susp_procs:
        out.append("\nPROCESOS SOSPECHOSOS (EJECUTÁNDOSE EN /tmp O MINERS):")
        out.append("-" * 80)
        for p in susp_procs[:10]:
            out.append("  " + p)

    # Top CPU
    out.append("\nTOP PROCESOS CON MAYOR CONSUMO DE CPU:")
    out.append("-" * 80)
    for p in top_procs[:7]:
        out.append("  " + p)

    # Conexiones salientes SMTP
    if smtp_conns:
        out.append("\nCONEXIONES SALIENTES DIRECTAS A PUERTO 25 (SMTP):")
        out.append("-" * 80)
        for c in smtp_conns[:10]:
            out.append("  " + c)

    # Conexiones por IP externa
    if rem_ips:
        out.append("\nTOP IPs EXTERNAS CON CONEXIONES ESTABLECIDAS:")
        out.append("-" * 80)
        for ip, cnt in rem_ips.most_common(10):
            out.append("  %6d conexiones desde %s" % (cnt, ip))

    # ==============================================================================
    # SECCIÓN DE EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE RED, PROCESOS Y DISCO)
    # ==============================================================================
    out.append("\n" + "=" * 80)
    out.append("EVIDENCIA PARA IRIS (LÍNEAS CRUDAS DE PROCESOS, PUERTOS Y DISCO)")
    out.append("Copiar y pegar las siguientes secciones directamente en el caso de IRIS:")
    out.append("=" * 80)

    out.append("\n--- [EVIDENCIA 1/3] LISTADO CRUDO DE PROCESOS (PS AUX) ---")
    if susp_procs:
        for idx, l in enumerate(susp_procs[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    elif raw_ps:
        for idx, l in enumerate(raw_ps[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros de procesos disponibles)")

    out.append("\n--- [EVIDENCIA 2/3] PUERTOS Y CONEXIONES DE RED (SS / NETSTAT) ---")
    if smtp_conns:
        for idx, l in enumerate(smtp_conns[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    elif ports:
        for idx, l in enumerate(ports[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin registros de puertos disponibles)")

    out.append("\n--- [EVIDENCIA 3/3] ESTADO DE DISCO Y PARTICIONES (DF -H) ---")
    if disk_text:
        for idx, l in enumerate(disk_text.splitlines()[:8], 1):
            out.append("[%02d] %s" % (idx, l))
    else:
        out.append("(Sin datos de disco disponibles)")

    out.append("\n" + "=" * 80)
    out.append("FIN DEL REPORTE")
    out.append("=" * 80)

    result_text = "\n".join(out) + "\n"

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fh:
                fh.write(result_text)
            print("[+] Reporte de salud y exposición guardado en: %s" % args.output)
        except OSError as e:
            print("[!] Error al guardar archivo: %s" % e, file=sys.stderr)
            print(result_text)
    else:
        print(result_text)


if __name__ == '__main__':
    main()

