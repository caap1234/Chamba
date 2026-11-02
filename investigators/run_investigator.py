#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suite de Investigadores Forenses y de Abuso — Hub Central
Lanzador interactivo para la suite completa de herramientas de investigación:

01. Abuse Mail Investigator
02. Web Access Investigator
03. Malware & File Investigator
04. Account Access Investigator
05. Abuse Evidence Collector
06. DNS & Domain Investigator
07. Suspicious Activity Correlator
08. Windows Server Investigator
09. Service Health & Exposure Check

Uso directo en cualquier servidor (sin necesidad de clonar el repo):
  python3 <(wget -qO- https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/run_investigator.py)
  python3 <(curl -sL https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/run_investigator.py)
"""

import os
import subprocess
import sys
import tempfile
import urllib.request

RAW_GITHUB_BASE = "https://raw.githubusercontent.com/caap1234/Chamba/main/investigators/"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else '/tmp'

TOOLS = [
    ("01", "Abuse Mail Investigator", "01_abuse_mail_investigator.py", "Exim, Dovecot, Spam, Webmail X-Forwarded-For"),
    ("02", "Web Access Investigator", "02_web_access_investigator.py", "Apache, Nginx, POST, Webshells, Domlogs"),
    ("03", "Malware & File Investigator", "03_malware_file_investigator.py", "Archivos recientes, Hashes MD5/SHA256, Permisos, Persistencia"),
    ("04", "Account Access Investigator", "04_account_access_investigator.py", "cPanel, WHM, DirectAdmin, SSH logins y auditoría"),
    ("05", "Abuse Evidence Collector", "05_abuse_evidence_collector.py", "Compilador técnico para expedientes y tickets de IRIS"),
    ("06", "DNS & Domain Investigator", "06_dns_domain_investigator.py", "Resolución DNS, MX, SPF, Hosting, CDN y propagación"),
    ("07", "Suspicious Activity Correlator", "07_suspicious_activity_correlator.py", "Timeline cronológico cruzando IP, Web, Exim, Archivos y SSH"),
    ("08", "Windows Server Investigator", "08_windows_server_investigator.py", "IIS W3C logs, Eventos Windows 4624/4625, RDP, Tareas"),
    ("09", "Service Health & Exposure Check", "09_service_health_check.py", "Procesos, Miners, Puertos, Conexiones SMTP, Inodos y Servicios"),
]


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def ensure_script_available(script_name):
    """
    Verifica si el script está en disco local. Si no existe (ej. ejecución
    vía pipe wget o curl), lo descarga automáticamente de GitHub a /tmp.
    """
    local_path = os.path.join(SCRIPT_DIR, script_name)
    if os.path.isfile(local_path):
        return local_path

    tmp_path = os.path.join(tempfile.gettempdir(), script_name)
    if os.path.isfile(tmp_path):
        return tmp_path

    # Descargar desde GitHub raw
    url = RAW_GITHUB_BASE + script_name
    print("[*] Descargando módulo '%s' desde GitHub..." % script_name)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Neubox-Investigator-Runner/1.0'})
        with urllib.request.urlopen(req, timeout=12) as resp:
            content = resp.read()
        with open(tmp_path, 'wb') as fh:
            fh.write(content)
        os.chmod(tmp_path, 0o755)
        print("[+] Descarga completada en: %s" % tmp_path)
        return tmp_path
    except Exception as e:
        print("[!] Error descargando módulo desde %s: %s" % (url, e))
        # Intento fallback con wget o curl
        try:
            cmd = ['wget', '-qO', tmp_path, url]
            subprocess.run(cmd, timeout=10)
            if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 0:
                os.chmod(tmp_path, 0o755)
                return tmp_path
        except Exception:
            pass
        return None


def print_banner():
    print("=" * 80)
    print("        NEUBOX INCIDENT RESPONSE & ABUSE INVESTIGATION TOOLKIT")
    print("=" * 80)
    print("Selecciona el módulo que deseas ejecutar:\n")
    for num, name, _, desc in TOOLS:
        print("  [%s] %-32s — %s" % (num, name, desc))
    print("\n  [00] Salir")
    print("=" * 80)


def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print(__doc__)
        sys.exit(0)

    while True:
        print_banner()
        choice = input("\nIngresa el número de módulo [01-09, 00 para salir]: ").strip()
        if choice in ('00', '0', 'exit', 'quit', 'q'):
            print("\nSaliendo del toolkit. ¡Buen turno!")
            break

        # Normalizar '1' a '01'
        if len(choice) == 1 and choice.isdigit():
            choice = '0' + choice

        matched_tool = None
        for num, name, script, desc in TOOLS:
            if num == choice:
                matched_tool = (num, name, script, desc)
                break

        if not matched_tool:
            input("\n[!] Opción no reconocida. Presiona Enter para continuar...")
            continue

        num, name, script_name, desc = matched_tool
        script_path = ensure_script_available(script_name)

        if not script_path or not os.path.isfile(script_path):
            print("\n[!] Error: No se pudo obtener el script: %s" % script_name)
            input("Presiona Enter para continuar...")
            continue

        print("\n" + "=" * 80)
        print("EJECUTANDO: [%s] %s" % (num, name))
        print("=" * 80)
        print("¿Cómo deseas ejecutar el módulo?")
        print("  1) Asistente interactivo guiado (Paso a paso) [Recomendado]")
        print("  2) Ver ayuda completa y ejemplos (--help)")
        print("  3) Personalizar parámetros manualmente en línea de comandos")
        print("  4) Ejecución rápida estándar con valores por defecto")
        mode_sel = input("Opción [1-4, def: 1]: ").strip()

        cmd = [sys.executable, script_path]
        if mode_sel == '2':
            cmd.append('--help')
        elif mode_sel == '3':
            user_params = input("Ingresa los argumentos (ej. --server cpanel --email user@dom.com): ").strip()
            if user_params:
                cmd.extend(user_params.split())
        elif mode_sel == '4':
            pass
        else:
            cmd.append('--interactive')

        print("\n[+] Comando a ejecutar: %s\n" % " ".join(cmd))
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\n[!] Ejecución interrumpida por el usuario.")
        except Exception as e:
            print("\n[!] Error ejecutando módulo: %s" % e)

        print("\n" + "-" * 80)
        input("Presiona Enter para volver al menú principal...")


if __name__ == '__main__':
    main()
