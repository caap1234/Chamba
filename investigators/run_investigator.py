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
"""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

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
        script_path = os.path.join(SCRIPT_DIR, script_name)

        if not os.path.isfile(script_path):
            print("\n[!] Error: No se localizó el archivo: %s" % script_path)
            input("Presiona Enter para continuar...")
            continue

        print("\n" + "=" * 80)
        print("EJECUTANDO: [%s] %s" % (num, name))
        print("=" * 80)
        print("Para pasar parámetros directos o modo interactivo:")
        extra_args = input("Ingresa parámetros adicionales (o Enter para modo guiado interactivo): ").strip()

        cmd = [sys.executable, script_path]
        if extra_args:
            cmd.extend(extra_args.split())
        else:
            cmd.append('--interactive')

        print("\n[+] Comando: %s\n" % " ".join(cmd))
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\n[!] Ejecución interrumpida por el usuario.")
        except Exception as e:
            print("\n[!] Error ejecutando módulo: %s" % e)

        print("\n" + "-" * 80)
        input("Ejecución finalizada. Presiona Enter para volver al menú principal...")


if __name__ == '__main__':
    main()
