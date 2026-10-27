#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DFIR-IRIS Abuse Sync CLI
------------------------
Automatización de creación de casos en DFIR-IRIS a partir de tickets de abuso en PDF.
Soporta SOC Abuse Lite v2.0 (Phishing, Spam, Fraude, Marca, Malware, Red, Takedown).
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import Optional

import config
from parser import TicketParser, extract_text_from_pdf
from classifier import TemplateClassifier
from case_builder import CaseBuilder
from iris_client import IrisClient


class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'
    END = '\033[0m'


def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════╗
║          DFIR-IRIS Abuse Sync — SOC Neubox Automation                ║
║           Clasificador Inteligente & Creador de Casos                 ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.END}""")


def cmd_test_iris(args):
    print(f"\n{Colors.BOLD}Comprobando conexión con DFIR-IRIS...{Colors.END}")
    print(f"URL: {Colors.CYAN}{config.IRIS_URL}{Colors.END}")
    client = IrisClient()
    res = client.test_connection()
    if res.get("success"):
        print(f"{Colors.GREEN}✓ Conexión exitosa con DFIR-IRIS (HTTP {res.get('status_code')}){Colors.END}")
        tmpl_res = client.get_templates()
        if tmpl_res.get("success"):
            tmpls = tmpl_res.get("templates", {})
            print(f"{Colors.GREEN}✓ Se encontraron {len(tmpls)} templates en el servidor:{Colors.END}")
            for name, tid in tmpls.items():
                print(f"   • {Colors.YELLOW}{name}{Colors.END} -> ID {tid}")
        else:
            print(f"{Colors.YELLOW}! No se pudieron consultar templates remotos ({tmpl_res.get('error')}){Colors.END}")
    else:
        print(f"{Colors.RED}✗ Error conectando a DFIR-IRIS: {res.get('error')}{Colors.END}")
        print(f"{Colors.GRAY}Consejo: Revisa las variables IRIS_URL y IRIS_API_KEY en tu archivo .env{Colors.END}")


def cmd_list_templates(args):
    clf = TemplateClassifier()
    print(f"\n{Colors.BOLD}Templates locales disponibles (SOC Abuse Lite v2.0):{Colors.END}")
    for name, data in clf.templates.items():
        prefix = data.get("title_prefix", "")
        disp = data.get("display_name", "")
        tags = ", ".join(data.get("tags", []))
        desc = data.get("description", "")
        print(f"\n {Colors.CYAN}{prefix}{Colors.END} {Colors.BOLD}{disp}{Colors.END} ({Colors.YELLOW}{name}{Colors.END})")
        print(f"   {Colors.GRAY}Tags: {tags}{Colors.END}")
        print(f"   {Colors.GRAY}{desc}{Colors.END}")


def cmd_parse(args):
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"{Colors.RED}Error: El archivo '{file_path}' no existe.{Colors.END}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}Analizando archivo:{Colors.END} {file_path.name}")
    if file_path.suffix.lower() == ".pdf":
        raw_text = extract_text_from_pdf(file_path)
    else:
        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")

    parser = TicketParser(raw_text)
    data = parser.parse()

    clf = TemplateClassifier()
    classification = clf.classify(data)

    print(f"\n{Colors.GREEN}{Colors.BOLD}--- Datos Extraídos del Ticket ---{Colors.END}")
    print(f"  • {Colors.BOLD}Ticket ID:{Colors.END} {data['ticket_id'] or 'No detectado'}")
    print(f"  • {Colors.BOLD}URL Ticket:{Colors.END} {data['ticket_url']}")
    rep_org_str = f"({data.get('reporter_org')})" if data.get('reporter_org') else ""
    print(f"  • {Colors.BOLD}Reportante:{Colors.END} {data['reporter']} {rep_org_str}")
    print(f"  • {Colors.BOLD}Activo Afectado:{Colors.END} {Colors.CYAN}{data['affected_asset']}{Colors.END}")
    print(f"  • {Colors.BOLD}Servidor(es) Neubox:{Colors.END} {', '.join(data['neubox_servers']) or 'No especificado'}")
    print(f"  • {Colors.BOLD}IP Primaria:{Colors.END} {data['primary_ip'] or 'No detectada'}")
    print(f"  • {Colors.BOLD}Cuenta Autenticada:{Colors.END} {data['primary_account'] or 'N/A'}")
    print(f"  • {Colors.BOLD}Ticket Titular:{Colors.END} {data['client_ticket'] or 'N/A'}")
    print(f"  • {Colors.BOLD}Resumen:{Colors.END} {data['brief_summary']}")

    print(f"\n{Colors.MAGENTA}{Colors.BOLD}--- Clasificación de Template Recomendada ---{Colors.END}")
    print(f"  • {Colors.BOLD}Template:{Colors.END} {classification['title_prefix']} {classification['display_name']} ({Colors.YELLOW}{classification['template_name']}{Colors.END})")
    print(f"  • {Colors.BOLD}Confianza:{Colors.END} {classification['confidence'] * 100:.1f}%")
    print(f"  • {Colors.BOLD}Criterios / Motivos:{Colors.END} {', '.join(classification['reasons'])}")

    print(f"\n{Colors.YELLOW}{Colors.BOLD}--- Indicadores (IOCs) detectados ({len(data['iocs'])}) ---{Colors.END}")
    for ioc in data['iocs']:
        print(f"  [{ioc['type'].upper()}] {ioc['value']}")

    if args.json:
        payload = CaseBuilder.build(data, classification)
        print("\n" + json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_create(args):
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"{Colors.RED}Error: El archivo '{file_path}' no existe.{Colors.END}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}Procesando:{Colors.END} {file_path.name}")
    if file_path.suffix.lower() == ".pdf":
        raw_text = extract_text_from_pdf(file_path)
    else:
        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")

    parser = TicketParser(raw_text)
    data = parser.parse()

    clf = TemplateClassifier()
    classification = clf.classify(data)

    # Allow overriding template via --template
    if args.template:
        tmpl_name = args.template
        # Check if matched by prefix or name
        matched = None
        for k, v in clf.templates.items():
            if k == tmpl_name or v.get("title_prefix", "").strip("[]").lower() == tmpl_name.strip("[]").lower():
                matched = k
                break
        if matched and matched in clf.templates:
            tmpl_obj = clf.templates[matched]
            classification = {
                "template_name": matched,
                "title_prefix": tmpl_obj.get("title_prefix", "[ABUSE]"),
                "display_name": tmpl_obj.get("display_name", matched),
                "template_data": tmpl_obj,
                "confidence": 1.0,
                "reasons": ["Manual override specified by user"]
            }
            print(f"{Colors.YELLOW}! Template forzado por el usuario: {classification['title_prefix']} ({matched}){Colors.END}")
        else:
            print(f"{Colors.RED}Advertencia: El template '{args.template}' no fue encontrado. Usando clasificación automática.{Colors.END}")

    overrides = {
        "customer_key": args.customer.lower() if args.customer and not args.customer.isdigit() else None,
        "report_ticket": args.report_ticket,
        "client_ticket": args.client_ticket,
        "client_id": args.client_id,
        "service_id": args.service_id,
        "server": args.server,
        "affected_asset": args.asset
    }

    # If customer is an integer ID, map it or use directly
    customer_key = None
    if args.customer:
        if args.customer.lower() in ("hospedando", "hp", "3"):
            customer_key = "hospedando"
        elif args.customer.lower() in ("neubox", "nbx", "2"):
            customer_key = "neubox"

    payload = CaseBuilder.build(data, classification, customer_key=customer_key, overrides=overrides)

    is_dry = args.dry_run
    mode_str = f"{Colors.YELLOW}[MODO SIMULACIÓN (DRY-RUN)]{Colors.END}" if is_dry else f"{Colors.GREEN}[MODO REAL]{Colors.END}"
    print(f"\nCreando caso en DFIR-IRIS {mode_str}...")
    print(f"  • Cliente/Organización: {Colors.CYAN}{payload['customer_name']} (ID {payload['case_customer']}){Colors.END}")
    print(f"  • Título: {Colors.BOLD}{payload['case_name']}{Colors.END}")
    print(f"  • Template: {Colors.CYAN}{payload['template_name']}{Colors.END}")
    print(f"  • IOCs a cargar: {len(payload['iocs'])}")
    print(f"  • Notas a registrar: {len(payload['notes'])}")

    client = IrisClient()
    res = client.create_case(payload, pdf_path=file_path, dry_run=is_dry)

    if res.get("success"):
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Caso creado satisfactoriamente:{Colors.END}")
        print(f"  • ID de Caso: {Colors.BOLD}{res.get('case_id')}{Colors.END}")
        print(f"  • Nombre: {res.get('case_name')}")
        print(f"  • URL en IRIS: {Colors.CYAN}{res.get('case_url')}{Colors.END}")
        if is_dry:
            print(f"\n{Colors.GRAY}Simulación completa. No se modificó la base de datos de DFIR-IRIS.{Colors.END}")
    else:
        print(f"\n{Colors.RED}✗ Error al crear caso en DFIR-IRIS:{Colors.END}")
        print(f"  {res.get('error')}")


def cmd_batch(args):
    dir_path = Path(args.directory)
    if not dir_path.is_dir():
        print(f"{Colors.RED}Error: El directorio '{dir_path}' no existe.{Colors.END}")
        sys.exit(1)

    pdf_files = list(dir_path.glob("*.pdf")) + list(dir_path.glob("*.txt"))
    if not pdf_files:
        print(f"{Colors.YELLOW}No se encontraron archivos PDF o TXT en {dir_path}{Colors.END}")
        return

    print(f"\n{Colors.BOLD}Procesando {len(pdf_files)} archivos en lote:{Colors.END}")
    client = IrisClient()
    clf = TemplateClassifier()

    for idx, f in enumerate(pdf_files, 1):
        print(f"\n[{idx}/{len(pdf_files)}] {Colors.BOLD}{f.name}{Colors.END}")
        try:
            if f.suffix.lower() == ".pdf":
                raw_text = extract_text_from_pdf(f)
            else:
                raw_text = f.read_text(encoding="utf-8", errors="ignore")

            parser = TicketParser(raw_text)
            data = parser.parse()
            classification = clf.classify(data)
            payload = CaseBuilder.build(data, classification)
            res = client.create_case(payload, pdf_path=f, dry_run=args.dry_run)

            if res.get("success"):
                status = f"{Colors.YELLOW}[DRY-RUN]{Colors.END}" if args.dry_run else f"{Colors.GREEN}[OK]{Colors.END}"
                print(f"  {status} {res.get('case_name')} -> {res.get('case_url')}")
            else:
                print(f"  {Colors.RED}[ERROR]{Colors.END} {res.get('error')}")
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.END} Falló al procesar: {e}")


def main():
    banner()
    parser = argparse.ArgumentParser(description="Automatización de tickets de abuso a DFIR-IRIS")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # test-iris
    subparsers.add_parser("test-iris", help="Verifica la conexión y templates de DFIR-IRIS")

    # templates
    subparsers.add_parser("templates", help="Lista los templates de SOC Abuse Lite v2.0")

    # parse
    p_parse = subparsers.add_parser("parse", help="Analiza y clasifica un PDF o TXT sin crear caso")
    p_parse.add_argument("file", help="Ruta al archivo PDF o TXT del ticket")
    p_parse.add_argument("--json", action="store_true", help="Muestra el payload JSON generado")

    # create
    p_create = subparsers.add_parser("create", help="Crea el caso en DFIR-IRIS")
    p_create.add_argument("file", help="Ruta al archivo PDF o TXT del ticket")
    p_create.add_argument("--template", "-t", help="Forzar un template (ej. abuse_spam, [BRAND], etc.)")
    p_create.add_argument("--customer", "-c", help="Cliente/Organización ('neubox', 'hospedando' o ID)")
    p_create.add_argument("--client-ticket", help="Ticket del cliente / titular (ej. 247629)")
    p_create.add_argument("--report-ticket", help="Ticket de reporte / abuso (ej. 789034)")
    p_create.add_argument("--client-id", help="ID del cliente en sistema de facturación/panel")
    p_create.add_argument("--service-id", help="ID del servicio contratado")
    p_create.add_argument("--server", help="Nombre del servidor Neubox (ej. svgp261.serverneubox.com.mx)")
    p_create.add_argument("--asset", help="Activo o dominio afectado")
    p_create.add_argument("--dry-run", action="store_true", help="Simula la creación sin escribir en la API")

    # batch
    p_batch = subparsers.add_parser("batch", help="Procesa todos los archivos de una carpeta")
    p_batch.add_argument("directory", help="Directorio con archivos PDF o TXT")
    p_batch.add_argument("--dry-run", action="store_true", help="Simula sin escribir en la API")

    args = parser.parse_args()

    if args.command == "test-iris":
        cmd_test_iris(args)
    elif args.command == "templates":
        cmd_list_templates(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "create":
        cmd_create(args)
    elif args.command == "batch":
        cmd_batch(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
