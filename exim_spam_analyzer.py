#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Exim SpamAssassin Analyzer
--------------------------
Analiza bloqueos de SpamAssassin en Exim recibiendo un ID de Exim (ej: 1xE4Y8-000000027jC-3kxX).
Busca en /var/log/exim_mainlog y /var/log/maillog el Message-ID, extrae las reglas de SpamAssassin activadas,
busca los puntajes y descripciones en los archivos de configuración de SpamAssassin y genera un reporte visual ordenado.

Uso:
  python3 exim_spam_analyzer.py <EXIM_ID>
  python3 exim_spam_analyzer.py 1xE4Y8-000000027jC-3kxX

Autor: Antigravity AI Assistant
"""

import sys
import os
import re
import glob
import gzip
import argparse
from datetime import datetime

# --- Configuración de rutas predeterminadas ---
DEFAULT_EXIM_LOGS = [
    "/var/log/exim_mainlog",
    "/var/log/exim/mainlog",
    "/var/log/exim_rejectlog"
]

DEFAULT_MAIL_LOGS = [
    "/var/log/maillog",
    "/var/log/maillog.1",
    "/var/log/syslog"
]

DEFAULT_SA_DIRS = [
    "/etc/mail/spamassassin",
    "/usr/share/spamassassin",
    "/var/lib/spamassassin",
    "/etc/spamassassin"
]

# --- Códigos de Color ANSI para la CLI ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'
    ENDC = '\033[0m'

    @classmethod
    def disable(cls):
        cls.HEADER = ''
        cls.OKBLUE = ''
        cls.OKCYAN = ''
        cls.OKGREEN = ''
        cls.WARNING = ''
        cls.FAIL = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
        cls.GRAY = ''
        cls.ENDC = ''


# --- Diccionario de Respaldo para Reglas Comunes de SpamAssassin (Español) ---
FALLBACK_DESCRIPTIONS = {
    "ALL_TRUSTED": "El correo pasó únicamente por hosts confiables (Reduce spam score)",
    "CPANEL_LOTS_OF_EMPTY_LINE": "El correo contiene una cantidad excesiva de líneas vacías consecutivas",
    "DC_PNG_UNO_LARGO": "Imagen PNG adjunta o incrustada con proporciones largas/sospechosas",
    "HTML_MESSAGE": "El correo incluye cuerpo en formato HTML",
    "KAM_DMARC_NONE": "La política DMARC del dominio remitente está en 'p=none' o sin protección estricta",
    "KAM_DMARC_STATUS": "Estado o prueba de fallo en verificación DKIM / SPF / DMARC",
    "KAM_INFOUSMEBIZ": "Uso de dominios con TLDs comunes en spam (.info, .us, .me, .biz)",
    "KAM_MAILBOX2": "Filtro KAM: Patrón coincidente con correo/buzón spammed o lista negra",
    "KAM_SHORT": "Cuerpo de correo extremadamente corto o contiene acortadores de URL",
    "PDS_BAD_THREAD_QP_64": "Encabezados con codificación Quoted-Printable (QP) sospechosa",
    "T_FILL_THIS_FORM_SHORT": "Patrón de formulario corto o solicitud de datos dentro del correo",
    "URIBL_BLOCKED": "La consulta a las listas URIBL fue bloqueada (límite de peticiones del servidor)",
    "BAYES_00": "Filtro Bayesiano indica 0% a 1% de probabilidad de spam (Reduce score)",
    "BAYES_50": "Filtro Bayesiano indica 40% a 60% de probabilidad de spam",
    "BAYES_99": "Filtro Bayesiano indica 99% a 100% de probabilidad de spam",
    "SPF_PASS": "Verificación SPF exitosa (Sender Policy Framework)",
    "SPF_FAIL": "Fallo en verificación SPF del remitente",
    "DKIM_SIGNED": "El mensaje contiene una firma digital DKIM",
    "DKIM_VALID": "La firma digital DKIM es válida y coincide con el dominio",
    "MALW_ATTACH": "Nombre de archivo adjunto sospechoso con probabilidad de contener malware",
    "RCVD_IN_PBL": "Recibido desde una IP/relay listada en la lista Spamhaus PBL",
    "RCVD_IN_SBL_CSS": "Recibido desde una IP/relay listada en la lista Spamhaus SBL-CSS",
    "SPOOFED_FREEMAIL_NO_RDNS": "Remitente de correo gratuito sospechoso sin reverso DNS (rDNS)",
    "SPOOFED_FREEMAIL": "Remitente suplantado haciendo uso de dominio de correo gratuito",
    "RDNS_NONE": "Entregado a la red por un host sin reverso DNS (rDNS) configurado",
    "SPF_HELO_SOFTFAIL": "El saludo HELO/EHLO no coincide con el registro SPF del dominio (softfail)",
    "SPF_SOFTFAIL": "La IP de envío no está explícitamente autorizada en el SPF (softfail)",
    "SUBJ_ALL_CAPS": "El asunto del correo está escrito totalmente en letras Mayúsculas",
    "RCVD_IN_XBL": "Recibido desde una IP listada en Spamhaus XBL (Exploits Blocklist)",
    "RCVD_IN_SBL": "Recibido desde una IP listada en Spamhaus SBL (Spamhaus Block List)",
    "MIME_HTML_ONLY": "El correo contiene únicamente formato HTML sin versión en texto plano",
    "DKIM_ADSP_CUSTOM_MED": "Sin firma de autor válida según política ADSP",
    "FREEMAIL_FROM": "Dirección remitente pertenece a proveedor gratuito frecuentemente abusado",
    "RCVD_IN_DNSWL_BLOCKED": "Aviso: Consulta a DNSWL bloqueada por límite de peticiones del servidor",
    "SPOOF_GMAIL_MID": "Aparenta ser de Gmail pero el Message-ID no cumple el patrón oficial",
    "FORGED_GMAIL_RCVD": "Indica remitente @gmail.com pero los servidores de envío no son de Google"
}


def open_log_file(filepath):
    """Abre un archivo normal o comprimido (.gz)."""
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
    return open(filepath, 'r', encoding='utf-8', errors='ignore')


def search_exim_log(exim_id, custom_exim_log=None):
    """
    Busca el ID de Exim en los logs de Exim y extrae detalles.
    """
    log_files = []
    if custom_exim_log:
        log_files.append(custom_exim_log)
    else:
        for path in DEFAULT_EXIM_LOGS:
            log_files.extend(sorted(glob.glob(path + "*")))

    details = {
        "exim_id": exim_id,
        "timestamp_str": None,
        "timestamp_dt": None,
        "sender": None,
        "domain": None,
        "client": None,
        "rejection_msg": None,
        "score_from_exim": None,
        "raw_lines": []
    }

    re_exim_line = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<exim_id>' + re.escape(exim_id) + r')\s+'
        r'(?P<rest>.*)$'
    )
    re_sender = re.compile(r'F=<([^>]+)>')
    re_client = re.compile(r'H=([^\s]+(?:\s+\[[^\]]+\])?)')
    re_rejection = re.compile(r'rejected after DATA:\s*"(.*?)"')
    re_exim_score = re.compile(r'spam\s*\(([\d\.]+)\)')

    for file_path in log_files:
        if not os.path.exists(file_path):
            continue
        try:
            with open_log_file(file_path) as f:
                for line in f:
                    if exim_id in line:
                        details["raw_lines"].append(line.strip())
                        match = re_exim_line.search(line)
                        if match:
                            date_str = match.group("date")
                            details["timestamp_str"] = date_str
                            try:
                                details["timestamp_dt"] = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                            except ValueError:
                                pass

                            rest = match.group("rest")
                            m_sender = re_sender.search(rest)
                            if m_sender and not details["sender"]:
                                details["sender"] = m_sender.group(1)
                                if "@" in details["sender"]:
                                    details["domain"] = details["sender"].split("@")[-1]

                            m_client = re_client.search(rest)
                            if m_client and not details["client"]:
                                details["client"] = m_client.group(1)

                            m_rej = re_rejection.search(rest)
                            if m_rej and not details["rejection_msg"]:
                                details["rejection_msg"] = m_rej.group(1)
                                m_score = re_exim_score.search(m_rej.group(1))
                                if m_score:
                                    try:
                                        details["score_from_exim"] = float(m_score.group(1))
                                    except ValueError:
                                        pass
        except Exception:
            continue

        if details["timestamp_str"]:
            break

    return details


def search_maillog(domain, sender=None, timestamp_dt=None, custom_mail_log=None):
    """
    Busca en maillog las líneas de spamd asociadas al dominio/remitente y la hora cercana.
    """
    log_files = []
    if custom_mail_log:
        log_files.append(custom_mail_log)
    else:
        for path in DEFAULT_MAIL_LOGS:
            log_files.extend(sorted(glob.glob(path + "*")))

    sa_info = {
        "mid": None,
        "spamd_pid": None,
        "is_spam": False,
        "score": None,
        "required_score": None,
        "rules": [],
        "scantime": None,
        "size": None,
        "raw_checking_line": None,
        "raw_result_line": None
    }

    time_patterns = []
    if timestamp_dt:
        time_patterns.append(timestamp_dt.strftime("%b %e %H:%M"))
        time_patterns.append(timestamp_dt.strftime("%b %d %H:%M"))
        time_patterns.append(timestamp_dt.strftime("%H:%M"))

    re_checking = re.compile(r'spamd\[(?P<pid>\d+)\]:\s*spamd:\s*checking message\s*<(?P<mid>[^>]+)>\s*for\s*(?P<user>\S+)')
    re_identified = re.compile(r'spamd\[(?P<pid>\d+)\]:\s*spamd:\s*identified spam \((?P<score>[\d\.]+)\/(?P<req>[\d\.]+)\)')
    re_result = re.compile(
        r'spamd\[(?P<pid>\d+)\]:\s*spamd:\s*result:\s*(?P<flag>[YN])\s+'
        r'(?P<score>[\d\.-]+)\s*-\s*(?P<rules>[A-Z0-9_,]+)\s+'
        r'(?P<kv>.*)'
    )

    found_mid = None
    target_pid = None

    for file_path in log_files:
        if not os.path.exists(file_path):
            continue
        try:
            with open_log_file(file_path) as f:
                lines = f.readlines()

            for line in lines:
                if "spamd:" in line and "checking message" in line:
                    match_domain = (domain and domain.lower() in line.lower()) or (sender and sender.lower() in line.lower())
                    match_time = any(tp in line for tp in time_patterns) if time_patterns else True

                    if match_domain and match_time:
                        m = re_checking.search(line)
                        if m:
                            found_mid = "<" + m.group("mid") + ">"
                            target_pid = m.group("pid")
                            sa_info["mid"] = found_mid
                            sa_info["spamd_pid"] = target_pid
                            sa_info["raw_checking_line"] = line.strip()
                            break

            if target_pid or found_mid:
                for line in lines:
                    if "spamd:" in line:
                        m_ident = re_identified.search(line)
                        if m_ident and (target_pid and f"spamd[{target_pid}]" in line):
                            try:
                                sa_info["score"] = float(m_ident.group("score"))
                                sa_info["required_score"] = float(m_ident.group("req"))
                            except ValueError:
                                pass

                        if "spamd: result:" in line:
                            if (target_pid and f"spamd[{target_pid}]" in line) or (found_mid and found_mid in line):
                                m_res = re_result.search(line)
                                if m_res:
                                    sa_info["raw_result_line"] = line.strip()
                                    sa_info["is_spam"] = (m_res.group("flag") == 'Y')
                                    if sa_info["score"] is None:
                                        try:
                                            sa_info["score"] = float(m_res.group("score"))
                                        except ValueError:
                                            pass

                                    rules_str = m_res.group("rules")
                                    sa_info["rules"] = [r.strip() for r in rules_str.split(",") if r.strip()]

                                    kv_str = m_res.group("kv")
                                    for kv in kv_str.split(","):
                                        if "=" in kv:
                                            k, v = kv.split("=", 1)
                                            k, v = k.strip(), v.strip()
                                            if k == "required_score" and sa_info["required_score"] is None:
                                                try:
                                                    sa_info["required_score"] = float(v)
                                                except ValueError:
                                                    pass
                                            elif k == "scantime":
                                                sa_info["scantime"] = v
                                            elif k == "size":
                                                sa_info["size"] = v
                                            elif k == "mid" and not sa_info["mid"]:
                                                sa_info["mid"] = v
                                    break
        except Exception:
            continue

        if sa_info["rules"]:
            break

    return sa_info


def load_spamassassin_rules(custom_sa_dirs=None):
    """
    Carga las definiciones de reglas, puntajes y descripciones desde SpamAssassin.
    """
    sa_dirs = custom_sa_dirs if custom_sa_dirs else DEFAULT_SA_DIRS
    cf_files = []
    for d in sa_dirs:
        if os.path.isdir(d):
            cf_files.extend(glob.glob(os.path.join(d, "**", "*.cf"), recursive=True))

    rule_database = {}

    re_score = re.compile(r'^\s*score\s+([A-Za-z0-9_]+)\s+(.+)$')
    re_describe = re.compile(r'^\s*describe\s+([A-Za-z0-9_]+)\s+(.+)$')

    for cf_file in cf_files:
        try:
            with open(cf_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    m_score = re_score.match(line)
                    if m_score:
                        rule_name = m_score.group(1)
                        raw_scores = m_score.group(2).split('#')[0].strip().split()
                        try:
                            score_floats = [float(s) for s in raw_scores]
                            if rule_name not in rule_database:
                                rule_database[rule_name] = {"score": 0.0, "scores_all": [], "description": None}
                            
                            rule_database[rule_name]["scores_all"] = score_floats
                            
                            if len(score_floats) == 4:
                                selected_score = score_floats[3]
                            elif len(score_floats) == 2:
                                selected_score = score_floats[1]
                            elif len(score_floats) > 0:
                                selected_score = score_floats[0]
                            else:
                                selected_score = 0.0

                            rule_database[rule_name]["score"] = selected_score
                        except ValueError:
                            pass

                    m_desc = re_describe.match(line)
                    if m_desc:
                        rule_name = m_desc.group(1)
                        desc_text = m_desc.group(2).strip()
                        if rule_name not in rule_database:
                            rule_database[rule_name] = {"score": 0.0, "scores_all": [], "description": desc_text}
                        else:
                            rule_database[rule_name]["description"] = desc_text
        except Exception:
            continue

    return rule_database


def format_visual_report(exim_data, sa_data, rule_db):
    """Imprime el reporte visual con formato y colores adaptados."""
    import shutil

    # Obtener el ancho de la consola (mínimo 120 caracteres para mejor visibilidad de descripciones)
    term_width = shutil.get_terminal_size((125, 24)).columns
    term_width = max(term_width, 120)

    box_width = min(term_width, 135)

    print()
    print(f"{Colors.BOLD}{Colors.OKCYAN}╔{'═' * (box_width - 2)}╗{Colors.ENDC}")
    title = "ANALIZADOR DE BLOQUEOS SPAMASSASSIN EN EXIM"
    print(f"{Colors.BOLD}{Colors.OKCYAN}║{title.center(box_width - 2)}║{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}╚{'═' * (box_width - 2)}╝{Colors.ENDC}")
    print()

    # --- Sección 1: Información del Correo ---
    print(f"{Colors.BOLD}{Colors.HEADER}─── 1. DETALLES DEL CORREO RECHAZADO {'─' * (box_width - 38)}{Colors.ENDC}")
    print(f"  • {Colors.BOLD}Exim Message ID:{Colors.ENDC}  {Colors.WARNING}{exim_data['exim_id']}{Colors.ENDC}")
    print(f"  • {Colors.BOLD}Message-ID Header:{Colors.ENDC} {sa_data['mid'] or 'No encontrado en maillog'}")
    print(f"  • {Colors.BOLD}Fecha / Hora Exim:{Colors.ENDC} {exim_data['timestamp_str'] or 'Desconocida'}")
    print(f"  • {Colors.BOLD}Remitente (From):{Colors.ENDC} {exim_data['sender'] or 'Desconocido'}")
    print(f"  • {Colors.BOLD}Dominio Detectado:{Colors.ENDC} {exim_data['domain'] or 'Desconocido'}")
    print(f"  • {Colors.BOLD}Host / IP Cliente:{Colors.ENDC} {exim_data['client'] or 'Desconocido'}")
    if exim_data['rejection_msg']:
        print(f"  • {Colors.BOLD}Motivo en Exim:{Colors.ENDC}    {Colors.FAIL}{exim_data['rejection_msg']}{Colors.ENDC}")
    print()

    final_score = sa_data['score'] if sa_data['score'] is not None else exim_data['score_from_exim']

    # --- Sección 2: Resultado de SpamAssassin ---
    print(f"{Colors.BOLD}{Colors.HEADER}─── 2. RESULTADO DE SPAMASSASSIN (spamd) {'─' * (box_width - 42)}{Colors.ENDC}")
    
    score_str = f"{final_score:.1f}" if final_score is not None else "N/A"
    req_str = f"{sa_data['required_score']:.1f}" if sa_data['required_score'] is not None else "5.0"
    
    status_badge = f"{Colors.BOLD}{Colors.FAIL}[ 🚫 CORREO BLOQUEADO POR SPAM ]{Colors.ENDC}" if (sa_data['is_spam'] or (final_score and final_score >= 5.0)) else f"{Colors.BOLD}{Colors.OKGREEN}[ ✔ CORREO LIMPIO / ACEPTADO ]{Colors.ENDC}"
    
    print(f"  • {Colors.BOLD}Estatus Final:{Colors.ENDC}       {status_badge}")
    print(f"  • {Colors.BOLD}Puntaje Total:{Colors.ENDC}       {Colors.BOLD}{Colors.FAIL if sa_data['is_spam'] else Colors.OKGREEN}{score_str}{Colors.ENDC} / {req_str} (requerido para bloqueo)")
    print(f"  • {Colors.BOLD}PID de spamd:{Colors.ENDC}        {sa_data['spamd_pid'] or 'N/A'}")
    if sa_data['scantime']:
        print(f"  • {Colors.BOLD}Tiempo de Escaneo:{Colors.ENDC}   {sa_data['scantime']} seg")
    if sa_data['size']:
        print(f"  • {Colors.BOLD}Tamaño del Correo:{Colors.ENDC}   {sa_data['size']} bytes")
    print()

    # --- Sección 3: Desglose de Reglas y Puntajes ---
    print(f"{Colors.BOLD}{Colors.HEADER}─── 3. DESGLOSE DE REGLAS Y APORTACIÓN AL SCORE FINAL {'─' * (box_width - 55)}{Colors.ENDC}")
    
    if not sa_data['rules']:
        print(f"  {Colors.WARNING}No se encontraron listas de reglas en maillog.{Colors.ENDC}")
        return

    analyzed_rules = []
    total_positive_score = 0.0

    for rule_name in sa_data['rules']:
        info = rule_db.get(rule_name, {})
        score = info.get("score", 0.0)
        desc = info.get("description")
        
        if not desc or desc.startswith("Sin descripción"):
            desc = FALLBACK_DESCRIPTIONS.get(rule_name, desc or "Sin descripción en archivos de configuración")

        if score == 0.0 and rule_name.startswith("T_"):
            score = 0.01
        
        if score > 0:
            total_positive_score += score
            
        analyzed_rules.append({
            "name": rule_name,
            "score": score,
            "desc": desc
        })

    analyzed_rules.sort(key=lambda x: x["score"], reverse=True)

    # Definir anchos dinámicos de columnas para la tabla
    rule_col_w = 27
    score_col_w = 9
    bar_col_w = 14
    # La columna de descripción ocupará todo el resto del espacio disponible en pantalla
    desc_col_w = max(box_width - (rule_col_w + score_col_w + bar_col_w + 5), 65)

    print(f"┌{'─' * rule_col_w}┬{'─' * score_col_w}┬{'─' * bar_col_w}┬{'─' * desc_col_w}┐")
    print(f"│ {Colors.BOLD}{'REGLA DISPARADA':<{rule_col_w-1}}{Colors.ENDC}│ {Colors.BOLD}{'PUNTAJE':<{score_col_w-1}}{Colors.ENDC}│ {Colors.BOLD}{'IMPACTO':<{bar_col_w-1}}{Colors.ENDC}│ {Colors.BOLD}{'DESCRIPCIÓN DE LA REGLA':<{desc_col_w-1}}{Colors.ENDC}│")
    print(f"├{'─' * rule_col_w}┼{'─' * score_col_w}┼{'─' * bar_col_w}┼{'─' * desc_col_w}┤")

    for r in analyzed_rules:
        r_name = r["name"]
        r_score = r["score"]
        r_desc = r["desc"]

        if r_score > 0:
            score_fmt = f"{Colors.FAIL}+{r_score:<6.3f}{Colors.ENDC}"
        elif r_score < 0:
            score_fmt = f"{Colors.OKGREEN}{r_score:<6.3f}{Colors.ENDC}"
        else:
            score_fmt = f"{Colors.GRAY} 0.000 {Colors.ENDC}"

        if r_score > 0 and total_positive_score > 0:
            pct = (r_score / total_positive_score) * 100
            filled = int(round((pct / 100) * 8))
            bar_str = "█" * filled + "░" * (8 - filled)
            impact_fmt = f"{Colors.FAIL}{bar_str} {pct:3.0f}%{Colors.ENDC}"
        elif r_score < 0:
            impact_fmt = f"{Colors.OKGREEN}RESTAN{Colors.ENDC}       "
        else:
            impact_fmt = f"{Colors.GRAY}NEUTRAL{Colors.ENDC}      "

        if len(r_desc) > (desc_col_w - 2):
            r_desc_fmt = r_desc[:desc_col_w - 5] + "..."
        else:
            r_desc_fmt = r_desc

        print(f"│ {Colors.BOLD}{r_name:<{rule_col_w-1}}{Colors.ENDC}│ {score_fmt} │ {impact_fmt} │ {r_desc_fmt:<{desc_col_w-1}}│")

    print(f"└{'─' * rule_col_w}┴{'─' * score_col_w}┴{'─' * bar_col_w}┴{'─' * desc_col_w}┘")
    print()

    # --- Sección 4: Conclusión de Bloqueo ---
    print(f"{Colors.BOLD}{Colors.HEADER}─── 4. CONCLUSIÓN Y REGLAS CLAVE DEL BLOQUEO {'─' * (box_width - 46)}{Colors.ENDC}")
    top_rules = [r for r in analyzed_rules if r["score"] > 0]
    if top_rules:
        top_rule = top_rules[0]
        pct_top = (top_rule['score'] / total_positive_score * 100) if total_positive_score > 0 else 0
        print(f"  • {Colors.BOLD}Causa Principal:{Colors.ENDC} La regla {Colors.FAIL}{Colors.BOLD}{top_rule['name']}{Colors.ENDC} sumó {Colors.FAIL}{Colors.BOLD}+{top_rule['score']:.3f} puntos{Colors.ENDC} ({pct_top:.1f}% del total positivo).")
        print(f"    └─ Detalle: {Colors.GRAY}{top_rule['desc']}{Colors.ENDC}")
        
        high_impact = [r for r in top_rules if r["score"] >= 0.5]
        if len(high_impact) > 1:
            other_names = ", ".join([f"{r['name']} (+{r['score']:.2f})" for r in high_impact[1:]])
            print(f"  • {Colors.BOLD}Reglas Secundarias Significativas (≥0.5 pts):{Colors.ENDC} {other_names}")
    else:
        print(f"  • No se detectaron reglas con puntajes positivos significativos.")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analiza la correlación de reglas de SpamAssassin para un ID de Exim.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("exim_id", nargs="?", help="ID del mensaje en Exim (ej: 1xE4Y8-000000027jC-3kxX)")
    parser.add_argument("--exim-log", help="Ruta personalizada a exim_mainlog")
    parser.add_argument("--mail-log", help="Ruta personalizada a maillog")
    parser.add_argument("--sa-dirs", nargs="+", help="Directorios de reglas de SpamAssassin")
    parser.add_argument("--no-color", action="store_true", help="Desactivar colores en la consola")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    exim_id = args.exim_id

    # Si se ejecuta mediante pipe (wget | python3 -), sys.stdin no es una TTY.
    # Para permitir lectura interactiva del ID, leemos directamente desde la consola /dev/tty.
    if not exim_id:
        try:
            if not sys.stdin.isatty() and os.path.exists('/dev/tty'):
                with open('/dev/tty', 'r') as tty:
                    sys.stdout.write(f"{Colors.BOLD}Ingrese el Exim Message ID (ej: 1xE4Y8-000000027jC-3kxX): {Colors.ENDC}")
                    sys.stdout.flush()
                    exim_id = tty.readline().strip()
            else:
                exim_id = input(f"{Colors.BOLD}Ingrese el Exim Message ID (ej: 1xE4Y8-000000027jC-3kxX): {Colors.ENDC}").strip()
        except (KeyboardInterrupt, EOFError, Exception):
            print("\nOperación cancelada.")
            sys.exit(0)

    if not exim_id:
        print(f"{Colors.FAIL}[!] Debe especificar un ID de Exim válido.{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.GRAY}[i] Buscando ID '{exim_id}' en los logs de Exim...{Colors.ENDC}")
    exim_data = search_exim_log(exim_id, custom_exim_log=args.exim_log)

    if not exim_data["timestamp_str"] and not exim_data["domain"]:
        print(f"{Colors.FAIL}[!] No se encontró el ID '{exim_id}' en el log de Exim.{Colors.ENDC}")
        print(f"{Colors.WARNING}Verifique que el ID sea correcto y que las rutas de log existan.{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.GRAY}[i] Remitente detectado: {exim_data['sender'] or 'N/A'}, Dominio: {exim_data['domain'] or 'N/A'}{Colors.ENDC}")
    print(f"{Colors.GRAY}[i] Buscando Message-ID y resultado de SpamAssassin en maillog...{Colors.ENDC}")

    sa_data = search_maillog(
        domain=exim_data["domain"],
        sender=exim_data["sender"],
        timestamp_dt=exim_data["timestamp_dt"],
        custom_mail_log=args.mail_log
    )

    print(f"{Colors.GRAY}[i] Cargando reglas y puntajes de SpamAssassin...{Colors.ENDC}")
    rule_db = load_spamassassin_rules(custom_sa_dirs=args.sa_dirs)

    format_visual_report(exim_data, sa_data, rule_db)


if __name__ == "__main__":
    main()


