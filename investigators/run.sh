#!/usr/bin/env bash
# ==============================================================================
# Neubox Incident Response Toolkit — Universal Runner
# Detecta automáticamente si existe python3, python (Python 2.7.5) o cPanel python3
# ==============================================================================

PY_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
elif [ -x /usr/local/cpanel/3rdparty/bin/python3 ]; then
    PY_BIN="/usr/local/cpanel/3rdparty/bin/python3"
elif command -v python2 >/dev/null 2>&1; then
    PY_BIN="python2"
else
    echo "[!] Error crítico: No se encontró ningún intérprete de Python (ni python3 ni python)." >&2
    exit 1
fi

BASE_URL="https://raw.githubusercontent.com/caap1234/Chamba/main/investigators"

# Script por defecto
SCRIPT="run_investigator.py"

if [ $# -gt 0 ]; then
    case "$1" in
        01|01_abuse_mail_investigator.py|mail)
            SCRIPT="01_abuse_mail_investigator.py"; shift ;;
        02|02_web_access_investigator.py|web)
            SCRIPT="02_web_access_investigator.py"; shift ;;
        03|03_malware_file_investigator.py|malware)
            SCRIPT="03_malware_file_investigator.py"; shift ;;
        04|04_account_access_investigator.py|access)
            SCRIPT="04_account_access_investigator.py"; shift ;;
        05|05_abuse_evidence_collector.py|evidence)
            SCRIPT="05_abuse_evidence_collector.py"; shift ;;
        06|06_dns_domain_investigator.py|dns)
            SCRIPT="06_dns_domain_investigator.py"; shift ;;
        07|07_suspicious_activity_correlator.py|correlator)
            SCRIPT="07_suspicious_activity_correlator.py"; shift ;;
        08|08_windows_server_investigator.py|windows)
            SCRIPT="08_windows_server_investigator.py"; shift ;;
        09|09_service_health_check.py|health)
            SCRIPT="09_service_health_check.py"; shift ;;
        10|10_dns_subdomain_changes_investigator.py|subdomains)
            SCRIPT="10_dns_subdomain_changes_investigator.py"; shift ;;
        --*)
            # Si inicia con argumento flag (--server, --email, etc.), asociar a 01_abuse_mail_investigator
            SCRIPT="01_abuse_mail_investigator.py"
            ;;
        *)
            SCRIPT="$1"; shift ;;
    esac
fi

if command -v wget >/dev/null 2>&1; then
    $PY_BIN <(wget -qO- "$BASE_URL/$SCRIPT") "$@"
elif command -v curl >/dev/null 2>&1; then
    $PY_BIN <(curl -sL "$BASE_URL/$SCRIPT") "$@"
else
    echo "[!] Error: Se requiere wget o curl para descargar el script." >&2
    exit 1
fi

