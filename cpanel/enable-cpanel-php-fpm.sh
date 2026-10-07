#!/bin/bash
#
# enable-cpanel-php-fpm.sh
#
# Habilita PHP-FPM en todos los VirtualHosts de un servidor cPanel/WHM
# conservando la versión PHP efectiva que cada dominio tenía inicialmente.
#
# Genera:
#   - Snapshot JSON inicial
#   - Snapshot JSON final
#   - Log completo
#   - Reporte CSV
#   - Tabla comparativa en pantalla
#
# Uso:
#   ./enable-cpanel-php-fpm.sh
#
# Requisitos:
#   - Ejecutar como root
#   - cPanel/WHM
#   - python3
#

set -u

# ============================================================
# CONFIGURACIÓN
# ============================================================

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/root/php-fpm-migration-${TIMESTAMP}"

BEFORE_JSON="${WORKDIR}/before.json"
AFTER_JSON="${WORKDIR}/after.json"
LOG_FILE="${WORKDIR}/migration.log"
CSV_FILE="${WORKDIR}/report.csv"
DOMAINS_FILE="${WORKDIR}/domains.tsv"

mkdir -p "$WORKDIR"

# ============================================================
# COLORES
# ============================================================

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    RESET=''
fi

# ============================================================
# FUNCIONES
# ============================================================

log() {
    echo "$(date '+%F %T') $*" >> "$LOG_FILE"
}

die() {
    echo -e "${RED}ERROR:${RESET} $*"
    log "ERROR: $*"
    exit 1
}

# ============================================================
# VALIDACIONES
# ============================================================

[[ $EUID -eq 0 ]] || die "Este script debe ejecutarse como root."

command -v whmapi1 >/dev/null 2>&1 || \
    die "No se encontró whmapi1. ¿Es un servidor cPanel/WHM?"

command -v python3 >/dev/null 2>&1 || \
    die "No se encontró python3."

echo
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD} cPanel PHP-FPM migration tool${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo
echo "Directorio de trabajo:"
echo "  $WORKDIR"
echo

log "Inicio del proceso."

# ============================================================
# SNAPSHOT INICIAL
# ============================================================

echo -e "${CYAN}[1/5] Obteniendo configuración PHP inicial...${RESET}"

if ! whmapi1 --output=json php_get_vhost_versions > "$BEFORE_JSON" 2>>"$LOG_FILE"; then
    die "No fue posible obtener php_get_vhost_versions."
fi

# Validar que la API realmente respondió correctamente
python3 - "$BEFORE_JSON" <<'PY'
import json
import sys

f = sys.argv[1]

try:
    data = json.load(open(f))
except Exception as e:
    print("JSON inválido:", e)
    sys.exit(1)

if not data.get("data", {}).get("versions"):
    print("La API no devolvió VirtualHosts.")
    sys.exit(1)
PY

[[ $? -eq 0 ]] || die "La respuesta inicial de WHM API no es válida."

# ============================================================
# GENERAR LISTA DE DOMINIOS
# ============================================================

python3 - "$BEFORE_JSON" > "$DOMAINS_FILE" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))

for item in data.get("data", {}).get("versions", []):

    domain = item.get("vhost", "")
    account = item.get("account", "")
    version = item.get("version", "")
    fpm = int(bool(item.get("php_fpm", 0)))
    suspended = int(bool(item.get("is_suspended", 0)))

    src = item.get("phpversion_source", {})

    if src.get("system_default"):
        source = "system_default"
    elif src.get("domain"):
        source = "domain"
    else:
        source = "unknown"

    if domain and version:
        print(
            f"{domain}\t"
            f"{account}\t"
            f"{version}\t"
            f"{fpm}\t"
            f"{source}\t"
            f"{suspended}"
        )
PY

TOTAL=$(wc -l < "$DOMAINS_FILE")

echo
echo "VirtualHosts encontrados: $TOTAL"
echo

printf "%-40s %-16s %-12s %-8s %-15s\n" \
    "DOMINIO" "CUENTA" "PHP" "FPM" "ORIGEN"

printf "%-40s %-16s %-12s %-8s %-15s\n" \
    "----------------------------------------" \
    "----------------" \
    "------------" \
    "--------" \
    "---------------"

while IFS=$'\t' read -r DOMAIN ACCOUNT VERSION FPM SOURCE SUSPENDED
do
    if [[ "$FPM" == "1" ]]; then
        FPM_TEXT="ON"
    else
        FPM_TEXT="OFF"
    fi

    printf "%-40s %-16s %-12s %-8s %-15s\n" \
        "$DOMAIN" \
        "$ACCOUNT" \
        "$VERSION" \
        "$FPM_TEXT" \
        "$SOURCE"

done < "$DOMAINS_FILE"

echo

# ============================================================
# CONFIRMACIÓN
# ============================================================

echo -e "${YELLOW}El script hará lo siguiente:${RESET}"
echo
echo "  - Mantendrá la versión PHP efectiva de cada dominio."
echo "  - Activará PHP-FPM."
echo "  - Los dominios que heredaban PHP del sistema quedarán"
echo "    fijados explícitamente a su versión PHP actual."
echo "  - No cambiará de versión PHP intencionalmente."
echo

read -r -p "¿Deseas continuar? [y/N]: " CONFIRM

case "$CONFIRM" in
    y|Y|yes|YES)
        ;;
    *)
        echo "Proceso cancelado."
        exit 0
        ;;
esac

# ============================================================
# ACTIVAR PHP-FPM
# ============================================================

echo
echo -e "${CYAN}[2/5] Activando PHP-FPM...${RESET}"
echo

COUNT=0
OK=0
FAILED=0
ALREADY=0
SKIPPED=0

while IFS=$'\t' read -r DOMAIN ACCOUNT VERSION FPM SOURCE SUSPENDED
do
    ((COUNT++))

    echo -e "${BLUE}[$COUNT/$TOTAL]${RESET} $DOMAIN"
    echo "         Cuenta : $ACCOUNT"
    echo "         PHP    : $VERSION"

    if [[ "$SUSPENDED" == "1" ]]; then
        echo -e "         Estado : ${YELLOW}SKIPPED - cuenta suspendida${RESET}"

        log "$DOMAIN | SKIPPED | suspended"
        ((SKIPPED++))

        echo
        continue
    fi

    if [[ "$FPM" == "1" ]]; then
        echo -e "         Estado : ${GREEN}YA TENÍA PHP-FPM${RESET}"

        log "$DOMAIN | ALREADY_ENABLED | $VERSION"
        ((ALREADY++))

        echo
        continue
    fi

    log "$DOMAIN | enabling FPM | version=$VERSION | source=$SOURCE"

    RESULT="$(whmapi1 --output=json \
        php_set_vhost_versions \
        version="$VERSION" \
        vhost="$DOMAIN" \
        php_fpm=1 2>&1)"

    echo "$RESULT" >> "$LOG_FILE"

    API_STATUS="$(printf '%s' "$RESULT" | python3 -c '
import json
import sys

try:
    x = json.load(sys.stdin)
    print(x.get("metadata", {}).get("result", 0))
except Exception:
    print(0)
')"

    if [[ "$API_STATUS" == "1" ]]; then
        echo -e "         Estado : ${GREEN}PHP-FPM ACTIVADO${RESET}"
        ((OK++))
        log "$DOMAIN | SUCCESS"
    else
        echo -e "         Estado : ${RED}ERROR${RESET}"
        ((FAILED++))
        log "$DOMAIN | FAILED"
    fi

    echo

done < "$DOMAINS_FILE"

# ============================================================
# SNAPSHOT FINAL
# ============================================================

echo -e "${CYAN}[3/5] Obteniendo configuración final...${RESET}"

sleep 2

if ! whmapi1 --output=json php_get_vhost_versions > "$AFTER_JSON" 2>>"$LOG_FILE"; then
    die "No fue posible obtener el estado final."
fi

# ============================================================
# COMPARACIÓN
# ============================================================

echo
echo -e "${CYAN}[4/5] Comparando estado inicial y final...${RESET}"
echo

python3 - "$BEFORE_JSON" "$AFTER_JSON" "$CSV_FILE" <<'PY'
import csv
import json
import sys

before_file = sys.argv[1]
after_file = sys.argv[2]
csv_file = sys.argv[3]

before_data = json.load(open(before_file))
after_data = json.load(open(after_file))


def parse(data):
    output = {}

    for x in data.get("data", {}).get("versions", []):

        domain = x.get("vhost")

        if not domain:
            continue

        source_data = x.get("phpversion_source", {})

        if source_data.get("system_default"):
            source = "system_default"
        elif source_data.get("domain"):
            source = "domain"
        else:
            source = "unknown"

        output[domain] = {
            "account": x.get("account", ""),
            "version": x.get("version", ""),
            "fpm": int(bool(x.get("php_fpm", 0))),
            "source": source,
            "suspended": int(bool(x.get("is_suspended", 0))),
        }

    return output


before = parse(before_data)
after = parse(after_data)

domains = sorted(set(before) | set(after))

rows = []

for domain in domains:

    b = before.get(domain, {})
    a = after.get(domain, {})

    before_version = b.get("version", "N/A")
    after_version = a.get("version", "N/A")

    before_fpm = b.get("fpm", "N/A")
    after_fpm = a.get("fpm", "N/A")

    before_source = b.get("source", "N/A")
    after_source = a.get("source", "N/A")

    suspended = b.get("suspended", 0)

    if suspended:
        status = "SUSPENDED"
    elif before_version != after_version:
        status = "VERSION_MISMATCH"
    elif after_fpm != 1:
        status = "FPM_NOT_ENABLED"
    elif before_source == "system_default" and after_source == "domain":
        status = "OK_PINNED"
    else:
        status = "OK"

    rows.append([
        domain,
        b.get("account", a.get("account", "")),
        before_version,
        after_version,
        before_fpm,
        after_fpm,
        before_source,
        after_source,
        status
    ])


with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "domain",
        "account",
        "php_before",
        "php_after",
        "fpm_before",
        "fpm_after",
        "source_before",
        "source_after",
        "status"
    ])

    writer.writerows(rows)


headers = [
    "DOMAIN",
    "PHP BEFORE",
    "PHP AFTER",
    "FPM",
    "STATUS"
]

print(
    f"{headers[0]:<42} "
    f"{headers[1]:<12} "
    f"{headers[2]:<12} "
    f"{headers[3]:<8} "
    f"{headers[4]}"
)

print(
    "-" * 42,
    "-" * 12,
    "-" * 12,
    "-" * 8,
    "-" * 20
)

for r in rows:

    domain = r[0]
    before_ver = r[2]
    after_ver = r[3]
    fpm_after = r[5]
    status = r[8]

    fpm_text = "ON" if fpm_after == 1 else "OFF"

    print(
        f"{domain:<42} "
        f"{before_ver:<12} "
        f"{after_ver:<12} "
        f"{fpm_text:<8} "
        f"{status}"
    )

print()

total = len(rows)
ok = sum(1 for r in rows if r[8] in ("OK", "OK_PINNED"))
mismatch = sum(1 for r in rows if r[8] == "VERSION_MISMATCH")
fpm_off = sum(1 for r in rows if r[8] == "FPM_NOT_ENABLED")
suspended = sum(1 for r in rows if r[8] == "SUSPENDED")
pinned = sum(1 for r in rows if r[8] == "OK_PINNED")

print("SUMMARY")
print("-------")
print(f"Total domains       : {total}")
print(f"OK                  : {ok}")
print(f"PHP version mismatch: {mismatch}")
print(f"FPM not enabled     : {fpm_off}")
print(f"Suspended/skipped   : {suspended}")
print(f"Pinned from inherit : {pinned}")
PY

# ============================================================
# DETECTAR INCONSISTENCIAS
# ============================================================

VERSION_MISMATCHES=$(awk -F',' '$9 ~ /VERSION_MISMATCH/ {x++} END {print x+0}' "$CSV_FILE")
FPM_NOT_ENABLED=$(awk -F',' '$9 ~ /FPM_NOT_ENABLED/ {x++} END {print x+0}' "$CSV_FILE")

echo
echo -e "${CYAN}[5/5] Resultado final${RESET}"
echo

echo "Procesados inicialmente : $TOTAL"
echo "FPM activado ahora      : $OK"
echo "Ya tenían FPM           : $ALREADY"
echo "Suspendidos omitidos    : $SKIPPED"
echo "Errores API             : $FAILED"
echo

if [[ "$VERSION_MISMATCHES" -gt 0 ]]; then
    echo -e "${RED}ATENCIÓN: Se detectaron $VERSION_MISMATCHES cambios inesperados de versión PHP.${RESET}"
else
    echo -e "${GREEN}OK: No se detectaron cambios de versión PHP.${RESET}"
fi

if [[ "$FPM_NOT_ENABLED" -gt 0 ]]; then
    echo -e "${RED}ATENCIÓN: Hay $FPM_NOT_ENABLED dominios activos sin PHP-FPM después del proceso.${RESET}"
else
    echo -e "${GREEN}OK: Todos los dominios procesables tienen PHP-FPM habilitado.${RESET}"
fi

echo
echo "Archivos generados:"
echo
echo "  Configuración inicial:"
echo "    $BEFORE_JSON"
echo
echo "  Configuración final:"
echo "    $AFTER_JSON"
echo
echo "  Reporte CSV:"
echo "    $CSV_FILE"
echo
echo "  Log:"
echo "    $LOG_FILE"
echo

log "Proceso finalizado."
