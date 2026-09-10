#!/bin/bash
#
# php-fpm-auto-tuner-cpanel.sh
#
# Herramienta integral de diagnóstico, migración opcional a PHP-FPM y
# optimización inteligente de pools PHP-FPM en servidores VPS/Dedicados
# con cPanel/WHM y EasyApache 4.
#
# Diseñado para AlmaLinux / RHEL / CentOS con cPanel/WHM ejecutado como root.
#
# Uso:
#   bash php-fpm-auto-tuner-cpanel.sh [MINUTOS] [CURL_REPEATS]
# Ejemplo:
#   bash php-fpm-auto-tuner-cpanel.sh 30 3
#

set -u
set -o pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/cpanel/bin"

# ============================================================
# PARÁMETROS Y LÍMITES DE SEGURIDAD
# ============================================================

MINUTES="${1:-30}"
CURL_REPEATS="${2:-3}"

PHP_BUDGET_MAX_PCT="${PHP_BUDGET_MAX_PCT:-60}"   # Máximo % de RAM física comprometida teóricamente a FPM
HEADROOM_MIN_MB="${HEADROOM_MIN_MB:-1024}"       # MemAvailable que intentamos dejar libre/reclamable (MB)
HEADROOM_PCT="${HEADROOM_PCT:-10}"               # O este % de RAM, lo que sea mayor
MAX_CHILDREN_HARD="${MAX_CHILDREN_HARD:-20}"     # Tope absoluto de max_children por pool salvo override
ACTIVE_MIN_CHILDREN="${ACTIVE_MIN_CHILDREN:-2}"  # Mínimo para pool activo con tráfico
IDLE_MIN_CHILDREN="${IDLE_MIN_CHILDREN:-1}"      # Mínimo para pool sin tráfico reciente
MAX_CONSECUTIVE_REGRESSIONS="${MAX_CONSECUTIVE_REGRESSIONS:-3}" # Aborto global si hay N regresiones seguidas
MAX_REDUCTION_RATIO="${MAX_REDUCTION_RATIO:-0.50}" # Máxima reducción porcentual en una sola ejecución (50%)

# ============================================================
# DIRECTORIO PERMANENTE DE TRABAJO
# ============================================================

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/root/php-fpm-optimizer-${TIMESTAMP}"
mkdir -p "$WORKDIR/yaml_backups"

LOG_FILE="${WORKDIR}/optimizer.log"
BEFORE_JSON="${WORKDIR}/before.json"
AFTER_MIGRATION_JSON="${WORKDIR}/after_migration.json"
DOMAINS_FILE="${WORKDIR}/domains.tsv"
URLS_FILE="${WORKDIR}/urls.tsv"
HTTP_BEFORE_FILE="${WORKDIR}/http_before_fpm.tsv"
HTTP_AFTER_FILE="${WORKDIR}/http_after_fpm.tsv"
HTTP_COMPARE_FILE="${WORKDIR}/http_fpm_comparison.tsv"
MIGRATION_CANDIDATES="${WORKDIR}/migration_candidates.tsv"

SYSTEM_ENV="${WORKDIR}/system.env"
POOLS_FILE="${WORKDIR}/pools.tsv"
MEMORY_FILE="${WORKDIR}/memory.tsv"
HITS_FILE="${WORKDIR}/hits_max_children.tsv"
TRAFFIC_FILE="${WORKDIR}/traffic.tsv"
HTTP_PERF_FILE="${WORKDIR}/http_perf.tsv"
MERGED_FILE="${WORKDIR}/merged.tsv"
RECS_FILE="${WORKDIR}/recommendations.tsv"
CHANGED_LIST="${WORKDIR}/applied_changes.tsv"
REPORT_CSV="${WORKDIR}/report.csv"

# ============================================================
# FORMATO Y COLORES (TTY DEPENDIENTE CON ANSI-C QUOTING)
# ============================================================

if [[ -t 1 ]]; then
    RED=$(printf '\033[0;31m')
    GREEN=$(printf '\033[0;32m')
    YELLOW=$(printf '\033[1;33m')
    BLUE=$(printf '\033[0;34m')
    CYAN=$(printf '\033[0;36m')
    BOLD=$(printf '\033[1m')
    RESET=$(printf '\033[0m')
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    RESET=''
fi

log() {
    echo "$(date '+%F %T') $*" >> "$LOG_FILE"
}

die() {
    echo -e "${RED}ERROR:${RESET} $*" >&2
    log "ERROR: $*"
    exit 1
}

stage() {
    local num="$1"
    local total="$2"
    local msg="$3"
    echo
    echo -e "${CYAN}[${num}/${total}] ${msg}${RESET}"
    log "ETAPA [${num}/${total}] ${msg}"
}

hr() {
    echo -e "${BOLD}============================================================${RESET}"
}

prompt_user() {
    local msg="$1"
    local varname="$2"
    local input_val=""
    if [[ -t 0 ]]; then
        read -r -p "$msg" input_val
    elif [[ -c /dev/tty ]]; then
        read -r -p "$msg" input_val < /dev/tty
    else
        read -r -p "$msg" input_val 2>/dev/null || input_val=""
    fi
    eval "$varname=\"\$input_val\""
}

# ============================================================
# ETAPA 1: VALIDACIONES DEL SERVIDOR
# ============================================================

stage "1" "18" "Validaciones del servidor..."

[[ $EUID -eq 0 ]] || die "Este script debe ejecutarse como root."

command -v whmapi1 >/dev/null 2>&1 || die "No se encontró 'whmapi1'. ¿Es un servidor cPanel/WHM?"
command -v python3 >/dev/null 2>&1 || die "No se encontró 'python3'."

for cmd in awk sed grep find sort ps curl free nproc date cp rpm column; do
    command -v "$cmd" >/dev/null 2>&1 || die "Falta la herramienta requerida: $cmd"
done

echo
hr
echo -e "${BOLD} OPTIMIZADOR Y DIAGNÓSTICO PHP-FPM PARA CPANEL / EA4${RESET}"
echo " Fecha             : $(date)"
echo " Directorio        : $WORKDIR"
echo " Ventana de tráfico: últimos $MINUTES minutos"
echo " Pruebas HTTP      : $CURL_REPEATS por endpoint"
hr
echo

log "Inicio de ejecución del script."

# ============================================================
# ETAPA 2: INVENTARIO COMPLETO DE VIRTUALHOSTS (WHM API)
# ============================================================

stage "2" "18" "Obteniendo inventario completo de VirtualHosts vía WHM API..."

if ! whmapi1 --output=json php_get_vhost_versions </dev/null > "$BEFORE_JSON" 2>>"$LOG_FILE"; then
    die "No fue posible ejecutar 'whmapi1 php_get_vhost_versions'."
fi

# Validar respuesta JSON
python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"JSON inválido: {e}")
    sys.exit(1)

versions = data.get("data", {}).get("versions")
if not versions:
    print("La API whmapi1 no devolvió VirtualHosts.")
    sys.exit(1)
' "$BEFORE_JSON" </dev/null

[[ $? -eq 0 ]] || die "La respuesta de WHM API php_get_vhost_versions no es válida."

# Parsear handlers globales / por versión PHP y comprobar binaries FPM
EA4_CONF="/etc/cpanel/ea4/php.conf"

python3 -c '
import json, sys, os, glob

before_json = sys.argv[1]
ea4_conf = sys.argv[2]

handlers_map = {}
if os.path.isfile(ea4_conf):
    with open(ea4_conf) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                k, v = line.split(":", 1)
                handlers_map[k.strip()] = v.strip().strip("\"")

data = json.load(open(before_json))

for item in data.get("data", {}).get("versions", []):
    domain = item.get("vhost", "").strip()
    account = item.get("account", "").strip()
    version = item.get("version", "").strip()
    fpm = 1 if item.get("php_fpm") else 0
    suspended = 1 if item.get("is_suspended") else 0

    src = item.get("phpversion_source", {})
    if src.get("system_default"):
        source = "system_default"
    elif src.get("domain"):
        source = "domain"
    else:
        source = "unknown"

    handler = handlers_map.get(version, "unknown")

    yaml_path = "MISSING"
    if account and domain:
        candidate = f"/var/cpanel/userdata/{account}/{domain}.php-fpm.yaml"
        if os.path.isfile(candidate):
            yaml_path = candidate
        else:
            found = glob.glob(f"/var/cpanel/userdata/*/{domain}.php-fpm.yaml")
            if found:
                yaml_path = found[0]

    fpm_bin1 = f"/opt/cpanel/{version}/root/usr/sbin/php-fpm"
    fpm_bin2 = f"/opt/cpanel/{version}/root/usr/bin/php-fpm"
    fpm_pkg_installed = 1 if (os.path.isfile(fpm_bin1) or os.path.isfile(fpm_bin2)) else 0

    if domain and version:
        print(f"{domain}\t{account}\t{version}\t{fpm}\t{source}\t{suspended}\t{handler}\t{yaml_path}\t{fpm_pkg_installed}")
' "$BEFORE_JSON" "$EA4_CONF" </dev/null > "$DOMAINS_FILE"

TOTAL_VH=$(wc -l < "$DOMAINS_FILE")
echo "VirtualHosts totales encontrados: $TOTAL_VH"
log "VirtualHosts encontrados: $TOTAL_VH"

# ============================================================
# ETAPA 3: ANÁLISIS DE ACCESS LOGS Y SELECCIÓN DE URLS
# ============================================================

stage "3" "18" "Analizando tráfico reciente y seleccionando URLs de prueba seguras..."

# Generar patrones de minutos para el filtrado de logs
PATTERNS_FILE="$WORKDIR/time_patterns"
: > "$PATTERNS_FILE"
for i in $(seq 0 $((MINUTES-1))); do
    date -d "$i minutes ago" '+[%d/%b/%Y:%H:%M:' >> "$PATTERNS_FILE"
done

# Seleccionar URLs seguras por dominio
python3 -c '
import sys, os, re, glob
from collections import Counter

domains_file, patterns_file, minutes, urls_file = sys.argv[1:5]

with open(patterns_file) as f:
    patterns = [line.strip() for line in f if line.strip()]

static_exts = (".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webm", ".pdf", ".zip", ".xml", ".txt")

sensitive_terms = ("token", "nonce", "auth", "login", "logout", "session", "secret",
                   "password", "key", "admin", "cart", "checkout", "pay", "reset")

urls_out = []

with open(domains_file) as f:
    for line in f:
        parts = line.strip().split("\t")
        if len(parts) < 9:
            continue
        domain = parts[0]

        logfile = None
        for cand in [f"/var/log/nginx/domains/{domain}", f"/var/log/nginx/domains/{domain}.log",
                     f"/etc/apache2/logs/domlogs/{domain}", f"/usr/local/apache/domlogs/{domain}"]:
            if os.path.isfile(cand):
                logfile = cand
                break

        selected = ["/"]

        if logfile:
            counter = Counter()
            try:
                with open(logfile, "r", encoding="utf-8", errors="ignore") as lf:
                    for l in lf:
                        if any(p in l for p in patterns):
                            m = re.search(r"\"(GET|HEAD)\s+([^\s]+)", l)
                            if m:
                                method, raw_url = m.groups()
                                path_clean = raw_url.split("#")[0]
                                path_no_q = path_clean.split("?")[0].lower()
                                if path_clean == "/" or path_clean == "":
                                    continue
                                if any(path_no_q.endswith(ext) for ext in static_exts):
                                    continue
                                if any(term in path_clean.lower() for term in sensitive_terms):
                                    continue
                                counter[path_clean] += 1
            except Exception:
                pass

            for url_cand, _ in counter.most_common(3):
                if url_cand not in selected:
                    selected.append(url_cand)

        for path in selected:
            urls_out.append(f"{domain}\t{path}")

with open(urls_file, "w") as f:
    for u in urls_out:
        f.write(u + "\n")
' "$DOMAINS_FILE" "$PATTERNS_FILE" "$MINUTES" "$URLS_FILE" </dev/null

echo "URLs de prueba seguras seleccionadas."
log "URLs de prueba guardadas en $URLS_FILE"

# ============================================================
# ETAPA 4: BASELINE HTTP PRE-MIGRACIÓN
# ============================================================

stage "4" "18" "Obteniendo Baseline HTTP pre-migración..."

printf "domain\tpath\tfull_url\thttp_code\teffective_url\tredirect_count\tttfb_s\ttotal_time_s\ttimestamp\tcurl_result\n" > "$HTTP_BEFORE_FILE"

run_http_test() {
    local domain="$1"
    local url_path="$2"
    local outfile="$3"

    local full_url="https://${domain}${url_path}"
    local tmp="$WORKDIR/curl_tmp.$$.txt"

    curl -kLsS \
        --connect-timeout 5 \
        --max-time 20 \
        -o /dev/null \
        -w "%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_starttransfer}\t%{time_total}\n" \
        "$full_url" </dev/null 2>/dev/null > "$tmp" || echo -e "000\t${full_url}\t0\t0.000\t0.000" > "$tmp"

    local code eff_url redirects ttfb total
    read -r code eff_url redirects ttfb total < "$tmp"
    rm -f "$tmp"

    local result_str="OK"
    if [[ "$code" == "000" ]]; then
        result_str="CONNECT_ERROR"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$domain" "$url_path" "$full_url" "$code" "$eff_url" "$redirects" "$ttfb" "$total" "$(date '+%F %T')" "$result_str" >> "$outfile"
}

# Ejecutar baseline pre-migración para todos los dominios activos
while IFS=$'\t' read -r DOMAIN URL_PATH; do
    [ -n "$DOMAIN" ] || continue
    run_http_test "$DOMAIN" "$URL_PATH" "$HTTP_BEFORE_FILE"
done < "$URLS_FILE"

echo "Baseline HTTP pre-migración completado."
log "Baseline pre-migración guardado en $HTTP_BEFORE_FILE"

# ============================================================
# ETAPA 5: EVALUACIÓN DE MIGRACIÓN A PHP-FPM
# ============================================================

stage "5" "18" "EVALUACIÓN DE MIGRACIÓN A PHP-FPM"

python3 -c '
import sys, csv
from collections import defaultdict

domains_file, http_file, candidates_file = sys.argv[1:4]

http_summary = defaultdict(list)
with open(http_file) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        http_summary[row["domain"]].append(row["http_code"])

with open(domains_file) as f, open(candidates_file, "w", newline="") as out:
    w = csv.writer(out, delimiter="\t", lineterminator="\n")
    w.writerow(["domain", "account", "version", "fpm", "source", "suspended", "handler", "yaml", "fpm_pkg_installed", "category"])

    for line in f:
        parts = line.strip().split("\t")
        if len(parts) < 9:
            continue
        domain, account, version, fpm, source, suspended, handler, yaml_path, fpm_pkg_installed = parts
        fpm = int(fpm)
        suspended = int(suspended)
        fpm_pkg_installed = int(fpm_pkg_installed)

        if suspended == 1:
            cat = "SUSPENDED"
        elif fpm == 1:
            cat = "ALREADY_FPM"
        elif fpm_pkg_installed == 1:
            cat = "CAN_ENABLE_FPM"
        else:
            cat = "NEEDS_FPM_PKG"

        w.writerow([domain, account, version, fpm, source, suspended, handler, yaml_path, fpm_pkg_installed, cat])
' "$DOMAINS_FILE" "$HTTP_BEFORE_FILE" "$MIGRATION_CANDIDATES" </dev/null

CAND_TABLE="$WORKDIR/cand_table.tsv"
printf "DOMINIO\tCUENTA\tPHP\tHANDLER\tPAQUETE FPM\tESTADO FPM\n" > "$CAND_TABLE"

sed -i 's/\r$//' "$MIGRATION_CANDIDATES" 2>/dev/null || true

while IFS=$'\t' read -r DOMAIN ACCOUNT VERSION FPM SOURCE SUSPENDED HANDLER YAML PKG_INST CAT; do
    DOM_CLEAN=$(echo "$DOMAIN" | tr -d '\r')
    CAT_CLEAN=$(echo "$CAT" | tr -d '\r')
    [ "$DOM_CLEAN" = "domain" ] && continue
    PKG_NAME="${VERSION}-php-fpm"

    if [[ "$CAT_CLEAN" == "ALREADY_FPM" ]]; then
        STATUS_TEXT="FPM ACTIVO"
    elif [[ "$CAT_CLEAN" == "CAN_ENABLE_FPM" ]]; then
        STATUS_TEXT="LISTO PARA MIGRAR"
    elif [[ "$CAT_CLEAN" == "NEEDS_FPM_PKG" ]]; then
        STATUS_TEXT="FALTA PAQUETE"
    elif [[ "$CAT_CLEAN" == "SUSPENDED" ]]; then
        STATUS_TEXT="SUSPENDIDO"
    else
        STATUS_TEXT="ESPECIAL"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$DOM_CLEAN" "$ACCOUNT" "$VERSION" "$HANDLER" "$PKG_NAME" "$STATUS_TEXT" >> "$CAND_TABLE"
done < "$MIGRATION_CANDIDATES"

echo
column -t -s $'\t' "$CAND_TABLE" | awk 'NR==1 {print $0; line=""; for(i=1;i<=length($0);i++) line=line "-"; print line; next} {print $0}' | sed \
    -e "s/LISTO PARA MIGRAR/${YELLOW}LISTO PARA MIGRAR${RESET}/g" \
    -e "s/FPM ACTIVO/${GREEN}FPM ACTIVO${RESET}/g" \
    -e "s/FALTA PAQUETE/${RED}FALTA PAQUETE${RESET}/g" \
    -e "s/SUSPENDIDO/${YELLOW}SUSPENDIDO${RESET}/g"
echo

CAN_MIGRATE_COUNT=$(awk -F'\t' '{gsub(/\r/,""); if($10=="CAN_ENABLE_FPM") c++} END {print c+0}' "$MIGRATION_CANDIDATES")
NEEDS_PKG_COUNT=$(awk -F'\t' '{gsub(/\r/,""); if($10=="NEEDS_FPM_PKG") c++} END {print c+0}' "$MIGRATION_CANDIDATES")

ENABLE_MIGRATION=0

if [[ "$CAN_MIGRATE_COUNT" -gt 0 || "$NEEDS_PKG_COUNT" -gt 0 ]]; then
    echo -e "${YELLOW}Se detectaron dominios que actualmente no utilizan PHP-FPM (${CAN_MIGRATE_COUNT} listos para migrar, ${NEEDS_PKG_COUNT} necesitan paquete).${RESET}"
    prompt_user "¿Deseas habilitar PHP-FPM en los dominios compatibles que actualmente no lo utilizan? [y/N]: " CONFIRM_MIG
    case "$CONFIRM_MIG" in
        y|Y|yes|YES)
            ENABLE_MIGRATION=1
            ;;
        *)
            echo "Migración a PHP-FPM declinada. Se continuará únicamente con la optimización de pools existentes."
            log "Usuario declinó habilitar PHP-FPM."
            ;;
    esac
else
    echo "No hay dominios pendientes de migración a PHP-FPM."
fi

# ============================================================
# ETAPA 6: INSTALACIÓN OPCIONAL DE PAQUETES FPM
# ============================================================

stage "6" "18" "Instalación opcional de componentes PHP-FPM faltantes..."

INSTALLED_NEW_PKGS=0

if [[ "$ENABLE_MIGRATION" == "1" && "$NEEDS_PKG_COUNT" -gt 0 ]]; then
    MISSING_PKGS=$(awk -F'\t' '{gsub(/\r/,""); if($10=="NEEDS_FPM_PKG") print $3"-php-fpm"}' "$MIGRATION_CANDIDATES" | sort -u)

    echo
    echo -e "${YELLOW}Los siguientes paquetes son necesarios para activar PHP-FPM:${RESET}"
    for pkg in $MISSING_PKGS; do
        echo "  - $pkg"
    done
    echo

    prompt_user "¿Deseas instalar estos paquetes mediante EasyApache/YUM/DNF? [y/N]: " CONFIRM_PKG
    case "$CONFIRM_PKG" in
        y|Y|yes|YES)
            echo "Instalando paquetes FPM faltantes..."
            log "Instalando paquetes: $MISSING_PKGS"
            if yum install -y $MISSING_PKGS </dev/null >> "$LOG_FILE" 2>&1; then
                echo -e "${GREEN}Paquetes instalados correctamente.${RESET}"
                INSTALLED_NEW_PKGS=1
                # Actualizar candidates
                python3 -c '
import sys, os, csv

candidates_file = sys.argv[1]
rows = []
with open(candidates_file) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        ver = row["version"]
        fpm_bin1 = f"/opt/cpanel/{ver}/root/usr/sbin/php-fpm"
        fpm_bin2 = f"/opt/cpanel/{ver}/root/usr/bin/php-fpm"
        if os.path.isfile(fpm_bin1) or os.path.isfile(fpm_bin2):
            row["fpm_pkg_installed"] = "1"
            if row["category"] == "NEEDS_FPM_PKG":
                row["category"] = "CAN_ENABLE_FPM"
        rows.append(row)

with open(candidates_file, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=list(rows[0].keys()), delimiter="\t", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
' "$MIGRATION_CANDIDATES" </dev/null
            else
                echo -e "${RED}Error al instalar paquetes FPM. Omitiendo esos dominios.${RESET}"
                log "Error en yum install FPM pkgs."
            fi
            ;;
        *)
            echo "Instalación de paquetes declinada. Se omitirán los dominios sin paquete FPM."
            log "Usuario declinó instalar paquetes FPM."
            ;;
    esac
fi

# ============================================================
# ETAPAS 7 Y 8: MIGRACIÓN DOMINIO POR DOMINIO Y ROLLBACK POR REGRESIÓN
# ============================================================

stage "7" "18" "Migrando dominios a PHP-FPM y realizando verificación unitaria..."

printf "domain\tpath\tfull_url\thttp_code\teffective_url\tredirect_count\tttfb_s\ttotal_time_s\ttimestamp\tcurl_result\n" > "$HTTP_AFTER_FILE"
printf "domain\tbefore_code\tafter_code\tstatus\tnotes\n" > "$HTTP_COMPARE_FILE"

CONSECUTIVE_REGRESSIONS=0
GLOBAL_ABORT=0

if [[ "$ENABLE_MIGRATION" == "1" ]]; then
    while IFS=$'\t' read -r DOMAIN ACCOUNT VERSION FPM SOURCE SUSPENDED HANDLER YAML PKG_INST CAT; do
        DOM_CLEAN=$(echo "$DOMAIN" | tr -d '\r')
        CAT_CLEAN=$(echo "$CAT" | tr -d '\r')
        [ "$DOM_CLEAN" = "domain" ] && continue

        if [[ "$CAT_CLEAN" != "CAN_ENABLE_FPM" ]]; then
            continue
        fi

        if [[ "$GLOBAL_ABORT" == "1" ]]; then
            echo -e "${YELLOW}OMITIDO $DOM_CLEAN (Global Abort activado por regresiones previas).${RESET}"
            log "$DOM_CLEAN | SKIPPED | Global Abort"
            continue
        fi

        echo -e "${BLUE}Procesando migración:${RESET} $DOM_CLEAN ($VERSION)"
        log "$DOM_CLEAN | Activando FPM | version=$VERSION | source=$SOURCE"

        # 1. Invocación WHM API
        RESULT="$(whmapi1 --output=json php_set_vhost_versions version="$VERSION" vhost="$DOM_CLEAN" php_fpm=1 </dev/null 2>&1)"
        echo "$RESULT" >> "$LOG_FILE"

        API_STATUS="$(printf '%s' "$RESULT" | python3 -c '
import json, sys
try:
    x = json.load(sys.stdin)
    print(x.get("metadata", {}).get("result", 0))
except Exception:
    print(0)
')"

        if [[ "$API_STATUS" != "1" ]]; then
            echo -e "  Estado: ${RED}ERROR API WHM${RESET}"
            log "$DOM_CLEAN | FAILED API"
            continue
        fi

        # 2. Re-verificar pruebas HTTP post migración para este dominio
        DOMAIN_URLS=$(grep "^${DOM_CLEAN}"$'\t' "$URLS_FILE" || true)

        HAS_REGRESSION=0

        while IFS=$'\t' read -r _ DOM_PATH; do
            [ -n "$DOM_PATH" ] || continue
            run_http_test "$DOM_CLEAN" "$DOM_PATH" "$HTTP_AFTER_FILE"

            # Comparar pre vs post para esta URL
            python3 -c '
import sys, csv

before_file, after_file, domain, path, compare_file = sys.argv[1:6]

def get_row(fpath, dom, pth):
    with open(fpath) as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["domain"] == dom and r["path"] == pth:
                return r
    return None

b = get_row(before_file, domain, path)
a = get_row(after_file, domain, path)

b_code = int(b["http_code"]) if b and b["http_code"].isdigit() else 0
a_code = int(a["http_code"]) if a and a["http_code"].isdigit() else 0

if a_code == 0 or (b_code in (200, 301, 302) and a_code in (500, 502, 503, 504)):
    status = "REGRESSION_CRITICAL"
elif b_code == 200 and a_code == 200:
    status = "OK"
elif b_code == 301 and a_code == 301:
    status = "OK"
elif b_code in (500, 502, 503) and a_code in (500, 502, 503):
    status = "EXISTING_ERROR"
elif b_code == 403 and a_code == 403:
    status = "UNCHANGED"
elif b_code in (500, 502, 503) and a_code in (200, 301, 302):
    status = "IMPROVED"
elif b_code < 400 and a_code >= 400:
    status = "REGRESSION_CRITICAL"
else:
    status = "CHANGED"

with open(compare_file, "a", newline="") as out:
    w = csv.writer(out, delimiter="\t", lineterminator="\n")
    w.writerow([domain, b_code, a_code, status, f"path={path}"])

if status == "REGRESSION_CRITICAL":
    sys.exit(2)
' "$HTTP_BEFORE_FILE" "$HTTP_AFTER_FILE" "$DOM_CLEAN" "$DOM_PATH" "$HTTP_COMPARE_FILE" </dev/null
            RC=$?
            if [[ $RC -eq 2 ]]; then
                HAS_REGRESSION=1
            fi
        done <<< "$DOMAIN_URLS"

        if [[ "$HAS_REGRESSION" == "1" ]]; then
            echo -e "  Estado: ${RED}[REGRESSION_CRITICAL] Se detectó regresión HTTP.${RESET}"
            log "$DOM_CLEAN | REGRESSION_CRITICAL | Realizando rollback de FPM..."

            # Rollback unitario
            whmapi1 --output=json php_set_vhost_versions version="$VERSION" vhost="$DOM_CLEAN" php_fpm=0 </dev/null >> "$LOG_FILE" 2>&1
            echo -e "  Rollback: ${YELLOW}PHP-FPM desactivado para $DOM_CLEAN (versión $VERSION preservada).${RESET}"
            log "$DOM_CLEAN | ROLLED_BACK"

            ((CONSECUTIVE_REGRESSIONS++))

            if [[ "$CONSECUTIVE_REGRESSIONS" -ge "$MAX_CONSECUTIVE_REGRESSIONS" ]]; then
                echo -e "${RED}[GLOBAL_ABORT] Se detectaron $CONSECUTIVE_REGRESSIONS regresiones consecutivas. Deteniendo nuevas migraciones.${RESET}"
                log "GLOBAL_ABORT disparado a las $CONSECUTIVE_REGRESSIONS regresiones."
                GLOBAL_ABORT=1
            fi
        else
            echo -e "  Estado: ${GREEN}[OK] PHP-FPM activado y validado sin regresiones.${RESET}"
            log "$DOM_CLEAN | SUCCESS FPM"
            CONSECUTIVE_REGRESSIONS=0
        fi

        echo
    done < "$MIGRATION_CANDIDATES"
fi

# ============================================================
# ETAPA 9: SNAPSHOT POST-MIGRACIÓN
# ============================================================

stage "9" "18" "Obteniendo snapshot final post-migración..."

if ! whmapi1 --output=json php_get_vhost_versions </dev/null > "$AFTER_MIGRATION_JSON" 2>>"$LOG_FILE"; then
    die "No fue posible obtener el snapshot final post-migración."
fi

# ============================================================
# ETAPA 10: DIAGNÓSTICO GLOBAL DE RECURSOS DEL VPS
# ============================================================

stage "10" "18" "Diagnóstico global de recursos del servidor..."

TOTAL_MB=$(awk '/MemTotal:/ {printf "%.0f",$2/1024}' /proc/meminfo)
AVAIL_MB=$(awk '/MemAvailable:/ {printf "%.0f",$2/1024}' /proc/meminfo)
SWAP_TOTAL_MB=$(awk '/SwapTotal:/ {printf "%.0f",$2/1024}' /proc/meminfo)
SWAP_FREE_MB=$(awk '/SwapFree:/ {printf "%.0f",$2/1024}' /proc/meminfo)
SWAP_USED_MB=$(( SWAP_TOTAL_MB - SWAP_FREE_MB ))
CPU=$(nproc)
LOAD1=$(awk '{print $1}' /proc/loadavg)

PHP_RSS_MB=$(ps -eo rss,args | awk '/php-fpm: pool/ {s+=$1} END {printf "%.0f",s/1024}')
MYSQL_RSS_MB=$(ps -eo rss,comm | awk 'tolower($2) ~ /^(mysqld|mariadbd)$/ {s+=$1} END {printf "%.0f",s/1024}')
HTTPD_RSS_MB=$(ps -eo rss,comm | awk 'tolower($2) ~ /^(httpd|apache2|nginx)$/ {s+=$1} END {printf "%.0f",s/1024}')

cat > "$SYSTEM_ENV" <<EOF
TOTAL_MB=$TOTAL_MB
AVAIL_MB=$AVAIL_MB
SWAP_TOTAL_MB=$SWAP_TOTAL_MB
SWAP_USED_MB=$SWAP_USED_MB
CPU=$CPU
LOAD1=$LOAD1
PHP_RSS_MB=$PHP_RSS_MB
MYSQL_RSS_MB=$MYSQL_RSS_MB
HTTPD_RSS_MB=$HTTPD_RSS_MB
MINUTES=$MINUTES
PHP_BUDGET_MAX_PCT=$PHP_BUDGET_MAX_PCT
HEADROOM_MIN_MB=$HEADROOM_MIN_MB
HEADROOM_PCT=$HEADROOM_PCT
MAX_CHILDREN_HARD=$MAX_CHILDREN_HARD
ACTIVE_MIN_CHILDREN=$ACTIVE_MIN_CHILDREN
IDLE_MIN_CHILDREN=$IDLE_MIN_CHILDREN
MAX_REDUCTION_RATIO=$MAX_REDUCTION_RATIO
EOF

hr
echo " RECURSOS DEL SERVIDOR"
hr
echo " RAM Total            : ${TOTAL_MB} MB"
echo " RAM Disponible       : ${AVAIL_MB} MB"
echo " Swap Usada           : ${SWAP_USED_MB} / ${SWAP_TOTAL_MB} MB"
echo " Cores CPU            : ${CPU}"
echo " Carga 1m             : ${LOAD1}"
echo " PHP-FPM RSS Actual   : ${PHP_RSS_MB} MB"
echo " MariaDB/MySQL RSS    : ${MYSQL_RSS_MB} MB"
echo " Apache/Nginx RSS     : ${HTTPD_RSS_MB} MB"
hr
echo

# ============================================================
# ETAPA 11: WARM-UP INICIAL DE POOLS RECIÉN MIGRADOS
# ============================================================

stage "11" "18" "Warm-up inicial y primera muestra para pools recién creados..."

# Enviar solicitudes GET livianas a dominios recién migrados
while IFS=$'\t' read -r DOMAIN URL_PATH; do
    curl -kLsS --connect-timeout 2 --max-time 3 "https://${DOMAIN}${URL_PATH}" </dev/null >/dev/null 2>&1 || true
done < "$URLS_FILE"

sleep 1

# ============================================================
# ETAPA 12: ANÁLISIS DE POOLS Y CLASIFICACIÓN DE CONFIANZA
# ============================================================

stage "12" "18" "Análisis de pools PHP-FPM y clasificación de datos..."

printf "domain\tphpver\tconf\tcurrent_children\tcurrent_requests\tpm\tidle\tyaml\tpool_type\n" > "$POOLS_FILE"

for f in /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf; do
    [ -f "$f" ] || continue

    phpver=$(echo "$f" | sed -n 's#^/opt/cpanel/\(ea-php[0-9]*\)/.*#\1#p')
    domain=$(basename "$f" .conf)

    # Ignorar pools internos
    echo "$domain" | grep -qE '^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$' || continue

    pm=$(awk -F= '/^[[:space:]]*pm[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")
    children=$(awk -F= '/^[[:space:]]*pm\.max_children[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")
    requests=$(awk -F= '/^[[:space:]]*pm\.max_requests[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")
    idle=$(awk -F= '/^[[:space:]]*pm\.process_idle_timeout[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")

    # Localizar YAML
    yaml="MISSING"
    account=$(awk -F'\t' -v d="$domain" '$1==d {print $2; exit}' "$DOMAINS_FILE")
    if [ -n "$account" ] && [ -f "/var/cpanel/userdata/${account}/${domain}.php-fpm.yaml" ]; then
        yaml="/var/cpanel/userdata/${account}/${domain}.php-fpm.yaml"
    else
        found=$(find /var/cpanel/userdata -mindepth 2 -maxdepth 2 -type f -name "${domain}.php-fpm.yaml" -print -quit 2>/dev/null || true)
        [ -n "$found" ] && yaml="$found"
    fi

    # Determinar tipo de pool
    migrated=$(awk -F'\t' -v d="$domain" '$1==d && $4=="0" {print "NEW_FPM_POOL"}' "$MIGRATION_CANDIDATES")
    pool_type="${migrated:-EXISTING_FPM}"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$domain" "$phpver" "$f" "${children:-0}" "${requests:-0}" \
        "${pm:-unknown}" "${idle:-0}" "$yaml" "$pool_type" >> "$POOLS_FILE"
done

POOL_COUNT=$(( $(wc -l < "$POOLS_FILE") - 1 ))
[ "$POOL_COUNT" -gt 0 ] || die "No se encontraron pools PHP-FPM activos de dominios."

# Memoria por pool, P90 y Confidence
printf "domain\tworkers\ttotal_mb\tavg_mb\tp90_mb\tmax_mb\tmem_source\tconfidence\n" > "$MEMORY_FILE"

tail -n +2 "$POOLS_FILE" | while IFS=$'\t' read -r domain phpver conf cc cr pm idle yaml pool_type; do
    vals="$WORKDIR/rss.$$.txt"
    ps -eo rss,args | awk -v pool="$domain" '
        index($0, "php-fpm: pool " pool) {printf "%.3f\n",$1/1024}
    ' | sort -n > "$vals"

    workers=$(wc -l < "$vals")
    if [ "$workers" -gt 0 ]; then
        total=$(awk '{s+=$1} END {printf "%.1f",s}' "$vals")
        avg=$(awk '{s+=$1} END {printf "%.1f",s/NR}' "$vals")
        p90=$(awk '
            {a[NR]=$1}
            END {
                if (NR==0) {print 0; exit}
                i=int((NR-1)*0.90)+1
                printf "%.1f",a[i]
            }' "$vals")
        max=$(tail -1 "$vals")

        if [ "$pool_type" = "NEW_FPM_POOL" ]; then
            mem_source="ESTIMATED"
            confidence="PROVISIONAL"
        elif [ "$workers" -ge 2 ]; then
            mem_source="MEASURED"
            confidence="HIGH"
        else
            mem_source="MEASURED"
            confidence="MEDIUM"
        fi
    else
        total=0
        avg=0
        p90=0
        max=0
        mem_source="ESTIMATED"
        if [ "$pool_type" = "NEW_FPM_POOL" ]; then
            confidence="PROVISIONAL"
        else
            confidence="LOW"
        fi
    fi
    rm -f "$vals"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$domain" "$workers" "$total" "$avg" "$p90" "$max" "$mem_source" "$confidence"
done >> "$MEMORY_FILE"

# Max children hits
printf "domain\thits_max_children\n" > "$HITS_FILE"
tail -n +2 "$POOLS_FILE" | cut -f1 | while read -r domain; do
    hits=0
    for logfile in \
        /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log \
        /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/*.log \
        /var/log/php-fpm* /var/log/php-fpm/*; do
        [ -f "$logfile" ] || continue
        n=$(grep -Fi "[pool $domain]" "$logfile" 2>/dev/null \
            | grep -iEc 'server reached pm\.max_children|max_children.*reached|seems busy' || true)
        hits=$((hits+n))
    done
    printf "%s\t%s\n" "$domain" "$hits"
done >> "$HITS_FILE"

# Tráfico reciente por pool con diagnóstico de log y categoría
printf "domain\ttraffic_log\ttraffic_source\ttotal_reqs\tdynamic_reqs\tavg_dyn_rpm\tpeak_dyn_rpm\terrors\ttraffic_data\n" > "$TRAFFIC_FILE"

tail -n +2 "$POOLS_FILE" | cut -f1 | while read -r domain; do
    logfile=""
    source_type="NONE"
    for candidate in \
        "/var/log/nginx/domains/$domain" \
        "/var/log/nginx/domains/${domain}.log"; do
        if [ -f "$candidate" ]; then
            logfile="$candidate"
            source_type="NGINX"
            break
        fi
    done

    if [ -z "$logfile" ]; then
        for candidate in \
            "/etc/apache2/logs/domlogs/$domain" \
            "/usr/local/apache/domlogs/$domain"; do
            if [ -f "$candidate" ]; then
                logfile="$candidate"
                source_type="APACHE"
                break
            fi
        done
    fi

    if [ -n "$logfile" ]; then
        tmp="$WORKDIR/log.$$.tmp"
        grep -Ff "$PATTERNS_FILE" "$logfile" 2>/dev/null > "$tmp" || true
        total_reqs=$(wc -l < "$tmp")

        if [ "$total_reqs" -eq 0 ]; then
            printf "%s\t%s\t%s\t0\t0\t0\t0\t0\tMEASURED_ZERO\n" "$domain" "$logfile" "$source_type"
        else
            awk -v d="$domain" -v logf="$logfile" -v stype="$source_type" -v mins="$MINUTES" -F'"' '
            {
                split($2,a," ")
                url=a[2]
                isdyn = (url ~ /\.php([?\/]|$)/ ||
                         url ~ /\/([?]|$)/ ||
                         url !~ /\.(css|js|jpg|jpeg|png|gif|webp|svg|ico|woff|woff2|ttf|map|mp4|webm|pdf|zip|xml|txt)(\?|$)/)

                if (isdyn) {
                    dyn++
                    if (match($0,/\[[0-9][0-9]\/[A-Za-z]+\/[0-9]+:[0-9][0-9]:[0-9][0-9]:/)) {
                        ts=substr($0,RSTART+1,RLENGTH-2)
                        sub(/:[0-9][0-9]:$/,":",ts)
                        permin[ts]++
                    }
                }

                if (match($0,/" [45][0-9][0-9] /))
                    err++
            }
            END {
                peak=0
                for (x in permin)
                    if (permin[x] > peak) peak=permin[x]
                tdata = (dyn > 0) ? "MEASURED_TRAFFIC" : "MEASURED_ZERO"
                printf "%s\t%s\t%s\t%d\t%d\t%.2f\t%d\t%d\t%s\n",
                       d, logf, stype, NR, dyn+0, (dyn+0)/mins, peak+0, err+0, tdata
            }' "$tmp"
        fi
        rm -f "$tmp"
    else
        printf "%s\tNONE\tNONE\t0\t0\t0\t0\t0\tLOG_NOT_FOUND\n" "$domain"
    fi
done >> "$TRAFFIC_FILE"

# Alerta si la recolección de tráfico parece incompleta
MEASURED_TRAFFIC_COUNT=$(awk -F'\t' '$9=="MEASURED_TRAFFIC" {c++} END {print c+0}' "$TRAFFIC_FILE")
if [ "$MEASURED_TRAFFIC_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}ADVERTENCIA: No se detectó tráfico dinámico en los dominios analizados o los logs no fueron localizados.${RESET}"
    log "WARNING: Tráfico dinámico no detectado en logs."
fi

# HTTP performance metrics (resumido de baseline)
printf "domain\thttp_ok\tavg_total_s\tmax_total_s\tavg_ttfb_s\n" > "$HTTP_PERF_FILE"

python3 -c '
import sys, csv
from collections import defaultdict

before_file, perf_file = sys.argv[1:3]

metrics = defaultdict(list)
with open(before_file) as f:
    for r in csv.DictReader(f, delimiter="\t"):
        d = r["domain"]
        code = int(r["http_code"]) if r["http_code"].isdigit() else 0
        ttfb = float(r["ttfb_s"]) if r["ttfb_s"].replace(".","",1).isdigit() else 0.0
        total = float(r["total_time_s"]) if r["total_time_s"].replace(".","",1).isdigit() else 0.0
        if code > 0:
            metrics[d].append((code, total, ttfb))

with open(perf_file, "w", newline="") as out:
    w = csv.writer(out, delimiter="\t", lineterminator="\n")
    w.writerow(["domain", "http_ok", "avg_total_s", "max_total_s", "avg_ttfb_s"])

    for dom, vals in metrics.items():
        ok_count = len(vals)
        avg_tot = sum(v[1] for v in vals) / ok_count
        max_tot = max(v[1] for v in vals)
        avg_ttfb = sum(v[2] for v in vals) / ok_count
        w.writerow([dom, ok_count, f"{avg_tot:.3f}", f"{max_tot:.3f}", f"{avg_ttfb:.3f}"])
' "$HTTP_BEFORE_FILE" "$HTTP_PERF_FILE" </dev/null

# Merge de todas las métricas
python3 -c '
import csv, sys

paths = sys.argv[1:6]
out = sys.argv[6]

def read(path):
    with open(path, newline="") as f:
        return {r["domain"]: r for r in csv.DictReader(f, delimiter="\t")}

pools, memory, traffic, http, hits = map(read, paths)

fields = [
    "domain","phpver","yaml","pm","pool_type",
    "current_children","current_requests",
    "workers","avg_mb","p90_mb","max_mb","mem_source","confidence",
    "traffic_log","traffic_source","total_reqs","dynamic_reqs","avg_dyn_rpm","peak_dyn_rpm","errors","traffic_data",
    "http_ok","avg_total_s","max_total_s","avg_ttfb_s",
    "hits_max_children"
]

with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fields, delimiter="\t", lineterminator="\n")
    w.writeheader()
    for domain, p in sorted(pools.items()):
        row = {"domain": domain}
        for src in (p, memory.get(domain,{}), traffic.get(domain,{}),
                    http.get(domain,{}), hits.get(domain,{})):
            row.update(src)
        w.writerow({k: row.get(k, "0") for k in fields})
' "$POOLS_FILE" "$MEMORY_FILE" "$TRAFFIC_FILE" "$HTTP_PERF_FILE" "$HITS_FILE" "$MERGED_FILE" </dev/null

# ============================================================
# ETAPA 13: CÁLCULO DE RECOMENDACIONES DE OPTIMIZACIÓN
# ============================================================

stage "13" "18" "Calculando recomendaciones inteligentes (pm.max_children y pm.max_requests)..."

python3 -c '
import csv, math, sys

system_path, merged_path, out_path = sys.argv[1:4]

env = {}
with open(system_path) as f:
    for line in f:
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v

def f(k): return float(env[k])
def i(k): return int(float(env[k]))

total = f("TOTAL_MB")
avail = f("AVAIL_MB")
swap_used = f("SWAP_USED_MB")
swap_total = max(1.0, f("SWAP_TOTAL_MB"))
cpu = max(1.0, f("CPU"))
load1 = f("LOAD1")
php_now = f("PHP_RSS_MB")
max_reduction_ratio = float(env.get("MAX_REDUCTION_RATIO", "0.50"))

headroom = max(f("HEADROOM_MIN_MB"), total * f("HEADROOM_PCT") / 100.0)
cap_pct = total * f("PHP_BUDGET_MAX_PCT") / 100.0
cap_live = avail + php_now - headroom
php_budget = max(256.0, min(cap_pct, cap_live))

pressure = 1.0
reasons_global = []

swap_ratio = swap_used / swap_total if swap_total else 0
load_ratio = load1 / cpu

if swap_used > 256 and swap_ratio > 0.20:
    pressure *= 0.85
    reasons_global.append("swap alta (>20%)")
if load_ratio > 1.50:
    pressure *= 0.85
    reasons_global.append("load alto (>1.5x CPU)")
elif load_ratio > 1.00:
    pressure *= 0.92
    reasons_global.append("load sobre CPU")

php_budget *= pressure
php_budget = max(256.0, php_budget)

with open(merged_path, newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

def num(r, k, default=0.0):
    try: return float(r.get(k) or default)
    except: return default

measured_mems = [num(r, "p90_mb") or num(r, "avg_mb") for r in rows if num(r, "workers") > 0]
server_median_mem = sorted(measured_mems)[len(measured_mems)//2] if measured_mems else 64.0
server_median_mem = max(48.0, min(128.0, server_median_mem))

for r in rows:
    workers = num(r, "workers")
    avg_mem = num(r, "avg_mb")
    p90 = num(r, "p90_mb")
    max_mem = num(r, "max_mb")
    peak_rpm = num(r, "peak_dyn_rpm")
    avg_rpm = num(r, "avg_dyn_rpm")
    t = num(r, "avg_total_s")
    hits = num(r, "hits_max_children")
    dynamic = num(r, "dynamic_reqs")
    pool_type = r.get("pool_type", "EXISTING_FPM")

    if r.get("mem_source") == "MEASURED" and (p90 or avg_mem):
        mem_ref = max(48.0, p90 or avg_mem)
        if max_mem > mem_ref * 1.75:
            mem_ref = max(mem_ref, min(max_mem, mem_ref * 1.35))
    else:
        mem_ref = server_median_mem

    concurrency_peak = peak_rpm * max(t, 0.25) / 60.0
    concurrency_avg = avg_rpm * max(t, 0.25) / 60.0

    demand = max(
        1.0 if dynamic == 0 else float(i("ACTIVE_MIN_CHILDREN")),
        workers * 1.25,
        concurrency_peak * 1.75,
        concurrency_avg * 2.25,
    )

    if hits > 0:
        demand = max(demand, num(r, "current_children") + min(4.0, 1.0 + math.log10(hits + 1)))

    raw_rec = int(math.ceil(demand))

    if pool_type == "NEW_FPM_POOL":
        raw_rec = min(raw_rec, 4)

    raw_rec = max(i("IDLE_MIN_CHILDREN") if dynamic == 0 else i("ACTIVE_MIN_CHILDREN"), raw_rec)
    raw_rec = min(i("MAX_CHILDREN_HARD"), raw_rec)

    r["_mem_ref"] = mem_ref
    r["_raw_rec"] = raw_rec
    r["_demand"] = demand
    r["_concurrency"] = max(concurrency_peak, concurrency_avg)

out_fields = [
    "domain", "phpver", "yaml", "pool_type", "confidence", "mem_source", "traffic_data",
    "current_children", "raw_recommendation", "guardrail_recommendation", "final_children",
    "current_requests", "recommended_requests",
    "workers", "mem_ref_mb", "peak_dyn_rpm", "avg_total_s",
    "hits_max_children", "estimated_pool_max_mb", "tuning_eligibility", "reason"
]

with open(out_path, "w", newline="") as f:
    w = csv.DictWriter(f, out_fields, delimiter="\t", lineterminator="\n")
    w.writeheader()

    for idx, r in enumerate(rows):
        cur_ch = int(num(r, "current_children"))
        raw_rec = r["_raw_rec"]
        pool_type = r.get("pool_type", "EXISTING_FPM")
        mem_source = r.get("mem_source", "ESTIMATED")
        confidence = r.get("confidence", "LOW")
        traffic_data = r.get("traffic_data", "LOG_NOT_FOUND")
        hits = int(num(r, "hits_max_children"))

        reasons = []

        # REGLA 1 & 11: Protección estricta ante falta de datos
        if pool_type == "EXISTING_FPM" and (confidence in ("LOW", "PROVISIONAL") or traffic_data != "MEASURED_TRAFFIC" or mem_source == "ESTIMATED"):
            final_rec = cur_ch
            guardrail_rec = cur_ch
            eligibility = "INSUFFICIENT_DATA"
            reasons.append("Datos de tráfico/memoria no medidos estadísticamente; preserva configuración actual")
        else:
            # Regla de piso y guardrail de reducción
            min_allowed = 2 if (traffic_data == "MEASURED_TRAFFIC" or hits > 0 or r["_concurrency"] > 0.5) else 1

            if raw_rec == 1 and not (confidence in ("HIGH", "MEDIUM") and traffic_data == "MEASURED_ZERO" and hits == 0 and cur_ch <= 3):
                raw_rec = max(2, raw_rec)

            raw_rec = max(min_allowed, raw_rec)

            # Regla 6: Guardrail de Reducción Progresiva (max 50% por ejecución)
            if raw_rec < cur_ch:
                max_reduction = max(1, int(cur_ch * max_reduction_ratio))
                guardrail_rec = max(cur_ch - max_reduction, raw_rec)
            else:
                guardrail_rec = raw_rec

            final_rec = guardrail_rec

            if final_rec == cur_ch:
                eligibility = "NO_CHANGE"
                reasons.append("Configuración actual adecuada")
            elif pool_type == "NEW_FPM_POOL":
                eligibility = "SAFE_TO_APPLY"
                reasons.append("Configuración inicial provisional conservadora para nuevo pool")
            elif confidence in ("HIGH", "MEDIUM") and traffic_data == "MEASURED_TRAFFIC":
                eligibility = "SAFE_TO_APPLY"
                reasons.append("Ajuste basado en demanda/memoria real observada")
            else:
                eligibility = "REVIEW_RECOMMENDED"
                reasons.append("Ajuste recomendado para revisión manual")

        if hits > 0:
            reasons.append("alcanzó max_children (%d veces)" % hits)
        if num(r, "peak_dyn_rpm") > 0:
            reasons.append("pico %.0f dyn/min" % num(r, "peak_dyn_rpm"))
        if num(r, "avg_total_s") >= 2:
            reasons.append("HTTP lento %.2fs" % num(r, "avg_total_s"))

        # Reciclaje pm.max_requests
        mem = r["_mem_ref"]
        avg = num(r, "avg_mb")
        maxm = num(r, "max_mb")
        variability = (maxm / avg) if avg > 0 else 1.0

        if confidence == "PROVISIONAL" or num(r, "workers") == 0:
            maxreq = 250
        elif mem >= 256 or variability >= 3.0:
            maxreq = 100
        elif mem >= 192 or variability >= 2.3:
            maxreq = 150
        elif mem >= 128 or variability >= 1.8:
            maxreq = 200
        elif mem >= 96:
            maxreq = 300
        else:
            maxreq = 500

        w.writerow({
            "domain": r["domain"],
            "phpver": r["phpver"],
            "yaml": r["yaml"],
            "pool_type": pool_type,
            "confidence": confidence,
            "mem_source": mem_source,
            "traffic_data": traffic_data,
            "current_children": cur_ch,
            "raw_recommendation": raw_rec,
            "guardrail_recommendation": guardrail_rec,
            "final_children": final_rec,
            "current_requests": int(num(r, "current_requests")),
            "recommended_requests": maxreq,
            "workers": int(num(r, "workers")),
            "mem_ref_mb": "%.1f" % mem,
            "peak_dyn_rpm": "%.1f" % num(r, "peak_dyn_rpm"),
            "avg_total_s": "%.3f" % num(r, "avg_total_s"),
            "hits_max_children": hits,
            "estimated_pool_max_mb": "%.1f" % (final_rec * mem),
            "tuning_eligibility": eligibility,
            "reason": "; ".join(reasons)
        })
' "$SYSTEM_ENV" "$MERGED_FILE" "$RECS_FILE" </dev/null

# ============================================================
# ETAPA 14: PRESENTACIÓN Y CONFIRMACIÓN DE TUNING
# ============================================================

stage "14" "18" "RECOMENDACIONES DE OPTIMIZACIÓN DE POOLS"

RECS_TABLE="$WORKDIR/recs_table.tsv"
printf "DOMINIO\tTIPO POOL\tCONFIANZA\tTRÁFICO\tELEGIBILIDAD\tCUR_CH\tREC_CH\tCUR_RQ\tREC_RQ\tWORKERS\tMEM_MB\tHITS\n" > "$RECS_TABLE"

sed -i 's/\r$//' "$RECS_FILE" 2>/dev/null || true

tail -n +2 "$RECS_FILE" | while IFS=$'\t' read -r dom phpver yaml ptype conf msrc tdata cc raw_rec guard_rec final_ch cr rr workers mem peak htt hits est eligibility reason; do
    [ "$dom" = "domain" ] && continue
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$dom" "$ptype" "$conf" "$tdata" "$eligibility" "$cc" "$final_ch" "$cr" "$rr" "$workers" "$mem" "$hits" >> "$RECS_TABLE"
done

echo
column -t -s $'\t' "$RECS_TABLE" | awk 'NR==1 {print $0; line=""; for(i=1;i<=length($0);i++) line=line "-"; print line; next} {print $0}' | sed \
    -e "s/SAFE_TO_APPLY/${GREEN}SAFE_TO_APPLY${RESET}/g" \
    -e "s/REVIEW_RECOMMENDED/${YELLOW}REVIEW_RECOMMENDED${RESET}/g" \
    -e "s/INSUFFICIENT_DATA/${RED}INSUFFICIENT_DATA${RESET}/g" \
    -e "s/NO_CHANGE/${CYAN}NO_CHANGE${RESET}/g"
echo

echo "Detalle de decisiones por dominio:"
tail -n +2 "$RECS_FILE" | while IFS=$'\t' read -r dom phpver yaml ptype conf msrc tdata cc raw_rec guard_rec final_ch cr rr workers mem peak htt hits est eligibility reason; do
    echo "  - $dom [$eligibility]: $reason"
done

echo
MISSING_YAMLS=$(awk -F'\t' 'NR>1 && $3=="MISSING" {print $1}' "$RECS_FILE")
if [ -n "$MISSING_YAMLS" ]; then
    echo -e "${YELLOW}ADVERTENCIA: No se encontró YAML para los siguientes dominios (se omitirán):${RESET}"
    echo "$MISSING_YAMLS" | sed 's/^/  - /'
    echo
fi

APPLY_SAFE_COUNT=$(awk -F'\t' '{gsub(/\r/,""); if($20=="SAFE_TO_APPLY" && $8!=$11) c++} END {print c+0}' "$RECS_FILE")

echo -e "${YELLOW}INFORMACIÓN DE APLICACIÓN:${RESET}"
echo "  1) Se modificarán ÚNICAMENTE los pools marcados como SAFE_TO_APPLY ($APPLY_SAFE_COUNT pools elegibles)."
echo "  2) Se respaldará cada YAML en $WORKDIR/yaml_backups/"
echo "  3) Se modificarán ÚNICAMENTE pm_max_children y pm_max_requests en /var/cpanel/userdata/"
echo "  4) Se ejecutará /usr/local/cpanel/scripts/php_fpm_config --rebuild"
echo "  5) Se reiniciarán Apache PHP-FPM y HTTPD"
echo "  6) Si ocurre algún fallo, se aplicará ROLLBACK AUTOMÁTICO"
echo

if [ "$APPLY_SAFE_COUNT" -eq 0 ]; then
    echo -e "${GREEN}No hay pools con datos suficientes que requieran modificaciones automáticas.${RESET}"
    echo "Los pools sin datos de tráfico o memoria se han mantenido intactos de forma segura."
    log "No hay pools elegibles SAFE_TO_APPLY para modificar."
    exit 0
fi

prompt_user "Escribe APLICAR para confirmar los cambios de tuning, o cualquier otra cosa para salir: " CONFIRM_TUNING

if [[ "$CONFIRM_TUNING" != "APLICAR" ]]; then
    echo "Proceso finalizado sin aplicar tuning."
    log "Usuario no confirmó tuning. Proceso finalizado."
    exit 0
fi

# ============================================================
# ETAPAS 15, 16 Y 17: EDICIÓN DE YAMLS, REBUILD Y VERIFICACIÓN
# ============================================================

stage "15" "18" "Creando respaldos de YAML..."
stage "16" "18" "Aplicando cambios en YAMLs y ejecutando rebuild..."

printf "domain\tyaml\tbackup\tprev_c\tnew_c\tprev_r\tnew_r\n" > "$CHANGED_LIST"

update_yaml() {
    local yaml="$1"
    local children="$2"
    local requests="$3"

    python3 -c '
import os, re, sys, tempfile

path, children, requests = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

def set_key(lines, key, value):
    pat = re.compile(r"^(\s*)" + re.escape(key) + r"\s*:")
    out = []
    done = False
    for line in lines:
        if pat.match(line) and not done:
            indent = pat.match(line).group(1)
            out.append(f"{indent}{key}: {value}\n")
            done = True
        else:
            out.append(line)
    if not done:
        pos = None
        for idx, line in enumerate(out):
            if re.match(r"^\s*_is_present\s*:", line):
                pos = idx + 1
                break
        if pos is None:
            pos = 1 if out and out[0].strip() == "---" else 0
        out.insert(pos, f"{key}: {value}\n")
    return out

if not lines or lines[0].strip() != "---":
    lines.insert(0, "---\n")

lines = set_key(lines, "pm_max_children", children)
lines = set_key(lines, "pm_max_requests", requests)

fd, tmp = tempfile.mkstemp(prefix=".phpfpm.", dir=os.path.dirname(path), text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(lines)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        try: os.unlink(tmp)
        except: pass
' "$yaml" "$children" "$requests" </dev/null
}

rollback_yamls() {
    echo
    echo -e "${RED}!!! ROLLBACK AUTOMÁTICO DE CONFIGURACIÓN YAML !!!${RESET}"
    tail -n +2 "$CHANGED_LIST" | while IFS=$'\t' read -r dom yaml backup _ _ _ _; do
        if [ -f "$backup" ]; then
            cp -a "$backup" "$yaml"
            echo "  Restaurado $dom -> $yaml"
        fi
    done
    /usr/local/cpanel/scripts/php_fpm_config --rebuild </dev/null >/dev/null 2>&1 || true
    /usr/local/cpanel/scripts/restartsrv_apache_php_fpm --hard </dev/null >/dev/null 2>&1 || true
    /usr/local/cpanel/scripts/restartsrv_httpd --hard </dev/null >/dev/null 2>&1 || true
    log "Rollback de YAMLs completado."
}

# Modificar únicamente dominios marcados como SAFE_TO_APPLY
tail -n +2 "$RECS_FILE" | while IFS=$'\t' read -r dom phpver yaml ptype conf msrc tdata cc raw_rec guard_rec final_ch cr rr workers mem peak htt hits est eligibility reason; do
    [ "$dom" = "domain" ] && continue
    [ "$yaml" != "MISSING" ] || continue

    if [[ "$eligibility" != "SAFE_TO_APPLY" ]]; then
        echo -e "${YELLOW}OMITIDO${RESET} $dom (Elegibilidad: $eligibility - preservado)."
        continue
    fi

    if [ "$cc" = "$final_ch" ] && [ "$cr" = "$rr" ]; then
        echo -e "${GREEN}OMITIDO${RESET} $dom (ya coincide con la recomendación)."
        continue
    fi

    rel_name=$(echo "$yaml" | sed 's#/#_#g')
    backup="$WORKDIR/yaml_backups/${rel_name}"
    cp -a "$yaml" "$backup" || die "No se pudo respaldar $yaml"

    update_yaml "$yaml" "$final_ch" "$rr" || {
        echo "Error editando $yaml. Iniciando rollback."
        rollback_yamls
        exit 1
    }

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$dom" "$yaml" "$backup" "$cc" "$final_ch" "$cr" "$rr" >> "$CHANGED_LIST"
    echo -e "${GREEN}APLICADO${RESET} $dom: max_children $cc -> $final_ch | max_requests $cr -> $rr"
    log "$dom | TUNED | children: $cc->$final_ch | requests: $cr->$rr"
done

CHANGED_COUNT=$(( $(wc -l < "$CHANGED_LIST") - 1 ))

if [ "$CHANGED_COUNT" -gt 0 ]; then
    echo
    echo "Ejecutando cPanel php_fpm_config --rebuild..."
    if ! /usr/local/cpanel/scripts/php_fpm_config --rebuild </dev/null >> "$LOG_FILE" 2>&1; then
        echo -e "${RED}ERROR: php_fpm_config --rebuild falló.${RESET}"
        rollback_yamls
        exit 1
    fi

    echo "Reiniciando Apache PHP-FPM..."
    if ! /usr/local/cpanel/scripts/restartsrv_apache_php_fpm --hard </dev/null >> "$LOG_FILE" 2>&1; then
        echo -e "${RED}ERROR: fallo reinicio de Apache PHP-FPM.${RESET}"
        rollback_yamls
        exit 1
    fi

    echo "Reiniciando Apache Web Server..."
    if ! /usr/local/cpanel/scripts/restartsrv_httpd --hard </dev/null >> "$LOG_FILE" 2>&1; then
        echo -e "${RED}ERROR: fallo reinicio de Apache.${RESET}"
        rollback_yamls
        exit 1
    fi
fi

# Verification post-rebuild
stage "17" "18" "Verificación post-rebuild..."

VERIFY_FAIL=0
tail -n +2 "$CHANGED_LIST" | while IFS=$'\t' read -r dom yaml backup prev_c new_c prev_r new_r; do
    phpver=$(awk -F'\t' -v d="$dom" '$1==d {print $2}' "$POOLS_FILE")
    conf="/opt/cpanel/${phpver}/root/etc/php-fpm.d/${dom}.conf"

    if [ ! -f "$conf" ]; then
        echo -e "${RED}FAIL${RESET} $dom: no existe el archivo generado $conf"
        VERIFY_FAIL=1
        continue
    fi

    got_c=$(awk -F= '/^[[:space:]]*pm\.max_children[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2);print $2;exit}' "$conf")
    got_r=$(awk -F= '/^[[:space:]]*pm\.max_requests[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2);print $2;exit}' "$conf")

    if [ "$got_c" = "$new_c" ] && [ "$got_r" = "$new_r" ]; then
        echo -e "${GREEN}VERIFICADO${RESET} $dom: pm.max_children=$got_c | pm.max_requests=$got_r"
    else
        echo -e "${RED}FAIL${RESET} $dom: generado children=${got_c:-?} requests=${got_r:-?} | esperado children=$new_c requests=$new_r"
        VERIFY_FAIL=1
    fi
done

if [ "$VERIFY_FAIL" -eq 1 ]; then
    echo -e "${RED}Fallo en la verificación post-rebuild. Ejecutando rollback...${RESET}"
    rollback_yamls
    exit 1
fi

# ============================================================
# ETAPA 18: REPORTE FINAL
# ============================================================

stage "18" "18" "REPORTE FINAL Y RESUMEN DE EJECUCIÓN"

# Generar CSV final unificado
python3 -c '
import sys, csv

domains_file, recs_file, changed_file, compare_file, csv_out = sys.argv[1:6]

recs = {}
try:
    with open(recs_file) as f:
        for r in csv.DictReader(f, delimiter="\t"):
            recs[r["domain"]] = r
except Exception: pass

changed = {}
try:
    with open(changed_file) as f:
        for r in csv.DictReader(f, delimiter="\t"):
            changed[r["domain"]] = r
except Exception: pass

compare = {}
try:
    with open(compare_file) as f:
        for r in csv.DictReader(f, delimiter="\t"):
            compare[r["domain"]] = r["status"]
except Exception: pass

rows = []
with open(domains_file) as f:
    for line in f:
        parts = line.strip().split("\t")
        if len(parts) < 9: continue
        dom, acc, ver, fpm, src, susp, hand, ypath, pkg = parts
        rc = recs.get(dom, {})
        ch = changed.get(dom, {})
        comp = compare.get(dom, "N/A")

        rows.append([
            dom, acc, ver, "YES" if fpm=="1" else "NO", comp,
            rc.get("current_children", "N/A"), rc.get("final_children", "N/A"),
            rc.get("current_requests", "N/A"), rc.get("recommended_requests", "N/A"),
            rc.get("confidence", "N/A"), rc.get("tuning_eligibility", "N/A"), rc.get("reason", "N/A")
        ])

with open(csv_out, "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["domain", "account", "php_version", "fpm_active", "http_status",
                "cur_children", "final_children", "cur_requests", "rec_requests",
                "data_confidence", "eligibility", "tuning_reason"])
    w.writerows(rows)
' "$DOMAINS_FILE" "$RECS_FILE" "$CHANGED_LIST" "$HTTP_COMPARE_FILE" "$REPORT_CSV" </dev/null

echo
hr
echo -e "${BOLD} RESUMEN FINAL DE LA EJECUCIÓN${RESET}"
echo hr
echo " VirtualHosts analizados    : $TOTAL_VH"
echo " Pools FPM optimizados      : ${CHANGED_COUNT:-0}"
echo " Directorio de reportes     : $WORKDIR"
echo
echo " Archivos clave generados:"
echo "   - Diagnóstico y tuning   : $RECS_FILE"
echo "   - Baseline HTTP inicial  : $HTTP_BEFORE_FILE"
echo "   - Comparativa HTTP       : $HTTP_COMPARE_FILE"
echo "   - Reporte CSV unificado  : $REPORT_CSV"
echo "   - Log detallado          : $LOG_FILE"
echo

PROVISIONAL_POOLS=$(awk -F'\t' '$5=="PROVISIONAL" {print $1}' "$RECS_FILE" 2>/dev/null || true)
if [ -n "$PROVISIONAL_POOLS" ]; then
    echo -e "${YELLOW}AVISO IMPORTANTE DE REEVALUACIÓN:${RESET}"
    echo "Los siguientes pools recién migrados tienen recomendaciones PROVISIONALES (conservadoras):"
    echo "$PROVISIONAL_POOLS" | sed 's/^/  - /'
    echo "Se sugiere volver a ejecutar el optimizador en horario de tráfico representativo."
    echo
fi

hr
echo -e "${GREEN} PROCESO COMPLETADO EXITOSAMENTE${RESET}"
hr
echo
