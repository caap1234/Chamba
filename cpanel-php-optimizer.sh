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
# FORMATO Y COLORES (TTY DEPENDIENTE)
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

# ============================================================
# ETAPA 1: VALIDACIONES DEL SERVIDOR
# ============================================================

stage "1" "18" "Validaciones del servidor..."

[[ $EUID -eq 0 ]] || die "Este script debe ejecutarse como root."

command -v whmapi1 >/dev/null 2>&1 || die "No se encontró 'whmapi1'. ¿Es un servidor cPanel/WHM?"
command -v python3 >/dev/null 2>&1 || die "No se encontró 'python3'."

for cmd in awk sed grep find sort ps curl free nproc date cp rpm; do
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

if ! whmapi1 --output=json php_get_vhost_versions > "$BEFORE_JSON" 2>>"$LOG_FILE"; then
    die "No fue posible ejecutar 'whmapi1 php_get_vhost_versions'."
fi

# Validar respuesta JSON
python3 - "$BEFORE_JSON" <<'PY'
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
PY

[[ $? -eq 0 ]] || die "La respuesta de WHM API php_get_vhost_versions no es válida."

# Parsear handlers globales / por versión PHP
EA4_CONF="/etc/cpanel/ea4/php.conf"

python3 - "$BEFORE_JSON" "$EA4_CONF" > "$DOMAINS_FILE" <<'PY'
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
                handlers_map[k.strip()] = v.strip().strip('"')

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

    # Localizar YAML
    yaml_path = "MISSING"
    if account and domain:
        candidate = f"/var/cpanel/userdata/{account}/{domain}.php-fpm.yaml"
        if os.path.isfile(candidate):
            yaml_path = candidate
        else:
            found = glob.glob(f"/var/cpanel/userdata/*/{domain}.php-fpm.yaml")
            if found:
                yaml_path = found[0]

    # Comprobar paquete FPM instalado
    fpm_bin = f"/opt/cpanel/{version}/root/usr/sbin/php-fpm"
    fpm_pkg_installed = 1 if os.path.isfile(fpm_bin) else 0

    if domain and version:
        print(f"{domain}\t{account}\t{version}\t{fpm}\t{source}\t{suspended}\t{handler}\t{yaml_path}\t{fpm_pkg_installed}")
PY

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
python3 - "$DOMAINS_FILE" "$PATTERNS_FILE" "$MINUTES" "$URLS_FILE" <<'PY'
import sys, os, re, glob
from collections import Counter

domains_file, patterns_file, minutes, urls_file = sys.argv[1:5]

with open(patterns_file) as f:
    patterns = [line.strip() for line in f if line.strip()]

static_exts = ('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
               '.woff', '.woff2', '.ttf', '.map', '.mp4', '.webm', '.pdf', '.zip', '.xml', '.txt')

sensitive_terms = ('token', 'nonce', 'auth', 'login', 'logout', 'session', 'secret',
                   'password', 'key', 'admin', 'cart', 'checkout', 'pay', 'reset')

urls_out = []

with open(domains_file) as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) < 9:
            continue
        domain = parts[0]

        # Encontrar log
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
                with open(logfile, 'r', encoding='utf-8', errors='ignore') as lf:
                    for l in lf:
                        if any(p in l for p in patterns):
                            m = re.search(r'"(GET|HEAD)\s+([^\s]+)', l)
                            if m:
                                method, raw_url = m.groups()
                                path_clean = raw_url.split('#')[0]
                                path_no_q = path_clean.split('?')[0].lower()
                                if path_clean == '/' or path_clean == '':
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
PY

echo "URLs de prueba seguras seleccionadas."
log "URLs de prueba guardadas en $URLS_FILE"

# ============================================================
# ETAPA 4: BASELINE HTTP PRE-MIGRACIÓN
# ============================================================

stage "4" "18" "Obteniendo Baseline HTTP pre-migración..."

printf "domain\tpath\tfull_url\thttp_code\teffective_url\tredirect_count\tttfb_s\ttotal_time_s\ttimestamp\tcurl_result\n" > "$HTTP_BEFORE_FILE"

run_http_test() {
    local domain="$1"
    local path="$2"
    local outfile="$3"

    local full_url="https://${domain}${path}"
    local tmp="$WORKDIR/curl_tmp.$$.txt"

    curl -kLsS \
        --connect-timeout 5 \
        --max-time 20 \
        -o /dev/null \
        -w "%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_starttransfer}\t%{time_total}\n" \
        "$full_url" 2>/dev/null > "$tmp" || echo -e "000\t${full_url}\t0\t0.000\t0.000" > "$tmp"

    local code eff_url redirects ttfb total
    read -r code eff_url redirects ttfb total < "$tmp"
    rm -f "$tmp"

    local result_str="OK"
    if [[ "$code" == "000" ]]; then
        result_str="CONNECT_ERROR"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$domain" "$path" "$full_url" "$code" "$eff_url" "$redirects" "$ttfb" "$total" "$(date '+%F %T')" "$result_str" >> "$outfile"
}

# Ejecutar baseline pre-migración para todos los dominios activos
while IFS=$'\t' read -r DOMAIN PATH; do
    [ -n "$DOMAIN" ] || continue
    run_http_test "$DOMAIN" "$PATH" "$HTTP_BEFORE_FILE"
done < "$URLS_FILE"

echo "Baseline HTTP pre-migración completado."
log "Baseline pre-migración guardado en $HTTP_BEFORE_FILE"

# ============================================================
# ETAPA 5: EVALUACIÓN DE MIGRACIÓN A PHP-FPM
# ============================================================

stage "5" "18" "EVALUACIÓN DE MIGRACIÓN A PHP-FPM"

python3 - "$DOMAINS_FILE" "$HTTP_BEFORE_FILE" "$MIGRATION_CANDIDATES" <<'PY'
import sys, csv
from collections import defaultdict

domains_file, http_file, candidates_file = sys.argv[1:4]

http_summary = defaultdict(list)
with open(http_file) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        http_summary[row["domain"]].append(row["http_code"])

with open(domains_file) as f, open(candidates_file, "w", newline="") as out:
    w = csv.writer(out, delimiter="\t")
    w.writerow(["domain", "account", "version", "fpm", "source", "suspended", "handler", "yaml", "fpm_pkg_installed", "category"])

    for line in f:
        parts = line.strip().split("\t")
        if len(parts) < 9:
            continue
        domain, account, version, fpm, source, suspended, handler, yaml_path, fpm_pkg_installed = parts
        fpm = int(fpm)
        suspended = int(suspended)
        fpm_pkg_installed = int(fpm_pkg_installed)

        if suspended:
            cat = "SUSPENDED"
        elif fpm == 1:
            cat = "ALREADY_FPM"
        elif fpm == 0 and fpm_pkg_installed == 1:
            cat = "CAN_ENABLE_FPM"
        elif fpm == 0 and fpm_pkg_installed == 0:
            cat = "NEEDS_FPM_PKG"
        else:
            cat = "SPECIAL"

        w.writerow([domain, account, version, fpm, source, suspended, handler, yaml_path, fpm_pkg_installed, cat])
PY

echo
printf "%-32s %-12s %-10s %-10s %-18s %-15s\n" \
    "DOMINIO" "CUENTA" "PHP" "HANDLER" "PAQUETE FPM" "ESTADO FPM"
printf "%-32s %-12s %-10s %-10s %-18s %-15s\n" \
    "--------------------------------" "------------" "----------" "----------" "------------------" "---------------"

while IFS=$'\t' read -r DOMAIN ACCOUNT VERSION FPM SOURCE SUSPENDED HANDLER YAML PKG_INST CAT; do
    [ "$DOMAIN" = "domain" ] && continue
    PKG_NAME="${VERSION}-php-fpm"

    if [[ "$CAT" == "ALREADY_FPM" ]]; then
        STATUS_TEXT="${GREEN}FPM ACTIVO${RESET}"
    elif [[ "$CAT" == "CAN_ENABLE_FPM" ]]; then
        STATUS_TEXT="${YELLOW}LISTO PARA MIGRAR${RESET}"
    elif [[ "$CAT" == "NEEDS_FPM_PKG" ]]; then
        STATUS_TEXT="${RED}FALTA PAQUETE${RESET}"
    elif [[ "$CAT" == "SUSPENDED" ]]; then
        STATUS_TEXT="${YELLOW}SUSPENDIDO${RESET}"
    else
        STATUS_TEXT="ESPECIAL"
    fi

    PKG_TEXT="INSTALADO"
    [[ "$PKG_INST" == "0" ]] && PKG_TEXT="${RED}NO INSTALADO${RESET}"

    printf "%-32s %-12s %-10s %-10s %-18s %-15s\n" \
        "$DOMAIN" "$ACCOUNT" "$VERSION" "$HANDLER" "$PKG_NAME" "$STATUS_TEXT"
done < "$MIGRATION_CANDIDATES"

echo

CAN_MIGRATE_COUNT=$(awk -F'\t' '$10=="CAN_ENABLE_FPM" {c++} END {print c+0}' "$MIGRATION_CANDIDATES")
NEEDS_PKG_COUNT=$(awk -F'\t' '$10=="NEEDS_FPM_PKG" {c++} END {print c+0}' "$MIGRATION_CANDIDATES")

ENABLE_MIGRATION=0

if [[ "$CAN_MIGRATE_COUNT" -gt 0 || "$NEEDS_PKG_COUNT" -gt 0 ]]; then
    echo -e "${YELLOW}Se detectaron dominios que actualmente no utilizan PHP-FPM.${RESET}"
    read -r -p "¿Deseas habilitar PHP-FPM en los dominios compatibles que actualmente no lo utilizan? [y/N]: " CONFIRM_MIG
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
    MISSING_PKGS=$(awk -F'\t' '$10=="NEEDS_FPM_PKG" {print $3"-php-fpm"}' "$MIGRATION_CANDIDATES" | sort -u)

    echo
    echo -e "${YELLOW}Los siguientes paquetes son necesarios para activar PHP-FPM:${RESET}"
    for pkg in $MISSING_PKGS; do
        echo "  - $pkg"
    done
    echo

    read -r -p "¿Deseas instalar estos paquetes mediante EasyApache/YUM/DNF? [y/N]: " CONFIRM_PKG
    case "$CONFIRM_PKG" in
        y|Y|yes|YES)
            echo "Instalando paquetes FPM faltantes..."
            log "Instalando paquetes: $MISSING_PKGS"
            if yum install -y $MISSING_PKGS >> "$LOG_FILE" 2>&1; then
                echo -e "${GREEN}Paquetes instalados correctamente.${RESET}"
                INSTALLED_NEW_PKGS=1
                # Actualizar candidates
                python3 - "$MIGRATION_CANDIDATES" <<'PY'
import sys, os, csv

candidates_file = sys.argv[1]
rows = []
with open(candidates_file) as f:
    r = csv.DictReader(f, delimiter="\t")
    for row in r:
        fpm_bin = f"/opt/cpanel/{row['version']}/root/usr/sbin/php-fpm"
        if os.path.isfile(fpm_bin):
            row['fpm_pkg_installed'] = '1'
            if row['category'] == 'NEEDS_FPM_PKG':
                row['category'] = 'CAN_ENABLE_FPM'
        rows.append(row)

with open(candidates_file, "w", newline="") as out:
    w = csv.DictWriter(out, fieldnames=list(rows[0].keys()), delimiter="\t")
    w.writeheader()
    w.writerows(rows)
PY
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
        [ "$DOMAIN" = "domain" ] && continue

        if [[ "$CAT" != "CAN_ENABLE_FPM" ]]; then
            continue
        fi

        if [[ "$GLOBAL_ABORT" == "1" ]]; then
            echo -e "${YELLOW}OMITIDO $DOMAIN (Global Abort activado por regresiones previas).${RESET}"
            log "$DOMAIN | SKIPPED | Global Abort"
            continue
        fi

        echo -e "${BLUE}Procesando migración:${RESET} $DOMAIN ($VERSION)"
        log "$DOMAIN | Activando FPM | version=$VERSION | source=$SOURCE"

        # 1. Invocación WHM API
        RESULT="$(whmapi1 --output=json php_set_vhost_versions version="$VERSION" vhost="$DOMAIN" php_fpm=1 2>&1)"
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
            log "$DOMAIN | FAILED API"
            continue
        fi

        # 2. Re-verificar pruebas HTTP post migración para este dominio
        DOMAIN_URLS=$(grep "^${DOMAIN}"$'\t' "$URLS_FILE" || true)

        HAS_REGRESSION=0

        while IFS=$'\t' read -r _ DOM_PATH; do
            [ -n "$DOM_PATH" ] || continue
            run_http_test "$DOMAIN" "$DOM_PATH" "$HTTP_AFTER_FILE"

            # Comparar pre vs post para esta URL
            python3 - "$HTTP_BEFORE_FILE" "$HTTP_AFTER_FILE" "$DOMAIN" "$DOM_PATH" "$HTTP_COMPARE_FILE" <<'PY'
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
    w = csv.writer(out, delimiter="\t")
    w.writerow([domain, b_code, a_code, status, f"path={path}"])

if status == "REGRESSION_CRITICAL":
    sys.exit(2)
PY
            RC=$?
            if [[ $RC -eq 2 ]]; then
                HAS_REGRESSION=1
            fi
        done <<< "$DOMAIN_URLS"

        if [[ "$HAS_REGRESSION" == "1" ]]; then
            echo -e "  Estado: ${RED}[REGRESSION_CRITICAL] Se detectó regresión HTTP.${RESET}"
            log "$DOMAIN | REGRESSION_CRITICAL | Realizando rollback de FPM..."

            # Rollback unitario
            whmapi1 --output=json php_set_vhost_versions version="$VERSION" vhost="$DOMAIN" php_fpm=0 >> "$LOG_FILE" 2>&1
            echo -e "  Rollback: ${YELLOW}PHP-FPM desactivado para $DOMAIN (versión $VERSION preservada).${RESET}"
            log "$DOMAIN | ROLLED_BACK"

            ((CONSECUTIVE_REGRESSIONS++))

            if [[ "$CONSECUTIVE_REGRESSIONS" -ge "$MAX_CONSECUTIVE_REGRESSIONS" ]]; then
                echo -e "${RED}[GLOBAL_ABORT] Se detectaron $CONSECUTIVE_REGRESSIONS regresiones consecutivas. Deteniendo nuevas migraciones.${RESET}"
                log "GLOBAL_ABORT disparado a las $CONSECUTIVE_REGRESSIONS regresiones."
                GLOBAL_ABORT=1
            fi
        else
            echo -e "  Estado: ${GREEN}[OK] PHP-FPM activado y validado sin regresiones.${RESET}"
            log "$DOMAIN | SUCCESS FPM"
            CONSECUTIVE_REGRESSIONS=0
        fi

        echo
    done < "$MIGRATION_CANDIDATES"
fi

# ============================================================
# ETAPA 9: SNAPSHOT POST-MIGRACIÓN
# ============================================================

stage "9" "18" "Obteniendo snapshot final post-migración..."

if ! whmapi1 --output=json php_get_vhost_versions > "$AFTER_MIGRATION_JSON" 2>>"$LOG_FILE"; then
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
while IFS=$'\t' read -r DOMAIN PATH; do
    curl -kLsS --connect-timeout 2 --max-time 3 "https://${DOMAIN}${PATH}" >/dev/null 2>&1 || true
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

# Tráfico recente por pool
printf "domain\ttotal\tdynamic\tavg_dyn_rpm\tpeak_dyn_rpm\terrors\n" > "$TRAFFIC_FILE"

tail -n +2 "$POOLS_FILE" | cut -f1 | while read -r domain; do
    logfile=""
    for candidate in \
        "/var/log/nginx/domains/$domain" \
        "/var/log/nginx/domains/${domain}.log" \
        "/etc/apache2/logs/domlogs/$domain" \
        "/usr/local/apache/domlogs/$domain"; do
        [ -f "$candidate" ] && { logfile="$candidate"; break; }
    done

    if [ -n "$logfile" ]; then
        tmp="$WORKDIR/log.$$.tmp"
        grep -Ff "$PATTERNS_FILE" "$logfile" 2>/dev/null > "$tmp" || true
        total_reqs=$(wc -l < "$tmp")

        if [ "$total_reqs" -eq 0 ]; then
            printf "%s\t0\t0\t0\t0\t0\n" "$domain"
        else
            awk -v d="$domain" -v mins="$MINUTES" -F'"' '
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
                printf "%s\t%d\t%d\t%.2f\t%d\t%d\n",
                       d, NR, dyn+0, (dyn+0)/mins, peak+0, err+0
            }' "$tmp"
        fi
        rm -f "$tmp"
    else
        printf "%s\t0\t0\t0\t0\t0\n" "$domain"
    fi
done >> "$TRAFFIC_FILE"

# HTTP performance metrics (resumido de baseline)
printf "domain\thttp_ok\tavg_total_s\tmax_total_s\tavg_ttfb_s\n" > "$HTTP_PERF_FILE"

python3 - "$HTTP_BEFORE_FILE" "$HTTP_PERF_FILE" <<'PY'
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
    w = csv.writer(out, delimiter="\t")
    w.writerow(["domain", "http_ok", "avg_total_s", "max_total_s", "avg_ttfb_s"])

    for dom, vals in metrics.items():
        ok_count = len(vals)
        avg_tot = sum(v[1] for v in vals) / ok_count
        max_tot = max(v[1] for v in vals)
        avg_ttfb = sum(v[2] for v in vals) / ok_count
        w.writerow([dom, ok_count, f"{avg_tot:.3f}", f"{max_tot:.3f}", f"{avg_ttfb:.3f}"])
PY

# Merge de todas las métricas
python3 - "$POOLS_FILE" "$MEMORY_FILE" "$TRAFFIC_FILE" "$HTTP_PERF_FILE" "$HITS_FILE" "$MERGED_FILE" <<'PY'
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
    "dynamic","avg_dyn_rpm","peak_dyn_rpm","errors",
    "http_ok","avg_total_s","max_total_s","avg_ttfb_s",
    "hits_max_children"
]

with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fields, delimiter="\t")
    w.writeheader()
    for domain, p in sorted(pools.items()):
        row = {"domain": domain}
        for src in (p, memory.get(domain,{}), traffic.get(domain,{}),
                    http.get(domain,{}), hits.get(domain,{})):
            row.update(src)
        w.writerow({k: row.get(k, "0") for k in fields})
PY

# ============================================================
# ETAPA 13: CÁLCULO DE RECOMENDACIONES DE OPTIMIZACIÓN
# ============================================================

stage "13" "18" "Calculando recomendaciones inteligentes (pm.max_children y pm.max_requests)..."

python3 - "$SYSTEM_ENV" "$MERGED_FILE" "$RECS_FILE" <<'PY'
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
    reasons_global.append("swap alta")
if load_ratio > 1.50:
    pressure *= 0.85
    reasons_global.append("load alto")
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

# Calcular mediana de RAM medida en el servidor como fallback conservador
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
    dynamic = num(r, "dynamic")
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

    desired = int(math.ceil(demand))

    # Límite conservador para pools recién creados
    if pool_type == "NEW_FPM_POOL":
        desired = min(desired, 4)

    desired = max(i("IDLE_MIN_CHILDREN") if dynamic == 0 else i("ACTIVE_MIN_CHILDREN"), desired)
    desired = min(i("MAX_CHILDREN_HARD"), desired)

    r["_mem_ref"] = mem_ref
    r["_desired"] = desired
    r["_dynamic"] = dynamic

base_children = {}
base_cost = 0.0
for idx, r in enumerate(rows):
    base = i("ACTIVE_MIN_CHILDREN") if r["_dynamic"] > 0 else i("IDLE_MIN_CHILDREN")
    base = min(base, r["_desired"])
    base_children[idx] = base
    base_cost += base * r["_mem_ref"]

allocated = dict(base_children)
remaining = php_budget - base_cost

budget_insufficient = remaining < 0
if budget_insufficient:
    allocated = {idx: 1 for idx, _ in enumerate(rows)}
    remaining = php_budget - sum(r["_mem_ref"] for r in rows)

while remaining > 0:
    candidates = []
    for idx, r in enumerate(rows):
        cur = allocated[idx]
        if cur >= r["_desired"]:
            continue
        mem = r["_mem_ref"]
        if mem > remaining:
            continue

        peak = num(r, "peak_dyn_rpm")
        hits = num(r, "hits_max_children")
        workers = num(r, "workers")
        need = max(0.0, r["_desired"] - cur)
        priority = (
            need * 4.0 +
            min(10.0, peak / 10.0) +
            min(8.0, math.log10(hits + 1) * 3.0) +
            min(5.0, workers)
        ) / mem
        candidates.append((priority, idx))

    if not candidates:
        break
    _, idx = max(candidates)
    allocated[idx] += 1
    remaining -= rows[idx]["_mem_ref"]

cpu_soft_pool_cap = max(3, int(cpu * 3))

out_fields = [
    "domain", "phpver", "yaml", "pool_type", "confidence", "mem_source",
    "current_children", "recommended_children",
    "current_requests", "recommended_requests",
    "workers", "mem_ref_mb", "peak_dyn_rpm", "avg_total_s",
    "hits_max_children", "estimated_pool_max_mb", "reason"
]

with open(out_path, "w", newline="") as f:
    w = csv.DictWriter(f, out_fields, delimiter="\t")
    w.writeheader()

    for idx, r in enumerate(rows):
        rec = allocated[idx]
        if r["_desired"] > cpu_soft_pool_cap and num(r, "hits_max_children") == 0:
            rec = min(rec, cpu_soft_pool_cap)

        rec = max(1, min(i("MAX_CHILDREN_HARD"), int(rec)))

        mem = r["_mem_ref"]
        avg = num(r, "avg_mb")
        maxm = num(r, "max_mb")
        variability = (maxm / avg) if avg > 0 else 1.0

        if r.get("confidence") == "PROVISIONAL" or num(r, "workers") == 0:
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

        reasons = []
        if r.get("pool_type") == "NEW_FPM_POOL":
            reasons.append("pool recién migrado (recomendación provisional conservadora)")
        if num(r, "hits_max_children") > 0:
            reasons.append("alcanzó max_children")
        if num(r, "peak_dyn_rpm") > 0:
            reasons.append("pico %.0f dyn/min" % num(r, "peak_dyn_rpm"))
        if num(r, "avg_total_s") >= 2:
            reasons.append("HTTP lento %.2fs" % num(r, "avg_total_s"))
        if mem >= 128:
            reasons.append("worker pesado %.0fMB" % mem)
        if num(r, "dynamic") == 0:
            reasons.append("sin tráfico dinámico reciente")
        if budget_insufficient:
            reasons.append("RAM global insuficiente para mínimos")
        if not reasons:
            reasons.append("demanda/memoria observada")

        w.writerow({
            "domain": r["domain"],
            "phpver": r["phpver"],
            "yaml": r["yaml"],
            "pool_type": r.get("pool_type", "EXISTING_FPM"),
            "confidence": r.get("confidence", "HIGH"),
            "mem_source": r.get("mem_source", "MEASURED"),
            "current_children": int(num(r, "current_children")),
            "recommended_children": rec,
            "current_requests": int(num(r, "current_requests")),
            "recommended_requests": maxreq,
            "workers": int(num(r, "workers")),
            "mem_ref_mb": "%.1f" % mem,
            "peak_dyn_rpm": "%.1f" % num(r, "peak_dyn_rpm"),
            "avg_total_s": "%.3f" % num(r, "avg_total_s"),
            "hits_max_children": int(num(r, "hits_max_children")),
            "estimated_pool_max_mb": "%.1f" % (rec * mem),
            "reason": "; ".join(reasons)
        })
PY

# ============================================================
# ETAPA 14: PRESENTACIÓN Y CONFIRMACIÓN DE TUNING
# ============================================================

stage "14" "18" "RECOMENDACIONES DE OPTIMIZACIÓN DE POOLS"

echo
printf "%-32s %-12s %-12s %-6s %-6s %-6s %-6s %-7s %-8s %-6s\n" \
    "DOMINIO" "TIPO POOL" "CONFIANZA" "CUR_CH" "REC_CH" "CUR_RQ" "REC_RQ" "WORKERS" "MEM_MB" "HITS"
printf "%-32s %-12s %-12s %-6s %-6s %-6s %-6s %-7s %-8s %-6s\n" \
    "--------------------------------" "------------" "------------" "------" "------" "------" "------" "-------" "--------" "------"

tail -n +2 "$RECS_FILE" | while IFS=$'\t' read -r dom phpver yaml ptype conf msrc cc rc cr rr workers mem peak htt hits est reason; do
    printf "%-32s %-12s %-12s %-6s %-6s %-6s %-6s %-7s %-8s %-6s\n" \
        "$dom" "$ptype" "$conf" "$cc" "$rc" "$cr" "$rr" "$workers" "$mem" "$hits"
done

echo
echo "Detalle de motivos por dominio:"
tail -n +2 "$RECS_FILE" | while IFS=$'\t' read -r dom phpver yaml ptype conf msrc cc rc cr rr workers mem peak htt hits est reason; do
    echo "  - $dom: $reason"
done

echo
MISSING_YAMLS=$(awk -F'\t' 'NR>1 && $3=="MISSING" {print $1}' "$RECS_FILE")
if [ -n "$MISSING_YAMLS" ]; then
    echo -e "${YELLOW}ADVERTENCIA: No se encontró YAML para los siguientes dominios (se omitirán):${RESET}"
    echo "$MISSING_YAMLS" | sed 's/^/  - /'
    echo
fi

echo -e "${YELLOW}INFORMACIÓN DE APLICACIÓN:${RESET}"
echo "  1) Se respaldará cada YAML en $WORKDIR/yaml_backups/"
echo "  2) Se modificarán ÚNICAMENTE pm_max_children y pm_max_requests en /var/cpanel/userdata/"
echo "  3) Se ejecutará /usr/local/cpanel/scripts/php_fpm_config --rebuild"
echo "  4) Se reiniciarán Apache PHP-FPM y HTTPD"
echo "  5) Se verificará la coincidencia en los .conf generados"
echo "  6) Si ocurre algún fallo, se aplicará ROLLBACK AUTOMÁTICO"
echo

read -r -p "Escribe APLICAR para confirmar los cambios de tuning, o cualquier otra cosa para salir: " CONFIRM_TUNING

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

    python3 - "$yaml" "$children" "$requests" <<'PY'
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
PY
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
    /usr/local/cpanel/scripts/php_fpm_config --rebuild >/dev/null 2>&1 || true
    /usr/local/cpanel/scripts/restartsrv_apache_php_fpm --hard >/dev/null 2>&1 || true
    /usr/local/cpanel/scripts/restartsrv_httpd --hard >/dev/null 2>&1 || true
    log "Rollback de YAMLs completado."
}

while IFS=$'\t' read -r dom phpver yaml ptype conf msrc cc rc cr rr workers mem peak htt hits est reason; do
    [ "$dom" = "domain" ] && continue
    [ "$yaml" != "MISSING" ] || continue

    if [ "$cc" = "$rc" ] && [ "$cr" = "$rr" ]; then
        echo -e "${GREEN}OMITIDO${RESET} $dom (ya coincide con la recomendación)."
        continue
    fi

    rel_name=$(echo "$yaml" | sed 's#/#_#g')
    backup="$WORKDIR/yaml_backups/${rel_name}"
    cp -a "$yaml" "$backup" || die "No se pudo respaldar $yaml"

    update_yaml "$yaml" "$rc" "$rr" || {
        echo "Error editando $yaml. Iniciando rollback."
        rollback_yamls
        exit 1
    }

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$dom" "$yaml" "$backup" "$cc" "$rc" "$cr" "$rr" >> "$CHANGED_LIST"
    echo -e "${GREEN}APLICADO${RESET} $dom: max_children $cc -> $rc | max_requests $cr -> $rr"
    log "$dom | TUNED | children: $cc->$rc | requests: $cr->$rr"
done < "$RECS_FILE"

CHANGED_COUNT=$(( $(wc -l < "$CHANGED_LIST") - 1 ))

if [ "$CHANGED_COUNT" -gt 0 ]; then
    echo
    echo "Ejecutando cPanel php_fpm_config --rebuild..."
    if ! /usr/local/cpanel/scripts/php_fpm_config --rebuild >> "$LOG_FILE" 2>&1; then
        echo -e "${RED}ERROR: php_fpm_config --rebuild falló.${RESET}"
        rollback_yamls
        exit 1
    fi

    echo "Reiniciando Apache PHP-FPM..."
    if ! /usr/local/cpanel/scripts/restartsrv_apache_php_fpm --hard >> "$LOG_FILE" 2>&1; then
        echo -e "${RED}ERROR: fallo reinicio de Apache PHP-FPM.${RESET}"
        rollback_yamls
        exit 1
    fi

    echo "Reiniciando Apache Web Server..."
    if ! /usr/local/cpanel/scripts/restartsrv_httpd --hard >> "$LOG_FILE" 2>&1; then
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
python3 - "$DOMAINS_FILE" "$RECS_FILE" "$CHANGED_LIST" "$HTTP_COMPARE_FILE" "$REPORT_CSV" <<'PY'
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
            rc.get("current_children", "N/A"), rc.get("recommended_children", "N/A"),
            rc.get("current_requests", "N/A"), rc.get("recommended_requests", "N/A"),
            rc.get("confidence", "N/A"), rc.get("reason", "N/A")
        ])

with open(csv_out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["domain", "account", "php_version", "fpm_active", "http_status",
                "cur_children", "rec_children", "cur_requests", "rec_requests",
                "data_confidence", "tuning_reason"])
    w.writerows(rows)
PY

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
