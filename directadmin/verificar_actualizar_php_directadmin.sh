#!/usr/bin/env bash
# ==============================================================================
# Script: verificar_actualizar_php_directadmin.sh
# Proposito: Auditoria y compilacion/actualizacion de seguridad de PHP en DirectAdmin
#            utilizando CustomBuild (ramas 8.1 en adelante, 8.2-8.5 y 7.4/8.0).
# Boletin de Seguridad: 18 de Noviembre de 2026
# CVEs: CVE-2026-129289 (PHP-FPM Request Smuggling RCE), CVE-2026-126714, CVE-2026-115560
# Compatibilidad: CentOS 7, AlmaLinux, Rocky Linux, RHEL, Debian, Ubuntu
#                 (con python3, python2.7, python o utilidades del sistema)
# ==============================================================================
set -uo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/local/directadmin:$PATH"

if (( EUID != 0 )); then echo 'ERROR: Ejecutar como root.' >&2; exit 2; fi

FORCE=0
if [[ "${1:-}" =~ ^(-f|--force)$ ]]; then
  FORCE=1
fi

CONF=/usr/local/directadmin/custombuild/options.conf
CB_DIR=/usr/local/directadmin/custombuild

if [[ ! -f "$CONF" ]]; then
  echo 'ERROR: No se detecto DirectAdmin/CustomBuild (options.conf no existe).' >&2
  exit 2
fi

if [[ -f "$CB_DIR/build" && ! -x "$CB_DIR/build" ]]; then
  chmod +x "$CB_DIR/build" 2>/dev/null || true
fi

run_cb() {
  if [[ -x "$CB_DIR/build" ]]; then
    (cd "$CB_DIR" && ./build "$@")
  elif command -v da >/dev/null 2>&1 && da build --help >/dev/null 2>&1; then
    da build "$@"
  else
    echo 'ERROR: No se encontro CustomBuild (/usr/local/directadmin/custombuild/build).' >&2
    return 1
  fi
}

LOG="/root/php_security_directadmin_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

# Versiones minimas oficiales corregidas tras el lanzamiento de seguridad del 18 de Noviembre de 2026
declare -A MIN=( ["8.2"]="8.2.36" ["8.3"]="8.3.37" ["8.4"]="8.4.28" ["8.5"]="8.5.13" )
declare -A BACKPORT=( ["7.4"]="Parche de CustomBuild" ["8.0"]="Parche de CustomBuild" ["8.1"]="Parche de CustomBuild (Nov 18, 2026)" )

branches=() needs=0 failed=0

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

version_of() {
  local bin="/usr/local/php${1/./}/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

parse_date_to_epoch() {
  local datestr="$1"
  local epoch=""

  # 1. GNU date nativo (presente en CentOS, AlmaLinux, Rocky, RHEL, Debian, Ubuntu)
  epoch=$(date -d "$datestr" +%s 2>/dev/null || true)
  if [[ -n "$epoch" && "$epoch" =~ ^[0-9]+$ ]]; then
    echo "$epoch"
    return 0
  fi

  # 2. Python fallback (detecta python3, python, python2, python2.7, python2.8)
  # Usa time.mktime y time.strptime, 100% compatible con Python 2 y Python 3
  for py in python3 python python2 python2.7 python2.8; do
    if command -v "$py" >/dev/null 2>&1; then
      epoch=$("$py" -c "import time, sys; print(int(time.mktime(time.strptime(sys.argv[1].strip(), '%b %d %Y %H:%M:%S'))))" "$datestr" 2>/dev/null || echo "")
      if [[ -n "$epoch" && "$epoch" =~ ^[0-9]+$ ]]; then
        echo "$epoch"
        return 0
      fi
    fi
  done

  # 3. Fallback en Awk gawk
  epoch=$(awk -v d="$datestr" 'BEGIN {
    split(d, a, " ");
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ");
    for (i=1; i<=12; i++) mon[m[i]] = i;
    split(a[4], t, ":");
    spec = sprintf("%04d %02d %02d %02d %02d %02d", a[3], mon[a[1]], a[2], t[1], t[2], t[3]);
    ep = mktime(spec);
    if (ep > 0) print ep;
  }' 2>/dev/null || true)
  if [[ -n "$epoch" && "$epoch" =~ ^[0-9]+$ ]]; then
    echo "$epoch"
    return 0
  fi

  echo 0
}

is_da_backported() {
  local branch="$1"
  local bin="/usr/local/php${branch/./}/bin/php"
  [[ -x "$bin" ]] || return 1

  # Extraer fecha de compilacion reportada por el binario
  local built_str
  built_str=$("$bin" -v 2>/dev/null | grep -o 'built: [^)]*' | sed 's/built: //')
  if [[ -n "$built_str" ]]; then
    local built_epoch cutoff_epoch
    built_epoch=$(parse_date_to_epoch "$built_str")
    # Fecha de corte de parches de seguridad (18 de Noviembre de 2026 00:00:00 UTC)
    cutoff_epoch=$(parse_date_to_epoch "Nov 18 2026 00:00:00")
    if (( cutoff_epoch == 0 )); then
      cutoff_epoch=1794960000
    fi
    if (( built_epoch >= cutoff_epoch )); then
      return 0
    fi
  fi

  return 1
}

echo '===== ESTADO INICIAL ====='
for slot in 1 2 3 4; do
  branch=$(sed -n "s/^php${slot}_release=//p" "$CONF" | tail -n1 | tr -d '\r')
  [[ -z "$branch" || "$branch" == no ]] && continue
  branches+=("$branch")

  v=$(version_of "$branch") || v='NO DISPONIBLE'

  if [[ -n "${BACKPORT[$branch]:-}" ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && is_da_backported "$branch"; then
      echo "PHP $branch: $v - CUMPLE (Corregida: ${BACKPORT[$branch]})"
    else
      echo "PHP $branch: $v - ACTUALIZACION REQUERIDA (${BACKPORT[$branch]})"
      needs=1
    fi
  elif [[ -n "${MIN[$branch]:-}" ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$branch]}"; then
      echo "PHP $branch: $v - CUMPLE (Corregida: min ${MIN[$branch]})"
    else
      echo "PHP $branch: $v - ACTUALIZACION REQUERIDA (min ${MIN[$branch]})"
      needs=1
    fi
  else
    echo "AVISO: PHP $branch esta configurado; no esta entre las ramas 7.4-8.5 evaluadas."
  fi
done

if (( ${#branches[@]} == 0 )); then
  echo 'ERROR: No se encontraron ramas PHP configuradas en CustomBuild.'
  exit 2
fi

if (( needs || FORCE == 1 )); then
  if (( FORCE == 1 )); then
    echo '===== MODO FORZADO (--force): Recompilando CustomBuild independientemente del estado actual ====='
  fi

  echo '===== LIMPIANDO Y ACTUALIZANDO METADATOS DE CUSTOMBUILD (clean / update) ====='
  run_cb clean >/dev/null 2>&1 || true

  if run_cb update; then
    echo '===== RECOMPILANDO PHP CON CUSTOMBUILD (aplicando versiones y parches) ====='
    if ! run_cb php; then
      echo 'ERROR: CustomBuild reporto un fallo al compilar PHP.'
      failed=1
    else
      echo '===== REESCRIBIENDO CONFIGURACIONES Y REINICIANDO SERVICIOS ====='
      run_cb rewrite_confs >/dev/null 2>&1 || true
    fi
  else
    echo 'ERROR: No se pudo actualizar metadatos de CustomBuild (./build update).'
    failed=1
  fi
else
  echo 'Todas las ramas evaluadas cumplen con los parches de seguridad (November 18, 2026); no se recompila PHP.'
fi

echo '===== VALIDACION FINAL ====='
for branch in "${branches[@]}"; do
  v=$(version_of "$branch") || v='NO DISPONIBLE'
  if [[ -n "${BACKPORT[$branch]:-}" ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && is_da_backported "$branch"; then
      echo "OK PHP $branch: $v - CUMPLE (${BACKPORT[$branch]})"
    else
      echo "FALLO PHP $branch: $v (${BACKPORT[$branch]} no verificado)"
      failed=1
    fi
  elif [[ -n "${MIN[$branch]:-}" ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$branch]}"; then
      echo "OK PHP $branch: $v >= ${MIN[$branch]} - CUMPLE (Corregida)"
    else
      echo "FALLO PHP $branch: $v (minimo ${MIN[$branch]})"
      failed=1
    fi
  fi
done

printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
