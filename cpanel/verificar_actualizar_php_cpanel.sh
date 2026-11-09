#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

if (( EUID != 0 )); then echo 'ERROR: Ejecutar como root.' >&2; exit 2; fi
if [[ ! -d /usr/local/cpanel ]] || ! command -v dnf >/dev/null 2>&1; then
  echo 'ERROR: Este script requiere cPanel/WHM sobre un sistema con dnf.' >&2; exit 2
fi

LOG="/root/php_security_cpanel_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

declare -A MIN=( [82]=8.2.35 [83]=8.3.36 [84]=8.4.27 [85]=8.5.12 )
declare -A BACKPORT_DESC=(
  [74]="7.4.34 (cPanel) - Corregida mediante backport"
  [80]="8.0.30 + parche EA4 - Corregida mediante backport"
  [81]="8.1.34 + parche EA4 - Corregida mediante backport"
)

needs=() installed=() failed=0

version_of() {
  local bin="/opt/cpanel/ea-php${1}/root/usr/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

has_dnf_update() {
  local b="$1"
  local code=0
  dnf check-update -q "ea-php${b}*" >/dev/null 2>&1 || code=$?
  if (( code == 100 )); then
    return 0 # Hay actualización pendiente en los repositorios
  fi
  return 1
}

is_cpanel_backported() {
  local b="$1"
  local pkg="ea-php${b}-php-cli"

  # Si dnf reporta actualización pendiente para este ea-php, no está al día
  if has_dnf_update "$b"; then
    return 1
  fi

  # Comprobar si el changelog de RPM incluye el parche de seguridad de EA4 / CVEs
  if rpm -q --changelog "$pkg" 2>/dev/null | head -n 45 | grep -Eiq 'CVE-2026-|EA-13613|CVE-2024-|backport|parche'; then
    return 0
  fi

  # Comprobación de versión específica
  local v
  v=$(version_of "$b" 2>/dev/null || echo "")
  case "$b" in
    74) meets "$v" "7.4.34" && return 0 ;;
    80) meets "$v" "8.0.30" && rpm -q --changelog "$pkg" 2>/dev/null | head -n 30 | grep -Eiq 'CVE|EA' && return 0 ;;
    81) meets "$v" "8.1.34" && return 0 ;;
  esac

  return 1
}

if rpm -qa --qf '%{NAME}\n' | grep -q '^alt-php'; then
  echo 'AVISO: Detectado alt-php (CloudLinux). Este script NO actualiza alt-php.'
fi

echo '===== ESTADO INICIAL ====='
for b in 74 80 81 82 83 84 85; do
  if rpm -q "ea-php${b}-php-cli" >/dev/null 2>&1; then
    installed+=("$b")
    v=$(version_of "$b") || v='NO DISPONIBLE'

    if [[ "$b" =~ ^(74|80|81)$ ]]; then
      if [[ "$v" != 'NO DISPONIBLE' ]] && is_cpanel_backported "$b"; then
        echo "ea-php$b: $v - CUMPLE (${BACKPORT_DESC[$b]})"
      else
        echo "ea-php$b: $v - ACTUALIZACION REQUERIDA (Pendiente backport cPanel)"
        needs+=("$b")
      fi
    else
      # Ramas 8.2, 8.3, 8.4, 8.5
      if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$b]}"; then
        echo "ea-php$b: $v - CUMPLE (min ${MIN[$b]} - Corregida)"
      else
        echo "ea-php$b: $v - ACTUALIZACION REQUERIDA (min ${MIN[$b]})"
        needs+=("$b")
      fi
    fi
  else
    echo "ea-php$b: no instalado (omitido)"
  fi
done

legacy=$(rpm -qa --qf '%{NAME}\n' | grep -E '^ea-php(5[0-9]|7[0-3])-php-cli$' || true)
[[ -z "$legacy" ]] || printf 'AVISO: ramas EOL sin parche oficial detectadas:\n%s\n' "$legacy"

if (( ${#needs[@]} )); then
  patterns=()
  for b in "${needs[@]}"; do patterns+=("ea-php${b}*"); done
  echo "===== ACTUALIZANDO MEDIANTE DNF: ${needs[*]} ====="
  if ! dnf upgrade -y --refresh "${patterns[@]}"; then
    echo 'ERROR: dnf reportó un fallo en la actualización.'
    failed=1
  else
    if [[ -x /scripts/restartsrv_apache_php_fpm ]]; then
      echo 'Reiniciando servicios PHP-FPM de EasyApache 4...'
      /scripts/restartsrv_apache_php_fpm >/dev/null 2>&1 || true
    fi
  fi
else
  echo 'Todas las ramas instaladas (7.4 a 8.5) cumplen con los parches de seguridad; no se modifica nada.'
fi

echo '===== VALIDACION FINAL ====='
for b in "${installed[@]}"; do
  v=$(version_of "$b") || v='NO DISPONIBLE'
  if [[ "$b" =~ ^(74|80|81)$ ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && is_cpanel_backported "$b"; then
      echo "OK ea-php$b: $v - CUMPLE (${BACKPORT_DESC[$b]})"
    else
      echo "FALLO ea-php$b: $v (Requiere actualización backport de cPanel)"
      failed=1
    fi
  else
    if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$b]}"; then
      echo "OK ea-php$b: $v >= ${MIN[$b]} - CUMPLE (Corregida)"
    else
      echo "FALLO ea-php$b: $v < ${MIN[$b]} (o binario no disponible)"
      failed=1
    fi
  fi
done

if (( ${#installed[@]} == 0 )); then
  echo 'AVISO: no se encontraron ramas ea-php 7.4 a 8.5 instaladas.'
fi

printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
