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
needs=() installed=() failed=0
version_of() {
  local bin="/opt/cpanel/ea-php${1}/root/usr/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}
meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

if rpm -qa --qf '%{NAME}\n' | grep -q '^alt-php'; then
  echo 'AVISO: Detectado alt-php (CloudLinux). Este script NO actualiza alt-php.'
fi

echo '===== ESTADO INICIAL ====='
for b in 82 83 84 85; do
  if rpm -q "ea-php${b}-php-cli" >/dev/null 2>&1; then
    installed+=("$b")
    v=$(version_of "$b") || v='NO DISPONIBLE'
    if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$b]}"; then
      echo "ea-php$b: $v - CUMPLE (min ${MIN[$b]})"
    else
      echo "ea-php$b: $v - ACTUALIZACION REQUERIDA (min ${MIN[$b]})"
      needs+=("$b")
    fi
  else
    echo "ea-php$b: no instalado (omitido)"
  fi
done

legacy=$(rpm -qa --qf '%{NAME}\n' | grep -E '^ea-php(5[0-9]|7[0-9]|80|81)-php-cli$' || true)
[[ -z "$legacy" ]] || printf 'AVISO: ramas antiguas detectadas (verificar parches del proveedor):\n%s\n' "$legacy"

if (( ${#needs[@]} )); then
  patterns=()
  for b in "${needs[@]}"; do patterns+=("ea-php${b}*"); done
  echo "===== ACTUALIZANDO: ${needs[*]} ====="
  if ! dnf upgrade -y --refresh "${patterns[@]}"; then
    echo 'ERROR: dnf reportó un fallo en la actualización.'
    failed=1
  fi
else
  echo 'Todas las ramas instaladas 8.2-8.5 cumplen; no se modifica nada.'
fi

echo '===== VALIDACION FINAL ====='
for b in "${installed[@]}"; do
  v=$(version_of "$b") || v='NO DISPONIBLE'
  if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$b]}"; then
    echo "OK ea-php$b: $v >= ${MIN[$b]}"
  else
    echo "FALLO ea-php$b: $v < ${MIN[$b]} (o binario no disponible)"
    failed=1
  fi
done
if (( ${#installed[@]} == 0 )); then
  echo 'AVISO: no se encontraron ramas ea-php 8.2 a 8.5.'
fi
printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
