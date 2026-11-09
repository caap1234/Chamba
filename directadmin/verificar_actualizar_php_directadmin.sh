#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/local/directadmin:$PATH"

if (( EUID != 0 )); then echo 'ERROR: Ejecutar como root.' >&2; exit 2; fi

CONF=/usr/local/directadmin/custombuild/options.conf
DA_BIN=""
if command -v da >/dev/null 2>&1; then
  DA_BIN="da build"
elif [[ -x /usr/local/directadmin/custombuild/build ]]; then
  DA_BIN="/usr/local/directadmin/custombuild/build"
fi

if [[ ! -f "$CONF" || -z "$DA_BIN" ]]; then
  echo 'ERROR: No se detectó DirectAdmin/CustomBuild.' >&2; exit 2
fi

LOG="/root/php_security_directadmin_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

declare -A MIN=( ["8.2"]="8.2.35" ["8.3"]="8.3.36" ["8.4"]="8.4.27" ["8.5"]="8.5.12" )
branches=() needs=0 failed=0
meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }
version_of() {
  local bin="/usr/local/php${1/./}/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

# Solamente ramas habilitadas en options.conf.
for slot in 1 2 3 4; do
  branch=$(sed -n "s/^php${slot}_release=//p" "$CONF" | tail -n1 | tr -d '\r')
  [[ -z "$branch" || "$branch" == no ]] && continue
  branches+=("$branch")
  if [[ -n "${MIN[$branch]:-}" ]]; then
    v=$(version_of "$branch") || v='NO DISPONIBLE'
    if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$branch]}"; then
      echo "PHP $branch: $v - CUMPLE"
    else
      echo "PHP $branch: $v - ACTUALIZACION REQUERIDA (${MIN[$branch]})"
      needs=1
    fi
  else
    echo "AVISO: PHP $branch está configurado; no está entre las ramas 8.2-8.5 evaluadas."
  fi
done

if (( ${#branches[@]} == 0 )); then
  echo 'ERROR: No se encontraron ramas PHP configuradas en CustomBuild.'
  exit 2
fi

if (( needs )); then
  echo '===== ACTUALIZANDO METADATOS DE CUSTOMBUILD ====='
  if $DA_BIN update; then
    echo '===== RECOMPILANDO PHP (todas las ramas configuradas por CustomBuild) ====='
    if ! $DA_BIN php; then
      echo 'ERROR: CustomBuild no finalizó correctamente.'
      failed=1
    fi
  else
    echo 'ERROR: No se pudo actualizar CustomBuild.'
    failed=1
  fi
else
  echo 'Todas las ramas evaluadas cumplen; no se recompila PHP.'
fi

echo '===== VALIDACION FINAL ====='
for branch in "${branches[@]}"; do
  [[ -n "${MIN[$branch]:-}" ]] || continue
  v=$(version_of "$branch") || v='NO DISPONIBLE'
  if [[ "$v" != 'NO DISPONIBLE' ]] && meets "$v" "${MIN[$branch]}"; then
    echo "OK PHP $branch: $v >= ${MIN[$branch]}"
  else
    echo "FALLO PHP $branch: $v (minimo ${MIN[$branch]})"
    failed=1
  fi
done
printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
