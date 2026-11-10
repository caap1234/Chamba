#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/local/directadmin:$PATH"

if (( EUID != 0 )); then echo 'ERROR: Ejecutar como root.' >&2; exit 2; fi

CONF=/usr/local/directadmin/custombuild/options.conf
CB_DIR=/usr/local/directadmin/custombuild

if [[ ! -f "$CONF" ]]; then
  echo 'ERROR: No se detectó DirectAdmin/CustomBuild (options.conf no existe).' >&2
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
    echo 'ERROR: No se encontró CustomBuild (/usr/local/directadmin/custombuild/build).' >&2
    return 1
  fi
}

LOG="/root/php_security_directadmin_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

declare -A MIN=( ["8.2"]="8.2.35" ["8.3"]="8.3.36" ["8.4"]="8.4.27" ["8.5"]="8.5.12" )
declare -A BACKPORT=( ["7.4"]="Parche de CustomBuild" ["8.0"]="Parche de CustomBuild" ["8.1"]="Parche de CustomBuild" )

branches=() needs=0 failed=0

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

version_of() {
  local bin="/usr/local/php${1/./}/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

is_da_backported() {
  local branch="$1"
  local bin="/usr/local/php${branch/./}/bin/php"
  [[ -x "$bin" ]] || return 1

  # Extraer fecha de compilación reportada por el binario
  local built_str
  built_str=$("$bin" -v 2>/dev/null | grep -o 'built: [^)]*' | sed 's/built: //')
  if [[ -n "$built_str" ]]; then
    local built_epoch cutoff_epoch
    built_epoch=$(date -d "$built_str" +%s 2>/dev/null || python3 -c "import datetime, sys; print(int(datetime.datetime.strptime(sys.argv[1].strip(), '%b %d %Y %H:%M:%S').timestamp()))" "$built_str" 2>/dev/null || echo 0)
    # Fecha de corte de parches de seguridad (21 de Octubre de 2026)
    cutoff_epoch=$(date -d "2026-10-21 00:00:00 UTC" +%s 2>/dev/null || echo 1792540800)
    if (( built_epoch >= cutoff_epoch )); then
      return 0
    fi
  fi

  return 1
}

# Solamente ramas habilitadas en options.conf (php1_release .. php4_release)
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
    echo "AVISO: PHP $branch está configurado; no está entre las ramas 7.4-8.5 evaluadas."
  fi
done

if (( ${#branches[@]} == 0 )); then
  echo 'ERROR: No se encontraron ramas PHP configuradas en CustomBuild.'
  exit 2
fi

if (( needs )); then
  echo '===== ACTUALIZANDO METADATOS DE CUSTOMBUILD ====='
  if run_cb update; then
    echo '===== RECOMPILANDO PHP (aplicando versiones y parches de CustomBuild) ====='
    if ! run_cb php; then
      echo 'ERROR: CustomBuild no finalizó correctamente.'
      failed=1
    fi
  else
    echo 'ERROR: No se pudo actualizar CustomBuild.'
    failed=1
  fi
else
  echo 'Todas las ramas evaluadas (7.4 a 8.5) cumplen con los parches de seguridad; no se recompila PHP.'
fi

echo '===== VALIDACION FINAL ====='
for branch in "${branches[@]}"; do
  v=$(version_of "$branch") || v='NO DISPONIBLE'
  if [[ -n "${BACKPORT[$branch]:-}" ]]; then
    if [[ "$v" != 'NO DISPONIBLE' ]] && is_da_backported "$branch"; then
      echo "OK PHP $branch: $v - CUMPLE (Corregida: ${BACKPORT[$branch]})"
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
