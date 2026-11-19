#!/usr/bin/env bash
# ==============================================================================
# Script: verificar_actualizar_php_cpanel.sh
# Proposito: Auditoria y actualizacion de seguridad en cPanel/WHM:
#            1. EasyApache 4 PHP (ea-php 8.1 en adelante, 8.2-8.5 y 7.4/8.0 si estan presentes)
#            2. PHP interno de cPanel (/scripts/autorepair update_cpanel_php8)
#            3. Apache HTTP Server ea-apache24 (>= 2.4.71-1 - mod_http2 CVE-2026-119618 RCE)
# Referencias:
#  - PHP: https://support.cpanel.net/hc/en-us/articles/45152249350423-Security-Critical-PHP-Security-Release-on-November-18-2026
#  - Apache mod_http2: https://support.cpanel.net/hc/en-us/articles/44958593582103-Vulnerability-CVE-2026-119618-Remote-code-execution-in-Apache-HTTP-Server-mod-http2
# ==============================================================================
set -uo pipefail
export LC_ALL=C

if (( EUID != 0 )); then echo 'ERROR: Ejecutar como root.' >&2; exit 2; fi

FORCE=0
if [[ "${1:-}" =~ ^(-f|--force)$ ]]; then
  FORCE=1
fi

PKG_MGR=""
if command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MGR="yum"
fi

if [[ ! -d /usr/local/cpanel || -z "$PKG_MGR" ]]; then
  echo 'ERROR: Este script requiere cPanel/WHM sobre un sistema con dnf o yum.' >&2; exit 2
fi

LOG="/root/php_security_cpanel_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
echo "Gestor de paquetes detectado: $PKG_MGR"

# Versiones minimas oficiales corregidas tras el lanzamiento de seguridad del 18 de Noviembre de 2026
declare -A MIN=( [82]=8.2.36 [83]=8.3.37 [84]=8.4.28 [85]=8.5.13 )
declare -A BACKPORT_DESC=(
  [74]="7.4.34 (cPanel) - Corregida mediante backport EA4"
  [80]="8.0.30 + parche EA4 - Corregida mediante backport EA4"
  [81]="8.1.34 + parche EA4 - Corregida mediante backport EA4 (Nov 18, 2026)"
)

APACHE_MIN="2.4.71-1"
apache_installed=0
apache_needs_update=0
apache_current_ver=""

needs=() installed=() failed=0

version_of() {
  local bin="/opt/cpanel/ea-php${1}/root/usr/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

cpanel_internal_php() {
  local cphp="/usr/local/cpanel/3rdparty/bin/php"
  if [[ -x "$cphp" ]]; then
    "$cphp" -r 'echo PHP_VERSION;' 2>/dev/null || echo "Desconocida"
  else
    echo "No encontrado"
  fi
}

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

has_pkg_update() {
  local b="$1"
  local code=0
  if [[ "$PKG_MGR" == "yum" ]]; then
    yum check-update -q --setopt=*.skip_if_unavailable=1 "ea-php${b}*" >/dev/null 2>&1 || code=$?
  else
    $PKG_MGR check-update -q "ea-php${b}*" >/dev/null 2>&1 || code=$?
  fi
  if (( code == 100 )); then
    return 0 # Hay actualizacion pendiente en los repositorios
  fi
  return 1
}

has_apache_update() {
  local code=0
  if [[ "$PKG_MGR" == "yum" ]]; then
    yum check-update -q --setopt=*.skip_if_unavailable=1 "ea-apache24*" >/dev/null 2>&1 || code=$?
  else
    $PKG_MGR check-update -q "ea-apache24*" >/dev/null 2>&1 || code=$?
  fi
  if (( code == 100 )); then
    return 0 # Hay actualizacion pendiente
  fi
  return 1
}

is_cpanel_backported() {
  local b="$1"
  local pkg="ea-php${b}-php-cli"

  # Si el gestor de paquetes reporta actualizacion pendiente para este ea-php, requiere actualizarse
  if has_pkg_update "$b"; then
    return 1
  fi

  # Comprobar si el changelog de RPM incluye parches de seguridad de EA4 / CVEs recientes
  if rpm -q --changelog "$pkg" 2>/dev/null | head -n 50 | grep -Eiq 'CVE-2026-|EA-13613|CVE-2024-|backport|parche|security release'; then
    return 0
  fi

  # Comprobacion de version especifica
  local v
  v=$(version_of "$b" 2>/dev/null || echo "")
  case "$b" in
    74) meets "$v" "7.4.34" && return 0 ;;
    80) meets "$v" "8.0.30" && rpm -q --changelog "$pkg" 2>/dev/null | head -n 30 | grep -Eiq 'CVE|EA' && return 0 ;;
    81) meets "$v" "8.1.34" && return 0 ;;
  esac

  return 1
}

is_cloudlinux() {
  if [[ -f /etc/cloudlinux-release ]]; then
    return 0
  fi
  if command -v cldetect >/dev/null 2>&1 && cldetect --is-cl >/dev/null 2>&1; then
    return 0
  fi
  if grep -qi 'CloudLinux' /etc/redhat-release 2>/dev/null; then
    return 0
  fi
  return 1
}

# Solo alertar de alt-php si el sistema es autenticamente CloudLinux Y posee paquetes alt-php de hosting
if is_cloudlinux && rpm -qa --qf '%{NAME}\n' | grep -Eq '^alt-php(5[0-9]|7[0-9]|8[0-9])-cli$'; then
  echo 'AVISO: Servidor CloudLinux detectado con paquetes alt-php de hosting. Este script gestiona ea-php de EasyApache 4; para alt-php utilice los repositorios de CloudLinux.'
fi

echo '===== ESTADO INICIAL ====='
echo "cPanel Internal PHP: $(cpanel_internal_php)"

# 1. Auditoria de Apache HTTP Server (ea-apache24 / mod_http2 CVE-2026-119618)
if rpm -q ea-apache24 >/dev/null 2>&1; then
  apache_installed=1
  apache_current_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ea-apache24 2>/dev/null || echo "")
  if [[ -n "$apache_current_ver" ]] && meets "$apache_current_ver" "$APACHE_MIN" && ! has_apache_update; then
    echo "ea-apache24: $apache_current_ver - CUMPLE (>= $APACHE_MIN - mod_http2 CVE-2026-119618 corregido)"
  else
    echo "ea-apache24: $apache_current_ver - ACTUALIZACION REQUERIDA (Requiere >= $APACHE_MIN para corregir mod_http2 CVE-2026-119618)"
    apache_needs_update=1
  fi
else
  echo "ea-apache24: no instalado (omitido)"
fi

# 2. Auditoria de ramas PHP en EasyApache 4
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
      # Ramas 8.2, 8.3, 8.4, 8.5 (versiones de 8.1 en adelante)
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

if (( ${#needs[@]} > 0 || apache_needs_update == 1 || FORCE == 1 )); then
  if (( FORCE == 1 )); then
    echo "===== MODO FORZADO (--force): Ejecutando ciclo completo de actualizacion ====="
    if (( ${#installed[@]} > 0 )); then
      for b in "${installed[@]}"; do
        if [[ ! " ${needs[*]:-} " =~ " ${b} " ]]; then
          needs+=("$b")
        fi
      done
    fi
  fi

  echo "===== 1. LIMPIANDO Y ACTUALIZANDO CACHE DE REPOSITORIOS ($PKG_MGR clean all / makecache) ====="
  $PKG_MGR clean all || true
  if [[ "$PKG_MGR" == "yum" ]]; then
    yum makecache --setopt=*.skip_if_unavailable=1 2>/dev/null || true
  else
    $PKG_MGR makecache 2>/dev/null || true
  fi

  echo "===== 2. ACTUALIZANDO PAQUETES CON /scripts/update-packages ====="
  if [[ -x /scripts/update-packages ]]; then
    /scripts/update-packages || true
  else
    echo "AVISO: /scripts/update-packages no encontrado. Procediendo con el gestor de paquetes."
  fi

  echo "===== 3. ACTUALIZANDO PHP INTERNO DE CPANEL (/scripts/autorepair update_cpanel_php8) ====="
  if [[ -x /scripts/autorepair ]]; then
    /scripts/autorepair update_cpanel_php8
  else
    echo "AVISO: /scripts/autorepair no encontrado."
  fi

  # Actualizacion focalizada con el gestor de paquetes si hay paquetes especificos
  patterns=()
  if (( ${#needs[@]} > 0 )); then
    for b in "${needs[@]}"; do patterns+=("ea-php${b}*"); done
  fi
  if (( apache_needs_update == 1 || FORCE == 1 )) && (( apache_installed == 1 )); then
    patterns+=("ea-apache24*")
  fi

  if (( ${#patterns[@]} )); then
    echo "===== 4. ACTUALIZANDO PAQUETES MEDIANTE $PKG_MGR: ${patterns[*]} ====="

    update_ok=0
    if [[ "$PKG_MGR" == "dnf" ]]; then
      if dnf upgrade -y --refresh "${patterns[@]}"; then
        update_ok=1
      elif dnf upgrade -y --skip-broken "${patterns[@]}"; then
        echo "AVISO: dnf requirio --skip-broken para resolver dependencias."
        update_ok=1
      fi
    else
      # yum en CentOS 7 / CloudLinux 7
      yum clean expire-cache >/dev/null 2>&1 || true
      if yum update -y --setopt=*.skip_if_unavailable=1 "${patterns[@]}"; then
        update_ok=1
      elif yum update -y --setopt=*.skip_if_unavailable=1 --skip-broken "${patterns[@]}"; then
        echo "AVISO: La actualizacion requirio --skip-broken para resolver dependencias rotas en repositorios."
        update_ok=1
      elif yum update -y --disablerepo=updates,base,extras --skip-broken "${patterns[@]}"; then
        echo "AVISO: Se desactivaron repositorios EOL de CentOS (updates, base, extras) para completar la actualizacion de EA4."
        update_ok=1
      fi
    fi

    if (( update_ok == 0 )); then
      echo "ERROR: $PKG_MGR reporto un fallo en la actualizacion de paquetes."
      failed=1
    fi
  fi

  echo "===== 5. REINICIANDO SERVICIOS HTTPD Y PHP-FPM ====="
  if [[ -x /scripts/restartsrv_apache_php_fpm ]]; then
    echo 'Reiniciando servicios PHP-FPM de EasyApache 4...'
    /scripts/restartsrv_apache_php_fpm >/dev/null 2>&1 || true
  fi
  if [[ -x /scripts/restartsrv_httpd ]]; then
    echo 'Reiniciando Apache HTTPD...'
    /scripts/restartsrv_httpd >/dev/null 2>&1 || true
  fi
else
  echo 'Todos los componentes instalados cumplen con los parches de seguridad (PHP y Apache mod_http2).'
  echo 'Verificando y asegurando PHP interno de cPanel por precaucion...'
  if [[ -x /scripts/autorepair ]]; then
    /scripts/autorepair update_cpanel_php8 >/dev/null 2>&1 || true
  fi
fi

echo '===== VALIDACION FINAL ====='
echo "cPanel Internal PHP final: $(cpanel_internal_php)"

# Validacion final de Apache HTTP Server
if (( apache_installed )); then
  apache_final_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ea-apache24 2>/dev/null || echo "")
  if [[ -n "$apache_final_ver" ]] && meets "$apache_final_ver" "$APACHE_MIN"; then
    echo "OK ea-apache24: $apache_final_ver >= $APACHE_MIN - CUMPLE (mod_http2 CVE-2026-119618 corregido)"
  else
    echo "FALLO ea-apache24: $apache_final_ver < $APACHE_MIN (Vulnerable a CVE-2026-119618 en mod_http2)"
    failed=1
  fi
fi

# Validacion final de ramas PHP EasyApache 4
if (( ${#installed[@]} > 0 )); then
  for b in "${installed[@]}"; do
    v=$(version_of "$b") || v='NO DISPONIBLE'
    if [[ "$b" =~ ^(74|80|81)$ ]]; then
      if [[ "$v" != 'NO DISPONIBLE' ]] && is_cpanel_backported "$b"; then
        echo "OK ea-php$b: $v - CUMPLE (${BACKPORT_DESC[$b]})"
      else
        echo "FALLO ea-php$b: $v (Requiere actualizacion backport de cPanel)"
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
fi

if (( ${#installed[@]} == 0 )); then
  echo 'AVISO: no se encontraron ramas ea-php 7.4 a 8.5 instaladas.'
fi

printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
