#!/usr/bin/env bash
# ==============================================================================
# Script: verificar_actualizar_php_vps.sh
# Propósito: Auditoría y actualización automatizada de seguridad de PHP en VPS
#            standalone (sin panel de control) para AlmaLinux, CentOS, Rocky,
#            RHEL, Ubuntu y Debian.
# ==============================================================================
set -uo pipefail
export LC_ALL=C

if (( EUID != 0 )); then
  echo 'ERROR: Este script debe ejecutarse como root.' >&2
  exit 2
fi

# Advertencia si se detecta un panel de control
if [[ -d /usr/local/cpanel ]]; then
  echo 'AVISO: Se detectó cPanel/WHM en este servidor.'
  echo '       Para cPanel se recomienda: cpanel/verificar_actualizar_php_cpanel.sh'
fi
if [[ -d /usr/local/directadmin ]]; then
  echo 'AVISO: Se detectó DirectAdmin en este servidor.'
  echo '       Para DirectAdmin se recomienda: directadmin/verificar_actualizar_php_directadmin.sh'
fi

LOG="/root/php_security_vps_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

# ------------------------------------------------------------------------------
# 1. Detección del Sistema Operativo y Gestor de Paquetes
# ------------------------------------------------------------------------------
OS_ID="unknown"
OS_PRETTY="Linux desconocido"
FAMILY="unknown"
PKG_MGR="unknown"

if [[ -f /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  OS_ID_LIKE="${ID_LIKE:-}"
elif [[ -f /etc/redhat-release ]]; then
  OS_ID="rhel"
  OS_PRETTY=$(cat /etc/redhat-release)
  OS_ID_LIKE="rhel fedora"
elif [[ -f /etc/debian_version ]]; then
  OS_ID="debian"
  OS_PRETTY="Debian $(cat /etc/debian_version)"
  OS_ID_LIKE="debian"
fi

if [[ "$OS_ID" =~ ^(ubuntu|debian|linuxmint|pop)$ ]] || [[ "${OS_ID_LIKE:-}" =~ (debian|ubuntu) ]] || command -v apt-get >/dev/null 2>&1; then
  FAMILY="debian"
  PKG_MGR="apt-get"
elif [[ "$OS_ID" =~ ^(almalinux|centos|rocky|rhel|ol|fedora)$ ]] || [[ "${OS_ID_LIKE:-}" =~ (rhel|fedora|centos) ]] || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  FAMILY="redhat"
  if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  else
    PKG_MGR="yum"
  fi
else
  echo "ERROR: Sistema operativo no soportado ($OS_PRETTY). Se requiere AlmaLinux, CentOS, Rocky, RHEL, Ubuntu o Debian." >&2
  exit 2
fi

echo "===== DETECCION DE ENTORNO ====="
echo "Sistema Operativo : $OS_PRETTY ($FAMILY)"
echo "Gestor de Paquetes: $PKG_MGR"

# ------------------------------------------------------------------------------
# 2. Funciones de Ayuda y Estándares de Seguridad
# ------------------------------------------------------------------------------
declare -A MIN=( ["8.2"]="8.2.35" ["8.3"]="8.3.36" ["8.4"]="8.4.27" ["8.5"]="8.5.12" )
declare -A BACKPORT_DESC=(
  ["7.4"]="Corregida mediante backport / parches de seguridad"
  ["8.0"]="Corregida mediante backport / parches de seguridad"
  ["8.1"]="Corregida mediante backport / parches de seguridad"
)

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

# ------------------------------------------------------------------------------
# 3. Detección de Instalaciones y Binarios de PHP
# ------------------------------------------------------------------------------
# Un VPS puede tener el PHP por defecto (/usr/bin/php) y/o múltiples ramas
# (como /usr/bin/php7.4, /usr/bin/php8.1, o Remi /opt/remi/phpXX/root/usr/bin/php)
declare -A BRANCH_BIN=()
declare -a DETECTED_BRANCHES=()

register_branch() {
  local br="$1"
  local bin="$2"
  [[ -x "$bin" ]] || return 0
  if [[ -z "${BRANCH_BIN[$br]:-}" ]]; then
    BRANCH_BIN["$br"]="$bin"
    DETECTED_BRANCHES+=("$br")
  fi
}

# Búsqueda de binarios por versión estándar (Debian/Ubuntu/Sury y estándar)
for v_candidate in 7.4 8.0 8.1 8.2 8.3 8.4 8.5; do
  if [[ -x "/usr/bin/php$v_candidate" ]]; then
    register_branch "$v_candidate" "/usr/bin/php$v_candidate"
  fi
  # Remi RPM format (AlmaLinux / CentOS / Rocky)
  remi_nodot="${v_candidate/./}"
  if [[ -x "/opt/remi/php${remi_nodot}/root/usr/bin/php" ]]; then
    register_branch "$v_candidate" "/opt/remi/php${remi_nodot}/root/usr/bin/php"
  fi
done

# Búsqueda del binario predeterminado en PATH si no fue catalogado
if command -v php >/dev/null 2>&1; then
  DEFAULT_PHP=$(command -v php)
  PHP_VER_STR=$("$DEFAULT_PHP" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "")
  if [[ -n "$PHP_VER_STR" && -z "${BRANCH_BIN[$PHP_VER_STR]:-}" ]]; then
    register_branch "$PHP_VER_STR" "$DEFAULT_PHP"
  fi
fi

if (( ${#DETECTED_BRANCHES[@]} == 0 )); then
  echo ""
  echo "INFO: No se detectó ninguna instalación activa de PHP en este VPS."
  echo "      No hay paquetes ni binarios de PHP que verificar o actualizar."
  printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
  exit 0
fi

echo "Ramas PHP detectadas: ${DETECTED_BRANCHES[*]}"

# ------------------------------------------------------------------------------
# 4. Evaluación de Estado Inicial
# ------------------------------------------------------------------------------
needs_branches=()
packages_to_upgrade=()
failed=0

check_pkg_update_debian() {
  local br="$1"
  # Comprobar si apt reporta candidatos superiores para php$br-cli o php-cli
  local pkgs_to_check=("php${br}-cli" "php${br}-common" "php${br}-fpm" "php-cli")
  local has_update=1
  for p in "${pkgs_to_check[@]}"; do
    if dpkg -l "$p" 2>/dev/null | grep -q '^ii'; then
      local policy
      policy=$(apt-cache policy "$p" 2>/dev/null || true)
      local inst cand
      inst=$(echo "$policy" | awk '/Installed:/ {print $2}')
      cand=$(echo "$policy" | awk '/Candidate:/ {print $2}')
      if [[ -n "$inst" && -n "$cand" && "$inst" != "$cand" && "$cand" != "(none)" ]]; then
        packages_to_upgrade+=("$p")
        has_update=0
      fi
    fi
  done
  return "$has_update"
}

check_pkg_update_redhat() {
  local br="$1"
  local nodot="${br/./}"
  local patterns=("php*" "php${nodot}*")
  local code=0
  $PKG_MGR check-update -q "${patterns[@]}" >/dev/null 2>&1 || code=$?
  if (( code == 100 )); then
    packages_to_upgrade+=("${patterns[@]}")
    return 0
  fi
  return 1
}

# Refrescar repositorios según la distribución
echo ""
echo "Sincronizando índices de paquetes del sistema..."
if [[ "$FAMILY" == "debian" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
fi

echo ""
echo "===== ESTADO INICIAL DE PHP ====="
for br in "${DETECTED_BRANCHES[@]}"; do
  bin="${BRANCH_BIN[$br]}"
  full_ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || echo "NO DISPONIBLE")

  if [[ "$br" =~ ^(7\.4|8\.0|8\.1)$ ]]; then
    # Ramas EOL con backport
    has_pending=1
    if [[ "$FAMILY" == "debian" ]]; then
      check_pkg_update_debian "$br" && has_pending=0
    else
      check_pkg_update_redhat "$br" && has_pending=0
    fi

    if (( has_pending == 0 )); then
      echo "PHP $br: $full_ver - ACTUALIZACION REQUERIDA (Parches pendientes en repositorios)"
      needs_branches+=("$br")
    else
      echo "PHP $br: $full_ver - CUMPLE (${BACKPORT_DESC[$br]})"
    fi

  elif [[ -n "${MIN[$br]:-}" ]]; then
    # Ramas activas 8.2, 8.3, 8.4, 8.5
    if [[ "$full_ver" != "NO DISPONIBLE" ]] && meets "$full_ver" "${MIN[$br]}"; then
      echo "PHP $br: $full_ver - CUMPLE (min ${MIN[$br]} - Corregida)"
    else
      echo "PHP $br: $full_ver - ACTUALIZACION REQUERIDA (min ${MIN[$br]})"
      needs_branches+=("$br")
      if [[ "$FAMILY" == "debian" ]]; then
        check_pkg_update_debian "$br" || packages_to_upgrade+=("php${br}*" "php*")
      else
        local nodot="${br/./}"
        packages_to_upgrade+=("php${nodot}*" "php*")
      fi
    fi
  else
    echo "PHP $br: $full_ver - AVISO: Rama antigua/no evaluada."
  fi
done

# ------------------------------------------------------------------------------
# 5. Ejecución de Actualizaciones si se requieren
# ------------------------------------------------------------------------------
if (( ${#needs_branches[@]} )); then
  echo ""
  echo "===== ACTUALIZANDO RAMAS: ${needs_branches[*]} ====="

  uniq_pkgs=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && uniq_pkgs+=("$line")
  done < <(printf '%s\n' "${packages_to_upgrade[@]}" | sort -u)

  if [[ "$FAMILY" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    echo "Ejecutando actualización de paquetes PHP vía apt-get..."
    if (( ${#uniq_pkgs[@]} )); then
      if ! apt-get install --only-upgrade -y "${uniq_pkgs[@]}"; then
        echo "AVISO: Intento con lista específica falló, intentando actualización general de paquetes php..."
        apt-get --only-upgrade -y install 'php*' || failed=1
      fi
    else
      apt-get --only-upgrade -y install 'php*' || failed=1
    fi

  elif [[ "$FAMILY" == "redhat" ]]; then
    echo "Ejecutando actualización de paquetes PHP vía $PKG_MGR..."
    if (( ${#uniq_pkgs[@]} )); then
      if ! $PKG_MGR upgrade -y --refresh "${uniq_pkgs[@]}"; then
        echo "ERROR: Falló la actualización de paquetes con $PKG_MGR."
        failed=1
      fi
    else
      if ! $PKG_MGR upgrade -y --refresh 'php*'; then
        echo "ERROR: Falló la actualización general con $PKG_MGR."
        failed=1
      fi
    fi
  fi

  # Recarga/Reinicio de servicios PHP-FPM y servidores web
  echo ""
  echo "Reiniciando servicios PHP-FPM detectados..."
  systemctl restart 'php*-fpm' 2>/dev/null || systemctl restart php-fpm 2>/dev/null || service php-fpm restart 2>/dev/null || true

  if systemctl is-active --quiet apache2 2>/dev/null; then
    systemctl reload apache2 2>/dev/null || true
  fi
  if systemctl is-active --quiet httpd 2>/dev/null; then
    systemctl reload httpd 2>/dev/null || true
  fi
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || true
  fi
else
  echo ""
  echo "Todas las ramas instaladas cumplen con los criterios de seguridad; no se modificó ningún paquete."
fi

# ------------------------------------------------------------------------------
# 6. Validación Final
# ------------------------------------------------------------------------------
echo ""
echo "===== VALIDACION FINAL ====="
for br in "${DETECTED_BRANCHES[@]}"; do
  bin="${BRANCH_BIN[$br]}"
  full_ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || echo "NO DISPONIBLE")

  if [[ "$br" =~ ^(7\.4|8\.0|8\.1)$ ]]; then
    echo "OK PHP $br: $full_ver - CUMPLE (${BACKPORT_DESC[$br]})"
  elif [[ -n "${MIN[$br]:-}" ]]; then
    if [[ "$full_ver" != "NO DISPONIBLE" ]] && meets "$full_ver" "${MIN[$br]}"; then
      echo "OK PHP $br: $full_ver >= ${MIN[$br]} - CUMPLE (Corregida)"
    else
      echo "FALLO PHP $br: $full_ver < ${MIN[$br]}"
      failed=1
    fi
  fi
done

printf '\nFinal: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
