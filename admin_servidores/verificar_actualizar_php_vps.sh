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

meets() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

get_installed_php_packages() {
  if [[ "$FAMILY" == "debian" ]]; then
    # Filtrar exclusivamente paquetes con estado 'ii' (instalados) y quitar sufijo multiarch (:amd64)
    dpkg -l 'php*' 2>/dev/null | awk '/^ii/ {print $2}' | cut -d: -f1 | sort -u
  else
    rpm -qa --qf '%{NAME}\n' | grep -E '^(php|ea-php|alt-php)' | sort -u || true
  fi
}

get_pkg_revision() {
  local br="$1"
  if [[ "$FAMILY" == "debian" ]]; then
    dpkg-query -W -f='${Version}' "php${br}-cli" 2>/dev/null || \
    dpkg-query -W -f='${Version}' "php${br}-common" 2>/dev/null || \
    dpkg-query -W -f='${Version}' "php-cli" 2>/dev/null || echo ""
  else
    local nodot="${br/./}"
    rpm -q --qf '%{VERSION}-%{RELEASE}' "php${nodot}-php-cli" 2>/dev/null || \
    rpm -q --qf '%{VERSION}-%{RELEASE}' "php-cli" 2>/dev/null || echo ""
  fi
}

# ------------------------------------------------------------------------------
# 3. Detección de Instalaciones y Binarios de PHP
# ------------------------------------------------------------------------------
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
# 4. Evaluación de Estado Inicial y Actualizaciones Pendientes
# ------------------------------------------------------------------------------
echo ""
echo "Sincronizando índices de paquetes del sistema..."
if [[ "$FAMILY" == "debian" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq 2>/dev/null || true
fi

declare -a PENDING_PACKAGES=()

check_pending_updates() {
  PENDING_PACKAGES=()
  local installed
  installed=$(get_installed_php_packages)
  [[ -z "$installed" ]] && return 0

  if [[ "$FAMILY" == "debian" ]]; then
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      local policy
      policy=$(apt-cache policy "$pkg" 2>/dev/null || true)
      local inst cand
      inst=$(echo "$policy" | awk '/Installed:/ {print $2}')
      cand=$(echo "$policy" | awk '/Candidate:/ {print $2}')
      # Solo es pendiente si el paquete ESTÁ INSTALADO (inst != (none)) y existe candidato superior
      if [[ -n "$inst" && "$inst" != "(none)" && -n "$cand" && "$cand" != "(none)" && "$inst" != "$cand" ]]; then
        PENDING_PACKAGES+=("$pkg")
      fi
    done <<< "$installed"
  else
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      local code=0
      $PKG_MGR check-update -q "$pkg" >/dev/null 2>&1 || code=$?
      if (( code == 100 )); then
        PENDING_PACKAGES+=("$pkg")
      fi
    done <<< "$installed"
  fi
}

check_pending_updates

branch_has_pending() {
  local br="$1"
  local nodot="${br/./}"
  for p in "${PENDING_PACKAGES[@]}"; do
    if [[ "$p" == *"php${br}"* || "$p" == *"php${nodot}"* || "$p" == "php-cli" || "$p" == "php-common" ]]; then
      return 0
    fi
  done
  return 1
}

needs_branches=()
failed=0

echo ""
echo "===== ESTADO INICIAL DE PHP ====="
for br in "${DETECTED_BRANCHES[@]}"; do
  bin="${BRANCH_BIN[$br]}"
  full_ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || echo "NO DISPONIBLE")
  pkg_rev=$(get_pkg_revision "$br")

  # 1. ¿Cumple con la versión upstream de seguridad (p. ej. Ondrej PPA o Remi)?
  if [[ -n "${MIN[$br]:-}" ]] && meets "$full_ver" "${MIN[$br]}"; then
    echo "PHP $br: $full_ver - CUMPLE (Versión upstream >= ${MIN[$br]} corregida)"

  # 2. Si no es >= MIN, ¿está la distribución oficial al día con parches backport?
  elif ! branch_has_pending "$br"; then
    if [[ -n "$pkg_rev" ]]; then
      echo "PHP $br: $full_ver (paquete $pkg_rev) - CUMPLE (Al día con parches de seguridad de $OS_PRETTY)"
    else
      echo "PHP $br: $full_ver - CUMPLE (Sin actualizaciones pendientes en repositorios del SO)"
    fi

  # 3. Presenta actualizaciones pendientes en los repositorios
  else
    echo "PHP $br: $full_ver - ACTUALIZACION REQUERIDA (Parches pendientes en repositorios de $OS_PRETTY)"
    needs_branches+=("$br")
  fi
done

# ------------------------------------------------------------------------------
# 5. Ejecución de Actualizaciones si se requieren
# ------------------------------------------------------------------------------
if (( ${#needs_branches[@]} )); then
  echo ""
  echo "===== ACTUALIZANDO PAQUETES PHP PENDIENTES ====="
  echo "Ramas a actualizar: ${needs_branches[*]}"
  echo "Paquetes a actualizar: ${PENDING_PACKAGES[*]}"

  if [[ "$FAMILY" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    echo "Ejecutando apt-get install --only-upgrade..."
    if ! apt-get install --only-upgrade -y "${PENDING_PACKAGES[@]}"; then
      echo "ERROR: apt-get reportó un fallo al actualizar los paquetes."
      failed=1
    fi
  elif [[ "$FAMILY" == "redhat" ]]; then
    echo "Ejecutando $PKG_MGR upgrade..."
    if ! $PKG_MGR upgrade -y --refresh "${PENDING_PACKAGES[@]}"; then
      echo "ERROR: $PKG_MGR reportó un fallo al actualizar los paquetes."
      failed=1
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
# Re-evaluar paquetes pendientes post-actualización
check_pending_updates

echo ""
echo "===== VALIDACION FINAL ====="
for br in "${DETECTED_BRANCHES[@]}"; do
  bin="${BRANCH_BIN[$br]}"
  full_ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || echo "NO DISPONIBLE")
  pkg_rev=$(get_pkg_revision "$br")

  if [[ -n "${MIN[$br]:-}" ]] && meets "$full_ver" "${MIN[$br]}"; then
    echo "OK PHP $br: $full_ver >= ${MIN[$br]} - CUMPLE (Versión upstream)"
  elif ! branch_has_pending "$br"; then
    if [[ -n "$pkg_rev" ]]; then
      echo "OK PHP $br: $full_ver (paquete $pkg_rev) - CUMPLE (Corregida con parches de $OS_PRETTY)"
    else
      echo "OK PHP $br: $full_ver - CUMPLE (Corregida con parches del sistema)"
    fi
  else
    echo "FALLO PHP $br: $full_ver (Aún presenta actualizaciones pendientes en repositorios)"
    failed=1
  fi
done

printf '\nFinal: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
exit "$failed"
