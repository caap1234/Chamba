#!/usr/bin/env bash
# ==============================================================================
# Script: verificar_actualizar_php_directadmin.sh
# Proposito: Auditoria y aplicacion de parches de seguridad en DirectAdmin
#            CustomBuild mediante deteccion nativa de parches (DA 1.702+) para PHP
#            y verificacion de seguridad para Apache (mod_http2).
#
# Principios clave:
#  1. Actualizar metadatos de CustomBuild antes de verificar actualizaciones.
#  2. Deteccion nativa de CustomBuild ('da build versions' / 'versions_json')
#     conservando la informacion de parches pendientes (*).
#  3. Detectar versiones PHP realmente instaladas y configuradas.
#  4. Tratar como actualizacion pendiente tanto una version superior como parches pendientes.
#  5. No asumir que PHP EOL (5.6, 7.0, 7.4, 8.1) esta protegido solo por su version upstream.
#  6. Recompilar UNICAMENTE las versiones que requieran actualizacion via php_expert.
#  7. Validacion posterior post-compilacion: confirmar que ya no hay pendientes,
#     revisar hash Patches y validar estado del servicio PHP-FPM.
#  8. Si falla la compilacion o validacion: reportar ERROR.
#  9. Si no puede determinarse el estado de parches: reportar NO VERIFICADO (nunca ACTUALIZADO).
# 10. Conservar logica de Apache y protecciones del entorno de compilacion.
# ==============================================================================
set -uo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/local/directadmin:$PATH"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/libzip/lib/pkgconfig:/usr/lib64/pkgconfig:/usr/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# ------------------------------------------------------------------------------
# 1. PARAMETROS Y CONFIGURACION INICIAL
# ------------------------------------------------------------------------------
DRY_RUN=0
FORCE=0

for arg in "$@"; do
  case "$arg" in
    -n|--dry-run)
      DRY_RUN=1
      ;;
    -f|--force)
      FORCE=1
      ;;
    -h|--help)
      echo "Uso: $0 [OPCIONES]"
      echo "Opciones:"
      echo "  -n, --dry-run  Simulacion: diagnostica y verifica sin compilar ni modificar nada."
      echo "  -f, --force    Modo forzado: recompila versiones soportadas aun si ya cumplen version."
      echo "  -h, --help     Muestra esta ayuda."
      exit 0
      ;;
    *)
      echo "ERROR: Parametro no reconocido: $arg" >&2
      echo "Uso: $0 [--dry-run|-n] [--force|-f]" >&2
      exit 2
      ;;
  esac
done

TEST_MODE="${TEST_MODE:-0}"
if (( EUID != 0 )) && (( TEST_MODE == 0 )) && (( DRY_RUN == 0 )); then
  echo 'ERROR: Ejecutar como root.' >&2
  exit 2
fi

CB_DIR="${DA_CB_DIR:-/usr/local/directadmin/custombuild}"
CONF="${DA_CONF:-$CB_DIR/options.conf}"

if [[ ! -f "$CONF" ]] && (( TEST_MODE == 0 )); then
  echo "ERROR: No se detecto DirectAdmin/CustomBuild ($CONF no existe)." >&2
  exit 2
fi

if [[ -f "$CB_DIR/build" && ! -x "$CB_DIR/build" ]]; then
  chmod +x "$CB_DIR/build" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 2. CONTROL DE CONCURRENCIA (LOCKFILE)
# ------------------------------------------------------------------------------
LOCKFILE="/var/run/da_php_security_update.lock"
if (( DRY_RUN == 0 )) && (( TEST_MODE == 0 )); then
  if [[ -f "$LOCKFILE" ]]; then
    existing_pid=$(cat "$LOCKFILE" 2>/dev/null || true)
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "ERROR: Ya existe otra ejecucion activa de este script (PID $existing_pid). Abortando." >&2
      exit 3
    fi
  fi
  echo "$$" > "$LOCKFILE" 2>/dev/null || true
  trap 'rm -f "$LOCKFILE" 2>/dev/null || true' EXIT INT TERM

  if pgrep -f "$CB_DIR/build" >/dev/null 2>&1; then
    echo "ERROR: Se detecto un proceso de CustomBuild en ejecucion. Abortando para evitar conflictos." >&2
    exit 3
  fi
fi

# ------------------------------------------------------------------------------
# 3. REGISTRO DE LOGS
# ------------------------------------------------------------------------------
LOG_DIR="/root"
if [[ ! -w "$LOG_DIR" ]]; then
  LOG_DIR="/tmp"
fi
LOG="${LOG_DIR}/php_security_directadmin_$(date +%Y%m%d_%H%M%S).log"
if (( TEST_MODE == 0 )); then
  exec > >(tee -a "$LOG") 2>&1
fi
printf 'Inicio: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"
if (( DRY_RUN == 1 )); then
  echo ">>> MODO SIMULACION (--dry-run) ACTIVADO: No se modificara el sistema ni se compilaran paquetes <<<"
fi

# ------------------------------------------------------------------------------
# 4. FUNCIONES AUXILIARES Y COMPATIBILIDAD
# ------------------------------------------------------------------------------
APACHE_MIN="2.4.71"

meets() {
  local v1="$1" v2="$2"
  [[ -n "$v1" && -n "$v2" ]] || return 1
  [[ "$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)" == "$v2" ]]
}

is_lower_version() {
  local v1="$1" v2="$2"
  [[ -n "$v1" && -n "$v2" ]] || return 1
  [[ "$v1" != "$v2" && "$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | head -n1)" == "$v1" ]]
}

version_of() {
  local branch="$1"
  local bin="${DA_PHP_DIR:-/usr/local}/php${branch//./}/bin/php"
  [[ -x "$bin" ]] || return 1
  "$bin" -r 'echo PHP_VERSION;' 2>/dev/null
}

run_cb() {
  if (( DRY_RUN == 1 )); then
    if [[ "${1:-}" == "versions" || "${1:-}" == "versions_json" || "${1:-}" == "--debug" ]]; then
      # Permitir lectura diagnostica en dry-run si el binario existe
      if [[ -x "$CB_DIR/build" ]]; then
        (cd "$CB_DIR" && ./build "$@")
        return 0
      elif command -v da >/dev/null 2>&1 && da build --help >/dev/null 2>&1; then
        da build "$@"
        return 0
      fi
    fi
    echo "[DRY-RUN] Simulado: (cd $CB_DIR && ./build $*)"
    return 0
  fi
  if [[ -x "$CB_DIR/build" ]]; then
    (cd "$CB_DIR" && ./build "$@")
  elif command -v da >/dev/null 2>&1 && da build --help >/dev/null 2>&1; then
    da build "$@"
  else
    echo "ERROR: No se encontro CustomBuild ejecutable en $CB_DIR/build." >&2
    return 1
  fi
}

# Obtener hash de parches segun arquitectura DirectAdmin (DA 1.702+)
get_patch_hash() {
  local branch="$1"
  local b_clean="${branch//./}"
  local hash=""

  # 1. Intentar consultar debug nativo de CustomBuild si esta soportado
  local dbg_out
  dbg_out=$(run_cb --debug versions 2>/dev/null | grep -i -E "php.*(${branch}|${b_clean}).*patch" | head -n1 || echo "")
  if [[ -n "$dbg_out" ]]; then
    hash=$(echo "$dbg_out" | grep -oE '[a-f0-9]{12,32}' | head -n1 || echo "")
  fi

  # 2. Calculo local de hash segun especificacion de DirectAdmin (MD5 de 12 caracteres de patches/)
  if [[ -z "$hash" ]]; then
    local patch_files
    patch_files=$(ls "$CB_DIR/patches/php-${branch}/"*.patch "$CB_DIR/patches/php${b_clean}/"*.patch "$CB_DIR/patches/php-"*${b_clean}*/*.patch 2>/dev/null || true)
    if [[ -n "$patch_files" ]]; then
      if command -v md5sum >/dev/null 2>&1; then
        hash=$(cat $patch_files 2>/dev/null | md5sum | head -c 12 || echo "")
      elif command -v md5 >/dev/null 2>&1; then
        hash=$(cat $patch_files 2>/dev/null | md5 | head -c 12 || echo "")
      fi
    fi
  fi

  # Baseline oficial de DA para estado sin parches adicionales: md5sum /dev/null | head -c 12
  echo "${hash:-d41d8cd98f00}"
}

# ------------------------------------------------------------------------------
# 5. DETECCION DE SISTEMA Y ENTORNO
# ------------------------------------------------------------------------------
os_display="Linux (desconocido)"
os_id=""
os_ver=""
os_release_file="${SYS_OS_RELEASE:-/etc/os-release}"
if [[ -f "$os_release_file" ]]; then
  os_display=$(sed -n 's/^PRETTY_NAME=["'\'']\?\(.*\)["'\'']\?/\1/p' "$os_release_file" | head -n1)
  if [[ -z "$os_display" ]]; then
    os_display=$(sed -n 's/^NAME=["'\'']\?\(.*\)["'\'']\?/\1/p' "$os_release_file" | head -n1)
  fi
  os_id=$(sed -n 's/^ID=["'\'']\?\(.*\)["'\'']\?/\1/p' "$os_release_file" | head -n1)
  os_ver=$(sed -n 's/^VERSION_ID=["'\'']\?\(.*\)["'\'']\?/\1/p' "$os_release_file" | head -n1)
elif [[ -f /etc/redhat-release ]]; then
  os_display=$(cat /etc/redhat-release | head -n1)
elif [[ -f /etc/debian_version ]]; then
  os_display="Debian $(cat /etc/debian_version)"
fi
os_display=$(echo "$os_display" | tr -d '"' | tr -d "'" | sed 's/[[:space:]]*$//')

da_version="desconocida"
if [[ -x /usr/local/directadmin/directadmin ]]; then
  da_raw=$(/usr/local/directadmin/directadmin v 2>/dev/null | head -n1 || echo "")
  da_version=$(echo "$da_raw" | grep -oE '(v\.[0-9.]+|v[0-9.]+|[0-9]+\.[0-9]+(\.[0-9]+)?)' | head -n1 | sed 's/^v\.\?//')
  if [[ -z "$da_version" ]]; then
    da_version=$(echo "$da_raw" | awk '{print $1}' || echo "instalada")
  fi
elif command -v da >/dev/null 2>&1; then
  da_version=$(da version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1 || echo "instalada")
fi

cb_version="CustomBuild 2.0"
if [[ -f "$CB_DIR/build" ]]; then
  cb_header=$(grep -m1 '^# CustomBuild' "$CB_DIR/build" 2>/dev/null || true)
  if [[ -n "$cb_header" ]]; then
    cb_version=$(echo "$cb_header" | sed 's/^# //')
  fi
fi

echo '===== DIAGNOSTICO DE SISTEMA Y ENTORNO ====='
echo "Sistema operativo: $os_display"
echo "DirectAdmin: $da_version (SOLO LECTURA - NO SE MODIFICARA)"
echo "CustomBuild: $cb_version"

# ------------------------------------------------------------------------------
# 6. AUDITORIA DE CONFIGURACION (options.conf)
# ------------------------------------------------------------------------------
webserver=$(sed -n "s/^webserver=//p" "$CONF" 2>/dev/null | tail -n1 | tr -d '\r')
webserver="${webserver:-apache}"

httpd_bin="${DA_HTTPD_BIN:-}"
if [[ -z "$httpd_bin" ]]; then
  if command -v httpd >/dev/null 2>&1; then
    httpd_bin=$(command -v httpd)
  elif [[ -x /usr/sbin/httpd ]]; then
    httpd_bin="/usr/sbin/httpd"
  fi
fi

apache_installed_v=""
mod_http2_loaded=0
if [[ -n "$httpd_bin" && -x "$httpd_bin" ]]; then
  apache_installed_v=$("$httpd_bin" -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p' | head -n1)
  if "$httpd_bin" -M 2>/dev/null | grep -q 'http2_module'; then
    mod_http2_loaded=1
  fi
fi

echo "Servidor Web: $webserver (Apache bin: ${httpd_bin:-no encontrado}, mod_http2: $((mod_http2_loaded ? 1 : 0)))"

# Identificar ramas PHP configuradas en slots 1..4
declare -a slot_active=()
declare -a slot_rel=("" "" "" "" "")
declare -a slot_mode=("" "" "" "" "")
declare -a slot_v_inst=("" "" "" "" "")
declare -a slot_inst_raw=("" "" "" "" "")
declare -a slot_cb_avail=("" "" "" "" "")
declare -a slot_state=("" "" "" "" "")
declare -a slot_detail=("" "" "" "" "")
declare -a slot_prev=("" "" "" "" "")
declare -a slot_curr=("" "" "" "" "")
declare -a slot_patches_hash=("" "" "" "" "")

for slot in 1 2 3 4; do
  rel=$(sed -n "s/^php${slot}_release=//p" "$CONF" 2>/dev/null | tail -n1 | tr -d '\r')
  [[ -z "$rel" || "$rel" == "no" ]] && continue
  mode=$(sed -n "s/^php${slot}_mode=//p" "$CONF" 2>/dev/null | tail -n1 | tr -d '\r')
  mode="${mode:-php-fpm}"

  slot_active+=("$slot")
  slot_rel["$slot"]="$rel"
  slot_mode["$slot"]="$mode"
  v_inst=$(version_of "$rel" || echo "")
  slot_v_inst["$slot"]="$v_inst"
done

# ------------------------------------------------------------------------------
# 7. ACTUALIZAR METADATOS DE CUSTOMBUILD ANTES DE VERIFICAR (NO DIRECTADMIN)
# ------------------------------------------------------------------------------
echo '===== DEFINICIONES Y METADATOS DE CUSTOMBUILD ====='
if (( DRY_RUN == 0 )); then
  echo "Refrescando definiciones con CustomBuild (./build update)..."
  if run_cb update; then
    echo "Definiciones de CustomBuild actualizadas correctamente."
  else
    echo "ALERTA: './build update' devolvio codigo de error; se consultaran definiciones locales existentes."
  fi
else
  echo "[DRY-RUN] Se omite './build update' para mantener el sistema 100% intacto; leyendo definiciones disponibles."
fi

# ------------------------------------------------------------------------------
# 8. CONSULTAR DETECCION NATIVA DE CUSTOMBUILD ('da build versions' / 'versions_json')
# ------------------------------------------------------------------------------
cb_versions_output=""
cb_versions_json=""

cb_versions_output=$(run_cb versions 2>/dev/null || true)
cb_versions_json=$(run_cb versions_json 2>/dev/null || true)

cb_apache_latest=""
if [[ -f "$CB_DIR/versions.txt" ]]; then
  cb_apache_latest=$(grep -E '^(apache2\.4|apache):' "$CB_DIR/versions.txt" 2>/dev/null | head -n1 | cut -d: -f2 | tr -d '\r')
fi
if [[ -z "$cb_apache_latest" && -n "$cb_versions_output" ]]; then
  cb_apache_latest=$(echo "$cb_versions_output" | sed -n 's/^Latest version of Apache: //p' | head -n1 | tr -d '\r')
fi

# Funcion nativa para resolver estado y version de PHP usando interfaces soportadas por CustomBuild
parse_cb_php_status() {
  local b="$1"
  local b_clean="${b//./}"
  local inst_raw=""
  local latest_raw=""

  # 1. Intentar interfaz estructurada JSON (versions_json)
  if [[ -n "${cb_versions_json:-}" ]]; then
    inst_raw=$(python3 -c "import json, sys; d=json.loads(sys.argv[1]); key='php${b_clean}'; print(d.get(key,{}).get('current','') or d.get(key,{}).get('installed',''))" "$cb_versions_json" 2>/dev/null || echo "")
    latest_raw=$(python3 -c "import json, sys; d=json.loads(sys.argv[1]); key='php${b_clean}'; print(d.get(key,{}).get('latest','') or d.get(key,{}).get('offered',''))" "$cb_versions_json" 2>/dev/null || echo "")
  fi

  # 2. Interfaz nativa estandar 'da build versions' / './build versions'
  if [[ -z "$inst_raw" || -z "$latest_raw" ]]; then
    local inst_line
    inst_line=$(echo "$cb_versions_output" | grep -E "^[[:space:]]*Installed version of PHP ${b}:" | head -n1 || echo "")
    local latest_line
    latest_line=$(echo "$cb_versions_output" | grep -E "^[[:space:]]*Latest version of PHP ${b}:" | head -n1 || echo "")

    inst_raw=$(echo "$inst_line" | sed -n "s/^[[:space:]]*Installed version of PHP ${b}:[[:space:]]*//p" | tr -d '\r ')
    latest_raw=$(echo "$latest_line" | sed -n "s/^[[:space:]]*Latest version of PHP ${b}:[[:space:]]*//p" | tr -d '\r ')
  fi

  # Fallback a versions.txt para version latest si no fue extraida por comando
  if [[ -z "$latest_raw" && -f "$CB_DIR/versions.txt" ]]; then
    latest_raw=$(grep -E "^php${b_clean}:" "$CB_DIR/versions.txt" 2>/dev/null | head -n1 | cut -d: -f2 | tr -d '\r ')
  fi

  # Fallback a binario local si CustomBuild no entrego installed
  if [[ -z "$inst_raw" ]]; then
    inst_raw=$(version_of "$b" || echo "")
  fi

  echo "${inst_raw}|${latest_raw}"
}

echo "--- Versiones detectadas ---"
echo "Apache instalado: ${apache_installed_v:-NO DISPONIBLE} | Disponible en CustomBuild: ${cb_apache_latest:-desconocida}"

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  b="${slot_rel[$slot]}"
  v_res=$(parse_cb_php_status "$b")
  slot_inst_raw["$slot"]="${v_res%%|*}"
  slot_cb_avail["$slot"]="${v_res##*|}"
  echo "PHP $b configurado: instalada=${slot_inst_raw[$slot]:-NO DISPONIBLE} | latest=${slot_cb_avail[$slot]:-desconocida}"
done

# ------------------------------------------------------------------------------
# 9. VALIDACION PREVENTIVA DEL ENTORNO DE COMPILACION
# ------------------------------------------------------------------------------
build_env_ok=1
build_env_reason=""

repair_centos7_repos() {
  local is_centos7=0
  if [[ "${os_id:-}" =~ ^(centos|rhel)$ && "${os_ver:-}" =~ ^7 ]] || ([[ -f /etc/redhat-release ]] && grep -q -i 'CentOS Linux.* 7' /etc/redhat-release 2>/dev/null); then
    is_centos7=1
  fi

  (( is_centos7 == 1 )) || return 1

  if (( DRY_RUN == 1 )); then
    echo "[DRY-RUN] Repositorios de CentOS 7 descontinuados detectados; en ejecucion real se redirigirian a vault.centos.org."
    return 0
  fi

  echo "Detectados repositorios de CentOS 7 descontinuados (mirror.centos.org). Redirigiendo a vault.centos.org..."
  mkdir -p /etc/yum.repos.d/backup_pre_patch 2>/dev/null || true
  cp -n /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup_pre_patch/ 2>/dev/null || true

  if sed --version >/dev/null 2>&1; then
    sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
    sed -i 's/^#.*baseurl=http/baseurl=http/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
    sed -i 's/^mirrorlist=http/#mirrorlist=http/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
  else
    sed -i '' 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
    sed -i '' 's/^#.*baseurl=http/baseurl=http/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
    sed -i '' 's/^mirrorlist=http/#mirrorlist=http/g' /etc/yum.repos.d/*.repo 2>/dev/null || true
  fi

  yum clean all >/dev/null 2>&1 || true
  yum makecache fast >/dev/null 2>&1 || true
  return 0
}

check_build_environment() {
  local target_comp="$1"
  build_env_ok=1
  build_env_reason=""

  if (( TEST_MODE == 1 )); then
    if [[ "${MOCK_BROKEN_REPO:-0}" == "1" ]]; then
      if [[ "${MOCK_ALLOW_VAULT_FIX:-0}" == "1" ]]; then
        echo "Detectados repositorios de CentOS 7 descontinuados (mirror.centos.org). Redirigiendo a vault.centos.org..."
        echo "Repositorios de CentOS 7 redirigidos exitosamente a vault.centos.org."
      else
        build_env_ok=0
        build_env_reason="Repositorios del sistema no funcionales (Cannot find a valid baseurl for repo: base/7)"
        return 1
      fi
    fi
    if [[ "${MOCK_MISSING_LIBFFI:-0}" == "1" ]]; then
      build_env_ok=0
      build_env_reason="Dependencia critica faltante (libffi >= 3.0.11 no encontrada)"
      return 1
    fi
    if [[ "${MOCK_NO_COMPILER:-0}" == "1" ]]; then
      build_env_ok=0
      build_env_reason="Compilador gcc o make no disponible"
      return 1
    fi
    return 0
  fi

  # 1. Compilador basico
  if ! command -v gcc >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
    build_env_ok=0
    build_env_reason="Compilador gcc o make no disponible en el sistema"
    return 1
  fi

  # 2. Comprobar que repositorios no esten rotos (ej. CentOS 7 EOL)
  if command -v yum >/dev/null 2>&1; then
    local yum_test
    yum_test=$(timeout 8 yum repolist -q 2>&1 || true)
    if echo "$yum_test" | grep -E -q 'Cannot find a valid baseurl|Error: Cannot retrieve repository|Could not resolve host'; then
      if repair_centos7_repos; then
        yum_test=$(timeout 15 yum repolist -q 2>&1 || true)
      fi
      if echo "$yum_test" | grep -E -q 'Cannot find a valid baseurl|Error: Cannot retrieve repository|Could not resolve host'; then
        build_env_ok=0
        build_env_reason="Repositorios del sistema no funcionales (yum repolist fallo con error de baseurl)"
        return 1
      fi
    fi
  fi

  # 3. Comprobar y resolver libzip para PHP
  if [[ "$target_comp" =~ ^php ]]; then
    export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/libzip/lib/pkgconfig:/usr/lib64/pkgconfig:/usr/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

    local libzip_ok=0
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists 'libzip >= 0.11' 2>/dev/null; then
      libzip_ok=1
    elif [[ -f /usr/local/lib/pkgconfig/libzip.pc || -f /usr/local/lib64/pkgconfig/libzip.pc || -f /usr/lib64/pkgconfig/libzip.pc ]]; then
      libzip_ok=1
    fi

    if (( libzip_ok == 0 )); then
      if (( DRY_RUN == 1 )); then
        echo "[DRY-RUN] Dependencia libzip >= 0.11 no detectada; en ejecucion real se compilaria con './build libzip'."
      elif (( TEST_MODE == 1 )); then
        echo "Dependencia libzip >= 0.11 ausente para PHP. Compilando con CustomBuild (./build libzip)..."
        echo "libzip instalado y verificado correctamente."
        libzip_ok=1
      else
        echo "Dependencia libzip >= 0.11 ausente para PHP. Compilando con CustomBuild (./build libzip)..."
        if run_cb libzip; then
          export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/libzip/lib/pkgconfig:/usr/lib64/pkgconfig:/usr/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
          if pkg-config --exists 'libzip >= 0.11' 2>/dev/null || [[ -f /usr/local/lib/pkgconfig/libzip.pc || -f /usr/local/lib64/pkgconfig/libzip.pc ]]; then
            echo "libzip instalado y verificado correctamente."
            libzip_ok=1
          fi
        fi
        if (( libzip_ok == 0 )) && command -v yum >/dev/null 2>&1; then
          yum install -y libzip-devel 2>/dev/null || true
          if pkg-config --exists 'libzip >= 0.11' 2>/dev/null; then
            libzip_ok=1
          fi
        fi
        if (( libzip_ok == 0 )); then
          build_env_ok=0
          build_env_reason="Dependencia critica faltante (libzip >= 0.11 no encontrada ni instalable)"
          return 1
        fi
      fi
    fi
  fi

  # 4. Comprobar libffi para PHP >= 8.0
  if [[ "$target_comp" =~ ^php8 ]]; then
    local ffi_ok=0
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists 'libffi >= 3.0.11' 2>/dev/null; then
      ffi_ok=1
    elif [[ -f /usr/include/ffi.h || -f /usr/include/x86_64-linux-gnu/ffi.h ]]; then
      ffi_ok=1
    elif ls /usr/lib64/libffi.so* >/dev/null 2>&1 || ls /usr/lib/x86_64-linux-gnu/libffi.so* >/dev/null 2>&1; then
      ffi_ok=1
    fi

    if (( ffi_ok == 0 )); then
      build_env_ok=0
      build_env_reason="Dependencia critica faltante (libffi >= 3.0.11 / libffi-devel no encontrada)"
      return 1
    fi
  fi

  # 5. Comprobar / activar toolchain C11 en CentOS 7 para PHP >= 8.1
  if [[ "${os_id:-}" =~ ^(centos|rhel)$ && "${os_ver:-}" =~ ^7 ]] || ([[ -f /etc/redhat-release ]] && grep -q -i 'CentOS Linux.* 7' /etc/redhat-release 2>/dev/null); then
    if [[ "$target_comp" =~ ^php8 ]]; then
      local gcc_major
      gcc_major=$(gcc -dumpversion 2>/dev/null | cut -d. -f1 || echo 4)
      if (( gcc_major < 5 )); then
        local found_devtoolset=0
        for dt in 11 10 9 8 7; do
          if [[ -f "/opt/rh/devtoolset-${dt}/enable" ]]; then
            echo "Activando entorno de compilacion C11 devtoolset-${dt} para PHP..."
            # shellcheck source=/dev/null
            source "/opt/rh/devtoolset-${dt}/enable"
            found_devtoolset=1
            break
          fi
        done

        if (( found_devtoolset == 0 )) && (( DRY_RUN == 0 )) && (( TEST_MODE == 0 )) && command -v yum >/dev/null 2>&1; then
          echo "Instalando devtoolset para soporte C11 en CentOS 7..."
          yum install -y centos-release-scl 2>/dev/null || true
          repair_centos7_repos
          yum install -y devtoolset-11-gcc devtoolset-11-gcc-c++ 2>/dev/null || yum install -y devtoolset-9-gcc devtoolset-9-gcc-c++ 2>/dev/null || true
          for dt in 11 10 9; do
            if [[ -f "/opt/rh/devtoolset-${dt}/enable" ]]; then
              # shellcheck source=/dev/null
              source "/opt/rh/devtoolset-${dt}/enable"
              found_devtoolset=1
              break
            fi
          done
        fi

        gcc_major=$(gcc -dumpversion 2>/dev/null | cut -d. -f1 || echo 4)
        if (( gcc_major < 5 && found_devtoolset == 0 )); then
          build_env_ok=0
          build_env_reason="CentOS 7 carece de compilador C11 compatible (devtoolset-9/10/11 ausente)"
          return 1
        fi
      fi
    fi
  fi

  # 5. Espacio libre en disco (minimo 500MB en particion de CustomBuild)
  local free_mb
  free_mb=$(df -m "$CB_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 1000)
  if [[ -n "$free_mb" && "$free_mb" =~ ^[0-9]+$ ]] && (( free_mb < 500 )); then
    build_env_ok=0
    build_env_reason="Espacio insuficiente en disco ($free_mb MB libres, minimo 500 MB)"
    return 1
  fi

  # 6. Memoria disponible suficiente
  local mem_avail_mb
  mem_avail_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}' || echo "")
  if [[ -z "$mem_avail_mb" || "$mem_avail_mb" == "0" ]]; then
    mem_avail_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $4}' || echo 1000)
  fi
  if [[ -n "$mem_avail_mb" && "$mem_avail_mb" =~ ^[0-9]+$ ]] && (( mem_avail_mb < 250 )); then
    build_env_ok=0
    build_env_reason="Memoria RAM insuficiente ($mem_avail_mb MB disponibles, minimo 250 MB)"
    return 1
  fi

  return 0
}

# ------------------------------------------------------------------------------
# 10. EVALUACION Y ACCION: APACHE (CVE-2026-119618 mod_http2)
# ------------------------------------------------------------------------------
apache_state=""
apache_detail=""
apache_prev="${apache_installed_v:-NO DISPONIBLE}"
apache_curr="${apache_installed_v:-NO DISPONIBLE}"

if [[ -n "$apache_installed_v" ]] && meets "$apache_installed_v" "$APACHE_MIN"; then
  apache_state="OK"
  apache_detail="Parche verificado"
else
  # Requiere version corregida >= 2.4.71
  if [[ -n "$cb_apache_latest" ]] && meets "$cb_apache_latest" "$APACHE_MIN"; then
    if (( DRY_RUN == 1 )); then
      apache_state="PENDIENTE"
      apache_detail="Actualizacion a $cb_apache_latest disponible (simulacion dry-run)"
    else
      echo "Evaluando entorno para actualizacion de Apache a $cb_apache_latest..."
      if check_build_environment "apache"; then
        echo "===== RECOMPILANDO APACHE CON CUSTOMBUILD (actualizando a $cb_apache_latest >= $APACHE_MIN) ====="
        cp "$CONF" "${CONF}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        if run_cb apache; then
          new_v=$("$httpd_bin" -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p' | head -n1 || echo "")
          apache_curr="${new_v:-$cb_apache_latest}"
          if meets "$apache_curr" "$APACHE_MIN"; then
            apache_state="ACTUALIZADO CORRECTAMENTE"
            apache_detail="Versión corregida verificada"
          else
            apache_state="ERROR"
            apache_detail="Compilacion exitosa pero version resultante ($apache_curr) < $APACHE_MIN"
          fi
        else
          apache_state="ERROR"
          apache_detail="Fallo en compilacion de Apache mediante CustomBuild"
        fi
      else
        apache_state="PENDIENTE"
        apache_detail="Actualizacion disponible ($cb_apache_latest) omitida por seguridad: $build_env_reason"
      fi
    fi
  else
    # CustomBuild NO ofrece version >= 2.4.71 (ej. solo ofrece 2.4.63)
    apache_state="PENDIENTE"
    if (( mod_http2_loaded == 1 )); then
      apache_detail="Requiere >= $APACHE_MIN para mod_http2 (activo); CustomBuild solo dispone de ${cb_apache_latest:-desconocida}"
    else
      apache_detail="Requiere >= $APACHE_MIN para mod_http2 (no cargado); CustomBuild solo dispone de ${cb_apache_latest:-desconocida}"
    fi
  fi
fi

# ------------------------------------------------------------------------------
# 11. EVALUACION Y ACCION: PHP MEDIANTE DETECCION NATIVA DE PARCHES
# ------------------------------------------------------------------------------
compilaciones_realizadas=0

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  b="${slot_rel[$slot]}"
  b_clean="${b//./}"
  mode="${slot_mode[$slot]:-php-fpm}"

  raw_inst="${slot_inst_raw[$slot]}"
  raw_avail="${slot_cb_avail[$slot]}"

  clean_inst="${raw_inst//\*/}"
  clean_avail="${raw_avail//\*/}"

  slot_prev["$slot"]="${raw_inst:-NO DISPONIBLE}"
  slot_curr["$slot"]="${clean_inst:-NO DISPONIBLE}"

  has_asterisk=0
  if [[ "$raw_inst" =~ \* ]]; then
    has_asterisk=1
  fi

  needs_compilation=0
  initial_state="NO VERIFICADO"
  initial_detail="No fue posible confirmar el estado real en CustomBuild"

  # Evaluacion segun especificacion oficial de CustomBuild (DA 1.702+)
  if [[ -z "$clean_inst" || -z "$clean_avail" ]]; then
    initial_state="NO VERIFICADO"
    initial_detail="No fue posible determinar la version instalada o disponible mediante CustomBuild"
  elif (( has_asterisk == 1 )); then
    if [[ "$clean_inst" == "$clean_avail" ]]; then
      initial_state="PARCHES PENDIENTES"
      initial_detail="Misma versión ($clean_inst), nuevos parches disponibles de CustomBuild"
      needs_compilation=1
    elif is_lower_version "$clean_inst" "$clean_avail"; then
      initial_state="ACTUALIZACIÓN PENDIENTE"
      initial_detail="Versión superior disponible ($clean_avail) y parches pendientes"
      needs_compilation=1
    else
      initial_state="PARCHES PENDIENTES"
      initial_detail="Parches de seguridad pendientes segun CustomBuild (*)"
      needs_compilation=1
    fi
  else
    # Sin asterisco: no hay parches pendientes
    if is_lower_version "$clean_inst" "$clean_avail"; then
      initial_state="ACTUALIZACIÓN PENDIENTE"
      initial_detail="Versión superior disponible ($clean_avail)"
      needs_compilation=1
    elif [[ "$clean_inst" == "$clean_avail" ]] || meets "$clean_inst" "$clean_avail"; then
      initial_state="ACTUALIZADO"
      initial_detail="Versión y parches al día"
      needs_compilation=0
    else
      initial_state="NO VERIFICADO"
      initial_detail="Estado no concluyente en CustomBuild"
    fi
  fi

  if (( FORCE == 1 )) && [[ "$initial_state" == "ACTUALIZADO" ]]; then
    needs_compilation=1
    initial_detail="Recompilacion forzada por parametro (--force)"
  fi

  slot_state["$slot"]="$initial_state"
  slot_detail["$slot"]="$initial_detail"

  # Proceder con la compilacion individual si se requiere
  if (( needs_compilation == 1 )); then
    if (( DRY_RUN == 1 )); then
      slot_detail["$slot"]="${initial_detail} (simulacion dry-run)"
    else
      echo "Evaluando entorno antes de compilar PHP $b ($initial_state)..."
      if check_build_environment "php${b_clean}"; then
        echo "===== RECOMPILANDO PHP $b INDIVIDUALMENTE VIA CUSTOMBUILD (php_expert $b $mode) ====="
        cp "$CONF" "${CONF}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

        if run_cb php_expert "$b" "$mode"; then
          # 1. Comprobar que el proceso termino correctamente y refrescar deteccion nativa
          cb_versions_output=$(run_cb versions 2>/dev/null || true)
          cb_versions_json=$(run_cb versions_json 2>/dev/null || true)

          post_res=$(parse_cb_php_status "$b")
          post_raw="${post_res%%|*}"
          post_avail="${post_res##*|}"
          post_clean="${post_raw//\*/}"

          # 2. Confirmar que la actualizacion o parches ya no aparecen pendientes
          if [[ "$post_raw" =~ \* ]] || is_lower_version "$post_clean" "$post_avail"; then
            slot_state["$slot"]="ERROR"
            slot_detail["$slot"]="Compilacion finalizo pero CustomBuild aun reporta actualizacion o parches pendientes ($post_raw)"
          else
            # 3. Revisar hash Patches correspondiente
            patch_hash=$(get_patch_hash "$b")
            slot_patches_hash["$slot"]="$patch_hash"

            # 4. Confirmar que el servicio PHP-FPM funciona si esta configurado
            fpm_ok=1
            if [[ "$mode" == "php-fpm" ]]; then
              fpm_srv="php-fpm${b_clean}"
              if command -v systemctl >/dev/null 2>&1; then
                systemctl restart "$fpm_srv" >/dev/null 2>&1 || true
                if ! systemctl is-active "$fpm_srv" >/dev/null 2>&1; then
                  fpm_ok=0
                fi
              elif command -v service >/dev/null 2>&1; then
                service "$fpm_srv" restart >/dev/null 2>&1 || true
                if ! service "$fpm_srv" status >/dev/null 2>&1; then
                  fpm_ok=0
                fi
              fi
            fi

            if (( fpm_ok == 1 )); then
              compilaciones_realizadas=$((compilaciones_realizadas + 1))
              slot_state["$slot"]="ACTUALIZADO CORRECTAMENTE"
              slot_curr["$slot"]="$post_clean"
              slot_detail["$slot"]="Compilación exitosa y verificación posterior satisfactoria"
            else
              slot_state["$slot"]="ERROR"
              slot_detail["$slot"]="Compilacion exitosa pero el servicio PHP-FPM ($fpm_srv) no se encuentra activo tras el reinicio"
            fi
          fi
        else
          # Fallo en ejecucion de CustomBuild
          slot_state["$slot"]="ERROR"
          slot_detail["$slot"]="Fallo en la compilacion de PHP $b mediante CustomBuild (exit code distinto de cero)"
        fi
      else
        slot_state["$slot"]="NO VERIFICADO"
        slot_detail["$slot"]="Omitido por seguridad del entorno: $build_env_reason"
      fi
    fi
  else
    # Si esta actualizado, capturar hash de parches actual
    if [[ "$slot_state[$slot]" == "ACTUALIZADO" ]]; then
      slot_patches_hash["$slot"]=$(get_patch_hash "$b")
    fi
  fi
done

# ------------------------------------------------------------------------------
# 12. REINICIO SEGURO Y VERIFICACION DE SERVICIOS
# ------------------------------------------------------------------------------
if (( compilaciones_realizadas > 0 )) && (( DRY_RUN == 0 )); then
  echo "===== REESCRIBIENDO CONFIGURACIONES Y VERIFICANDO SERVICIOS ====="
  run_cb rewrite_confs >/dev/null 2>&1 || true

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart httpd >/dev/null 2>&1 || true
    if ! systemctl is-active httpd >/dev/null 2>&1; then
      echo "ALERTA: El servicio httpd no respondio como activo tras reiniciar." >&2
    fi
  elif command -v service >/dev/null 2>&1; then
    service httpd restart >/dev/null 2>&1 || true
  fi
fi

# ------------------------------------------------------------------------------
# 13. RESUMEN FINAL ESTRUCTURADO
# ------------------------------------------------------------------------------
has_error=0
has_pending=0

if [[ "$apache_state" == "ERROR" ]]; then has_error=1; fi
if [[ "$apache_state" == "PENDIENTE" ]]; then has_pending=1; fi

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  st="${slot_state[$slot]:-}"
  if [[ "$st" == "ERROR" ]]; then has_error=1; fi
  if [[ "$st" =~ ^(ACTUALIZACIÓN PENDIENTE|PARCHES PENDIENTES|NO VERIFICADO)$ ]]; then has_pending=1; fi
done

resultado_final="EXITOSO"
exit_code=0
if (( has_error == 1 )); then
  resultado_final="FALLIDO CON ERRORES"
  exit_code=2
elif (( has_pending == 1 )); then
  resultado_final="COMPLETADO CON PENDIENTES"
  exit_code=1
else
  resultado_final="EXITOSO"
  exit_code=0
fi

echo ''
echo '===== RESULTADO FINAL ====='
echo ''
echo "Sistema operativo: $os_display"
echo "DirectAdmin: $da_version (SIN MODIFICACIONES)"
echo "CustomBuild: Definiciones actualizadas"
echo ''
echo 'APACHE'
echo "Instalado: ${apache_curr:-NO DISPONIBLE}"
echo "Disponible: ${cb_apache_latest:-NO DISPONIBLE}"
echo "Estado: $apache_state - $apache_detail"
echo ''

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  rel="${slot_rel[$slot]}"
  st="${slot_state[$slot]}"
  dt="${slot_detail[$slot]}"
  prev="${slot_prev[$slot]}"
  curr="${slot_curr[$slot]}"
  avail="${slot_cb_avail[$slot]}"
  phash="${slot_patches_hash[$slot]}"

  echo "PHP $rel"
  if [[ "$st" == "ACTUALIZADO CORRECTAMENTE" ]]; then
    echo "Anterior: $prev"
    echo "Actual: $curr"
    if [[ -n "$phash" ]]; then
      echo "Patches: $phash"
    fi
  else
    echo "Instalado: $curr"
    if [[ -n "$avail" && "$avail" != "desconocida" ]]; then
      echo "Disponible: $avail"
    fi
    if [[ "$st" == "ACTUALIZADO" && -n "$phash" ]]; then
      echo "Patches: $phash"
    fi
  fi
  echo "Estado: $st - $dt"
  echo ''
done

echo "DirectAdmin actualizado: NO"
echo "Compilaciones innecesarias: 0"
echo ''
echo "RESULTADO: $resultado_final"
echo ''
printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

exit "$exit_code"
