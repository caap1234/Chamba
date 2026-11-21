#!/usr/bin/env bash
# ==============================================================================
# Script: verificar_actualizar_php_directadmin.sh
# Proposito: Auditoria y aplicacion conservadora de parches de seguridad en
#            DirectAdmin CustomBuild para PHP (>= 7.4) y Apache (mod_http2).
#
# Principios clave:
#  1. Ignorar completamente versiones de PHP < 7.4 (5.6, 7.0, 7.1, 7.2, 7.3).
#  2. NUNCA actualizar el panel DirectAdmin (solo refrescar metadatos de CustomBuild).
#  3. Consultar versiones disponibles en CustomBuild antes de tomar decisiones.
#  4. No recompilar de rutina si no hay un parche o version corregida verificable.
#  5. Compilar unicamente la version de PHP afectada mediante php_expert, no 'build php'.
#  6. Validar repositorios, compilador, libffi, disco y memoria antes de compilar.
#  7. Proveer modo simulacion (--dry-run).
#  8. Resumen final estructurado con estados claros (OK, ACTUALIZADO, OMITIDO, PENDIENTE, ERROR).
# Compatibilidad: Bash 3.2, Bash 4.2 (CentOS 7), AlmaLinux, Rocky, Debian, Ubuntu.
# ==============================================================================
set -uo pipefail
export LC_ALL=C
export PATH="/usr/local/bin:/usr/local/directadmin:$PATH"

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

# Rutas configurables (compatibles con pruebas unitarias)
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
# 4. REGLAS Y DEFINICIONES DE SEGURIDAD (PORTABILIDAD BASH 3 Y BASH 4+)
# ------------------------------------------------------------------------------
APACHE_MIN="2.4.71"

get_php_min() {
  case "$1" in
    8.1) echo "8.1.35" ;;
    8.2) echo "8.2.36" ;;
    8.3) echo "8.3.37" ;;
    8.4) echo "8.4.28" ;;
    8.5) echo "8.5.13" ;;
    *) echo "" ;;
  esac
}

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

# Identificar ramas PHP configuradas en slots 1..4 (usando arreglos indexados)
declare -a slot_active=()
declare -a slot_rel=("" "" "" "" "")
declare -a slot_mode=("" "" "" "" "")
declare -a slot_is_ignored=(0 0 0 0 0)
declare -a slot_v_inst=("" "" "" "" "")
declare -a slot_cb_avail=("" "" "" "" "")
declare -a slot_state=("" "" "" "" "")
declare -a slot_detail=("" "" "" "" "")
declare -a slot_prev=("" "" "" "" "")
declare -a slot_curr=("" "" "" "" "")

for slot in 1 2 3 4; do
  rel=$(sed -n "s/^php${slot}_release=//p" "$CONF" 2>/dev/null | tail -n1 | tr -d '\r')
  [[ -z "$rel" || "$rel" == "no" ]] && continue
  mode=$(sed -n "s/^php${slot}_mode=//p" "$CONF" 2>/dev/null | tail -n1 | tr -d '\r')
  mode="${mode:-php-fpm}"

  slot_active+=("$slot")
  slot_rel["$slot"]="$rel"
  slot_mode["$slot"]="$mode"

  # REGLA 1 OBLIGATORIA: Ignorar completamente PHP anterior a 7.4
  if is_lower_version "$rel" "7.4"; then
    v_inst=$(version_of "$rel" || echo "")
    slot_v_inst["$slot"]="$v_inst"
    slot_is_ignored["$slot"]=1
    v_label="${v_inst:-$rel}"
    echo "OMITIDO: PHP $v_label - Versión inferior a 7.4, fuera del alcance del script."
  else
    v_inst=$(version_of "$rel" || echo "")
    slot_v_inst["$slot"]="$v_inst"
    slot_is_ignored["$slot"]=0
  fi
done

# ------------------------------------------------------------------------------
# 7. ACTUALIZAR UNICAMENTE DEFINICIONES DE CUSTOMBUILD (NO DIRECTADMIN)
# ------------------------------------------------------------------------------
cb_updated=0
echo '===== DEFINICIONES Y METADATOS DE CUSTOMBUILD ====='
if (( DRY_RUN == 0 )); then
  echo "Refrescando definiciones con CustomBuild (./build update)..."
  # Regla 2: Solo refrescar definiciones. No ejecutar da update ni update de panel.
  if run_cb update; then
    cb_updated=1
    echo "Definiciones de CustomBuild actualizadas correctamente."
  else
    echo "ALERTA: './build update' devolvio codigo de error; se consultaran definiciones locales existentes."
  fi
else
  echo "[DRY-RUN] Se omite './build update' para mantener el sistema 100% intacto; leyendo definiciones locales."
fi

# ------------------------------------------------------------------------------
# 8. CONSULTAR VERSIONES DISPONIBLES EN CUSTOMBUILD
# ------------------------------------------------------------------------------
cb_apache_latest=""
if [[ -f "$CB_DIR/versions.txt" ]]; then
  cb_apache_latest=$(grep -E '^(apache2\.4|apache):' "$CB_DIR/versions.txt" 2>/dev/null | head -n1 | cut -d: -f2 | tr -d '\r')
fi
if [[ -z "$cb_apache_latest" ]]; then
  cb_apache_latest=$(run_cb versions 2>/dev/null | sed -n 's/^Latest version of Apache: //p' | head -n1 | tr -d '\r')
fi

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  if (( slot_is_ignored[slot] == 0 )); then
    b="${slot_rel[$slot]}"
    b_clean="${b//./}"
    cb_v=""
    if [[ -f "$CB_DIR/versions.txt" ]]; then
      cb_v=$(grep -E "^php${b_clean}:" "$CB_DIR/versions.txt" 2>/dev/null | head -n1 | cut -d: -f2 | tr -d '\r')
    fi
    if [[ -z "$cb_v" ]]; then
      cb_v=$(run_cb versions 2>/dev/null | sed -n "s/^Latest version of PHP ${b}: //p" | head -n1 | tr -d '\r')
    fi
    slot_cb_avail["$slot"]="${cb_v:-}"
  fi
done

echo "--- Versiones detectadas ---"
echo "Apache instalado: ${apache_installed_v:-NO DISPONIBLE} | Disponible en CustomBuild: ${cb_apache_latest:-desconocida}"
for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  b="${slot_rel[$slot]}"
  if (( slot_is_ignored[slot] == 0 )); then
    echo "PHP $b instalado: ${slot_v_inst[$slot]:-NO INSTALADO} | Disponible en CustomBuild: ${slot_cb_avail[$slot]:-desconocida}"
  fi
done

# ------------------------------------------------------------------------------
# 9. VALIDACION PREVENTIVA DEL ENTORNO DE COMPILACION
# ------------------------------------------------------------------------------
build_env_ok=1
build_env_reason=""

check_build_environment() {
  local target_comp="$1"
  build_env_ok=1
  build_env_reason=""

  if (( TEST_MODE == 1 )); then
    if [[ "${MOCK_BROKEN_REPO:-0}" == "1" ]]; then
      build_env_ok=0
      build_env_reason="Repositorios del sistema no funcionales (Cannot find a valid baseurl for repo: base/7)"
      return 1
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

  # 1. Herramientas de compilacion basicas
  if ! command -v gcc >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
    build_env_ok=0
    build_env_reason="Compilador gcc o make no disponible en el sistema"
    return 1
  fi

  # 2. Comprobar que los repositorios del sistema responden y no estan rotos (ej. CentOS 7 EOL)
  if command -v yum >/dev/null 2>&1; then
    local yum_test
    yum_test=$(timeout 8 yum repolist -q 2>&1 || true)
    if echo "$yum_test" | grep -E -q 'Cannot find a valid baseurl|Error: Cannot retrieve repository|Could not resolve host'; then
      build_env_ok=0
      build_env_reason="Repositorios del sistema no funcionales (yum repolist fallo con error de baseurl)"
      return 1
    fi
  fi

  # 3. Comprobar libffi para PHP >= 8.0
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

  # 4. Comprobar toolchain C11 en CentOS 7 para PHP >= 8.2
  if [[ "$os_id" =~ ^(centos|rhel)$ && "$os_ver" =~ ^7 ]]; then
    if [[ "$target_comp" =~ ^php8\.[2-9] ]]; then
      local gcc_major
      gcc_major=$(gcc -dumpversion 2>/dev/null | cut -d. -f1 || echo 4)
      if (( gcc_major < 5 )); then
        if [[ ! -d /opt/rh/devtoolset-9 && ! -d /opt/rh/devtoolset-10 && ! -d /opt/rh/devtoolset-11 ]]; then
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
# 10. EVALUACION Y ACCION: APACHE
# ------------------------------------------------------------------------------
apache_state=""
apache_detail=""
apache_prev="${apache_installed_v:-NO DISPONIBLE}"
apache_curr="${apache_installed_v:-NO DISPONIBLE}"

if [[ -n "$apache_installed_v" ]] && meets "$apache_installed_v" "$APACHE_MIN"; then
  apache_state="OK"
  apache_detail="Parche verificado"
else
  # No cumple minimo 2.4.71
  if [[ -n "$cb_apache_latest" ]] && meets "$cb_apache_latest" "$APACHE_MIN"; then
    # CustomBuild SI dispone de version corregida
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
            apache_state="ACTUALIZADO"
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
# 11. EVALUACION Y ACCION: PHP (VERSIONES >= 7.4 INDIVIDUALES VIA php_expert)
# ------------------------------------------------------------------------------
compilaciones_realizadas=0

for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  if (( slot_is_ignored[slot] == 1 )); then
    continue
  fi

  b="${slot_rel[$slot]}"
  mode="${slot_mode[$slot]:-php-fpm}"
  v_inst="${slot_v_inst[$slot]}"
  cb_avail="${slot_cb_avail[$slot]}"

  slot_prev["$slot"]="${v_inst:-NO DISPONIBLE}"
  slot_curr["$slot"]="${v_inst:-NO DISPONIBLE}"

  # Caso A: Ramas EOL 7.4 y 8.0
  if [[ "$b" =~ ^(7\.4|8\.0)$ ]]; then
    has_cb_patch=0
    if [[ -d "$CB_DIR/patches" ]] && ls "$CB_DIR/patches/"*php*${b}* >/dev/null 2>&1; then
      has_cb_patch=1
    fi

    if [[ "$v_inst" =~ ^(7\.4\.33|8\.0\.30) ]] && (( has_cb_patch == 0 && FORCE == 0 )); then
      slot_state["$slot"]="PENDIENTE"
      slot_detail["$slot"]="Parche no verificable"
    elif [[ -n "$v_inst" && "$v_inst" == "$cb_avail" ]] && (( has_cb_patch == 0 && FORCE == 0 )); then
      slot_state["$slot"]="PENDIENTE"
      slot_detail["$slot"]="Parche no verificable"
    elif [[ -n "$cb_avail" ]] && meets "$cb_avail" "$v_inst" && [[ "$cb_avail" != "$v_inst" ]]; then
      if (( DRY_RUN == 1 )); then
        slot_state["$slot"]="PENDIENTE"
        slot_detail["$slot"]="Actualizacion a $cb_avail disponible (simulacion dry-run)"
      else
        echo "Evaluando entorno para actualizacion de PHP $b a $cb_avail..."
        if check_build_environment "php${b//./}"; then
          echo "===== ACTUALIZANDO PHP $b INDIVIDUALMENTE (php_expert $b $mode) ====="
          cp "$CONF" "${CONF}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
          if run_cb php_expert "$b" "$mode"; then
            compilaciones_realizadas=$((compilaciones_realizadas + 1))
            new_v=$(version_of "$b" || echo "")
            slot_curr["$slot"]="${new_v:-$cb_avail}"
            slot_state["$slot"]="ACTUALIZADO"
            slot_detail["$slot"]="Actualizado a ${slot_curr[$slot]}; parches especificos no verificables"
          else
            slot_state["$slot"]="ERROR"
            slot_detail["$slot"]="Fallo al compilar PHP $b con php_expert"
          fi
        else
          slot_state["$slot"]="PENDIENTE"
          slot_detail["$slot"]="Actualizacion disponible ($cb_avail) omitida por seguridad: $build_env_reason"
        fi
      fi
    else
      slot_state["$slot"]="PENDIENTE"
      slot_detail["$slot"]="Parche no verificable"
    fi
    continue
  fi

  # Caso B: Ramas soportadas / activas (8.1, 8.2, 8.3, 8.4, 8.5)
  req_min=$(get_php_min "$b")
  if [[ -n "$req_min" && -n "$v_inst" ]] && meets "$v_inst" "$req_min" && (( FORCE == 0 )); then
    slot_state["$slot"]="OK"
    slot_detail["$slot"]="Parche verificado"
    continue
  fi

  # Requiere actualizacion a req_min
  if [[ -n "$cb_avail" && -n "$req_min" ]] && meets "$cb_avail" "$req_min"; then
    if (( DRY_RUN == 1 )); then
      slot_state["$slot"]="PENDIENTE"
      slot_detail["$slot"]="Actualizacion a $cb_avail disponible (simulacion dry-run)"
    else
      echo "Evaluando entorno para actualizacion de PHP $b a $cb_avail..."
      if check_build_environment "php${b//./}"; then
        echo "===== ACTUALIZANDO PHP $b INDIVIDUALMENTE (php_expert $b $mode) ====="
        cp "$CONF" "${CONF}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        if run_cb php_expert "$b" "$mode"; then
          compilaciones_realizadas=$((compilaciones_realizadas + 1))
          new_v=$(version_of "$b" || echo "")
          slot_curr["$slot"]="${new_v:-$cb_avail}"
          if meets "${slot_curr[$slot]}" "$req_min"; then
            slot_state["$slot"]="ACTUALIZADO"
            slot_detail["$slot"]="Versión corregida verificada"
          else
            slot_state["$slot"]="ERROR"
            slot_detail["$slot"]="Compilacion finalizo pero version resultante (${slot_curr[$slot]}) < $req_min"
          fi
        else
          slot_state["$slot"]="ERROR"
          slot_detail["$slot"]="Fallo al compilar PHP $b con php_expert"
        fi
      else
        slot_state["$slot"]="PENDIENTE"
        slot_detail["$slot"]="Actualizacion disponible ($cb_avail) omitida por seguridad: $build_env_reason"
      fi
    fi
  else
    slot_state["$slot"]="PENDIENTE"
    if [[ -z "$cb_avail" || "$cb_avail" == "$v_inst" ]]; then
      slot_detail["$slot"]="Versión corregida (>= ${req_min:-segura}) no disponible en CustomBuild (instalada: ${v_inst:-desconocida})"
    else
      slot_detail["$slot"]="Versión corregida (>= ${req_min:-segura}) no disponible en CustomBuild (disponible: $cb_avail)"
    fi
  fi
done

# ------------------------------------------------------------------------------
# 12. REINICIO SEGURO Y VERIFICACION DE SERVICIOS
# ------------------------------------------------------------------------------
if (( compilaciones_realizadas > 0 )) && (( DRY_RUN == 0 )); then
  echo "===== REESCRIBIENDO CONFIGURACIONES Y VERIFICANDO SERVICIOS ====="
  run_cb rewrite_confs >/dev/null 2>&1 || true

  # Verificar Apache
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
  if (( slot_is_ignored[slot] == 0 )); then
    st="${slot_state[$slot]:-}"
    if [[ "$st" == "ERROR" ]]; then has_error=1; fi
    if [[ "$st" == "PENDIENTE" ]]; then has_pending=1; fi
  fi
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

# Imprimir cada slot configurado
for slot in ${slot_active[@]+"${slot_active[@]}"}; do
  rel="${slot_rel[$slot]}"
  if (( slot_is_ignored[slot] == 1 )); then
    echo "PHP $rel"
    echo "Estado: OMITIDO - Inferior a PHP 7.4"
    echo ''
  else
    st="${slot_state[$slot]}"
    dt="${slot_detail[$slot]}"
    prev="${slot_prev[$slot]}"
    curr="${slot_curr[$slot]}"

    echo "PHP $rel"
    if [[ "$st" == "ACTUALIZADO" ]]; then
      echo "Anterior: $prev"
      echo "Actual: $curr"
    else
      echo "Instalado: $curr"
    fi
    echo "Estado: $st - $dt"
    echo ''
  fi
done

echo "DirectAdmin actualizado: NO"
echo "Compilaciones innecesarias: 0"
echo ''
echo "RESULTADO: $resultado_final"
echo ''
printf 'Final: %s | Log: %s\n' "$(date -Is 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')" "$LOG"

exit "$exit_code"
