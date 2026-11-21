#!/usr/bin/env bash
# ==============================================================================
# Suite de pruebas automatizadas para verificar_actualizar_php_directadmin.sh
# Valida la deteccion nativa de parches (DA 1.702+), estados de seguridad,
# recompilacion conservadora con php_expert, y validaciones posteriores.
# ==============================================================================
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/directadmin/verificar_actualizar_php_directadmin.sh"
TEST_TMP="/tmp/da_security_test_$$"
mkdir -p "$TEST_TMP"

cleanup() {
  rm -rf "$TEST_TMP"
}
trap cleanup EXIT

pass_count=0
fail_count=0

assert_output_contains() {
  local desc="$1"
  local needle="$2"
  local output="$3"

  if echo "$output" | grep -F -q "$needle"; then
    echo "  [PASS] $desc"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] $desc"
    echo "         Esperaba encontrar: '$needle'"
    echo "         Salida obtenida:"
    echo "$output" | sed 's/^/           /'
    fail_count=$((fail_count + 1))
  fi
}

assert_output_not_contains() {
  local desc="$1"
  local needle="$2"
  local output="$3"

  if ! echo "$output" | grep -F -q "$needle"; then
    echo "  [PASS] $desc"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] $desc"
    echo "         NO esperaba encontrar: '$needle'"
    fail_count=$((fail_count + 1))
  fi
}

assert_exit_code() {
  local desc="$1"
  local expected="$2"
  local actual="$3"

  if [[ "$expected" == "$actual" ]]; then
    echo "  [PASS] $desc (Exit Code: $actual)"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] $desc (Esperaba Exit Code: $expected, pero fue: $actual)"
    fail_count=$((fail_count + 1))
  fi
}

setup_mock_env() {
  local name="$1"
  local env_dir="$TEST_TMP/$name"
  rm -rf "$env_dir"
  mkdir -p "$env_dir/cb" "$env_dir/bin" "$env_dir/os" "$env_dir/php" "$env_dir/cb/patches"

  # Crear mock de options.conf por defecto
  cat <<'EOF' > "$env_dir/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
php2_release=7.4
php2_mode=php-fpm
php3_release=5.6
php3_mode=php-fpm
EOF

  # Crear mock de versions.txt
  cat <<'EOF' > "$env_dir/cb/versions.txt"
apache2.4:2.4.63:mockhash
php56:5.6.40:mockhash
php70:7.0.33:mockhash
php74:7.4.33:mockhash
php80:8.0.30:mockhash
php81:8.1.35:mockhash
php82:8.2.36:mockhash
php83:8.3.37:mockhash
EOF

  # Archivo de estado para respuestas de 'versions'
  cat <<'EOF' > "$env_dir/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.63
Installed version of PHP 8.2: 8.2.36
Latest version of PHP 8.2: 8.2.36
Installed version of PHP 7.4: 7.4.33
Latest version of PHP 7.4: 7.4.33
Installed version of PHP 5.6: 5.6.40
Latest version of PHP 5.6: 5.6.40
EOF

  # Mock de ./build ejecutable
  cat <<'EOF' > "$env_dir/cb/build"
#!/usr/bin/env bash
cmd="${1:-}"
cb_dir="$(cd "$(dirname "$0")" && pwd)"
case "$cmd" in
  update)
    exit 0
    ;;
  versions)
    if [[ -f "$cb_dir/versions_mock_data.txt" ]]; then
      cat "$cb_dir/versions_mock_data.txt"
    fi
    exit 0
    ;;
  php_expert)
    target_branch="$2"
    target_mode="${3:-php-fpm}"
    echo "[MOCK_CB] Compilando php_expert $target_branch $target_mode..."
    if [[ -f "$cb_dir/fail_php_expert" ]]; then
      exit 1
    fi
    # Por defecto, si compila exitosamente, quita el asterisco en versions_mock_data.txt
    if [[ -f "$cb_dir/versions_mock_data.txt" ]]; then
      sed -i.bak "s/Installed version of PHP ${target_branch}: .*\*/Installed version of PHP ${target_branch}: ${target_branch}.33/" "$cb_dir/versions_mock_data.txt" 2>/dev/null || true
    fi
    exit 0
    ;;
  apache)
    echo "[MOCK_CB] Compilando apache..."
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod +x "$env_dir/cb/build"

  # Mock de /etc/os-release
  cat <<'EOF' > "$env_dir/os/os-release"
NAME="AlmaLinux"
VERSION="8.10 (Cerulean Leopard)"
ID="almalinux"
VERSION_ID="8.10"
PRETTY_NAME="AlmaLinux 8.10 (Cerulean Leopard)"
EOF

  echo "$env_dir"
}

create_mock_php_bin() {
  local env_dir="$1"
  local branch="$2"
  local ver="$3"
  local b_clean="${branch//./}"
  mkdir -p "$env_dir/php/php${b_clean}/bin"
  cat <<EOF > "$env_dir/php/php${b_clean}/bin/php"
#!/usr/bin/env bash
if [[ "\$1" == "-r" ]]; then
  echo "$ver"
elif [[ "\$1" == "-v" ]]; then
  echo "PHP $ver (cli) (built: Nov 10 2026 12:00:00)"
else
  echo "$ver"
fi
EOF
  chmod +x "$env_dir/php/php${b_clean}/bin/php"
}

create_mock_httpd() {
  local env_dir="$1"
  local ver="$2"
  local has_http2="${3:-1}"
  mkdir -p "$env_dir/bin"
  cat <<EOF > "$env_dir/bin/httpd"
#!/usr/bin/env bash
if [[ "\$1" == "-v" ]]; then
  echo "Server version: Apache/$ver (Unix)"
elif [[ "\$1" == "-M" ]]; then
  echo "Loaded Modules:"
  echo " core_module (static)"
  if (( $has_http2 )); then
    echo " http2_module (shared)"
  fi
fi
EOF
  chmod +x "$env_dir/bin/httpd"
}

# ==============================================================================
# EJECUCION DE LOS ESCENARIOS DE PRUEBA
# ==============================================================================

echo "======================================================================"
echo "INICIANDO PRUEBAS UNITARIAS DE VERIFICAR_ACTUALIZAR_PHP_DIRECTADMIN.SH"
echo "======================================================================"

# --- Escenario 1: Deteccion de parches pendientes con asterisco (*) en dry-run ---
echo "Test 1: Servidor con parches pendientes indicados por asterisco (*) en PHP 7.4 y 5.6 (dry-run)"
ENV1=$(setup_mock_env "test1")
cat <<'EOF' > "$ENV1/cb/options.conf"
webserver=apache
php1_release=7.4
php1_mode=php-fpm
php2_release=5.6
php2_mode=php-fpm
EOF
cat <<'EOF' > "$ENV1/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 7.4: 7.4.33*
Latest version of PHP 7.4: 7.4.33
Installed version of PHP 5.6: 5.6.40*
Latest version of PHP 5.6: 5.6.40
EOF
create_mock_php_bin "$ENV1" "7.4" "7.4.33"
create_mock_php_bin "$ENV1" "5.6" "5.6.40"
create_mock_httpd "$ENV1" "2.4.71" 1

set +e
OUT1=$(TEST_MODE=1 DA_CB_DIR="$ENV1/cb" DA_CONF="$ENV1/cb/options.conf" DA_PHP_DIR="$ENV1/php" SYS_OS_RELEASE="$ENV1/os/os-release" PATH="$ENV1/bin:$PATH" bash "$SCRIPT_PATH" --dry-run 2>&1)
EXIT1=$?
set -e

assert_output_contains "Detecta asterisco en PHP 7.4 (7.4.33*)" "PHP 7.4 configurado: instalada=7.4.33* | latest=7.4.33" "$OUT1"
assert_output_contains "Detecta asterisco en PHP 5.6 (5.6.40*)" "PHP 5.6 configurado: instalada=5.6.40* | latest=5.6.40" "$OUT1"
assert_output_contains "Estado PARCHES PENDIENTES para PHP 7.4" "Estado: PARCHES PENDIENTES - Misma versión (7.4.33), nuevos parches disponibles" "$OUT1"
assert_output_contains "Estado PARCHES PENDIENTES para PHP 5.6" "Estado: PARCHES PENDIENTES - Misma versión (5.6.40), nuevos parches disponibles" "$OUT1"
assert_output_not_contains "No compila en modo dry-run" "[MOCK_CB] Compilando php_expert" "$OUT1"
assert_exit_code "Dry-run con parches pendientes finaliza con codigo 1" "1" "$EXIT1"

# --- Escenario 2: Recompilacion de parches pendientes (7.4.33*) a ACTUALIZADO CORRECTAMENTE ---
echo "Test 2: Recompilacion exitosa de PHP 7.4.33* tras parches pendientes"
ENV2=$(setup_mock_env "test2")
cat <<'EOF' > "$ENV2/cb/options.conf"
webserver=apache
php1_release=7.4
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV2/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 7.4: 7.4.33*
Latest version of PHP 7.4: 7.4.33
EOF
create_mock_php_bin "$ENV2" "7.4" "7.4.33"
create_mock_httpd "$ENV2" "2.4.71" 1

# Mock de php_expert que quita el asterisco post-compilacion
cat <<'EOF' > "$ENV2/cb/build"
#!/usr/bin/env bash
cmd="${1:-}"
cb_dir="$(cd "$(dirname "$0")" && pwd)"
case "$cmd" in
  update) exit 0 ;;
  versions)
    cat "$cb_dir/versions_mock_data.txt"
    exit 0
    ;;
  php_expert)
    # Quitar el asterisco de versions_mock_data.txt para simular que ya se aplico el parche
    cat <<'VEREOF' > "$cb_dir/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 7.4: 7.4.33
Latest version of PHP 7.4: 7.4.33
VEREOF
    echo "[MOCK_CB] Compilando php_expert 7.4 php-fpm..."
    exit 0
    ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$ENV2/cb/build"

set +e
OUT2=$(TEST_MODE=1 DA_CB_DIR="$ENV2/cb" DA_CONF="$ENV2/cb/options.conf" DA_PHP_DIR="$ENV2/php" SYS_OS_RELEASE="$ENV2/os/os-release" PATH="$ENV2/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT2=$?
set -e

assert_output_contains "Llama a php_expert 7.4 individualmente" "[MOCK_CB] Compilando php_expert 7.4 php-fpm..." "$OUT2"
assert_output_contains "Reporta estado ACTUALIZADO CORRECTAMENTE" "Estado: ACTUALIZADO CORRECTAMENTE - Compilación exitosa y verificación posterior satisfactoria" "$OUT2"
assert_output_contains "Muestra version previa con asterisco" "Anterior: 7.4.33*" "$OUT2"
assert_output_contains "Muestra version actual limpia" "Actual: 7.4.33" "$OUT2"
assert_output_contains "Muestra identificador Patches" "Patches: d41d8cd98f00" "$OUT2"
assert_exit_code "Exit code es 0 al quedar todo actualizado correctamente" "0" "$EXIT2"

# --- Escenario 3: PHP 8.2 vulnerable (8.2.10) y version superior disponible (8.2.36) ---
echo "Test 3: PHP 8.2 con actualizacion pendiente (8.2.10 -> 8.2.36)"
ENV3=$(setup_mock_env "test3")
cat <<'EOF' > "$ENV3/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV3/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 8.2: 8.2.10
Latest version of PHP 8.2: 8.2.36
EOF
create_mock_php_bin "$ENV3" "8.2" "8.2.10"
create_mock_httpd "$ENV3" "2.4.71" 1

cat <<'EOF' > "$ENV3/cb/build"
#!/usr/bin/env bash
cmd="${1:-}"
cb_dir="$(cd "$(dirname "$0")" && pwd)"
case "$cmd" in
  update) exit 0 ;;
  versions)
    cat "$cb_dir/versions_mock_data.txt"
    exit 0
    ;;
  php_expert)
    cat <<'VEREOF' > "$cb_dir/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 8.2: 8.2.36
Latest version of PHP 8.2: 8.2.36
VEREOF
    cat <<'PHPEOF' > "$DA_PHP_DIR/php82/bin/php"
#!/usr/bin/env bash
if [[ "$1" == "-r" ]]; then echo "8.2.36"; else echo "PHP 8.2.36"; fi
PHPEOF
    chmod +x "$DA_PHP_DIR/php82/bin/php"
    echo "[MOCK_CB] Compilado php_expert 8.2 php-fpm a 8.2.36 exitosamente"
    exit 0
    ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$ENV3/cb/build"

set +e
OUT3=$(TEST_MODE=1 DA_CB_DIR="$ENV3/cb" DA_CONF="$ENV3/cb/options.conf" DA_PHP_DIR="$ENV3/php" SYS_OS_RELEASE="$ENV3/os/os-release" PATH="$ENV3/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT3=$?
set -e

assert_output_contains "Llama a php_expert 8.2" "[MOCK_CB] Compilado php_expert 8.2 php-fpm a 8.2.36 exitosamente" "$OUT3"
assert_output_contains "Reporta estado ACTUALIZADO CORRECTAMENTE" "Estado: ACTUALIZADO CORRECTAMENTE - Compilación exitosa y verificación posterior satisfactoria" "$OUT3"
assert_output_contains "Muestra version anterior 8.2.10" "Anterior: 8.2.10" "$OUT3"
assert_output_contains "Muestra version actual 8.2.36" "Actual: 8.2.36" "$OUT3"
assert_exit_code "Exit code es 0 al quedar todo actualizado" "0" "$EXIT3"

# --- Escenario 4: CentOS 7 con repositorios rotos ---
echo "Test 4: Servidor CentOS 7 con repositorios rotos"
ENV4=$(setup_mock_env "test4")
cat <<'EOF' > "$ENV4/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV4/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 8.2: 8.2.10
Latest version of PHP 8.2: 8.2.36
EOF
create_mock_php_bin "$ENV4" "8.2" "8.2.10"
create_mock_httpd "$ENV4" "2.4.71" 1

set +e
OUT4=$(TEST_MODE=1 MOCK_BROKEN_REPO=1 DA_CB_DIR="$ENV4/cb" DA_CONF="$ENV4/cb/options.conf" DA_PHP_DIR="$ENV4/php" SYS_OS_RELEASE="$ENV4/os/os-release" PATH="$ENV4/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT4=$?
set -e

assert_output_contains "Detecta repositorios rotos y omite compilacion" "Repositorios del sistema no funcionales" "$OUT4"
assert_output_not_contains "No ejecuta php_expert si repos estan rotos" "[MOCK_CB] Compilando" "$OUT4"
assert_output_contains "Queda como NO VERIFICADO sin provocar fallo destructor" "Estado: NO VERIFICADO" "$OUT4"

# --- Escenario 4b: CentOS 7 con repositorios descontinuados autorreparados hacia vault ---
echo "Test 4b: Servidor CentOS 7 con repositorios descontinuados autorreparados a vault"
set +e
OUT4B=$(TEST_MODE=1 MOCK_BROKEN_REPO=1 MOCK_ALLOW_VAULT_FIX=1 DA_CB_DIR="$ENV4/cb" DA_CONF="$ENV4/cb/options.conf" DA_PHP_DIR="$ENV4/php" SYS_OS_RELEASE="$ENV4/os/os-release" PATH="$ENV4/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT4B=$?
set -e

assert_output_contains "Detecta repositorios descontinuados y aplica redireccion" "Redirigiendo a vault.centos.org" "$OUT4B"
assert_output_contains "Confirma repositorios redirigidos exitosamente" "Repositorios de CentOS 7 redirigidos exitosamente a vault.centos.org" "$OUT4B"

# --- Escenario 5: Servidor con libffi faltante ---
echo "Test 5: Servidor con libffi faltante"
ENV5=$(setup_mock_env "test5")
cat <<'EOF' > "$ENV5/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV5/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 8.2: 8.2.10
Latest version of PHP 8.2: 8.2.36
EOF
create_mock_php_bin "$ENV5" "8.2" "8.2.10"
create_mock_httpd "$ENV5" "2.4.71" 1

set +e
OUT5=$(TEST_MODE=1 MOCK_MISSING_LIBFFI=1 DA_CB_DIR="$ENV5/cb" DA_CONF="$ENV5/cb/options.conf" DA_PHP_DIR="$ENV5/php" SYS_OS_RELEASE="$ENV5/os/os-release" PATH="$ENV5/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT5=$?
set -e

assert_output_contains "Detecta dependencia critica libffi faltante" "libffi >= 3.0.11 no encontrada" "$OUT5"
assert_output_not_contains "No intenta compilar si falta libffi" "[MOCK_CB] Compilando" "$OUT5"
assert_output_contains "Estado NO VERIFICADO" "Estado: NO VERIFICADO" "$OUT5"

# --- Escenario 6: Apache 2.4.63 disponible y objetivo 2.4.71 ---
echo "Test 6: Apache disponible en CustomBuild es 2.4.63 (< 2.4.71)"
ENV6=$(setup_mock_env "test6")
cat <<'EOF' > "$ENV6/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV6/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.63
Installed version of PHP 8.2: 8.2.36
Latest version of PHP 8.2: 8.2.36
EOF
create_mock_php_bin "$ENV6" "8.2" "8.2.36"
create_mock_httpd "$ENV6" "2.4.54" 1

set +e
OUT6=$(TEST_MODE=1 DA_CB_DIR="$ENV6/cb" DA_CONF="$ENV6/cb/options.conf" DA_PHP_DIR="$ENV6/php" SYS_OS_RELEASE="$ENV6/os/os-release" PATH="$ENV6/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT6=$?
set -e

assert_output_contains "Registra que el parche de Apache sigue pendiente" "Estado: PENDIENTE - Requiere >= 2.4.71 para mod_http2" "$OUT6"
assert_output_not_contains "No compila Apache si solo hay 2.4.63" "[MOCK_CB] Compilando apache" "$OUT6"
assert_exit_code "Exit code 1 (pendiente, no error destructor)" "1" "$EXIT6"

# --- Escenario 7: Apache y PHP ya cumplen requisitos sin pendientes ---
echo "Test 7: Servidor donde Apache y PHP ya cumplen (sin asterisco ni actualizacion pendiente)"
ENV7=$(setup_mock_env "test7")
cat <<'EOF' > "$ENV7/cb/options.conf"
webserver=apache
php1_release=8.2
php1_mode=php-fpm
php2_release=7.4
php2_mode=php-fpm
EOF
cat <<'EOF' > "$ENV7/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 8.2: 8.2.36
Latest version of PHP 8.2: 8.2.36
Installed version of PHP 7.4: 7.4.33
Latest version of PHP 7.4: 7.4.33
EOF
create_mock_php_bin "$ENV7" "8.2" "8.2.36"
create_mock_php_bin "$ENV7" "7.4" "7.4.33"
create_mock_httpd "$ENV7" "2.4.71" 1

set +e
OUT7=$(TEST_MODE=1 DA_CB_DIR="$ENV7/cb" DA_CONF="$ENV7/cb/options.conf" DA_PHP_DIR="$ENV7/php" SYS_OS_RELEASE="$ENV7/os/os-release" PATH="$ENV7/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT7=$?
set -e

assert_output_contains "Apache instalado 2.4.71" "Instalado: 2.4.71" "$OUT7"
assert_output_contains "Apache en estado OK" "Estado: OK - Parche verificado" "$OUT7"
assert_output_contains "PHP 8.2 en estado ACTUALIZADO" "Estado: ACTUALIZADO - Versión y parches al día" "$OUT7"
assert_output_contains "PHP 7.4 en estado ACTUALIZADO" "Estado: ACTUALIZADO - Versión y parches al día" "$OUT7"
assert_output_contains "Resultado final EXITOSO" "RESULTADO: EXITOSO" "$OUT7"
assert_exit_code "Exit code 0" "0" "$EXIT7"

# --- Escenario 8: Falla en compilacion de php_expert debe reportar ERROR ---
echo "Test 8: Falla en compilacion de CustomBuild (exit code != 0)"
ENV8=$(setup_mock_env "test8")
cat <<'EOF' > "$ENV8/cb/options.conf"
webserver=apache
php1_release=7.4
php1_mode=php-fpm
EOF
cat <<'EOF' > "$ENV8/cb/versions_mock_data.txt"
Latest version of Apache: 2.4.71
Installed version of PHP 7.4: 7.4.33*
Latest version of PHP 7.4: 7.4.33
EOF
touch "$ENV8/cb/fail_php_expert"
create_mock_php_bin "$ENV8" "7.4" "7.4.33"
create_mock_httpd "$ENV8" "2.4.71" 1

set +e
OUT8=$(TEST_MODE=1 DA_CB_DIR="$ENV8/cb" DA_CONF="$ENV8/cb/options.conf" DA_PHP_DIR="$ENV8/php" SYS_OS_RELEASE="$ENV8/os/os-release" PATH="$ENV8/bin:$PATH" bash "$SCRIPT_PATH" 2>&1)
EXIT8=$?
set -e

assert_output_contains "Reporta estado ERROR ante fallo en php_expert" "Estado: ERROR - Fallo en la compilacion de PHP 7.4 mediante CustomBuild" "$OUT8"
assert_output_contains "Resultado final FALLIDO" "RESULTADO: FALLIDO" "$OUT8"
assert_exit_code "Exit code es 2 por fallo de compilacion" "2" "$EXIT8"

# --- Escenario 9: En ningun caso actualiza DirectAdmin ---
echo "Test 9: Verificar que DirectAdmin NUNCA se actualiza"
assert_output_contains "Reporta DirectAdmin actualizado: NO" "DirectAdmin actualizado: NO" "$OUT1"
if ! grep -E '^[[:space:]]*da update\b' "$SCRIPT_PATH" >/dev/null 2>&1; then
  echo "  [PASS] No contiene llamadas al comando 'da update'"
  pass_count=$((pass_count + 1))
else
  echo "  [FAIL] Se detectaron llamadas activas a 'da update'"
  fail_count=$((fail_count + 1))
fi

if ! grep -E '(update_da\b)' "$SCRIPT_PATH" >/dev/null 2>&1; then
  echo "  [PASS] No contiene llamadas a 'update_da'"
  pass_count=$((pass_count + 1))
else
  echo "  [FAIL] Se detectaron llamadas activas a 'update_da'"
  fail_count=$((fail_count + 1))
fi

# --- Escenario 10: Modo --dry-run no compila nada ---
echo "Test 10: Modo --dry-run"
set +e
OUT10=$(TEST_MODE=1 DA_CB_DIR="$ENV2/cb" DA_CONF="$ENV2/cb/options.conf" DA_PHP_DIR="$ENV2/php" SYS_OS_RELEASE="$ENV2/os/os-release" PATH="$ENV2/bin:$PATH" bash "$SCRIPT_PATH" --dry-run 2>&1)
EXIT10=$?
set -e
assert_output_contains "Muestra banner de dry-run" "MODO SIMULACION (--dry-run) ACTIVADO" "$OUT10"
assert_output_not_contains "No compila en dry-run" "[MOCK_CB] Compilando php_expert" "$OUT10"

echo ""
echo "======================================================================"
echo "RESUMEN DE PRUEBAS: $pass_count PASADAS | $fail_count FALLADAS"
echo "======================================================================"

if (( fail_count > 0 )); then
  exit 1
fi
exit 0
