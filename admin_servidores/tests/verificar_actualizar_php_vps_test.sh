#!/usr/bin/env bash
# Ejecutar con Bash 4.4+; los comandos de paquetes y servicios son mocks.
set -uo pipefail
test_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../verificar_actualizar_php_vps.sh
source "$test_dir/../verificar_actualizar_php_vps.sh"

work=$(mktemp -d "${TMPDIR:-/tmp}/php-security-test.XXXXXXXX") || exit 1
trap 'rm -rf -- "$work"' EXIT
passed=0

fail() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }
pass() { passed=$((passed + 1)); printf 'OK: %s\n' "$*"; }
expect() { [[ "$1" == "$2" ]] || fail "esperado [$1], obtenido [$2]"; }
run_status() {
  local expected=$1 actual=0
  shift
  "$@" > "$work/test-output" 2>&1 || actual=$?
  if [[ "$expected" != "$actual" ]]; then cat "$work/test-output"; fail "$*: código $actual (esperado $expected)"; fi
}

today=2026-11-23
os=centos release=7.9 major=7 pretty='CentOS Linux 7'
lifecycle
expect eol "$status_os"
expect rpm "$family"
release=9 major=9 pretty='CentOS Stream 9'
lifecycle
expect supported "$status_os"
os=debian release=11 major=11
lifecycle
expect eol "$status_os"
os=debian release=13 major=13
lifecycle
expect trixie "$codename"
expect supported "$status_os"
os=ubuntu release=26.04 major=26
lifecycle
expect resolute "$codename"
os=rocky release=11 major=11
lifecycle
expect unknown "$status_os"
pass 'ciclo de vida, CentOS Stream y EOL'

expect 8.3 "$(branch_of '2:8.3.6-0ubuntu0.24.04.14')"
expect 8.3.6 "$(upstream_of '2:8.3.6-0ubuntu0.24.04.14')"
expect 8.3.37 "$(reference 8.3)"
expect 'EOL upstream' "$(php_support 8.1)"
for path in /usr/sbin/php-fpm8.3 /opt/remi/php82/root/usr/sbin/php-fpm /usr/bin/php-cgi8.3 /usr/lib/apache2/modules/libphp8.3.so; do
  php_path "$path" || fail "$path"
done
if php_path /var/www/vendor/phpunit; then fail 'phpunit no es una instalación PHP'; fi
pass 'detección de CLI/FPM/CGI/mod_php y ramas'

mkdir -p "$work/panel/usr/local/cpanel" "$work/usr/bin/php" || fail 'fixture de inventario'
expect ninguno "$(detect_panel "$work/panel")"
touch "$work/panel/usr/local/cpanel/cpanel"
expect ninguno "$(detect_panel "$work/panel")"
chmod +x "$work/panel/usr/local/cpanel/cpanel"
expect cPanel "$(detect_panel "$work/panel")"
mkdir -p "$work/da/usr/local/"{directadmin,cpanel} || fail 'fixture de DirectAdmin'
expect ninguno "$(detect_panel "$work/da")"
touch "$work/da/usr/local/directadmin/directadmin"
expect ninguno "$(detect_panel "$work/da")"
chmod +x "$work/da/usr/local/directadmin/directadmin"
expect DirectAdmin "$(detect_panel "$work/da")"
for path in /etc/php /usr/lib/php /etc/init.d/php8.3-fpm /usr/share/doc/php8.3 "$work/usr/bin/php"; do
  if packaged_php_path "$path"; then fail "ruta ajena a PHP ejecutable: $path"; fi
done
packaged_php_path "$work/usr/sbin/php-fpm8.3" || fail 'un FPM ausente todavía debe detectarse'
packaged_php_path /usr/lib/apache2/modules/libphp8.3.so || fail 'mod_php omitido'
pass 'los directorios residuales de cPanel o DirectAdmin y las rutas auxiliares de PHP no generan falsos positivos'

cat > "$work/apt-repos" <<'FIXTURE'
Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 http://archive.ubuntu.com/ubuntu noble-updates/main arm64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=arm64
     origin archive.ubuntu.com
 500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble/main arm64 Packages
     release v=24.04,o=LP-PPA-ondrej-php,a=noble,n=noble,l=PHP,c=main,b=arm64
     origin ppa.launchpadcontent.net
FIXTURE
key=php8.3-fpm:arm64
cat > "$work/policy.$key" <<'FIXTURE'
php8.3-fpm:arm64:
  Installed: 8.3.6-0ubuntu0.24.04.13
  Candidate: 8.3.6-0ubuntu0.24.04.14
  Version table:
     8.3.6-0ubuntu0.24.04.14 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main arm64 Packages
 *** 8.3.6-0ubuntu0.24.04.13 100
        500 http://archive.ubuntu.com/ubuntu noble-updates/main arm64 Packages
        100 /var/lib/dpkg/status
     8.3.37-1+ubuntu24.04.1+deb.sury.org+1 100
        100 https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble/main arm64 Packages
FIXTURE
expect ubuntu "$(apt_origin "$key" 8.3.6-0ubuntu0.24.04.13)"
expect ubuntu "$(apt_origin "$key" 8.3.6-0ubuntu0.24.04.14)"
expect sury "$(apt_origin "$key" 8.3.37-1+ubuntu24.04.1+deb.sury.org+1)"
cat >> "$work/policy.$key" <<'FIXTURE'
     8.3.6-0ubuntu0.24.04.14 500
        500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble/main arm64 Packages
FIXTURE
expect $'sury\nubuntu' "$(apt_origin "$key" 8.3.6-0ubuntu0.24.04.14)"
pass 'repositorio por revisión exacta, arquitectura y proveedor ambiguo'

if ! command -v dpkg >/dev/null; then
  # Fixtures ordenados para macOS. En Linux se prueba la comparación nativa.
  dpkg() {
    [[ "$1" == --compare-versions ]] || fail "llamada DPKG inesperada: $*"
    local a b
    case "$2" in *.13) a=13 ;; *.14) a=14 ;; *) fail "$2" ;; esac
    case "$4" in *.13) b=13 ;; *.14) b=14 ;; *) fail "$4" ;; esac
    case "$3" in ge) (( a >= b )) ;; lt) (( a < b )) ;; gt) (( a > b )) ;; *) fail "$3" ;; esac
  }
fi
os=ubuntu
for cve in $(campaign_cves 8.3); do
  printf 'php8.3\t%s\t8.3.6-0ubuntu0.24.04.14\tsecurity\n' "$cve"
done > "$work/tracker.tsv"
run_status 0 tracker_evidence php8.3 8.3.6-0ubuntu0.24.04.14 8.3
run_status 1 tracker_evidence php8.3 8.3.6-0ubuntu0.24.04.13 8.3
run_status 0 tracker_fix_available php8.3 8.3.6-0ubuntu0.24.04.13 8.3.6-0ubuntu0.24.04.14
: > "$work/tracker.tsv"
run_status 3 tracker_evidence php8.3 8.3.6-0ubuntu0.24.04.14 8.3
printf 'php8.3 (8.3.6-0ubuntu0.24.04.14) noble-security; urgency=medium\n  * security CVE-2026-129289\n' > "$work/changelog"
run_status 3 changelog_evidence "$work/changelog" 8.3.6-0ubuntu0.24.04.14 8.3
pass 'backport corregido, revisión vulnerable y evidencia insuficiente'

printf '%s %s\n' "$key" 8.3.6-0ubuntu0.24.04.14 > "$work/approved"
cat > "$work/plan.test" <<'FIXTURE'
Inst php8.3-fpm [8.3.6-0ubuntu0.24.04.13] (8.3.6-0ubuntu0.24.04.14 Ubuntu:24.04/noble-security [arm64])
Conf php8.3-fpm (8.3.6-0ubuntu0.24.04.14 Ubuntu:24.04/noble-security [arm64])
FIXTURE
run_status 0 validate_apt_plan "$work/approved" "$work/plan.test"
cp "$work/plan.test" "$work/extra"
echo 'Inst php8.4-fpm (8.4.28 Ubuntu:24.04/noble-security [arm64])' >> "$work/extra"
run_status 1 validate_apt_plan "$work/approved" "$work/extra"
cp "$work/plan.test" "$work/remove"
echo 'Remv php8.3-gd [8.3.6]' >> "$work/remove"
run_status 1 validate_apt_plan "$work/approved" "$work/remove"
sed 's/arm64/amd64/g' "$work/plan.test" > "$work/wrong-arch"
run_status 1 validate_apt_plan "$work/approved" "$work/wrong-arch"
sed '/^Inst /s/$/ []/' "$work/plan.test" > "$work/apt-empty-suffix"
run_status 0 validate_apt_plan "$work/approved" "$work/apt-empty-suffix"
sed '/^Inst /s/$/ [paquete-pendiente]/' "$work/plan.test" > "$work/apt-unresolved"
run_status 1 validate_apt_plan "$work/approved" "$work/apt-unresolved"
sed '/^Conf /s/php8.3-fpm/php8.3-gd/' "$work/plan.test" > "$work/apt-unapproved-conf"
run_status 1 validate_apt_plan "$work/approved" "$work/apt-unapproved-conf"
pass 'guardia APT rechaza altas, bajas y arquitectura distinta'

run_status 0 rpm_modularity_compatible 'php:remi-8.3:42:xyz' 0:8.3.37-1.module_el9.remi remi-modular
run_status 1 rpm_modularity_compatible 'php:remi-8.3:42:xyz' 0:8.4.28-1.module_el9.remi remi-modular
run_status 1 rpm_modularity_compatible 'php:remi-8.3:42:xyz' 0:8.3.37-1.module_el9 appstream
expect remi "$(rpm_provider "Remi's RPM repository <https://rpms.remirepo.net/> #StandWithUkraine")"
expect remi "$(rpm_provider "Remi's RPM repository <https://rpms.remirepo.net/>")"
expect remi "$(rpm_provider "Remi's RPM repository <https://rpms.remirepo.net/> #StandWithUkraine #NoAI")"
expect '' "$(rpm_provider "Remi's RPM repository <https://rpms.remirepo.net/> otro proveedor")"
expect '' "$(rpm_provider "Remi's RPM repository <https://example.test/> #StandWithUkraine")"
for branch in 8.2 8.4; do
  revision="0:$(reference "$branch")-1.module_php.$branch.el9.remi"
  srpm="php-${revision#*:}.src.rpm"
  expect remi "$(rpm_candidate_provider '' remi-modular "$revision" "$srpm")"
  expect remi "$(rpm_candidate_provider '(none)' remi-modular "$revision" "$srpm")"
  expect '' "$(rpm_candidate_provider 'Otro proveedor' remi-modular "$revision" "$srpm")"
  expect '' "$(rpm_candidate_provider '' appstream "$revision" "$srpm")"
  expect '' "$(rpm_candidate_provider '' remi-modular "$revision" "otro-$srpm")"
done
(
  rpm_compare() { [[ "$1:$2:$3" == gt:0:8.4.28-1.module_php.8.4.el9.remi:0:8.4.24-1.module_php.8.4.el9.remi ]]; }
  old=0:8.4.24-1.module_php.8.4.el9.remi
  new=0:8.4.28-1.module_php.8.4.el9.remi
  expect '' "$(rpm_candidate_rejection unique "$old" "$new" "php-${old#*:}.src.rpm" \
    "php-${new#*:}.src.rpm" remi remi remi-modular remi-modular php:remi-8.4:123:abcd 8.4)"
  expect 'el proveedor del candidato no coincide o no se pudo verificar' \
    "$(rpm_candidate_rejection unique "$old" "$new" "php-${old#*:}.src.rpm" \
    "php-${new#*:}.src.rpm" remi '' remi-modular remi-modular php:remi-8.4:123:abcd 8.4)"
) || fail 'validación del candidato Remi de los logs'
pass 'RPM conserva rama y origen modular'

(
  declare -A installed=() planned=(["$key"]=8.3.6-0ubuntu0.24.04.14)
  declare -A extension_before=()
  technical=0 pending=0 status_os=supported panel=ninguno
  discover_services() { echo discover >> "$work/calls"; }
  preflight() { echo preflight >> "$work/calls"; }
  make_plan() { echo simulate >> "$work/calls"; }
  affected_services() { echo service-test >> "$work/calls"; }
  backup_configuration() { fail 'respaldo durante auditoría'; }
  apply_plan() { fail 'instalación inesperada'; }
  post_validate() { fail 'validación de reinicio inesperada'; }

  mode=check
  process_plan
  expect discover "$(cat "$work/calls")"
  : > "$work/calls"
  mode=dry-run
  process_plan
  expect $'preflight\nsimulate\nservice-test' "$(cat "$work/calls")"
  : > "$work/calls"
  mode=update status_os=eol
  process_plan
  expect discover "$(cat "$work/calls")"
  : > "$work/calls"
  mode=update status_os=supported panel=cPanel
  process_plan
  expect discover "$(cat "$work/calls")"
) || fail 'modalidades sin modificaciones'
pass 'check y dry-run no aplican ni reinician, update se bloquea en EOL y con panel'

(
  declare -A planned=() planned_repo=()
  declare -a apt_options=()
  pending=0 indeterminate=0 technical=0 family=apt
  os=ubuntu release=24.04 codename=noble major=24 esm_infra=disabled esm_apps=disabled
  apt_evidence() { [[ "$2" == 8.3.6-0ubuntu0.24.04.14 ]] || return 1; }
  apt-cache() {
    if [[ "$1" == policy ]]; then cat "$work/apt-fixture"
    elif [[ "$1" == show ]]; then printf 'Source: %s\n\n' "$candidate_source"
    else fail "comando de mock APT inesperado: $*"; fi
  }
  printf '%s|%s|php8.3|%s|installed|Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n' \
    "$key" 8.3.6-0ubuntu0.24.04.13 8.3.6-0ubuntu0.24.04.13 > "$work/packages"
  candidate_source=php8.3
  : > "$work/holds"
  # Elimina la fuente ambigua agregada en la prueba de políticas anterior.
  awk 'NR<=10' "$work/policy.$key" > "$work/apt-fixture"
  audit_apt > "$work/audit"
  expect 8.3.6-0ubuntu0.24.04.14 "${planned[$key]:-}"
  planned=()
  printf '%s\n' "$key" > "$work/holds"
  audit_apt > "$work/audit"
  expect 0 "${#planned[@]}"
  : > "$work/holds"
  candidate_source='php8.4 (8.4.28-1ubuntu1)'
  audit_apt > "$work/audit"
  expect 0 "${#planned[@]}"
  grep -Fq 'cambio de rama' "$work/audit" || fail 'la migración de rama debe explicarse'
) || fail 'selección APT'
pass 'auditoría APT aprueba el backport y evita paquetes retenidos o cambios de rama'

if command -v python3 >/dev/null; then
  manager=dnf
  declare -a rpm_options=() rpm_transaction=()
  rpm_python=$(command -v true)
  [[ "$rpm_python" == /* ]] || rpm_python=/usr/bin/true
  build_rpm_guard || fail 'generación del plugin DNF'
  printf '%s\n' 'php-fpm.x86_64 0:8.3.37-1.remi remi-modular' > "$work/approved.rpm"
  printf '%s\n' 'php-fpm.x86_64 0:8.3.36-1.remi' > "$work/previous"
  python3 - "$work" <<'PY' || fail 'guardia del plugin DNF y configuración'
import importlib.util
import pathlib
import sys
import types

directory = pathlib.Path(sys.argv[1])
dnf = types.ModuleType("dnf")
dnf.exceptions = types.ModuleType("dnf.exceptions")

class Error(Exception):
    pass

class Plugin:
    def __init__(self, base, cli):
        self.base = base

dnf.exceptions.Error = Error
dnf.Plugin = Plugin
upgrade = types.ModuleType("dnf.cli.commands.upgrade")
upgrade.UpgradeCommand = object
sys.modules.update({"dnf": dnf, "dnf.exceptions": dnf.exceptions,
                    "dnf.cli.commands.upgrade": upgrade})
spec = importlib.util.spec_from_file_location("guard", directory / "plugins" / "vps_php_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
def package(name, version, repoid):
    return types.SimpleNamespace(name=name, arch="x86_64", epoch=0,
                                 version=version, release="1.remi", repoid=repoid)
existing = package("php-fpm", "8.3.36", "@System")
candidate = package("php-fpm", "8.3.37", "remi-modular")
transaction = types.SimpleNamespace(install_set=[candidate], remove_set=[existing])
plugin = guard.Guard(types.SimpleNamespace(transaction=transaction), None)
plugin.resolved()
assert (directory / "dnf.guarded").exists()
for install, remove in [
    ([package("php-fpm", "8.3.37", "appstream")], [existing]),
    ([package("php-fpm", "8.4.28", "remi-modular")], [existing]),
    ([candidate, package("php-gd", "8.3.37", "remi-modular")], [existing]),
    ([candidate], [existing, package("php-gd", "8.3.36", "@System")]),
]:
    transaction.install_set, transaction.remove_set = install, remove
    try:
        plugin.resolved()
    except Error as error:
        detail = str(error)
        assert "plan de DNF difiere" in detail
        for package_item in install:
            if package_item.repoid != candidate.repoid or package_item.version != candidate.version or package_item.name != candidate.name:
                assert "entrada no prevista: {}.{}".format(package_item.name, package_item.arch) in detail
        if len(remove) > 1:
            assert "salida no prevista: php-gd.x86_64" in detail
        continue
    raise AssertionError("la guardia aceptó un cambio fuera de la transacción aprobada")

config_spec = importlib.util.spec_from_file_location("config_guard", directory / "config_guard.py")
config_guard = importlib.util.module_from_spec(config_spec)
config_spec.loader.exec_module(config_guard)
assert config_guard.remi_vendor("Remi's RPM repository <https://rpms.remirepo.net/> #StandWithUkraine #NoAI")
assert not config_guard.remi_vendor("Remi's RPM repository <https://example.test/> #NoAI")
assert not config_guard.remi_vendor("Remi's RPM repository <https://rpms.remirepo.net/> otro proveedor")
import hashlib
configuration = directory / "php.ini"
configuration.write_bytes(b"memory_limit=256M\n")
config_guard.require_same(str(configuration), hashlib.sha256(configuration.read_bytes()).hexdigest(), "sha256")
try:
    config_guard.require_same(str(configuration), hashlib.sha256(b"memory_limit=128M\n").hexdigest(), "sha256")
except ValueError:
    pass
else:
    raise AssertionError("la guardia aceptó reemplazar una configuración existente")
PY
  pass 'resolución DNF rechaza otro proveedor, rama, altas o bajas y valida digest de configuración'
fi

# La consola ejecuta un envoltorio sh con stdin cerrado y registra el estado
# después de ejecutar el comando del usuario.
script="$test_dir/../verificar_actualizar_php_vps.sh"
cat > "$work/ssh-wrapper" <<'SH'
cat "$1" | "$2" -s -- "$3"
printf '%s\n' "$?" > "$4"
SH
for argument in --help --opcion-invalida; do
  sh "$work/ssh-wrapper" "$script" "$BASH" "$argument" "$work/ssh.exit" \
    </dev/null > "$work/ssh.log" 2>&1 || fail 'envoltorio SSH'
  if [[ "$argument" == --help ]]; then expected=0; else expected=2; fi
  expect "$expected" "$(cat "$work/ssh.exit")"
  grep -q '^Uso:' "$work/ssh.log" || fail 'salida por stdin incompleta'
done
pass 'bash -s funciona con stdin no interactivo y devuelve el estado al envoltorio'

# Comprueba la entrega completa de la salida antes de devolver el estado.
(
  log_work="$work/logger"
  mkdir "$log_work" || exit 1
  mkfifo "$log_work/output" || exit 1
  exec {console_out}>&1 {console_err}>&2
  tee "$work/summary.log" < "$log_work/output" &
  logger_pid=$!
  exec > "$log_work/output" 2>&1
  say 'Inventario terminado'
  summary 3 "$log_work" check "$work/summary.log" "$logger_pid" "$console_out" "$console_err"
) > "$work/console.log" 2>&1
expect 3 "$?"
cmp "$work/summary.log" "$work/console.log" || fail 'salida distinta en consola y log'
grep -q '^Resultado: 3 ' "$work/console.log" || fail 'resumen final incompleto'
[[ ! -e "$work/logger" ]] || fail 'directorio de trabajo sin limpiar'
pass 'el cierre del log entrega el resumen y conserva el código de salida'

(
  # shellcheck disable=SC2329 # main invoca uname de forma indirecta.
  uname() { printf '%s\n' 'SistemaFixture'; }
  run_status 2 main --update
  grep -Fq 'Sistema detectado: SistemaFixture' "$work/test-output" || fail 'diagnóstico del sistema'
) || fail 'requisitos de ejecución'
if (( EUID != 0 )) && [[ -x /usr/bin/sudo ]]; then
  (
    exec() {
      expect /usr/bin/sudo "$1"
      expect -n "$2"
      expect /bin/bash "$4"
      [[ "$5" == /*/verificar_actualizar_php_vps.sh ]] || fail 'ruta del script para sudo'
      expect --dry-run "$6"
      expect --force "$7"
      printf 'sudo invocado\n'
    }
    require_root --dry-run --force > "$work/sudo-mock"
    grep -Fxq 'sudo invocado' "$work/sudo-mock" || fail 'no se intentó sudo'
  ) || fail 'elevación no interactiva'
fi
pass 'diagnóstico del sistema y elevación no interactiva con argumentos intactos'

printf '%d grupos de pruebas aprobados.\n' "$passed"
