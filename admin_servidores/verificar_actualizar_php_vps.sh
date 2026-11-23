#!/usr/bin/env bash
# Auditoría y actualización de PHP en VPS Linux sin panel.
set -uo pipefail
export LC_ALL=C
umask 077

# Referencias de la campaña del 19-11-2026, no un certificado de seguridad general.
# https://www.php.net/ChangeLog-8.php
# https://blog.remirepo.net/
reference() {
  case "$1" in
    8.2) echo 8.2.36 ;;
    8.3) echo 8.3.37 ;;
    8.4) echo 8.4.28 ;;
    8.5) echo 8.5.13 ;;
  esac
}

branch_of() {
  local version=${1#*:}
  [[ "$version" =~ ^([0-9]+\.[0-9]+)\.[0-9]+ ]] && printf '%s\n' "${BASH_REMATCH[1]}"
}

upstream_of() {
  local version=${1#*:}
  [[ "$version" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]] && printf '%s\n' "${BASH_REMATCH[1]}"
}

php_support() {
  case "$1" in
    8.[2-6])
      local end="$((2024 + ${1#*.}))-12-31"
      if [[ "$today" > "$end" ]]; then echo 'EOL upstream'; else echo "seguridad upstream hasta $end"; fi ;;
    [457].*|8.[01]) echo 'EOL upstream' ;;
    *) echo 'ciclo upstream indeterminado' ;;
  esac
}

help_text() {
  cat <<'HELP'
Uso: verificar_actualizar_php_vps.sh [--check | --dry-run | --update] [--force]

  --check    Inventario y auditoría con los índices locales (predeterminado).
  --dry-run  Simula y valida la transacción sin instalar ni reiniciar.
  --update   Refresca índices privados, simula y aplica una transacción validada.
  --force    Refresca índices privados también en auditoría o simulación.
  --help     Muestra esta ayuda.

Ejemplos:
  sudo bash verificar_actualizar_php_vps.sh --check --force
  sudo bash verificar_actualizar_php_vps.sh --dry-run --force
  sudo bash verificar_actualizar_php_vps.sh --update
  bash -s -- --check < verificar_actualizar_php_vps.sh

Los informes y respaldos se guardan en /root.
Salida: 0 sin hallazgos en el alcance evaluado, 1 pendientes o intervención,
2 error técnico, 3 evidencia de seguridad insuficiente.
HELP
}

# https://www.debian.org/releases/
# https://ubuntu.com/about/release-cycle
# https://docs.rockylinux.org/releases/
# https://wiki.almalinux.org/release-notes/
# https://access.redhat.com/support/policy/updates/errata
# https://www.centos.org/cl-vs-cs/
lifecycle() {
  family=unknown lifecycle_end='' status_os=unknown codename=''
  case "$os:$major" in
    debian:*|ubuntu:*) family=apt ;;
    almalinux:*|rocky:*|rhel:*|centos:*) family=rpm ;;
  esac
  case "$os:$release" in
    debian:11|debian:11.*) lifecycle_end=2026-08-31; codename=bullseye ;;
    debian:12|debian:12.*) lifecycle_end=2028-06-30; codename=bookworm ;;
    debian:13|debian:13.*) lifecycle_end=2030-06-30; codename=trixie ;;
    ubuntu:20.04) lifecycle_end=2030-04-30; codename=focal ;;
    ubuntu:22.04) lifecycle_end=2032-04-30; codename=jammy ;;
    ubuntu:24.04) lifecycle_end=2034-04-30; codename=noble ;;
    ubuntu:26.04) lifecycle_end=2036-04-30; codename=resolute ;;
  esac
  case "$os:$major" in
    almalinux:8) lifecycle_end=2029-03-01 ;;
    rocky:8|rhel:8) lifecycle_end=2029-05-31 ;;
    almalinux:9|rocky:9|rhel:9) lifecycle_end=2032-05-31 ;;
    almalinux:10|rocky:10|rhel:10) lifecycle_end=2035-05-31 ;;
    centos:7) lifecycle_end=2024-06-30 ;;
    centos:8)
      lifecycle_end=2021-12-31
      [[ "$pretty" == *Stream* ]] && lifecycle_end=2024-05-31 ;;
    centos:9) [[ "$pretty" == *Stream* ]] && lifecycle_end=2027-05-31 ;;
    centos:10) [[ "$pretty" == *Stream* ]] && lifecycle_end=2030-05-31 ;;
  esac
  if [[ -z "$lifecycle_end" && "$family" == apt ]]; then
    read -r codename lifecycle_end <<< "$(local_apt_lifecycle "$os" "$release")"
  fi
  if [[ -n "$lifecycle_end" ]]; then
    status_os=supported
    [[ "$today" > "$lifecycle_end" ]] && status_os=eol
  fi
}

# Las ediciones futuras solo se aceptan si distro-info-data ya las registra
# como publicadas y con fechas de mantenimiento.
local_apt_lifecycle() {
  local distribution=$1 version=$2 owner table="/usr/share/distro-info/$1.csv"
  [[ -r "$table" ]] && have dpkg-query || return 1
  owner=$(dpkg-query -S "$table" 2>/dev/null) || return 1
  [[ "$owner" == "distro-info-data: $table" ]] || return 1
  awk -F, -v version="$version" -v today="$today" -v distro="$distribution" '
    NR==1 {for (i=1;i<=NF;i++) col[$i]=i; next}
    {
      id=$1; sub(/ LTS$/,"",id)
      if (id!=version || !col["release"] || !col["series"] || !col["eol"] ||
          $col["release"]=="" || $col["release"]>today) next
      end=(distro=="debian" && col["eol-lts"]) ? $col["eol-lts"] : ""
      if (end=="") end=$col["eol"]
      if ($col["series"] ~ /^[a-z][a-z0-9-]*$/ && end ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        print $col["series"],end; exit
      }
    }' "$table"
}

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
error() { say "ERROR: $*"; technical=1; }
manual() { say "REVISIÓN MANUAL: $*"; pending=1; }
unknown() { say "NO VERIFICADO / REVISIÓN MANUAL: $*"; indeterminate=1; }
die() { error "$*"; exit 2; }

os_value() {
  awk -v key="$1" 'index($0,key "=")==1 {
    sub(/^[^=]*=/,""); sub(/^["\047]/,""); sub(/["\047]$/,""); print; exit
  }' /etc/os-release
}

package_inventory() {
  if [[ "$family" == apt ]]; then
    dpkg-query -W -f='${Package}:${Architecture}|${Version}|${source:Package}|${source:Version}|${db:Status-Status}|${Maintainer}\n' |
      awk -F'|' '$5=="installed" && ($1 ~ /^(php|libapache2-mod-php|libphp|libembed-php)[0-9:-]/ || $3 ~ /^php([0-9.]+)?$/)'
  elif [[ "$family" == rpm ]]; then
    rpm -qa --qf '%{NAME}.%{ARCH}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{SOURCERPM}|%{VERSION}|installed|%{VENDOR}|%{MODULARITYLABEL}\n' |
      awk -F'|' '$1 ~ /^(php([0-9]*-php)?|rh-php[0-9]+-php|alt-php[0-9]+|ea-php[0-9]+)([-.]|[0-9])/'
  fi
}

# rpm en CentOS 7 no expone MODULARITYLABEL.
rpm_inventory_legacy() {
  rpm -qa --qf '%{NAME}.%{ARCH}|%{EPOCH}:%{VERSION}-%{RELEASE}|%{SOURCERPM}|%{VERSION}|installed|%{VENDOR}|(none)\n' |
    awk -F'|' '$1 ~ /^(php|rh-php|alt-php|ea-php)/'
}

owner_of() {
  local owner
  case "$family" in
    apt)
      owner=$(dpkg-query -S -- "$1" 2>/dev/null) || return 1
      [[ "$owner" != *$'\n'* && "$owner" != *,* ]] || return 1
      owner=${owner%%: /*}
      dpkg-query -W -f='${Package}:${Architecture}' "$owner" ;;
    rpm) rpm -qf --qf '%{NAME}.%{ARCH}' -- "$1" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

package_files() {
  case "$family" in
    apt) dpkg-query -L "$1" ;;
    rpm) rpm -ql "$1" ;;
  esac
}

php_path() {
  [[ "${1##*/}" =~ ^(php([0-9]+([.][0-9]+)?)?(-cgi|-fpm)?([0-9]+([.][0-9]+)?)?|php-fcgi|lsphp[0-9]*|libphp[0-9.]*\.so)$ ]]
}

register_path() {
  local path canonical owner version branch
  path=$1
  [[ -f "$path" ]] || return 0
  canonical=$(readlink -f -- "$path") || return 1
  [[ -z "${seen_path[$canonical]:-}" ]] || return 0
  seen_path[$canonical]=1
  if owner=$(owner_of "$canonical") && [[ -n "${installed[$owner]:-}" ]]; then
    version=${installed[$owner]}
    branch=$(branch_of "$version")
    say "Instalación: $canonical | propietario: $owner | rama: ${branch:-desconocida}"
  else
    unknown "Instalación sin propietario PHP reconocido: $canonical. Identificar compilación, versión y extensiones manualmente."
  fi
}

discover_paths() {
  local scan_dir path
  for scan_dir in /usr/bin /usr/sbin /usr/lib/cgi-bin /usr/local /opt /srv /var/www; do
    [[ -d "$scan_dir" ]] || continue
    if ! find "$scan_dir" -xdev -maxdepth 10 \( -type f -o -type l \) \
       \( -name 'php*' -o -name 'lsphp*' -o -name 'libphp*.so' \) -print0 >> "$work/paths"; then
      unknown "Inventario incompleto bajo $scan_dir."
    fi
  done
  while IFS= read -r -d '' path; do
    php_path "$path" && register_path "$path"
  done < "$work/paths"
}

inventory_packages() {
  local key version src srcver _ vendor module path
  if [[ "$family" == rpm ]] && ! rpm --querytags | grep -Fx MODULARITYLABEL > /dev/null; then
    rpm_inventory_legacy > "$work/packages" || return 1
  else
    package_inventory > "$work/packages" || return 1
  fi
  while IFS='|' read -r key version src srcver _ vendor module; do
    installed[$key]=$version
    say "Paquete: $key | revisión: $version | fuente: $src ($srcver) | mantenedor: $vendor | módulo: ${module:-n/a}"
  done < "$work/packages"
  while IFS='|' read -r key _; do
    package_files "$key" > "$work/files.$key" || return 1
    while IFS= read -r path; do
      if php_path "$path"; then
        if [[ -f "$path" ]]; then register_path "$path"; else unknown "$key declara un archivo PHP ausente: $path"; fi
      elif [[ "$path" == *.so || "$path" == */mods-available/*.ini || "$path" == */php.d/*.ini ]]; then
        say "  Extensión/configuración de $key: $path"
      fi
    done < "$work/files.$key"
  done < "$work/packages"
}

# Origen de la revisión exacta en los índices, agrupando mirrors del mismo proveedor.
# Una revisión ausente o publicada simultáneamente por proveedores distintos es ambigua.
apt_origin() {
  local key=$1 revision=$2
  awk -v revision="$revision" -v suite="$codename" '
    function index_key() {
      return $2 " " $3 " " $4 " " $5
    }
    NR==FNR {
      if ($1 ~ /^[0-9]+$/ && $2 ~ /^(https?:|file:)/) {
        url=$2; location=index_key()
      }
      if (location!="" && $1=="release") {
        same_suite=(suite=="" || $0 ~ ("[ ,]n=" suite "([-][a-z0-9-]+)?([,]|$)"))
        if (!same_suite) providers[location]="otra-edicion:" url
        else if ($0 ~ /[ ,]o=Debian( Backports)?([,]|$)/) providers[location]="debian"
        else if ($0 ~ /[ ,]o=Ubuntu([ ,]|$)/ ||
                 $0 ~ /[ ,]o=UbuntuESM(Apps|Infra)([ ,]|$)/) providers[location]="ubuntu"
        else if ($0 ~ /[ ,]o=LP-PPA-ondrej-php([ ,]|$)/ &&
                 url ~ /^https?:\/\/ppa\.launchpad(content)?\.net\/ondrej\/php\//) providers[location]="sury"
        else if (url ~ /^https:\/\/packages\.sury\.org\/php\/?$/) providers[location]="sury"
        else providers[location]="desconocido:" url
        location=""
      }
      next
    }
    /^ \*\*\* |^     [^ ]/ {selected=($1=="***" ? $2 : $1)==revision}
    selected && $1 ~ /^[0-9]+$/ && $5=="Packages" {
      location=index_key()
      if (location in providers) print providers[location]
      else print "desconocido:" $2
    }
  ' "$work/apt-repos" "$work/policy.$key" | sort -u
}

deb_core() { [[ "$1" =~ ^php([0-9]+\.[0-9]+)?$ ]]; }
rpm_core() { [[ "$1" =~ ^php([0-9]+-php|[0-9]+[.][0-9]+)?-[0-9][0-9.]*- ]]; }

# El tracker compara la revisión de FUENTE, con epoch y revisión Debian intactos.
tracker_evidence() {
  local source=$1 version=$2 cve fixed state result=0 expected pocket
  [[ -s "$work/tracker.tsv" ]] || return 3
  expected=$(campaign_cves "$3") || expected=$(campaign_cves 8.2)
  for cve in $expected; do
    read -r fixed pocket <<< "$(awk -F'\t' -v s="$source" -v c="$cve" '$1==s && $2==c {print $3,$4; exit}' "$work/tracker.tsv")"
    state=indeterminado
    if [[ "$fixed" == affected ]]; then
      state=pendiente; result=1
    elif [[ -n "$fixed" && "$fixed" != 0 ]]; then
      if dpkg --compare-versions "$version" ge "$fixed"; then state=corregido
      else state=pendiente; result=1; fi
    elif [[ "$fixed" == 0 ]]; then
      state="sin revisión afectada según el tracker"
    elif (( result == 0 )); then
      result=3
    fi
    say "  $source $version $cve: $state (tracker $os: ${fixed:-sin revisión publicada} ${pocket:-})"
  done
  return "$result"
}

campaign_cves() {
  local common='CVE-2026-129538 CVE-2026-129496 CVE-2026-129289 CVE-2026-129292 CVE-2026-129291 CVE-2026-128090 CVE-2026-126714 CVE-2026-115560 CVE-2026-129481 CVE-2026-15353 CVE-2026-129506 CVE-2026-128064 CVE-2026-127960'
  case "$1" in
    8.2|8.3) echo "$common" ;;
    8.4) echo "$common CVE-2026-129501" ;;
    8.5) echo "$common CVE-2026-129501 CVE-2026-129474 CVE-2026-129182 CVE-2026-48841 CVE-2026-129438" ;;
    *) return 1 ;;
  esac
}

load_debian_tracker() {
  have curl && have python3 || return 1
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-time 60 --max-filesize 100000000 \
    https://security-tracker.debian.org/tracker/data/json -o "$work/tracker.json" || return 1
  python3 - "$work/tracker.json" "$codename" > "$work/tracker.tsv" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    tracker = json.load(source)
for package, issues in tracker.items():
    if not re.fullmatch(r"php(?:\d+\.\d+)?", package):
        continue
    for cve, issue in issues.items():
        release = issue.get("releases", {}).get(sys.argv[2], {})
        if release.get("status") == "resolved" and release.get("fixed_version"):
            print(package, cve, release["fixed_version"], sep="\t")
        elif release.get("status") == "open":
            print(package, cve, "affected", sep="\t")
PY
}

# Un changelog sirve si documenta corrección explícita para todos los CVE
# evaluados y la entrada de cabecera corresponde a la revisión solicitada.
changelog_evidence() {
  local changelog=$1 version=$2 branch=$3 cves cve
  cves=$(campaign_cves "$branch") || return 3
  awk -v version="$version" 'NR==1 {
    head=$2; sub(/^\(/,"",head); sub(/\)$/,"",head); exit head!=version
  } END {if (!NR) exit 1}' "$changelog" || return 3
  local missing=0
  for cve in $cves; do
    if awk -v cve="$cve" 'BEGIN {IGNORECASE=0}
      {line=tolower($0)}
      $0 ~ ("(^|[^A-Za-z0-9-])" cve "([^A-Za-z0-9-]|$)") &&
        line ~ /(^|[^a-z])(fix(e[ds])?|patch(ed)?|address(es|ed)?)([^a-z]|$)/ &&
        line !~ /not |unfixed|regress|revert|pending|incomplete/ {found=1}
      END {exit !found}' "$changelog"; then
      say "  $version $cve: corrección explícita en changelog"
    else
      missing=1
    fi
  done
  (( missing == 0 )) || return 3
}

upstream_evidence() {
  local package_version=$1 branch=$2 floor actual rest cves cve
  floor=$(reference "$branch")
  actual=$(upstream_of "$package_version")
  rest=${package_version#*:}
  rest=${rest#"$actual"}
  [[ -n "$floor" && -n "$actual" && "$rest" != [[:alpha:]]* && "$rest" != '~'* ]] || return 3
  cves=$(campaign_cves "$branch") || return 3
  # Este camino solo recibe builds del proveedor de la campaña o builds con
  # origen trazable que llevan su versión estable publicada en la revisión.
  if dpkg --compare-versions "$actual" ge "$floor"; then
    for cve in $cves; do say "  $package_version $cve: versión de la campaña publicada ($floor)"; done
    return 0
  fi
  return 3
}

# Marcadores del empaquetado para revisiones que ya salieron de los índices.
apt_package_origin() {
  local version=$1 maintainer=$2
  if [[ "$version" == *+deb.sury.org+* && "$maintainer" == *PHP* ]]; then
    echo sury
  elif [[ "$os" == ubuntu && "$version" == *ubuntu* && "$maintainer" == *ubuntu-devel-discuss@lists.ubuntu.com* ]]; then
    echo ubuntu
  elif [[ "$os" == debian && "$version" == *"deb${major}u"* && "$maintainer" == *pkg-php-maint@lists.alioth.debian.org* ]]; then
    echo debian
  fi
}

load_ubuntu_tracker() {
  have python3 || return 1
  local identifiers
  identifiers="$(campaign_cves 8.5)"
  python3 - "$codename" "$identifiers" > "$work/tracker.tsv" <<'PY'
import concurrent.futures
import json
import re
import sys
import urllib.request

codename, identifiers = sys.argv[1:]

def load(cve):
    url = "https://ubuntu.com/security/cves/{}.json".format(cve)
    try:
        with urllib.request.urlopen(url, timeout=12) as response:
            if response.geturl() != url:
                return None
            data = json.loads(response.read(2000000))
        if data.get("id") != cve:
            return None
        rows = []
        for package in data.get("packages", []):
            for status in package.get("statuses", []):
                if status.get("release_codename") != codename:
                    continue
                version = status.get("description", "")
                pocket = status.get("pocket", "")
                if status["status"] == "released" and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version):
                    rows.append((package["name"], cve, version, pocket))
                elif status["status"] == "not-affected":
                    rows.append((package["name"], cve, "0", pocket))
                elif status["status"] in {"needed", "pending", "deferred"}:
                    rows.append((package["name"], cve, "affected", pocket))
        return rows
    except (OSError, ValueError, KeyError):
        return None

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(load, identifiers.split()))
for rows in results:
    for row in rows or []:
        print(*row, sep="\t")
sys.exit(any(rows is None for rows in results))
PY
}

tracker_fix_available() {
  local source=$1 current=$2 target=$3 cve fixed pocket found=1
  [[ -s "$work/tracker.tsv" ]] || return 1
  while IFS=$'\t' read -r _ cve fixed pocket; do
    [[ "$fixed" != 0 && "$fixed" != affected ]] || continue
    if dpkg --compare-versions "$current" lt "$fixed" && dpkg --compare-versions "$target" ge "$fixed"; then
      say "  $source $cve: candidato documentado por $os ($fixed ${pocket:-})"
      found=0
    fi
  done < <(awk -F'\t' -v source="$source" '$1==source' "$work/tracker.tsv")
  return "$found"
}

fetch_changelog() {
  local key=$1 binary_version=$2 filename="$work/changelog.$3"
  [[ -e "$filename" ]] || {
    if ! timeout 30 apt-get "${apt_options[@]}" changelog "$key=$binary_version" > "$filename"; then
      : > "$filename"
    fi
  }
  [[ -s "$filename" ]]
}

changelog_fix_available() {
  local key=$1 binary_version=$2 srcver=$3 current=$4 cve revision found=1
  fetch_changelog "$key" "$binary_version" "$srcver" || return 1
  while read -r revision cve; do
    dpkg --compare-versions "$revision" gt "$current" || continue
    say "  $key $cve: corrección explícita de changelog introducida en $revision"
    found=0
  done < <(awk -v version="$srcver" '
    function print_entry(   count,i,a,line) {
      count=split(entry,a," ")
      line=tolower(entry)
      if (line ~ /(^|[^a-z])(fix(e[ds])?|patch(ed)?|address(es|ed)?)([^a-z]|$)/ &&
          line !~ /not |unfixed|regress|revert|pending|incomplete/) {
        for (i=1;i<=count;i++) {
          if (match(a[i],/CVE-[0-9]+-[0-9]+/)) print revision,substr(a[i],RSTART,RLENGTH)
        }
      }
    }
    /^[^ ]+ \([^()]+\) [^;]+;/ {
      print_entry(); entry=""; revision=$2
      gsub(/[()]/,"",revision)
      if (NR==1 && revision!=version) {revision=""; exit 1}
      next
    }
    /^[[:space:]]+[*-] / {print_entry(); entry=$0; next}
    /^[[:space:]]+[^ ]/ {entry=entry " " $0}
    END {if (revision!="") print_entry()}
  ' "$work/changelog.$srcver" | sort -u)
  return "$found"
}


prepare_apt() {
  apt_options=(-o APT::Color=0 -o Acquire::AllowInsecureRepositories=false
    -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false)
  if (( refresh )); then
    chmod 0711 "$work" || return 1
    mkdir -p "$work/lists/partial" && chmod 0755 "$work/lists" || return 1
    cat > "$work/apt-refresh.conf" <<'CONF'
#clear APT::Update::Pre-Invoke;
#clear APT::Update::Post-Invoke;
#clear APT::Update::Post-Invoke-Success;
CONF
    apt_options+=(-o "Dir::State::lists=$work/lists")
    apt-get "${apt_options[@]}" -c "$work/apt-refresh.conf" -o APT::Update::Error-Mode=any \
      -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update || return 1
  fi
  apt-cache "${apt_options[@]}" policy > "$work/apt-repos" || return 1
  cat "$work/apt-repos"
  grep -q '^     release ' "$work/apt-repos" || return 1
  apt-mark showhold > "$work/holds" || return 1
  say "Paquetes retenidos APT: $(tr '\n' ' ' < "$work/holds")"
  apt "${apt_options[@]}" list --upgradable || return 1
}

report_evidence() {
  case "$1" in
    0) say "CORREGIDO / VERIFICADO: $2 (campaña del 19-11-2026)" ;;
    1) say "VULNERABLE / PARCHE PENDIENTE: $2"; pending=1 ;;
    *) unknown "$2 (campaña del 19-11-2026)" ;;
  esac
}

candidate_deb_source() {
  apt-cache "${apt_options[@]}" show "$1=$2" |
    awk -v fallback="${1%%:*}" -v version="$2" '
      /^Source: / {source=$2; revision=$3; gsub(/[()]/,"",revision)}
      /^$/ && !done {print (source?source:fallback), (revision?revision:version); done=1}
      END {if (!done) print (source?source:fallback), (revision?revision:version)}'
}

audit_apt() {
  local key current target origin next_origin branch next_branch src srcver nextsrc nextsrcver state nextstate vendor
  if [[ ! -e "$work/tracker.tsv" ]]; then
    if [[ "$os" == debian ]] && ! load_debian_tracker; then
      say 'Tracker Debian no disponible. Se intentará comprobar el changelog exacto.'
    elif [[ "$os" == ubuntu ]] && ! load_ubuntu_tracker; then
      say 'Tracker Ubuntu incompleto. Se intentará comprobar el changelog exacto.'
    fi
  fi
  while IFS='|' read -r key current src srcver _ vendor; do
    apt-cache "${apt_options[@]}" policy "$key" > "$work/policy.$key" || { error "policy de $key"; continue; }
    target=$(awk '/^[[:space:]]*Candidate:/ {print $2; exit}' "$work/policy.$key")
    origin=$(apt_origin "$key" "$current") || return 1
    next_origin=$(apt_origin "$key" "$target") || return 1
    if [[ -z "$origin" ]]; then
      origin=$(apt_package_origin "$current" "$vendor")
      [[ -z "$origin" ]] || say "  Procedencia instalada inferida de la revisión y el mantenedor: $origin"
    fi
    branch=$(branch_of "$srcver")
    say "PHP APT $key | instalado: $current | candidato: ${target:-sin datos} | origen: ${origin:-indeterminado} → ${next_origin:-indeterminado}"
    if ! deb_core "$src" || [[ -z "$branch" ]]; then
      [[ -z "$branch" ]] || say "  Extensión o metapaquete de fuente $src con ciclo propio"
      if [[ -n "$target" && "$target" != '(none)' ]] && dpkg --compare-versions "$target" gt "$current"; then
        manual "$key requiere comprobar la compatibilidad y el advisory de su fuente por separado."
      fi
      continue
    fi
    say "Rama $branch | upstream: $(upstream_of "$srcver") | referencia: $(reference "$branch") | $(php_support "$branch") | cobertura del paquete: consultar proveedor"
    state=3
    case "$origin" in
      debian|ubuntu|sury) apt_evidence "$key" "$current" "$origin" "$src" "$srcver" "$branch" && state=0 || state=$? ;;
    esac
    report_evidence "$state" "$key $current"
    if [[ -z "$target" || "$target" == '(none)' ]]; then
      unknown "$key carece de candidato."
      continue
    fi
    if ! dpkg --compare-versions "$target" gt "$current"; then continue; fi
    pending=1
    if grep -Fxq -e "$key" -e "${key%%:*}" "$work/holds"; then
      manual "$key está retenido."
      continue
    fi
    read -r nextsrc nextsrcver <<< "$(candidate_deb_source "$key" "$target")"
    next_branch=$(branch_of "$nextsrcver")
    if [[ "$branch" != "$next_branch" || "$src" != "$nextsrc" ||
          "$origin" != "$next_origin" || ! "$origin" =~ ^(debian|ubuntu|sury)$ ]]; then
      manual "$key tiene cambio de rama, fuente o proveedor, o procedencia ambigua."
      continue
    fi
    if [[ "$os:$release" == ubuntu:20.04 && "$esm_infra" != enabled && "$esm_apps" != enabled && "$origin" == ubuntu ]]; then
      manual "$key requiere verificar cobertura ESM para Ubuntu 20.04."
      continue
    fi
    if [[ "$origin" == sury && "$(php_support "$branch")" == 'EOL upstream' ]]; then
      manual "Rama $branch de Surý con mantenimiento de terceros sin confirmar."
      continue
    fi
    nextstate=3
    apt_evidence "$key" "$target" "$origin" "$nextsrc" "$nextsrcver" "$branch" && nextstate=0 || nextstate=$?
    if (( nextstate == 0 && state != 0 )) ||
       { [[ "$origin" == "$os" ]] && tracker_fix_available "$src" "$srcver" "$nextsrcver"; } ||
       changelog_fix_available "$key" "$target" "$nextsrcver" "$srcver"; then
      say "Acción: actualizar $key a $target con evidencia de seguridad"
      planned[$key]=$target
      planned_repo[$key]=$origin
    else
      manual "$key tiene una revisión superior sin una corrección aplicable demostrada por esta evaluación."
    fi
  done < "$work/packages"
}

apt_evidence() {
  local key=$1 binary_version=$2 origin=$3 src=$4 srcver=$5 branch=$6 result=3
  if [[ "$origin" == "$os" ]]; then
    tracker_evidence "$src" "$srcver" "$branch" && return 0
    result=$?
    (( result == 1 )) && return 1
  fi
  if [[ "$origin" == sury ]] && upstream_evidence "$srcver" "$branch"; then return 0; fi
  fetch_changelog "$key" "$binary_version" "$srcver" || return 3
  changelog_evidence "$work/changelog.$srcver" "$srcver" "$branch"
}

# Relaciona las acciones Inst y Conf con el conjunto exacto aprobado, incluida la arquitectura.
validate_apt_plan() {
  awk '
    NR==FNR {approved[$1]=$2; wanted++; next}
    $1=="Remv" || $1=="Purg" {bad=1}
    $1=="Inst" {
      if ($3 !~ /^\[/ || $NF !~ /\[[[:alnum:]_-]+\]\)$/) {bad=1; next}
      arch=$NF; sub(/^\[/,"",arch); sub(/\]\)$/,"",arch)
      key=$2; if (key !~ /:/) key=key ":" arch
      revision=$4; sub(/^\(/,"",revision)
      if (!(key in approved) || revision!=approved[key] || seen[key]++) bad=1
      count++
    }
    END {exit (bad || !wanted || count!=wanted)}
  ' "$1" "$2"
}

write_config_guard() {
  cat > "$work/config_guard.py" <<'PY'
import hashlib
import os
import subprocess
import sys
import tarfile

PREFIXES = ("/etc/php/", "/etc/php.d/", "/etc/php-fpm.d/", "/etc/opt/remi/",
            "/etc/apache2/", "/etc/httpd/", "/etc/nginx/")
FILES = ("/etc/php.ini", "/etc/php-fpm.conf")

def protected(path):
    return ((path in FILES or path.startswith(PREFIXES) or
             (path.startswith("/opt/") and path.endswith((".conf", ".ini"))))
            and os.path.lexists(path) and not os.path.isdir(path))

def require_same(path, digest, algorithm):
    if not os.path.isfile(path) or os.path.islink(path) or not digest:
        raise ValueError("tipo o digest de configuración indeterminado: " + path)
    with open(path, "rb") as existing:
        local = hashlib.new(algorithm, existing.read()).hexdigest()
    if local != digest.lower():
        raise ValueError("la configuración existente difiere del paquete: " + path)

def check_deb(archive):
    with subprocess.Popen(["dpkg-deb", "--fsys-tarfile", archive],
                          stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as payload:
            for member in payload:
                name = member.name[2:] if member.name.startswith("./") else member.name
                path = "/" + name.lstrip("/")
                if not protected(path):
                    continue
                if member.issym() and os.path.islink(path):
                    if os.readlink(path) == member.linkname:
                        continue
                if not member.isfile():
                    raise ValueError("cambio de tipo de configuración: " + path)
                digest = hashlib.sha256(payload.extractfile(member).read()).hexdigest()
                require_same(path, digest, "sha256")
        while process.stdout.read(65536):
            pass
        if process.wait():
            raise ValueError("no se pudo inspeccionar el archivo " + archive)

def check_rpm(archive):
    import rpm
    with open(archive, "rb") as package:
        transaction = rpm.TransactionSet()
        header = transaction.hdrFromFdno(package.fileno())
    paths = header[rpm.RPMTAG_FILENAMES]
    if not paths:
        return
    digests = header[rpm.RPMTAG_FILEDIGESTS]
    links = header[rpm.RPMTAG_FILELINKTOS]
    if len(paths) != len(digests) or len(paths) != len(links):
        raise ValueError("cabecera RPM sin inventario de archivos completo")
    algorithms = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
    algorithm = algorithms.get(header[rpm.RPMTAG_FILEDIGESTALGO] or 1)
    for path, digest, link in zip(paths, digests, links):
        if not protected(path):
            continue
        if link and os.path.islink(path) and os.readlink(path) == link:
            continue
        if not algorithm or link:
            raise ValueError("tipo o digest de configuración indeterminado: " + path)
        require_same(path, digest, algorithm)

if __name__ == "__main__":
    try:
        check_deb(sys.argv[1])
    except (ValueError, OSError, tarfile.TarError) as error:
        sys.exit(str(error))
PY
}

build_apt_guard() {
  have python3 && write_config_guard || return 1
  cat > "$work/apt-guard" <<'GUARD'
#!/bin/bash
set -euo pipefail
directory=${0%/*}
while read -r package revision; do
  actual=$(dpkg-query -W -f='${Version}' "$package")
  [[ "$actual" == "$revision" ]]
done < "$directory/previous"
while IFS= read -r archive; do
  [[ "$archive" == /* && "$archive" == *.deb ]] || exit 1
  package=$(dpkg-deb -f "$archive" Package)
  arch=$(dpkg-deb -f "$archive" Architecture)
  revision=$(dpkg-deb -f "$archive" Version)
  python3 "$directory/config_guard.py" "$archive"
  printf '%s %s\n' "$package:$arch" "$revision"
done | sort > "$directory/apt.actual"
cmp "$directory/approved" "$directory/apt.actual"
GUARD
  chmod 0700 "$work/apt-guard"
}

rpm_compare() {
  local operation=$1 left=$2 right=$3
  "$rpm_python" - "$operation" "$left" "$right" <<'PY'
import rpm
import sys

def evr(value):
    epoch, _, rest = value.partition(":")
    version, _, release = rest.rpartition("-")
    return epoch, version, release

result = rpm.labelCompare(evr(sys.argv[2]), evr(sys.argv[3]))
sys.exit(not {"gt": result > 0, "ge": result >= 0}[sys.argv[1]])
PY
}

rpm_provider() {
  case "$1" in
    'Remi Collet'|'Remi'|'Remi RPM repository') echo remi ;;
    'AlmaLinux'|'AlmaLinux OS Foundation') echo almalinux ;;
    'Rocky Enterprise Software Foundation'|'Rocky Linux') echo rocky ;;
    'Red Hat, Inc.') echo rhel ;;
    'CentOS'|'CentOS Stream') echo centos ;;
  esac
}

prepare_rpm() {
  manager=dnf
  if ! have dnf; then
    have yum || return 1
    manager=yum
  fi
  rpm_options=(--setopt="logdir=$work")
  if [[ "$major" != 7 ]]; then
    rpm_options+=(--setopt='*.skip_if_unavailable=False')
    if (( refresh )); then
      rpm_options+=(--setopt="cachedir=$work/dnf-cache" --refresh)
    else
      rpm_options+=(--cacheonly)
    fi
  else
    rpm_options+=(--cacheonly)
  fi
  "$manager" "${rpm_options[@]}" repolist --enabled || return 1
  local rc=0
  "$manager" "${rpm_options[@]}" check-update || rc=$?
  (( rc == 0 || rc == 100 )) || return 1
  local config
  for config in /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/*.repo; do
    [[ -f "$config" ]] || continue
    awk -v config="$config" '/^[[:space:]]*(exclude|excludepkgs|includepkgs)[[:space:]]*=/ {print config ": " $0}' "$config"
  done
  for config in /etc/dnf/plugins/versionlock.list /etc/yum/pluginconf.d/versionlock.list; do
    [[ -s "$config" ]] || continue
    say "Restricciones versionlock en $config:"
    awk '/^[[:space:]]*[^#[:space:]]/ {print}' "$config"
  done
  if [[ "$major" == 8 || "$major" == 9 ]]; then
    if ! "$manager" "${rpm_options[@]}" module list php; then
      say 'No se encontró un stream PHP visible. Se conservará la etiqueta modular instalada.'
    fi
  fi
  if (( refresh )) && [[ "$major" != 7 ]]; then
    rpm_options=(--setopt="logdir=$work" --setopt='*.skip_if_unavailable=False'
      --setopt="cachedir=$work/dnf-cache" --setopt='*.metadata_expire=-1')
  fi
}

rpm_stream() {
  local label=$1
  [[ "$label" != '(none)' && "$label" != None && -n "$label" ]] || { echo none; return; }
  [[ "$label" =~ ^([^:]+:[^:]+): ]] && printf '%s\n' "${BASH_REMATCH[1]}"
}

# Fechas de AppStream documentadas para RHEL; las derivadas publican su propia cobertura.
# https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle
rhel_php_support() {
  local end
  case "$major:$1" in
    8:7.2) end=2021-05-31 ;;
    8:7.3) end=2021-11-30 ;;
    8:8.0) end=2024-11-30 ;;
    9:8.1) end=2025-05-31 ;;
    8:8.2|9:8.2|9:8.3|9:8.4|10:8.4) end=2029-05-31 ;;
    8:7.4|9:8.0|10:8.3) end=$lifecycle_end ;;
    *) echo 'cobertura AppStream sin fecha verificada'; return ;;
  esac
  if [[ "$today" > "$end" ]]; then echo "AppStream EOL desde $end"
  else echo "AppStream hasta $end"; fi
}

rpm_modularity_compatible() {
  local stream revision=$2 repo=$3
  stream=$(rpm_stream "$1") || return 1
  if [[ "$stream" == none ]]; then [[ "$revision" != *module* ]]; return; fi
  [[ "$revision" == *module* ]] || return 1
  case "$stream:$repo" in
    php:remi-*:remi-modular) [[ "$stream" == "php:remi-$(branch_of "$revision")" ]] ;;
    php:*:*appstream*) [[ "$stream" == "php:$(branch_of "$revision")" ]] ;;
    *) return 1 ;;
  esac
}

rpm_errata() {
  local key=$1 branch=$2 name=${1%.*} arch=${1##*.} cve nevra fixed
  local -A first=()
  while read -r cve nevra; do
    [[ "$nevra" == "$name-"*".$arch" && "$nevra" != *remi* ]] || continue
    fixed=${nevra#"$name-"}
    fixed=${fixed%".$arch"}
    [[ "$fixed" == *:* ]] || fixed=0:$fixed
    [[ "$(branch_of "$fixed")" == "$branch" ]] || continue
    if [[ -z "${first[$cve]:-}" ]] || rpm_compare gt "${first[$cve]}" "$fixed"; then
      first[$cve]=$fixed
    fi
  done < <(awk '{
    col=1+($1=="i")
    if ($col ~ /^CVE-[0-9]+-[0-9]+$/ && $(col+1) ~ /Sec[.]/) print $col,$(col+2)
  }' "$work/rpm.updateinfo")
  for cve in "${!first[@]}"; do printf '%s %s\n' "$cve" "${first[$cve]}"; done
}

rpm_updateinfo() {
  local key=$1 current=$2 branch=$3 cve fixed cves result=0
  local -A covered=()
  while read -r cve fixed; do
    if rpm_compare ge "$current" "$fixed"; then
      covered[$cve]=1
    else
      say "  $key $cve: parche disponible en errata $fixed"
      result=1
    fi
  done < <(rpm_errata "$key" "$branch")
  (( result == 0 )) || return 1
  cves=$(campaign_cves "$branch") || return 3
  for cve in $cves; do
    if [[ -n "${covered[$cve]:-}" ]]; then
      say "  $key $cve: cubierto por errata"
    else
      result=3
    fi
  done
  return "$result"
}

rpm_fix_available() {
  local key=$1 current=$2 target=$3 branch=$4 cve fixed found=1
  while read -r cve fixed; do
    if rpm_compare gt "$fixed" "$current" && rpm_compare ge "$target" "$fixed"; then
      say "  $key $cve: el candidato alcanza la revisión de la errata ($fixed)"
      found=0
    fi
  done < <(rpm_errata "$key" "$branch")
  return "$found"
}

rpm_changelog_evidence() {
  local changelog=$1 cves cve result=0
  cves=$(campaign_cves "$2") || return 3
  for cve in $cves; do
    if awk -v cve="$cve" '{
      line=tolower($0)
      if ($0 ~ ("(^|[^A-Za-z0-9-])" cve "([^A-Za-z0-9-]|$)") &&
          line ~ /(^|[^a-z])(fix(e[ds])?|patch(ed)?|address(es|ed)?)([^a-z]|$)/ &&
          line !~ /not |unfixed|regress|revert|pending|incomplete/) fixed=1
    } END {exit !fixed}' "$changelog"; then
      say "  $cve: corrección explícita en changelog RPM instalado"
    else
      result=3
    fi
  done
  return "$result"
}

remi_evidence() {
  local revision=$1 branch=$2 floor version cves cve
  floor=$(reference "$branch")
  version=$(upstream_of "$revision")
  [[ -n "$floor" && -n "$version" && "${revision#*:}" == "$version-"* && "$revision" == *remi* ]] || return 3
  rpm_compare ge "0:$version-0" "0:$floor-0" || return 3
  cves=$(campaign_cves "$branch") || return 3
  for cve in $cves; do say "  $revision $cve: lanzamiento Remi de la campaña ($floor)"; done
}

audit_rpm() {
  local key current src version state vendor module origin target nextsrc nextvendor nextrepo nextprovider
  local inst_repo branch nextstate name candidate_record
  rpm_python=
  local interpreter
  for interpreter in /usr/libexec/platform-python /usr/bin/python3; do
    if [[ -x "$interpreter" ]] && "$interpreter" -c 'import rpm, dnf'; then
      rpm_python=$interpreter
      break
    fi
  done
  if [[ -z "$rpm_python" || "$major" == 7 ]]; then unknown 'Sin API RPM/DNF4 para comparar EVR y resolver candidatos.'; return 0; fi
  if ! "$manager" "${rpm_options[@]}" updateinfo list --all --security --with-cve > "$work/rpm.updateinfo"; then
    unknown 'No fue posible consultar las erratas DNF por CVE.'
    : > "$work/rpm.updateinfo"
  fi
  local query='%{name}.%{arch}|%{epoch}:%{version}-%{release}|%{sourcerpm}|%{vendor}|%{repoid}'
  local -a candidates=("${!installed[@]}")
  if ! "$manager" "${rpm_options[@]}" repoquery --upgrades --latest-limit=1 --qf "$query" "${candidates[@]}" > "$work/rpm.candidates"; then
    error 'repoquery no pudo resolver candidatos.'
    return 1
  fi
  while IFS='|' read -r key current src version _ vendor module; do
    name=${key%.*}
    branch=$(branch_of "$version")
    origin=$(rpm_provider "$vendor")
    inst_repo=$("$manager" "${rpm_options[@]}" info --installed "$key" |
      awk -F': *' '/^From repo[[:space:]]*:/ {print $2; exit}')
    candidate_record=$(awk -F'|' -v key="$key" '$1==key' "$work/rpm.candidates")
    IFS='|' read -r _ target nextsrc nextvendor nextrepo <<< "$candidate_record"
    nextprovider=$(rpm_provider "$nextvendor")
    say "PHP RPM $key | instalado: $current | origen: ${origin:-indeterminado}/${inst_repo:-sin historial} | candidato: ${target:-sin datos} (${nextrepo:-n/a})"
    if ! rpm_core "$src" || [[ -z "$branch" ]]; then
      [[ -z "$target" ]] || manual "$key requiere comprobar el ciclo y advisory de la extensión/metapaquete."
      continue
    fi
    local support='cobertura del paquete: verificar proveedor'
    if [[ "$origin:$inst_repo" == rhel:*appstream* ]]; then
      support=$(rhel_php_support "$branch")
      [[ "$support" != 'AppStream EOL'* ]] || manual "$key: $support."
    fi
    say "Rama $branch | upstream: $version | referencia: $(reference "$branch") | $(php_support "$branch") | $support"
    state=3
    if [[ "$origin" == remi && "$inst_repo" == remi-* && "$inst_repo" != *test* ]]; then
      remi_evidence "$current" "$branch" && state=0 || state=$?
    elif [[ "$origin" == "$os" && "$inst_repo" == *appstream* ]]; then
      rpm_updateinfo "$key" "$current" "$branch" && state=0 || state=$?
    fi
    if (( state == 3 )) && [[ "$origin" == "$os" || "$origin" == remi ]]; then
      if rpm -q --changelog "$key" > "$work/rpm-changelog.$key"; then
        rpm_changelog_evidence "$work/rpm-changelog.$key" "$branch" && state=0
      else
        unknown "Changelog RPM instalado no disponible para $key."
      fi
    fi
    report_evidence "$state" "$key $current"
    if [[ -z "$target" ]]; then continue; fi
    pending=1
    if [[ "$candidate_record" == *$'\n'* || "$target" == *'(none)'* ||
          "$branch" != "$(branch_of "$target")" || "$origin" != "$nextprovider" ||
          "${src%%-"$version"-*}" != "${nextsrc%%-"$(upstream_of "$target")"-*}" ||
          -z "$inst_repo" || "$inst_repo" != "$nextrepo" ||
          -z "$(rpm_stream "$module")" ]] ||
       ! rpm_modularity_compatible "$module" "$target" "$nextrepo" ||
       ! rpm_compare gt "$target" "$current"; then
      manual "$key tiene un candidato ambiguo o cambio de proveedor, repositorio, rama o stream."
      continue
    fi
    nextstate=3
    if [[ "$origin" == remi && "$nextrepo" =~ ^remi-(modular|safe|php[0-9]+)$ &&
          "$(php_support "$branch")" != 'EOL upstream' ]]; then
      remi_evidence "$target" "$branch" && nextstate=0 || nextstate=$?
    elif [[ "$origin" == "$os" && "$nextrepo" == *appstream* && "$support" != "AppStream EOL"* ]]; then
      rpm_updateinfo "$key" "$target" "$branch" && nextstate=0 || nextstate=$?
    fi
    if (( nextstate == 0 && state != 0 )) ||
       { [[ "$origin" == "$os" && "$state" == 1 && "$support" != "AppStream EOL"* ]] && rpm_fix_available "$key" "$current" "$target" "$branch"; }; then
      planned[$key]=$target
      planned_repo[$key]=$nextrepo
    else
      manual "$key carece de una corrección aplicable demostrada por esta evaluación."
    fi
  done < "$work/packages"
}

build_rpm_guard() {
  mkdir "$work/plugins" && write_config_guard || return 1
  cat > "$work/plugins/vps_php_guard.py" <<'PY'
from pathlib import Path
import runpy
import dnf
import dnf.exceptions
from dnf.cli.commands.upgrade import UpgradeCommand

directory = Path(__file__).resolve().parent.parent

class Guard(dnf.Plugin):
    name = "vps_php_guard"

    def __init__(self, base, cli):
        super().__init__(base, cli)
        if cli:
            cli.register_command(GuardedUpgrade)

    def validate(self):
        try:
            transaction = self.base.transaction
            def key(package):
                return "{}.{}".format(package.name, package.arch)

            def revision(package):
                return "{}:{}-{}".format(package.epoch or 0, package.version, package.release)

            incoming = sorted("{} {} {}".format(key(p), revision(p), p.repoid)
                              for p in transaction.install_set)
            outgoing = sorted("{} {}".format(key(p), revision(p))
                              for p in transaction.remove_set)
            approved = (directory / "approved.rpm").read_text().splitlines()
            previous = (directory / "previous").read_text().splitlines()
            if not incoming or incoming != approved or outgoing != previous:
                raise ValueError("cambió el conjunto de paquetes, revisiones o repositorios")
        except Exception as exc:
            raise dnf.exceptions.Error("Transacción PHP rechazada: {}".format(exc))
        (directory / "dnf.guarded").touch()

    def resolved(self):
        self.validate()

    def pre_transaction(self):
        self.validate()
        try:
            check_rpm = runpy.run_path(str(directory / "config_guard.py"))["check_rpm"]
            for package in self.base.transaction.install_set:
                check_rpm(package.localPkg())
        except Exception as exc:
            raise dnf.exceptions.Error("Configuración PHP protegida: {}".format(exc))

class GuardedUpgrade(UpgradeCommand):
    aliases = ("vps-php-upgrade",)
    summary = "Actualización PHP con validación de la transacción"
PY
  local plugin_paths
  plugin_paths=$("$rpm_python" -c 'import dnf; conf=dnf.Base().conf; conf.read(); print(",".join(conf.pluginpath))') || return 1
  rpm_transaction=("$manager" "${rpm_options[@]}" --setopt="pluginpath=$plugin_paths,$work/plugins"
    --enableplugin=vps_php_guard --setopt=install_weak_deps=False --setopt=obsoletes=False
    --setopt=best=True --setopt=gpgcheck=True --setopt='*.gpgcheck=True')
}

make_plan() {
  local key rc=0
  : > "$work/approved"
  : > "$work/approved.rpm"
  : > "$work/previous"
  transaction_args=()
  for key in "${!planned[@]}"; do
    printf '%s %s\n' "$key" "${planned[$key]}" >> "$work/approved"
    printf '%s %s\n' "$key" "${installed[$key]}" >> "$work/previous"
    if [[ "$family" == apt ]]; then
      transaction_args+=("$key=${planned[$key]}")
    else
      transaction_args+=("${key%.*}-${planned[$key]}.${key##*.}")
      printf '%s %s %s\n' "$key" "${planned[$key]}" "${planned_repo[$key]}" >> "$work/approved.rpm"
    fi
  done
  for key in approved previous approved.rpm; do sort -o "$work/$key" "$work/$key" || return 1; done
  if [[ "$family" == apt ]]; then
    apt_transaction=(apt-get "${apt_options[@]}" --no-remove --no-install-recommends
      --only-upgrade -o DPkg::Lock::Timeout=0 -o Dpkg::Options::=--force-confold)
    "${apt_transaction[@]}" -s install "${transaction_args[@]}" > "$work/simulation" 2>&1 || rc=$?
    cat "$work/simulation"
    (( rc == 0 )) && validate_apt_plan "$work/approved" "$work/simulation"
  else
    build_rpm_guard || return 1
    "${rpm_transaction[@]}" --assumeno vps-php-upgrade "${transaction_args[@]}" > "$work/simulation" 2>&1 || rc=$?
    cat "$work/simulation"
    [[ "$rc" == 1 && -f "$work/dnf.guarded" ]] && grep -qx 'Operation aborted.' "$work/simulation"
  fi
}

# Correlaciona ejecutables y bibliotecas mapeados con sus propietarios.
# Se usa el cgroup como identidad y se valida que systemd reconozca la unidad.
discover_services() {
  local proc exe path key unit pid mappings service_kind linked
  for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    exe=${exe% (deleted)}
    service_kind=
    if php_path "$exe"; then
      [[ "${exe##*/}" == *fpm* ]] && service_kind=fpm
      [[ -n "$service_kind" ]] || service_kind=cgi
    elif [[ "${exe##*/}" =~ ^(apache2|httpd)$ ]]; then
      service_kind=apache
    elif [[ "${exe##*/}" == nginx ]]; then
      service_kind=nginx
    else
      continue
    fi
    pid=${proc##*/}
    if [[ "$(readlink "$proc/ns/mnt" 2>/dev/null)" != "$host_mount_namespace" ]]; then
      say "Proceso $pid en otro espacio de montaje: $exe. Revisar por separado."
      continue
    fi
    if [[ "$service_kind" == fpm || "$service_kind" == cgi ]]; then register_path "$exe"; fi
    # La unidad más interna puede ser un servicio de usuario o un contenedor.
    unit=$(awk -F/ '{for (i=NF;i>0;i--) if ($i ~ /[.]service$/) {print $i; exit}}' "$proc/cgroup" 2>/dev/null)
    mappings=$(awk 'NF>=6 && $6 ~ /^\// {print $6}' "$proc/maps" 2>/dev/null | sort -u) || {
      if [[ -d "$proc" ]]; then
        unknown "No se pudieron leer los mapas de $pid ($exe)."
        (( ${#affected_file[@]} == 0 )) || service_block=1
      fi
      continue
    }
    linked=0
    while IFS= read -r path; do
      [[ -n "$path" ]] || continue
      if [[ "$service_kind" == apache && "${path##*/}" == libphp*.so ]]; then
        register_path "$path"
      fi
      key=${affected_file[$path]:-}
      [[ -n "$key" ]] || continue
      linked=1
      if [[ "$service_kind" == cgi || ! "$unit" =~ ^[a-zA-Z0-9_.@-]+\.service$ ]] ||
         ! have systemctl || ! systemctl is-active --quiet "$unit"; then
        manual "Proceso afectado sin unidad gestionable: $pid ($exe)."
        service_block=1
        continue
      fi
      service_exe[$unit]=$exe
      service_type[$unit]=$service_kind
    done <<< "$exe"$'\n'"$mappings"
    if [[ -n "$unit" && -z "${seen_unit[$unit]:-}" && "$service_kind" != cgi ]]; then
      seen_unit[$unit]=1
      if [[ "$service_kind" == apache || "$service_kind" == nginx ]] &&
         have systemctl && systemctl is-active --quiet "$unit"; then
        frontend_units[$unit]=1
      fi
      say "Servicio observado: $unit | $exe | PID: $pid"
    fi
    if (( linked )) && [[ "$service_kind" == nginx ]]; then
      manual "Nginx tiene un archivo PHP actualizado mapeado; requiere evaluación manual."
      service_block=1
    fi
  done
}

test_service() {
  local unit=$1 exe=${service_exe[$1]} spec args flag pid configured_pid owner output
  local -a tokens config_args
  case "${service_type[$unit]}" in
    fpm)
      owner=$(owner_of "$exe") || return 1
      [[ -n "${installed[$owner]:-}" ]] || return 1
      spec=$(systemctl show "$unit" --property=ExecStart --value) || return 1
      pid=$(systemctl show "$unit" --property=MainPID --value) || return 1
      [[ "$pid" =~ ^[1-9][0-9]*$ && "$spec" == *'argv[]='* && "$spec" != *'} {'* ]] || return 1
      configured_pid=$(readlink -f "/proc/$pid/exe") || return 1
      [[ "${configured_pid% (deleted)}" == "$exe" ]] || return 1
      args=${spec#*argv[]=}
      args=${args%% ;*}
      read -r -a tokens <<< "$args"
      [[ "${tokens[0]:-}" == "$exe" ]] || return 1
      config_args=()
      local i
      for (( i=1; i<${#tokens[@]}; i++ )); do
        flag=${tokens[i]}
        case "$flag" in
          -F|--nodaemonize|-O|--force-stderr|-D|--daemonize) ;;
          -y|--fpm-config|-c|--php-ini|-p|--prefix|-d|--define)
            i=$((i + 1))
            [[ "${tokens[i]:-}" =~ ^[a-zA-Z0-9_./:+=,-]+$ ]] || return 1
            config_args+=("$flag" "${tokens[i]}") ;;
          --fpm-config=*|--prefix=*|--php-ini=*|--define=*)
            [[ "$flag" =~ ^[a-zA-Z0-9_./:+=,-]+$ ]] || return 1
            config_args+=("$flag") ;;
          *) return 1 ;;
        esac
      done
      if output=$(timeout 30 "$exe" "${config_args[@]}" -t 2>&1); then
        say "$output"
        ! grep -Eiq 'PHP (Warning|Fatal)|unable to load|undefined symbol' <<< "$output"
      else
        say "$output"
        return 1
      fi
      ;;
    apache)
      case "$unit:$exe" in
        apache2.service:/usr/sbin/apache2)
          spec=$(systemctl show "$unit" --property=ExecStart --value) || return 1
          [[ "$spec" =~ argv\[\]=/usr/sbin/(apachectl|apache2ctl)\ start\ \; ]] || return 1
          timeout 30 apachectl configtest ;;
        httpd.service:/usr/sbin/httpd)
          spec=$(systemctl show "$unit" --property=ExecStart --value) || return 1
          [[ "$spec" == *'argv[]=/usr/sbin/httpd -DFOREGROUND ;'* ]] || return 1
          timeout 30 "$exe" -t ;;
        *) return 1 ;;
      esac
      ;;
    nginx) timeout 30 "$exe" -t ;;
  esac
}

affected_services() {
  local key file unit
  for key in "${!planned[@]}"; do
    while IFS= read -r file; do
      [[ -f "$file" ]] || continue
      affected_file[$file]=$key
    done < "$work/files.$key"
  done
  discover_services
  for unit in "${!service_exe[@]}"; do
    say "Servicio afectado: $unit"
    service_pid_before[$unit]=$(systemctl show "$unit" --property=MainPID --value)
    if [[ ! "${service_pid_before[$unit]}" =~ ^[1-9][0-9]*$ ]] || ! test_service "$unit"; then
      manual "Falló la prueba de configuración o de identidad de $unit."
      service_block=1
    fi
  done
  (( service_block == 0 ))
}

containers() {
  local engine output
  for engine in docker podman; do
    have "$engine" || continue
    if output=$(timeout 15 "$engine" ps -a --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}}'); then
      [[ -n "$output" ]] || continue
      say "Contenedores $engine para revisión separada (las imágenes personalizadas pueden incluir PHP):"
      say "$output"
      if grep -Eiq 'php|wordpress|nextcloud|drupal|laravel|prestashop|magento' <<< "$output"; then
        manual "Hay contenedores $engine con indicios de PHP."
      else
        unknown "Cobertura PHP dentro de contenedores $engine indeterminada."
      fi
    else
      unknown "No se pudo inventariar $engine."
    fi
  done
}

preflight() {
  local space at location
  for location in / /usr /var /root "$work"; do
    space=$(df -Pk "$location" | awk 'NR==2 {print $4}') || return 1
    if [[ ! "$space" =~ ^[0-9]+$ ]] || (( space < 524288 )); then
      say "Espacio insuficiente o indeterminado en $location (mínimo 512 MiB disponibles)."
      return 1
    fi
    at=$(df -Pi "$location" | awk 'NR==2 {print $4}') || return 1
    [[ "$at" =~ ^[0-9]+$ ]] && (( at >= 1024 )) || return 1
  done
  if [[ "$family" == apt ]]; then
    local audit
    audit=$(dpkg --audit) || return 1
    [[ -z "$audit" ]] || { say "$audit"; return 1; }
    apt-get "${apt_options[@]}" -s check || return 1
  else
    rpm --verifydb || return 1
    "$manager" "${rpm_options[@]}" check || return 1
  fi
}

backup_configuration() {
  local path key file unit
  local -a paths=()
  backup=$(mktemp -d "/root/php_security_vps_${stamp}_backup.XXXXXXXX") || return 1
  cp "$work/packages" "$backup/packages.before" || return 1
  cp "$work/approved" "$backup/transaction" || return 1
  for path in /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.conf /etc/php-fpm.d /etc/opt/remi /etc/apache2 /etc/httpd /etc/nginx; do
    [[ -e "$path" ]] && paths+=("${path#/}")
  done
  for key in "${!planned[@]}"; do
    while IFS= read -r file; do
      [[ "$file" == /etc/* && ( -f "$file" || -L "$file" ) ]] || continue
      paths+=("${file#/}")
    done < "$work/files.$key"
  done
  : > "$backup/services"
  for unit in "${!service_exe[@]}"; do
    systemctl show "$unit" --property=Id,ActiveState,MainPID,FragmentPath,DropInPaths,ExecStart >> "$backup/services" || return 1
  done
  printf '%s\n' "${paths[@]}" | sort -u > "$backup/configuration.manifest" || return 1
  if (( ${#paths[@]} )); then
    tar -C / -czf "$backup/configuration.tar.gz" --null -T <(printf '%s\0' "${paths[@]}") || return 1
  fi
  say "Respaldo: $backup. Solo configuración y manifiestos. El rollback de paquetes requiere un mecanismo independiente."
}

apply_plan() {
  local key current
  if [[ "$family" == apt ]]; then
    for key in "${!planned[@]}"; do
      current=$(dpkg-query -W -f='${Version}' "$key") || return 1
      [[ "$current" == "${installed[$key]}" ]] || return 1
    done
    build_apt_guard || return 1
    if ! DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l "${apt_transaction[@]}" \
       -o "DPkg::Pre-Install-Pkgs::=$work/apt-guard" -y install "${transaction_args[@]}"; then return 1; fi
    [[ -f "$work/apt.actual" ]] && cmp -s "$work/approved" "$work/apt.actual"
  else
    rm -f "$work/dnf.guarded" || return 1
    NEEDRESTART_MODE=l "${rpm_transaction[@]}" -y vps-php-upgrade "${transaction_args[@]}" &&
      [[ -f "$work/dnf.guarded" ]]
  fi
}

validate_cli_version() {
  local path=$1 revision=$2 output version
  have runuser || return 1
  if ! output=$(cd / && timeout 20 runuser -u nobody -- "$path" -n -v 2>&1); then
    say "$output"
    return 1
  fi
  version=$(awk 'NR==1 && $1=="PHP" {print $2}' <<< "$output")
  say "PHP final de $path: ${version:-indeterminado}"
  [[ -n "$version" && "$(upstream_of "$version")" == "$(upstream_of "$revision")" ]]
}

post_validate() {
  local apply_ok=$1 key unit path revision current origin updated state=0 basename pid
  local -A after=()
  if package_inventory > "$work/packages.after"; then
    while IFS='|' read -r key revision _; do after[$key]=$revision; done < "$work/packages.after"
    [[ -z "$backup" ]] || cp "$work/packages.after" "$backup/packages.after" || state=1
    for key in "${!installed[@]}"; do
      current=${after[$key]:-}
      if [[ -z "$current" || "$current" != "${planned[$key]:-${installed[$key]}}" ]]; then
        say "Revisión final inesperada de $key: ${current:-ausente}"
        state=1
      fi
      if [[ -n "${planned[$key]:-}" && "$current" == "${planned[$key]}" ]]; then
        origin=${planned_repo[$key]}
        say "Paquete final: $key $current | PHP: $(upstream_of "$current") | origen de la transacción verificada: $origin"
        say "Evidencia final: revisión instalada idéntica a la revisión documentada en el plan."
      fi
      while IFS= read -r path; do
        basename=${path##*/}
        if [[ "$path" == *.so && -n "${extension_before[$path]:-}" && ! -f "$path" ]]; then
          say "Extensión ausente después del cambio: $path"
          state=1
        fi
        if [[ -n "${planned[$key]:-}" && "$basename" =~ ^php([0-9]+([.][0-9]+)?)?$ &&
              "$path" == */bin/* ]]; then
          if ! validate_cli_version "$path" "$current"; then
            say "La versión del binario $path no coincide con la revisión instalada."
            state=1
          fi
        fi
      done < "$work/files.$key"
    done
    for key in "${!after[@]}"; do
      if [[ -z "${installed[$key]:-}" ]]; then say "Paquete PHP nuevo inesperado: $key"; state=1; fi
    done
  else
    state=1
  fi
  for unit in "${!service_exe[@]}"; do
    updated=0
    if (( apply_ok && state == 0 )); then
      if test_service "$unit"; then
        pid=$(systemctl show "$unit" --property=MainPID --value)
        if [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "${service_pid_before[$unit]}" ]] &&
           [[ -r "/proc/$pid/maps" ]] &&
           ! grep -Eq '/[^ ]*(php|remi)[^ ]* [(]deleted[)]$' "/proc/$pid/maps"; then
          say "$unit ya usa un nuevo proceso principal tras la instalación."
          updated=1
        else
          # En Apache, un graceful reload puede conservar el módulo del padre.
          systemctl restart "$unit" && updated=1
        fi
      fi
      if (( ! updated )); then error "CRÍTICO: falló la validación o reinicio de $unit."; fi
    fi
    if systemctl is-active --quiet "$unit"; then
      say "Servicio final: $unit activo"
    else
      error "CRÍTICO: $unit está caído. Revisar journalctl -u $unit."
    fi
    if have journalctl; then
      if ! journalctl -u "$unit" --since "$transaction_started" -p warning --no-pager -n 40; then
        unknown "No se pudieron leer los logs recientes de $unit."
      fi
    fi
  done
  for unit in "${!frontend_units[@]}"; do
    [[ -z "${service_exe[$unit]:-}" ]] || continue
    if systemctl is-active --quiet "$unit"; then
      say "Servidor web observado: $unit activo"
    else
      error "CRÍTICO: cambió el estado de $unit. Revisar journalctl -u $unit."
    fi
  done
  say 'Disponibilidad funcional de aplicaciones: pendiente de pruebas HTTP o funcionales específicas.'
  (( state == 0 ))
}

process_plan() {
  local key file
  if [[ "$mode" == check || "$status_os" != supported || "$panel" != ninguno ]] ||
     (( technical || ${#planned[@]} == 0 )); then
    discover_services
  else
    for key in "${!installed[@]}"; do
      while IFS= read -r file; do
        if [[ "$file" == *.so && -f "$file" ]]; then extension_before[$file]=1; fi
      done < "$work/files.$key"
    done
    if ! preflight; then
      error 'Comprobación de espacio, dependencias o base de paquetes fallida.'
    elif ! make_plan; then
      manual 'Simulación rechazada: dependencias o resultado distinto al conjunto de paquetes PHP aprobado.'
    elif ! affected_services; then
      manual 'Transacción cancelada por riesgo de interrupción.'
    elif [[ "$mode" == update ]]; then
      if ! backup_configuration; then error 'Falló el respaldo previo de configuración.'; return 1; fi
      transaction_started=$(date '+%Y-%m-%d %H:%M:%S') || die 'No se obtuvo el comienzo de la transacción.'
      local apply_ok=1
      if ! apply_plan; then
        error 'Falló la instalación. Se comprobará el estado resultante antes de cualquier cambio adicional.'
        apply_ok=0
      fi
      if ! post_validate "$apply_ok"; then error 'Validación posterior incompleta o revisiones inesperadas.'; fi
      if (( technical )); then
        say 'Actualización: FALLIDA O PARCIAL. Revisar manifiesto, paquetes y servicios.'
      else
        say 'Actualización: APLICADA Y VALIDADA para los paquetes y servicios indicados.'
        pending=$before_pending
        indeterminate=$before_indeterminate
        cp "$work/packages.after" "$work/packages" || die 'No se pudo preparar la reevaluación final.'
        planned=()
        if [[ "$family" == apt ]]; then audit_apt || error 'Falló la reevaluación APT.'
        else audit_rpm || error 'Falló la reevaluación RPM.'; fi
      fi
    else
      say 'Simulación validada. Acciones de paquetes y servicios pendientes de --update.'
    fi
  fi
}

branch_summary() {
  local list="$work/packages" key revision source source_version branch
  [[ ! -s "$work/packages.after" ]] || list="$work/packages.after"
  [[ -s "$list" ]] || return 0
  say 'Resumen de ramas administradas y paquetes de cada fuente PHP:'
  while IFS='|' read -r key revision source source_version _; do
    if [[ "$family" == apt ]]; then deb_core "$source" || continue
    else rpm_core "$source" || continue; fi
    branch=$(branch_of "$source_version")
    printf '%s %s %s\n' "${branch:-desconocida}" "$key" "$revision"
  done < "$list" | sort
}

summary() {
  local rc=$1 work=$2 mode=$3 log=$4 logger_pid=$5 console_out=$6 console_err=$7
  trap - EXIT
  if [[ -n "$work" ]]; then
    if ! rm -rf -- "$work"; then rc=2; fi
  fi
  say "Resultado: $rc | modo: $mode | log: $log"
  # Cierra el escritor del FIFO y espera a que el log llegue a la consola SSH.
  exec 1>&"$console_out" 2>&"$console_err" {console_out}>&- {console_err}>&-
  if ! wait "$logger_pid"; then
    printf 'ERROR: No se pudo completar el log %s.\n' "$log" >&2
    rc=2
  fi
  exit "$rc"
}

main() {
  local mode=check mode_selected=0 force=0 refresh=0 option
  for option in "$@"; do
    case "$option" in
      --help) help_text; return 0 ;;
      --force) force=1 ;;
      --check|--dry-run|--update)
        if (( mode_selected )); then help_text >&2; return 2; fi
        mode=${option#--}
        mode_selected=1 ;;
      *) say "Opción desconocida: $option" >&2; help_text >&2; return 2 ;;
    esac
  done
  if (( BASH_VERSINFO[0] < 4 || EUID != 0 )) || [[ "$(uname -s)" != Linux ]]; then
    say 'Se requiere Linux, Bash 4.2 o posterior y privilegios de root.' >&2
    return 2
  fi
  if (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2 )); then return 2; fi
  if (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4 )); then set +u; fi
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
  unset PHPRC PHP_INI_SCAN_DIR LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV APT_CONFIG PYTHONPATH
  local technical=0 pending=0 indeterminate=0 service_block=0 work='' backup='' log stamp today lock_fd
  local os release major pretty family lifecycle_end status_os codename id_like esm_infra=disabled esm_apps=disabled panel=ninguno
  local manager rpm_python transaction_started host_mount_namespace key before_pending before_indeterminate
  local -a apt_options rpm_options apt_transaction rpm_transaction transaction_args
  local -A installed=()
  local -A planned=() planned_repo=() seen_path=() seen_unit=() affected_file=() extension_before=()
  local -A service_exe=() service_type=() frontend_units=() service_pid_before=()
  for key in awk sort grep date tee mktemp mkfifo find readlink timeout flock df tar cmp; do
    have "$key" || { say "Falta una dependencia del sistema: $key" >&2; return 2; }
  done
  today=$(date -u +%F) || return 2
  stamp=$(date -u +%Y%m%d_%H%M%S) || return 2
  log=$(mktemp "/root/php_security_vps_$stamp.XXXXXXXX.log") || return 2
  work=$(mktemp -d /var/tmp/php-security-vps.XXXXXXXX) || die 'No se pudo crear el directorio de trabajo.'
  local exit_args logger_pid console_out console_err
  if ! mkfifo "$work/output" || ! exec {console_out}>&1 {console_err}>&2; then
    rm -rf -- "$work"
    die 'No se pudo preparar el log.'
  fi
  tee -a "$log" < "$work/output" &
  logger_pid=$!
  exec > "$work/output" 2>&1
  printf -v exit_args '%q %q %q %q %q %q' "$work" "$mode" "$log" "$logger_pid" "$console_out" "$console_err"
  trap 'summary "$?" '"$exit_args" EXIT
  trap 'exit 2' HUP INT TERM
  say "Inicio: $(date -u +%FT%TZ) | modo: $mode | arquitectura: $(uname -m)"
  say 'Alcance del estado de parches: campaña del 19-11-2026 y erratas adicionales identificadas explícitamente.'
  [[ -r /etc/os-release ]] || die 'No se puede leer /etc/os-release.'
  os=$(os_value ID)
  release=$(os_value VERSION_ID)
  pretty=$(os_value PRETTY_NAME)
  major=${release%%.*}
  lifecycle
  if [[ "$family" == unknown ]]; then
    id_like=" $(os_value ID_LIKE) "
    if [[ "$id_like" == *' debian '* || "$id_like" == *' ubuntu '* ]] && have apt-get && have dpkg-query; then
      family=apt
    elif [[ "$id_like" == *' rhel '* || "$id_like" == *' fedora '* ]] && have rpm; then
      family=rpm
    fi
  fi
  if [[ -d /usr/local/cpanel ]]; then panel=cPanel
  elif [[ -d /usr/local/directadmin ]]; then panel=DirectAdmin
  elif [[ -d /usr/local/psa || -d /opt/psa || -e /etc/psa/psa.conf ]]; then panel=Plesk
  fi
  say "Sistema: ${pretty:-$os $release} | gestor: $family | ciclo: $status_os ${lifecycle_end:-sin fecha verificada} | panel: $panel"
  case "$panel" in
    cPanel) manual 'Usar cpanel/verificar_actualizar_php_cpanel.sh.' ;;
    DirectAdmin) manual 'Usar el procedimiento PHP de DirectAdmin CustomBuild.' ;;
    Plesk) manual 'Usar el procedimiento de administración de PHP de Plesk.' ;;
  esac
  case "$status_os" in
    eol) manual 'CRÍTICO: ciclo documentado agotado. Planificar migración o verificar soporte extendido.' ;;
    unknown) unknown 'Versión o distribución sin ciclo verificado. Auditoría únicamente.' ;;
  esac
  if [[ "$mode" == update && "$panel" == ninguno && "$status_os" == supported ]]; then
    exec {lock_fd}>/run/lock/php-security-vps.lock || die 'No se pudo abrir el bloqueo de ejecución.'
    flock -n "$lock_fd" || die 'Ya hay otra ejecución de actualización PHP.'
  fi
  : > "$work/paths"
  host_mount_namespace=$(readlink /proc/self/ns/mnt) || die 'No se pudo identificar el espacio de montaje del host.'
  case "$family" in
    apt)
      for key in apt apt-cache apt-get apt-mark dpkg dpkg-query dpkg-deb; do
        have "$key" || die "Falta $key."
      done ;;
    rpm) have rpm || die 'Falta rpm.' ;;
  esac
  if [[ "$family" != unknown ]]; then inventory_packages || die 'Inventario de paquetes incompleto.'; fi
  discover_paths
  containers
  before_pending=$pending
  before_indeterminate=$indeterminate
  if (( ${#installed[@]} )); then
    if [[ "$os" == ubuntu ]]; then
      if have pro; then
        if timeout 30 pro status > "$work/pro.status"; then
          cat "$work/pro.status"
          if awk '$1=="esm-infra" && $3=="enabled" {enabled=1} END {exit !enabled}' "$work/pro.status"; then
            esm_infra=enabled
          fi
          if awk '$1=="esm-apps" && $3=="enabled" {enabled=1} END {exit !enabled}' "$work/pro.status"; then
            esm_apps=enabled
          fi
        else
          unknown 'Ubuntu Pro no respondió correctamente.'
        fi
        if ! timeout 30 pro security-status; then unknown 'Cobertura ESM por paquete indeterminada.'; fi
      elif [[ "$release" == 20.04 ]]; then
        manual 'Ubuntu 20.04 requiere acreditar Ubuntu Pro/ESM.'
      fi
    fi
    before_pending=$pending
    before_indeterminate=$indeterminate
    if [[ "$status_os" == supported && "$panel" == ninguno ]] &&
       { (( force )) || [[ "$mode" == update ]]; }; then
      refresh=1
    fi
    case "$family" in
      apt)
        if prepare_apt; then audit_apt || error 'Falló la auditoría APT.'
        else error 'Índices APT incompletos o repositorios inaccesibles.'; fi ;;
      rpm)
        if prepare_rpm; then audit_rpm || error 'Falló la auditoría RPM.'
        elif [[ "$status_os" == eol ]]; then unknown 'Los metadatos históricos YUM/DNF no están disponibles.'
        else error 'Índices RPM incompletos o repositorios inaccesibles.'; fi ;;
    esac
  fi
  process_plan
  if (( ${#installed[@]} == 0 && ${#seen_path[@]} == 0 )); then
    say 'No se detectó PHP en paquetes, rutas ni procesos inspeccionados del host.'
  fi
  branch_summary || error 'No se pudo generar el resumen de ramas.'
  if (( technical )); then exit 2; fi
  if (( pending )); then exit 1; fi
  if (( indeterminate )); then exit 3; fi
  exit 0
}


# Bash deja BASH_SOURCE vacío al recibir el script por stdin.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  main "$@" </dev/null
fi
