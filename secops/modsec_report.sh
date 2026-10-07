#!/bin/bash
# ==============================================================================
# modsec_report.sh
# ==============================================================================
# Script unificado para búsqueda y análisis de logs de ModSecurity.
# Soporta búsqueda por IP o por Dominio + URI.
# Genera recomendaciones de reglas ModSecurity deshabilitadas por URI (sin host).
#
# Uso interactivo:
#   ./modsec_report.sh
#
# Uso por CLI:
#   ./modsec_report.sh ip <IP> [ticket] [logfile]
#   ./modsec_report.sh domain <dominio> <URI_aproximada> [ticket] [logfile]
#
# Ejemplos:
#   ./modsec_report.sh ip 190.116.61.94 1844933
#   ./modsec_report.sh domain cessum.mx /wa_webhook 31707783
# ==============================================================================

DEFAULT_LOGFILE="/usr/local/apache/logs/modsec_audit.log"

show_help() {
  echo "Uso interactivo:"
  echo "  $0"
  echo ""
  echo "Uso CLI:"
  echo "  $0 ip <IP> [ticket] [logfile]"
  echo "  $0 domain <dominio> <URI_aproximada> [ticket] [logfile]"
  echo ""
  echo "Ejemplos:"
  echo "  $0 ip 190.116.61.94 1844933"
  echo "  $0 domain kivae.com.mx /wc-api/Openpay_Cards 31705330"
  echo "  $0 domain cessum.mx /wa_webhook 31707783"
  exit 1
}

# ------------------------------------------------------------------------------
# Función: Búsqueda por IP
# ------------------------------------------------------------------------------
search_by_ip() {
  local ip="$1"
  local ticket="${2:-0000000}"
  local logfile="${3:-$DEFAULT_LOGFILE}"

  if [ -z "$ip" ]; then
    echo "[ERROR] Debe especificar una IP."
    exit 1
  fi

  if [ ! -f "$logfile" ]; then
    echo "[ERROR] No existe el archivo de log: $logfile"
    exit 1
  fi

  awk -v target_ip="$ip" -v ticket="$ticket" '
  function reset_tx() {
    remote_ip=""
    host=""
    method=""
    uri=""
    endpoint=""
    status=""
    msg_count=0
    delete rule_ids
    delete severities
  }

  function regex_escape(value, out, i, ch) {
    out=""
    for (i=1; i<=length(value); i++) {
      ch=substr(value,i,1)
      if (ch ~ /[][(){}.^$*+?|\\-]/) {
        out=out "\\" ch
      } else {
        out=out ch
      }
    }
    return out
  }

  function flush_tx(   i, key) {
    if (remote_ip != target_ip) {
      reset_tx()
      return
    }

    tx_match_count++

    for (i = 1; i <= msg_count; i++) {
      key = endpoint SUBSEP rule_ids[i] SUBSEP severities[i] SUBSEP status
      combo_count[key]++
      rule_count[rule_ids[i]]++
      if (rule_ids[i] != "-") {
        endpoint_rule[endpoint, rule_ids[i]] = 1
      }
      endpoint_seen[endpoint] = 1
    }

    reset_tx()
  }

  BEGIN {
    reset_tx()
    inA=0; inB=0; inF=0; inH=0
    tx_match_count=0
  }

  /^--[^-]+-A--$/ {
    if (remote_ip != "" || msg_count > 0 || method != "" || status != "") {
      flush_tx()
    }
    reset_tx()
    inA=1; inB=0; inF=0; inH=0
    next
  }

  /^--[^-]+-[A-Z]--$/ {
    inA=0; inB=0; inF=0; inH=0
    if ($0 ~ /-A--$/) inA=1
    else if ($0 ~ /-B--$/) inB=1
    else if ($0 ~ /-F--$/) inF=1
    else if ($0 ~ /-H--$/) inH=1
    else if ($0 ~ /-Z--$/) flush_tx()
    next
  }

  inA && remote_ip == "" {
    n=split($0, a, /[[:space:]]+/)
    if (n >= 4) {
      remote_ip = a[4]
    }
    next
  }

  inB && method == "" {
    request_line=$0
    sub(/\r$/, "", request_line)
    n=split(request_line, a, /[[:space:]]+/)
    if (n >= 3 && a[1] ~ /^[A-Z]+$/ && a[n] ~ /^HTTP\/[0-9.]+$/) {
      method = a[1]
      uri = a[2]
      endpoint = uri
      sub(/\?.*/, "", endpoint)
    }
    next
  }

  inF && status == "" {
    response_line=$0
    sub(/\r$/, "", response_line)
    n=split(response_line, a, /[[:space:]]+/)
    if (n >= 2 && a[1] ~ /^HTTP\/[0-9.]+$/ && a[2] ~ /^[0-9][0-9][0-9]$/) {
      status = a[2]
    }
    next
  }

  inH && /^Message:/ {
    msg_count++
    rule_ids[msg_count]="-"
    severities[msg_count]="-"
    line=$0

    if (line ~ /\[id "[^"]+"\]/) {
      id_value=line
      sub(/^.*\[id "/, "", id_value)
      sub(/"\].*$/, "", id_value)
      rule_ids[msg_count]=id_value
    }

    if (line ~ /\[severity "[^"]+"\]/) {
      severity_value=line
      sub(/^.*\[severity "/, "", severity_value)
      sub(/"\].*$/, "", severity_value)
      severities[msg_count]=severity_value
    }
    next
  }

  END {
    if (remote_ip != "" || msg_count > 0 || method != "" || status != "") {
      flush_tx()
    }

    print ""
    print "=============================================="
    print "BUSQUEDA MODSECURITY (POR IP)"
    print "=============================================="
    print ""
    print "IP analizada:              " target_ip
    print "Transacciones encontradas: " tx_match_count
    print ""

    if (tx_match_count == 0) {
      print "No se encontraron transacciones para la IP."
      exit
    }

    printf "%-50s %-12s %-10s %-8s %-8s\n", "Endpoint", "Rule ID", "Severity", "Status", "Veces"
    printf "%-50s %-12s %-10s %-8s %-8s\n", "--------------------------------------------------", "------------", "----------", "--------", "--------"

    n=0
    for (k in combo_count) {
      split(k, p, SUBSEP)
      endpoint_arr[++n] = p[1]
      rule_arr[n] = p[2]
      sev_arr[n] = p[3]
      stat_arr[n] = p[4]
      count_arr[n] = combo_count[k]
    }

    for (i=1; i<=n; i++) {
      for (j=i+1; j<=n; j++) {
        if (endpoint_arr[i] > endpoint_arr[j] || (endpoint_arr[i] == endpoint_arr[j] && rule_arr[i] > rule_arr[j])) {
          tmp=endpoint_arr[i]; endpoint_arr[i]=endpoint_arr[j]; endpoint_arr[j]=tmp
          tmp=rule_arr[i]; rule_arr[i]=rule_arr[j]; rule_arr[j]=tmp
          tmp=sev_arr[i]; sev_arr[i]=sev_arr[j]; sev_arr[j]=tmp
          tmp=stat_arr[i]; stat_arr[i]=stat_arr[j]; stat_arr[j]=tmp
          tmp=count_arr[i]; count_arr[i]=count_arr[j]; count_arr[j]=tmp
        }
      }
    }

    for (i=1; i<=n; i++) {
      printf "%-50s %-12s %-10s %-8s %-8s\n", endpoint_arr[i], rule_arr[i], sev_arr[i], stat_arr[i], count_arr[i]
    }

    print ""
    print "Total por regla:"
    printf "%-12s %-8s\n", "Rule ID", "Veces"
    printf "%-12s %-8s\n", "------------", "--------"

    nr=0
    for (r in rule_count) {
      rid[++nr]=r
      rcount[nr]=rule_count[r]
    }

    for (i=1; i<=nr; i++) {
      for (j=i+1; j<=nr; j++) {
        if (rcount[i] < rcount[j]) {
          tmp=rid[i]; rid[i]=rid[j]; rid[j]=tmp
          tmp=rcount[i]; rcount[i]=rcount[j]; rcount[j]=tmp
        }
      }
    }

    for (i=1; i<=nr; i++) {
      printf "%-12s %-8s\n", rid[i], rcount[i]
    }

    print ""
    print "=============================================="
    print "REGLAS SUGERIDAS (SIN HOST)"
    print "=============================================="
    print ""

    for (ep in endpoint_seen) {
      delete list
      c=0
      for (k in endpoint_rule) {
        split(k, p, SUBSEP)
        if (p[1] == ep && p[2] != "-") {
          c++
          list[c]=p[2]
        }
      }

      if (c == 0) continue

      for (i=1; i<=c; i++) {
        for (j=i+1; j<=c; j++) {
          if ((list[i]+0) > (list[j]+0)) {
            tmp=list[i]; list[i]=list[j]; list[j]=tmp
          }
        }
      }

      ctl=""
      for (i=1; i<=c; i++) {
        if (i > 1) ctl=ctl ","
        ctl=ctl "ctl:ruleRemoveById=" list[i]
      }

      ep_rx=regex_escape(ep)
      if (ep ~ /\?/) {
        uri_pat="^" ep_rx ".*$"
      } else {
        uri_pat="^" ep_rx "(\\?.*)?$"
      }

      print "# Disable ModSecurity rules for URI"
      print "# ticket " ticket
      print "SecRule REQUEST_URI \"@rx " uri_pat "\" \"id:20000120,nolog,pass," ctl "\""
      print ""
    }
  }
  ' "$logfile"
}

# ------------------------------------------------------------------------------
# Función: Búsqueda por Dominio y URI (con Wildcard en Dominio y URI)
# ------------------------------------------------------------------------------
search_by_domain_uri() {
  local raw_domain="$1"
  local raw_uri="$2"
  local ticket="${3:-0000000}"
  local logfile="${4:-$DEFAULT_LOGFILE}"

  if [ -z "$raw_domain" ] || [ -z "$raw_uri" ]; then
    echo "[ERROR] Debe especificar Dominio y URI."
    exit 1
  fi

  if [ ! -f "$logfile" ]; then
    echo "[ERROR] No existe el archivo de log: $logfile"
    exit 1
  fi

  # Normaliza el dominio ingresado
  local domain
  domain=$(printf '%s' "$raw_domain" | tr '[:upper:]' '[:lower:]')
  domain="${domain#http://}"
  domain="${domain#https://}"
  domain="${domain%%/*}"
  domain="${domain%%:*}"
  domain="${domain%.}"
  domain="${domain#www.}"

  # Normaliza la URI ingresada
  local target_uri="$raw_uri"
  case "$target_uri" in
    /*) ;;
    *) target_uri="/$target_uri" ;;
  esac

  awk -v target_domain="$domain" -v target_uri="$target_uri" -v ticket="$ticket" '

  function reset_tx() {
    remote_ip=""
    host=""
    method=""
    uri=""
    endpoint=""
    status=""
    msg_count=0
    delete rule_ids
    delete severities
  }

  function normalize_host(value) {
    value=tolower(value)
    gsub(/^[[:space:]]+/, "", value)
    gsub(/[[:space:]]+$/, "", value)
    sub(/\r$/, "", value)
    sub(/:[0-9]+$/, "", value)
    sub(/\.$/, "", value)
    return value
  }

  function base_host(value) {
    value=normalize_host(value)
    sub(/^www\./, "", value)
    return value
  }

  # Coincidencia flexible/wildcard de dominio (dominio exacto o subdominios)
  function host_matches(value, normalized, suffix) {
    normalized=base_host(value)
    if (normalized == target_domain) {
      return 1
    }
    suffix="." target_domain
    if (length(normalized) > length(suffix) &&
        substr(normalized, length(normalized) - length(suffix) + 1) == suffix) {
      return 1
    }
    return 0
  }

  # Coincidencia flexible/wildcard de URI (coincide subcadena en la URI)
  function uri_matches(value) {
    return index(tolower(value), tolower(target_uri)) > 0
  }

  function regex_escape(value, out, i, ch) {
    out=""
    for (i=1; i<=length(value); i++) {
      ch=substr(value,i,1)
      if (ch ~ /[][(){}.^$*+?|\\-]/) {
        out=out "\\" ch
      } else {
        out=out ch
      }
    }
    return out
  }

  function flush_tx(i, key) {
    host=normalize_host(host)

    if (!host_matches(host) || !uri_matches(endpoint)) {
      reset_tx()
      return
    }

    tx_match_count++

    actual_hosts[host]=1
    actual_endpoints[endpoint]=1
    host_endpoint[host,endpoint]=1

    if (remote_ip != "") {
      ip_count[remote_ip]++
    }

    for (i=1; i<=msg_count; i++) {
      key=host SUBSEP endpoint SUBSEP rule_ids[i] SUBSEP severities[i] SUBSEP status
      combo_count[key]++
      rule_count[rule_ids[i]]++
      if (rule_ids[i] != "-") {
        endpoint_rule[endpoint, rule_ids[i]]=1
      }
    }

    reset_tx()
  }

  BEGIN {
    reset_tx()
    inA=0; inB=0; inF=0; inH=0
    tx_match_count=0
  }

  /^--[^-]+-A--$/ {
    if (remote_ip != "" || host != "" || method != "" || status != "" || msg_count > 0) {
      flush_tx()
    }
    reset_tx()
    inA=1; inB=0; inF=0; inH=0
    next
  }

  /^--[^-]+-[A-Z]--$/ {
    inA=0; inB=0; inF=0; inH=0
    if ($0 ~ /-A--$/) inA=1
    else if ($0 ~ /-B--$/) inB=1
    else if ($0 ~ /-F--$/) inF=1
    else if ($0 ~ /-H--$/) inH=1
    else if ($0 ~ /-Z--$/) flush_tx()
    next
  }

  inA && remote_ip == "" {
    n=split($0,a,/[[:space:]]+/)
    if (n >= 4) {
      remote_ip=a[4]
    }
    next
  }

  inB && method == "" {
    request_line=$0
    sub(/\r$/, "", request_line)
    n=split(request_line,a,/[[:space:]]+/)
    if (n >= 3 && a[1] ~ /^[A-Z]+$/ && a[n] ~ /^HTTP\/[0-9.]+$/) {
      method=a[1]
      uri=a[2]
      endpoint=uri
    }
    next
  }

  inB && tolower($0) ~ /^host:[[:space:]]*/ {
    host=$0
    sub(/^[^:]+:[[:space:]]*/, "", host)
    host=normalize_host(host)
    next
  }

  inF && status == "" {
    response_line=$0
    sub(/\r$/, "", response_line)
    n=split(response_line,a,/[[:space:]]+/)
    if (n >= 2 && a[1] ~ /^HTTP\/[0-9.]+$/ && a[2] ~ /^[0-9][0-9][0-9]$/) {
      status=a[2]
    }
    next
  }

  inH && /^Message:/ {
    msg_count++
    rule_ids[msg_count]="-"
    severities[msg_count]="-"
    line=$0

    if (line ~ /\[id "[^"]+"\]/) {
      id_value=line
      sub(/^.*\[id "/, "", id_value)
      sub(/"\].*$/, "", id_value)
      rule_ids[msg_count]=id_value
    }

    if (line ~ /\[severity "[^"]+"\]/) {
      severity_value=line
      sub(/^.*\[severity "/, "", severity_value)
      sub(/"\].*$/, "", severity_value)
      severities[msg_count]=severity_value
    }
    next
  }

  END {
    if (remote_ip != "" || host != "" || method != "" || status != "" || msg_count > 0) {
      flush_tx()
    }

    print ""
    print "=============================================="
    print "BUSQUEDA MODSECURITY (POR DOMINIO Y URI)"
    print "=============================================="
    print ""
    print "Dominio buscado:           " target_domain
    print "URI aproximada:            " target_uri
    print "Transacciones encontradas: " tx_match_count
    print ""

    if (tx_match_count == 0) {
      print "No se encontraron transacciones aproximadas."
      print ""
      print "Se buscó:"
      print "  Dominio base: " target_domain
      print "  URI contiene: " target_uri
      exit
    }

    print "Hosts encontrados:"
    for (h in actual_hosts) {
      print "  " h
    }
    print ""

    print "Endpoints encontrados:"
    for (ep in actual_endpoints) {
      print "  " ep
    }
    print ""

    printf "%-30s %-70s %-12s %-10s %-8s %-8s\n", "Host", "Endpoint", "Rule ID", "Severity", "Status", "Veces"
    printf "%-30s %-70s %-12s %-10s %-8s %-8s\n", "------------------------------", "----------------------------------------------------------------------", "------------", "----------", "--------", "--------"

    n=0
    for (k in combo_count) {
      split(k,p,SUBSEP)
      host_arr[++n]=p[1]
      endpoint_arr[n]=p[2]
      rule_arr[n]=p[3]
      sev_arr[n]=p[4]
      stat_arr[n]=p[5]
      count_arr[n]=combo_count[k]
    }

    for (i=1; i<=n; i++) {
      for (j=i+1; j<=n; j++) {
        swap=0
        if (host_arr[i] > host_arr[j]) swap=1
        else if (host_arr[i] == host_arr[j] && endpoint_arr[i] > endpoint_arr[j]) swap=1
        else if (host_arr[i] == host_arr[j] && endpoint_arr[i] == endpoint_arr[j] && rule_arr[i] > rule_arr[j]) swap=1

        if (swap) {
          tmp=host_arr[i]; host_arr[i]=host_arr[j]; host_arr[j]=tmp
          tmp=endpoint_arr[i]; endpoint_arr[i]=endpoint_arr[j]; endpoint_arr[j]=tmp
          tmp=rule_arr[i]; rule_arr[i]=rule_arr[j]; rule_arr[j]=tmp
          tmp=sev_arr[i]; sev_arr[i]=sev_arr[j]; sev_arr[j]=tmp
          tmp=stat_arr[i]; stat_arr[i]=stat_arr[j]; stat_arr[j]=tmp
          tmp=count_arr[i]; count_arr[i]=count_arr[j]; count_arr[j]=tmp
        }
      }
    }

    for (i=1; i<=n; i++) {
      printf "%-30s %-70s %-12s %-10s %-8s %-8s\n", host_arr[i], endpoint_arr[i], rule_arr[i], sev_arr[i], stat_arr[i], count_arr[i]
    }

    print ""
    print "Total por regla:"
    printf "%-12s %-8s\n", "Rule ID", "Veces"
    printf "%-12s %-8s\n", "------------", "--------"

    nr=0
    for (r in rule_count) {
      rid[++nr]=r
      rcount[nr]=rule_count[r]
    }

    for (i=1; i<=nr; i++) {
      for (j=i+1; j<=nr; j++) {
        if (rcount[i] < rcount[j]) {
          tmp=rid[i]; rid[i]=rid[j]; rid[j]=tmp
          tmp=rcount[i]; rcount[i]=rcount[j]; rcount[j]=tmp
        }
      }
    }

    for (i=1; i<=nr; i++) {
      printf "%-12s %-8s\n", rid[i], rcount[i]
    }

    print ""
    print "IPs que realizaron las solicitudes:"
    printf "%-40s %-8s\n", "IP", "Veces"
    printf "%-40s %-8s\n", "----------------------------------------", "--------"

    nip=0
    for (ip in ip_count) {
      ips[++nip]=ip
      ipcounts[nip]=ip_count[ip]
    }

    for (i=1; i<=nip; i++) {
      for (j=i+1; j<=nip; j++) {
        if (ipcounts[i] < ipcounts[j]) {
          tmp=ips[i]; ips[i]=ips[j]; ips[j]=tmp
          tmp=ipcounts[i]; ipcounts[i]=ipcounts[j]; ipcounts[j]=tmp
        }
      }
    }

    for (i=1; i<=nip; i++) {
      printf "%-40s %-8s\n", ips[i], ipcounts[i]
    }

    print ""
    print "=============================================="
    print "REGLAS SUGERIDAS (SIN HOST)"
    print "=============================================="
    print ""

    for (ep in actual_endpoints) {
      delete list
      c=0

      for (k in endpoint_rule) {
        split(k, p, SUBSEP)
        if (p[1] == ep && p[2] != "-") {
          c++
          list[c]=p[2]
        }
      }

      if (c == 0) continue

      for (i=1; i<=c; i++) {
        for (j=i+1; j<=c; j++) {
          if ((list[i]+0) > (list[j]+0)) {
            tmp=list[i]; list[i]=list[j]; list[j]=tmp
          }
        }
      }

      ctl=""
      for (i=1; i<=c; i++) {
        if (i > 1) ctl=ctl ","
        ctl=ctl "ctl:ruleRemoveById=" list[i]
      }

      ep_rx=regex_escape(ep)
      if (ep ~ /\?/) {
        uri_pat="^" ep_rx ".*$"
      } else {
        uri_pat="^" ep_rx "(\\?.*)?$"
      }

      print "# Disable ModSecurity rules for URI"
      print "# ticket " ticket
      print "SecRule REQUEST_URI \"@rx " uri_pat "\" \"id:20000120,nolog,pass," ctl "\""
      print ""
    }
  }
  ' "$logfile"
}

# ------------------------------------------------------------------------------
# Modo Interactivo
# ------------------------------------------------------------------------------
interactive_menu() {
  echo "=============================================="
  echo "   BUSCADOR Y ANALIZADOR DE MODSECURITY"
  echo "=============================================="
  echo "Seleccione una opción:"
  echo "  1) Buscar por IP"
  echo "  2) Buscar por Dominio y URI"
  echo "  3) Salir"
  echo ""
  read -rp "Opción [1-3]: " opt

  case "$opt" in
    1)
      read -rp "Ingrese la IP a buscar: " ip
      read -rp "Número de ticket [0000000]: " ticket
      ticket="${ticket:-0000000}"
      read -rp "Ruta del log [$DEFAULT_LOGFILE]: " logfile
      logfile="${logfile:-$DEFAULT_LOGFILE}"
      search_by_ip "$ip" "$ticket" "$logfile"
      ;;
    2)
      read -rp "Ingrese el Dominio (ej: dominio.com): " domain
      read -rp "Ingrese la URI aproximada (ej: /wc-api/Openpay_Cards): " uri
      read -rp "Número de ticket [0000000]: " ticket
      ticket="${ticket:-0000000}"
      read -rp "Ruta del log [$DEFAULT_LOGFILE]: " logfile
      logfile="${logfile:-$DEFAULT_LOGFILE}"
      search_by_domain_uri "$domain" "$uri" "$ticket" "$logfile"
      ;;
    3)
      echo "Saliendo."
      exit 0
      ;;
    *)
      echo "[ERROR] Opción no válida."
      exit 1
      ;;
  esac
}

# ------------------------------------------------------------------------------
# Dispatcher / Control de Parámetros
# ------------------------------------------------------------------------------
if [ "$#" -eq 0 ]; then
  interactive_menu
  exit 0
fi

MODE="$1"

case "$MODE" in
  ip|-ip|--ip)
    shift
    search_by_ip "$@"
    ;;
  domain|-domain|--domain|uri|-uri|--uri)
    shift
    search_by_domain_uri "$@"
    ;;
  -h|--help|help)
    show_help
    ;;
  *)
    # Detección automática por formato del primer argumento
    if [[ "$MODE" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ "$MODE" =~ : ]]; then
      search_by_ip "$@"
    elif [ "$#" -ge 2 ]; then
      search_by_domain_uri "$@"
    else
      show_help
    fi
    ;;
esac
