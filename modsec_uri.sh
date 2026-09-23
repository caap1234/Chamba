#!/bin/bash

LOGFILE="/usr/local/apache/logs/modsec_audit.log"

if [ "$#" -lt 2 ]; then
  echo "Uso: $0 <dominio> <URI_aproximada> [ticket]"
  echo "Ejemplo: $0 kivae.com.mx /wc-api/Openpay_Cards 31705330"
  echo "Ejemplo: $0 cessum.mx /wa_webhook 31707783"
  exit 1
fi

DOMAIN=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
TARGET_URI="$2"
TICKET="${3:-0000000}"

# Elimina protocolo si accidentalmente fue incluido.
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"

# Elimina ruta si accidentalmente fue incluida con el dominio.
DOMAIN="${DOMAIN%%/*}"

# Elimina puerto y punto final.
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%.}"

# Elimina www. para que dominio.com y www.dominio.com sean equivalentes.
DOMAIN="${DOMAIN#www.}"

# Asegura que la URI comience con /.
case "$TARGET_URI" in
  /*) ;;
  *) TARGET_URI="/$TARGET_URI" ;;
esac

# Ignora parámetros GET.
TARGET_URI="${TARGET_URI%%\?*}"

if [ ! -f "$LOGFILE" ]; then
  echo "No existe el log: $LOGFILE"
  exit 1
fi

awk -v target_domain="$DOMAIN" -v target_uri="$TARGET_URI" -v ticket="$TICKET" '

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

#
# Elimina www. para efectos de búsqueda.
#
function base_host(value) {
  value=normalize_host(value)

  sub(/^www\./, "", value)

  return value
}

#
# Coincidencia flexible pero segura del dominio.
#
# Ejemplos buscando dominio.com:
#
# dominio.com       -> SI
# www.dominio.com   -> SI
# api.dominio.com   -> SI
# x.api.dominio.com -> SI
# falsodominio.com  -> NO
#
function host_matches(value, normalized, suffix) {
  normalized=base_host(value)

  if (normalized == target_domain) {
    return 1
  }

  suffix="." target_domain

  if (
    length(normalized) > length(suffix) &&
    substr(
      normalized,
      length(normalized) - length(suffix) + 1
    ) == suffix
  ) {
    return 1
  }

  return 0
}

#
# Coincidencia aproximada de URI.
#
# Ejemplos buscando /wa_webhook:
#
# /wa_webhook.php             -> SI
# /api/wa_webhook.php         -> SI
# /WA_WEBHOOK.PHP             -> SI
# /foo/bar                    -> NO
#
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

  #
  # Aquí ya no exigimos igualdad literal.
  #
  if (!host_matches(host) || !uri_matches(endpoint)) {
    reset_tx()
    return
  }

  tx_match_count++

  #
  # Guardamos host y endpoint REALES encontrados.
  #
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
    endpoint_rule[host,endpoint,rule_ids[i]]=1
  }

  reset_tx()
}

BEGIN {
  reset_tx()

  inA=0
  inB=0
  inF=0
  inH=0

  tx_match_count=0
}

/^--[^-]+-A--$/ {
  if (
    remote_ip != "" ||
    host != "" ||
    method != "" ||
    status != "" ||
    msg_count > 0
  ) {
    flush_tx()
  }

  reset_tx()

  inA=1
  inB=0
  inF=0
  inH=0

  next
}

/^--[^-]+-[A-Z]--$/ {
  inA=0
  inB=0
  inF=0
  inH=0

  if ($0 ~ /-A--$/) {
    inA=1
  } else if ($0 ~ /-B--$/) {
    inB=1
  } else if ($0 ~ /-F--$/) {
    inF=1
  } else if ($0 ~ /-H--$/) {
    inH=1
  } else if ($0 ~ /-Z--$/) {
    flush_tx()
  }

  next
}

#
# Sección A: IP remota.
#
inA && remote_ip == "" {
  n=split($0,a,/[[:space:]]+/)

  if (n >= 4) {
    remote_ip=a[4]
  }

  next
}

#
# Sección B: petición HTTP.
#
inB && method == "" {
  request_line=$0
  sub(/\r$/, "", request_line)

  n=split(request_line,a,/[[:space:]]+/)

  if (
    n >= 3 &&
    a[1] ~ /^[A-Z]+$/ &&
    a[n] ~ /^HTTP\/[0-9.]+$/
  ) {
    method=a[1]
    uri=a[2]
    endpoint=uri

    sub(/\?.*/, "", endpoint)
  }

  next
}

#
# Sección B: Host.
#
inB && tolower($0) ~ /^host:[[:space:]]*/ {
  host=$0

  sub(/^[^:]+:[[:space:]]*/, "", host)
  host=normalize_host(host)

  next
}

#
# Sección F: código HTTP.
#
inF && status == "" {
  response_line=$0
  sub(/\r$/, "", response_line)

  n=split(response_line,a,/[[:space:]]+/)

  if (
    n >= 2 &&
    a[1] ~ /^HTTP\/[0-9.]+$/ &&
    a[2] ~ /^[0-9][0-9][0-9]$/
  ) {
    status=a[2]
  }

  next
}

#
# Sección H: reglas ModSecurity.
#
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

  #
  # Procesa una transacción incompleta.
  #
  if (
    remote_ip != "" ||
    host != "" ||
    method != "" ||
    status != "" ||
    msg_count > 0
  ) {
    flush_tx()
  }

  print ""
  print "=============================================="
  print "BUSQUEDA MODSECURITY"
  print "=============================================="
  print ""
  print "Dominio buscado: " target_domain
  print "URI aproximada:  " target_uri
  print ""
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

  #
  # Hosts reales encontrados.
  #
  print "Hosts encontrados:"
  print ""

  for (h in actual_hosts) {
    print "  " h
  }

  print ""

  #
  # Endpoints reales encontrados.
  #
  print "Endpoints encontrados:"
  print ""

  for (ep in actual_endpoints) {
    print "  " ep
  }

  print ""

  printf "%-30s %-50s %-12s %-10s %-8s %-8s\n",
         "Host",
         "Endpoint",
         "Rule ID",
         "Severity",
         "Status",
         "Veces"

  printf "%-30s %-50s %-12s %-10s %-8s %-8s\n",
         "------------------------------",
         "--------------------------------------------------",
         "------------",
         "----------",
         "--------",
         "--------"

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

  #
  # Ordenamiento.
  #
  for (i=1; i<=n; i++) {
    for (j=i+1; j<=n; j++) {

      swap=0

      if (host_arr[i] > host_arr[j]) {
        swap=1
      } else if (
        host_arr[i] == host_arr[j] &&
        endpoint_arr[i] > endpoint_arr[j]
      ) {
        swap=1
      } else if (
        host_arr[i] == host_arr[j] &&
        endpoint_arr[i] == endpoint_arr[j] &&
        rule_arr[i] > rule_arr[j]
      ) {
        swap=1
      }

      if (swap) {
        tmp=host_arr[i]
        host_arr[i]=host_arr[j]
        host_arr[j]=tmp

        tmp=endpoint_arr[i]
        endpoint_arr[i]=endpoint_arr[j]
        endpoint_arr[j]=tmp

        tmp=rule_arr[i]
        rule_arr[i]=rule_arr[j]
        rule_arr[j]=tmp

        tmp=sev_arr[i]
        sev_arr[i]=sev_arr[j]
        sev_arr[j]=tmp

        tmp=stat_arr[i]
        stat_arr[i]=stat_arr[j]
        stat_arr[j]=tmp

        tmp=count_arr[i]
        count_arr[i]=count_arr[j]
        count_arr[j]=tmp
      }
    }
  }

  for (i=1; i<=n; i++) {
    printf "%-30s %-50s %-12s %-10s %-8s %-8s\n",
           host_arr[i],
           endpoint_arr[i],
           rule_arr[i],
           sev_arr[i],
           stat_arr[i],
           count_arr[i]
  }

  print ""
  print "Total por regla:"
  print ""

  printf "%-12s %-8s\n","Rule ID","Veces"
  printf "%-12s %-8s\n","------------","--------"

  nr=0

  for (r in rule_count) {
    rid[++nr]=r
    rcount[nr]=rule_count[r]
  }

  for (i=1; i<=nr; i++) {
    for (j=i+1; j<=nr; j++) {
      if (rcount[i] < rcount[j]) {
        tmp=rid[i]
        rid[i]=rid[j]
        rid[j]=tmp

        tmp=rcount[i]
        rcount[i]=rcount[j]
        rcount[j]=tmp
      }
    }
  }

  for (i=1; i<=nr; i++) {
    printf "%-12s %-8s\n",rid[i],rcount[i]
  }

  print ""
  print "IPs que realizaron las solicitudes:"
  print ""

  printf "%-40s %-8s\n","IP","Veces"
  printf "%-40s %-8s\n","----------------------------------------","--------"

  nip=0

  for (ip in ip_count) {
    ips[++nip]=ip
    ipcounts[nip]=ip_count[ip]
  }

  for (i=1; i<=nip; i++) {
    for (j=i+1; j<=nip; j++) {
      if (ipcounts[i] < ipcounts[j]) {
        tmp=ips[i]
        ips[i]=ips[j]
        ips[j]=tmp

        tmp=ipcounts[i]
        ipcounts[i]=ipcounts[j]
        ipcounts[j]=tmp
      }
    }
  }

  for (i=1; i<=nip; i++) {
    printf "%-40s %-8s\n",ips[i],ipcounts[i]
  }

  print ""
  print "=============================================="
  print "REGLAS SUGERIDAS"
  print "=============================================="
  print ""

  #
  # Generamos reglas usando host + endpoint REALES.
  #
  for (he in host_endpoint) {

    split(he,hp,SUBSEP)

    real_host=hp[1]
    ep=hp[2]

    delete list
    c=0

    for (k in endpoint_rule) {
      split(k,p,SUBSEP)

      if (
        p[1] == real_host &&
        p[2] == ep &&
        p[3] != "-"
      ) {
        c++
        list[c]=p[3]
      }
    }

    #
    # Ordena rule IDs.
    #
    for (i=1; i<=c; i++) {
      for (j=i+1; j<=c; j++) {
        if ((list[i]+0) > (list[j]+0)) {
          tmp=list[i]
          list[i]=list[j]
          list[j]=tmp
        }
      }
    }

    ctl=""

    for (i=1; i<=c; i++) {
      if (i > 1) {
        ctl=ctl ","
      }

      ctl=ctl "ctl:ruleRemoveById=" list[i]
    }

    ep_rx=regex_escape(ep)
    host_rx=regex_escape(real_host)

    print "# Disable specific ModSecurity rules for domain and URI"
    print "# ticket " ticket
    print "SecRule REQUEST_HEADERS:Host \"@rx ^" host_rx "(:[0-9]+)?$\" \"id:20000120,phase:1,nolog,pass,chain\""

    if (ctl != "") {
      print "    SecRule REQUEST_URI \"@rx ^" ep_rx "(\\?.*)?$\" \"t:none," ctl "\""
    } else {
      print "    SecRule REQUEST_URI \"@rx ^" ep_rx "(\\?.*)?$\" \"t:none\""
    }

    print ""
  }
}
' "$LOGFILE"
