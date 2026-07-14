#!/bin/bash

LOGFILE="/usr/local/apache/logs/modsec_audit.log"

if [ $# -lt 2 ]; then
  echo "Uso: $0 <dominio> <URI> [ticket]"
  echo "Ejemplo: $0 ejemplo.com /wp-admin/admin-ajax.php 1844933"
  exit 1
fi

DOMAIN="${1,,}"
TARGET_URI="$2"
TICKET="${3:-0000000}"

# Normaliza el dominio recibido:
# - Lo convierte a minúsculas.
# - Elimina un posible puerto.
# - Elimina el punto final de un FQDN.
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%.}"

# Asegura que la URI comience con /
if [[ "$TARGET_URI" != /* ]]; then
  TARGET_URI="/$TARGET_URI"
fi

# La comparación se realiza sin query string
TARGET_URI="${TARGET_URI%%\?*}"

if [ ! -f "$LOGFILE" ]; then
  echo "No existe el log: $LOGFILE"
  exit 1
fi

awk \
  -v target_domain="$DOMAIN" \
  -v target_uri="$TARGET_URI" \
  -v ticket="$TICKET" '
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

  # Elimina espacios y retorno de carro
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
  sub(/\r$/, "", value)

  # Elimina puerto en dominios IPv4/FQDN
  sub(/:[0-9]+$/, "", value)

  # Elimina punto final del FQDN
  sub(/\.$/, "", value)

  return value
}

function flush_tx(   i, key) {
  host=normalize_host(host)

  if (host != target_domain || endpoint != target_uri) {
    reset_tx()
    return
  }

  for (i=1; i<=msg_count; i++) {
    key=endpoint SUBSEP rule_ids[i] SUBSEP severities[i] SUBSEP status

    combo_count[key]++
    rule_count[rule_ids[i]]++
    endpoint_rule[endpoint, rule_ids[i]]=1
    endpoint_seen[endpoint]=1
  }

  tx_match_count++
  ip_count[remote_ip]++

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

# Sección A: IP remota
inA && remote_ip == "" {
  n=split($0, a, /[[:space:]]+/)

  if (n >= 4) {
    remote_ip=a[4]
  }

  next
}

# Sección B: primera línea de la petición HTTP
inB && method == "" {
  if (match(
    $0,
    /^([A-Z]+)[ \t]+([^ \t]+)[ \t]+HTTP\/[0-9.]+$/,
    m
  )) {
    method=m[1]
    uri=m[2]

    endpoint=uri
    sub(/\?.*/, "", endpoint)
  }

  next
}

# Sección B: encabezado Host
inB && tolower($0) ~ /^host:[[:space:]]*/ {
  host=$0
  sub(/^[^:]+:[[:space:]]*/, "", host)
  host=normalize_host(host)

  next
}

# Sección F: código HTTP de respuesta
inF && status == "" {
  if (match(
    $0,
    /^HTTP\/[0-9.]+[ \t]+([0-9]{3})/,
    m
  )) {
    status=m[1]
  }

  next
}

# Sección H: reglas activadas
inH && /^Message:/ {
  msg_count++

  rule_ids[msg_count]="-"
  severities[msg_count]="-"

  if (match($0, /\[id "([^"]+)"\]/, m)) {
    rule_ids[msg_count]=m[1]
  }

  if (match($0, /\[severity "([^"]+)"\]/, m)) {
    severities[msg_count]=m[1]
  }

  next
}

END {
  # Procesa una transacción incompleta si el archivo no termina en Z
  if (
    remote_ip != "" ||
    host != "" ||
    method != "" ||
    status != "" ||
    msg_count > 0
  ) {
    flush_tx()
  }

  print "Dominio analizado: " target_domain
  print "URI analizada:     " target_uri
  print "Transacciones encontradas: " tx_match_count
  print ""

  printf "%-50s %-12s %-10s %-8s %-8s\n",
    "Endpoint",
    "Rule ID",
    "Severity",
    "Status",
    "Veces"

  printf "%-50s %-12s %-10s %-8s %-8s\n",
    "--------------------------------------------------",
    "------------",
    "----------",
    "--------",
    "--------"

  n=0

  for (k in combo_count) {
    split(k, p, SUBSEP)

    endpoint_arr[++n]=p[1]
    rule_arr[n]=p[2]
    sev_arr[n]=p[3]
    stat_arr[n]=p[4]
    count_arr[n]=combo_count[k]
  }

  for (i=1; i<=n; i++) {
    for (j=i+1; j<=n; j++) {
      if (
        endpoint_arr[i] > endpoint_arr[j] ||
        (
          endpoint_arr[i] == endpoint_arr[j] &&
          rule_arr[i] > rule_arr[j]
        )
      ) {
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
    printf "%-50s %-12s %-10s %-8s %-8s\n",
      endpoint_arr[i],
      rule_arr[i],
      sev_arr[i],
      stat_arr[i],
      count_arr[i]
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
    printf "%-12s %-8s\n", rid[i], rcount[i]
  }

  print ""
  print "IPs que solicitaron la URI:"

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
    printf "%-40s %-8s\n", ips[i], ipcounts[i]
  }

  print ""
  print "Regla sugerida para dominio y URI:"

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

    for (i=1; i<=c; i++) {
      for (j=i+1; j<=c; j++) {
        if ((list[i] + 0) > (list[j] + 0)) {
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

    ep_rx=ep
    domain_rx=target_domain

    gsub(/\\/, "\\\\", ep_rx)
    gsub(/\//, "\\/", ep_rx)
    gsub(/\./, "\\.", ep_rx)
    gsub(/\+/, "\\+", ep_rx)
    gsub(/\-/, "\\-", ep_rx)
    gsub(/\?/, "\\?", ep_rx)
    gsub(/\(/, "\\(", ep_rx)
    gsub(/\)/, "\\)", ep_rx)
    gsub(/\[/, "\\[", ep_rx)
    gsub(/\]/, "\\]", ep_rx)

    gsub(/\./, "\\.", domain_rx)
    gsub(/\-/, "\\-", domain_rx)

    print "# Disable specific ModSecurity rules for domain and URI"
    print "# ticket " ticket
    print "SecRule REQUEST_HEADERS:Host \"@rx ^" domain_rx "(:[0-9]+)?$\" \"id:20000120,phase:1,nolog,pass,chain\""
    print "    SecRule REQUEST_URI \"@rx ^" ep_rx "(\\?.*)?$\" \"t:none," ctl "\""
    print ""
  }

  if (tx_match_count == 0) {
    print "No se encontraron transacciones que coincidan con:"
    print "  Host: " target_domain
    print "  URI:  " target_uri
  }
}
' "$LOGFILE"
