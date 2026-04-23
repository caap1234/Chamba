#!/bin/bash

LOGFILE="/usr/local/apache/logs/modsec_audit.log"

if [ $# -lt 1 ]; then
  echo "Uso: $0 <IP> [ticket]"
  echo "Ejemplo: $0 189.219.246.101 1793326"
  exit 1
fi

IP="$1"
TICKET="${2:-0000000}"

if [ ! -f "$LOGFILE" ]; then
  echo "No existe el log: $LOGFILE"
  exit 1
fi

gawk -v target_ip="$IP" -v ticket="$TICKET" '
function trim(s) {
  gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s)
  return s
}

function reset_tx() {
  tx_id=""
  remote_ip=""
  method=""
  uri=""
  endpoint=""
  status=""
  delete rule_ids
  delete severities
  delete messages
  msg_count=0
}

function flush_tx(   i, key) {
  if (remote_ip != target_ip) {
    reset_tx()
    return
  }

  for (i = 1; i <= msg_count; i++) {
    key = endpoint SUBSEP rule_ids[i] SUBSEP severities[i] SUBSEP status
    combo_count[key]++
    rule_count[rule_ids[i]]++
    endpoint_rule[endpoint, rule_ids[i]] = 1
    endpoint_seen[endpoint] = 1
  }

  tx_match_count++
  reset_tx()
}

BEGIN {
  reset_tx()
  inA=0; inB=0; inF=0; inH=0
  tx_match_count=0
}

# Inicio de transacción
/^--[A-Fa-f0-9]+-A--$/ {
  if (tx_id != "") {
    flush_tx()
  }
  reset_tx()
  inA=1; inB=0; inF=0; inH=0
  next
}

# Cambio de sección
/^--[A-Fa-f0-9]+-[A-Z]--$/ {
  inA=0; inB=0; inF=0; inH=0

  if ($0 ~ /-A--$/) inA=1
  else if ($0 ~ /-B--$/) inB=1
  else if ($0 ~ /-F--$/) inF=1
  else if ($0 ~ /-H--$/) inH=1
  else if ($0 ~ /-Z--$/) {
    flush_tx()
  }
  next
}

# Sección A: IP remota
inA && remote_ip == "" {
  # ejemplo:
  # [23/Apr/2026:13:34:51.087269 --0600] aep0WrBKgo9omDubQeZeHgAA1xU 189.219.246.101 1342 65.99.252.96 443
  n=split($0, a, " ")
  if (n >= 3) {
    remote_ip = a[3]
  }
  next
}

# Sección B: request line
inB && method == "" {
  # ejemplo: GET /wp-json/wp/v2/users/me?context=edit&_locale=user HTTP/2.0
  if (match($0, /^([A-Z]+)[ \t]+([^ \t]+)[ \t]+HTTP\/[0-9.]+$/, m)) {
    method = m[1]
    uri = m[2]
    endpoint = uri
    sub(/\?.*/, "", endpoint)
  }
  next
}

# Sección F: status
inF && status == "" {
  # ejemplo: HTTP/1.1 200 OK
  if (match($0, /^HTTP\/[0-9.]+[ \t]+([0-9]{3})/, m)) {
    status = m[1]
  }
  next
}

# Sección H: mensajes/rules
inH && /^Message:/ {
  msg_count++

  rule_ids[msg_count]="-"
  severities[msg_count]="-"
  messages[msg_count]=$0

  if (match($0, /\[id "([^"]+)"\]/, m)) {
    rule_ids[msg_count]=m[1]
  }

  if (match($0, /\[severity "([^"]+)"\]/, m)) {
    severities[msg_count]=m[1]
  }

  if (match($0, /\[msg "([^"]+)"\]/, m)) {
    messages[msg_count]=m[1]
  }

  next
}

END {
  print "IP analizada: " target_ip
  print "Transacciones encontradas: " tx_match_count
  print ""

  printf "%-45s %-12s %-10s %-8s %-8s\n", "Endpoint", "Rule ID", "Severity", "Status", "Veces"
  printf "%-45s %-12s %-10s %-8s %-8s\n", "---------------------------------------------", "------------", "----------", "--------", "--------"

  n=0
  for (k in combo_count) {
    split(k, p, SUBSEP)
    endpoint_arr[++n] = p[1]
    rule_arr[n]      = p[2]
    sev_arr[n]       = p[3]
    stat_arr[n]      = p[4]
    count_arr[n]     = combo_count[k]
  }

  # orden simple por endpoint/rule
  for (i=1; i<=n; i++) {
    for (j=i+1; j<=n; j++) {
      if (endpoint_arr[i] > endpoint_arr[j] || (endpoint_arr[i] == endpoint_arr[j] && rule_arr[i] > rule_arr[j])) {
        tmp=endpoint_arr[i]; endpoint_arr[i]=endpoint_arr[j]; endpoint_arr[j]=tmp
        tmp=rule_arr[i];     rule_arr[i]=rule_arr[j];         rule_arr[j]=tmp
        tmp=sev_arr[i];      sev_arr[i]=sev_arr[j];           sev_arr[j]=tmp
        tmp=stat_arr[i];     stat_arr[i]=stat_arr[j];         stat_arr[j]=tmp
        tmp=count_arr[i];    count_arr[i]=count_arr[j];       count_arr[j]=tmp
      }
    }
  }

  for (i=1; i<=n; i++) {
    printf "%-45s %-12s %-10s %-8s %-8s\n",
      endpoint_arr[i], rule_arr[i], sev_arr[i], stat_arr[i], count_arr[i]
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
  print "Reglas sugeridas por endpoint:"
  for (ep in endpoint_seen) {
    delete list
    c=0
    for (k in endpoint_rule) {
      split(k, p, SUBSEP)
      if (p[1] == ep) {
        c++
        list[c]=p[2]
      }
    }

    # ordenar ids
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

    ep_rx=ep
    gsub(/\//, "\\/", ep_rx)
    gsub(/\./, "\\.", ep_rx)
    gsub(/\+/, "\\+", ep_rx)
    gsub(/\-/, "\\-", ep_rx)
    gsub(/\?/, "\\?", ep_rx)
    gsub(/\(/, "\\(", ep_rx)
    gsub(/\)/, "\\)", ep_rx)

    print "# Disable ModSecurity for certain URI names"
    print "# ticket " ticket
    print "SecRule REQUEST_URI \"@rx ^" ep_rx "$\" \"id:20000120,nolog,pass," ctl "\""
    print ""
  }
}
' "$LOGFILE"
