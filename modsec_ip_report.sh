#!/bin/bash

LOGFILE="/usr/local/apache/logs/modsec_audit.log"

if [ $# -lt 1 ]; then
  echo "Uso: $0 <IP> [ticket]"
  echo "Ejemplo: $0 190.116.61.94 1844933"
  exit 1
fi

IP="$1"
TICKET="${2:-0000000}"

if [ ! -f "$LOGFILE" ]; then
  echo "No existe el log: $LOGFILE"
  exit 1
fi

awk -v target_ip="$IP" -v ticket="$TICKET" '
function reset_tx() {
  remote_ip=""
  method=""
  uri=""
  endpoint=""
  status=""
  msg_count=0
  delete rule_ids
  delete severities
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
  if (match($0, /^([A-Z]+)[ \t]+([^ \t]+)[ \t]+HTTP\/[0-9.]+$/, m)) {
    method = m[1]
    uri = m[2]
    endpoint = uri
    sub(/\?.*/, "", endpoint)
  }
  next
}

inF && status == "" {
  if (match($0, /^HTTP\/[0-9.]+[ \t]+([0-9]{3})/, m)) {
    status = m[1]
  }
  next
}

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
  print "IP analizada: " target_ip
  print "Transacciones encontradas: " tx_match_count
  print ""

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
