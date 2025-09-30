#!/bin/bash
# Revisa si IPs de los rangos/hosts del SPF están bloqueadas en CSF
# Imprime SOLO las bloqueadas (usa SHOW_OK=true para ver todas)

SHOW_OK=false  # cambia a true si quieres ver OK/ BLOCKED

# IPs sueltas si solo son algunas ips
single_ips=(
  216.55.154.45
  216.55.154.46
)

# CIDRs (solo IPv4)
cidrs=(
  69.49.113.0/24
  74.116.88.0/22
  216.55.172.0/24
)

check_ip() {
  local ip="$1"
  # csf -g muestra coincidencias en csf.deny/iptables/ipset
  local out
  out="$(csf -g "$ip" 2>/dev/null || true)"
  if echo "$out" | grep -qiE 'csf\.deny|DENY|DROP|ipset|Chain .* DENY|BLOCK'; then
    echo "BLOCKED  $ip"
  else
    $SHOW_OK && echo "OK       $ip"
  fi
}

echo "== Revisando IPs sueltas =="
for ip in "${single_ips[@]}"; do
  check_ip "$ip"
done

echo "== Revisando rangos =="
for cidr in "${cidrs[@]}"; do
  base_ip="${cidr%/*}"
  mask="${cidr#*/}"
  IFS='.' read -r o1 o2 o3 o4 <<< "$base_ip"

  case "$mask" in
    24)
      # Recorre 1..254 del mismo /24
      for ((h=1; h<=254; h++)); do
        check_ip "$o1.$o2.$o3.$h"
      done
      ;;
    22)
      # Recorre los 4 /24 completos dentro del /22
      for ((b="$o3"; b<="$o3"+3; b++)); do
        for ((h=1; h<=254; h++)); do
          check_ip "$o1.$o2.$b.$h"
        done
      done
      ;;
    *)
      echo "Mascara /$mask no manejada por este script simple: $cidr"
      echo "Añade un caso extra si necesitas otro tamaño."
      ;;
  esac
done

echo "Listo."
