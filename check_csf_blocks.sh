#!/bin/bash
# Revisa IPs de tus rangos/hosts en CSF, en paralelo, mostrando salida en vivo.

# ===== Configura aquí =====
cidrs=(
  69.49.113.0/24
  74.116.88.0/22
  216.55.172.0/24
)

singles=(
  216.55.154.45
  216.55.154.46
)

CONCURRENCY="$(nproc 2>/dev/null || echo 8)"   # hilos paralelos (ajústalo si quieres)

# ===== Genera lista completa de IPs =====
gen_ips() {
  # /24 => 1..254
  # /22 => 4 bloques /24 consecutivos
  for cidr in "${cidrs[@]}"; do
    base="${cidr%/*}"; mask="${cidr#*/}"
    IFS='.' read -r a b c d <<< "$base"

    case "$mask" in
      24)
        for ((h=1; h<=254; h++)); do
          printf "%s.%s.%s.%s\n" "$a" "$b" "$c" "$h"
        done
        ;;
      22)
        for ((cc=c; cc<=c+3; cc++)); do
          for ((h=1; h<=254; h++)); do
            printf "%s.%s.%s.%s\n" "$a" "$b" "$cc" "$h"
          done
        done
        ;;
      *)
        echo "WARN: Máscara /$mask no soportada en este script simple: $cidr" >&2
        ;;
    esac
  done

  # Agrega IPs sueltas al final
  for ip in "${singles[@]}"; do
    echo "$ip"
  done
}

# ===== Chequeo por IP (sin falsos positivos) =====
check_one() {
  ip="$1"
  out="$(csf -g "$ip" 2>/dev/null || true)"

  # Si aparece en csf.deny => bloqueada
  if echo "$out" | grep -Eqi '^csf\.deny:|/etc/csf/csf\.deny'; then
    echo "BLOCKED  $ip"; exit 0
  fi

  # Si iptables NO dice "No matches found ..." => hay coincidencia => bloqueada
  if ! echo "$out" | grep -Fq "No matches found for $ip in iptables"; then
    echo "BLOCKED  $ip"; exit 0
  fi

  # Si IPSET NO dice "No matches found ..." => hay coincidencia => bloqueada
  if ! echo "$out" | grep -Fq "IPSET: No matches found for $ip"; then
    echo "BLOCKED  $ip"; exit 0
  fi

  # Si pasó todo lo anterior, no hay bloqueos
  echo "OK       $ip"
}

export -f check_one
export -f gen_ips

# ===== Ejecuta en paralelo (salida en vivo) =====
gen_ips | xargs -n1 -P "$CONCURRENCY" -I{} bash -c 'check_one "$@"' _ {}
