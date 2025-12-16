#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   sudo bash collect_logs.sh <usuario> [directorio_destino]
# Ejemplo:
#   sudo bash collect_logs.sh cuceicom
#   sudo bash collect_logs.sh cuceicom /home/cuceicom/sentinelx_bundle_$(date +%F)

USER_NAME="${1:-user}"
DEST_DIR="${2:-/home/${USER_NAME}/sentinelx_bundle_$(date -u +%F_%H%M%S)}"

# Logs a copiar
LOGS=(
  "/usr/local/cpanel/logs/access_log"
  "/usr/local/cpanel/logs/error_log"

  # Apache (renombrar para diferenciar)
  "/usr/local/apache/logs/access_log"
  "/usr/local/apache/logs/error_log"

  "/usr/local/apache/logs/modsec_audit.log"
  "/var/log/exim_mainlog"
  "/var/log/maillog"
  "/var/log/messages"
  "/var/log/lfd.log"
  "/var/log/secure"
)

# Sysstat saXX a procesar
SA_DAYS=(14 15 16)

umask 027

echo "[*] Destino: ${DEST_DIR}"
mkdir -p "${DEST_DIR}"

# -----------------------------
# Copia de logs (preserva permisos/fechas si existen)
# -----------------------------
echo "[*] Copiando logs..."
for src in "${LOGS[@]}"; do
  if [[ -f "$src" ]]; then
    # nombre destino por defecto
    base="$(basename "$src")"
    dest_name="$base"

    # renombres para Apache (evitar colisión con cPanel)
    case "$src" in
      "/usr/local/apache/logs/access_log") dest_name="apache_access_log" ;;
      "/usr/local/apache/logs/error_log")  dest_name="apache_error_log" ;;
    esac

    cp -a "$src" "${DEST_DIR}/${dest_name}"
  else
    echo "WARN: No existe: $src" >&2
  fi
done

# -----------------------------
# SAR: -q -r -d para sa14 sa15 sa16
# -----------------------------
echo "[*] Generando SAR..."
for day in "${SA_DAYS[@]}"; do
  sa_file="/var/log/sa/sa${day}"
  if [[ ! -f "$sa_file" ]]; then
    echo "WARN: No existe: $sa_file (¿sysstat instalado y habilitado?)" >&2
    continue
  fi

  # Fecha real del archivo saXX (usando mtime en UTC)
  sar_date="$(date -u -r "$sa_file" +%F)"

  for mode in q r d; do
    out="${DEST_DIR}/sar_sa${day}_${mode}.txt"
    {
      echo "SAR_DATE=${sar_date}"
      echo "SAR_FILE=${sa_file}"
      echo "SAR_MODE=-${mode}"
      echo "GENERATED_AT_UTC=$(date -u +%F\ %T)"
      echo "----------------------------------------"
      sar -f "$sa_file" "-${mode}"
    } > "$out"
  done
done

# -----------------------------
# Ownership final
# -----------------------------
echo "[*] Ajustando ownership a ${USER_NAME}:${USER_NAME} ..."
chown -R "${USER_NAME}:${USER_NAME}" "${DEST_DIR}"

echo "[OK] Listo. Archivos en: ${DEST_DIR}"
ls -lah "${DEST_DIR}"
