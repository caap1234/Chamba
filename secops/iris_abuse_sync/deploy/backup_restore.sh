#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Script de Respaldo y Restauración — DFIR-IRIS Abuse Sync SOC Platform v3.0
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-backup}"
TARGET_PATH="${2:-${PROJECT_DIR}/storage/backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DB_CONTAINER="soc-iris-postgres"
DB_USER="${POSTGRES_USER:-soc_admin}"
DB_NAME="${POSTGRES_DB:-soc_iris_platform}"

case "${MODE}" in
  backup)
    mkdir -p "${TARGET_PATH}"
    ARCHIVE_FILE="${TARGET_PATH}/soc_iris_backup_${TIMESTAMP}.tar.gz"
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    echo "[1/3] Exportando base de datos (PostgreSQL o SQLite local)..."
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${DB_CONTAINER}$"; then
      docker exec "${DB_CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" -F c > "${TMP_DIR}/postgres_dump.custom"
    elif [ -f "${PROJECT_DIR}/storage/soc_platform.db" ]; then
      cp "${PROJECT_DIR}/storage/soc_platform.db" "${TMP_DIR}/soc_platform.db"
    fi

    echo "[2/3] Empaquetando bóveda de evidencias, snapshots de migración y reportes..."
    mkdir -p "${TMP_DIR}/storage"
    for subdir in evidences migration_backups reports; do
      if [ -d "${PROJECT_DIR}/storage/${subdir}" ]; then
        cp -R "${PROJECT_DIR}/storage/${subdir}" "${TMP_DIR}/storage/"
      fi
    done

    echo "[3/3] Generando archivo comprimido ${ARCHIVE_FILE}..."
    tar -czf "${ARCHIVE_FILE}" -C "${TMP_DIR}" .
    shasum -a 256 "${ARCHIVE_FILE}" > "${ARCHIVE_FILE}.sha256"
    echo "✓ Respaldo completado: ${ARCHIVE_FILE}"
    ;;

  restore)
    if [ ! -f "${TARGET_PATH}" ]; then
      echo "Error: Debes especificar la ruta al archivo .tar.gz a restaurar."
      exit 1
    fi
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    echo "[1/3] Extrayendo archivo de respaldo ${TARGET_PATH}..."
    tar -xzf "${TARGET_PATH}" -C "${TMP_DIR}"

    echo "[2/3] Restaurando directorios de evidencias y snapshots..."
    mkdir -p "${PROJECT_DIR}/storage"
    if [ -d "${TMP_DIR}/storage" ]; then
      cp -R "${TMP_DIR}/storage/"* "${PROJECT_DIR}/storage/" || true
    fi

    echo "[3/3] Restaurando base de datos..."
    if [ -f "${TMP_DIR}/postgres_dump.custom" ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${DB_CONTAINER}$"; then
      docker exec -i "${DB_CONTAINER}" pg_restore -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists < "${TMP_DIR}/postgres_dump.custom"
    elif [ -f "${TMP_DIR}/soc_platform.db" ]; then
      cp "${TMP_DIR}/soc_platform.db" "${PROJECT_DIR}/storage/soc_platform.db"
    fi
    echo "✓ Restauración completada exitosamente."
    ;;

  *)
    echo "Uso:"
    echo "  $0 backup [directorio_destino]"
    echo "  $0 restore /ruta/al/soc_iris_backup_YYYYMMDD_HHMMSS.tar.gz"
    exit 1
    ;;
esac

