#!/usr/bin/env bash
# ==============================================================================
# Acceso directo para iniciar y abrir DFIR-IRIS Abuse Sync en tu navegador
# Puedes crear un alias o mover este archivo a tu escritorio
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

./start.sh start

sleep 1
open "http://localhost:8080"
