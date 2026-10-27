#!/usr/bin/env bash
# ==============================================================================
# Administrador de Servicio Local — DFIR-IRIS Abuse Sync (SOC Neubox)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"
PID_FILE="${SCRIPT_DIR}/.service.pid"
LOG_FILE="${SCRIPT_DIR}/web.log"
PORT=8080

if [ ! -f "${VENV_PYTHON}" ]; then
  echo "Virtual environment no encontrado en ${SCRIPT_DIR}/venv"
  echo "Creando entorno virtual e instalando requerimientos..."
  /opt/homebrew/bin/python3.14 -m venv "${SCRIPT_DIR}/venv" 2>/dev/null || python3 -m venv "${SCRIPT_DIR}/venv"
  "${SCRIPT_DIR}/venv/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
fi

get_pid() {
  if [ -f "${PID_FILE}" ]; then
    PID=$(cat "${PID_FILE}")
    if ps -p "${PID}" > /dev/null 2>&1; then
      echo "${PID}"
      return 0
    fi
  fi
  # Fallback: check port listener
  PID=$(lsof -ti :${PORT} 2>/dev/null | head -n 1)
  if [ -n "${PID}" ]; then
    echo "${PID}" > "${PID_FILE}"
    echo "${PID}"
    return 0
  fi
  return 1
}

MODE="${1:-status}"

case "${MODE}" in
  start)
    if PID=$(get_pid); then
      echo "✓ El servicio ya está corriendo en segundo plano (PID: ${PID}) en http://localhost:${PORT}"
      exit 0
    fi
    echo "Iniciando DFIR-IRIS Abuse Sync en segundo plano..."
    nohup "${VENV_PYTHON}" "${SCRIPT_DIR}/web.py" > "${LOG_FILE}" 2>&1 &
    PID=$!
    echo "${PID}" > "${PID_FILE}"
    sleep 1.5
    if ps -p "${PID}" > /dev/null 2>&1; then
      echo "✓ Servicio iniciado exitosamente (PID: ${PID})"
      echo "  • Panel Web disponible en: http://localhost:${PORT}"
      echo "  • Logs en tiempo real: ./start.sh logs"
    else
      echo "✗ Falló al iniciar. Revisa los logs con: cat ${LOG_FILE}"
    fi
    ;;

  stop)
    if PID=$(get_pid); then
      echo "Deteniendo DFIR-IRIS Abuse Sync (PID: ${PID})..."
      kill "${PID}" 2>/dev/null || true
      sleep 1
      if ps -p "${PID}" > /dev/null 2>&1; then
        kill -9 "${PID}" 2>/dev/null || true
      fi
      rm -f "${PID_FILE}"
      echo "✓ Servicio detenido."
    else
      echo "El servicio no está en ejecución."
      rm -f "${PID_FILE}"
    fi
    ;;

  restart)
    $0 stop
    sleep 1
    $0 start
    ;;

  status)
    echo "========================================================"
    echo " Estado de DFIR-IRIS Abuse Sync"
    echo "========================================================"
    if PID=$(get_pid); then
      echo "✓ ESTADO: ACTIVO (Corriendo en segundo plano)"
      echo "  • PID: ${PID}"
      echo "  • URL Local: http://localhost:${PORT}"
      echo "  • Memoria: $(ps -o rss= -p "${PID}" 2>/dev/null | awk '{print int($1/1024) " MB"}')"
      echo ""
      echo "Comprobando endpoint de salud:"
      curl -s --max-time 3 http://127.0.0.1:${PORT}/api/status | grep -q '"status":"online"' \
        && echo "  • API: Online y respondiendo correctamente" \
        || echo "  • API: No responde"
    else
      echo "✗ ESTADO: INACTIVO (Detenido)"
      echo "  Para iniciarlo ejecuta: ./start.sh start"
    fi
    echo "========================================================"
    ;;

  logs)
    if [ ! -f "${LOG_FILE}" ]; then
      touch "${LOG_FILE}"
    fi
    echo "Mostrando logs de ${LOG_FILE} (Ctrl+C para salir)..."
    tail -n 50 -f "${LOG_FILE}"
    ;;

  web)
    echo "Iniciando servidor en primer plano (interactivo) en http://localhost:${PORT}..."
    exec "${VENV_PYTHON}" "${SCRIPT_DIR}/web.py"
    ;;

  watcher)
    echo "Iniciando daemon de monitoreo de carpetas (inbox/) ..."
    exec "${VENV_PYTHON}" "${SCRIPT_DIR}/watcher.py" "${@:2}"
    ;;

  cli)
    shift
    exec "${VENV_PYTHON}" "${SCRIPT_DIR}/cli.py" "$@"
    ;;

  test)
    echo "Probando conexión con DFIR-IRIS..."
    exec "${VENV_PYTHON}" "${SCRIPT_DIR}/cli.py" test-iris
    ;;

  autostart)
    # Configure macOS LaunchAgent
    PLIST_PATH="${HOME}/Library/LaunchAgents/com.neubox.iris-abuse-sync.plist"
    mkdir -p "${HOME}/Library/LaunchAgents"
    cat <<EOF > "${PLIST_PATH}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.neubox.iris-abuse-sync</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV_PYTHON}</string>
        <string>${SCRIPT_DIR}/web.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>${LOG_FILE}</string>
</dict>
</plist>
EOF
    launchctl unload "${PLIST_PATH}" 2>/dev/null || true
    launchctl load "${PLIST_PATH}"
    echo "✓ Autostart configurado en macOS LaunchAgents."
    echo "  El servicio se iniciará automáticamente cada vez que inicies sesión en tu Mac."
    echo "  Archivo: ${PLIST_PATH}"
    ;;

  *)
    echo "Uso: $0 {start|stop|restart|status|logs|web|watcher|cli|test|autostart}"
    echo ""
    echo "Comandos para uso en local:"
    echo "  $0 start       # Inicia en segundo plano (daemon) en http://localhost:${PORT}"
    echo "  $0 stop        # Detiene el servicio en segundo plano"
    echo "  $0 restart     # Reinicia el servicio"
    echo "  $0 status      # Verifica si está activo, PID y salud"
    echo "  $0 logs        # Muestra los logs en tiempo real"
    echo "  $0 web         # Lo ejecuta en primer plano en la terminal actual"
    echo "  $0 autostart   # Configura inicio automático permanente en macOS"
    exit 1
    ;;
esac
