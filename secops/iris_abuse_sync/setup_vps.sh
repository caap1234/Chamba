#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# DFIR-IRIS Abuse Sync SOC Platform — VPS Community Installer
# - Basado en la arquitectura robusta de despliegue SentinelX
# - NO hardcodea credenciales ni datos privados
# - Genera .env con permisos restringidos (chmod 600)
# - Compatible con Docker Compose v2 y Servicio Nativo Systemd
# - Detección y mitigación automática de CSF Firewall (DOCKER="1")
# - Configuración automatizada de Nginx Reverse Proxy (SSL Ready)
# - Compatible con AlmaLinux, Rocky, CentOS, RHEL, Debian y Ubuntu
# ============================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
ENV_EXAMPLE_FILE="${ROOT_DIR}/.env.example"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
STORAGE_DIR="${ROOT_DIR}/storage"

# ---------- Colores y Ayudantes de Terminal ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

die() { echo -e "${RED}[ERROR] $*${NC}" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]  $*${NC}" >&2; }
info() { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN}[OK]    $*${NC}"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
require_cmd() { has_cmd "$1" || die "Falta comando requerido en el sistema: $1"; }
is_root() { [[ "${EUID}" -eq 0 ]]; }
is_linux() { [[ "$(uname -s 2>/dev/null || echo unknown)" == "Linux" ]]; }

confirm() {
  local label="$1" default="${2:-y}"
  local ans=""
  read -r -p "$(echo -e "${CYAN}?${NC} ${label} [${default}]: ")" ans
  [[ -z "$ans" ]] && ans="$default"
  [[ "$ans" =~ ^[YySs]$ ]]
}

prompt() {
  local var_name="$1" label="$2" default="${3:-}" secret="${4:-0}" allow_empty="${5:-0}"
  local value=""
  while true; do
    if [[ "$secret" == "1" ]]; then
      if [[ -n "$default" ]]; then
        read -r -s -p "$(echo -e "${CYAN}?${NC} ${label} [default oculto]: ")" value; echo
        [[ -z "$value" ]] && value="$default"
      else
        read -r -s -p "$(echo -e "${CYAN}?${NC} ${label}: ")" value; echo
      fi
    else
      if [[ -n "$default" ]]; then
        read -r -p "$(echo -e "${CYAN}?${NC} ${label} [${default}]: ")" value
        [[ -z "$value" ]] && value="$default"
      else
        read -r -p "$(echo -e "${CYAN}?${NC} ${label}: ")" value
      fi
    fi
    if [[ "$allow_empty" == "1" ]]; then break; fi
    [[ -n "$value" ]] && break
    echo -e "${YELLOW}-> Este campo no puede estar vacío.${NC}"
  done
  printf -v "$var_name" "%s" "$value"
}

detect_os_id() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

install_pkgs() {
  local os_id; os_id="$(detect_os_id)"
  if [[ "$os_id" =~ (almalinux|rocky|rhel|centos|fedora) ]]; then
    require_cmd dnf
    dnf -y install "$@"
  elif [[ "$os_id" =~ (debian|ubuntu) ]]; then
    require_cmd apt-get
    apt-get update -y
    apt-get install -y "$@"
  else
    die "Distribución Linux no soportada automáticamente (ID=${os_id}). Instala manualmente: $*"
  fi
}

ensure_python3() {
  if has_cmd python3; then return 0; fi
  if is_linux && is_root; then
    info "Instalando python3 y python3-pip..."
    install_pkgs python3 python3-pip
  else
    die "Se requiere python3. Instálalo o ejecuta como root."
  fi
}

gen_secret_key() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

gen_password() {
  python3 - <<'PY'
import secrets, string
chars = string.ascii_letters + string.digits + "!@#$%^&*"
print("".join(secrets.choice(chars) for _ in range(20)))
PY
}

# ---------- Detección y Mitigación CSF (ConfigServer Security & Firewall) ----------
csf_installed() { [[ -x /usr/sbin/csf || -x /usr/local/sbin/csf || -x /usr/local/csf/bin/csf ]]; }

csf_enable_docker_integration() {
  local conf="/etc/csf/csf.conf"
  [[ -f "$conf" ]] || return 0

  local current
  current="$(grep -E '^DOCKER\s*=' "$conf" 2>/dev/null | head -n1 || true)"
  if [[ "$current" =~ \"1\" ]]; then
    success "CSF: Integración DOCKER=\"1\" ya se encuentra activa."
    return 0
  fi

  echo
  warn "CSF Firewall detectado en el servidor."
  echo "Para evitar que CSF bloquee las cadenas IPTABLES de Docker (DOCKER-ISOLATION),"
  echo "se recomienda habilitar DOCKER = \"1\" en /etc/csf/csf.conf."
  echo
  if confirm "¿Deseas que el instalador active DOCKER=\"1\" y reinicie CSF?" "y"; then
    if ! is_root; then
      warn "Se requieren permisos de root para modificar CSF. Omitiendo."
      return 0
    fi
    info "Modificando ${conf} para habilitar DOCKER=\"1\"..."
    if grep -qE '^DOCKER\s*=' "$conf"; then
      sed -i 's/^DOCKER\s*=.*/DOCKER = "1"/' "$conf"
    else
      echo 'DOCKER = "1"' >> "$conf"
    fi
    info "Reiniciando CSF Firewall (csf -r)..."
    csf -r >/dev/null 2>&1 || true
    success "CSF actualizado exitosamente."
  fi
}

csf_open_port() {
  local port="$1"
  local conf="/etc/csf/csf.conf"
  [[ -f "$conf" ]] || return 0

  if ! grep -qE "TCP_IN\s*=.*\"[^\"]*${port}[^\"]*\"" "$conf"; then
    if confirm "¿Deseas abrir el puerto ${port} en TCP_IN de CSF?" "y"; then
      if ! is_root; then
        warn "Se requieren permisos de root para abrir puertos en CSF."
        return 0
      fi
      info "Añadiendo puerto ${port} a TCP_IN en ${conf}..."
      sed -i "s/^TCP_IN\s*=\s*\"/TCP_IN = \"${port},/" "$conf"
      csf -r >/dev/null 2>&1 || true
      success "Puerto ${port} abierto en CSF."
    fi
  fi
}

# ---------- Nginx Reverse Proxy Config ----------
nginx_install_if_needed() {
  if has_cmd nginx; then return 0; fi
  echo
  info "Nginx no está instalado."
  if confirm "¿Deseas instalar Nginx para configurar el Reverse Proxy?" "y"; then
    if ! is_root; then die "Debes ejecutar como root para instalar paquetes."; fi
    install_pkgs nginx
    systemctl enable nginx >/dev/null 2>&1 || true
    success "Nginx instalado."
  else
    warn "Continuando sin instalación automática de Nginx."
  fi
}

nginx_configure_proxy() {
  local domain="$1"
  local backend_port="$2"
  local conf_path="/etc/nginx/conf.d/iris_abuse_sync.conf"

  echo
  info "Configurando Nginx Reverse Proxy para el dominio: ${domain}"
  echo "Ruta de configuración: ${conf_path}"
  echo "Backend local: http://127.0.0.1:${backend_port}"
  echo

  if ! confirm "¿Deseas escribir y aplicar esta configuración en Nginx?" "y"; then
    warn "Nginx no configurado. Deberás configurar el proxy manualmente."
    return 0
  fi

  if ! is_root; then
    warn "Se requieren permisos de root para escribir en /etc/nginx/conf.d/."
    return 0
  fi

  cat > "$conf_path" <<EOF
# DFIR-IRIS Abuse Sync SOC Platform — Reverse Proxy
server {
    listen 80;
    server_name ${domain};

    client_max_body_size 64M;

    # Encabezados de seguridad estándar
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Frontend y API proxificados al servicio local
    location / {
        proxy_pass http://127.0.0.1:${backend_port};
        proxy_http_version 1.1;

        # Soporte WebSocket y conexiones persistentes
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Tiempos de espera extendidos para OCR, IA y reportes PDF
        proxy_read_timeout 300s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }
}
EOF

  if nginx -t >/dev/null 2>&1; then
    systemctl restart nginx || systemctl reload nginx || true
    success "Nginx configurado y recargado con éxito para ${domain}."
    echo
    echo -e "${YELLOW}[NOTA SSL]${NC} Para habilitar HTTPS gratuito con Let's Encrypt, ejecuta:"
    echo "  certbot --nginx -d ${domain}"
  else
    warn "nginx -t arrojó advertencias. Por favor revisa ${conf_path}."
  fi
}

# ============================================================
# INICIO DEL INSTALADOR INTERACTIVO
# ============================================================
clear 2>/dev/null || true
echo -e "${BLUE}============================================================${NC}"
echo -e "${BOLD}   DFIR-IRIS Abuse Sync — Instalador VPS & Servidor SOC    ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo "Automatización de Ingesta, Clasificación Heurística/IA y Casos IRIS"
echo

ensure_python3

# 1. Modo de Despliegue
echo -e "${BOLD}1. Modo de Red y Dominio:${NC}"
echo "  [1] SERVER / DOMINIO — Configura dominio público + Nginx Reverse Proxy"
echo "  [2] LOCALHOST / IP — Puerto directo en local (ej. http://IP:8080)"
prompt DEPLOY_MODE "Selecciona una opción (1 o 2)" "1"

DOMAIN="localhost"
if [[ "$DEPLOY_MODE" == "1" ]]; then
  prompt DOMAIN "Ingresa el dominio o subdominio FQDN para el aplicativo" "soc.tudominio.com"
fi

# 2. Puerto del aplicativo
prompt APP_PORT "Puerto local de enlace del servicio" "8080"

# 3. Credenciales Iniciales de Administrador
echo
echo -e "${BOLD}2. Credenciales del Administrador Inicial (Bootstrap):${NC}"
echo "Nota: Esta contraseña solo se utiliza durante la instalación inicial."
echo "Una vez inicializada la base de datos, los cambios de clave y usuarios"
echo "se gestionan exclusivamente desde la interfaz web (Configuración > Usuarios)."
echo
prompt ADMIN_USER "Usuario Administrador" "admin"
prompt ADMIN_EMAIL "Correo Electrónico del Administrador" "admin@${DOMAIN}"
GEN_PASS="$(gen_password)"
prompt ADMIN_PASSWORD "Contraseña del Administrador" "${GEN_PASS}" 0

# 4. Configuración DFIR-IRIS
echo
echo -e "${BOLD}3. Integración Oficial DFIR-IRIS API:${NC}"
prompt IRIS_URL "URL base de DFIR-IRIS" "https://iris.ejemplo.com"
prompt IRIS_API_KEY "API Key de DFIR-IRIS" "" 1

# 5. Configuración Opcional Gemini AI
echo
echo -e "${BOLD}4. Asistencia Inteligente Gemini AI (Opcional):${NC}"
prompt GEMINI_API_KEY "Google Gemini API Key (Enter para omitir)" "" 1 1

# 6. Generación de Llaves Criptográficas
SECRET_KEY="$(gen_secret_key)"
FERNET_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null || python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"

# 7. Escritura del archivo .env
echo
info "Generando archivo de entorno seguro: ${ENV_FILE}..."
mkdir -p "${STORAGE_DIR}" "${STORAGE_DIR}/evidences" "${STORAGE_DIR}/reports" "${STORAGE_DIR}/backups"

cat > "${ENV_FILE}" <<EOF
# ============================================================
# DFIR-IRIS Abuse Sync SOC Platform — Configuración de Entorno
# Generado automáticamente por setup_vps.sh en $(date)
# ============================================================

# Seguridad & Sesión
APP_SECRET_KEY=${SECRET_KEY}
ENCRYPTION_SECRET_KEY=${FERNET_KEY}
PORT=${APP_PORT}
HOST=0.0.0.0
DEBUG=False

# Administrador Inicial (Solo tomado en el primer bootstrap)
BOOTSTRAP_ADMIN_USER=${ADMIN_USER}
BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASSWORD}
BOOTSTRAP_ADMIN_EMAIL=${ADMIN_EMAIL}
BOOTSTRAP_ADMIN_NAME=Administrador SOC

# Integración DFIR-IRIS API v2.4.29+
IRIS_URL=${IRIS_URL}
IRIS_API_KEY=${IRIS_API_KEY}
IRIS_VERIFY_SSL=True

# Asistencia IA (Google Gemini)
GEMINI_API_KEY=${GEMINI_API_KEY}
GEMINI_MODEL=gemini-2.5-flash

# Base de datos y Almacenamiento
DATABASE_URL=sqlite:///storage/soc_platform.db
EOF

chmod 600 "${ENV_FILE}"
success "Archivo .env creado con permisos 600 (solo lectura por propietario)."

# 8. Verificación y Mitigación CSF
if is_linux && csf_installed; then
  echo
  info "Comprobando cortafuegos CSF..."
  csf_enable_docker_integration
  if [[ "$DEPLOY_MODE" == "2" ]]; then
    csf_open_port "${APP_PORT}"
  else
    csf_open_port "80"
    csf_open_port "443"
  fi
fi

# 9. Método de Ejecución (Docker o Nativo)
echo
echo -e "${BOLD}5. Motor de Ejecución:${NC}"
echo "  [1] Docker Compose v2 (Contenedor aislado, recomendado)"
echo "  [2] Servicio Nativo Systemd (Python venv + Node dist)"
prompt RUN_MODE "Selecciona método de ejecución (1 o 2)" "1"

if [[ "$RUN_MODE" == "1" ]]; then
  if ! has_cmd docker || ! docker compose version >/dev/null 2>&1; then
    warn "Docker o Docker Compose v2 no detectados."
    if confirm "¿Deseas instalar Docker automáticamente en este servidor?" "y"; then
      info "Instalando Docker Engine..."
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker
      success "Docker instalado y activado."
    else
      die "Docker requerido para el modo de contenedores. Reintenta seleccionando modo 2."
    fi
  fi

  info "Iniciando contenedores con Docker Compose..."
  docker compose build
  docker compose up -d
  success "Contenedores Docker iniciados y en ejecución."
else
  info "Preparando entorno virtual Python nativo..."
  python3 -m venv "${ROOT_DIR}/venv"
  "${ROOT_DIR}/venv/bin/pip" install --upgrade pip
  "${ROOT_DIR}/venv/bin/pip" install -r "${ROOT_DIR}/requirements.txt"

  if [[ ! -d "${ROOT_DIR}/frontend/dist" ]]; then
    if has_cmd npm; then
      info "Compilando frontend estático..."
      (cd "${ROOT_DIR}/frontend" && npm install && npm run build)
    else
      warn "npm no está instalado. Si tienes dist/ previamente compilado continuará con este."
    fi
  fi

  # Configuración de Systemd
  SERVICE_FILE="/etc/systemd/system/iris-abuse-sync.service"
  if is_root && confirm "¿Deseas crear y habilitar el servicio systemd iris-abuse-sync?" "y"; then
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=DFIR-IRIS Abuse Sync SOC Platform
After=network.target

[Service]
Type=simple
User=${USER:-root}
WorkingDirectory=${ROOT_DIR}
ExecStart=${ROOT_DIR}/venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now iris-abuse-sync
    success "Servicio systemd iris-abuse-sync habilitado y corriendo."
  else
    info "Puedes iniciar el aplicativo ejecutando: ./start.sh start"
  fi
fi

# 10. Configuración Nginx si aplica
if [[ "$DEPLOY_MODE" == "1" && "$DOMAIN" != "localhost" ]]; then
  nginx_install_if_needed
  nginx_configure_proxy "$DOMAIN" "$APP_PORT"
fi

# Resumen Final
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${BOLD}   ¡Instalación de DFIR-IRIS Abuse Sync Finalizada!         ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
echo -e "  • URL de Acceso:       ${CYAN}$([[ "$DEPLOY_MODE" == "1" ]] && echo "http://${DOMAIN}" || echo "http://IP_SERVIDOR:${APP_PORT}")${NC}"
echo -e "  • Usuario Admin:       ${BOLD}${ADMIN_USER}${NC}"
echo -e "  • Contraseña Inicial:  ${YELLOW}${ADMIN_PASSWORD}${NC}"
echo -e "  • Base de Datos:       ${STORAGE_DIR}/soc_platform.db"
echo
echo -e "${BOLD}Consejos Post-Instalación:${NC}"
echo "  1. Guarda la contraseña inicial en tu gestor de claves seguro."
echo "  2. Puedes dar de alta analistas adicionales en: Configuración SOC > Usuarios y roles."
echo "  3. Para consultar bitácoras en vivo ejecuta: ./start.sh logs o docker compose logs -f"
echo
