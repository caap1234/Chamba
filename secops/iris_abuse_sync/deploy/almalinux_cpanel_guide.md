# Guía de Despliegue en Producción — AlmaLinux 8/9 con cPanel/WHM y Docker Compose

Esta guía detalla el despliegue seguro de **DFIR-IRIS Abuse Sync SOC Platform v3.0** sobre un servidor **AlmaLinux 8 o 9** que ejecuta **cPanel / WHM**, exponiendo la consola mediante **Reverse Proxy HTTPS** gestionado por Apache/AutoSSL y manteniendo los contenedores aislados en `127.0.0.1:8080`.

---

## 1. Requisitos del Servidor (AlmaLinux + cPanel)

1. **Docker Engine y Docker Compose Plugin** instalados desde el repositorio oficial de Docker CE:
   ```bash
   dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
   dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
   systemctl enable --now docker
   ```
2. **SELinux (si se encuentra en modo `Enforcing`)**:
   Permitir que Apache (`httpd`) se conecte al socket local `127.0.0.1:8080`:
   ```bash
   setsebool -P httpd_can_network_connect 1
   ```
3. **Firewall CSF / Firewalld**:
   - **No** abrir el puerto `8080` ni `5432` hacia Internet. `docker-compose.yml` publica únicamente en `127.0.0.1:8080:8080`.
   - En `/etc/csf/csf.conf`, verificar que el tráfico de la interfaz `docker0` y redes `br-*` esté permitido en `/etc/csf/csfpost.sh` para que el contenedor pueda alcanzar `https://iris.tokyo-03.com`, `generativelanguage.googleapis.com`, Zammad, WHMCS e IMAP.

---

## 2. Configuración de Variables de Entorno (`.env`)

Ubicar el proyecto en `/opt/secops/iris_abuse_sync` y crear `/opt/secops/iris_abuse_sync/.env` con permisos `chmod 600 .env`:

```ini
APP_ENV=production
POSTGRES_USER=soc_admin
POSTGRES_PASSWORD=CAMBIAR_PASSWORD_POSTGRES_SEGURO
POSTGRES_DB=soc_iris_platform

# Claves criptográficas para firma de sesiones y cifrado Fernet del Baúl de Secretos
APP_SECRET_KEY=GENERAR_CADENA_ALEATORIA_64_HEX
APP_MASTER_KEY=GENERAR_CADENA_ALEATORIA_32_BYTES

# Instancia DFIR-IRIS Backend Principal
IRIS_URL=https://iris.tokyo-03.com
IRIS_API_KEY=TU_API_KEY_DFIR_IRIS
VERIFY_SSL=False

# Google Gemini API (Opcional en .env; configurable y cifrable desde el Panel Admin UI)
GEMINI_API_KEY=TU_GEMINI_API_KEY
GEMINI_MODEL=gemini-2.5-flash

# Administrador Inicial (Bootstrap)
BOOTSTRAP_ADMIN_USER=admin
BOOTSTRAP_ADMIN_PASSWORD=CAMBIAR_PASSWORD_ADMIN_SOC
BOOTSTRAP_ADMIN_EMAIL=christianaceves@neubox.net
```

---

## 3. Inicio de Servicios con Docker Compose

```bash
cd /opt/secops/iris_abuse_sync
docker compose up -d --build
docker compose ps
```

El contenedor `soc-iris-app` ejecutará automáticamente `alembic upgrade head` sobre PostgreSQL 16 antes de iniciar Uvicorn.

Verificar estado de salud local:
```bash
curl -s http://127.0.0.1:8080/api/health
```

---

## 4. Configuración de Reverse Proxy HTTPS en cPanel (Apache VirtualHost Include)

Para publicar la plataforma bajo un subdominio gestionado en cPanel (por ejemplo `soc-abuse.neubox.net` perteneciente al usuario cPanel `neuboxsoc`):

1. Crear el archivo de inclusión de Apache para SSL:
   ```bash
   mkdir -p /etc/apache2/conf.d/userdata/ssl/2_4/neuboxsoc/soc-abuse.neubox.net/
   vi /etc/apache2/conf.d/userdata/ssl/2_4/neuboxsoc/soc-abuse.neubox.net/proxy_soc.conf
   ```

2. Contenido de `proxy_soc.conf`:
   ```apache
   ProxyPreserveHost On
   RequestHeader set X-Forwarded-Proto "https"
   RequestHeader set X-Forwarded-Port "443"

   # Aumentar límite de subida para reportes PDF y correos .EML con adjuntos
   LimitRequestBody 52428800

   ProxyPass /.well-known !
   ProxyPass / http://127.0.0.1:8080/ retry=0 timeout=120
   ProxyPassReverse / http://127.0.0.1:8080/
   ```

3. Reconstruir configuración de Apache en cPanel y reiniciar `httpd`:
   ```bash
   /scripts/rebuildhttpdconf
   /scripts/restartsrv_httpd
   ```

---

## 5. Respaldo y Restauración (`deploy/backup_restore.sh`)

El script `deploy/backup_restore.sh` automatiza el respaldo íntegro de:
- Base de datos PostgreSQL (`pg_dump` en formato comprimido).
- Bóveda de paquetes de evidencia forense (`storage/evidences/`).
- Snapshots inmutables de migración histórica (`storage/migration_backups/`).
- Informes PDF generados (`storage/reports/`).

Programar en `cron` diario a las `03:15 AM`:
```cron
15 3 * * * /opt/secops/iris_abuse_sync/deploy/backup_restore.sh backup /var/backups/soc_iris >> /var/log/soc_iris_backup.log 2>&1
```

