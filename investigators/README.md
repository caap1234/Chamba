# Incident Response & Abuse Investigation Toolkit

Suite integral de scripts forenses y de respuesta a incidentes de abuso para servidores **cPanel / WHM**, **DirectAdmin**, **Linux Genérico** y **Windows Server**.

Todos los scripts están desarrollados en Python estándar sin dependencias de terceros para ejecutarse de forma inmediata en cualquier servidor, y todos generan una sección final estructurada con **líneas de log crudas completas (snippets)** listas para copiar y pegar como evidencia en tickets del sistema **IRIS**.

---

## 🛠️ Índice de Herramientas

| # | Herramienta | Plataformas | Enfoque Principal |
|---|---|---|---|
| **01** | [`01_abuse_mail_investigator.py`](#01-abuse-mail-investigator) | cPanel, DirectAdmin | Spam, Exim, Dovecot, scripts PHP (`cwd`), Webmail y `X-Forwarded-For`. |
| **02** | [`02_web_access_investigator.py`](#02-web-access-investigator) | Apache, Nginx, cPanel, DirectAdmin | Peticiones a webshells, IPs atacantes, métodos POST, códigos HTTP. |
| **03** | [`03_malware_file_investigator.py`](#03-malware-file-investigator) | Linux, cPanel, DirectAdmin | Archivos recientes, hashes MD5/SHA256, permisos 777, crontab y persistencia. |
| **04** | [`04_account_access_investigator.py`](#04-account-access-investigator) | cPanel, WHM, DirectAdmin, SSH | Logins exitosos/fallidos, IPs de acceso, acciones en paneles administrativos. |
| **05** | [`05_abuse_evidence_collector.py`](#05-abuse-evidence-collector) | Linux, Windows Server | Recolector forense técnico y expediente listo para IRIS con metadatos y hashes. |
| **06** | [`06_dns_domain_investigator.py`](#06-dns-domain-investigator) | Multiplataforma | Resolución DNS, MX, SPF, DMARC, hosting local vs externo, detección de CDN. |
| **07** | [`07_suspicious_activity_correlator.py`](#07-suspicious-activity-correlator) | cPanel, DirectAdmin, Linux | Timeline cronológico cruzando IP, Web, Exim, Archivos y SSH en una sola ventana. |
| **08** | [`08_windows_server_investigator.py`](#08-windows-server-investigator) | Windows Server (y análisis offline en Linux) | Logs IIS W3C, Eventos Windows 4624/4625, RDP, Tareas programadas y SMTP. |
| **09** | [`09_service_health_check.py`](#09-service-health-check) | cPanel, DirectAdmin, Linux, Windows | Procesos, miners, puertos, conexiones directas al puerto 25, inodos y salud. |

---

## 🚀 Menú Interactivo Global

Puedes ejecutar el menú principal que te permite seleccionar cualquiera de las 9 herramientas con un menú numérico:

```bash
python3 run_investigator.py
```

O dar permisos de ejecución y correr cualquier script individualmente.

---

## 📖 Documentación y Ejemplos de Uso

### 01. Abuse Mail Investigator
Analiza envíos salientes en Exim, Dovecot y Webmail. Si el remitente envió vía Webmail (`127.0.0.1`), busca en los logs de acceso de cPanel / DirectAdmin para extraer la IP real de la cabecera `X-Forwarded-For`.

```bash
# Modo general en cPanel (últimos 3 días, top 25)
python3 01_abuse_mail_investigator.py --server cpanel --days 3 --top 25

# Modo general en DirectAdmin
python3 01_abuse_mail_investigator.py --server directadmin --days 2

# Investigar una cuenta de correo específica
python3 01_abuse_mail_investigator.py --email ventas@empresa.com --days 5

# Investigar todo un dominio
python3 01_abuse_mail_investigator.py --domain empresa.com --days 7

# Guardar reporte en archivo
python3 01_abuse_mail_investigator.py --email spammer@empresa.com --output reporte_spam.txt
```

---

### 02. Web Access Investigator
Analiza domlogs de Apache/Nginx para investigar ataques web, inyecciones y webshells.

```bash
# Investigar accesos a un archivo sospechoso en un dominio
python3 02_web_access_investigator.py --server cpanel --domain cliente.com --file wso.php

# Filtrar solo peticiones POST a un dominio
python3 02_web_access_investigator.py --domain cliente.com --post-only

# Analizar actividad web 60 minutos antes y después de una hora de infección
python3 02_web_access_investigator.py --domain cliente.com --time "2026-11-02 14:30:00" --window-minutes 60

# Filtrar por IP atacante
python3 02_web_access_investigator.py --ip 185.220.101.5
```

---

### 03. Malware & File Investigator
Inspecciona directorios en búsqueda de archivos modificados recientemente, webshells con firmas maliciosas (`eval`, `base64`, `passthru`), permisos 777 y persistencia en cron y SSH.

```bash
# Auditar la cuenta de un usuario de cPanel (últimas 48 horas)
python3 03_malware_file_investigator.py --server cpanel --user cliente1 --hours 48

# Auditar una ruta específica buscando modificaciones de los últimos 7 días
python3 03_malware_file_investigator.py --path /home/cliente1/public_html --days 7

# Escaneo profundo de contenido en todos los archivos PHP
python3 03_malware_file_investigator.py --path /home/cliente1/public_html --deep-scan
```

---

### 04. Account Access Investigator
Audita accesos e inicios de sesión a paneles administrativos (cPanel, WHM, DirectAdmin) y accesos SSH.

```bash
# Auditar accesos a la cuenta de un cliente en cPanel
python3 04_account_access_investigator.py --server cpanel --user cliente1 --days 7

# Auditar accesos desde una IP sospechosa en DirectAdmin
python3 04_account_access_investigator.py --server directadmin --ip 198.51.100.25

# Auditar accesos de root a SSH y paneles
python3 04_account_access_investigator.py --user root --days 3
```

---

### 05. Abuse Evidence Collector
Genera un expediente técnico consolidado de evidencia listo para pegar directamente en IRIS.

```bash
# Crear expediente para caso de malware con archivos y domlog
python3 05_abuse_evidence_collector.py --case-id IRIS-9821 --domain cliente.com --abuse-type malware \
    --files /home/cliente/public_html/wso.php,/home/cliente/public_html/shell.php \
    --log-files /etc/apache2/logs/domlogs/cliente.com --grep wso.php

# Crear expediente de caso de spam con IP y exim mainlog
python3 05_abuse_evidence_collector.py --case-id INC-4412 --abuse-type spam --ip 198.51.100.2 \
    --log-files /var/log/exim_mainlog --grep 198.51.100.2
```

---

### 06. DNS & Domain Investigator
Audita registros DNS, MX, políticas SPF y DMARC, proveedor de hosting y comprueba si el dominio apunta al servidor actual o es externo.

```bash
# Auditoría básica de un dominio
python3 06_dns_domain_investigator.py --domain cliente.com

# Comparar resolución entre múltiples resolvers (Google y Cloudflare)
python3 06_dns_domain_investigator.py --domain cliente.com --resolvers 8.8.8.8,1.1.1.1
```

---

### 07. Suspicious Activity Correlator
Cruza eventos de múltiples fuentes en una sola línea de tiempo (timeline cronológico): Web, Exim, Dovecot, Panel y cambios de archivos.

```bash
# Correlacionar actividad de una IP sospechosa en las últimas 24 horas
python3 07_suspicious_activity_correlator.py --server cpanel --ip 198.51.100.2 --hours 24

# Correlacionar por usuario y dominio alrededor de una hora específica
python3 07_suspicious_activity_correlator.py --server cpanel --user cliente1 --domain cliente.com \
    --time "2026-11-02 15:30:00" --window-minutes 90
```

---

### 08. Windows Server Investigator
Auditoría de entornos Windows Server para servidores IIS, RDP, Eventos de seguridad y SMTP.

```powershell
# Ejecución directa en Windows Server
python 08_windows_server_investigator.py --days 3

# Filtrar por IP en IIS
python 08_windows_server_investigator.py --ip 198.51.100.5 --days 7

# Ejecución offline en Linux analizando logs IIS exportados
python3 08_windows_server_investigator.py --mode offline --iis-dir /var/log/exported_iis/
```

---

### 09. Service Health & Exposure Check
Verifica salud operativa y señales que puedan estar afectando la investigación forense o indicando un ataque masivo.

```bash
# Verificación general en cPanel
python3 09_service_health_check.py --server cpanel

# Verificación general en DirectAdmin
python3 09_service_health_check.py --server directadmin

# Detección de procesos de cripto-minería y conexiones salientes al puerto 25
python3 09_service_health_check.py --check-miners
```

---

## 📋 Evidencia para IRIS

Cada uno de los scripts contiene una sección final titulada:

```
================================================================================
EVIDENCIA PARA IRIS (LÍNEAS CRUDAS / LOG SNIPPETS COMPLETOS)
Copiar y pegar las siguientes secciones directamente en el caso de IRIS:
================================================================================
```

Esta sección incluye de 5 a 15 líneas completas y sin truncar de los logs analizados (como `exim_mainlog`, domlogs de Apache, `access_log` de cPanel con `X-Forwarded-For`, o eventos de seguridad de Windows) con el formato exacto requerido por el equipo de respuesta a incidentes de Neubox.

