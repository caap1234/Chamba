# DFIR-IRIS Abuse Sync — SOC Platform v3.1 (NEUBOX & Hospedando)

Plataforma unificada de respuesta a incidentes, triage forense, gobernanza de casos, gestión de abusos y generación automatizada de informes ejecutivos para Centros de Operaciones de Seguridad (SOC), optimizada para:

- **NEUBOX (`NBX`)** — DFIR-IRIS Customer ID `2`.
- **Hospedando (`HP`)** — DFIR-IRIS Customer ID `3`.
- **Integración Nativa DFIR-IRIS:** Compatible con DFIR-IRIS `v2.4.29+` (REST API v2.0+).

---

## 🚀 Arquitectura y Capacidades Principales (v3.1)

1. **Expediente de Caso Integral & Taxonomía de 4 Ejes:**
   - Eje 1 (Actividad Reportada), Eje 2 (Incidente Confirmado), Eje 3 (Vector de Entrada) y Eje 4 (Causa Raíz).
   - Ficha lateral deslizante del Activo & Cliente (`AssetSheetDrawer`) con accesos directos al panel WHMCS, cPanel/DirectAdmin y expediente DFIR-IRIS sin opacar la pantalla de investigación.

2. **Bitácora Forense Unificada & Editor WYSIWYG en Tiempo Real:**
   - Registro unificado de Investigación técnica, Acciones operativas, Evidencias forenses y Comunicaciones con cliente/reportante.
   - Editor WYSIWYG integrado en línea (sin modales invasivos) que interpreta Markdown visualmente al instante (negritas, encabezados, bloques de código, listas).
   - Sincronización automática no destructiva con la Ficha Operativa Integrada en DFIR-IRIS Notes.
   - Selección múltiple de actividades y eliminación por lotes.
   - Vinculación y desvinculación selectiva con filtro por pestañas contra los pasos de playbooks.

3. **Catálogo de 11 Playbooks Estandarizados del SOC:**
   - Procedimientos supervisados de 5 pasos estructurados por categoría:
     1. **Phishing** (`abuse_phishing`): Validación DNS/URL, elementos de suplantación, preservación SHA-256, análisis de compromiso y contención.
     2. **Sitio comprometido** (`web_compromise`): Identificación de webshells/malware, auditoría de logs/fechas CMS y cuarentena.
     3. **Spam** (`abuse_spam`): Análisis de cabeceras SMTP, cola Exim, origen de envíos, bloqueo y rotación de credenciales.
     4. **Acceso no autorizado** (`account_compromise`): Auditoría de accesos panel/SSH, correlación de IPs y reversión de cambios DNS/2FA.
     5. **Autoridades** (`authority_req`): Atención y validación formal de requerimientos de fiscalías/reguladores y preservación legal.
     6. **Disputa de marca** (`brand_dispute`): Verificación de titularidad, descarte de phishing activo y orientación WIPO/OMPI.
     7. **IP en blacklist** (`blacklist_rbl`): Diagnóstico en vivo contra listas RBL (Spamhaus, Barracuda, SpamCop), mitigación y solicitud de delisting.
     8. **Fraude / Scam** (`abuse_fraud`): Denuncias comerciales, análisis de engaño/cobros y requerimiento de documentación mercantil.
     9. **Productos regulados** (`regulated_products`): Comercialización de medicamentos/sustancias y verificación de términos de servicio.
     10. **Abuso de red** (`network_abuse`): Escaneos de puertos, ataques de fuerza bruta y mitigación perimetral.
     11. **Derechos de autor** (`copyright_complaint`): Reclamos de propiedad intelectual y retiro de material protegido.

4. **Copiloto SOC Flotante (Google Gemini AI):**
   - Burbuja flotante e interactiva en la esquina inferior derecha disponible en toda la plataforma.
   - Asistente contextual con conocimiento en vivo del expediente activo: genera líneas de tiempo forenses automáticas, sugiere acciones de mitigación, redacta respuestas formales para clientes y analiza logs técnicos.
   - Renderizado completo de Markdown, bloques de código monoespaciados y botón de limpieza de conversación.

5. **Gestor de Indicadores de Compromiso (IoCs):**
   - Extracción y gestión de IoCs en tiempo real con sincronización nativa a los IoCs oficiales de DFIR-IRIS.
   - Generación asistida de Timeline de incidentes con eventos correlacionados.

6. **Generador de Dictámenes e Informes PDF:**
   - Compilación de reportes ejecutivos en PDF con membrete institucional, tablas de hallazgos técnicos estructurados y renderizado directo de capturas de pantalla desde el Datastore oficial.
   - Paginación dinámica en tablas de casos, alertas e informes para escalabilidad con miles de expedientes.

7. **Gobernanza Centralizada & Control de Acceso (RBAC):**
   - Directorio de usuarios y roles (`admin`, `supervisor`, `analyst`, `readonly`) con asignación de organizaciones permitidas (`NBX`, `HP`).
   - Gestión completa de contraseñas y altas directamente desde la interfaz web.
   - Seguridad de instalación: la contraseña de administrador definida en `.env` solo se utiliza en el primer bootstrap, impidiendo sobreescrituras accidentales en reinicios.

8. **Retención de Evidencias & Purga Forense Segura:**
   - Políticas configurables de retención local con generación de respaldos comprimidos (`.tar.gz`) con manifiesto criptográfico SHA-256 antes del purgado de binarios.

---

## 🛠️ Instalación Rápida en Servidor VPS

La plataforma incluye un instalador interactivo automatizado para entornos de producción en VPS (AlmaLinux, Rocky, Debian, Ubuntu):

```bash
# 1. Clonar el repositorio
git clone https://github.com/caap1234/Chamba.git
cd Chamba/secops/iris_abuse_sync

# 2. Ejecutar el asistente de instalación interactivo
chmod +x setup_vps.sh
./setup_vps.sh
```

El asistente `setup_vps.sh` configura de forma guiada:
- **Dominio / FQDN** y puerto del aplicativo.
- **Usuario y contraseña inicial de administrador** (generador criptográfico aleatorio).
- **Conexión API con DFIR-IRIS** y llave de Gemini AI (opcional).
- **Generación de archivo `.env` seguro** con permisos `600`.
- **Detección y mitigación automática de CSF Firewall** (activa `DOCKER="1"` en `/etc/csf/csf.conf` y abre puertos en `TCP_IN`).
- **Nginx Reverse Proxy** con soporte WebSocket, cabeceras seguras, tiempos de espera ampliados para OCR/reportes y compatibilidad con Certbot (Let's Encrypt).
- **Modo de despliegue a elegir:** Docker Compose v2 o Servicio nativo Systemd.

---

## 💻 Ejecución Local y Desarrollo

```bash
# Iniciar o reiniciar el servicio en segundo plano (http://localhost:8080)
./start.sh start
./start.sh restart

# Comprobar estado del servicio
./start.sh status

# Ver bitácoras en tiempo real
./start.sh logs

# Ejecutar suite de pruebas pytest
./venv/bin/pytest tests/ -v
```

---

## 📂 Estructura del Proyecto

```
secops/iris_abuse_sync/
├── app/
│   ├── ai/               # Integración oficial Google Gemini SDK (Copiloto SOC)
│   ├── api/routers/      # Endpoints REST (cases, alerts, admin, auth, ingest, reports)
│   ├── classification/   # Taxonomía de 4 ejes, catálogos normativos y heurística
│   ├── core/             # Configuración, bootstrap de base de datos y seguridad Argon2id/Fernet
│   ├── ingestion/        # Parsers multi-canal (Zammad, WHMCS, IMAP, PDF, OCR)
│   ├── iris/             # Cliente REST oficial DFIR-IRIS v2.4.29+
│   ├── models/           # Modelos relacionales SQLAlchemy 2.0
│   └── reports/          # Compilador de informes técnicos en PDF con evidencias
├── frontend/             # Single Page Application moderna (React 18, TypeScript, Tailwind CSS, Vite)
│   └── src/
│       ├── components/   # Componentes modulares (ActivityStream WYSIWYG, Copilot, IoCs, Drawers)
│       ├── pages/        # Vistas operativas (Dashboard, Casos, Alertas, Ingesta, Admin, Blacklist)
│       └── api/          # Cliente API HTTP tipado
├── deploy/               # Guías para cPanel / AlmaLinux y utilerías de backup
├── tests/                # Pruebas automatizadas (pytest)
├── setup_vps.sh          # Asistente de instalación automática para VPS con CSF y Nginx
├── start.sh              # Control de inicio/parada/reinicio en segundo plano
└── docker-compose.yml    # Orquestación de contenedores en producción
```

---

## 📄 Licencia

Desarrollado para la operación y automatización de respuesta a incidentes de seguridad y abuso en **NEUBOX Internet** y **Hospedando**.
