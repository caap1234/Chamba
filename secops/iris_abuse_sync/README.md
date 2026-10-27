# DFIR-IRIS Abuse Sync — SOC Neubox Automation

Sistema integral y modular para automatizar la extracción de datos desde tickets de abuso en formato **PDF** (Helpdesk Neubox) y la creación de casos estructurados en **DFIR-IRIS**, utilizando los templates oficiales de **SOC Abuse Lite v2.0**.

Diseñado para ejecutarse tanto **en local (macOS/Linux)** como en **servidores VPS** (vía Docker, daemon o CLI).

---

## 🌟 Características Principales

1. **Suite Completa de Interacción**:
   - 🖥️ **Web UI (SPA)**: Panel visual con diseño Dark Mode SOC, zona de Drag & Drop para PDFs, previsualización de datos, selector de templates y creación con un clic.
   - ⚡ **CLI Avanzada (`cli.py`)**: Analizador rápido por consola con salida en color, soporte para modo simulación (`--dry-run`), forzado manual de templates y procesamiento en lote (`batch`).
   - 👁️ **Folder Watcher Daemon (`watcher.py`)**: Servicio en segundo plano que monitorea la carpeta `inbox/`. Cualquier ticket PDF depositado se procesa automáticamente, crea el caso en DFIR-IRIS y se mueve a `processed/` con comprobante JSON.
   - 🐳 **Contenedor Docker & Compose**: Listo para desplegar en cualquier VPS sin preocuparse por dependencias.

2. **Parser Heurístico de Alta Precisión**:
   - Extrae automáticamente:
     - Número de Ticket y URL (`Ticket 789034`, etc.)
     - Activo afectado (dominio, IP o cuenta autenticada)
     - Reportante y organización (PhishFort, BrutalRx, CTIR Gov, etc.)
     - Servidores internos de hosting Neubox (`svgp261`, `svgs311`, `svds058`, etc.)
     - Cuentas de correo autenticadas comprometidas (`X-Authenticated-Id`)
     - Ticket del cliente en panel de Hospedando (`id=666491`)
     - Reportes de análisis automático de Bastion (Nlab Bot)
     - Cabeceras completas de correo SMTP (DKIM, Received, SPF, DMARC)
     - Indicadores de compromiso (IOCs: dominios, IPs, URLs, emails).

3. **Clasificador Automático Multi-Template (SOC Abuse Lite v2.0)**:
   - `[PHISH]` **`abuse_phishing`**: Páginas de captura de credenciales o suplantación web.
   - `[SPAM]` **`abuse_spam`**: Cuentas vulneradas enviando spam (ej. dating spam, envíos masivos).
   - `[FRAUD]` **`abuse_fraud`**: Venta no autorizada de medicamentos / esteroides (COFEPRIS), estafas.
   - `[BRAND]` **`abuse_trademark`**: Denuncias de uso de marca / copyright (ej. PhishFort Don Julio / Diageo).
   - `[MAL]` **`abuse_malware`**: Sitios comprometidos, webshells o enlaces maliciosos.
   - `[NET]` **`abuse_network`**: Tráfico abusivo, ataques de fuerza bruta o escaneo de puertos.
   - `[TAKE]` **`abuse_takedown`**: Notificaciones formales de CSIRT / CERT / Gobierno (ej. CTIR Gov BR TLP:AMBER).
   - *(Opcional)* Conexión con LLM (Gemini / OpenAI / Ollama) para refinamiento contextual.

4. **Formato Estructurado de Notas y Atributos**:
   - **Nota 01**: `01 Reporte inicial` (Ticket, reportante, activo, URL/IP reportada y síntesis).
   - **Nota 02**: `02 Investigación y evidencia` (Servidor Neubox, IP, bloque de Bastion o cabeceras).
   - **Nota 03**: `03 Acciones y resolución` (Estructura de gestión y ticket del titular).
   - **Atributos Personalizados**: `01 Identificación` (`Ticket de abuso`, `Dominio o activo`, `IP reportada`, `Ticket del titular`).
   - **Evidencia Adjunta**: Carga automática del archivo PDF original al caso en IRIS.

---

## 📁 Estructura del Proyecto

```
iris_abuse_sync/
├── cli.py             # CLI interactiva para consola
├── web.py             # Servidor Web FastAPI & API REST
├── watcher.py         # Daemon de monitoreo de carpetas
├── parser.py          # Extractor de metadatos, timeline e IOCs
├── classifier.py      # Motor de clasificación y selección de template
├── case_builder.py    # Constructor de casos y notas en formato SOC Lite v2.0
├── iris_client.py     # Cliente REST API para DFIR-IRIS (v2 y legacy)
├── config.py          # Gestor de configuración y variables de entorno
├── start.sh           # Script de conveniencia para arranque rápido
├── .env.example       # Plantilla de variables de entorno
├── Dockerfile         # Imagen optimizada para VPS
├── docker-compose.yml # Despliegue con Docker Compose
├── requirements.txt   # Dependencias de Python
├── inbox/             # Carpeta de entrada para el watcher
├── processed/         # Tickets procesados exitosamente (con comprobante JSON)
├── errors/            # Tickets que presentaron error
├── static/            # Interfaz gráfica moderna (HTML/CSS/JS)
└── templates/         # Templates oficiales JSON (SOC Abuse Lite v2.0)
```

---

## 🚀 Instalación y Puesta en Marcha

### 1. Configuración de credenciales (.env)

Copia `.env.example` a `.env` y configura los datos de tu instancia de DFIR-IRIS:

```bash
cp .env.example .env
nano .env
```

Parámetros clave:
```ini
IRIS_URL=https://iris.neubox.com
IRIS_API_KEY=tu_token_de_api_generado_en_iris
IRIS_CUSTOMER_ID=1
IRIS_VERIFY_SSL=false
WEB_PORT=8080
```

---

### 2. Uso con el Script de Inicio (`start.sh`)

El script `start.sh` prepara automáticamente el entorno virtual si no existe:

```bash
# Probar conexión con DFIR-IRIS
./start.sh test

# Iniciar la interfaz Web (puerto 8080)
./start.sh web

# Iniciar el daemon de monitoreo de carpetas
./start.sh watcher

# Analizar un ticket en consola
./start.sh cli parse ruta/ticket.pdf

# Crear caso en DFIR-IRIS desde consola
./start.sh cli create ruta/ticket.pdf
```

---

## 💻 Guía de Uso de la CLI (`cli.py`)

### 1. Inspeccionar templates locales
```bash
python3 cli.py templates
```

### 2. Analizar un PDF sin crear el caso (inspección)
```bash
python3 cli.py parse /ruta/al/ticket.pdf
```

Salida esperada:
```text
Analizando archivo: ticket_789475.pdf

--- Datos Extraídos del Ticket ---
  • Ticket ID: 789475
  • URL Ticket: https://helpdesk.neubox.com/#ticket/zoom/789475
  • Reportante: Hector Hernandez (BrutalRx)
  • Activo Afectado: nexapharm.com
  • Servidor(es) Neubox: svgp261.serverneubox.com.mx
  • IP Primaria: 198.59.144.23
  • Resumen: Venta de catálogo de esteroides anabólicos y prescripción médica sin receta (COFEPRIS).

--- Clasificación de Template Recomendada ---
  • Template: [FRAUD] ABUSE | Fraude, scam y suplantación (abuse_fraud)
  • Confianza: 98.0%
  • Criterios / Motivos: esteroides, anabólicos, medicamentos, cofepris, receta médica

--- Indicadores (IOCs) detectados (4) ---
  [DOMAIN] nexapharm.com
  [URL] https://nexapharm.com/farmaceuticos
  [IP] 198.59.144.23
```

### 3. Simular la creación (Dry-Run)
Valida la generación del payload y comprueba la estructura sin escribir en la base de datos de IRIS:
```bash
python3 cli.py create /ruta/al/ticket.pdf --dry-run
```

### 4. Crear el caso real en DFIR-IRIS
```bash
python3 cli.py create /ruta/al/ticket.pdf
```

### 5. Forzar un template específico
Si deseas sobreescribir la clasificación automática:
```bash
python3 cli.py create /ruta/al/ticket.pdf --template abuse_takedown
```

### 6. Procesamiento por lote (Batch)
Procesa todos los PDFs dentro de un directorio:
```bash
python3 cli.py batch /ruta/a/carpeta_tickets/ [--dry-run]
```

---

## 📂 Modo Watcher (Daemon / VPS)

Para automatizar la ingesta continua de archivos:

```bash
python3 watcher.py --inbox ./inbox
```

- Cada vez que arrastres o descargues un PDF a `./inbox/`, el daemon:
  1. Extrae los datos y clasifica el template.
  2. Crea el caso en DFIR-IRIS con sus notas, IOCs y adjunta el PDF.
  3. Mueve el PDF a `processed/<timestamp>_<archivo>.pdf`.
  4. Genera un recibo `processed/<timestamp>_<archivo>.json` con el URL del caso y el ID creado.

---

## 🌐 Panel Web UI (FastAPI)

Inicia el servicio web:
```bash
python3 web.py
```
Abre tu navegador en: **`http://localhost:8080`**

### Funciones del panel:
- **Drag & Drop**: Arrastra cualquier ticket PDF o TXT.
- **Botones de muestra**: Carga instantánea de tickets reales (COFEPRIS, PhishFort, Spam de citas, CTIR Gov).
- **Selector de Template**: Muestra el porcentaje de confianza y permite cambiar el template con un menú desplegable.
- **Pestañas interactivas**:
  - `Notas Lite v2.0`: Visualiza las 3 notas que se generarán.
  - `Indicadores IOCs`: Checkboxes para habilitar/deshabilitar IOCs antes de enviarlos.
  - `Atributos Personalizados`: Muestra los campos mapeados a `01 Identificación`.
  - `Texto Raw`: Revisa el texto extraído del ticket.
- **Acciones**:
  - `Simular Creación (Dry-Run)`
  - `Crear Caso en DFIR-IRIS`
- **Enlace Directo**: Al crear el caso, obtienes un botón directo para abrir el caso en tu instancia de IRIS (`/#/case?cid=...`).

---

## 🐳 Despliegue en VPS con Docker

En tu servidor VPS con Docker y Docker Compose instalado:

```bash
# 1. Clonar o copiar la carpeta iris_abuse_sync
cd /opt/iris_abuse_sync

# 2. Configurar variables de entorno
cp .env.example .env
nano .env

# 3. Iniciar el contenedor en segundo plano
docker compose up -d

# 4. Ver logs en tiempo real
docker compose logs -f
```

El servicio estará disponible en el puerto `8080` de tu VPS.
