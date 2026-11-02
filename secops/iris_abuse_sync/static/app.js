/**
 * DFIR-IRIS Abuse Sync — Consola SOC v3.0 (NBX & HP)
 * Arquitectura modular frontend conectada a FastAPI + PostgreSQL + DFIR-IRIS v2.4.29 + Google Gemini SDK
 */

const SOC_STATE = {
  currentView: "dashboard",
  globalOrg: "",
  csrfToken: null,
  currentUser: null,
  catalogs: null,
  activeAlertId: null,
  activeCaseId: null,
  activeCaseBundle: null,
  activeMigrationCaseId: null,
};

function showToast(msg, duration = 3800) {
  const el = document.getElementById("socToast");
  if (!el) return;
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(el._timer);
  el._timer = setTimeout(() => {
    el.style.display = "none";
  }, duration);
}

async function apiFetch(url, options = {}) {
  const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (SOC_STATE.csrfToken) {
    headers["X-CSRF-Token"] = SOC_STATE.csrfToken;
  }
  const resp = await fetch(url, Object.assign({}, options, { headers }));
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || data.message || `HTTP ${resp.status}`);
  }
  return data;
}

function esc(val, fallback = "—") {
  if (val === null || val === undefined || val === "") return fallback;
  return String(val)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function orgBadge(org) {
  const o = (org || "NBX").toUpperCase();
  return `<span class="badge ${o === "HP" ? "badge-hp" : "badge-nbx"}">${esc(o)}</span>`;
}

function provBadge(prov) {
  const p = (prov || "rule").toLowerCase();
  if (p === "manual") return `<span class="prov-tag prov-manual">MANUAL</span>`;
  if (p === "ai") return `<span class="prov-tag prov-ai">GEMINI IA</span>`;
  return `<span class="prov-tag prov-rule">REGLA</span>`;
}

// =========================================================
// NAVEGACIÓN PRINCIPAL DE VISTAS
// =========================================================
const VIEW_TITLES = {
  "dashboard": "Dashboard Operativo SOC (Datos Reales DFIR-IRIS & PostgreSQL)",
  "alerts": "Centro de Alertas & Triage Comparativo (Reglas vs Gemini)",
  "cases": "Gestión Estructurada de Casos DFIR-IRIS",
  "case-workspace": "Estación de Investigación Estructurada del Caso",
  "ingest": "Motor de Ingesta Multicanal & Empaquetado Forense SHA-256",
  "migration": "Migración y Normalización de Casos Históricos a v3.0",
  "connectors": "Conectores Externos & Monitoreo Blacklist Master RBL",
  "admin": "Administración: Google Gemini API, Usuarios RBAC y Auditoría",
};

function switchView(viewName) {
  SOC_STATE.currentView = viewName;
  document.querySelectorAll(".view-section").forEach((s) => s.classList.remove("active"));
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.classList.add("active");

  document.querySelectorAll(".soc-sidebar .nav-btn").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-view") === viewName);
  });

  const titleEl = document.getElementById("currentViewTitle");
  if (titleEl) titleEl.textContent = VIEW_TITLES[viewName] || "Consola SOC v3.0";

  if (viewName === "dashboard") loadDashboard();
  else if (viewName === "alerts") loadAlerts();
  else if (viewName === "cases") loadCases();
  else if (viewName === "migration") loadMigrationCases();
  else if (viewName === "connectors") loadConnectorsView();
  else if (viewName === "admin") loadAdminView();
}

function onGlobalOrgChange() {
  const sel = document.getElementById("globalOrgFilter");
  SOC_STATE.globalOrg = sel ? sel.value : "";
  if (SOC_STATE.currentView === "alerts") loadAlerts();
  else if (SOC_STATE.currentView === "cases") loadCases();
  else loadDashboard();
}

// =========================================================
// INICIALIZACIÓN Y CATÁLOGOS
// =========================================================
async function initSocConsole() {
  try {
    const me = await apiFetch("/api/v1/auth/me");
    if (me.authenticated && me.user) {
      SOC_STATE.currentUser = me.user;
      SOC_STATE.csrfToken = me.csrf_token;
      updateUserUi();
    }
  } catch (_) {}

  try {
    const cats = await apiFetch("/api/v1/admin/catalogs");
    SOC_STATE.catalogs = cats;
    populateTaxonomySelects(cats);
  } catch (e) {
    console.error("Error cargando catálogos:", e);
  }

  try {
    const g = await apiFetch("/api/v1/admin/gemini");
    updateGeminiTopbar(g.gemini || {});
  } catch (_) {}

  await loadDashboard();
}

function populateTaxonomySelects(cats) {
  const fill = (id, list, valKey, labelKey) => {
    const el = document.getElementById(id);
    if (!el || !Array.isArray(list)) return;
    el.innerHTML = list
      .map((item) => `<option value="${esc(item[valKey])}">${esc(item[labelKey])}</option>`)
      .join("");
  };

  for (const prefix of ["triage", "ws", "mig"]) {
    fill(`${prefix}Category`, cats.categories, "code", "name");
    fill(`${prefix}CategoryCode`, cats.categories, "code", "name");
    fill(`${prefix}ReportedActivity`, cats.reported_activities, "code", "label");
    fill(`${prefix}RepAct`, cats.reported_activities, "code", "label");
    fill(`${prefix}ConfirmedIncident`, cats.confirmed_incident_types, "code", "label");
    fill(`${prefix}ConfInc`, cats.confirmed_incident_types, "code", "label");
    fill(`${prefix}EntryVector`, cats.entry_vectors, "code", "label");
    fill(`${prefix}Vector`, cats.entry_vectors, "code", "label");
    fill(`${prefix}RootCause`, cats.root_causes, "code", "label");
  }

  fill("newActionType", cats.standard_actions, "code", "title");
  fill("wsPlaybookSelect", cats.playbooks, "code", "name");
}

function updateGeminiTopbar(gCfg) {
  const dot = document.getElementById("geminiStatusDot");
  const txt = document.getElementById("geminiStatusText");
  const hint = document.getElementById("adminGeminiKeyHint");
  const wsModel = document.getElementById("wsGeminiModelBadge");

  const model = gCfg.model || "gemini-2.5-flash";
  const hasKey = gCfg.key_hint && gCfg.key_hint !== "No configurada";
  if (wsModel) wsModel.textContent = model;
  if (hint) hint.textContent = gCfg.key_hint || "No configurada";

  if (dot && txt) {
    if (gCfg.is_enabled && hasKey) {
      dot.className = "dot online";
      txt.textContent = `Gemini (${model})`;
    } else {
      dot.className = "dot warn";
      txt.textContent = `Heurísticas SOC (Gemini sin API Key)`;
    }
  }
}

// =========================================================
// 1. DASHBOARD OPERATIVO
// =========================================================
async function loadDashboard() {
  try {
    const data = await apiFetch("/api/v1/dashboard/summary");
    const k = data.kpis || {};
    document.getElementById("kpiAlertsPending").textContent = k.alerts_pending ?? 0;
    document.getElementById("kpiAlertsTotal").textContent = k.alerts_total ?? 0;
    document.getElementById("kpiCasesOpen").textContent = k.cases_open ?? 0;
    document.getElementById("kpiCasesProgress").textContent = k.cases_in_progress ?? 0;
    document.getElementById("kpiCasesClosed").textContent = k.cases_closed ?? 0;
    document.getElementById("kpiCasesMigrated").textContent = k.cases_migrated_v3 ?? 0;
    document.getElementById("kpiCasesTotal").textContent = k.cases_total ?? 0;
    document.getElementById("kpiCorrelated").textContent = k.alerts_correlated ?? 0;
    document.getElementById("kpiEscalated").textContent = k.alerts_escalated ?? 0;
    document.getElementById("kpiMerged").textContent = k.alerts_merged ?? 0;
    document.getElementById("kpiRblActive").textContent = k.active_rbl_episodes ?? 0;

    document.getElementById("navAlertsBadge").textContent = k.alerts_pending ?? 0;
    document.getElementById("navCasesBadge").textContent = k.cases_open ?? 0;
    document.getElementById("navMigrationBadge").textContent = k.cases_total ?? 20;

    const irisConn = data.iris_connection || {};
    const irisDot = document.getElementById("irisStatusDot");
    const irisTxt = document.getElementById("irisStatusText");
    if (irisDot && irisTxt) {
      irisDot.className = irisConn.ok ? "dot online" : "dot err";
      irisTxt.textContent = irisConn.ok
        ? `DFIR-IRIS ${irisConn.iris_version || "v2.4.29"}`
        : "DFIR-IRIS Desconectado";
    }

    // Distribuciones
    const orgs = data.cases_by_organization || {};
    const cats = data.cases_by_category || {};
    const srcs = data.reports_by_source || {};
    const catRows = Object.entries(cats)
      .map(([cName, cnt]) => `<div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(148,163,184,0.08);"><span>${esc(cName)}</span><strong>${cnt}</strong></div>`)
      .join("");
    const srcRows = Object.entries(srcs)
      .map(([sName, cnt]) => `<span class="badge badge-info" style="margin-right:6px;">${esc(sName)}: ${cnt}</span>`)
      .join("") || `<span class="badge badge-neutral">Sin eventos en cola local aún</span>`;

    document.getElementById("dashboardDistributions").innerHTML = `
      <div style="display:flex; gap:12px; margin-bottom:12px;">
        <div class="badge badge-nbx" style="padding:6px 12px; font-size:12.5px;">NEUBOX (NBX): ${orgs.NBX || 0} casos</div>
        <div class="badge badge-hp" style="padding:6px 12px; font-size:12.5px;">Hospedando (HP): ${orgs.HP || 0} casos</div>
      </div>
      <div style="margin-bottom:10px;">${catRows}</div>
      <div style="font-size:11.5px; color:var(--text-secondary);">Ingestas por canal: ${srcRows}</div>
    `;

    // Conectores
    const connBody = document.getElementById("dashboardConnectorsBody");
    connBody.innerHTML = (data.connectors || [])
      .map(
        (c) => `
        <tr>
          <td><strong>${esc(c.name)}</strong><br/><span style="font-size:11px; color:var(--text-muted);">${esc(c.type)}</span></td>
          <td><span class="badge ${c.is_enabled ? "badge-ok" : "badge-neutral"}">${c.is_enabled ? "Activo (" + esc(c.status) + ")" : "Desactivado"}</span></td>
          <td>${esc(c.last_sync_at, "Pendiente")}</td>
        </tr>`
      )
      .join("");

    // Auditoría reciente
    const auditBody = document.getElementById("dashboardAuditBody");
    const logs = data.recent_activity || [];
    auditBody.innerHTML = logs.length
      ? logs
          .map(
            (l) => `
          <tr>
            <td style="font-size:11.5px; color:var(--text-secondary);">${esc((l.timestamp || "").replace("T", " ").slice(0, 19))}</td>
            <td><strong>${esc(l.username)}</strong></td>
            <td><span class="badge badge-info">${esc(l.module)}</span></td>
            <td><code>${esc(l.action)}</code></td>
            <td>${l.iris_case_id ? "Caso #" + l.iris_case_id : l.iris_alert_id ? "Alerta #" + l.iris_alert_id : "—"}</td>
            <td>${esc(l.details)}</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="6" style="color:var(--text-muted);">Sin eventos registrados aún.</td></tr>`;
  } catch (e) {
    showToast("Error cargando Dashboard: " + e.message);
  }
}

// =========================================================
// 2. CENTRO DE ALERTAS & TRIAGE
// =========================================================
async function loadAlerts() {
  const tbody = document.getElementById("alertsTableBody");
  if (!tbody) return;
  const search = (document.getElementById("alertSearchInput")?.value || "").trim();
  const params = new URLSearchParams();
  if (SOC_STATE.globalOrg) params.set("organization", SOC_STATE.globalOrg);
  if (search) params.set("search", search);

  try {
    const data = await apiFetch(`/api/v1/alerts?${params.toString()}`);
    const list = data.alerts || [];
    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:22px; color:var(--text-secondary);">No hay alertas en la cola de DFIR-IRIS con los filtros actuales. Usa <strong>Ingesta Multicanal</strong> para crear una alerta de prueba desde los PDFs reales.</td></tr>`;
      return;
    }
    tbody.innerHTML = list
      .map(
        (a) => `
        <tr>
          <td><strong>#${a.alert_id}</strong></td>
          <td>${orgBadge(a.organization)}</td>
          <td>
            <strong>${esc(a.alert_title)}</strong>
            <div style="font-size:11px; color:var(--text-secondary);">Fuente: ${esc(a.alert_source)} | Ref: ${esc(a.abuse_ticket_id)} | IOCs: ${a.iocs_count}</div>
          </td>
          <td><code>${esc(a.reported_activity)}</code></td>
          <td><span class="badge badge-purple">${esc(a.confirmed_incident_type)}</span></td>
          <td><span class="badge ${a.severity_name === "High" || a.severity_name === "Critical" ? "badge-high" : "badge-medium"}">${esc(a.severity_name)}</span></td>
          <td><span class="badge badge-info">${esc(a.status_name)}</span></td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="openAlertTriage(${a.alert_id})">🔍 Abrir Triage</button>
          </td>
        </tr>`
      )
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--status-danger);">Error consultando cola de alertas IRIS: ${esc(e.message)}</td></tr>`;
  }
}

async function openAlertTriage(alertId) {
  SOC_STATE.activeAlertId = alertId;
  try {
    const data = await apiFetch(`/api/v1/alerts/${alertId}`);
    const ia = data.iris_alert || {};
    const ext = data.extension || {};
    const ing = data.ingest_event || {};
    const prov = ext.field_provenance || {};

    document.getElementById("alertDetailDrawer").style.display = "block";
    document.getElementById("triageAlertTitle").textContent = `Alerta #${alertId}: ${ia.alert_title || ""}`;
    document.getElementById("triageAlertSourceBadge").textContent = `${ia.alert_source || "SOC"} · Estado: ${(ia.status || {}).status_name || "New"}`;

    document.getElementById("triageEvidenceMeta").innerHTML = ing && ing.evidence_sha256
      ? `<strong>SHA-256 Paquete Inicial:</strong> <code>${esc(ing.evidence_sha256)}</code><br/><strong>Ruta Custodia:</strong> <code>${esc(ing.evidence_package_path)}</code>`
      : `Alerta nativa de DFIR-IRIS (Ref: ${esc(ia.alert_source_ref)})`;

    document.getElementById("triageOriginalContentBox").textContent =
      (ing && ing.original_content) || ia.alert_description || "Sin contenido original.";

    document.getElementById("triageIndicatorsByRole").textContent = JSON.stringify(
      ext.indicators_by_role || ia.iocs || {},
      null,
      2
    );

    document.getElementById("triageOrg").value = ext.organization || "NBX";
    document.getElementById("triageTicket").value = ext.abuse_ticket_id || "";
    document.getElementById("triageDomain").value = ext.primary_domain || "";
    document.getElementById("triageHostingIp").value = ext.hosting_ip || "";
    document.getElementById("triageReportedIp").value = ext.reported_ip || "";
    document.getElementById("triageServer").value = ext.server_name || "";
    document.getElementById("triageCategory").value = ext.category_code || "abuse_phishing";
    document.getElementById("triageReportedActivity").value = ext.reported_activity || "unknown";
    document.getElementById("triageConfirmedIncident").value = ext.confirmed_incident_type || "pending_investigation";
    document.getElementById("triageEntryVector").value = ext.entry_vector || "unknown";
    document.getElementById("triageRootCause").value = ext.root_cause || "unknown";
    document.getElementById("triageSeverity").value = ext.severity || "Medium";

    for (const k of [
      "organization",
      "abuse_ticket_id",
      "primary_domain",
      "hosting_ip",
      "reported_ip",
      "server_name",
      "category_code",
      "reported_activity",
      "confirmed_incident_type",
      "entry_vector",
      "root_cause",
      "severity",
    ]) {
      const pEl = document.getElementById(`prov_${k}`);
      if (pEl) {
        const pVal = (prov[k] || "rule").toLowerCase();
        pEl.className = `prov-tag prov-${pVal === "manual" ? "manual" : pVal === "ai" ? "ai" : "rule"}`;
        pEl.textContent = pVal.toUpperCase();
      }
    }

    const heurSignals = (ext.heuristic_result || {}).signals || [];
    const gemUsed = (ext.gemini_result || {}).ai_used;
    const corrCases = ext.correlated_case_ids || [];
    document.getElementById("triageComparisonSignals").textContent =
      `• Señales Heurísticas: ${heurSignals.join(" | ") || "N/A"}\n` +
      `• Enriquecimiento Gemini: ${gemUsed ? "Activo (" + (ext.gemini_result.model || "") + ")" : "Fallback determinista"}\n` +
      `• Casos Correlacionados en IRIS: ${corrCases.length ? corrCases.map((c) => "#" + c).join(", ") : "Ninguno"}`;
  } catch (e) {
    showToast("Error abriendo alerta: " + e.message);
  }
}

async function saveAlertTriageChanges() {
  if (!SOC_STATE.activeAlertId) return;
  try {
    const body = {
      organization: document.getElementById("triageOrg").value,
      abuse_ticket_id: document.getElementById("triageTicket").value,
      primary_domain: document.getElementById("triageDomain").value,
      hosting_ip: document.getElementById("triageHostingIp").value,
      reported_ip: document.getElementById("triageReportedIp").value,
      server_name: document.getElementById("triageServer").value,
      category_code: document.getElementById("triageCategory").value,
      reported_activity: document.getElementById("triageReportedActivity").value,
      confirmed_incident_type: document.getElementById("triageConfirmedIncident").value,
      entry_vector: document.getElementById("triageEntryVector").value,
      root_cause: document.getElementById("triageRootCause").value,
      severity: document.getElementById("triageSeverity").value,
    };
    await apiFetch(`/api/v1/alerts/${SOC_STATE.activeAlertId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    });
    showToast("Cambios de triage guardados en Alerta #" + SOC_STATE.activeAlertId + " (marcados como MANUAL)");
    await openAlertTriage(SOC_STATE.activeAlertId);
    await loadAlerts();
  } catch (e) {
    showToast("Error guardando triage: " + e.message);
  }
}

async function escalateCurrentAlert() {
  if (!SOC_STATE.activeAlertId) return;
  try {
    const res = await apiFetch(`/api/v1/alerts/${SOC_STATE.activeAlertId}/escalate`, {
      method: "POST",
      body: JSON.stringify({ note: "Alerta escalada desde Centro de Alertas SOC v3.0" }),
    });
    showToast(`Alerta #${SOC_STATE.activeAlertId} convertida en Caso IRIS #${res.case_id}`);
    document.getElementById("alertDetailDrawer").style.display = "none";
    await openCaseWorkspace(res.case_id);
  } catch (e) {
    showToast("Error escalando alerta: " + e.message);
  }
}

async function promptMergeCurrentAlert() {
  if (!SOC_STATE.activeAlertId) return;
  const cidStr = prompt("Ingresa el ID del Caso existente en DFIR-IRIS con el que deseas relacionar/fusionar esta alerta:");
  if (!cidStr || isNaN(parseInt(cidStr, 10))) return;
  try {
    await apiFetch(`/api/v1/alerts/${SOC_STATE.activeAlertId}/merge`, {
      method: "POST",
      body: JSON.stringify({ target_case_id: parseInt(cidStr, 10) }),
    });
    showToast(`Alerta #${SOC_STATE.activeAlertId} fusionada con el Caso #${cidStr}`);
    await loadAlerts();
  } catch (e) {
    showToast("Error fusionando alerta: " + e.message);
  }
}

async function promptDiscardCurrentAlert() {
  if (!SOC_STATE.activeAlertId) return;
  const reason = prompt("Ingresa el motivo obligatorio de descarte de la alerta (mín. 5 caracteres):");
  if (!reason || reason.trim().length < 5) {
    showToast("Debes especificar un motivo obligatorio de al menos 5 caracteres.");
    return;
  }
  try {
    await apiFetch(`/api/v1/alerts/${SOC_STATE.activeAlertId}/discard`, {
      method: "POST",
      body: JSON.stringify({ discard_reason: reason.trim() }),
    });
    showToast(`Alerta #${SOC_STATE.activeAlertId} descartada y cerrada en DFIR-IRIS.`);
    document.getElementById("alertDetailDrawer").style.display = "none";
    await loadAlerts();
  } catch (e) {
    showToast("Error descartando alerta: " + e.message);
  }
}

// =========================================================
// 3. MOTOR DE INGESTA MULTICANAL
// =========================================================
async function handleFileUpload(ev) {
  const file = ev.target.files?.[0];
  if (!file) return;
  const org = document.getElementById("ingestOrgSelect").value;
  const createAlert = document.getElementById("ingestModeSelect").value === "alert";
  const useGem = document.getElementById("ingestGeminiToggle").value === "true";

  const fd = new FormData();
  fd.append("file", file);
  if (org) fd.append("organization", org);
  fd.append("create_iris_alert", String(createAlert));
  fd.append("use_gemini", String(useGem));

  document.getElementById("ingestResultStatusBadge").textContent = "Procesando...";
  try {
    const res = await apiFetch("/api/v1/ingest/upload", { method: "POST", body: fd });
    renderIngestOutput(res);
    showToast(
      res.iris_alert_id
        ? `Alerta #${res.iris_alert_id} creada en DFIR-IRIS con paquete SHA-256`
        : "Previsualización de normalización completada (Dry-Run)"
    );
  } catch (e) {
    showToast("Error procesando archivo: " + e.message);
  } finally {
    ev.target.value = "";
  }
}

async function handleTextIngest() {
  const text = (document.getElementById("ingestRawText")?.value || "").trim();
  if (text.length < 5) {
    showToast("Pega primero el contenido del reporte o correo.");
    return;
  }
  const org = document.getElementById("ingestOrgSelect").value || "NBX";
  const createAlert = document.getElementById("ingestModeSelect").value === "alert";
  const useGem = document.getElementById("ingestGeminiToggle").value === "true";

  document.getElementById("ingestResultStatusBadge").textContent = "Procesando...";
  try {
    const res = await apiFetch("/api/v1/ingest/text", {
      method: "POST",
      body: JSON.stringify({
        text,
        organization: org,
        create_iris_alert: createAlert,
        use_gemini: useGem,
      }),
    });
    renderIngestOutput(res);
    showToast(res.iris_alert_id ? `Alerta #${res.iris_alert_id} creada en DFIR-IRIS` : "Texto normalizado en Dry-Run");
  } catch (e) {
    showToast("Error en ingesta de texto: " + e.message);
  }
}

async function runReferenceSample(sampleKey) {
  const createAlert = document.getElementById("ingestModeSelect").value === "alert";
  document.getElementById("ingestResultStatusBadge").textContent = `Analizando ticket #${sampleKey}...`;
  try {
    const res = await apiFetch(`/api/v1/ingest/sample/${sampleKey}?create_iris_alert=${createAlert}`);
    renderIngestOutput(res);
    showToast(`Ticket de referencia #${sampleKey} procesado correctamente.`);
  } catch (e) {
    showToast("Error cargando muestra: " + e.message);
  }
}

function renderIngestOutput(res) {
  const norm = res.normalized || {};
  const heur = res.heuristics || {};
  const pkg = res.evidence_package || {};
  const corr = res.correlations || {};

  document.getElementById("ingestResultStatusBadge").textContent = res.iris_alert_id
    ? `Alerta IRIS #${res.iris_alert_id}`
    : "Dry-Run Normalizado";

  const alertActionBtn = res.iris_alert_id
    ? `<button class="btn btn-primary btn-sm" onclick="switchView('alerts'); openAlertTriage(${res.iris_alert_id})">🚨 Abrir Alerta #${res.iris_alert_id} en Triage →</button>`
    : "";

  document.getElementById("ingestPipelineOutput").innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
      <div>${orgBadge(res.organization)} <strong style="margin-left:6px;">${esc(res.alert_title)}</strong></div>
      ${alertActionBtn}
    </div>
    <div class="form-grid-3" style="margin-bottom:10px;">
      <div class="kpi-card" style="padding:9px;">
        <div class="kpi-label">Activo / Dominio</div>
        <div style="font-weight:700; margin-top:2px;">${esc(norm.primary_domain)}</div>
        <div class="kpi-sub">Marca ref: ${esc(norm.impersonated_brand, "Ninguna")}</div>
      </div>
      <div class="kpi-card" style="padding:9px;">
        <div class="kpi-label">IPs por Rol Semántico</div>
        <div style="font-weight:700; margin-top:2px;">Hosting: ${esc(norm.hosting_ip)}</div>
        <div class="kpi-sub">Reportada: ${esc(norm.reported_ip)} | SMTP: ${esc(norm.src_ip)}</div>
      </div>
      <div class="kpi-card" style="padding:9px;">
        <div class="kpi-label">Cliente & Servidor</div>
        <div style="font-weight:700; margin-top:2px;">Srv: ${esc(norm.server_name)}</div>
        <div class="kpi-sub">Cliente #${esc(norm.client_id)} · Servicio #${esc(norm.service_id)}</div>
      </div>
    </div>
    <div style="font-size:12px; margin-bottom:8px;">
      <strong>4 Ejes de Clasificación:</strong>
      <span class="badge badge-info">1. Reportado: ${esc(heur.reported_activity)}</span>
      <span class="badge badge-purple">2. Confirmado: ${esc(heur.confirmed_incident_type)}</span>
      <span class="badge badge-neutral">3. Vector: ${esc(heur.entry_vector)}</span>
      <span class="badge badge-neutral">4. Causa: ${esc(heur.root_cause)}</span>
    </div>
    <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:8px;">
      <strong>Paquete Forense SHA-256:</strong> <code>${esc(pkg.primary_sha256)}</code><br/>
      <strong>Casos Correlacionados en IRIS:</strong> ${(corr.correlated_case_ids || []).map((id) => "#" + id).join(", ") || "Ninguno"}
    </div>
    <div class="code-box" style="max-height:210px;">${esc(JSON.stringify({ indicators_by_role: norm.indicators_by_role, signals: heur.signals, actions: heur.proposed_actions }, null, 2))}</div>
  `;
}

// =========================================================
// 4. GESTIÓN ESTRUCTURADA DE CASOS DFIR-IRIS
// =========================================================
async function loadCases() {
  const tbody = document.getElementById("casesTableBody");
  if (!tbody) return;
  const st = document.getElementById("casesStateFilter")?.value || "open";
  const q = (document.getElementById("casesSearchInput")?.value || "").trim();
  const params = new URLSearchParams({ state_filter: st });
  if (SOC_STATE.globalOrg) params.set("organization", SOC_STATE.globalOrg);
  if (q) params.set("search", q);

  try {
    const data = await apiFetch(`/api/v1/cases?${params.toString()}`);
    const list = data.cases || [];
    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--text-secondary);">No se encontraron casos con los filtros seleccionados.</td></tr>`;
      return;
    }
    tbody.innerHTML = list
      .map(
        (c) => `
        <tr>
          <td><strong>#${c.case_id}</strong></td>
          <td>${orgBadge(c.organization)}</td>
          <td><strong>${esc(c.case_name)}</strong></td>
          <td>
            <div>${esc(c.primary_domain)}</div>
            <div style="font-size:11px; color:var(--text-muted);">Srv: ${esc(c.server_name)}</div>
          </td>
          <td>
            <div>Abuso: #${esc(c.abuse_ticket_id)}</div>
            <div style="font-size:11px; color:var(--text-muted);">Titular: #${esc(c.holder_ticket_id)} | Cte: #${esc(c.client_id)}</div>
          </td>
          <td>
            <span class="badge ${c.schema_version === "3.0" ? "badge-purple" : "badge-warn"}">
              ${c.schema_version === "3.0" ? "v3.0 Normalizado" : "Histórico v2"}
            </span>
          </td>
          <td><span class="badge ${c.is_closed ? "badge-neutral" : "badge-ok"}">${esc(c.state_name)}</span></td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-primary btn-sm" onclick="openCaseWorkspace(${c.case_id})">✏️ Estación Caso</button>
              <a href="/api/v1/cases/${c.case_id}/report.pdf" target="_blank" class="btn btn-sm" title="Informe PDF 15 Secciones">📄 PDF</a>
            </div>
          </td>
        </tr>`
      )
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--status-danger);">Error cargando casos: ${esc(e.message)}</td></tr>`;
  }
}

async function openCaseWorkspace(caseId) {
  SOC_STATE.activeCaseId = caseId;
  const navBtn = document.getElementById("navActiveCaseBtn");
  const navLbl = document.getElementById("navActiveCaseLabel");
  if (navBtn && navLbl) {
    navBtn.style.display = "flex";
    navLbl.textContent = `✏️ Caso #${caseId}`;
  }
  switchView("case-workspace");

  try {
    const bundle = await apiFetch(`/api/v1/cases/${caseId}`);
    SOC_STATE.activeCaseBundle = bundle;
    renderCaseWorkspace(bundle);
  } catch (e) {
    showToast("Error cargando estación del caso #" + caseId + ": " + e.message);
  }
}

function closeCaseWorkspace(ev) {
  if (ev) ev.stopPropagation();
  SOC_STATE.activeCaseId = null;
  SOC_STATE.activeCaseBundle = null;
  const navBtn = document.getElementById("navActiveCaseBtn");
  if (navBtn) navBtn.style.display = "none";
  switchView("cases");
}

function switchCaseSubtab(tabKey) {
  document.querySelectorAll(".case-subtab-pane").forEach((p) => (p.style.display = "none"));
  const pane = document.getElementById(`case-subtab-${tabKey}`);
  if (pane) pane.style.display = "block";

  const buttons = document.querySelectorAll("#view-case-workspace .subtab-btn");
  const idxMap = { ident: 0, inv: 1, actions: 2, comms: 3, notes: 4 };
  buttons.forEach((b, i) => b.classList.toggle("active", i === idxMap[tabKey]));
}

function renderCaseWorkspace(bundle) {
  const iris = bundle.iris_case || {};
  const ext = bundle.extension || {};
  const prov = ext.field_provenance_json || {};
  const cid = iris.case_id || ext.iris_case_id;

  const cleanTitle = (iris.case_name || "").replace(/^#\d+\s*-\s*/, "");
  document.getElementById("wsCaseHeaderTitle").textContent = `Caso #${cid} — ${cleanTitle}`;
  document.getElementById("wsCaseOrgBadge").textContent = ext.organization || "NBX";
  document.getElementById("wsCaseSchemaBadge").textContent = `Esquema ${ext.schema_version || "3.0"}`;
  document.getElementById("wsDownloadPdfBtn").href = `/api/v1/cases/${cid}/report.pdf`;

  document.getElementById("wsQuickSummaryBox").innerHTML = `
    <div><strong>Dominio:</strong> <code>${esc(ext.primary_domain)}</code></div>
    <div><strong>Ticket Abuso:</strong> #${esc(ext.abuse_ticket_id)} | <strong>Titular:</strong> #${esc(ext.holder_ticket_id)}</div>
    <div><strong>ID Cliente:</strong> #${esc(ext.client_id)} | <strong>ID Servicio:</strong> #${esc(ext.service_id)}</div>
    <div><strong>Servidor:</strong> <code>${esc(ext.server_name)}</code></div>
    <div><strong>IP Hosting:</strong> ${esc(ext.hosting_ip)} | <strong>IP Reportada:</strong> ${esc(ext.reported_ip)}</div>
    <div><strong>IOCs en IRIS:</strong> ${(iris.iocs || []).length} | <strong>Evidencias:</strong> ${(iris.evidences || []).length}</div>
  `;

  document.getElementById("wsCaseName").value = cleanTitle;
  document.getElementById("wsOrganization").value = ext.organization || "NBX";
  document.getElementById("wsStateId").value = String(iris.state_id || 3);
  document.getElementById("wsAbuseTicket").value = ext.abuse_ticket_id || "";
  document.getElementById("wsHolderTicket").value = ext.holder_ticket_id || "";
  document.getElementById("wsClientId").value = ext.client_id || "";
  document.getElementById("wsServiceId").value = ext.service_id || "";
  document.getElementById("wsPrimaryDomain").value = ext.primary_domain || "";
  document.getElementById("wsServerName").value = ext.server_name || "";
  document.getElementById("wsHostingIp").value = ext.hosting_ip || "";
  document.getElementById("wsReportedIp").value = ext.reported_ip || "";
  document.getElementById("wsCategoryCode").value = ext.category_code || "abuse_phishing";
  document.getElementById("wsReportedActivity").value = ext.reported_activity || "unknown";
  document.getElementById("wsConfirmedIncident").value = ext.confirmed_incident_type || "pending_investigation";
  document.getElementById("wsEntryVector").value = ext.entry_vector || "unknown";
  document.getElementById("wsRootCause").value = ext.root_cause || "unknown";
  document.getElementById("wsIsCompromise").value = String(Boolean(ext.is_technical_compromise));
  document.getElementById("wsCaseDescription").value = iris.case_description || "";

  for (const k of [
    "abuse_ticket_id",
    "holder_ticket_id",
    "client_id",
    "service_id",
    "primary_domain",
    "server_name",
    "hosting_ip",
    "reported_ip",
  ]) {
    const el = document.getElementById(`ws_prov_${k}`);
    if (el) {
      const pv = (prov[k] || "rule").toLowerCase();
      el.className = `prov-tag prov-${pv === "manual" ? "manual" : pv === "ai" ? "ai" : "rule"}`;
      el.textContent = pv.toUpperCase();
    }
  }

  // Renderizar Investigaciones
  const invList = bundle.investigations || [];
  document.getElementById("wsInvestigationsList").innerHTML = invList.length
    ? `<table class="soc-table"><thead><tr><th>Fuente</th><th>Consulta</th><th>Naturaleza</th><th>Resultado</th></tr></thead><tbody>` +
      invList
        .map(
          (i) =>
            `<tr><td><strong>${esc(i.source_consulted)}</strong></td><td><code>${esc(i.commands_or_queries)}</code></td><td><span class="badge badge-info">${esc(i.fact_type)}</span></td><td>${esc(i.results_observed)}</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    : `<p style="color:var(--text-muted); font-size:12px;">Sin actividades de investigación registradas aún.</p>`;

  // Renderizar Hallazgos
  const findList = bundle.findings || [];
  document.getElementById("wsFindingsList").innerHTML = findList.length
    ? `<table class="soc-table"><thead><tr><th>Hallazgo</th><th>Naturaleza</th><th>Estado Verificación</th><th>Descripción</th></tr></thead><tbody>` +
      findList
        .map(
          (f) =>
            `<tr><td><strong>${esc(f.title)}</strong></td><td><code>${esc(f.finding_nature)}</code></td><td><span class="badge badge-purple">${esc(f.verification_state)}</span></td><td>${esc(f.description)}</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    : `<p style="color:var(--text-muted); font-size:12px;">Sin hallazgos estructurados registrados aún.</p>`;

  // Renderizar Acciones con selector en vivo de los 8 estados oficiales
  const actList = bundle.actions || [];
  const allStatuses = ["propuesta", "autorizada", "pendiente", "en_ejecucion", "ejecutada", "verificada", "cancelada", "no_aplicable"];
  document.getElementById("wsActionsList").innerHTML = actList.length
    ? `<table class="soc-table"><thead><tr><th>Acción</th><th>Tipo</th><th>Estado (8 Estados)</th><th>Evidencia / Notas</th></tr></thead><tbody>` +
      actList
        .map(
          (a) => `
          <tr>
            <td><strong>${esc(a.title)}</strong> ${provBadge(a.provenance)}</td>
            <td><code>${esc(a.action_type)}</code></td>
            <td>
              <select onchange="changeCaseActionStatus(${a.id}, this.value)" style="width:145px;">
                ${allStatuses.map((st) => `<option value="${st}" ${a.status === st ? "selected" : ""}>${st.toUpperCase()}</option>`).join("")}
              </select>
            </td>
            <td>${esc(a.result_notes)}</td>
          </tr>`
        )
        .join("") +
      `</tbody></table>`
    : `<p style="color:var(--text-muted); font-size:12px;">Sin acciones registradas. Puedes aplicar un Playbook arriba o agregar una acción abajo.</p>`;

  // Renderizar Comunicaciones
  const commsList = bundle.communications || [];
  document.getElementById("wsCommsList").innerHTML = commsList.length
    ? `<table class="soc-table"><thead><tr><th>Canal</th><th>Destinatario</th><th>Ref / Ticket</th><th>Resumen</th></tr></thead><tbody>` +
      commsList
        .map(
          (cm) =>
            `<tr><td>${esc(cm.channel)}</td><td><strong>${esc(cm.recipient)}</strong></td><td>${esc(cm.ticket_reference)}</td><td>${esc(cm.summary)}</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    : `<p style="color:var(--text-muted); font-size:12px;">Sin comunicaciones registradas aún.</p>`;

  // Evidencias e IOCs
  const iocs = iris.iocs || [];
  const evs = iris.evidences || [];
  document.getElementById("wsEvidencesAndIocsBox").innerHTML = `
    <div style="margin-bottom:10px;">
      <strong>Evidencias en Datastore IRIS (${evs.length}):</strong>
      ${evs.map((e) => `<span class="badge badge-ok" style="margin-left:6px;">📎 ${esc(e.filename)} (${esc(e.file_size, 0)} B)</span>`).join("") || "Ninguna"}
    </div>
    <div>
      <strong>Indicadores IOCs en IRIS (${iocs.length}):</strong>
      ${iocs.map((i) => `<span class="badge badge-info" style="margin:3px;">${esc(i.ioc_type)}: ${esc(i.ioc_value)}</span>`).join("") || "Ninguno"}
    </div>
  `;

  // Notas originales de IRIS
  const notes = iris.notes || [];
  document.getElementById("wsIrisNotesList").innerHTML = notes
    .map(
      (n) => `
      <div class="card" style="background:var(--bg-card); margin-bottom:10px;">
        <div style="font-weight:700; margin-bottom:6px; color:var(--accent-cyan);">
          📝 ${esc(n.note_title)} <span style="font-size:11px; color:var(--text-muted);">(${esc(n.directory_name)} · Nota #${n.note_id})</span>
        </div>
        <div class="code-box" style="max-height:220px;">${esc(n.note_content)}</div>
      </div>`
    )
    .join("");
}

async function saveStructuredCaseWorkspace() {
  if (!SOC_STATE.activeCaseId) return;
  try {
    const body = {
      case_name: document.getElementById("wsCaseName").value,
      organization: document.getElementById("wsOrganization").value,
      state_id: parseInt(document.getElementById("wsStateId").value, 10),
      case_description: document.getElementById("wsCaseDescription").value,
      abuse_ticket_id: document.getElementById("wsAbuseTicket").value,
      holder_ticket_id: document.getElementById("wsHolderTicket").value,
      client_id: document.getElementById("wsClientId").value,
      service_id: document.getElementById("wsServiceId").value,
      primary_domain: document.getElementById("wsPrimaryDomain").value,
      server_name: document.getElementById("wsServerName").value,
      hosting_ip: document.getElementById("wsHostingIp").value,
      reported_ip: document.getElementById("wsReportedIp").value,
      category_code: document.getElementById("wsCategoryCode").value,
      reported_activity: document.getElementById("wsReportedActivity").value,
      confirmed_incident_type: document.getElementById("wsConfirmedIncident").value,
      entry_vector: document.getElementById("wsEntryVector").value,
      root_cause: document.getElementById("wsRootCause").value,
      is_technical_compromise: document.getElementById("wsIsCompromise").value === "true",
      sync_structured_note_to_iris: true,
    };
    await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    });
    showToast(`Caso #${SOC_STATE.activeCaseId} guardado en PostgreSQL y sincronizado con DFIR-IRIS.`);
    await openCaseWorkspace(SOC_STATE.activeCaseId);
  } catch (e) {
    showToast("Error guardando caso: " + e.message);
  }
}

async function addWorkspaceInvestigation() {
  if (!SOC_STATE.activeCaseId) return;
  const resObs = document.getElementById("newInvResult").value.trim();
  if (!resObs) return showToast("Describe el resultado observado.");
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/investigations`, {
    method: "POST",
    body: JSON.stringify({
      source_consulted: document.getElementById("newInvSource").value,
      commands_or_queries: document.getElementById("newInvQuery").value,
      fact_type: document.getElementById("newInvFactType").value,
      results_observed: resObs,
    }),
  });
  document.getElementById("newInvResult").value = "";
  showToast("Actividad de investigación registrada.");
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function addWorkspaceFinding() {
  if (!SOC_STATE.activeCaseId) return;
  const title = document.getElementById("newFindingTitle").value.trim();
  const desc = document.getElementById("newFindingDesc").value.trim();
  if (!title || !desc) return showToast("Completa título y descripción del hallazgo.");
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/findings`, {
    method: "POST",
    body: JSON.stringify({
      title,
      description: desc,
      finding_nature: document.getElementById("newFindingNature").value,
      verification_state: document.getElementById("newFindingState").value,
    }),
  });
  document.getElementById("newFindingTitle").value = "";
  document.getElementById("newFindingDesc").value = "";
  showToast("Hallazgo registrado.");
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function addWorkspaceAction() {
  if (!SOC_STATE.activeCaseId) return;
  const title = document.getElementById("newActionTitle").value.trim();
  if (!title) return showToast("Escribe el título de la acción.");
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/actions`, {
    method: "POST",
    body: JSON.stringify({
      action_type: document.getElementById("newActionType").value,
      title,
      status: document.getElementById("newActionStatus").value,
      result_notes: document.getElementById("newActionNotes").value,
      sync_task_to_iris: true,
    }),
  });
  document.getElementById("newActionTitle").value = "";
  document.getElementById("newActionNotes").value = "";
  showToast("Acción registrada y sincronizada con Tareas de DFIR-IRIS.");
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function changeCaseActionStatus(actionId, newStatus) {
  if (!SOC_STATE.activeCaseId) return;
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/actions/${actionId}`, {
    method: "PUT",
    body: JSON.stringify({ status: newStatus }),
  });
  showToast(`Estado de acción actualizado a '${newStatus.toUpperCase()}' y sincronizado con IRIS.`);
}

async function applySelectedPlaybookToCase() {
  if (!SOC_STATE.activeCaseId) return;
  const pbCode = document.getElementById("wsPlaybookSelect").value;
  if (!pbCode) return;
  const res = await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/apply-playbook/${pbCode}`, {
    method: "POST",
  });
  showToast(`Playbook aplicado (${res.steps_added} pasos nuevos sincronizados en IRIS).`);
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function addWorkspaceCommunication() {
  if (!SOC_STATE.activeCaseId) return;
  const rec = document.getElementById("newCommRecipient").value.trim();
  const sum = document.getElementById("newCommSummary").value.trim();
  if (!rec || !sum) return showToast("Completa destinatario y resumen.");
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/communications`, {
    method: "POST",
    body: JSON.stringify({
      channel: document.getElementById("newCommChannel").value,
      recipient: rec,
      ticket_reference: document.getElementById("newCommRef").value,
      summary: sum,
    }),
  });
  document.getElementById("newCommRecipient").value = "";
  document.getElementById("newCommSummary").value = "";
  showToast("Comunicación registrada.");
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function closeCurrentCaseInIris() {
  if (!SOC_STATE.activeCaseId) return;
  if (!confirm(`¿Confirmas cerrar el Caso #${SOC_STATE.activeCaseId} en DFIR-IRIS?`)) return;
  await apiFetch(`/api/v1/cases/${SOC_STATE.activeCaseId}/close`, { method: "POST" });
  showToast(`Caso #${SOC_STATE.activeCaseId} cerrado en DFIR-IRIS.`);
  await openCaseWorkspace(SOC_STATE.activeCaseId);
}

async function askGeminiCaseAssistant(presetPrompt) {
  const inputEl = document.getElementById("wsGeminiInput");
  const instruction = presetPrompt || (inputEl ? inputEl.value.trim() : "");
  if (!instruction) return;
  if (!presetPrompt && inputEl) inputEl.value = "";

  const outBox = document.getElementById("wsGeminiChatOutput");
  outBox.textContent = "Consultando a Google Gemini SOC Assistant...";

  const ctx = (SOC_STATE.activeCaseBundle && SOC_STATE.activeCaseBundle.extension) || {};
  try {
    const res = await apiFetch("/api/v1/admin/gemini/assist", {
      method: "POST",
      body: JSON.stringify({ instruction, context: ctx }),
    });
    outBox.textContent = `[Motor: ${res.engine}]\n\n${res.reply}`;
  } catch (e) {
    outBox.textContent = "Error en asistente: " + e.message;
  }
}

async function openManualCaseModal() {
  const domain = prompt("Dominio o activo primario para el nuevo caso manual:");
  if (!domain) return;
  const ticket = prompt("Número de ticket de referencia (opcional):", "MANUAL") || "MANUAL";
  const org = prompt("Organización (NBX o HP):", SOC_STATE.globalOrg || "NBX") || "NBX";
  try {
    const res = await apiFetch("/api/v1/cases", {
      method: "POST",
      body: JSON.stringify({
        organization: org.toUpperCase(),
        primary_domain: domain.trim(),
        abuse_ticket_id: ticket.trim(),
      }),
    });
    showToast(`Caso manual #${res.case_id} creado en DFIR-IRIS.`);
    await openCaseWorkspace(res.case_id);
  } catch (e) {
    showToast("Error creando caso manual: " + e.message);
  }
}

// =========================================================
// 5. MIGRACIÓN HISTÓRICA CONTROLADA (DRY-RUN Y LADO A LADO)
// =========================================================
async function loadMigrationCases() {
  const tbody = document.getElementById("migrationTableBody");
  if (!tbody) return;
  try {
    const data = await apiFetch("/api/v1/migration/cases");
    const list = data.cases || [];
    tbody.innerHTML = list
      .map(
        (c) => `
        <tr>
          <td><strong>#${c.case_id}</strong></td>
          <td>${orgBadge(c.organization)}</td>
          <td><strong>${esc(c.case_name)}</strong></td>
          <td><span class="badge badge-info">${esc(c.state_name)}</span></td>
          <td><span class="badge ${c.schema_version === "3.0" ? "badge-purple" : "badge-warn"}">${esc(c.schema_version)}</span></td>
          <td>
            <span class="badge ${
              c.migration_status === "migrated"
                ? "badge-ok"
                : c.migration_status === "preview_ready"
                ? "badge-info"
                : "badge-warn"
            }">
              ${esc(c.migration_status.toUpperCase())}
            </span>
          </td>
          <td><code>${c.snapshot_sha256 ? c.snapshot_sha256.slice(0, 14) + "..." : "Sin snapshot aún"}</code></td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-primary btn-sm" onclick="runCaseMigrationPreview(${c.case_id})">
                🔍 Previsualizar (Dry-Run)
              </button>
              <button class="btn btn-sm" onclick="openCaseWorkspace(${c.case_id})">
                📂 Ver Caso
              </button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--status-danger);">Error escaneando casos históricos: ${esc(e.message)}</td></tr>`;
  }
}

async function runCaseMigrationPreview(caseId) {
  SOC_STATE.activeMigrationCaseId = caseId;
  showToast(`Tomando snapshot SHA-256 y ejecutando Dry-Run para el Caso #${caseId}...`);
  try {
    const res = await apiFetch(`/api/v1/migration/cases/${caseId}/preview`, {
      method: "POST",
      body: JSON.stringify({ use_gemini: true }),
    });
    const orig = res.original || {};
    const prop = res.proposed || {};
    const dry = res.dry_run || {};

    document.getElementById("migrationPreviewCard").style.display = "block";
    document.getElementById("migPreviewTitle").textContent = `Previsualización Comparativa (Dry-Run) — Caso #${caseId}: ${orig.case_name || ""}`;
    document.getElementById("migSnapshotBadge").textContent = `Snapshot SHA-256: ${(res.snapshot_sha256 || "").slice(0, 16)}...`;

    const origNotesText = (orig.notes || [])
      .map((n) => `--- [${n.note_title}] ---\n${n.note_content}`)
      .join("\n\n");
    document.getElementById("migOriginalBox").textContent =
      `TÍTULO ORIGINAL: ${orig.case_name}\n\n` +
      `RESUMEN ORIGINAL:\n${orig.case_description || ""}\n\n` +
      `ATRIBUTOS PERSONALIZADOS:\n${JSON.stringify(orig.custom_attributes || {}, null, 2)}\n\n` +
      `NOTAS HISTÓRICAS CONSERVADAS (${(orig.notes || []).length}):\n${origNotesText}`;

    document.getElementById("migOrg").value = prop.organization || "NBX";
    document.getElementById("migAbuseTicket").value = prop.abuse_ticket_id || "";
    document.getElementById("migHolderTicket").value = prop.holder_ticket_id || "";
    document.getElementById("migClientId").value = prop.client_id || "";
    document.getElementById("migServiceId").value = prop.service_id || "";
    document.getElementById("migDomain").value = prop.primary_domain || "";
    document.getElementById("migServer").value = prop.server_name || "";
    document.getElementById("migHostingIp").value = prop.hosting_ip || "";
    document.getElementById("migReportedIp").value = prop.reported_ip || "";
    document.getElementById("migCategory").value = prop.category_code || "abuse_phishing";
    document.getElementById("migRepAct").value = prop.reported_activity || "unknown";
    document.getElementById("migConfInc").value = prop.confirmed_incident_type || "pending_investigation";
    document.getElementById("migVector").value = prop.entry_vector || "unknown";
    document.getElementById("migRootCause").value = prop.root_cause || "unknown";
    document.getElementById("migVerifState").value = prop.verification_state || "pendiente";

    document.getElementById("migProposedBreakdownBox").textContent = JSON.stringify(
      {
        epistemological_breakdown: prop.epistemological_breakdown,
        dry_run_operations: {
          original_notes_preserved: dry.original_notes_preserved_count,
          original_evidences_preserved: dry.original_evidences_preserved_count,
          new_iocs_to_add: (dry.new_iocs_to_sync || []).length,
          new_tasks_to_add: (dry.new_tasks_to_sync || []).length,
          destructive_operations: 0,
        },
      },
      null,
      2
    );
    await loadMigrationCases();
  } catch (e) {
    showToast("Error en previsualización de migración: " + e.message);
  }
}

async function approveAndExecuteSingleMigration() {
  const caseId = SOC_STATE.activeMigrationCaseId;
  if (!caseId) return;
  if (
    !confirm(
      `¿Autorizas ejecutar la migración estructurada v3.0 para el Caso #${caseId}?\n\n` +
        `• Se conservarán intactas las notas y evidencias originales.\n` +
        `• Se guardarán los 4 ejes y entidades estructuradas en PostgreSQL.\n` +
        `• Se sincronizarán IOCs, tareas y la nota técnica 04 en DFIR-IRIS sin duplicar.`
    )
  ) {
    return;
  }

  const reviewedData = {
    organization: document.getElementById("migOrg").value,
    abuse_ticket_id: document.getElementById("migAbuseTicket").value,
    holder_ticket_id: document.getElementById("migHolderTicket").value,
    client_id: document.getElementById("migClientId").value,
    service_id: document.getElementById("migServiceId").value,
    primary_domain: document.getElementById("migDomain").value,
    server_name: document.getElementById("migServer").value,
    hosting_ip: document.getElementById("migHostingIp").value,
    reported_ip: document.getElementById("migReportedIp").value,
    category_code: document.getElementById("migCategory").value,
    reported_activity: document.getElementById("migRepAct").value,
    confirmed_incident_type: document.getElementById("migConfInc").value,
    entry_vector: document.getElementById("migVector").value,
    root_cause: document.getElementById("migRootCause").value,
    verification_state: document.getElementById("migVerifState").value,
  };

  try {
    await apiFetch(`/api/v1/migration/cases/${caseId}/execute`, {
      method: "POST",
      body: JSON.stringify({
        reviewed_data: reviewedData,
        sync_to_iris: true,
        explicit_approval: true,
      }),
    });
    showToast(`Caso #${caseId} migrado exitosamente al esquema v3.0.`);
    document.getElementById("migrationPreviewCard").style.display = "none";
    await loadMigrationCases();
  } catch (e) {
    showToast("Error ejecutando migración: " + e.message);
  }
}

// =========================================================
// 6. CONECTORES & BLACKLIST MASTER RBL
// =========================================================
async function loadConnectorsView() {
  try {
    const data = await apiFetch("/api/v1/admin/connectors");
    const container = document.getElementById("connectorsCardsContainer");
    container.innerHTML = (data.connectors || [])
      .map(
        (c) => `
        <div class="card" style="background:var(--bg-card); margin-bottom:0;">
          <div class="card-header">
            <div>
              <strong>${esc(c.name)}</strong>
              <div style="font-size:11px; color:var(--text-muted);">Tipo: <code>${esc(c.connector_type)}</code> · Secreto: ${esc(c.secret_hint)}</div>
            </div>
            <span class="badge ${c.is_enabled ? "badge-ok" : "badge-neutral"}">${c.is_enabled ? "Habilitado" : "Deshabilitado"}</span>
          </div>
          <div class="code-box" style="max-height:110px; margin-bottom:10px;">${esc(JSON.stringify(c.settings_json || {}, null, 2))}</div>
          <div style="display:flex; gap:6px; justify-content:flex-end;">
            <button class="btn btn-sm" onclick="testConnectorById(${c.id})">🔌 Probar Conexión</button>
            <button class="btn btn-sm" onclick="toggleConnectorEnabled(${c.id}, ${!c.is_enabled})">
              ${c.is_enabled ? "⏸ Desactivar" : "▶ Activar"}
            </button>
            <button class="btn btn-primary btn-sm" onclick="promptConnectorSecret(${c.id}, '${esc(c.name)}')">🔑 Configurar Token/Clave</button>
          </div>
        </div>`
      )
      .join("");

    const rblData = await apiFetch("/api/v1/ingest/rbl-episodes");
    const rblBody = document.getElementById("rblEpisodesBody");
    const eps = rblData.episodes || [];
    rblBody.innerHTML = eps.length
      ? eps
          .map(
            (r) => `
          <tr>
            <td>#${r.id}</td>
            <td><code>${esc(r.ip_address)}</code></td>
            <td>${esc(r.server_name)}</td>
            <td>${orgBadge(r.organization)}</td>
            <td><strong>${esc(r.rbl_provider)}</strong></td>
            <td><span class="badge ${r.status === "active" ? "badge-high" : "badge-ok"}">${esc(r.status)}</span></td>
            <td><strong>${r.check_count}</strong> chequeo(s)</td>
            <td>${r.iris_alert_id ? "Alerta #" + r.iris_alert_id : "—"}</td>
            <td>${esc((r.last_seen_at || "").replace("T", " ").slice(0, 19))}</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="9" style="color:var(--text-muted); text-align:center;">Sin episodios RBL registrados. Haz clic en "Simular Evento RBL" para probar la deduplicación.</td></tr>`;
  } catch (e) {
    showToast("Error cargando conectores: " + e.message);
  }
}

async function testConnectorById(id) {
  try {
    const res = await apiFetch(`/api/v1/admin/connectors/${id}/test`, { method: "POST" });
    showToast(`${res.ok ? "✅ Conectado" : "⚠️ Aviso"}: ${res.message || res.status}`);
    await loadConnectorsView();
  } catch (e) {
    showToast("Error probando conector: " + e.message);
  }
}

async function toggleConnectorEnabled(id, enabled) {
  await apiFetch(`/api/v1/admin/connectors/${id}`, {
    method: "PUT",
    body: JSON.stringify({ is_enabled: enabled }),
  });
  showToast("Estado del conector actualizado.");
  await loadConnectorsView();
}

async function promptConnectorSecret(id, name) {
  const sec = prompt(`Ingresa el Token / API Key / Contraseña para '${name}' (se almacenará cifrado con Fernet/AES):`);
  if (!sec || !sec.trim()) return;
  await apiFetch(`/api/v1/admin/connectors/${id}`, {
    method: "PUT",
    body: JSON.stringify({ secret_value: sec.trim(), is_enabled: true }),
  });
  showToast(`Credencial cifrada y guardada para ${name}.`);
  await loadConnectorsView();
}

async function simulateRblWebhookEvent() {
  const res = await apiFetch("/api/v1/webhooks/blacklist-master", {
    method: "POST",
    body: JSON.stringify({
      ip_address: "174.136.26.134",
      rbl_provider: "Spamhaus ZEN",
      server_name: "svgr252.serverneubox.com.mx",
      organization: "NBX",
      event_status: "listed",
      reason: "Detección de envío SMTP en IP compartida",
    }),
  });
  showToast(
    res.is_new_episode
      ? `Nuevo episodio RBL #${res.episode_id} creado (Alerta IRIS #${res.iris_alert_id})`
      : `Episodio RBL #${res.episode_id} deduplicado (Conteo incrementado a ${res.check_count}, 0 alertas duplicadas)`
  );
  await loadConnectorsView();
}

// =========================================================
// 7. ADMINISTRACIÓN, GEMINI API, USUARIOS Y AUDITORÍA
// =========================================================
async function loadAdminView() {
  try {
    const g = await apiFetch("/api/v1/admin/gemini");
    const cfg = g.gemini || {};
    updateGeminiTopbar(cfg);
    document.getElementById("geminiModelSelect").value = cfg.model || "gemini-2.5-flash";
    document.getElementById("geminiEnabledSelect").value = String(Boolean(cfg.is_enabled));

    const audit = await apiFetch("/api/v1/admin/audit-logs");
    document.getElementById("adminAuditBody").innerHTML = (audit.logs || [])
      .map(
        (l) => `
        <tr>
          <td>#${l.id}</td>
          <td style="font-size:11.5px;">${esc((l.timestamp || "").replace("T", " ").slice(0, 19))}</td>
          <td><strong>${esc(l.username)}</strong></td>
          <td><span class="badge badge-info">${esc(l.module)}</span></td>
          <td><code>${esc(l.action)}</code></td>
          <td>${l.organization ? orgBadge(l.organization) : "—"}</td>
          <td>${l.iris_case_id ? "Caso #" + l.iris_case_id : l.iris_alert_id ? "Alerta #" + l.iris_alert_id : "—"}</td>
          <td>${esc(l.details)}</td>
        </tr>`
      )
      .join("");

    try {
      const uData = await apiFetch("/api/v1/auth/users");
      document.getElementById("adminUsersBody").innerHTML = (uData.users || [])
        .map(
          (u) => `
          <tr>
            <td><strong>${esc(u.username)}</strong></td>
            <td>${esc(u.full_name)}</td>
            <td><span class="badge badge-purple">${esc(u.role)}</span></td>
            <td>${(u.allowed_orgs || []).join(", ")}</td>
            <td><span class="badge ${u.is_active ? "badge-ok" : "badge-high"}">${u.is_active ? "Activo" : "Inactivo"}</span></td>
          </tr>`
        )
        .join("");
    } catch (_) {
      document.getElementById("adminUsersBody").innerHTML = `<tr><td colspan="5" style="color:var(--text-muted);">Inicia sesión con rol Supervisor o Admin para administrar usuarios.</td></tr>`;
    }
  } catch (e) {
    showToast("Error cargando vista de administración: " + e.message);
  }
}

async function saveGeminiConfig() {
  const key = document.getElementById("geminiApiKeyInput").value.trim();
  const model = document.getElementById("geminiModelSelect").value;
  const enabled = document.getElementById("geminiEnabledSelect").value === "true";

  try {
    const res = await apiFetch("/api/v1/admin/gemini", {
      method: "PUT",
      body: JSON.stringify({
        api_key: key || undefined,
        model,
        is_enabled: enabled,
      }),
    });
    document.getElementById("geminiApiKeyInput").value = "";
    updateGeminiTopbar(res.gemini || {});
    showToast("Configuración de Google Gemini guardada y cifrada en base de datos.");
  } catch (e) {
    showToast("Error guardando Gemini: " + e.message);
  }
}

async function testGeminiApi() {
  const msgEl = document.getElementById("geminiTestStatusMsg");
  if (msgEl) msgEl.textContent = "Probando conexión con Google Gemini API...";
  try {
    const res = await apiFetch("/api/v1/admin/gemini/test", { method: "POST" });
    if (msgEl) {
      msgEl.textContent = res.ok
        ? `✅ Conectado a ${res.model} (${res.key_hint})`
        : `⚠️ ${res.message}`;
    }
    showToast(res.ok ? "Conexión exitosa con Google Gemini API" : res.message);
  } catch (e) {
    if (msgEl) msgEl.textContent = "Error: " + e.message;
  }
}

// =========================================================
// AUTENTICACIÓN MODAL
// =========================================================
function openLoginModal() {
  document.getElementById("loginModal").classList.add("open");
}

function closeLoginModal() {
  document.getElementById("loginModal").classList.remove("open");
}

async function submitLogin() {
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  try {
    const res = await apiFetch("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    SOC_STATE.currentUser = res.user;
    SOC_STATE.csrfToken = res.csrf_token;
    updateUserUi();
    closeLoginModal();
    showToast(`Bienvenido, ${res.user.full_name} (Rol: ${res.user.role})`);
    if (SOC_STATE.currentView === "admin") loadAdminView();
  } catch (e) {
    showToast("Error de autenticación: " + e.message);
  }
}

function updateUserUi() {
  const lbl = document.getElementById("currentUserLabel");
  const btn = document.getElementById("sidebarAuthBtn");
  if (SOC_STATE.currentUser) {
    if (lbl) lbl.textContent = `${SOC_STATE.currentUser.username} (${SOC_STATE.currentUser.role})`;
    if (btn) {
      btn.textContent = "🚪 Cerrar Sesión (" + SOC_STATE.currentUser.username + ")";
      btn.onclick = async () => {
        await apiFetch("/api/v1/auth/logout", { method: "POST" });
        SOC_STATE.currentUser = null;
        SOC_STATE.csrfToken = null;
        if (lbl) lbl.textContent = "Sesión Local SOC";
        btn.textContent = "🔐 Iniciar Sesión SOC";
        btn.onclick = openLoginModal;
        showToast("Sesión cerrada.");
      };
    }
  }
}

document.addEventListener("DOMContentLoaded", initSocConsole);
