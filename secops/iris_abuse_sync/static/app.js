// DFIR-IRIS Abuse Sync Frontend Controller (v2.2)
// Supports: Live Markdown Preview, DFIR-IRIS Case Management, Report Generation & PDF Export

let currentParsedData = null;
let currentClassification = null;
let currentPreviewPayload = null;
let availableTemplates = [];
let activeCustomer = "neubox"; // "neubox" or "hospedando"
let currentIocs = [];
let attachedEvidences = []; // Evidence files to upload to IRIS datastore

// Case Management State
let loadedIrisCases = [];
let currentCasesFilterState = "open"; // "open" or "all"
let currentCasesFilterCust = "all"; // "all", "neubox", "hospedando"
let activeReportCaseId = null;
let activeReportCaseData = null;
let allNotesInPreviewMode = false;

document.addEventListener("DOMContentLoaded", () => {
  initStatus();
  initOllama();
  initTemplates();
  initDropzone();
  initEvidenceDropzone();
  initReportEditorPasteListener();
  loadHistory();
  loadIrisCases(false);
});

// Configure Marked options if loaded
if (typeof marked !== "undefined") {
  marked.setOptions({
    gfm: true,
    breaks: true
  });
}

function parseMarkdownSafe(mdText) {
  if (!mdText) return "<p><em>(Sin contenido)</em></p>";
  if (typeof marked !== "undefined" && typeof marked.parse === "function") {
    return marked.parse(mdText);
  }
  // Simple fallback
  return mdText.replace(/\n/g, "<br>");
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// -------------------------------------------------------------
// Top Navigation Views (Ingest vs Cases)
// -------------------------------------------------------------
function switchMainView(viewName) {
  const btnIngest = document.getElementById("tab-nav-ingest");
  const btnCases = document.getElementById("tab-nav-cases");
  const viewIngest = document.getElementById("view-ingest");
  const viewCases = document.getElementById("view-cases");

  if (viewName === "cases") {
    btnCases.classList.add("active");
    btnIngest.classList.remove("active");
    viewCases.classList.remove("hidden");
    viewIngest.classList.add("hidden");
    loadIrisCases(true);
  } else {
    btnIngest.classList.add("active");
    btnCases.classList.remove("active");
    viewIngest.classList.remove("hidden");
    viewCases.classList.add("hidden");
  }
}

// -------------------------------------------------------------
// 1. Fetch system status
// -------------------------------------------------------------
async function initStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    const badge = document.getElementById("iris-status-badge");
    const text = document.getElementById("iris-status-text");
    const urlPill = document.getElementById("iris-url-val");

    urlPill.textContent = data.iris_url.replace(/^https?:\/\//, "");

    if (data.iris_connected) {
      badge.className = "status-indicator online";
      text.textContent = "DFIR-IRIS Conectado";
    } else {
      badge.className = "status-indicator checking";
      text.textContent = data.iris_error ? "DFIR-IRIS: Revisar API Key" : "DFIR-IRIS Offline";
    }

    if (data.default_customer) {
      setCustomer(data.default_customer, false);
    }
  } catch (e) {
    const badge = document.getElementById("iris-status-badge");
    badge.className = "status-indicator offline";
    document.getElementById("iris-status-text").textContent = "API Local No Disponible";
  }
}

// -------------------------------------------------------------
// 2. Fetch Ollama models
// -------------------------------------------------------------
async function initOllama() {
  const select = document.getElementById("ollama-model-select");
  try {
    const res = await fetch("/api/ollama/models");
    const data = await res.json();
    select.innerHTML = "";

    if (data.available && data.models.length > 0) {
      data.models.forEach(m => {
        const opt = document.createElement("option");
        opt.value = m;
        opt.textContent = m;
        if (m === data.current || (m.includes("qwen") && !data.current)) {
          opt.selected = true;
        }
        select.appendChild(opt);
      });
    } else {
      select.innerHTML = "<option value='none'>Ollama no detectado</option>";
    }
  } catch (e) {
    select.innerHTML = "<option value='none'>Ollama no disponible</option>";
  }
}

function onOllamaModelChange() {
  console.log("Selected Ollama model:", document.getElementById("ollama-model-select").value);
}

// -------------------------------------------------------------
// 3. Load available templates
// -------------------------------------------------------------
async function initTemplates() {
  try {
    const res = await fetch("/api/templates");
    const data = await res.json();
    availableTemplates = data.templates || [];

    const select = document.getElementById("template-select");
    select.innerHTML = "";
    availableTemplates.forEach(t => {
      const opt = document.createElement("option");
      opt.value = t.name;
      opt.textContent = `${t.prefix} ${t.display_name} (${t.name})`;
      select.appendChild(opt);
    });
  } catch (e) {
    console.error("Error loading templates", e);
  }
}

// -------------------------------------------------------------
// 4. Customer Switching (Neubox vs Hospedando)
// -------------------------------------------------------------
function setCustomer(custKey, triggerRecalc = true) {
  activeCustomer = custKey.toLowerCase();

  const btnNbx = document.getElementById("btn-cust-nbx");
  const btnHp = document.getElementById("btn-cust-hp");

  if (activeCustomer === "hospedando") {
    btnHp.classList.add("active");
    btnNbx.classList.remove("active");
  } else {
    btnNbx.classList.add("active");
    btnHp.classList.remove("active");
  }

  if (triggerRecalc && currentParsedData) {
    recalculateFields();
  }
}

// -------------------------------------------------------------
// 5. Dropzone setup
// -------------------------------------------------------------
function initDropzone() {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");

  dropzone.addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") {
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length) {
      uploadFile(e.target.files[0]);
    }
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });
}

// -------------------------------------------------------------
// 6. Sample Loader
// -------------------------------------------------------------
async function loadSample(sampleName) {
  const loading = document.getElementById("parse-loading");
  loading.classList.remove("hidden");

  try {
    const res = await fetch(`/api/sample/${sampleName}`);
    if (!res.ok) throw new Error("Error cargando muestra");
    const data = await res.json();
    renderAnalysis(data);
  } catch (err) {
    alert("Error cargando muestra: " + err.message);
  } finally {
    loading.classList.add("hidden");
  }
}

// -------------------------------------------------------------
// 7. Upload & Parse File
// -------------------------------------------------------------
async function uploadFile(file) {
  const loading = document.getElementById("parse-loading");
  loading.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/parse", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Error al procesar el archivo");
    }

    const data = await res.json();
    renderAnalysis(data);
  } catch (e) {
    alert("Error: " + e.message);
  } finally {
    loading.classList.add("hidden");
  }
}

// -------------------------------------------------------------
// 8. Render Extracted Analysis in UI
// -------------------------------------------------------------
function renderAnalysis(data) {
  currentParsedData = data.parsed;
  currentClassification = data.classification;
  currentPreviewPayload = data.preview_payload;
  currentIocs = [...(currentPreviewPayload.iocs || [])];
  attachedEvidences = [];
  renderEvidencesList();

  // Auto-detect customer
  const detectedCust = currentPreviewPayload.customer_key || "neubox";
  setCustomer(detectedCust, false);

  // Overview Card
  document.getElementById("overview-card").classList.remove("hidden");
  document.getElementById("lbl-ticket-id").textContent = `Ticket #${currentParsedData.ticket_id || "N/A"}`;
  const lnkTicket = document.getElementById("lnk-ticket");
  if (currentParsedData.ticket_url) {
    lnkTicket.href = currentParsedData.ticket_url;
    lnkTicket.classList.remove("hidden");
  } else {
    lnkTicket.classList.add("hidden");
  }

  document.getElementById("lbl-priority").textContent = currentParsedData.priority || "Normal";
  document.getElementById("lbl-asset").textContent = currentParsedData.affected_asset || "No especificado";
  document.getElementById("lbl-reporter").textContent = currentParsedData.reporter || "No especificado";
  document.getElementById("lbl-server").textContent = currentParsedData.neubox_servers.join(", ") || "No detectado";
  document.getElementById("lbl-ip").textContent = currentParsedData.primary_ip || "N/A";
  document.getElementById("lbl-auth").textContent = currentParsedData.primary_account || "N/A";
  document.getElementById("lbl-client-ticket").textContent = currentParsedData.client_ticket ? `#${currentParsedData.client_ticket}` : "N/A";
  document.getElementById("lbl-summary").textContent = currentParsedData.brief_summary || "Sin resumen";

  // Fill Quick Parameter Fields
  document.getElementById("param-report-ticket").value = currentParsedData.ticket_id || "";
  document.getElementById("param-client-ticket").value = currentParsedData.client_ticket || "";
  document.getElementById("param-client-id").value = "";
  document.getElementById("param-service-id").value = "";
  document.getElementById("param-asset").value = currentParsedData.affected_asset || "";
  document.getElementById("param-server").value = currentParsedData.primary_server || (currentParsedData.neubox_servers[0] || "");

  // Activate Right Panel
  document.getElementById("case-empty-state").classList.add("hidden");
  document.getElementById("case-active-state").classList.remove("hidden");

  // Template Selector
  const select = document.getElementById("template-select");
  select.value = currentClassification.template_name;

  const confBadge = document.getElementById("confidence-badge");
  const confPct = Math.round(currentClassification.confidence * 100);
  confBadge.textContent = `${confPct}% Confianza`;

  document.getElementById("reasons-text").textContent = `Criterios: ${currentClassification.reasons.join(", ")}`;

  // Case Name & Summary
  document.getElementById("case-name-input").value = currentPreviewPayload.case_name;
  const descInput = document.getElementById("case-desc-input");
  descInput.value = currentPreviewPayload.case_description;
  // Reset preview for desc
  const descPreview = document.getElementById("case-desc-preview");
  descPreview.classList.add("hidden");
  descInput.classList.remove("hidden");
  document.getElementById("btn-toggle-desc").textContent = "👁️ Previsualizar Markdown";

  // Render Tabs
  renderEditableNotes(currentPreviewPayload.notes);
  renderIocs(currentIocs);
  renderAttributes(currentPreviewPayload.custom_attributes);
  document.getElementById("raw-text-view").textContent = currentParsedData.raw_text;

  document.getElementById("result-banner").classList.add("hidden");
}

function onTemplateChange() {
  recalculateFields();
}

function onParamChange() {
  // Update Case Name dynamically in real time
  const tmpl = availableTemplates.find(t => t.name === document.getElementById("template-select").value);
  const prefix = tmpl ? tmpl.prefix : "[ABUSE]";
  const asset = document.getElementById("param-asset").value.trim();
  const code = activeCustomer === "hospedando" ? "HP" : "NBX";

  let num = "";
  const clientTick = document.getElementById("param-client-ticket").value.trim();
  const reportTick = document.getElementById("param-report-ticket").value.trim();

  if (activeCustomer === "hospedando" && clientTick) {
    num = clientTick;
  } else if (reportTick) {
    num = reportTick;
  } else if (clientTick) {
    num = clientTick;
  } else {
    num = "S/N";
  }

  const caseName = asset ? `${prefix} ${asset} | ${code}-${num}` : `${prefix} ${code}-${num}`;
  document.getElementById("case-name-input").value = caseName;

  // Sync with editable attributes inputs
  document.querySelectorAll(".attr-field-input").forEach(input => {
    const key = input.dataset.key;
    if (key === "Ticket de abuso" && document.activeElement !== input) input.value = reportTick;
    else if (key === "Dominio o activo reportado" && document.activeElement !== input) input.value = asset;
    else if (key === "Ticket del titular" && document.activeElement !== input) input.value = clientTick;
  });
}

// -------------------------------------------------------------
// 9. Recalculate fields from server
// -------------------------------------------------------------
async function recalculateFields() {
  if (!currentParsedData) return;

  const reqData = {
    parsed_data: currentParsedData,
    template_name: document.getElementById("template-select").value,
    overrides: {
      customer_key: activeCustomer,
      report_ticket: document.getElementById("param-report-ticket").value.trim(),
      client_ticket: document.getElementById("param-client-ticket").value.trim(),
      client_id: document.getElementById("param-client-id").value.trim(),
      service_id: document.getElementById("param-service-id").value.trim(),
      server: document.getElementById("param-server").value.trim(),
      affected_asset: document.getElementById("param-asset").value.trim()
    }
  };

  try {
    const res = await fetch("/api/recalculate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reqData)
    });
    const data = await res.json();
    if (data.success) {
      currentPreviewPayload = data.preview_payload;
      document.getElementById("case-name-input").value = currentPreviewPayload.case_name;
      document.getElementById("case-desc-input").value = currentPreviewPayload.case_description;
      renderEditableNotes(currentPreviewPayload.notes);
      renderAttributes(currentPreviewPayload.custom_attributes);
    }
  } catch (e) {
    console.error("Recalculate error", e);
  }
}

// -------------------------------------------------------------
// 10. Switch Sub-Tabs in Case Panel
// -------------------------------------------------------------
function switchTab(tabId) {
  document.querySelectorAll(".tabs-nav .tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-panes .tab-pane").forEach(pane => pane.classList.remove("active"));

  const targetPane = document.getElementById(`pane-${tabId}`);
  if (targetPane) targetPane.classList.add("active");

  const activeBtn = Array.from(document.querySelectorAll(".tabs-nav .tab-btn")).find(b => b.getAttribute("onclick").includes(tabId));
  if (activeBtn) activeBtn.classList.add("active");
}

// -------------------------------------------------------------
// 11. Render Notes with Markdown Live Preview
// -------------------------------------------------------------
function renderEditableNotes(notes) {
  const container = document.getElementById("notes-accordion");
  container.innerHTML = "";
  allNotesInPreviewMode = false;
  const toggleAllBtn = document.getElementById("btn-toggle-all-notes");
  if (toggleAllBtn) toggleAllBtn.textContent = "👁️ Previsualizar Todas";

  (notes || []).forEach((n, idx) => {
    const item = document.createElement("div");
    item.className = "note-item";
    item.id = `note-item-${idx}`;

    const header = document.createElement("div");
    header.className = "note-header";
    header.innerHTML = `
      <span style="font-weight:600">${n.title}</span>
      <div class="note-header-actions">
        <button type="button" class="btn-note-toggle" id="btn-note-toggle-${idx}" onclick="toggleNoteMode(${idx})">
          👁️ Vista Previa
        </button>
      </div>
    `;

    const textarea = document.createElement("textarea");
    textarea.className = "editable-note-textarea";
    textarea.id = `note-text-${idx}`;
    textarea.dataset.title = n.title;
    textarea.rows = 8;
    textarea.value = n.content;

    const previewDiv = document.createElement("div");
    previewDiv.className = "rendered-note-view hidden";
    previewDiv.id = `note-preview-${idx}`;
    previewDiv.title = "Haz clic en 'Editar' para modificar este texto";

    item.appendChild(header);
    item.appendChild(textarea);
    item.appendChild(previewDiv);
    container.appendChild(item);
  });
}

function toggleNoteMode(idx) {
  const textarea = document.getElementById(`note-text-${idx}`);
  const previewDiv = document.getElementById(`note-preview-${idx}`);
  const toggleBtn = document.getElementById(`btn-note-toggle-${idx}`);

  if (!textarea || !previewDiv) return;

  const isPreview = !previewDiv.classList.contains("hidden");

  if (isPreview) {
    // Switch to edit mode
    previewDiv.classList.add("hidden");
    textarea.classList.remove("hidden");
    toggleBtn.textContent = "👁️ Vista Previa";
    toggleBtn.classList.remove("active");
    textarea.focus();
  } else {
    // Switch to rendered preview mode
    const mdText = textarea.value;
    previewDiv.innerHTML = parseMarkdownSafe(mdText);
    textarea.classList.add("hidden");
    previewDiv.classList.remove("hidden");
    toggleBtn.textContent = "✏️ Editar Markdown";
    toggleBtn.classList.add("active");
  }
}

function toggleAllNotesMode() {
  allNotesInPreviewMode = !allNotesInPreviewMode;
  const toggleAllBtn = document.getElementById("btn-toggle-all-notes");

  document.querySelectorAll(".note-item").forEach((item, idx) => {
    const textarea = document.getElementById(`note-text-${idx}`);
    const previewDiv = document.getElementById(`note-preview-${idx}`);
    const toggleBtn = document.getElementById(`btn-note-toggle-${idx}`);

    if (allNotesInPreviewMode) {
      previewDiv.innerHTML = parseMarkdownSafe(textarea.value);
      textarea.classList.add("hidden");
      previewDiv.classList.remove("hidden");
      toggleBtn.textContent = "✏️ Editar";
      toggleBtn.classList.add("active");
    } else {
      previewDiv.classList.add("hidden");
      textarea.classList.remove("hidden");
      toggleBtn.textContent = "👁️ Vista Previa";
      toggleBtn.classList.remove("active");
    }
  });

  toggleAllBtn.textContent = allNotesInPreviewMode ? "✏️ Editar Todas" : "👁️ Previsualizar Todas";
}

function toggleDescMode() {
  const textarea = document.getElementById("case-desc-input");
  const previewDiv = document.getElementById("case-desc-preview");
  const toggleBtn = document.getElementById("btn-toggle-desc");

  const isPreview = !previewDiv.classList.contains("hidden");

  if (isPreview) {
    previewDiv.classList.add("hidden");
    textarea.classList.remove("hidden");
    toggleBtn.textContent = "👁️ Previsualizar Markdown";
    toggleBtn.classList.remove("active");
    textarea.focus();
  } else {
    previewDiv.innerHTML = parseMarkdownSafe(textarea.value);
    textarea.classList.add("hidden");
    previewDiv.classList.remove("hidden");
    toggleBtn.textContent = "✏️ Editar Markdown";
    toggleBtn.classList.add("active");
  }
}

// -------------------------------------------------------------
// 12. Render IOCs with delete and toggle
// -------------------------------------------------------------
function renderIocs(iocs) {
  const container = document.getElementById("iocs-list");
  const countBadge = document.getElementById("iocs-count");
  container.innerHTML = "";
  countBadge.textContent = (iocs || []).length;

  if (!iocs || !iocs.length) {
    container.innerHTML = "<p class='pane-hint'>No se detectaron IOCs automáticamente en el ticket.</p>";
    return;
  }

  iocs.forEach((ioc, idx) => {
    const row = document.createElement("div");
    row.className = "ioc-row";
    row.id = `ioc-row-${idx}`;

    const chk = document.createElement("input");
    chk.type = "checkbox";
    chk.id = `ioc-chk-${idx}`;
    chk.checked = true;
    chk.dataset.idx = idx;

    const badge = document.createElement("span");
    badge.className = `ioc-badge ${ioc.type}`;
    badge.textContent = ioc.type;

    const val = document.createElement("span");
    val.className = "ioc-val";
    val.textContent = ioc.value;

    const btnDel = document.createElement("button");
    btnDel.type = "button";
    btnDel.className = "btn-del-ioc";
    btnDel.innerHTML = "✕";
    btnDel.title = "Eliminar este indicador";
    btnDel.onclick = () => removeIoc(idx);

    row.appendChild(chk);
    row.appendChild(badge);
    row.appendChild(val);
    row.appendChild(btnDel);
    container.appendChild(row);
  });
}

function removeIoc(idx) {
  currentIocs.splice(idx, 1);
  renderIocs(currentIocs);
}

function promptAddIoc() {
  const type = prompt("Tipo de IOC (domain, ip, url, email):", "domain");
  if (!type) return;
  const value = prompt("Valor del IOC:", "");
  if (!value) return;

  currentIocs.push({
    type: type.trim().toLowerCase(),
    value: value.trim(),
    description: "Agregado manualmente por el analista"
  });
  renderIocs(currentIocs);
}

// -------------------------------------------------------------
// 13. Render Editable Custom Attributes
// -------------------------------------------------------------
function renderAttributes(attrs) {
  const container = document.getElementById("attributes-preview");
  container.innerHTML = "";

  const section = (attrs && attrs["01 Identificación"]) || {};

  // Standard official keys in 01 Identificación
  const defaultKeys = [
    "Ticket de abuso",
    "Dominio o activo reportado",
    "IP reportada",
    "Ticket del titular"
  ];

  const allEntries = { ...section };
  defaultKeys.forEach(k => {
    if (!(k in allEntries)) allEntries[k] = "";
  });

  let idx = 0;
  for (const [key, val] of Object.entries(allEntries)) {
    const row = document.createElement("div");
    row.className = "attr-row-editable";
    row.id = `attr-row-${idx}`;

    row.innerHTML = `
      <div class="attr-label-col">
        <label for="attr-input-${idx}">
          ${key}:
        </label>
      </div>
      <div class="attr-input-col">
        <input 
          type="text" 
          id="attr-input-${idx}" 
          class="attr-field-input" 
          data-category="01 Identificación" 
          data-key="${key}" 
          value="${val || ''}" 
          placeholder="(vacío)"
          oninput="onAttributeFieldChange('${key}', this.value)"
        >
      </div>
    `;
    container.appendChild(row);
    idx++;
  }
}

function onAttributeFieldChange(key, value) {
  const val = value.trim();

  // 1. Sync with quick parameters if corresponding
  if (key === "Ticket de abuso") {
    const param = document.getElementById("param-report-ticket");
    if (param && param.value !== val) {
      param.value = val;
      onParamChange();
    }
  } else if (key === "Dominio o activo reportado") {
    const param = document.getElementById("param-asset");
    if (param && param.value !== val) {
      param.value = val;
      onParamChange();
    }
  } else if (key === "Ticket del titular") {
    const param = document.getElementById("param-client-ticket");
    if (param && param.value !== val) {
      param.value = val;
      onParamChange();
    }
  }

  // 2. Update currentPreviewPayload
  if (currentPreviewPayload) {
    if (!currentPreviewPayload.custom_attributes) {
      currentPreviewPayload.custom_attributes = { "01 Identificación": {} };
    }
    if (!currentPreviewPayload.custom_attributes["01 Identificación"]) {
      currentPreviewPayload.custom_attributes["01 Identificación"] = {};
    }
    currentPreviewPayload.custom_attributes["01 Identificación"][key] = val;
  }
}

function promptAddCustomAttribute() {
  const name = prompt("Nombre del nuevo atributo (ej. IP Secundaria, Ticket Proveedor):", "");
  if (!name || !name.trim()) return;
  const val = prompt(`Valor para '${name.trim()}':`, "");

  if (!currentPreviewPayload) currentPreviewPayload = {};
  if (!currentPreviewPayload.custom_attributes) currentPreviewPayload.custom_attributes = { "01 Identificación": {} };
  if (!currentPreviewPayload.custom_attributes["01 Identificación"]) currentPreviewPayload.custom_attributes["01 Identificación"] = {};

  currentPreviewPayload.custom_attributes["01 Identificación"][name.trim()] = (val || "").trim();
  renderAttributes(currentPreviewPayload.custom_attributes);
}

// -------------------------------------------------------------
// 14. Submit Case Creation
// -------------------------------------------------------------
async function submitCase(isDryRun) {
  if (!currentParsedData) return;

  const btnDry = document.getElementById("btn-dry-run");
  const btnReal = document.getElementById("btn-create-real");
  const resultBanner = document.getElementById("result-banner");

  btnDry.disabled = true;
  btnReal.disabled = true;
  resultBanner.className = "result-banner hidden";

  // Gather edited notes (read textarea value regardless of mode)
  const editedNotes = [];
  document.querySelectorAll(".editable-note-textarea").forEach(ta => {
    editedNotes.push({
      title: ta.dataset.title,
      content: ta.value
    });
  });

  // Gather selected IOCs
  const selectedIocs = [];
  document.querySelectorAll("#iocs-list input[type='checkbox']:checked").forEach(chk => {
    const idx = parseInt(chk.dataset.idx, 10);
    if (!isNaN(idx) && currentIocs[idx]) {
      selectedIocs.push(currentIocs[idx]);
    }
  });

  // Gather editable custom attributes
  const customAttrs = { "01 Identificación": {} };
  document.querySelectorAll(".attr-field-input").forEach(input => {
    const cat = input.dataset.category || "01 Identificación";
    const key = input.dataset.key;
    if (!customAttrs[cat]) customAttrs[cat] = {};
    customAttrs[cat][key] = input.value.trim();
  });

  const reqPayload = {
    parsed_data: currentParsedData,
    template_name: document.getElementById("template-select").value,
    overrides: {
      customer_key: activeCustomer,
      report_ticket: document.getElementById("param-report-ticket").value.trim(),
      client_ticket: document.getElementById("param-client-ticket").value.trim(),
      client_id: document.getElementById("param-client-id").value.trim(),
      service_id: document.getElementById("param-service-id").value.trim(),
      server: document.getElementById("param-server").value.trim(),
      affected_asset: document.getElementById("param-asset").value.trim(),
      case_name: document.getElementById("case-name-input").value.trim(),
      case_description: document.getElementById("case-desc-input").value.trim(),
      notes: editedNotes,
      selected_iocs: selectedIocs,
      custom_attributes: customAttrs
    },
    evidence_tokens: attachedEvidences.map(e => e.token),
    dry_run: isDryRun
  };

  try {
    const res = await fetch("/api/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reqPayload)
    });

    const data = await res.json();

    if (data.success) {
      if (isDryRun) {
        resultBanner.className = "result-banner dry-run";
        resultBanner.innerHTML = `
          <div>
            <strong>✓ Simulación Exitosa:</strong> Caso '${data.case_name}' validado con template '${data.template_applied}'.
          </div>
          <span style="font-family:var(--font-mono);font-size:0.8rem">Payload verificado (${selectedIocs.length} IOCs, ${editedNotes.length} Notas)</span>
        `;
      } else {
        resultBanner.className = "result-banner success";
        resultBanner.innerHTML = `
          <div>
            <strong>✓ Caso Creado en DFIR-IRIS (ID: ${data.case_id}):</strong> ${data.case_name}
          </div>
          <a href="${data.case_url}" target="_blank" class="result-link">Abrir en DFIR-IRIS ↗</a>
        `;
      }
      loadHistory();
      loadIrisCases(false);
    } else {
      resultBanner.className = "result-banner error";
      resultBanner.innerHTML = `<strong>✗ Error:</strong> ${data.error || "No se pudo crear el caso en IRIS"}`;
    }
  } catch (err) {
    resultBanner.className = "result-banner error";
    resultBanner.innerHTML = `<strong>✗ Error de red:</strong> ${err.message}`;
  } finally {
    btnDry.disabled = false;
    btnReal.disabled = false;
  }
}

// -------------------------------------------------------------
// 15. History Table (Session created cases)
// -------------------------------------------------------------
async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    const history = data.history || [];

    const tbody = document.getElementById("history-tbody");
    const countBadge = document.getElementById("history-count");
    countBadge.textContent = `${history.length} casos`;

    if (!history.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No se han creado casos en esta sesión aún.</td></tr>';
      return;
    }

    tbody.innerHTML = "";
    history.forEach(item => {
      const tr = document.createElement("tr");
      const modeBadge = item.dry_run 
        ? '<span style="color:var(--accent-amber);font-size:0.75rem;font-weight:600">DRY-RUN</span>' 
        : '<span style="color:var(--accent-green);font-size:0.75rem;font-weight:600">PROD</span>';

      tr.innerHTML = `
        <td><span style="font-weight:600;color:var(--accent-cyan)">${item.customer || 'Neubox'}</span></td>
        <td style="font-family:var(--font-mono)">${item.ticket_id || 'N/A'}</td>
        <td style="font-weight:600">${item.case_name}</td>
        <td><span style="font-family:var(--font-mono);font-size:0.8rem">${item.template}</span></td>
        <td>${modeBadge}</td>
        <td><a href="${item.case_url}" target="_blank">Caso #${item.case_id} ↗</a></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Error loading history", e);
  }
}

// -------------------------------------------------------------
// 16. DFIR-IRIS Live Cases Management Panel
// -------------------------------------------------------------
async function loadIrisCases(showSpinner = false) {
  const loading = document.getElementById("cases-loading");
  if (showSpinner && loading) loading.classList.remove("hidden");

  try {
    const res = await fetch(`/api/cases?state=${currentCasesFilterState}`);
    const data = await res.json();
    loadedIrisCases = data.cases || [];

    // Update open counter badge in navigation tab
    const openCases = loadedIrisCases.filter(c => !c.is_closed);
    const badge = document.getElementById("open-cases-badge");
    if (badge) badge.textContent = `${openCases.length}`;

    renderCasesTable(loadedIrisCases);
  } catch (err) {
    console.error("Error loading cases from IRIS", err);
  } finally {
    if (loading) loading.classList.add("hidden");
  }
}

function filterCasesState(state) {
  currentCasesFilterState = state;
  const btnOpen = document.getElementById("btn-filter-open");
  const btnAll = document.getElementById("btn-filter-all");

  if (state === "open") {
    btnOpen.classList.add("active");
    btnAll.classList.remove("active");
  } else {
    btnAll.classList.add("active");
    btnOpen.classList.remove("active");
  }

  loadIrisCases(true);
}

function filterCasesCustomer(cust) {
  currentCasesFilterCust = cust;
  document.querySelectorAll(".customer-filter-chips .btn-chip").forEach(c => c.classList.remove("active"));
  const activeChip = document.getElementById(`chip-cust-${cust === 'neubox' ? 'nbx' : cust === 'hospedando' ? 'hp' : 'all'}`);
  if (activeChip) activeChip.classList.add("active");

  onCasesSearch();
}

function onCasesSearch() {
  const query = (document.getElementById("cases-search-input").value || "").trim().toLowerCase();
  let filtered = [...loadedIrisCases];

  if (currentCasesFilterCust !== "all") {
    filtered = filtered.filter(c => 
      c.customer_name.toLowerCase().includes(currentCasesFilterCust) ||
      c.customer_code.toLowerCase().includes(currentCasesFilterCust)
    );
  }

  if (query) {
    filtered = filtered.filter(c => 
      String(c.case_id).includes(query) ||
      (c.case_name || "").toLowerCase().includes(query) ||
      (c.description || "").toLowerCase().includes(query) ||
      (c.soc_id || "").toLowerCase().includes(query)
    );
  }

  renderCasesTable(filtered);
}

function renderCasesTable(cases) {
  const tbody = document.getElementById("iris-cases-tbody");
  if (!tbody) return;

  if (!cases || !cases.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No se encontraron casos en DFIR-IRIS que coincidan con el filtro.</td></tr>';
    return;
  }

  tbody.innerHTML = "";
  cases.forEach(c => {
    const tr = document.createElement("tr");

    // State badge style
    let stateClass = "state-progress";
    if (c.is_closed || c.state_id === 9) stateClass = "state-closed";
    else if (c.state_id === 3) stateClass = "state-open";
    else if (c.state_id === 4 || c.state_id === 5) stateClass = "state-containment";

    // Customer code badge style
    const custColor = c.customer_code === "HP" ? "var(--accent-purple)" : "var(--accent-cyan)";

    tr.innerHTML = `
      <td style="font-family:var(--font-mono);font-weight:600">#${c.case_id}</td>
      <td>
        <span style="font-weight:700;color:${custColor}">${c.customer_code}</span>
        <span style="font-size:0.75rem;color:var(--text-dim);display:block">${c.customer_name}</span>
      </td>
      <td>
        <strong style="color:#fff;display:block;font-size:0.9rem">${c.case_name}</strong>
      </td>
      <td>
        <span class="state-badge ${stateClass}">${c.state_name || 'En curso'}</span>
      </td>
      <td style="font-size:0.8rem;color:var(--text-muted)">
        ${c.open_date || 'N/A'}
      </td>
      <td>
        <div class="btn-action-group">
          <a href="${c.case_url}" target="_blank" class="btn-action" title="Abrir caso en interfaz DFIR-IRIS">
            🌐 IRIS ↗
          </a>
          <button type="button" class="btn-action btn-action-report" onclick="openReportModal(${c.case_id})" title="Generar informe en Markdown y exportar a PDF">
            📄 Reporte
          </button>
          <button type="button" class="btn-action" onclick="openEditModal(${c.case_id})" title="Editar título, descripción o estado">
            ✏️ Editar
          </button>
          ${!c.is_closed ? `
            <button type="button" class="btn-action btn-action-close" onclick="closeCasePrompt(${c.case_id}, '${c.case_name.replace(/'/g, "\\'")}')" title="Cerrar caso">
              🔒 Cerrar
            </button>
          ` : ''}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// -------------------------------------------------------------
// 17. Close Case Prompt
// -------------------------------------------------------------
async function closeCasePrompt(caseId, caseName) {
  const ok = confirm(`¿Estás seguro de cerrar el Caso #${caseId} en DFIR-IRIS?\n\n"${caseName}"`);
  if (!ok) return;

  try {
    const res = await fetch(`/api/cases/${caseId}/close`, { method: "POST" });
    const data = await res.json();
    if (res.ok && data.success) {
      alert(`✓ Caso #${caseId} cerrado exitosamente.`);
      loadIrisCases(true);
    } else {
      alert(`Error al cerrar caso: ${data.detail || data.error}`);
    }
  } catch (err) {
    alert("Error de red cerrando caso: " + err.message);
  }
}

// -------------------------------------------------------------
// 18. Report Generator Modal & PDF Export
// -------------------------------------------------------------
async function openReportModal(caseId) {
  activeReportCaseId = caseId;
  const modal = document.getElementById("modal-report");
  const title = document.getElementById("modal-report-title");
  const paper = document.getElementById("report-rendered-paper");
  const editor = document.getElementById("report-markdown-editor");
  const statusHint = document.getElementById("report-modal-status");

  title.textContent = `Informe de Incidente — Caso #${caseId}`;
  paper.innerHTML = "<p><em>Cargando y renderizando reporte desde DFIR-IRIS...</em></p>";
  editor.value = "Cargando...";
  statusHint.textContent = "Obteniendo datos...";
  modal.classList.remove("hidden");

  // Default to Preview Tab
  switchReportTab("preview");

  try {
    const res = await fetch(`/api/cases/${caseId}/report`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Error generando reporte");
    }

    const data = await res.json();
    activeReportCaseData = data;

    title.textContent = `Informe de Incidente — Caso #${caseId} (${data.customer_name})`;
    document.getElementById("modal-report-subtitle").textContent = `Plantilla: ${data.template || 'Report_Template_Abuse_Lite.md'} | ${data.case_name}`;

    editor.value = data.markdown;
    paper.innerHTML = data.html || parseMarkdownSafe(data.markdown);
    statusHint.textContent = "Reporte renderizado listo para exportar a PDF";
  } catch (e) {
    paper.innerHTML = `<p style="color:#ef4444"><strong>Error:</strong> ${e.message}</p>`;
    statusHint.textContent = "Error al generar";
  }
}

function closeReportModal() {
  document.getElementById("modal-report").classList.add("hidden");
  const paper = document.getElementById("report-rendered-paper");
  if (paper) paper.innerHTML = "";
  activeReportCaseId = null;
  activeReportCaseData = null;
}

function switchReportTab(tab) {
  const btnPrev = document.getElementById("btn-report-view-preview");
  const btnEdit = document.getElementById("btn-report-view-edit");
  const panePrev = document.getElementById("report-pane-preview");
  const paneEdit = document.getElementById("report-pane-edit");

  if (tab === "edit") {
    btnEdit.classList.add("active");
    btnPrev.classList.remove("active");
    paneEdit.classList.add("active");
    panePrev.classList.remove("active");
  } else {
    btnPrev.classList.add("active");
    btnEdit.classList.remove("active");
    panePrev.classList.add("active");
    paneEdit.classList.remove("active");
  }
}

function onReportMarkdownEdit() {
  const editor = document.getElementById("report-markdown-editor");
  const paper = document.getElementById("report-rendered-paper");
  
  const custName = activeReportCaseData ? activeReportCaseData.customer_name : "Neubox";
  const custCode = activeReportCaseData ? activeReportCaseData.customer_code : "NBX";
  const badgeColor = custCode === "NBX" ? "#3b82f6" : "#8b5cf6";
  const badgeBg = custCode === "NBX" ? "#eff6ff" : "#f5f3ff";

  const renderedContent = parseMarkdownSafe(editor.value);
  paper.innerHTML = `
    <div class="report-banner" style="border-bottom: 2px solid ${badgeColor};">
      <div class="banner-title-group">
        <span class="org-badge" style="color: ${badgeColor}; background: ${badgeBg}; border: 1px solid ${badgeColor};">
          SOC ${custName.toUpperCase()} &bull; ${custCode}
        </span>
        <h1 class="banner-heading">DFIR-IRIS Abuse Incident Report</h1>
      </div>
      <div class="banner-meta">
        <div><strong>Marco Operativo:</strong> SOC Abuse Lite v2.0</div>
        <div><strong>Plataforma:</strong> DFIR-IRIS</div>
        <div><strong>Generado:</strong> Automatizado por SecOps</div>
      </div>
    </div>
    <div class="report-content">
      ${renderedContent}
    </div>
    <div class="report-footer">
      <span>Documento Confidencial &bull; Uso Exclusivo del Centro de Operaciones de Seguridad (SOC)</span>
      <span>SOC Neubox &bull; Hospedando</span>
    </div>
  `;
}

function copyReportMarkdown() {
  const editor = document.getElementById("report-markdown-editor");
  navigator.clipboard.writeText(editor.value).then(() => {
    alert("✓ Markdown del informe copiado al portapapeles.");
  }).catch(() => {
    editor.select();
    document.execCommand("copy");
    alert("✓ Markdown copiado.");
  });
}

function printReportDocument() {
  window.print();
}

async function downloadReportPdf() {
  if (!activeReportCaseId) return;

  const btnDownload = document.getElementById("btn-download-pdf");
  const statusHint = document.getElementById("report-modal-status");
  btnDownload.disabled = true;
  statusHint.textContent = "Compilando PDF con Google Chrome / motor de renderizado...";

  const editor = document.getElementById("report-markdown-editor");
  const editedMarkdown = editor.value;

  const custName = activeReportCaseData ? activeReportCaseData.customer_name : "Neubox";
  const custCode = activeReportCaseData ? activeReportCaseData.customer_code : "NBX";

  try {
    const res = await fetch("/api/report/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        markdown: editedMarkdown,
        title: `Informe de Incidente — Caso #${activeReportCaseId}`,
        customer_name: custName,
        customer_code: custCode
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Error al compilar PDF");
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Reporte_Incidente_Caso_${activeReportCaseId}_${custCode}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    statusHint.textContent = "✓ PDF descargado exitosamente";
  } catch (err) {
    alert("Error al descargar PDF: " + err.message);
    statusHint.textContent = "Error en la descarga";
  } finally {
    btnDownload.disabled = false;
  }
}

// -------------------------------------------------------------
// 18.1. Report Image Upload to IRIS Datastore & Paste Listener
// -------------------------------------------------------------
async function uploadReportImage(event) {
  const files = event.target.files;
  if (!files || !files.length) return;
  if (!activeReportCaseId) {
    alert("No hay un caso activo para adjuntar la evidencia.");
    return;
  }

  const btn = document.getElementById("btn-attach-report-img");
  const origText = btn ? btn.textContent : "🖼️ Adjuntar Imagen";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "⏳ Subiendo...";
  }

  const statusHint = document.getElementById("report-modal-status");

  for (const file of Array.from(files)) {
    if (statusHint) statusHint.textContent = `Subiendo ${file.name} al Datastore de IRIS...`;
    const formData = new FormData();
    formData.append("file", file);
    formData.append("description", `Captura adjunta al reporte (${file.name})`);

    try {
      const res = await fetch(`/api/cases/${activeReportCaseId}/upload-evidence`, {
        method: "POST",
        body: formData
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Error al subir evidencia a IRIS");
      }

      const data = await res.json();
      const editor = document.getElementById("report-markdown-editor");
      if (editor) {
        const snippet = data.markdown_snippet;
        const cursorPos = editor.selectionStart;
        if (cursorPos != null && cursorPos >= 0) {
          const before = editor.value.substring(0, cursorPos);
          const after = editor.value.substring(editor.selectionEnd);
          editor.value = before + snippet + after;
        } else {
          editor.value += snippet;
        }
        onReportMarkdownEdit();
      }

      if (statusHint) {
        statusHint.textContent = `✓ ${data.filename} guardada en Datastore IRIS (SHA-256: ${data.sha256.substring(0, 10)}...)`;
        statusHint.style.color = "#10b981";
      }
    } catch (err) {
      alert(`Error al subir ${file.name}: ` + err.message);
    }
  }

  if (btn) {
    btn.disabled = false;
    btn.textContent = origText;
  }
  event.target.value = "";
  setTimeout(() => {
    if (statusHint) {
      statusHint.style.color = "";
      statusHint.textContent = "Listo para exportar";
    }
  }, 4000);
}

function initReportEditorPasteListener() {
  const reportEditor = document.getElementById("report-markdown-editor");
  if (!reportEditor) return;

  reportEditor.addEventListener("paste", async (e) => {
    const items = (e.clipboardData || window.clipboardData).items;
    for (const item of items) {
      if (item.kind === "file" && item.type.startsWith("image/")) {
        e.preventDefault();
        const blob = item.getAsFile();
        if (blob && activeReportCaseId) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
          const ext = blob.type.split("/")[1] || "png";
          const file = new File([blob], `captura_evidencia_${timestamp}.${ext}`, { type: blob.type });
          const mockEvent = { target: { files: [file], value: "" } };
          await uploadReportImage(mockEvent);
        } else if (!activeReportCaseId) {
          alert("Abre un caso en el reporte antes de pegar imágenes.");
        }
        break;
      }
    }
  });
}

// -------------------------------------------------------------
// 18.2. Ticket Creation Evidence Attachments (Datastore)
// -------------------------------------------------------------
function handleTicketEvidenceUpload(event) {
  const files = event.target.files;
  if (!files || !files.length) return;
  uploadTicketEvidenceFiles(Array.from(files));
  event.target.value = "";
}

async function uploadTicketEvidenceFiles(files) {
  for (const file of files) {
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await fetch("/api/upload-evidence-temp", {
        method: "POST",
        body: formData
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Error subiendo evidencia temporal");
      }
      const data = await res.json();
      attachedEvidences.push(data);
      renderEvidencesList();
    } catch (err) {
      alert(`Error procesando ${file.name}: ` + err.message);
    }
  }
}

function removeEvidence(idx) {
  attachedEvidences.splice(idx, 1);
  renderEvidencesList();
}

function renderEvidencesList() {
  const grid = document.getElementById("evidences-grid");
  const countEl = document.getElementById("evidences-count");
  if (countEl) countEl.textContent = attachedEvidences.length;
  if (!grid) return;

  if (attachedEvidences.length === 0) {
    grid.innerHTML = "";
    return;
  }

  grid.innerHTML = attachedEvidences.map((ev, idx) => `
    <div class="evidence-card">
      <button type="button" class="evidence-card-delete" onclick="removeEvidence(${idx})" title="Eliminar evidencia">&times;</button>
      ${ev.is_image ? `<img src="${ev.data_uri}" class="evidence-card-thumb" alt="${ev.filename}">` : `<div class="evidence-card-placeholder">📄</div>`}
      <div class="evidence-card-meta">
        <div class="evidence-card-name" title="${ev.filename}">${ev.filename}</div>
        <div class="evidence-card-hash" title="SHA-256: ${ev.sha256}">SHA: ${ev.sha256.substring(0, 16)}...</div>
        <div style="font-size:0.7rem; color:#64748b; margin-top:3px;">${(ev.file_size / 1024).toFixed(1)} KB &bull; Datastore IRIS</div>
      </div>
    </div>
  `).join("");
}

function initEvidenceDropzone() {
  const dropzone = document.getElementById("evidences-dropzone");
  if (!dropzone) return;

  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("drag-over");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length) {
      uploadTicketEvidenceFiles(Array.from(files));
    }
  });
}

// -------------------------------------------------------------
// 19. Edit Case Modal
// -------------------------------------------------------------
async function openEditModal(caseId) {
  const modal = document.getElementById("modal-edit-case");
  const title = document.getElementById("modal-edit-title");
  const caseIdInput = document.getElementById("edit-case-id");
  const nameInput = document.getElementById("edit-case-name");
  const stateSelect = document.getElementById("edit-case-state");
  const descInput = document.getElementById("edit-case-desc");
  const descPreview = document.getElementById("edit-case-desc-preview");
  const toggleBtn = document.getElementById("btn-toggle-edit-desc");
  const notesContainer = document.getElementById("edit-case-notes-container");
  const iocsContainer = document.getElementById("edit-case-iocs-container");

  title.textContent = `Editar Caso #${caseId}`;
  caseIdInput.value = caseId;
  nameInput.value = "Cargando...";
  descInput.value = "Cargando...";
  descPreview.classList.add("hidden");
  descInput.classList.remove("hidden");
  toggleBtn.textContent = "👁️ Previsualizar";
  if (notesContainer) notesContainer.innerHTML = "<p style='color:var(--text-muted);font-size:0.84rem'>Cargando notas de DFIR-IRIS...</p>";
  if (iocsContainer) iocsContainer.innerHTML = "<p style='color:var(--text-muted);font-size:0.84rem'>Cargando IOCs...</p>";
  modal.classList.remove("hidden");

  try {
    const res = await fetch(`/api/cases/${caseId}`);
    if (!res.ok) throw new Error("No se pudo obtener información del caso");
    const data = await res.json();
    const c = data.case || {};

    nameInput.value = c.name || "";
    stateSelect.value = String(c.state_id || 2);
    descInput.value = c.description || "";

    // Render case notes
    if (notesContainer) {
      const notes = data.notes || [];
      if (notes.length === 0) {
        notesContainer.innerHTML = "<p style='color:var(--text-dim);font-size:0.82rem;font-style:italic'>No se encontraron notas en IRIS para este caso.</p>";
      } else {
        notesContainer.innerHTML = "";
        notes.forEach((n, idx) => {
          const card = document.createElement("div");
          card.className = "note-item";
          card.style.marginBottom = "8px";
          card.innerHTML = `
            <div class="note-header">
              <span style="font-weight:600">${escapeHtml(n.note_title)}</span>
              <div class="note-header-actions">
                <button type="button" class="btn-note-toggle" id="btn-edit-note-toggle-${idx}" onclick="toggleEditModalNote(${idx})">
                  👁️ Previsualizar
                </button>
              </div>
            </div>
            <textarea
              class="editable-note-textarea edit-modal-note-textarea"
              id="edit-modal-note-text-${idx}"
              data-note-id="${n.note_id || ''}"
              data-title="${escapeHtml(n.note_title)}"
              rows="6"
            ></textarea>
            <div class="rendered-note-view hidden" id="edit-modal-note-preview-${idx}"></div>
          `;
          const ta = card.querySelector("textarea");
          if (ta) ta.value = n.note_content || "";
          notesContainer.appendChild(card);
        });
      }
    }

    // Render case IOCs
    if (iocsContainer) {
      const iocs = data.iocs || [];
      if (iocs.length === 0) {
        iocsContainer.innerHTML = "<p style='color:var(--text-dim);font-size:0.82rem;font-style:italic'>No hay indicadores IOCs registrados para este caso.</p>";
      } else {
        iocsContainer.innerHTML = "";
        iocs.forEach(ioc => {
          const row = document.createElement("div");
          row.className = "ioc-row";
          const t = (ioc.ioc_type || "other").toLowerCase();
          const badgeClass = t.includes("domain") ? "domain" : (t.includes("ip") ? "ip" : (t.includes("url") ? "url" : (t.includes("mail") ? "email" : "other")));
          row.innerHTML = `
            <span class="ioc-badge ${badgeClass}">${escapeHtml((ioc.ioc_type || "IOC").toUpperCase())}</span>
            <span class="ioc-val">${escapeHtml(ioc.ioc_value)}</span>
            <span style="font-size:0.75rem;color:var(--text-dim)">${escapeHtml(ioc.tlp_name || 'TLP:AMBER')}</span>
          `;
          iocsContainer.appendChild(row);
        });
      }
    }
  } catch (err) {
    alert("Error cargando caso: " + err.message);
    closeEditModal();
  }
}

function closeEditModal() {
  document.getElementById("modal-edit-case").classList.add("hidden");
  document.getElementById("edit-modal-status").textContent = "";
}

function toggleEditModalDesc() {
  const descInput = document.getElementById("edit-case-desc");
  const descPreview = document.getElementById("edit-case-desc-preview");
  const toggleBtn = document.getElementById("btn-toggle-edit-desc");

  const isPreview = !descPreview.classList.contains("hidden");
  if (isPreview) {
    descPreview.classList.add("hidden");
    descInput.classList.remove("hidden");
    toggleBtn.textContent = "👁️ Previsualizar";
    descInput.focus();
  } else {
    descPreview.innerHTML = parseMarkdownSafe(descInput.value);
    descInput.classList.add("hidden");
    descPreview.classList.remove("hidden");
    toggleBtn.textContent = "✏️ Editar";
  }
}

function toggleEditModalNote(idx) {
  const textarea = document.getElementById(`edit-modal-note-text-${idx}`);
  const previewDiv = document.getElementById(`edit-modal-note-preview-${idx}`);
  const toggleBtn = document.getElementById(`btn-edit-note-toggle-${idx}`);

  if (!textarea || !previewDiv) return;
  const isPreview = !previewDiv.classList.contains("hidden");

  if (isPreview) {
    previewDiv.classList.add("hidden");
    textarea.classList.remove("hidden");
    toggleBtn.textContent = "👁️ Previsualizar";
    textarea.focus();
  } else {
    previewDiv.innerHTML = parseMarkdownSafe(textarea.value);
    textarea.classList.add("hidden");
    previewDiv.classList.remove("hidden");
    toggleBtn.textContent = "✏️ Editar";
  }
}

async function saveCaseEdits() {
  const caseId = document.getElementById("edit-case-id").value;
  const name = document.getElementById("edit-case-name").value.trim();
  const stateId = parseInt(document.getElementById("edit-case-state").value, 10);
  const desc = document.getElementById("edit-case-desc").value.trim();
  const statusElem = document.getElementById("edit-modal-status");
  const btnSave = document.getElementById("btn-save-case");

  // Gather edited notes
  const editedNotes = [];
  document.querySelectorAll(".edit-modal-note-textarea").forEach(ta => {
    editedNotes.push({
      note_id: ta.dataset.noteId ? parseInt(ta.dataset.noteId, 10) : null,
      title: ta.dataset.title,
      content: ta.value
    });
  });

  btnSave.disabled = true;
  statusElem.textContent = "Guardando en DFIR-IRIS...";

  try {
    const res = await fetch(`/api/cases/${caseId}/update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_name: name,
        case_description: desc,
        state_id: stateId,
        notes: editedNotes
      })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      statusElem.textContent = "✓ Guardado exitosamente";
      setTimeout(() => {
        closeEditModal();
        loadIrisCases(true);
      }, 700);
    } else {
      statusElem.textContent = `Error: ${data.detail || data.error}`;
    }
  } catch (err) {
    statusElem.textContent = `Error de red: ${err.message}`;
  } finally {
    btnSave.disabled = false;
  }
}
