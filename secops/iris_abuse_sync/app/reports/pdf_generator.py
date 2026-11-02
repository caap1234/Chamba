import base64
import html
import io
import logging
import os
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import markdown
from xhtml2pdf import pisa

logger = logging.getLogger("iris_abuse_sync.reports")

CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
    shutil.which("chromium-browser") or "",
]


def _find_chrome() -> Optional[str]:
    for p in CHROME_PATHS:
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return p
    return None


class FormalPdfReportGenerator:
    """Genera el Informe Técnico Formal y Ejecutivo en PDF a partir del expediente oficial de DFIR-IRIS,
    con renderizado visual de evidencias, bloques de terminal nítidos y formato institucional conciso."""

    @classmethod
    def _get_evidence_image_base64(cls, case_id: Any, ev: Dict[str, Any]) -> Optional[str]:
        fname = str(ev.get("filename") or "")
        is_img = any(fname.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"])
        if not is_img and not (str(ev.get("mime_type") or "").startswith("image/")):
            return None

        raw_bytes = None
        cid_str = str(case_id)
        # 1. Buscar en disco local storage/evidences/{cid}/{fname}
        local_path = Path(f"storage/evidences/{cid_str}/{fname}")
        if local_path.is_file():
            try:
                raw_bytes = local_path.read_bytes()
            except Exception:
                pass

        # 2. Buscar en subdirectorios de storage/evidences
        if not raw_bytes:
            for p in Path("storage/evidences").glob(f"**/{fname}"):
                if p.is_file():
                    try:
                        raw_bytes = p.read_bytes()
                        break
                    except Exception:
                        pass

        # 3. Descargar desde IRIS Datastore si existe ID numérico
        if not raw_bytes:
            fid = ev.get("id") or ev.get("file_id") or ev.get("iris_file_id")
            if fid and str(case_id).isdigit():
                try:
                    from app.iris.client import IrisApiClient
                    client = IrisApiClient()
                    raw_bytes = client.download_datastore_file(int(case_id), int(fid))
                except Exception:
                    pass

        if raw_bytes and len(raw_bytes) > 50:
            ext = fname.split(".")[-1].lower() if "." in fname else "png"
            mime = f"image/{'jpeg' if ext in ('jpg', 'jpeg') else ext}"
            b64 = base64.b64encode(raw_bytes).decode("ascii")
            return f"data:{mime};base64,{b64}"

        return None

    @classmethod
    def generate_case_pdf_bytes(cls, case_bundle: Dict[str, Any]) -> bytes:
        html_str = cls.render_case_report_html(case_bundle)
        chrome_bin = _find_chrome()

        # Intentar renderizado vectorial nítido con Chrome Headless si está disponible
        if chrome_bin:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".html", mode="w", encoding="utf-8", delete=False) as tf:
                    tf.write(html_str)
                    tf_path = Path(tf.name)
                out_pdf_path = tf_path.with_suffix(".pdf")
                cmd = [
                    chrome_bin,
                    "--headless",
                    "--disable-gpu",
                    "--no-sandbox",
                    f"--print-to-pdf={out_pdf_path}",
                    f"file://{tf_path.resolve()}",
                ]
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                if tf_path.exists():
                    tf_path.unlink()
                if res.returncode == 0 and out_pdf_path.exists() and out_pdf_path.stat().st_size > 1000:
                    pdf_data = out_pdf_path.read_bytes()
                    out_pdf_path.unlink()
                    return pdf_data
                if out_pdf_path.exists():
                    out_pdf_path.unlink()
            except Exception as exc:
                logger.warning("Fallo generación con Chrome headless, usando fallback xhtml2pdf: %s", exc)

        # Fallback confiable en Python puro: xhtml2pdf
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html_str, dest=pdf_buffer)
        if pisa_status.err:
            raise RuntimeError("Error generando el documento PDF del caso mediante xhtml2pdf.")
        return pdf_buffer.getvalue()

    @classmethod
    def render_case_report_html(cls, bundle: Dict[str, Any]) -> str:
        ext: Dict[str, Any] = bundle.get("extension") or {}
        iris: Dict[str, Any] = bundle.get("iris_case") or {}
        investigations: List[Dict[str, Any]] = bundle.get("investigations") or []
        findings: List[Dict[str, Any]] = bundle.get("findings") or []
        actions: List[Dict[str, Any]] = bundle.get("actions") or []
        communications: List[Dict[str, Any]] = bundle.get("communications") or []

        cid = ext.get("iris_case_id") or iris.get("case_id") or "S/N"
        org = (ext.get("organization") or "NBX").upper()
        is_hp = org == "HP"
        org_legal = "Hospedando S.A. de C.V." if is_hp else "NEUBOX Internet S.A. de C.V."
        brand_color = "#8b5cf6" if is_hp else "#2563eb"
        badge_bg = "#f5f3ff" if is_hp else "#eff6ff"
        badge_border = "#c4b5fd" if is_hp else "#bfdbfe"
        badge_text = "#6d28d9" if is_hp else "#1d4ed8"

        cname = html.escape(str(iris.get("case_name") or f"Caso #{cid}"))
        state_name = html.escape(str(iris.get("state_name") or "Open"))
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        res_data = ext.get("resolution_data_json") or {}
        reported_info = html.escape(
            str(
                res_data.get("reported_information")
                or (ext.get("initial_report_json") or {}).get("summary")
                or iris.get("case_description")
                or "Reporte recibido en Helpdesk."
            )
        )

        evidences = iris.get("evidences") or []
        notes = iris.get("notes") or []

        def _esc(val: Any, default: str = "No especificado") -> str:
            if val is None or str(val).strip() == "" or str(val).strip().lower() == "none":
                return default
            return html.escape(str(val))

        # 1. Investigaciones y Hallazgos
        inv_rows = ""
        if investigations:
            for idx, inv in enumerate(investigations, 1):
                inv_rows += (
                    f"<tr>"
                    f"<td style='width: 30px; text-align: center;'>{idx}</td>"
                    f"<td style='width: 140px;'><b>{_esc(inv.get('source_consulted'))}</b><br/><span class='muted'>{_esc(inv.get('fact_type'), 'Hecho')}</span></td>"
                    f"<td><code>{_esc(inv.get('commands_or_queries'), 'Consulta manual / Bastion')}</code></td>"
                    f"<td>{_esc(inv.get('results_observed'))}</td>"
                    f"</tr>"
                )
        elif findings:
            for idx, f in enumerate(findings, 1):
                inv_rows += (
                    f"<tr>"
                    f"<td style='width: 30px; text-align: center;'>{idx}</td>"
                    f"<td style='width: 140px;'><b>{_esc(f.get('title'))}</b><br/><span class='muted'>{_esc(f.get('finding_nature'))}</span></td>"
                    f"<td><code>{_esc(f.get('verification_state'))}</code></td>"
                    f"<td>{_esc(f.get('description'))}</td>"
                    f"</tr>"
                )
        else:
            inv_rows = "<tr><td colspan='4'>Revisión técnica inicial documentada en el reporte de abuso y notas internas.</td></tr>"

        # 2. Acciones y Medidas de Contención
        act_rows = ""
        if actions:
            for a in actions:
                st = str(a.get("status") or "propuesta").lower()
                st_color = "#10b981" if st in ("ejecutada", "verificada") else ("#f59e0b" if st in ("pendiente", "en_ejecucion") else "#64748b")
                act_rows += (
                    f"<tr>"
                    f"<td><b>{_esc(a.get('title'))}</b></td>"
                    f"<td><code>{_esc(a.get('action_type'))}</code></td>"
                    f"<td><span style='color: {st_color}; font-weight: bold;'>{_esc(a.get('status')).upper()}</span></td>"
                    f"<td>{_esc(a.get('responsible'), 'Analista SOC')}</td>"
                    f"<td>{_esc(a.get('result_notes'), '—')}</td>"
                    f"</tr>"
                )
        else:
            act_rows = "<tr><td colspan='5'>Sin acciones registradas.</td></tr>"

        # 3. Evidencias: Tabla + Vistas Previas de Capturas
        ev_rows = ""
        ev_previews_html = ""
        if evidences:
            for ev in evidences:
                fname = _esc(ev.get("filename"))
                fsize = _esc(ev.get("file_size"), "0")
                fhash = _esc(ev.get("file_hash") or ev.get("sha256"), "Datastore IRIS")
                fdesc = _esc(ev.get("file_description"), "Evidencia preservada")
                fid = _esc(ev.get("id") or ev.get("file_id"), "-")

                ev_rows += (
                    f"<tr>"
                    f"<td><b>{fname}</b></td>"
                    f"<td>#{fid}</td>"
                    f"<td>{fsize} B</td>"
                    f"<td><code>{fhash}</code></td>"
                    f"<td>{fdesc}</td>"
                    f"</tr>"
                )

                # Cargar imagen en base64 para vista previa visual
                img_data_uri = cls._get_evidence_image_base64(cid, ev)
                if img_data_uri:
                    ev_previews_html += (
                        f"<div class='evidence-card'>"
                        f"<div class='evidence-header'>"
                        f"<b>Captura Forense:</b> {fname} &bull; "
                        f"<span class='muted'>Tamaño: {fsize} bytes &bull; SHA-256: <code>{fhash}</code></span>"
                        f"</div>"
                        f"<div style='text-align: center; padding: 6px 0;'>"
                        f"<img src='{img_data_uri}' style='max-width: 95%; max-height: 270px; border-radius: 4px; border: 1px solid #cbd5e1; box-shadow: 0 1px 3px rgba(0,0,0,0.1);' />"
                        f"</div>"
                        f"{f'<div class=\"muted\" style=\"text-align: center; font-style: italic;\">{fdesc}</div>' if fdesc != fname else ''}"
                        f"</div>"
                    )
        else:
            ev_rows = "<tr><td colspan='5'>Evidencia preservada en paquete forense y ticket original.</td></tr>"

        # 4. Comunicaciones (si aplican)
        comm_section_html = ""
        if communications:
            comm_rows = ""
            for cm in communications:
                comm_rows += (
                    f"<tr>"
                    f"<td>{_esc(cm.get('channel'))} ({_esc(cm.get('direction'))})</td>"
                    f"<td>{_esc(cm.get('recipient'))}</td>"
                    f"<td>#{_esc(cm.get('ticket_reference'), '—')}</td>"
                    f"<td>{_esc(cm.get('summary'))}</td>"
                    f"</tr>"
                )
            comm_section_html = f"""
            <h2>5. Comunicaciones y Notificaciones</h2>
            <table>
              <thead><tr><th>Canal</th><th>Destinatario</th><th>Ticket / Ref</th><th>Resumen</th></tr></thead>
              <tbody>{comm_rows}</tbody>
            </table>
            """

        # 5. Notas oficiales renderizadas con Markdown
        notes_html = ""
        for n in notes:
            raw_c = n.get("note_content") or ""
            rendered = markdown.markdown(raw_c, extensions=["extra", "tables", "fenced_code"])
            notes_html += (
                f"<div class='note-card'>"
                f"<div class='note-title'>Nota DFIR-IRIS #{_esc(n.get('note_id'))}: {_esc(n.get('note_title'))}</div>"
                f"<div class='note-body'>{rendered}</div>"
                f"</div>"
            )

        is_compromised = ext.get("is_technical_compromise")
        compromise_label = (
            "<span style='color: #dc2626; font-weight: bold;'>SÍ — Compromiso técnico verificado</span>"
            if is_compromised
            else "<span style='color: #059669; font-weight: bold;'>NO — Sin intrusión técnica confirmada</span>"
        )

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8" />
<title>Informe SOC Caso #{cid}</title>
<style>
  @page {{
    size: letter portrait;
    margin: 14mm 13mm 14mm 13mm;
    @bottom-center {{
      content: "SOC {org} &bull; Informe Técnico de Incidentes &bull; Confidencial TLP:AMBER";
      font-size: 7.5pt;
      color: #94a3b8;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 8.5pt;
    line-height: 1.45;
    color: #1e293b;
    background: #ffffff;
    margin: 0;
    padding: 0;
  }}
  .header-banner {{
    border-bottom: 2.5px solid {brand_color};
    padding-bottom: 8px;
    margin-bottom: 14px;
  }}
  .badge-org {{
    display: inline-block;
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 4px;
    background: {badge_bg};
    border: 1px solid {badge_border};
    color: {badge_text};
    margin-bottom: 4px;
  }}
  .banner-title {{
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    margin: 0 0 3px 0;
  }}
  .banner-meta {{
    font-size: 8pt;
    color: #64748b;
  }}
  h2 {{
    font-size: 10pt;
    font-weight: 700;
    color: #0f172a;
    background: #f1f5f9;
    border-left: 4px solid {brand_color};
    padding: 5px 8px;
    margin-top: 16px;
    margin-bottom: 8px;
    border-radius: 0 4px 4px 0;
    page-break-after: avoid;
  }}
  table {{
    width: 100%;
    margin-top: 4px;
    margin-bottom: 12px;
    border-collapse: collapse;
  }}
  th, td {{
    border: 1px solid #cbd5e1;
    padding: 5px 7px;
    font-size: 8pt;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background: #e2e8f0;
    color: #0f172a;
    font-weight: 700;
  }}
  .kv-label {{
    width: 25%;
    background: #f8fafc;
    font-weight: 600;
    color: #334155;
  }}
  pre, code {{
    font-family: "Courier New", Courier, monospace !important;
  }}
  .note-body pre, pre, .code-block {{
    background: #090d16 !important;
    color: #38bdf8 !important;
    border: 1px solid #1e293b !important;
    border-radius: 6px !important;
    padding: 8px 12px !important;
    font-size: 7.5pt !important;
    line-height: 1.35 !important;
    white-space: pre-wrap !important;
    word-break: break-all !important;
    margin: 6px 0 !important;
  }}
  .note-body pre code, pre code {{
    background: transparent !important;
    color: #38bdf8 !important;
    border: none !important;
    padding: 0 !important;
  }}
  .note-body code {{
    background: #e2e8f0 !important;
    color: #0369a1 !important;
    padding: 1px 4px !important;
    border-radius: 3px !important;
    font-size: 8pt !important;
  }}
  .evidence-card {{
    border: 1px solid #cbd5e1;
    background: #f8fafc;
    padding: 8px 12px;
    margin-top: 6px;
    margin-bottom: 10px;
    border-radius: 6px;
    page-break-inside: avoid;
  }}
  .evidence-header {{
    font-size: 8pt;
    color: #0f172a;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 3px;
    margin-bottom: 5px;
  }}
  .note-card {{
    border: 1px solid #cbd5e1;
    background: #f8fafc;
    padding: 8px 12px;
    margin-top: 6px;
    margin-bottom: 12px;
    border-radius: 6px;
    page-break-inside: avoid;
  }}
  .note-title {{
    font-weight: 700;
    font-size: 9pt;
    color: #0f172a;
    margin-bottom: 6px;
    padding-bottom: 3px;
    border-bottom: 1.5px solid #e2e8f0;
  }}
  .note-body {{
    font-size: 8pt;
    line-height: 1.45;
    color: #334155;
  }}
  .note-body h1, .note-body h2, .note-body h3, .note-body h4 {{
    font-weight: 700;
    color: #0f172a;
    margin: 8px 0 3px 0;
  }}
  .note-body h1 {{ font-size: 10pt; border-bottom: 1px solid #cbd5e1; padding-bottom: 2px; }}
  .note-body h2 {{ font-size: 9.5pt; background: transparent; border-left: none; padding: 0; }}
  .note-body h3 {{ font-size: 8.5pt; }}
  .note-body p {{ margin: 4px 0; }}
  .note-body ul, .note-body ol {{ margin: 4px 0; padding-left: 18px; }}
  .note-body li {{ margin-bottom: 2px; }}
  .note-body table {{
    width: 100%;
    border-collapse: collapse;
    margin: 6px 0 10px 0;
  }}
  .note-body th, .note-body td {{
    border: 1px solid #cbd5e1;
    padding: 4px 6px;
    font-size: 7.5pt;
  }}
  .note-body th {{
    background: #e2e8f0;
    color: #0f172a;
    font-weight: 700;
  }}
  .note-body blockquote {{
    border-left: 3px solid {brand_color};
    padding: 3px 8px;
    margin: 6px 0;
    background: #f1f5f9;
    color: #475569;
    font-style: italic;
    border-radius: 0 4px 4px 0;
  }}
  table, tr, td, th, .note-card, .evidence-card {{
    page-break-inside: avoid;
  }}
  .muted {{ color: #64748b; font-size: 7.5pt; }}
  .badge {{ background: #e2e8f0; padding: 2px 5px; border-radius: 3px; font-weight: 600; font-size: 7.5pt; }}
</style>
</head>
<body>

<div class="header-banner">
  <span class="badge-org">SOC {org} &bull; {org_legal}</span>
  <h1 class="banner-title">INFORME TÉCNICO FORMAL &bull; CASO #{cid}</h1>
  <div class="banner-meta">
    <b>Título Oficial en DFIR-IRIS:</b> {cname} &bull;
    <b>Estado:</b> {state_name} &bull;
    <b>Generado:</b> {now_str} &bull;
    <b>Clasificación:</b> TLP:AMBER (Confidencial SOC)
  </div>
</div>

<h2>1. Resumen Ejecutivo y Alegación Inicial</h2>
<p style="margin: 4px 0;"><b>Alegación Recibida:</b> {reported_info}</p>

<h2>2. Identificación del Activo, Red y Taxonomía SOC</h2>
<table>
  <tr><td class="kv-label">Dominio / Activo Primario</td><td><b style="color: {brand_color}; font-size: 9pt;">{_esc(ext.get('primary_domain'))}</b></td><td class="kv-label">Servidor Afectado</td><td><b>{_esc(ext.get('server_name'))}</b></td></tr>
  <tr><td class="kv-label">IP de Hosting (Alojamiento)</td><td>{_esc(ext.get('hosting_ip'))}</td><td class="kv-label">IP Reportada en Denuncia</td><td>{_esc(ext.get('reported_ip'))}</td></tr>
  <tr><td class="kv-label">Ticket de Abuso (Helpdesk)</td><td><b>#{_esc(ext.get('abuse_ticket_id'))}</b></td><td class="kv-label">Ticket Titular (cPanel/Client)</td><td>#{_esc(ext.get('holder_ticket_id'), 'No vinculado')}</td></tr>
  <tr><td class="kv-label">ID de Cliente / Servicio WHMCS</td><td>Cliente #{_esc(ext.get('client_id'), 'S/N')} / Serv #{_esc(ext.get('service_id'), 'S/N')}</td><td class="kv-label">Marca Suplantada</td><td>{_esc(ext.get('impersonated_brand'), 'No aplica')}</td></tr>
  <tr><td class="kv-label">Categoría SOC / Taxonomía</td><td><b>{_esc(ext.get('category_code'))}</b></td><td class="kv-label">Incidente Confirmado</td><td><b>{_esc(ext.get('confirmed_incident_type'))}</b></td></tr>
  <tr><td class="kv-label">Evaluación de Compromiso Técnico</td><td colspan="3">{compromise_label}</td></tr>
</table>

<h2>3. Investigaciones Forenses y Hechos Confirmados</h2>
<table>
  <thead><tr><th>#</th><th>Fuente / Origen</th><th>Comando / Consulta</th><th>Resultado Observado</th></tr></thead>
  <tbody>{inv_rows}</tbody>
</table>

<h2>4. Medidas de Contención y Acciones Operativas</h2>
<table>
  <thead><tr><th>Acción</th><th>Tipo</th><th>Estado</th><th>Responsable</th><th>Resultado / Motivo</th></tr></thead>
  <tbody>{act_rows}</tbody>
</table>

<h2>5. Evidencias Forenses en Datastore</h2>
<table>
  <thead><tr><th>Archivo</th><th>ID Datastore</th><th>Tamaño</th><th>Hash SHA-256</th><th>Descripción</th></tr></thead>
  <tbody>{ev_rows}</tbody>
</table>

{ev_previews_html}

{comm_section_html}

<h2>6. Ficha Técnica Oficial Integrada (DFIR-IRIS)</h2>
{notes_html}

</body>
</html>"""
