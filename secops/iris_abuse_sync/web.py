import os
import io
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests

import config
from parser import TicketParser, extract_text_from_pdf
from classifier import TemplateClassifier
from case_builder import CaseBuilder
from iris_client import IrisClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("iris_abuse_sync.web")

app = FastAPI(
    title="DFIR-IRIS Abuse Sync API",
    description="Automatización de creación de casos DFIR-IRIS desde tickets de abuso",
    version="2.1.0"
)

STATIC_DIR = config.BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path in ("/", "/index.html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

recent_history: List[Dict[str, Any]] = []


class CaseOverrides(BaseModel):
    customer_key: Optional[str] = "neubox"
    report_ticket: Optional[str] = ""
    client_ticket: Optional[str] = ""
    client_id: Optional[str] = ""
    service_id: Optional[str] = ""
    server: Optional[str] = ""
    affected_asset: Optional[str] = ""
    case_name: Optional[str] = None
    case_description: Optional[str] = None
    notes: Optional[List[Dict[str, str]]] = None
    selected_iocs: Optional[List[Dict[str, Any]]] = None
    custom_attributes: Optional[Dict[str, Any]] = None


class CreateCaseRequest(BaseModel):
    parsed_data: Dict[str, Any]
    template_name: str
    overrides: Optional[CaseOverrides] = None
    dry_run: bool = False
    evidence_tokens: Optional[List[str]] = None


class RecalculateRequest(BaseModel):
    parsed_data: Dict[str, Any]
    template_name: str
    overrides: CaseOverrides


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Web UI no inicializada</h1>", status_code=404)
    return FileResponse(index_file)


@app.get("/api/status")
async def get_system_status():
    client = IrisClient()
    conn = client.test_connection()
    tmpl_res = client.get_templates() if conn.get("success") else {"success": False, "templates": {}}
    clf = TemplateClassifier()

    return {
        "status": "online",
        "iris_url": config.IRIS_URL,
        "customers": config.CUSTOMERS,
        "default_customer": config.DEFAULT_CUSTOMER,
        "ssl_verify": config.IRIS_VERIFY_SSL,
        "iris_connected": conn.get("success", False),
        "iris_error": conn.get("error"),
        "remote_templates": tmpl_res.get("templates", {}),
        "local_templates_count": len(clf.templates),
        "llm_provider": config.LLM_PROVIDER,
        "llm_model": config.LLM_MODEL
    }


@app.get("/api/ollama/models")
async def list_ollama_models():
    """Lists locally installed Ollama models."""
    try:
        r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m.get("name") for m in r.json().get("models", [])]
            return {"available": True, "models": models, "current": config.LLM_MODEL}
    except Exception as e:
        logger.debug(f"Ollama not reachable: {e}")
    return {"available": False, "models": [], "current": config.LLM_MODEL}


@app.get("/api/templates")
async def list_available_templates():
    clf = TemplateClassifier()
    templates = []
    for name, data in clf.templates.items():
        templates.append({
            "name": name,
            "prefix": data.get("title_prefix", ""),
            "display_name": data.get("display_name", name),
            "description": data.get("description", ""),
            "tags": data.get("tags", [])
        })
    return {"templates": templates}


@app.get("/api/sample/{sample_name}")
async def get_sample_ticket(sample_name: str):
    sample_file = config.BASE_DIR / "tests" / "sample_ocr" / sample_name
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="Muestra no encontrada")
    raw_text = sample_file.read_text(encoding="utf-8", errors="ignore")
    parser = TicketParser(raw_text)
    parsed = parser.parse()
    clf = TemplateClassifier()
    classification = clf.classify(parsed)
    preview_payload = CaseBuilder.build(parsed, classification)
    return {
        "success": True,
        "filename": sample_name,
        "parsed": parsed,
        "classification": classification,
        "preview_payload": preview_payload
    }


@app.post("/api/parse")
async def parse_uploaded_ticket(file: UploadFile = File(...)):
    filename = file.filename or "ticket.pdf"
    content = await file.read()

    try:
        if filename.lower().endswith(".pdf"):
            raw_text = extract_text_from_pdf(content)
        else:
            raw_text = content.decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error leyendo archivo: {e}")

    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="El archivo no contiene texto legible.")

    temp_path = config.BASE_DIR / "scratch" / f"temp_{filename}"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_bytes(content)

    parser = TicketParser(raw_text)
    parsed = parser.parse()

    clf = TemplateClassifier()
    classification = clf.classify(parsed)

    preview_payload = CaseBuilder.build(parsed, classification)

    return {
        "success": True,
        "filename": filename,
        "temp_token": temp_path.name,
        "parsed": parsed,
        "classification": classification,
        "preview_payload": preview_payload
    }


@app.post("/api/recalculate")
async def recalculate_case_preview(req: RecalculateRequest):
    clf = TemplateClassifier()
    template_obj = clf.templates.get(req.template_name, {})
    prefix = template_obj.get("title_prefix", "[ABUSE]")
    disp = template_obj.get("display_name", req.template_name)

    classification = {
        "template_name": req.template_name,
        "title_prefix": prefix,
        "display_name": disp,
        "template_data": template_obj,
        "confidence": 1.0,
        "reasons": ["Ajustado en panel Web"]
    }

    overrides_dict = req.overrides.dict()
    recalculated = CaseBuilder.build(
        req.parsed_data,
        classification,
        customer_key=req.overrides.customer_key,
        overrides=overrides_dict
    )
    return {"success": True, "preview_payload": recalculated}


@app.post("/api/upload-evidence-temp")
async def upload_temp_evidence(file: UploadFile = File(...)):
    """
    Uploads a temporary evidence screenshot during ticket creation before case ID exists.
    Saves in scratch/evidences and returns token and base64 data uri for live preview.
    """
    import uuid
    import base64
    import hashlib
    import mimetypes

    filename = file.filename or "evidence.png"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="El archivo está vacío.")

    sha256_hash = hashlib.sha256(content).hexdigest().upper()
    mime_type, _ = mimetypes.guess_type(filename)
    mime_type = mime_type or "image/png"

    token = f"{uuid.uuid4().hex[:8]}_{filename}"
    save_dir = config.BASE_DIR / "scratch" / "evidences"
    save_dir.mkdir(parents=True, exist_ok=True)
    file_path = save_dir / token
    file_path.write_bytes(content)

    is_image = mime_type.startswith("image/")
    data_uri = ""
    if is_image:
        b64_str = base64.b64encode(content).decode("utf-8")
        data_uri = f"data:{mime_type};base64,{b64_str}"

    return {
        "success": True,
        "token": token,
        "filename": filename,
        "file_size": len(content),
        "sha256": sha256_hash,
        "is_image": is_image,
        "data_uri": data_uri
    }


@app.post("/api/create")
async def create_case_from_web(req: CreateCaseRequest):
    clf = TemplateClassifier()
    template_obj = clf.templates.get(req.template_name, {})
    prefix = template_obj.get("title_prefix", "[ABUSE]")
    disp = template_obj.get("display_name", req.template_name)

    classification = {
        "template_name": req.template_name,
        "title_prefix": prefix,
        "display_name": disp,
        "template_data": template_obj,
        "confidence": 1.0,
        "reasons": ["Aprobado en panel Web"]
    }

    overrides_dict = req.overrides.dict() if req.overrides else {}
    customer_key = overrides_dict.get("customer_key") or "neubox"

    payload = CaseBuilder.build(
        req.parsed_data,
        classification,
        customer_key=customer_key,
        overrides=overrides_dict
    )

    temp_name = req.parsed_data.get("temp_token")
    temp_path = config.BASE_DIR / "scratch" / temp_name if temp_name else None

    client = IrisClient()
    res = client.create_case(payload, pdf_path=temp_path, dry_run=req.dry_run)

    if res.get("success"):
        new_case_id = res.get("case_id")
        # Upload any user-attached evidence screenshots to the datastore
        if req.evidence_tokens and new_case_id and not req.dry_run:
            for tok in req.evidence_tokens:
                ev_file = config.BASE_DIR / "scratch" / "evidences" / tok
                if ev_file.is_file():
                    orig_name = tok.split("_", 1)[-1] if "_" in tok else tok
                    client.upload_datastore_file(
                        case_id=new_case_id,
                        file_data=ev_file,
                        filename=orig_name,
                        description="Evidencia gráfica adjunta al ticket",
                        is_evidence=True
                    )

        record = {
            "ticket_id": overrides_dict.get("report_ticket") or req.parsed_data.get("ticket_id"),
            "case_id": new_case_id,
            "case_name": res.get("case_name"),
            "customer": payload.get("customer_name"),
            "template": req.template_name,
            "case_url": res.get("case_url"),
            "dry_run": req.dry_run
        }
        recent_history.insert(0, record)
        if len(recent_history) > 20:
            recent_history.pop()

    return res


@app.get("/api/history")
async def get_recent_history():
    return {"history": recent_history}


class UpdateCaseRequest(BaseModel):
    case_name: Optional[str] = None
    case_description: Optional[str] = None
    state_id: Optional[int] = None
    case_soc_id: Optional[str] = None
    notes: Optional[List[Dict[str, Any]]] = None


class ExportPdfRequest(BaseModel):
    markdown: str
    title: Optional[str] = "Informe de Incidente — SOC / Abuse"
    customer_name: Optional[str] = "Neubox"
    customer_code: Optional[str] = "NBX"


@app.get("/api/cases")
async def list_cases(state: str = "open", customer: Optional[str] = None):
    """
    Lists cases from DFIR-IRIS.
    state: 'open' (default, excludes closed) or 'all'
    customer: optional filter ('neubox' or 'hospedando')
    """
    client = IrisClient()
    res = client.list_cases(filter_state=state)
    if not res.get("success"):
        return JSONResponse(status_code=500, content=res)

    cases = res.get("cases", [])
    if customer:
        cust_norm = customer.lower()
        cases = [c for c in cases if cust_norm in c.get("customer_name", "").lower() or cust_norm in c.get("customer_code", "").lower()]

    return {"success": True, "cases": cases, "total": len(cases)}


@app.get("/api/cases/{case_id}")
async def get_case_details(case_id: int):
    """Fetches full case details including evidences and IOCs."""
    client = IrisClient()
    res = client.get_case(case_id)
    if not res.get("success"):
        raise HTTPException(status_code=404, detail=res.get("error"))
    return res


@app.post("/api/cases/{case_id}/close")
async def close_case_endpoint(case_id: int):
    """Closes a case in DFIR-IRIS."""
    client = IrisClient()
    res = client.close_case(case_id)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.post("/api/cases/{case_id}/update")
async def update_case_endpoint(case_id: int, req: UpdateCaseRequest):
    """Updates case details in DFIR-IRIS."""
    client = IrisClient()
    updates = req.dict(exclude_unset=True)
    res = client.update_case(case_id, updates)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.get("/api/cases/{case_id}/report")
async def get_case_report(case_id: int, template: str = "Report_Template_Abuse_Lite.md"):
    """
    Generates a Markdown report and interpreted inner HTML for the case using the requested template.
    """
    from report_generator import render_report_body_html

    client = IrisClient()
    rep_res = client.generate_case_report(case_id, template_filename=template)
    if not rep_res.get("success"):
        raise HTTPException(status_code=400, detail=rep_res.get("error"))

    case_data = rep_res["case"]
    cust_name = case_data.get("customer_name", "Neubox")
    cust_code = case_data.get("customer_code", "NBX")

    html_rendered = render_report_body_html(
        md_content=rep_res["markdown"],
        customer_name=cust_name,
        customer_code=cust_code
    )

    return {
        "success": True,
        "case_id": case_id,
        "case_name": case_data.get("name"),
        "customer_name": cust_name,
        "customer_code": cust_code,
        "markdown": rep_res["markdown"],
        "html": html_rendered,
        "template": rep_res.get("template")
    }


@app.get("/api/cases/{case_id}/report/pdf")
async def download_case_report_pdf(case_id: int, template: str = "Report_Template_Abuse_Lite.md"):
    """
    Generates and downloads an executive PDF report for the case.
    """
    from report_generator import generate_pdf_from_markdown

    client = IrisClient()
    rep_res = client.generate_case_report(case_id, template_filename=template)
    if not rep_res.get("success"):
        raise HTTPException(status_code=400, detail=rep_res.get("error"))

    case_data = rep_res["case"]
    cust_name = case_data.get("customer_name", "Neubox")
    cust_code = case_data.get("customer_code", "NBX")

    pdf_filename = f"Reporte_Incidente_Caso_{case_id}_{cust_code}.pdf"
    pdf_path = config.BASE_DIR / "scratch" / pdf_filename

    ok = generate_pdf_from_markdown(
        md_content=rep_res["markdown"],
        output_path=pdf_path,
        title=f"Informe de Incidente — {case_data.get('name')}",
        customer_name=cust_name,
        customer_code=cust_code
    )

    if not ok or not pdf_path.exists():
        raise HTTPException(status_code=500, detail="Error al generar el archivo PDF del reporte.")

    return FileResponse(
        path=pdf_path,
        filename=pdf_filename,
        media_type="application/pdf"
    )


@app.post("/api/cases/{case_id}/upload-evidence")
async def upload_case_evidence_image(
    case_id: int,
    file: UploadFile = File(...),
    description: str = Form("")
):
    """
    Uploads an image or document as evidence directly into the DFIR-IRIS Datastore,
    associating it with the case and returning the Base64 Data URI and formatted Markdown
    snippet for immediate insertion into the report editor.
    """
    import base64
    import hashlib
    import mimetypes

    filename = file.filename or "evidence.png"
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="El archivo está vacío.")

    sha256_hash = hashlib.sha256(content).hexdigest().upper()
    mime_type, _ = mimetypes.guess_type(filename)
    mime_type = mime_type or "image/png"

    # Upload directly to DFIR-IRIS Datastore
    client = IrisClient()
    res = client.upload_datastore_file(
        case_id=case_id,
        file_data=content,
        filename=filename,
        description=description or f"Captura adjunta al reporte ({filename})",
        is_evidence=True
    )

    # Encode to Base64 data URI if image
    is_image = mime_type.startswith("image/")
    if is_image:
        b64_str = base64.b64encode(content).decode("utf-8")
        data_uri = f"data:{mime_type};base64,{b64_str}"
        snippet = f"\n\n### Evidencia Gráfica: {filename}\n![{filename}]({data_uri})\n*Archivo: `{filename}` | SHA-256: `{sha256_hash}` | Registrado en Datastore IRIS*\n"
    else:
        data_uri = ""
        snippet = f"\n\n- **Evidencia Adjunta:** `{filename}` | SHA-256: `{sha256_hash}`\n"

    return {
        "success": res.get("success", True),
        "filename": filename,
        "sha256": sha256_hash,
        "file_size": len(content),
        "mime_type": mime_type,
        "is_image": is_image,
        "data_uri": data_uri,
        "markdown_snippet": snippet,
        "iris_res": res
    }


@app.post("/api/report/export-pdf")
async def export_custom_markdown_pdf(req: ExportPdfRequest):
    """
    Exports arbitrary or edited Markdown into an executive PDF.
    """
    from report_generator import generate_pdf_from_markdown

    pdf_filename = f"Reporte_Incidente_SOC_{req.customer_code}.pdf"
    pdf_path = config.BASE_DIR / "scratch" / pdf_filename

    ok = generate_pdf_from_markdown(
        md_content=req.markdown,
        output_path=pdf_path,
        title=req.title or "Informe de Incidente — SOC / Abuse",
        customer_name=req.customer_name or "Neubox",
        customer_code=req.customer_code or "NBX"
    )

    if not ok or not pdf_path.exists():
        raise HTTPException(status_code=500, detail="Error al compilar el reporte en PDF.")

    return FileResponse(
        path=pdf_path,
        filename=pdf_filename,
        media_type="application/pdf"
    )


@app.post("/api/report/preview-html")
async def preview_custom_markdown_html(req: ExportPdfRequest):
    """Renders custom Markdown to executive inner HTML."""
    from report_generator import render_report_body_html
    html = render_report_body_html(
        md_content=req.markdown,
        customer_name=req.customer_name or "Neubox",
        customer_code=req.customer_code or "NBX"
    )
    return {"success": True, "html": html}


def run_server():
    import uvicorn
    uvicorn.run("web:app", host=config.WEB_HOST, port=config.WEB_PORT, reload=False)


if __name__ == "__main__":
    run_server()
