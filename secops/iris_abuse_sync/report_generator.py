"""
Report Generator & PDF Converter for DFIR-IRIS Abuse Sync.
Converts Markdown incident reports into executive, beautifully-formatted PDFs.
Supports both Google Chrome headless (vector quality) and xhtml2pdf (pure Python fallback).
"""

import os
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any
import markdown
import xhtml2pdf.pisa as pisa

import config

logger = logging.getLogger("iris_abuse_sync.report_generator")

CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
    shutil.which("chromium-browser") or ""
]


def find_chrome_binary() -> Optional[str]:
    """Finds an available Google Chrome / Chromium executable."""
    for p in CHROME_PATHS:
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return p
    return None


def render_report_body_html(
    md_content: str,
    customer_name: str = "Neubox",
    customer_code: str = "NBX"
) -> str:
    """
    Renders Markdown into the inner HTML structure of the executive report.
    Does NOT include <html>, <head>, or global <style> tags to avoid leaking styles into the parent app.
    """
    body_html = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "nl2br", "sane_lists"]
    )

    badge_color = "#3b82f6" if customer_code == "NBX" else "#8b5cf6"
    badge_bg = "#eff6ff" if customer_code == "NBX" else "#f5f3ff"

    return f"""<div class="report-banner" style="border-bottom: 2px solid {badge_color};">
  <div class="banner-title-group">
    <span class="org-badge" style="color: {badge_color}; background: {badge_bg}; border: 1px solid {badge_color};">
      SOC {customer_name.upper()} &bull; {customer_code}
    </span>
    <h1 class="banner-heading">DFIR-IRIS Abuse Incident Report</h1>
  </div>
  <div class="banner-meta">
    <div><strong>Marco Operativo:</strong> SOC Abuse Lite v2.0</div>
    <div><strong>Plataforma:</strong> DFIR-IRIS ({config.IRIS_URL.replace('https://', '')})</div>
    <div><strong>Generado:</strong> Automatizado por SecOps</div>
  </div>
</div>

<div class="report-content">
  {body_html}
</div>

<div class="report-footer">
  <span>Documento Confidencial &bull; Uso Exclusivo del Centro de Operaciones de Seguridad (SOC)</span>
  <span>SOC Neubox &bull; Hospedando</span>
</div>"""


def markdown_to_executive_html(
    md_content: str,
    title: str = "Informe de Incidente — SOC / Abuse",
    customer_name: str = "Neubox",
    customer_code: str = "NBX"
) -> str:
    """
    Renders Markdown into a standalone executive SOC report HTML document.
    Used exclusively for PDF compilation (Chrome Headless / xhtml2pdf).
    """
    body_content = render_report_body_html(md_content, customer_name, customer_code)
    badge_color = "#3b82f6" if customer_code == "NBX" else "#8b5cf6"

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    @page {{
      size: A4 portrait;
      margin: 18mm 15mm 20mm 15mm;
      @bottom-center {{
        content: "SOC Neubox &bull; DFIR-IRIS Incident Report &bull; Confidencial";
        font-size: 8pt;
        color: #94a3b8;
      }}
    }}
    
    * {{
      box-sizing: border-box;
    }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 10.5pt;
      line-height: 1.6;
      color: #1e293b;
      margin: 0;
      padding: 0;
      background: #ffffff;
    }}

    .report-banner {{
      border-bottom: 2px solid {badge_color};
      padding-bottom: 12px;
      margin-bottom: 22px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    .banner-title-group {{
      display: flex;
      flex-direction: column;
    }}

    .org-badge {{
      display: inline-block;
      align-self: flex-start;
      font-size: 8.5pt;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      padding: 3px 8px;
      border-radius: 4px;
      margin-bottom: 6px;
    }}

    .banner-heading {{
      font-size: 16pt;
      font-weight: 700;
      color: #0f172a;
      margin: 0;
    }}

    .banner-meta {{
      text-align: right;
      font-size: 8.5pt;
      color: #64748b;
      line-height: 1.4;
    }}

    .report-content h1 {{
      font-size: 15pt;
      color: #0f172a;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 6px;
      margin-top: 18px;
      margin-bottom: 12px;
      page-break-after: avoid;
    }}

    .report-content h2 {{
      font-size: 12.5pt;
      color: #1e40af;
      border-bottom: 1px solid #f1f5f9;
      padding-bottom: 4px;
      margin-top: 18px;
      margin-bottom: 10px;
      page-break-after: avoid;
    }}

    .report-content h3 {{
      font-size: 11pt;
      color: #334155;
      margin-top: 14px;
      margin-bottom: 6px;
      page-break-after: avoid;
    }}

    .report-content p {{
      margin-top: 0;
      margin-bottom: 10px;
      text-align: justify;
    }}

    .report-content strong {{
      color: #0f172a;
      font-weight: 600;
    }}

    .report-content ul, .report-content ol {{
      margin-top: 4px;
      margin-bottom: 12px;
      padding-left: 22px;
    }}

    .report-content li {{
      margin-bottom: 5px;
    }}

    .report-content blockquote {{
      margin: 12px 0;
      padding: 8px 14px;
      background: #f8fafc;
      border-left: 3px solid #3b82f6;
      color: #475569;
      font-style: italic;
    }}

    .report-content p code,
    .report-content li code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 8.5pt;
      background: #f1f5f9;
      padding: 2px 5px;
      border-radius: 4px;
      color: #b91c1c;
      border: 1px solid #e2e8f0;
      word-break: break-word;
      overflow-wrap: anywhere;
    }}

    .report-content pre {{
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 10px 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 7.8pt;
      line-height: 1.45;
      margin: 12px 0;
      white-space: pre-wrap !important;
      word-break: break-all !important;
      overflow-wrap: anywhere !important;
      page-break-inside: auto;
      break-inside: auto;
      color: #1e293b;
    }}

    .report-content pre code {{
      background: transparent !important;
      padding: 0 !important;
      border: none !important;
      border-radius: 0 !important;
      color: #1e293b !important;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 7.8pt;
      line-height: 1.45;
      white-space: pre-wrap !important;
      word-break: break-all !important;
      overflow-wrap: anywhere !important;
    }}

    .report-content table {{
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }}

    .report-content th, .report-content td {{
      border: 1px solid #cbd5e1;
      padding: 7px 10px;
      text-align: left;
    }}

    .report-content th {{
      background: #f1f5f9;
      color: #1e293b;
      font-weight: 600;
    }}

    .report-content tr:nth-child(even) {{
      background: #f8fafc;
    }}

    .report-content img {{
      max-width: 100%;
      max-height: 480px;
      height: auto;
      display: block;
      margin: 16px auto;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      page-break-inside: avoid;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.08);
    }}

    .report-content p em {{
      display: block;
      text-align: center;
      color: #64748b;
      font-size: 8.5pt;
      margin-top: -6px;
      margin-bottom: 14px;
    }}

    .report-footer {{
      margin-top: 35px;
      padding-top: 12px;
      border-top: 1px solid #cbd5e1;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 8.5pt;
      color: #64748b;
      page-break-inside: avoid;
    }}

    @media print {{
      body {{
        padding: 0;
        background: transparent;
      }}
      .no-print {{
        display: none !important;
      }}
    }}
  </style>
</head>
<body>
  {body_content}
</body>
</html>"""
    return html


def convert_html_to_pdf(html_content: str, output_path: Path) -> bool:
    """
    Renders HTML to PDF using Chrome Headless (preferred) or xhtml2pdf (fallback).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chrome_bin = find_chrome_binary()

    if chrome_bin:
        try:
            temp_html = output_path.with_suffix(".temp.html")
            temp_html.write_text(html_content, encoding="utf-8")

            cmd = [
                chrome_bin,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                f"--print-to-pdf={output_path}",
                f"file://{temp_html.resolve()}"
            ]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if temp_html.exists():
                temp_html.unlink()

            if res.returncode == 0 and output_path.exists() and output_path.stat().st_size > 1000:
                logger.info(f"PDF generated via Google Chrome: {output_path} ({output_path.stat().st_size} bytes)")
                return True
        except Exception as e:
            logger.warning(f"Chrome PDF generation failed, attempting xhtml2pdf fallback: {e}")

    # Fallback: xhtml2pdf
    try:
        with open(output_path, "wb") as f:
            pisa_status = pisa.CreatePDF(html_content, dest=f)
            if not pisa_status.err and output_path.exists() and output_path.stat().st_size > 500:
                logger.info(f"PDF generated via xhtml2pdf: {output_path} ({output_path.stat().st_size} bytes)")
                return True
    except Exception as e:
        logger.error(f"xhtml2pdf generation failed: {e}")

    return False


def generate_pdf_from_markdown(
    md_content: str,
    output_path: Path,
    title: str = "Informe de Incidente — SOC / Abuse",
    customer_name: str = "Neubox",
    customer_code: str = "NBX"
) -> bool:
    """Convenience wrapper to convert Markdown to styled PDF."""
    html = markdown_to_executive_html(
        md_content=md_content,
        title=title,
        customer_name=customer_name,
        customer_code=customer_code
    )
    return convert_html_to_pdf(html, output_path)
