import json
import logging
from typing import Dict, Any, List, Tuple
from pathlib import Path

import config

logger = logging.getLogger("iris_abuse_sync.classifier")


class TemplateClassifier:
    """
    Hybrid classification engine for DFIR-IRIS abuse tickets.
    Uses rule-based heuristic scoring with optional LLM fallback/refinement.
    """

    KEYWORD_RULES = {
        "abuse_takedown": {
            "keywords": [
                "ctir", "cert.br", "csirt", "tlp:amber", "tlp:red", "takedown",
                "notificación oficial", "orden judicial", "fiscalía", "autoridad",
                "cyber incident prevention", "first.org", "tlp:"
            ],
            "weight": 3.0
        },
        "abuse_trademark": {
            "keywords": [
                "phishfort", "brand", "marca", "logo", "copyright", "propiedad intelectual",
                "don julio", "diageo", "casamigos", "trademark", "derechos de autor",
                "no substantiated abuse", "solicitud de baja de marca"
            ],
            "weight": 2.5
        },
        "abuse_fraud": {
            "keywords": [
                "esteroides", "anabólicos", "farmacéuticos", "medicamentos", "cofepris",
                "prescripción", "receta médica", "scam", "estafa", "fraude",
                "venta no autorizada", "testosterona", "nandrolona", "trembolona",
                "winstrol", "dianabol"
            ],
            "weight": 2.5
        },
        "abuse_spam": {
            "keywords": [
                "spam", "dating", "dating site", "singles site", "correo no deseado",
                "x-rpcampaign", "x-authenticated-id", "esmtpsa", "mass mail",
                "proxmox", "getting attention - by women", "correo masivo",
                "envío de correo no autorizado", "relaying", "open relay"
            ],
            "weight": 2.5
        },
        "abuse_phishing": {
            "keywords": [
                "phishing", "phish", "credenciales", "captura de credenciales",
                "clonación", "suplantación", "banco", "login fraudulento",
                "phishing attempt", "phishing message", "phishing sender"
            ],
            "weight": 2.0
        },
        "abuse_malware": {
            "keywords": [
                "malware", "webshell", "trojan", "virus", "payload",
                "infección", "c2", "ransomware", "backdoor", "c99", "r57"
            ],
            "weight": 2.5
        },
        "abuse_network": {
            "keywords": [
                "fuerza bruta", "brute force", "ddos", "dos", "botnet",
                "port scan", "escaneo de puertos", "ataque de red", "ssh scan"
            ],
            "weight": 2.5
        }
    }

    def __init__(self, templates_dir: Path = config.TEMPLATES_DIR):
        self.templates_dir = templates_dir
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, Dict[str, Any]]:
        templates = {}
        for file_path in self.templates_dir.glob("*.json"):
            if "atributo" in file_path.name.lower():
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "name" in data:
                        templates[data["name"]] = data
            except Exception as e:
                logger.warning(f"Error loading template {file_path}: {e}")
        return templates

    def classify(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies the ticket and returns the best matching template,
        along with confidence and matching reasons.
        """
        text = parsed_data.get("clean_text") or parsed_data.get("raw_text", "").lower()
        summary = parsed_data.get("brief_summary", "").lower()
        reporter = parsed_data.get("reporter", "").lower()
        reporter_org = parsed_data.get("reporter_org", "").lower()

        scores: Dict[str, float] = {name: 0.0 for name in self.templates.keys()}
        reasons: Dict[str, List[str]] = {name: [] for name in self.templates.keys()}

        # 1. Rule-based evaluation
        combined_text = f"{text} {summary} {reporter} {reporter_org}".lower()

        for tmpl_name, rule_cfg in self.KEYWORD_RULES.items():
            if tmpl_name not in scores:
                continue

            weight = rule_cfg["weight"]
            for kw in rule_cfg["keywords"]:
                if kw in combined_text:
                    scores[tmpl_name] += 1.0 * weight
                    reasons[tmpl_name].append(kw)

        # 2. Contextual boosts
        # If CTIR / CERT / TLP notification
        if "ctir" in combined_text or "tlp:amber" in combined_text:
            if "abuse_takedown" in scores:
                scores["abuse_takedown"] += 5.0
                reasons["abuse_takedown"].append("Reporte formal de CSIRT/CERT gubernamental")
        
        # If Brand / Trademark report from PhishFort
        if "phishfort" in combined_text or "don julio" in combined_text:
            if "abuse_trademark" in scores:
                scores["abuse_trademark"] += 6.0
                reasons["abuse_trademark"].append("Reporte de marca / derechos de autor")

        # If COFEPRIS / steroids / illegal pharma
        if "cofepris" in combined_text or "esteroides" in combined_text:
            if "abuse_fraud" in scores:
                scores["abuse_fraud"] += 6.0
                reasons["abuse_fraud"].append("Catálogo de esteroides / medicamentos COFEPRIS")

        # If compromised email account sending dating / mass spam
        if parsed_data.get("auth_accounts") and ("dating" in combined_text or "esmtpsa" in combined_text or "x-rpcampaign" in combined_text):
            if "abuse_spam" in scores:
                scores["abuse_spam"] += 6.0
                reasons["abuse_spam"].append("Cuenta vulnerada emitiendo spam de citas")

        # 3. Determine highest scoring template
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_template_name, top_score = sorted_scores[0] if sorted_scores else ("abuse_phishing", 0.0)

        # Default fallback if no keywords matched
        if top_score <= 0.0:
            top_template_name = "abuse_phishing"
            top_score = 1.0
            reasons[top_template_name] = ["Asignado por defecto (investigación de abuso)"]

        # Calculate relative confidence
        total_score = sum(scores.values()) or 1.0
        confidence = min(0.98, max(0.50, top_score / (total_score + 1.0) * 1.5))

        selected_template = self.templates.get(top_template_name, {})
        title_prefix = selected_template.get("title_prefix", "[ABUSE]")
        display_name = selected_template.get("display_name", top_template_name)

        # Optional: LLM Hybrid check
        if config.LLM_PROVIDER != "none" and config.LLM_API_KEY:
            llm_result = self._try_llm_classification(parsed_data, top_template_name)
            if llm_result:
                top_template_name = llm_result.get("template_name", top_template_name)
                selected_template = self.templates.get(top_template_name, selected_template)
                title_prefix = selected_template.get("title_prefix", title_prefix)
                display_name = selected_template.get("display_name", display_name)
                reasons[top_template_name].append(f"LLM: {llm_result.get('reason')}")

        return {
            "template_name": top_template_name,
            "title_prefix": title_prefix,
            "display_name": display_name,
            "template_data": selected_template,
            "confidence": round(confidence, 2),
            "reasons": reasons.get(top_template_name, []),
            "all_scores": scores
        }

    def _try_llm_classification(self, parsed_data: Dict[str, Any], current_pick: str) -> Optional[Dict[str, str]]:
        """
        Queries Ollama API for contextual refinement and classification.
        """
        if config.LLM_PROVIDER != "ollama":
            return None

        ollama_url = f"{config.OLLAMA_URL}/api/chat"
        model = config.LLM_MODEL or "qwen3-abliterated-8k:latest"

        prompt = (
            "Eres un analista de ciberseguridad del SOC de Neubox / Hospedando. "
            "Analiza el siguiente texto de un ticket de abuso y clasifícalo en EXACTAMENTE UNO de estos templates:\n"
            "- abuse_phishing (sitios falsos, login falso, captura de credenciales)\n"
            "- abuse_spam (cuentas vulneradas enviando correo masivo o spam de citas)\n"
            "- abuse_fraud (venta no autorizada de medicamentos/esteroides COFEPRIS, estafas comerciales)\n"
            "- abuse_trademark (uso no autorizado de marcas, logotipos, copyright, Don Julio, Diageo)\n"
            "- abuse_malware (sitios infectados, webshells, virus, troyanos)\n"
            "- abuse_network (fuerza bruta, escaneo de puertos, ataques DDoS)\n"
            "- abuse_takedown (notificaciones formales de CSIRT/CERT gubernamentales como CTIR Gov bajo TLP)\n\n"
            f"Texto del ticket:\n\"\"\"\n{parsed_data.get('raw_text', '')[:3000]}\n\"\"\"\n\n"
            "Responde ÚNICAMENTE en formato JSON con las claves: "
            "\"template_name\" (nombre del template exacto), \"reason\" (motivo breve en español) y \"refined_summary\" (resumen ejecutivo de 1 o 2 oraciones en español)."
        )

        try:
            import requests
            r = requests.post(
                ollama_url,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "format": "json",
                    "stream": False
                },
                timeout=20
            )
            if r.status_code == 200:
                content = r.json().get("message", {}).get("content", "")
                data = json.loads(content)
                tmpl = data.get("template_name", "").strip().lower()
                if tmpl in self.templates:
                    return {
                        "template_name": tmpl,
                        "reason": data.get("reason", "Confirmado por Ollama"),
                        "refined_summary": data.get("refined_summary", "")
                    }
        except Exception as e:
            logger.debug(f"Ollama call skipped/failed: {e}")

        return None
