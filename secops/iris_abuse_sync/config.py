import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the iris_abuse_sync package
BASE_DIR = Path(__file__).resolve().parent

# Load .env file if it exists
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

# DFIR-IRIS connection settings
IRIS_URL = os.getenv("IRIS_URL", "http://127.0.0.1:8000").rstrip("/")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
IRIS_CUSTOMER_ID = int(os.getenv("IRIS_CUSTOMER_ID", "1"))
IRIS_VERIFY_SSL = os.getenv("IRIS_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

# Customer Mapping (Neubox & Hospedando)
CUSTOMERS = {
    "neubox": {"id": 2, "name": "Neubox", "code": "NBX"},
    "hospedando": {"id": 3, "name": "Hospedando", "code": "HP"}
}
DEFAULT_CUSTOMER = os.getenv("DEFAULT_CUSTOMER", "neubox").lower()

# Directory paths
TEMPLATES_DIR = Path(os.getenv("TEMPLATES_DIR", str(BASE_DIR / "templates")))
INBOX_DIR = Path(os.getenv("INBOX_DIR", str(BASE_DIR / "inbox")))
PROCESSED_DIR = Path(os.getenv("PROCESSED_DIR", str(BASE_DIR / "processed")))
ERRORS_DIR = Path(os.getenv("ERRORS_DIR", str(BASE_DIR / "errors")))

# Web server settings
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))

# LLM Hybrid Engine Settings (Ollama, Gemini, OpenAI)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()  # none, ollama, gemini, openai
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3-abliterated-8k:latest")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")

# Ensure required directories exist
for d in (TEMPLATES_DIR, INBOX_DIR, PROCESSED_DIR, ERRORS_DIR):
    d.mkdir(parents=True, exist_ok=True)
