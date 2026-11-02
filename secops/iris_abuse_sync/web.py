"""Punto de entrada compatible hacia la arquitectura modular app.main:app (SOC Platform v3.0)."""
import uvicorn
from app.main import app

__all__ = ["app"]

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8080, reload=False)
