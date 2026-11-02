from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routers import admin, alerts, auth, cases, dashboard, ingest, migration, blacklist, retention
from app.core.bootstrap import init_db_and_seed
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_and_seed()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Plataforma SOC v3.0 de Recepción Multicanal, Normalización, Clasificación Híbrida (Heurísticas + Google Gemini), "
        "Triage de Alertas, Investigación Estructurada de Casos, Migración Histórica e Informes para NEUBOX (NBX) y Hospedando (HP)."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registrar routers modulares v3.0
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(ingest.router)
app.include_router(migration.router)
app.include_router(admin.router)
app.include_router(blacklist.router)
app.include_router(retention.router)

static_dir = settings.BASE_DIR / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

frontend_dist = settings.BASE_DIR / "frontend" / "dist"
assets_dir = frontend_dist / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_assets")


def _serve_spa():
    index_file = frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return FileResponse(str(static_dir / "index.html"))


@app.get("/", include_in_schema=False)
def serve_soc_console():
    return _serve_spa()


spa_routes = [
    "/dashboard",
    "/alerts",
    "/cases",
    "/cases/{case_id}",
    "/ingest",
    "/ingest-history",
    "/migration",
    "/connectors",
    "/blacklist",
    "/users",
    "/gemini",
    "/audit",
    "/playbooks",
    "/reports",
    "/login",
]

for r_path in spa_routes:
    app.add_api_route(r_path, _serve_spa, methods=["GET"], include_in_schema=False)


@app.get("/api/health", tags=["health"])
def healthcheck():
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "app": settings.APP_NAME,
        "iris_url": settings.IRIS_URL,
    }

