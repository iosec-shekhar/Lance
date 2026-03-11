"""
LANCE — FastAPI Application
REST API for the dashboard and CLI integration.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lance.db.models import init_db
from lance.config import settings
from lance.api.routers import campaigns, findings, reports, system


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB on startup."""
    init_db()
    yield


app = FastAPI(
    title="LANCE",
    description="LLM Red Team Evaluation Framework — lance.iosec.in",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST API routers
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["Campaigns"])
app.include_router(findings.router,  prefix="/api/findings",  tags=["Findings"])
app.include_router(reports.router,   prefix="/api/reports",   tags=["Reports"])
app.include_router(system.router,    prefix="/api/system",    tags=["System"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "tool": "LANCE", "version": settings.app_version, "url": settings.app_url}
