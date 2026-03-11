"""
LANCE — Web UI Server (v0.5.0)
Self-hosted dashboard. Launch with: lance ui
"""
import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager

from lance.db.models import (
    get_db, init_db, SessionLocal,
    Campaign, Finding, Probe,
    CampaignStatus, Severity,
)
from lance.config import settings

# ── Paths ──────────────────────────────────────────────────────────────────────
UI_DIR       = Path(__file__).parent
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR    = UI_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ── WebSocket connection manager ───────────────────────────────────────────────
class ConnectionManager:
    """Manages WebSocket connections per campaign."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, campaign_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(campaign_id, []).append(ws)

    def disconnect(self, campaign_id: str, ws: WebSocket):
        conns = self._connections.get(campaign_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, campaign_id: str, data: dict):
        conns = self._connections.get(campaign_id, [])
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(campaign_id, ws)


manager = ConnectionManager()

# ── Progress callback factory ──────────────────────────────────────────────────
def make_progress_callback(campaign_id: str, db: Session):
    """Returns an async callback that broadcasts progress over WebSocket."""
    async def _cb(current: int, total: int, message: str):
        # Update DB
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if campaign:
            db.refresh(campaign)

        await manager.broadcast(campaign_id, {
            "type":    "progress",
            "current": current,
            "total":   total,
            "message": message,
            "pct":     round((current / total * 100) if total else 0, 1),
        })

    return _cb


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


# ── App ────────────────────────────────────────────────────────────────────────
ui_app = FastAPI(
    title="LANCE UI",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url=None, redoc_url=None,
)

ui_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ui_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Helper: campaign stats ─────────────────────────────────────────────────────
def campaign_to_dict(c: Campaign, db: Session) -> dict:
    findings = db.query(Finding).filter(Finding.campaign_id == c.id).all()
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

    return {
        "id":                c.id,
        "id_short":          c.id[:8],
        "name":              c.name,
        "target_model":      c.target_model,
        "attack_modules":    c.attack_modules or [],
        "status":            c.status.value,
        "created_at":        c.created_at.isoformat() if c.created_at else None,
        "completed_at":      c.completed_at.isoformat() if c.completed_at else None,
        "total_probes":      c.total_probes or 0,
        "successful_attacks":c.successful_attacks or 0,
        "failed_attacks":    c.failed_attacks or 0,
        "error_count":       c.error_count or 0,
        "risk_score":        c.risk_score,
        "findings_count":    len(findings),
        "severity":          sev,
    }


def finding_to_dict(f: Finding) -> dict:
    return {
        "id":               f.id,
        "title":            f.title,
        "description":      f.description,
        "severity":         f.severity.value,
        "owasp_ref":        f.owasp_ref,
        "mitre_atlas_ref":  f.mitre_atlas_ref,
        "evidence_payload": f.evidence_payload,
        "evidence_response":f.evidence_response,
        "remediation":      f.remediation,
        "cvss_score":       f.cvss_score,
        "created_at":       f.created_at.isoformat() if f.created_at else None,
    }


# ── PAGE: Dashboard ────────────────────────────────────────────────────────────
@ui_app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    campaigns = (
        db.query(Campaign)
        .order_by(Campaign.created_at.desc())
        .limit(50)
        .all()
    )
    campaign_dicts = [campaign_to_dict(c, db) for c in campaigns]

    # Stats
    total     = len(campaign_dicts)
    completed = sum(1 for c in campaign_dicts if c["status"] == "completed")
    running   = sum(1 for c in campaign_dicts if c["status"] == "running")
    avg_risk  = (
        round(sum(c["risk_score"] for c in campaign_dicts if c["risk_score"]) /
              max(1, sum(1 for c in campaign_dicts if c["risk_score"])), 1)
        if campaign_dicts else 0
    )
    total_findings = sum(c["findings_count"] for c in campaign_dicts)

    # Risk trend data for chart (last 10 completed)
    trend = [
        {"label": c["id_short"], "score": c["risk_score"], "model": c["target_model"]}
        for c in campaign_dicts
        if c["status"] == "completed" and c["risk_score"] is not None
    ][:10][::-1]

    return templates.TemplateResponse("dashboard.html", {
        "request":        request,
        "campaigns":      campaign_dicts,
        "stats": {
            "total":          total,
            "completed":      completed,
            "running":        running,
            "avg_risk":       avg_risk,
            "total_findings": total_findings,
        },
        "trend_json":     json.dumps(trend),
        "version":        settings.app_version,
    })


# ── PAGE: Campaign Detail ──────────────────────────────────────────────────────
@ui_app.get("/campaign/{campaign_id}", response_class=HTMLResponse)
async def campaign_detail(
    request: Request,
    campaign_id: str,
    db: Session = Depends(get_db),
):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    probes   = db.query(Probe).filter(Probe.campaign_id == campaign_id).all()
    c_dict   = campaign_to_dict(campaign, db)
    f_dicts  = [finding_to_dict(f) for f in findings]

    # Chart data
    sev = c_dict["severity"]

    # Module breakdown
    MODULE_DISPLAY = {
        "prompt_injection":  "Prompt Injection",
        "data_exfiltration": "Data Exfiltration",
        "jailbreak":         "Jailbreak",
        "model_dos":         "Model DoS",
        "rag_poisoning":     "RAG Poisoning",
    }
    modules = campaign.attack_modules or []
    has_module_data = any(getattr(p, "attack_module", None) for p in probes)
    if has_module_data:
        mod_labels = [MODULE_DISPLAY.get(m, m) for m in modules]
        mod_hits   = [sum(1 for p in probes if getattr(p, "attack_module", None) == m and p.status.value == "success") for m in modules]
        mod_blocked= [sum(1 for p in probes if getattr(p, "attack_module", None) == m and p.status.value == "failure") for m in modules]
    else:
        owasp_groups = {}
        for f in findings:
            ref = f.owasp_ref or "Other"
            owasp_groups[ref] = owasp_groups.get(ref, 0) + 1
        mod_labels  = list(owasp_groups.keys())
        mod_hits    = [owasp_groups[k] for k in mod_labels]
        mod_blocked = [0] * len(mod_labels)

    # OWASP radar
    OWASP_MAP = ["LLM01","LLM02","LLM03","LLM04","LLM05","LLM06","LLM07","LLM08"]
    owasp_refs = [f.owasp_ref or "" for f in findings]
    ref_counts  = {ref: owasp_refs.count(ref) for ref in OWASP_MAP}
    max_count   = max(ref_counts.values()) if ref_counts and max(ref_counts.values()) > 0 else 1
    radar_data  = [round(ref_counts[ref] / max_count * 10, 1) for ref in OWASP_MAP]

    # Probe outcomes
    total   = campaign.total_probes or 0
    hits    = campaign.successful_attacks or 0
    blocked = campaign.failed_attacks or 0
    errors  = campaign.error_count or 0
    miss    = max(0, total - hits - blocked - errors)

    chart_data = {
        "severity": {
            "labels": ["Critical", "High", "Medium", "Low"],
            "data":   [sev["critical"], sev["high"], sev["medium"], sev["low"]],
        },
        "modules": {
            "labels":  mod_labels,
            "hits":    mod_hits,
            "blocked": mod_blocked,
        },
        "outcomes": {
            "labels": ["Hits", "Blocked", "Miss", "Error"],
            "data":   [hits, blocked, miss, errors],
        },
        "radar": {
            "labels": OWASP_MAP,
            "data":   radar_data,
        },
    }

    return templates.TemplateResponse("campaign_detail.html", {
        "request":     request,
        "campaign":    c_dict,
        "findings":    f_dicts,
        "chart_data":  json.dumps(chart_data),
        "version":     settings.app_version,
    })


# ── PAGE: New Scan (quick launch) ──────────────────────────────────────────────
@ui_app.get("/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    from lance.engine.orchestrator import list_available_modules
    modules = list_available_modules()
    return templates.TemplateResponse("new_scan.html", {
        "request": request,
        "modules": modules,
        "version": settings.app_version,
    })


# ── API: Create + run campaign ─────────────────────────────────────────────────
@ui_app.post("/api/scan")
async def api_start_scan(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    model         = body.get("model", "").strip()
    system_prompt = body.get("system_prompt", "").strip() or None
    modules       = body.get("modules", ["all"])
    name          = body.get("name", f"scan-{model.split('/')[-1]}") if model else "scan"

    if not model:
        return JSONResponse({"error": "model is required"}, status_code=400)

    from lance.engine.orchestrator import ALL_MODULES, create_campaign, run_campaign

    module_list = ALL_MODULES if "all" in modules else [m for m in modules if m in ALL_MODULES]
    if not module_list:
        module_list = ALL_MODULES

    campaign = create_campaign(
        db=db, name=name,
        target_model=model,
        attack_modules=module_list,
        target_system_prompt=system_prompt,
    )

    async def _run():
        sess = SessionLocal()
        try:
            cb = make_progress_callback(campaign.id, sess)
            await run_campaign(campaign.id, sess, progress_callback=cb)
            # Broadcast completion
            c = sess.query(Campaign).filter(Campaign.id == campaign.id).first()
            await manager.broadcast(campaign.id, {
                "type":       "complete",
                "risk_score": c.risk_score,
                "status":     c.status.value,
            })
        finally:
            sess.close()

    asyncio.create_task(_run())

    return {"campaign_id": campaign.id, "status": "started"}


# ── API: Campaign list (JSON) ──────────────────────────────────────────────────
@ui_app.get("/api/campaigns")
async def api_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).limit(50).all()
    return [campaign_to_dict(c, db) for c in campaigns]


# ── API: Campaign delete ───────────────────────────────────────────────────────
@ui_app.delete("/api/campaigns/{campaign_id}")
async def api_delete_campaign(campaign_id: str, db: Session = Depends(get_db)):
    c = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not c:
        raise HTTPException(404, "Not found")
    db.delete(c)
    db.commit()
    return {"deleted": campaign_id}


# ── API: Report HTML ───────────────────────────────────────────────────────────
@ui_app.get("/api/report/{campaign_id}")
async def api_report(campaign_id: str, db: Session = Depends(get_db)):
    from lance.api.routers.reports import render_report_html
    c = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not c:
        raise HTTPException(404)
    findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    probes   = db.query(Probe).filter(Probe.campaign_id == campaign_id).all()
    html = render_report_html(c, findings, probes)
    return HTMLResponse(content=html)


# ── WebSocket: live scan progress ──────────────────────────────────────────────
@ui_app.websocket("/ws/{campaign_id}")
async def ws_progress(websocket: WebSocket, campaign_id: str):
    await manager.connect(campaign_id, websocket)
    try:
        # Send current status immediately on connect
        db = SessionLocal()
        try:
            c = db.query(Campaign).filter(Campaign.id == campaign_id).first()
            if c:
                await websocket.send_json({
                    "type":   "status",
                    "status": c.status.value,
                })
        finally:
            db.close()

        # Keep alive — client sends pings
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(campaign_id, websocket)
