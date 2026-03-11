"""LANCE — Reports Router"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import tempfile
import json

from lance.db.models import get_db, Campaign, Finding, Probe
from lance.config import settings

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "reports" / "templates"

MODULE_DISPLAY = {
    "prompt_injection":  "Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "jailbreak":         "Jailbreak",
    "model_dos":         "Model DoS",
    "rag_poisoning":     "RAG Poisoning",
}

OWASP_MAP = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Insecure Output Handling"),
    ("LLM03", "Training Data Poisoning"),
    ("LLM04", "Model Denial of Service"),
    ("LLM05", "Supply Chain Vuln"),
    ("LLM06", "Sensitive Info Disclosure"),
    ("LLM07", "Plugin Design Flaws"),
    ("LLM08", "Excessive Agency"),
]


def build_chart_data(campaign: Campaign, findings: list, probes: list) -> dict:
    """Compute all chart data in Python and return as JSON-serialisable dict."""

    # Severity counts
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

    # Module bar — prefer attack_module field, fall back to owasp_ref grouping
    modules = campaign.attack_modules or []
    has_module_data = any(getattr(f, "attack_module", None) for f in findings)

    if has_module_data:
        mod_labels, mod_hits, mod_blocked = [], [], []
        for m in modules:
            label   = MODULE_DISPLAY.get(m, m.replace("_", " ").title())
            hits    = sum(1 for p in probes if getattr(p, "attack_module", None) == m and getattr(p.status, "value", "") == "success")
            blocked = sum(1 for p in probes if getattr(p, "attack_module", None) == m and getattr(p.status, "value", "") == "failed")
            mod_labels.append(label)
            mod_hits.append(hits)
            mod_blocked.append(blocked)
    else:
        # Fallback: group findings by owasp_ref
        owasp_groups = {}
        for f in findings:
            ref = f.owasp_ref or "Other"
            owasp_groups[ref] = owasp_groups.get(ref, 0) + 1
        mod_labels  = list(owasp_groups.keys())
        mod_hits    = [owasp_groups[k] for k in mod_labels]
        mod_blocked = [0] * len(mod_labels)

    # Probe outcomes
    total   = campaign.total_probes or 0
    hits    = campaign.successful_attacks or 0
    blocked = campaign.failed_attacks or 0
    errors  = campaign.error_count or 0
    miss    = max(0, total - hits - blocked - errors)

    # OWASP radar — normalise to 0-10 relative to highest ref count
    owasp_refs = [f.owasp_ref or "" for f in findings]
    ref_counts  = {ref: owasp_refs.count(ref) for ref, _ in OWASP_MAP}
    max_count   = max(ref_counts.values()) if ref_counts and max(ref_counts.values()) > 0 else 1
    radar_this   = [round(ref_counts[ref] / max_count * 10, 1) for ref, _ in OWASP_MAP]
    radar_labels = [ref for ref, _ in OWASP_MAP]
    radar_avg    = [6, 5, 4, 4, 3, 5, 3, 4]

    return {
        "severity": {
            "labels":  ["Critical", "High", "Medium", "Low"],
            "data":    [sev["critical"], sev["high"], sev["medium"], sev["low"]],
            "colors":  ["#7E22CE", "#DC2626", "#EA580C", "#0E7490"],
        },
        "modules": {
            "labels":  mod_labels,
            "hits":    mod_hits,
            "blocked": mod_blocked,
        },
        "outcomes": {
            "labels": ["Hits", "Blocked", "Miss", "Error"],
            "data":   [hits, blocked, miss, errors],
            "colors": ["#DC2626", "#0E7490", "#C8CAD8", "#EA580C"],
        },
        "radar": {
            "labels":       radar_labels,
            "this_scan":    radar_this,
            "industry_avg": radar_avg,
        },
    }


def render_report_html(campaign: Campaign, findings: list, probes: list) -> str:
    """Render the report as HTML using Jinja2."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    template = env.get_template("report.html")

    severity_counts = {
        "critical": sum(1 for f in findings if f.severity.value == "critical"),
        "high":     sum(1 for f in findings if f.severity.value == "high"),
        "medium":   sum(1 for f in findings if f.severity.value == "medium"),
        "low":      sum(1 for f in findings if f.severity.value == "low"),
    }

    chart_data = build_chart_data(campaign, findings, probes)

    return template.render(
        campaign=campaign,
        findings=findings,
        probes=probes,
        severity_counts=severity_counts,
        chart_data_json=json.dumps(chart_data),
        org_name=settings.org_name,
        tool_url=settings.app_url,
    )


@router.get("/{campaign_id}/html", response_class=HTMLResponse)
async def get_report_html(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    probes   = db.query(Probe).filter(Probe.campaign_id == campaign_id).all()
    return HTMLResponse(content=render_report_html(campaign, findings, probes))


@router.get("/{campaign_id}/pdf")
async def get_report_pdf(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    probes   = db.query(Probe).filter(Probe.campaign_id == campaign_id).all()
    html = render_report_html(campaign, findings, probes)
    try:
        from weasyprint import HTML
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
            HTML(string=html).write_pdf(f.name)
            return FileResponse(
                path=f.name,
                media_type="application/pdf",
                filename=f"lance-report-{campaign_id[:8]}.pdf",
                background=None,
            )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="WeasyPrint not installed. Use /html endpoint or install: pip install weasyprint",
        )
