"""LANCE — Findings Router"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from lance.db.models import get_db, Finding, Campaign
from lance.db.schemas import FindingOut, DashboardStats

router = APIRouter()


@router.get("/", response_model=list[FindingOut])
async def list_findings(
    campaign_id: str | None = None,
    severity: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """List findings, optionally filtered by campaign or severity."""
    q = db.query(Finding)
    if campaign_id:
        q = q.filter(Finding.campaign_id == campaign_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregate stats for the dashboard home page."""
    from sqlalchemy import func
    from lance.db.models import Probe, Severity as Sev

    total_campaigns = db.query(Campaign).count()
    total_probes = db.query(Probe).count()
    total_findings = db.query(Finding).count()
    critical = db.query(Finding).filter(Finding.severity == Sev.CRITICAL).count()
    high = db.query(Finding).filter(Finding.severity == Sev.HIGH).count()

    avg_risk = db.query(func.avg(Campaign.risk_score)).scalar()
    top_model = (
        db.query(Campaign.target_model, func.count(Finding.id).label("cnt"))
        .join(Finding, Finding.campaign_id == Campaign.id)
        .group_by(Campaign.target_model)
        .order_by(func.count(Finding.id).desc())
        .first()
    )

    return DashboardStats(
        total_campaigns=total_campaigns,
        total_probes=total_probes,
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
        avg_risk_score=round(avg_risk, 1) if avg_risk else None,
        most_vulnerable_model=top_model[0] if top_model else None,
    )


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
