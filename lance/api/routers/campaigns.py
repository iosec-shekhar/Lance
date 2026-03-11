"""
LANCE — Campaigns Router
Endpoints for creating, listing, and running campaigns.
"""
import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from lance.db.models import get_db, Campaign, CampaignStatus
from lance.db.schemas import CampaignCreate, CampaignSummary, CampaignDetail
from lance.engine.orchestrator import create_campaign, run_campaign, list_available_modules

router = APIRouter()

# Track running campaigns {campaign_id: progress_dict}
_running: dict[str, dict] = {}


@router.get("/", response_model=list[CampaignSummary])
async def list_campaigns(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """List all campaigns, newest first."""
    campaigns = (
        db.query(Campaign)
        .order_by(Campaign.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return campaigns


@router.get("/modules")
async def get_modules():
    """List all available attack modules."""
    return list_available_modules()


@router.post("/", response_model=CampaignDetail, status_code=201)
async def create_new_campaign(
    payload: CampaignCreate,
    db: Session = Depends(get_db),
):
    """Create a new campaign (does not start it)."""
    campaign = create_campaign(
        db=db,
        name=payload.name,
        description=payload.description,
        target_model=payload.target_model,
        attack_modules=payload.attack_modules,
        target_system_prompt=payload.target_system_prompt,
    )
    return campaign


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign(campaign_id: str, db: Session = Depends(get_db)):
    """Get full details of a campaign."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/{campaign_id}/run")
async def run_campaign_endpoint(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start executing a campaign in the background."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status == CampaignStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Campaign is already running")

    _running[campaign_id] = {"current": 0, "total": 0, "message": "Starting..."}

    async def _run():
        from lance.db.models import SessionLocal
        session = SessionLocal()
        try:
            async def progress(current, total, message):
                _running[campaign_id] = {
                    "current": current,
                    "total": total,
                    "message": message,
                }
            await run_campaign(campaign_id, session, progress_callback=progress)
        finally:
            session.close()
            _running.pop(campaign_id, None)

    background_tasks.add_task(_run)
    return {"status": "started", "campaign_id": campaign_id}


@router.get("/{campaign_id}/progress")
async def get_progress(campaign_id: str, db: Session = Depends(get_db)):
    """Get live progress of a running campaign."""
    progress = _running.get(campaign_id)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {
        "campaign_id": campaign_id,
        "status": campaign.status,
        "progress": progress,
    }


@router.delete("/{campaign_id}", status_code=204)
async def delete_campaign(campaign_id: str, db: Session = Depends(get_db)):
    """Delete a campaign and all its data."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    db.delete(campaign)
    db.commit()
