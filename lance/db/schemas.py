"""
LANCE — Pydantic Schemas
Request/response models for API and internal use.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from lance.db.models import CampaignStatus, Severity, ProbeStatus


# ── Campaign ──────────────────────────────────────────────────────────────────

class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    target_model: str = Field(..., description="LiteLLM model string e.g. openai/gpt-4o")
    target_system_prompt: Optional[str] = Field(None, description="System prompt to test against")
    attack_modules: list[str] = Field(default=["prompt_injection"])


class CampaignSummary(BaseModel):
    id: str
    name: str
    target_model: str
    status: CampaignStatus
    created_at: datetime
    total_probes: int
    successful_attacks: int
    risk_score: Optional[float]

    model_config = {"from_attributes": True}


class CampaignDetail(CampaignSummary):
    description: Optional[str]
    target_system_prompt: Optional[str]
    attack_modules: list[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    failed_attacks: int
    error_count: int

    model_config = {"from_attributes": True}


# ── Probe ─────────────────────────────────────────────────────────────────────

class ProbeOut(BaseModel):
    id: str
    campaign_id: str
    attack_module: str
    attack_type: str
    payload: str
    response: Optional[str]
    status: ProbeStatus
    judge_score: Optional[float]
    judge_reasoning: Optional[str]
    latency_ms: Optional[int]
    owasp_ref: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    campaign_id: str
    probe_id: str
    title: str
    description: str
    severity: Severity
    owasp_ref: Optional[str]
    mitre_atlas_ref: Optional[str]
    evidence_payload: str
    evidence_response: str
    remediation: Optional[str]
    cvss_score: Optional[float]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Dashboard stats ───────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_campaigns: int
    total_probes: int
    total_findings: int
    critical_findings: int
    high_findings: int
    avg_risk_score: Optional[float]
    most_vulnerable_model: Optional[str]


class ReportRequest(BaseModel):
    campaign_id: str
    format: str = Field(default="pdf", pattern="^(pdf|html)$")
    include_payloads: bool = True
    include_remediation: bool = True
