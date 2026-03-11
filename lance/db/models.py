"""
LANCE — Database Models
All campaign, probe, and finding data stored here.
"""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text,
    ForeignKey, Enum, Boolean, JSON, create_engine
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker
from lance.config import settings


class Base(DeclarativeBase):
    pass


class CampaignStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProbeStatus(str, PyEnum):
    PENDING = "pending"
    SUCCESS = "success"       # attack worked — model was vulnerable
    FAILURE = "failure"       # attack blocked — model was safe
    ERROR = "error"           # probe failed to execute


class Campaign(Base):
    """A single red team engagement run."""
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    target_model = Column(String, nullable=False)       # e.g. "openai/gpt-4o"
    target_system_prompt = Column(Text, nullable=True)  # system prompt under test
    attack_modules = Column(JSON, nullable=False)       # list of module names
    status = Column(Enum(CampaignStatus), default=CampaignStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    total_probes = Column(Integer, default=0)
    successful_attacks = Column(Integer, default=0)
    failed_attacks = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    risk_score = Column(Float, nullable=True)           # 0–10 overall risk score
    metadata_ = Column("metadata", JSON, nullable=True)

    probes = relationship("Probe", back_populates="campaign", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="campaign", cascade="all, delete-orphan")


class Probe(Base):
    """A single attack probe — one payload fired at the target model."""
    __tablename__ = "probes"

    id = Column(String, primary_key=True)
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=False)
    attack_module = Column(String, nullable=False)      # e.g. "prompt_injection"
    attack_type = Column(String, nullable=False)        # e.g. "direct_override"
    payload = Column(Text, nullable=False)              # the actual prompt sent
    response = Column(Text, nullable=True)              # model's response
    status = Column(Enum(ProbeStatus), default=ProbeStatus.PENDING)
    judge_score = Column(Float, nullable=True)          # 0.0–1.0 from LLM judge
    judge_reasoning = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    tokens_used = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    owasp_ref = Column(String, nullable=True)           # e.g. "LLM01"
    mitre_atlas_ref = Column(String, nullable=True)     # e.g. "AML.T0051"
    metadata_ = Column("metadata", JSON, nullable=True)

    campaign = relationship("Campaign", back_populates="probes")
    finding = relationship("Finding", back_populates="probe", uselist=False)


class Finding(Base):
    """A confirmed vulnerability — probe that scored above threshold."""
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=False)
    probe_id = Column(String, ForeignKey("probes.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    owasp_ref = Column(String, nullable=True)
    mitre_atlas_ref = Column(String, nullable=True)
    evidence_payload = Column(Text, nullable=False)
    evidence_response = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    confirmed = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("Campaign", back_populates="findings")
    probe = relationship("Probe", back_populates="finding")


# ── Engine & Session ──────────────────────────────────────────────────────────

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    echo=settings.debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)
