"""
SecureScan Backend — SQLAlchemy Models
User, Scan, Report, and ApiKey database models
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON, ForeignKey, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


# ── Helpers ──
def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return uuid.uuid4()


# ═══════════════════════════════════════════════════════════
#  USER MODEL
# ═══════════════════════════════════════════════════════════
class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=True)  # Null for OAuth-only users
    name = Column(String(255), nullable=True)
    oauth_provider = Column(String(50), nullable=True)   # "github", "google"
    oauth_id = Column(String(255), nullable=True)
    tier = Column(String(20), default="free")            # "free", "pro", "enterprise"
    scan_quota = Column(Integer, default=50)              # Scans per month
    scans_used = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")


# ═══════════════════════════════════════════════════════════
#  SCAN MODEL
# ═══════════════════════════════════════════════════════════
class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type = Column(String(20), nullable=False)       # "code", "text", "image"
    status = Column(String(20), default="queued")        # "queued", "running", "completed", "failed"
    input_snippet = Column(Text, nullable=True)          # First 500 chars of input
    language = Column(String(50), nullable=True)         # For code: "python", "javascript"...
    file_path = Column(String(500), nullable=True)       # Storage path for images

    # Results
    result = Column(JSON, nullable=True)                 # Full scan result
    score = Column(Integer, nullable=True)               # 0-100 insecurity score
    risk_level = Column(String(20), nullable=True)       # "low", "medium", "high", "critical"
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Metadata
    processing_time_ms = Column(Float, nullable=True)
    engine_version = Column(String(20), default="1.0.0")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    user = relationship("User", back_populates="scans")
    report = relationship("Report", back_populates="scan", uselist=False, cascade="all, delete-orphan")


# ═══════════════════════════════════════════════════════════
#  REPORT MODEL
# ═══════════════════════════════════════════════════════════
class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    full_report = Column(JSON, nullable=True)
    export_format = Column(String(20), nullable=True)    # "pdf", "json", "sarif"
    file_url = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="report")


# ═══════════════════════════════════════════════════════════
#  API KEY MODEL
# ═══════════════════════════════════════════════════════════
class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String(255), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    user = relationship("User", back_populates="api_keys")
