"""
SecureScan Backend — Pydantic Schemas
Request/response validation and serialization
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ═══════════════════════════════════════════════════════════
#  AUTH SCHEMAS
# ═══════════════════════════════════════════════════════════
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    name: Optional[str] = Field(None, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: Optional[str]
    tier: str
    scan_quota: int
    scans_used: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  SCAN SCHEMAS
# ═══════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    scan_type: str = Field(..., pattern="^(code|text|image)$")
    content: Optional[str] = Field(None, max_length=500_000)  # For code/text
    language: Optional[str] = None     # For code scans
    image_data: Optional[str] = None   # Base64 image data


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    message: str


class ScanIssue(BaseModel):
    severity: str
    name: str
    location: Optional[str] = None
    description: str
    snippet: Optional[str] = None
    fix: Optional[str] = None
    exploit: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: Optional[str] = None
    attack_vector: Optional[str] = None
    data_flow: Optional[list[str]] = None


class ScanResult(BaseModel):
    scan_id: uuid.UUID
    scan_type: str
    status: str
    score: Optional[int] = None
    risk_level: Optional[str] = None
    issues: list[ScanIssue] = []
    summary: Optional[dict] = None
    recommendations: list[str] = []
    engine_version: str = "1.0.0"
    processing_time_ms: Optional[float] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: uuid.UUID
    scan_type: str
    status: str
    score: Optional[int] = None
    risk_level: Optional[str] = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  DASHBOARD SCHEMAS
# ═══════════════════════════════════════════════════════════
class DashboardStats(BaseModel):
    total_scans: int
    average_score: Optional[float] = None
    scans_this_month: int
    quota_remaining: int
    severity_breakdown: dict
    scan_type_breakdown: dict
    recent_scans: list[ScanListItem]


# ═══════════════════════════════════════════════════════════
#  GENERIC SCHEMAS
# ═══════════════════════════════════════════════════════════
class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str
