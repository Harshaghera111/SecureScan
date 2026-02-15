"""
SecureScan Backend — Scan API Routes
Create scans, get results, list history, dashboard stats
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, get_optional_user
from app.models.models import User, Scan
from app.schemas.schemas import (
    ScanRequest, ScanCreateResponse, ScanResult, ScanIssue,
    ScanListItem, DashboardStats, MessageResponse,
)
from app.services.scan_service import run_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResult)
async def create_scan(
    req: ScanRequest,
    user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Run a security scan. Supports code, text, and image types.
    Auth is optional — unauthenticated scans are allowed but not persisted.
    """
    content = req.content or req.image_data
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Content or image_data is required")

    # Run the analysis
    result = await run_scan(req.scan_type, content, req.language)

    if "error" in result:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result["error"])

    # Persist if authenticated
    scan_id = uuid.uuid4()
    if user:
        scan = Scan(
            id=scan_id,
            user_id=user.id,
            scan_type=req.scan_type,
            status="completed",
            input_snippet=content[:500] if req.scan_type != "image" else "[image data]",
            language=result.get("language"),
            result=result,
            score=result.get("score", 0),
            risk_level=result.get("risk_level", "low"),
            critical_count=result.get("summary", {}).get("critical", 0),
            high_count=result.get("summary", {}).get("high", 0),
            medium_count=result.get("summary", {}).get("medium", 0),
            low_count=result.get("summary", {}).get("low", 0),
            processing_time_ms=result.get("processing_time_ms"),
        )
        db.add(scan)
        await db.flush()

        # Update user scan count
        user.scans_used += 1
        db.add(user)

    # Build response
    issues = [
        ScanIssue(
            severity=i.get("severity", "low"),
            name=i.get("name", "Unknown"),
            location=i.get("location"),
            description=i.get("description", ""),
            snippet=i.get("snippet"),
            fix=i.get("fix"),
            exploit=i.get("exploit"),
            remediation=i.get("remediation"),
            cwe=i.get("cwe"),
            owasp=i.get("owasp"),
            confidence=i.get("confidence"),
            attack_vector=i.get("attack_vector"),
            data_flow=i.get("data_flow"),
        )
        for i in result.get("issues", [])
    ]

    return ScanResult(
        scan_id=scan_id,
        scan_type=req.scan_type,
        status="completed",
        score=result.get("score"),
        risk_level=result.get("risk_level"),
        issues=issues,
        summary=result.get("summary"),
        recommendations=result.get("recommendations", []),
        engine_version=result.get("engine_version", "1.0.0"),
        processing_time_ms=result.get("processing_time_ms"),
    )


@router.get("/history", response_model=list[ScanListItem])
async def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    scan_type: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the authenticated user's scan history."""
    query = select(Scan).where(Scan.user_id == user.id).order_by(desc(Scan.created_at))
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()
    return [ScanListItem.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan_result(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific scan result by ID."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    stored = scan.result or {}
    issues = [
        ScanIssue(
            severity=i.get("severity", "low"),
            name=i.get("name", "Unknown"),
            location=i.get("location"),
            description=i.get("description", ""),
            snippet=i.get("snippet"),
            fix=i.get("fix"),
            exploit=i.get("exploit"),
            remediation=i.get("remediation"),
            cwe=i.get("cwe"),
            owasp=i.get("owasp"),
            confidence=i.get("confidence"),
            attack_vector=i.get("attack_vector"),
            data_flow=i.get("data_flow"),
        )
        for i in stored.get("issues", [])
    ]

    return ScanResult(
        scan_id=scan.id,
        scan_type=scan.scan_type,
        status=scan.status,
        score=scan.score,
        risk_level=scan.risk_level,
        issues=issues,
        summary=stored.get("summary"),
        recommendations=stored.get("recommendations", []),
        engine_version=scan.engine_version,
        processing_time_ms=scan.processing_time_ms,
        created_at=scan.created_at,
    )


@router.delete("/{scan_id}", response_model=MessageResponse)
async def delete_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan by ID."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    await db.delete(scan)
    return MessageResponse(message="Scan deleted successfully")


@router.get("/stats/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard analytics for the current user."""
    # Total scans
    total_result = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id)
    )
    total_scans = total_result.scalar() or 0

    # Average score
    avg_result = await db.execute(
        select(func.avg(Scan.score)).where(Scan.user_id == user.id, Scan.score.isnot(None))
    )
    avg_score = avg_result.scalar()

    # Severity breakdown
    sev_result = await db.execute(
        select(
            func.sum(Scan.critical_count),
            func.sum(Scan.high_count),
            func.sum(Scan.medium_count),
            func.sum(Scan.low_count),
        ).where(Scan.user_id == user.id)
    )
    sev_row = sev_result.one()

    # Scan type breakdown
    type_counts = {}
    for scan_type in ["code", "text", "image"]:
        count_result = await db.execute(
            select(func.count()).select_from(Scan).where(
                Scan.user_id == user.id, Scan.scan_type == scan_type
            )
        )
        type_counts[scan_type] = count_result.scalar() or 0

    # Recent scans
    recent_result = await db.execute(
        select(Scan).where(Scan.user_id == user.id)
        .order_by(desc(Scan.created_at)).limit(10)
    )
    recent_scans = recent_result.scalars().all()

    return DashboardStats(
        total_scans=total_scans,
        average_score=round(float(avg_score), 1) if avg_score else None,
        scans_this_month=total_scans,  # Simplified for now
        quota_remaining=max(0, user.scan_quota - user.scans_used),
        severity_breakdown={
            "critical": int(sev_row[0] or 0),
            "high": int(sev_row[1] or 0),
            "medium": int(sev_row[2] or 0),
            "low": int(sev_row[3] or 0),
        },
        scan_type_breakdown=type_counts,
        recent_scans=[ScanListItem.model_validate(s) for s in recent_scans],
    )
