"""
SecureScan Backend — Scan Orchestrator
Coordinates analysis engines, LLM enrichment, and result assembly
"""

import time
from typing import Optional

from app.engines.code_analyzer import analyze_code
from app.engines.text_analyzer import analyze_text
from app.engines.image_analyzer import analyze_image
from app.engines.llm_engine import analyze_with_llm


async def run_scan(scan_type: str, content: str, language: Optional[str] = None) -> dict:
    """
    Run a complete security scan.
    Orchestrates the appropriate engine, optionally enriches with LLM.
    Returns the full result dict.
    """
    start = time.time()

    # Phase 1: Run the appropriate engine
    if scan_type == "code":
        result = analyze_code(content, language)
    elif scan_type == "text":
        result = analyze_text(content)
    elif scan_type == "image":
        result = analyze_image(content)
    else:
        return {"error": f"Unknown scan type: {scan_type}"}

    # Phase 2: LLM enrichment (optional)
    try:
        llm_result = await analyze_with_llm(content, scan_type, result.get("issues", []))
        result["llm_analysis"] = llm_result

        # Merge additional findings from LLM
        if llm_result.get("status") == "success":
            analysis = llm_result.get("analysis", {})
            additional = analysis.get("additional_findings", [])
            for finding in additional:
                result["issues"].append({
                    "severity": finding.get("severity", "medium"),
                    "name": finding.get("name", "LLM Finding"),
                    "description": finding.get("description", ""),
                    "location": finding.get("line", "LLM Analysis"),
                    "fix": finding.get("fix", ""),
                    "cwe": finding.get("cwe"),
                    "confidence": "llm",
                    "attack_vector": "network",
                })
            if analysis.get("risk_assessment"):
                result["recommendations"].append(f"LLM Assessment: {analysis['risk_assessment']}")
    except Exception:
        result["llm_analysis"] = {"status": "error", "reason": "LLM analysis failed"}

    # Phase 3: Finalize
    elapsed = (time.time() - start) * 1000
    result["processing_time_ms"] = round(elapsed, 2)
    result["engine_version"] = "1.0.0"

    # Recalculate severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in result.get("issues", []):
        sev = issue.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    result["summary"] = {"total_issues": len(result.get("issues", [])), **counts}

    return result
