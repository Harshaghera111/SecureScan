"""
SecureScan Backend — LLM Engine
Supports OpenAI, Gemini, and a mock mode for development.
Provides security-focused analysis via LLM APIs.
"""

import json
from typing import Optional

from app.config import get_settings

settings = get_settings()


async def analyze_with_llm(content: str, scan_type: str, initial_findings: list) -> dict:
    """
    Send content + initial findings to an LLM for deeper security analysis.
    Returns structured findings from the LLM.
    """
    provider = settings.LLM_PROVIDER.lower()

    if provider == "openai":
        return await _openai_analyze(content, scan_type, initial_findings)
    elif provider == "gemini":
        return await _gemini_analyze(content, scan_type, initial_findings)
    else:
        return _mock_analyze(content, scan_type, initial_findings)


async def _openai_analyze(content: str, scan_type: str, initial_findings: list) -> dict:
    """Analyze using OpenAI GPT-4o."""
    if not settings.OPENAI_API_KEY:
        return {"llm_provider": "openai", "status": "skipped", "reason": "No API key configured"}

    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        prompt = _build_prompt(content, scan_type, initial_findings)

        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity analyst. Respond only with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
            response_format={"type": "json_object"},
        )

        result_text = response.choices[0].message.content
        return {"llm_provider": "openai", "status": "success", "analysis": json.loads(result_text)}
    except Exception as e:
        return {"llm_provider": "openai", "status": "error", "reason": str(e)}


async def _gemini_analyze(content: str, scan_type: str, initial_findings: list) -> dict:
    """Analyze using Google Gemini 1.5 Pro."""
    if not settings.GEMINI_API_KEY:
        return {"llm_provider": "gemini", "status": "skipped", "reason": "No API key configured"}

    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-pro")

        prompt = _build_prompt(content, scan_type, initial_findings)

        response = await model.generate_content_async(
            prompt,
            generation_config=genai.GenerationConfig(temperature=0.1, max_output_tokens=4096),
        )

        return {"llm_provider": "gemini", "status": "success", "analysis": json.loads(response.text)}
    except Exception as e:
        return {"llm_provider": "gemini", "status": "error", "reason": str(e)}


def _mock_analyze(content: str, scan_type: str, initial_findings: list) -> dict:
    """Mock LLM analysis for development/testing."""
    return {
        "llm_provider": "mock",
        "status": "success",
        "analysis": {
            "summary": f"Mock LLM analysis for {scan_type} content. "
                       f"Found {len(initial_findings)} initial issues from static analysis.",
            "additional_findings": [],
            "risk_assessment": "Based on static analysis findings only (LLM in mock mode).",
            "confidence": "low",
        },
    }


def _build_prompt(content: str, scan_type: str, initial_findings: list) -> str:
    """Build the analysis prompt for the LLM."""
    truncated = content[:8000] if len(content) > 8000 else content
    findings_summary = json.dumps(initial_findings[:20], indent=2) if initial_findings else "None"

    if scan_type == "code":
        return f"""Analyze the following code for security vulnerabilities. Our static analyzer found these initial issues:

Initial Findings:
{findings_summary}

Code to analyze:
```
{truncated}
```

Respond with JSON containing:
- "additional_findings": array of objects with severity, name, description, line (if applicable), cwe, fix
- "risk_assessment": overall risk assessment string
- "confidence": "high", "medium", or "low"
"""
    elif scan_type == "text":
        return f"""Analyze the following text for phishing, social engineering, or scam indicators:

Initial Findings:
{findings_summary}

Text to analyze:
{truncated}

Respond with JSON containing:
- "additional_findings": array of objects with severity, name, description, fix
- "risk_assessment": overall risk assessment string
- "confidence": "high", "medium", or "low"
"""
    else:
        return f"""Analyze the following image analysis results for deepfake/manipulation indicators:

Initial Findings:
{findings_summary}

Respond with JSON containing:
- "risk_assessment": overall risk assessment string
- "confidence": "high", "medium", or "low"
"""
