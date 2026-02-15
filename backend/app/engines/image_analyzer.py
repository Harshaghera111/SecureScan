"""
SecureScan Backend — Image Analysis Engine
Port of image-analyzer.js: ELA simulation, noise analysis,
LBP texture, symmetry, GAN artifacts, chromatic aberration
Server-side Pillow-based analysis (replaces canvas heuristics)
"""

import io
import math
import base64
from typing import Optional

import numpy as np
from PIL import Image


# ═══════════════════════════════════════════════════════════
#  MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════
def analyze_image(image_data: str) -> dict:
    """
    Analyze an image for deepfake/manipulation indicators.
    Accepts base64-encoded image data.
    Returns a structured result dict.
    """
    issues = []
    signals = {}
    suspicion = 0

    try:
        # Decode base64 image
        if "," in image_data:
            image_data = image_data.split(",", 1)[1]
        image_bytes = base64.b64decode(image_data)
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return _build_result([{
            "severity": "medium", "name": "Image Load Failed", "location": "Input",
            "description": "Image could not be decoded for analysis.",
            "snippet": "Invalid image data",
            "fix": "Re-upload in JPEG, PNG, or WebP format.",
            "confidence": "confirmed",
        }], "image", 0)

    # Resize for analysis
    MAX_DIM = 512
    w, h = img.size
    original_w, original_h = w, h
    scale = min(1, MAX_DIM / max(w, h))
    if scale < 1:
        w, h = int(w * scale), int(h * scale)
        img = img.resize((w, h), Image.LANCZOS)

    px = np.array(img, dtype=np.float32)  # (H, W, 3)
    total_px = w * h

    # ── CHECK 1: Noise Distribution Analysis ──
    noise_count = 0
    edge_count = 0
    smooth_count = 0
    total_diff = 0.0

    for y in range(h):
        row = px[y]
        for x in range(w - 1):
            diff = float(np.abs(row[x] - row[x + 1]).sum())
            total_diff += diff
            if 1 < diff < 8:
                noise_count += 1
            elif diff > 60:
                edge_count += 1
            elif diff == 0:
                smooth_count += 1

    noise_ratio = noise_count / total_px
    edge_ratio = edge_count / total_px
    smooth_ratio = smooth_count / total_px
    signals["noise"] = noise_ratio
    signals["edges"] = edge_ratio
    signals["smooth"] = smooth_ratio

    if 0.3 < noise_ratio < 0.7:
        suspicion += 18
        issues.append({
            "severity": "medium", "name": "Uniform Micro-Noise Pattern", "location": "Pixel analysis",
            "description": f"{noise_ratio * 100:.1f}% of adjacent pixels show micro-noise (1-8 diff). AI images have unnaturally uniform noise.",
            "snippet": f"Noise: {noise_ratio * 100:.1f}% | Edges: {edge_ratio * 100:.1f}% | Smooth: {smooth_ratio * 100:.1f}%",
            "fix": "AI models produce noise patterns unlike camera sensors.",
            "confidence": "likely",
        })

    if edge_ratio < 0.03:
        suspicion += 12
        issues.append({
            "severity": "medium", "name": "Unusually Smooth Image", "location": "Edge analysis",
            "description": f"Only {edge_ratio * 100:.1f}% edge pixels. Natural photos: 5-20%.",
            "snippet": f"Edge density: {edge_ratio * 100:.1f}%",
            "fix": "Over-smoothed images may be AI-generated. Request the original.",
            "confidence": "likely",
        })

    # ── CHECK 2: ELA Simulation ──
    try:
        small_w, small_h = max(1, w // 2), max(1, h // 2)
        small_img = img.resize((small_w, small_h), Image.LANCZOS)
        ela_img = small_img.resize((w, h), Image.LANCZOS)
        ela_px = np.array(ela_img, dtype=np.float32)

        region_size = 32
        region_errors = []
        ela_total = 0.0

        for ry in range(0, h, region_size):
            for rx in range(0, w, region_size):
                re_h = min(region_size, h - ry)
                re_w = min(region_size, w - rx)
                orig_region = px[ry:ry + re_h, rx:rx + re_w]
                ela_region = ela_px[ry:ry + re_h, rx:rx + re_w]
                diff = np.abs(orig_region - ela_region).sum()
                count = re_h * re_w
                avg_err = diff / max(count, 1)
                region_errors.append(avg_err)
                ela_total += diff

        ela_avg = ela_total / total_px
        ela_max = max(region_errors) if region_errors else 0
        ela_min = min(region_errors) if region_errors else 0
        ela_variance = sum((e - ela_avg) ** 2 for e in region_errors) / max(len(region_errors), 1)
        ela_std = math.sqrt(ela_variance)

        signals["ela"] = {"avg": ela_avg, "max": ela_max, "min": ela_min, "std": ela_std}

        if ela_std > 15 and (ela_max / max(ela_min, 0.01)) > 3:
            suspicion += 22
            issues.append({
                "severity": "high", "name": "ELA: Region Inconsistency Detected", "location": "Error Level Analysis",
                "description": f"Different regions show different compression errors (σ={ela_std:.1f}). Indicates editing.",
                "snippet": f"ELA σ: {ela_std:.1f} | Max/Min: {ela_max / max(ela_min, 0.01):.1f}x | Regions: {len(region_errors)}",
                "fix": "Different compression levels suggest image manipulation.",
                "confidence": "likely",
            })

        if ela_avg < 5 and ela_std < 3:
            suspicion += 15
            issues.append({
                "severity": "medium", "name": "ELA: Uniform Low Error (AI Signature)", "location": "Error Level Analysis",
                "description": f"Uniformly low compression error (avg={ela_avg:.1f}, σ={ela_std:.1f}). AI images were never JPEG-compressed.",
                "snippet": f"ELA Average: {ela_avg:.1f} | Expected for real photos: >10",
                "fix": "This pattern is consistent with AI-generated imagery.",
                "confidence": "likely",
            })
    except Exception:
        pass

    # ── CHECK 3: Color Distribution ──
    color_hist = np.zeros(64, dtype=int)
    for y in range(h):
        for x in range(w):
            r, g, b = px[y, x].astype(int)
            bin_idx = (r // 64) * 16 + (g // 64) * 4 + b // 64
            if 0 <= bin_idx < 64:
                color_hist[bin_idx] += 1

    used_bins = int(np.count_nonzero(color_hist))
    signals["color_bins"] = used_bins

    if used_bins < 16:
        suspicion += 8
        issues.append({
            "severity": "low", "name": "Limited Color Palette", "location": "Color analysis",
            "description": f"Only {used_bins}/64 color bins used. Natural photos: 30+.",
            "snippet": f"Color bins: {used_bins}/64",
            "fix": "Limited palettes suggest generation or heavy processing.",
            "confidence": "possible",
        })

    # ── CHECK 4: Bilateral Symmetry ──
    sym_score = 0
    sym_total = 0
    mid_x = w // 2
    for y in range(0, h, 3):
        for x in range(0, mid_x, 3):
            mirror_x = w - 1 - x
            if mirror_x < w:
                diff = float(np.abs(px[y, x] - px[y, mirror_x]).sum())
                if diff < 30:
                    sym_score += 1
                sym_total += 1

    sym_ratio = sym_score / max(sym_total, 1)
    signals["symmetry"] = sym_ratio

    if sym_ratio > 0.55:
        suspicion += 15
        issues.append({
            "severity": "medium", "name": "Unnaturally High Symmetry", "location": "Symmetry analysis",
            "description": f"{sym_ratio * 100:.1f}% bilateral symmetry. Real faces: 20-45%.",
            "snippet": f"Symmetry: {sym_ratio * 100:.1f}% | Samples: {sym_total}",
            "fix": "GAN-generated faces are often unnaturally symmetric.",
            "confidence": "likely" if sym_ratio > 0.7 else "possible",
        })

    # ── CHECK 5: LBP Texture ──
    gray = np.dot(px, [0.299, 0.587, 0.114]).astype(np.float32)
    lbp_hist = np.zeros(256, dtype=int)

    for y in range(1, h - 1, 2):
        for x in range(1, w - 1, 2):
            center = gray[y, x]
            neighbors = [
                gray[y - 1, x - 1], gray[y - 1, x], gray[y - 1, x + 1],
                gray[y, x + 1], gray[y + 1, x + 1], gray[y + 1, x],
                gray[y + 1, x - 1], gray[y, x - 1],
            ]
            lbp = 0
            for b, n in enumerate(neighbors):
                if n >= center:
                    lbp |= (1 << b)
            lbp_hist[lbp] += 1

    lbp_total = int(lbp_hist.sum())
    lbp_nonzero = lbp_hist[lbp_hist > 0].astype(np.float64)
    if lbp_total > 0 and len(lbp_nonzero) > 0:
        probs = lbp_nonzero / lbp_total
        lbp_entropy = float(-np.sum(probs * np.log2(probs)))
    else:
        lbp_entropy = 0.0

    signals["lbp_entropy"] = lbp_entropy

    if lbp_entropy < 4.0:
        suspicion += 12
        issues.append({
            "severity": "medium", "name": "Low Texture Complexity (LBP)", "location": "Texture analysis",
            "description": f"LBP entropy {lbp_entropy:.2f} bits (natural: 5-7 bits).",
            "snippet": f"LBP Entropy: {lbp_entropy:.2f} bits",
            "fix": "AI images often have smoother, more uniform textures.",
            "confidence": "likely",
        })

    # ── CHECK 6: GAN Grid Artifacts ──
    grid_size = 16
    repeat_count = 0
    grid_checks = 0
    for y in range(0, h - grid_size, grid_size):
        for x in range(0, w - grid_size, grid_size):
            diff = float(np.abs(px[y, x] - px[y + grid_size, x]).sum())
            if diff < 5:
                repeat_count += 1
            grid_checks += 1

    repeat_ratio = repeat_count / max(grid_checks, 1)
    signals["grid_repeat"] = repeat_ratio

    if repeat_ratio > 0.35:
        suspicion += 18
        issues.append({
            "severity": "high", "name": "GAN Grid Artifacts Detected", "location": "Pattern analysis",
            "description": f"{repeat_ratio * 100:.1f}% of {grid_size}px blocks show repeating patterns.",
            "snippet": f"Repeat ratio: {repeat_ratio * 100:.1f}% | Grid: {grid_size}px",
            "fix": "Zoom to 400%+ and look for subtle repeating textures.",
            "confidence": "likely",
        })

    # ── CHECK 7: Chromatic Aberration ──
    chr_count = 0
    chr_total = 0
    for y in range(0, h, 4):
        for x in range(1, w - 1, 4):
            l_px = px[y, x - 1]
            r_px = px[y, x + 1]
            r_shift = abs((r_px[0] - l_px[0]) - (r_px[1] - l_px[1]))
            b_shift = abs((r_px[2] - l_px[2]) - (r_px[1] - l_px[1]))
            if r_shift > 10 or b_shift > 10:
                chr_count += 1
            chr_total += 1

    chr_ratio = chr_count / max(chr_total, 1)
    signals["chromatic_aberration"] = chr_ratio

    if chr_ratio < 0.02 and total_px > 10000:
        suspicion += 8
        issues.append({
            "severity": "low", "name": "No Lens Chromatic Aberration", "location": "Optical analysis",
            "description": f"Chromatic aberration: {chr_ratio * 100:.2f}%. Real lenses produce >2%.",
            "snippet": f"CA: {chr_ratio * 100:.2f}%",
            "fix": "All real camera lenses produce some color fringing.",
            "confidence": "possible",
        })

    # ── CHECK 8: Aspect Ratio ──
    aspect = original_w / max(original_h, 1)
    ai_ratios = [1.0, 0.75, 1.333, 0.5625, 1.778, 0.667, 1.5]
    is_ai_ratio = any(abs(aspect - r) < 0.015 for r in ai_ratios)

    if is_ai_ratio:
        suspicion += 3
        issues.append({
            "severity": "low", "name": "Common AI Output Dimensions", "location": "Image dimensions",
            "description": f"Aspect ratio {aspect:.3f} matches common AI formats. {original_w}×{original_h}.",
            "snippet": f"{original_w}×{original_h} | Ratio: {aspect:.3f}",
            "fix": "This ratio is commonly used by DALL·E, Midjourney, Stable Diffusion.",
            "confidence": "possible",
        })

    # ── Multi-Signal Fusion ──
    suspicion = min(95, suspicion)

    if not issues:
        issues.append({
            "severity": "low", "name": "No Strong Manipulation Indicators", "location": "Full image",
            "description": "No strong indicators of AI generation or manipulation found.",
            "snippet": f"Noise: {noise_ratio * 100:.1f}% | Edges: {edge_ratio * 100:.1f}% | Symmetry: {sym_ratio * 100:.1f}% | LBP: {lbp_entropy:.2f}",
            "fix": "For highest confidence, use ML-based deepfake detection.",
            "confidence": "confirmed",
        })
        suspicion = max(suspicion, 8)

    if suspicion >= 50:
        issues.insert(0, {
            "severity": "critical", "name": "High Probability of AI Generation/Manipulation",
            "location": "Multi-signal fusion",
            "description": f"Combined analysis: {suspicion}% suspicion across {len(signals)} signals.",
            "snippet": f"Suspicion: {suspicion}%",
            "fix": "Do not use for identity verification. Cross-verify with multiple tools.",
            "confidence": "likely" if suspicion >= 70 else "possible",
        })
    elif suspicion >= 30:
        issues.insert(0, {
            "severity": "high", "name": "Moderate Manipulation Indicators",
            "location": "Multi-signal fusion",
            "description": f"Combined analysis yields {suspicion}% suspicion.",
            "snippet": f"Suspicion: {suspicion}% | {len(signals)} signals analyzed",
            "fix": "Exercise caution. Run through additional detection tools.",
            "confidence": "possible",
        })

    return _build_result(issues, "image", suspicion)


# ═══════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _build_result(issues: list, scan_type: str, suspicion: int = 0) -> dict:
    sev_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    total_weight = sum(sev_weights.get(i.get("severity", "low"), 3) for i in issues)

    score = suspicion if suspicion > 0 else min(95, max(5, int(total_weight * 1.5)))

    risk_level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        severity_counts[i.get("severity", "low")] = severity_counts.get(i.get("severity", "low"), 0) + 1

    return {
        "scan_type": scan_type,
        "score": score,
        "risk_level": risk_level,
        "issues": issues,
        "summary": {"total_issues": len(issues), **severity_counts},
        "recommendations": _generate_recommendations(issues, score),
    }


def _generate_recommendations(issues: list, score: int) -> list[str]:
    recs = []
    if score >= 50:
        recs.append("High probability of AI generation or manipulation. Do not use for verification.")
    names = {i.get("name", "") for i in issues}
    if any("ELA" in n for n in names):
        recs.append("Error Level Analysis detected regions with different compression levels.")
    if any("GAN" in n for n in names):
        recs.append("GAN grid artifacts suggest this image was generated by a neural network.")
    if any("Symmetry" in n for n in names):
        recs.append("Unusually high facial symmetry is a common deepfake indicator.")
    if not recs:
        recs.append("No strong indicators found. For highest confidence, use ML-based detection.")
    return recs
