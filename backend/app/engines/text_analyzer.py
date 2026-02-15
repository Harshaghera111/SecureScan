"""
SecureScan Backend — Text Analysis Engine
Port of text-analyzer.js: URL analysis, phishing detection, social engineering,
PII solicitation, crypto scam detection, AI text detection
"""

import re
import math
from typing import Optional


# ═══════════════════════════════════════════════════════════
#  BRAND & HOMOGLYPH DATA
# ═══════════════════════════════════════════════════════════
BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "facebook", "meta", "twitter",
    "instagram", "netflix", "youtube", "linkedin", "github", "dropbox", "slack", "zoom",
    "spotify", "uber", "lyft", "airbnb", "stripe", "shopify", "wordpress", "adobe",
    "salesforce", "oracle", "cisco", "nvidia", "samsung", "sony", "whatsapp", "telegram",
    "signal", "snapchat", "tiktok", "reddit", "pinterest", "ebay", "walmart", "target",
    "bestbuy", "costco", "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "americanexpress", "venmo", "cashapp", "zelle", "coinbase", "binance", "kraken",
]

HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "і": "i", "ј": "j",
    "ɡ": "g", "ɩ": "l", "ʀ": "r", "ꮃ": "w", "ꭰ": "d", "ꮪ": "s", "ꮋ": "h",
    "0": "o", "1": "l", "!": "i", "|": "l", "ℓ": "l", "ƒ": "f", "ɑ": "a", "ο": "o",
    "ν": "v", "τ": "t", "κ": "k", "η": "n", "ω": "w", "ρ": "p", "χ": "x",
}

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club", ".work",
    ".click", ".link", ".info", ".online", ".site", ".icu", ".vip", ".win", ".loan",
    ".racing", ".stream", ".download", ".cricket", ".science", ".party", ".gdn",
    ".men", ".bid", ".trade", ".webcam", ".date", ".review", ".accountant",
]

SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "shorturl.at", "rb.gy", "cutt.ly"]


# ═══════════════════════════════════════════════════════════
#  UTILITY: Levenshtein Distance
# ═══════════════════════════════════════════════════════════
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ═══════════════════════════════════════════════════════════
#  MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════
def analyze_text(text: str) -> dict:
    """
    Analyze text for phishing, scam, social engineering, and threats.
    Returns a structured result dict.
    """
    issues = []
    lower_text = text.lower()
    words = text.split()
    sentences = [s.strip() for s in re.split(r'[.!?]+', text) if len(s.strip()) > 3]

    # ── PHASE 1: URL Analysis ──
    url_regex = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
    urls = url_regex.findall(text)

    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            hostname = hostname.lower()

            # Suspicious TLD
            has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

            # Typosquatting (Levenshtein)
            host_parts = re.sub(r'\.(com|org|net|io|co|xyz|top|info|dev|app).*$', '', hostname).replace('www.', '')
            closest_brand = None
            closest_dist = float('inf')
            for brand in BRANDS:
                dist = _levenshtein(host_parts, brand)
                if 0 < dist <= 2 and dist < closest_dist:
                    closest_brand = brand
                    closest_dist = dist

            # Homoglyph check
            de_homoglyphed = ''.join(HOMOGLYPHS.get(ch, ch) for ch in hostname)
            has_homoglyphs = de_homoglyphed != hostname
            homoglyph_brand = None
            if has_homoglyphs:
                clean_host = re.sub(r'\.(com|org|net|io).*$', '', de_homoglyphed).replace('www.', '')
                homoglyph_brand = next((b for b in BRANDS if b in clean_host), None)

            # IP address
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
            subdomain_count = len(hostname.split('.')) - 2
            has_at = '@' in url
            is_shortened = any(s in hostname for s in SHORTENERS)

            if homoglyph_brand:
                issues.append({
                    "severity": "critical", "name": "Homoglyph Phishing Domain", "location": "URL in text",
                    "description": f'URL "{hostname}" uses lookalike Unicode characters to impersonate "{homoglyph_brand}".',
                    "snippet": f"Original: {hostname}\nDe-homoglyphed: {de_homoglyphed}\nTarget brand: {homoglyph_brand}",
                    "fix": "Do NOT click it. Report it to the brand's security team.",
                    "confidence": "confirmed",
                })
            elif closest_brand:
                issues.append({
                    "severity": "critical", "name": "Typosquatted Domain Detected", "location": "URL in text",
                    "description": f'"{hostname}" is {closest_dist} char(s) from "{closest_brand}.com" — likely typosquatting.',
                    "snippet": f"{url}\nLevenshtein distance from '{closest_brand}': {closest_dist}",
                    "fix": "Do NOT click. Navigate to the official website by typing the URL yourself.",
                    "confidence": "confirmed",
                })
            if has_suspicious_tld:
                issues.append({
                    "severity": "high", "name": "Suspicious TLD in URL", "location": "URL in text",
                    "description": "URL uses a TLD commonly associated with phishing/scam campaigns.",
                    "snippet": url, "fix": "Verify through official channels.",
                    "confidence": "likely",
                })
            if is_ip:
                issues.append({
                    "severity": "high", "name": "IP-Based URL (No Domain)", "location": "URL in text",
                    "description": f"URL uses raw IP ({hostname}) instead of a domain name.",
                    "snippet": url, "fix": "Legitimate websites use domain names.",
                    "confidence": "confirmed",
                })
            if subdomain_count >= 3:
                issues.append({
                    "severity": "medium", "name": "Excessive Subdomains in URL", "location": "URL in text",
                    "description": f"{subdomain_count} subdomains detected — may hide the real destination.",
                    "snippet": url, "fix": "Look at the actual domain just before the TLD.",
                    "confidence": "likely",
                })
            if is_shortened:
                issues.append({
                    "severity": "medium", "name": "Shortened URL Detected", "location": "URL in text",
                    "description": f"URL shortener '{hostname}' hides the real destination.",
                    "snippet": url, "fix": "Use a URL expander tool before clicking.",
                    "confidence": "likely",
                })
            if has_at:
                issues.append({
                    "severity": "high", "name": "URL Contains @ Symbol", "location": "URL in text",
                    "description": "@ in URL causes browsers to ignore everything before it.",
                    "snippet": url, "fix": "Never click URLs with @ symbols.",
                    "confidence": "confirmed",
                })
            if parsed.scheme == "http" and not is_ip and hostname != "localhost":
                issues.append({
                    "severity": "low", "name": "Insecure HTTP Link", "location": "URL in text",
                    "description": "URL uses HTTP instead of HTTPS.",
                    "snippet": url, "fix": "Legitimate sites use HTTPS.",
                    "confidence": "confirmed",
                })
        except Exception:
            pass

    # ── PHASE 2: Social Engineering & Urgency ──
    urgency_patterns = [
        {"regex": re.compile(r'\b(urgent|immediately|right now|act now|right away|asap|time.sensitive)\b', re.I), "name": "Urgency Language", "sev": "high"},
        {"regex": re.compile(r'\b(suspend|terminat|delet|disabl|block|lock|freez|cancel|restrict|deactivat)\w*\s+(your|the|this)\s+(account|access|service|card|wallet)', re.I), "name": "Account Threat", "sev": "high"},
        {"regex": re.compile(r'\b(within|in)\s+\d+\s*(hour|minute|day|hr|min)s?\b', re.I), "name": "Time Pressure", "sev": "medium"},
        {"regex": re.compile(r'\b(permanent|irreversible|cannot be undone|final warning|last chance|last notice|immediate action required)\b', re.I), "name": "Finality Threat", "sev": "high"},
        {"regex": re.compile(r'\b(legal action|law enforcement|arrest|warrant|prosecution|federal|irs|fbi)\b', re.I), "name": "Legal/Authority Threat", "sev": "high"},
        {"regex": re.compile(r'\b(won|winner|congratulat|lottery|prize|selected|lucky|inheritance|million\s*dollar)\b', re.I), "name": "Prize/Lottery Scam Language", "sev": "high"},
    ]
    for pat in urgency_patterns:
        matches = pat["regex"].findall(text)
        if matches:
            issues.append({
                "severity": pat["sev"], "name": f"{pat['name']} Detected", "location": "Message body",
                "description": f'Social engineering tactic: "{matches[0]}" pressures you into acting.',
                "snippet": ", ".join(matches[:3]),
                "fix": "Legitimate organizations rarely use extreme urgency.",
                "confidence": "confirmed",
            })

    # ── PHASE 3: PII Solicitation ──
    pii_patterns = [
        {"regex": re.compile(r'\b(social\s+security|ssn|tax\s+id|tin\b|taxpayer)', re.I), "label": "Social Security / Tax ID", "sev": "critical"},
        {"regex": re.compile(r'\b(credit\s+card|debit\s+card|card\s+number|cvv|cvc|expir\w*\s+date|billing\s+address)', re.I), "label": "Credit/Debit Card Details", "sev": "critical"},
        {"regex": re.compile(r'\b(bank\s+account|routing\s+number|swift|iban|wire\s+transfer|account\s+number)', re.I), "label": "Banking Information", "sev": "critical"},
        {"regex": re.compile(r'\b(password|passcode|pin\s+number|login\s+credential|security\s+question|secret\s+answer)', re.I), "label": "Login Credentials", "sev": "critical"},
        {"regex": re.compile(r"\b(date\s+of\s+birth|mother'?s?\s+maiden|passport\s+number|driver'?s?\s+licen|national\s+id)", re.I), "label": "Personal Identity Data", "sev": "high"},
    ]
    found_pii = [p["label"] for p in pii_patterns if p["regex"].search(text)]
    if found_pii:
        issues.append({
            "severity": "critical", "name": "Requests Sensitive Personal Data", "location": "Message body",
            "description": f"Text solicits: {', '.join(found_pii)}. No legitimate org requests this via email.",
            "snippet": "\n".join(found_pii),
            "fix": "NEVER share SSN, passwords, credit cards, or ID photos via email.",
            "confidence": "confirmed",
        })

    # ── PHASE 4: Brand Impersonation ──
    email_regex = re.compile(r'[\w.+-]+@[\w.-]+\.\w+', re.I)
    emails = email_regex.findall(text)
    for email in emails:
        domain = email.split('@')[1].lower()
        domain_base = re.sub(r'\.(com|org|net|io|co).*$', '', domain)
        for brand in BRANDS:
            dist = _levenshtein(domain_base, brand)
            if 0 < dist <= 2:
                issues.append({
                    "severity": "critical", "name": "Spoofed Sender Email", "location": "Email address",
                    "description": f'"{email}" impersonates {brand} (distance: {dist}).',
                    "snippet": f"{email}\nExpected: @{brand}.com",
                    "fix": f"Official {brand} emails come from @{brand}.com.",
                    "confidence": "confirmed",
                })
                break

    # Authority impersonation
    authority_patterns = [
        re.compile(r'\b(ceo|chief\s+executive|managing\s+director|president|chairman|cfo|cto)\b', re.I),
        re.compile(r'\b(irs|internal\s+revenue|tax\s+authority|hmrc|federal\s+reserve)\b', re.I),
        re.compile(r'\b(tech\s+support|customer\s+service|security\s+team|fraud\s+department)\b', re.I),
    ]
    for pat in authority_patterns:
        m = pat.search(text)
        if m and any(w in lower_text for w in ["urgent", "confidential", "wire", "transfer"]):
            issues.append({
                "severity": "high", "name": "Authority Impersonation Detected", "location": "Message body",
                "description": f'Invokes "{m.group(0)}" with urgency/financial language. BEC pattern.',
                "snippet": m.group(0),
                "fix": "Verify through official channels. Call using a known phone number.",
                "confidence": "likely",
            })
            break

    # Generic greeting
    if re.search(r'\b(dear\s+(valued\s+)?customer|dear\s+(valued\s+)?user|dear\s+account\s+holder)\b', text, re.I):
        issues.append({
            "severity": "low", "name": "Generic Greeting", "location": "Opening",
            "description": "Uses a generic greeting instead of your name.",
            "fix": "Legitimate companies personalize communications.",
            "confidence": "likely",
        })

    # ── PHASE 5: Crypto Scams ──
    crypto_patterns = [
        {"regex": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'), "name": "Bitcoin Address Detected"},
        {"regex": re.compile(r'\b0x[a-fA-F0-9]{40}\b'), "name": "Ethereum Address Detected"},
        {"regex": re.compile(r'\b(send|transfer|deposit)\s+\d+\s*(btc|eth|bitcoin|ethereum|crypto|usdt)', re.I), "name": "Crypto Transfer Request"},
        {"regex": re.compile(r'\b(guaranteed\s+return|risk.free\s+invest|double\s+your\s+(money|bitcoin|crypto)|100%\s+profit)', re.I), "name": "Investment Scam Language"},
    ]
    for pat in crypto_patterns:
        matches = pat["regex"].findall(text)
        if matches:
            match_str = matches[0] if isinstance(matches[0], str) else matches[0][0] if matches[0] else str(matches[0])
            issues.append({
                "severity": "critical", "name": pat["name"], "location": "Message body",
                "description": f'{pat["name"]}: "{match_str}". Unsolicited crypto/investment requests are almost always scams.',
                "snippet": match_str,
                "fix": "Never send cryptocurrency to unknown addresses.",
                "confidence": "confirmed",
            })

    # ── PHASE 6: Phishing Phrases ──
    phishing_phrases = [
        {"regex": re.compile(r'\bverify\s+your\s+(identity|account|information|email|payment)\b', re.I), "sev": "high"},
        {"regex": re.compile(r'\bconfirm\s+your\s+(identity|account|details|payment|ownership)\b', re.I), "sev": "high"},
        {"regex": re.compile(r'\bunauthori[sz]ed\s+(access|activity|transaction|login|attempt)\b', re.I), "sev": "high"},
        {"regex": re.compile(r'\byour\s+account\s+(has\s+been|was)\s+(compromised|hacked|breached|flagged|suspended)\b', re.I), "sev": "critical"},
        {"regex": re.compile(r'\bclick\s+(here|below|the\s+link)\s+to\s+(verify|confirm|update|restore|unlock|secure)\b', re.I), "sev": "high"},
        {"regex": re.compile(r'\b(failure\s+to\s+(comply|verify|respond)|your\s+account\s+will\s+be)\b', re.I), "sev": "high"},
    ]
    for pat in phishing_phrases:
        matches = pat["regex"].findall(text)
        if matches:
            match_str = matches[0] if isinstance(matches[0], str) else " ".join(matches[0])
            issues.append({
                "severity": pat["sev"], "name": "Common Phishing Phrase", "location": "Message body",
                "description": f'"{match_str}" is a well-known phishing trigger phrase.',
                "snippet": match_str,
                "fix": "Never click verification links in unsolicited messages.",
                "confidence": "likely",
            })

    # ── PHASE 7: AI-Generated Text Detection ──
    if len(sentences) >= 5:
        sent_lens = [len(s.split()) for s in sentences]
        avg_len = sum(sent_lens) / len(sent_lens)
        variance = sum((l - avg_len) ** 2 for l in sent_lens) / len(sent_lens)
        std_dev = math.sqrt(variance)

        all_words = re.findall(r'\b[a-z]{3,}\b', text.lower())
        unique_words = set(all_words)
        ttr = len(unique_words) / max(len(all_words), 1)

        starters = [s.split()[0].lower() for s in sentences if s.split()]
        unique_starters = set(starters)
        starter_diversity = len(unique_starters) / max(len(starters), 1)

        transitions = len(re.findall(r'\b(however|moreover|furthermore|additionally|consequently|therefore|nevertheless|in\s+conclusion|in\s+addition|as\s+a\s+result)\b', text, re.I))
        transition_density = transitions / max(len(sentences), 1)

        ai_score = 0
        ai_signals = []
        if std_dev < 4 and avg_len > 12:
            ai_score += 25
            ai_signals.append(f"Uniform sentence length (σ={std_dev:.1f}, μ={avg_len:.1f})")
        if ttr < 0.4 and len(all_words) > 50:
            ai_score += 20
            ai_signals.append(f"Low vocabulary diversity (TTR={ttr:.2f})")
        if starter_diversity < 0.5 and len(starters) > 5:
            ai_score += 15
            ai_signals.append(f"Repetitive sentence starters ({starter_diversity * 100:.0f}% unique)")
        if transition_density > 0.3:
            ai_score += 15
            ai_signals.append(f"High transition word density ({transition_density * 100:.0f}%)")

        if ai_score >= 40:
            issues.append({
                "severity": "medium", "name": "Likely AI-Generated Text", "location": "Full text",
                "description": f"Multiple signals suggest AI generation:\n" + "\n".join(f"• {s}" for s in ai_signals),
                "snippet": f"AI Score: {ai_score}/100\n" + "\n".join(ai_signals),
                "fix": "Run through dedicated AI detection tools for confirmation.",
                "confidence": "likely" if ai_score >= 60 else "possible",
            })
        elif ai_score >= 20:
            issues.append({
                "severity": "low", "name": "Possible AI-Generated Text", "location": "Full text",
                "description": f"Some signals suggest AI generation:\n" + "\n".join(f"• {s}" for s in ai_signals),
                "snippet": f"AI Score: {ai_score}/100",
                "fix": "Consider running through AI detection tools.",
                "confidence": "possible",
            })

    # ── Build result ──
    if not issues:
        issues.append({
            "severity": "low", "name": "No Threats Detected", "location": "Full text",
            "description": "No phishing, scam, or social engineering indicators found.",
            "snippet": "Text appears clean",
            "fix": "Verify the sender independently if the message asks you to take any action.",
            "confidence": "confirmed",
        })

    issues = _dedup(issues)
    _sort_by_severity(issues)
    return _build_result(issues, "text")


# ═══════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_by_severity(issues: list):
    issues.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "low"), 99))


def _dedup(issues: list) -> list:
    seen = set()
    result = []
    for issue in issues:
        key = (issue.get("name"), issue.get("location"))
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result


def _build_result(issues: list, scan_type: str) -> dict:
    sev_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    total_weight = sum(sev_weights.get(i.get("severity", "low"), 3) for i in issues)

    if not issues:
        score = 5
    else:
        score = min(95, max(5, int(total_weight * 1.5)))
        has_critical = any(i["severity"] == "critical" for i in issues)
        has_high = any(i["severity"] == "high" for i in issues)
        if not has_critical and not has_high:
            score = min(score, 60)

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
        "recommendations": _generate_recommendations(issues),
    }


def _generate_recommendations(issues: list) -> list[str]:
    recs = []
    names = {i.get("name", "") for i in issues}
    if any("Phishing" in n or "Typosquat" in n for n in names):
        recs.append("Do not click any links in this message. Verify sender identity independently.")
    if any("PII" in n or "Personal Data" in n for n in names):
        recs.append("Never share sensitive data (SSN, passwords, bank details) via email or text.")
    if any("Crypto" in n or "Investment" in n for n in names):
        recs.append("This appears to be a financial scam. Report to local fraud authorities.")
    if any("AI-Generated" in n for n in names):
        recs.append("Content appears AI-generated. Verify the source's authenticity.")
    if not recs and issues:
        recs.append("Review all flagged indicators carefully before taking action.")
    return recs
