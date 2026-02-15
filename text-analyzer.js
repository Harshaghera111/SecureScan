/* ════════════════════════════════════════════════════════════════
   SecureScan v2 — Text Analysis Engine
   Levenshtein typosquatting, homoglyphs, behavioral profiling,
   crypto scam detection, NLP-inspired AI text detection
   ════════════════════════════════════════════════════════════════ */

SecureScanAnalyzer.analyzeText = function (text) {
    const issues = [];
    const lowerText = text.toLowerCase();
    const words = text.split(/\s+/);
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 3);

    // ═══════════════════════════════════════════════════════════
    //  BRAND DATABASE (50+ brands for impersonation detection)
    // ═══════════════════════════════════════════════════════════
    const BRANDS = [
        'google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'meta', 'twitter',
        'instagram', 'netflix', 'youtube', 'linkedin', 'github', 'dropbox', 'slack', 'zoom',
        'spotify', 'uber', 'lyft', 'airbnb', 'stripe', 'shopify', 'wordpress', 'adobe',
        'salesforce', 'oracle', 'cisco', 'nvidia', 'samsung', 'sony', 'whatsapp', 'telegram',
        'signal', 'snapchat', 'tiktok', 'reddit', 'pinterest', 'ebay', 'walmart', 'target',
        'bestbuy', 'costco', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'capitalone',
        'americanexpress', 'venmo', 'cashapp', 'zelle', 'coinbase', 'binance', 'kraken'
    ];

    // ═══════════════════════════════════════════════════════════
    //  HOMOGLYPH MAP (Cyrillic/Latin lookalikes)
    // ═══════════════════════════════════════════════════════════
    const HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'і': 'i', 'ј': 'j',
        'ɡ': 'g', 'ɩ': 'l', 'ʀ': 'r', 'ꮃ': 'w', 'ꭰ': 'd', 'ꮪ': 's', 'ꮋ': 'h',
        '0': 'o', '1': 'l', '!': 'i', '|': 'l', 'ℓ': 'l', 'ƒ': 'f', 'ɑ': 'a', 'ο': 'o',
        'ν': 'v', 'τ': 't', 'κ': 'k', 'η': 'n', 'ω': 'w', 'ρ': 'p', 'χ': 'x'
    };

    const suspiciousTLDs = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
        '.club', '.work', '.click', '.link', '.info', '.online', '.site', '.icu', '.vip',
        '.win', '.loan', '.racing', '.stream', '.download', '.cricket', '.science',
        '.party', '.gdn', '.men', '.bid', '.trade', '.webcam', '.date', '.review', '.accountant'];

    // ═══════════════════════════════════════════════════════════
    //  PHASE 1: URL Analysis (Deep Inspection)
    // ═══════════════════════════════════════════════════════════
    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    const urls = text.match(urlRegex) || [];

    for (const url of urls) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();

            // Suspicious TLD check
            const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));

            // Levenshtein-based typosquatting
            const hostParts = hostname.replace(/\.(com|org|net|io|co|xyz|top|info|dev|app).*$/, '').replace(/www\./, '');
            let closestBrand = null, closestDist = Infinity;
            for (const brand of BRANDS) {
                const dist = this._levenshtein(hostParts, brand);
                if (dist > 0 && dist <= 2 && dist < closestDist) {
                    closestBrand = brand; closestDist = dist;
                }
            }

            // Homoglyph check
            let deHomoglyphed = '';
            for (const ch of hostname) {
                deHomoglyphed += HOMOGLYPHS[ch] || ch;
            }
            const hasHomoglyphs = deHomoglyphed !== hostname;
            let homoglyphBrand = null;
            if (hasHomoglyphs) {
                const cleanHost = deHomoglyphed.replace(/\.(com|org|net|io).*$/, '').replace(/www\./, '');
                homoglyphBrand = BRANDS.find(b => cleanHost.includes(b));
            }

            // IP address check
            const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);

            // Subdomain depth
            const subdomainCount = hostname.split('.').length - 2;

            // URL encoding / obfuscation
            const hasEncodedChars = /%[0-9a-f]{2}/gi.test(url);
            const hasAtSign = /@/.test(url);

            // Shortened URL patterns
            const shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorturl.at', 'rb.gy', 'cutt.ly'];
            const isShortened = shorteners.some(s => hostname.includes(s));

            // Generate issues
            if (homoglyphBrand) {
                issues.push({
                    severity: 'critical', name: 'Homoglyph Phishing Domain', location: 'URL in text',
                    description: `The URL "${hostname}" uses lookalike Unicode characters to impersonate "${homoglyphBrand}". After de-homoglyphing: "${deHomoglyphed}". This is a sophisticated phishing technique.`,
                    snippet: `Original: ${hostname}\nDe-homoglyphed: ${deHomoglyphed}\nTarget brand: ${homoglyphBrand}`,
                    fix: 'This URL uses Unicode tricks to look like a legitimate domain. Do NOT click it. Report it to the brand\'s security team.',
                    confidence: 'confirmed', attackVector: 'network'
                });
            } else if (closestBrand) {
                issues.push({
                    severity: 'critical', name: 'Typosquatted Domain Detected', location: 'URL in text',
                    description: `The domain "${hostname}" is ${closestDist} character(s) away from "${closestBrand}.com" — a likely typosquatting attempt to steal credentials.`,
                    snippet: `${url}\nLevenshtein distance from "${closestBrand}": ${closestDist}`,
                    fix: 'Do NOT click this link. Navigate to the official website by typing the URL yourself. Report this domain.',
                    confidence: 'confirmed', attackVector: 'network'
                });
            }
            if (hasSuspiciousTLD) {
                issues.push({
                    severity: 'high', name: 'Suspicious TLD in URL', location: 'URL in text',
                    description: `The URL uses a TLD commonly associated with phishing/scam campaigns.`,
                    snippet: url, fix: 'Verify the link through official channels. Suspicious TLDs are frequently used for short-lived phishing sites.',
                    confidence: 'likely', attackVector: 'network'
                });
            }
            if (isIP) {
                issues.push({
                    severity: 'high', name: 'IP-Based URL (No Domain)', location: 'URL in text',
                    description: `The URL uses a raw IP address (${hostname}) instead of a domain name — a red flag for phishing.`,
                    snippet: url, fix: 'Legitimate websites use domain names. IP-based URLs are used to evade domain blacklists.',
                    confidence: 'confirmed', attackVector: 'network'
                });
            }
            if (subdomainCount >= 3) {
                issues.push({
                    severity: 'medium', name: 'Excessive Subdomains in URL', location: 'URL in text',
                    description: `${subdomainCount} subdomains detected — may be hiding the real destination domain.`,
                    snippet: url, fix: 'Look at the actual domain (just before the TLD). Long subdomain chains are used to look like legitimate URLs.',
                    confidence: 'likely', attackVector: 'network'
                });
            }
            if (isShortened) {
                issues.push({
                    severity: 'medium', name: 'Shortened URL Detected', location: 'URL in text',
                    description: `URL shortener "${hostname}" detected. Shortened URLs hide the real destination and are often used in phishing campaigns.`,
                    snippet: url, fix: 'Use a URL expander tool to see the real destination before clicking. Be extra cautious with shortened links in emails.',
                    confidence: 'likely', attackVector: 'network'
                });
            }
            if (hasAtSign) {
                issues.push({
                    severity: 'high', name: 'URL Contains @ Symbol', location: 'URL in text',
                    description: `The @ symbol in a URL causes browsers to ignore everything before it, making phishing URLs look legitimate.`,
                    snippet: url, fix: 'The @ trick makes you think you\'re going to one site but actually redirects elsewhere. Never click such URLs.',
                    confidence: 'confirmed', attackVector: 'network'
                });
            }
            if (urlObj.protocol === 'http:' && !isIP && hostname !== 'localhost') {
                issues.push({
                    severity: 'low', name: 'Insecure HTTP Link', location: 'URL in text',
                    description: `The URL uses HTTP instead of HTTPS — data is not encrypted.`, snippet: url,
                    fix: 'Legitimate sites use HTTPS. Be extra cautious with plaintext HTTP links.',
                    confidence: 'confirmed', attackVector: 'adjacent'
                });
            }
        } catch (e) { /* invalid URL */ }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 2: Social Engineering & Urgency Detection
    // ═══════════════════════════════════════════════════════════
    const urgencyPatterns = [
        { regex: /\b(urgent|immediately|right now|act now|right away|asap|time.sensitive)\b/gi, name: 'Urgency Language', sev: 'high' },
        { regex: /\b(suspend|terminat|delet|disabl|block|lock|freez|cancel|restrict|deactivat)\w*\s+(your|the|this)\s+(account|access|service|card|wallet)/gi, name: 'Account Threat', sev: 'high' },
        { regex: /\b(within|in)\s+\d+\s*(hour|minute|day|hr|min)s?\b/gi, name: 'Time Pressure', sev: 'medium' },
        { regex: /\b(permanent|irreversible|cannot be undone|final warning|last chance|last notice|immediate action required)\b/gi, name: 'Finality Threat', sev: 'high' },
        { regex: /\b(legal action|law enforcement|arrest|warrant|prosecution|federal|irs|fbi)\b/gi, name: 'Legal/Authority Threat', sev: 'high' },
        { regex: /\b(won|winner|congratulat|lottery|prize|selected|lucky|inheritance|million\s*dollar)\b/gi, name: 'Prize/Lottery Scam Language', sev: 'high' },
    ];

    for (const pat of urgencyPatterns) {
        const matches = text.match(pat.regex);
        if (matches && matches.length > 0) {
            issues.push({
                severity: pat.sev, name: `${pat.name} Detected`, location: 'Message body',
                description: `Social engineering tactic: "${matches[0]}" is designed to pressure you into acting without thinking.`,
                snippet: matches.slice(0, 3).join(', '),
                fix: 'Legitimate organizations rarely use extreme urgency. Take time to verify independently.',
                confidence: 'confirmed', attackVector: 'network'
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 3: PII Solicitation
    // ═══════════════════════════════════════════════════════════
    const piiPatterns = [
        { regex: /\b(social\s+security|ssn|tax\s+id|tin\b|taxpayer)/gi, label: 'Social Security / Tax ID', sev: 'critical' },
        { regex: /\b(credit\s+card|debit\s+card|card\s+number|cvv|cvc|expir\w*\s+date|billing\s+address)/gi, label: 'Credit/Debit Card Details', sev: 'critical' },
        { regex: /\b(bank\s+account|routing\s+number|swift|iban|wire\s+transfer|account\s+number)/gi, label: 'Banking Information', sev: 'critical' },
        { regex: /\b(password|passcode|pin\s+number|login\s+credential|security\s+question|secret\s+answer)/gi, label: 'Login Credentials', sev: 'critical' },
        { regex: /\b(date\s+of\s+birth|mother'?s?\s+maiden|passport\s+number|driver'?s?\s+licen|national\s+id)/gi, label: 'Personal Identity Data', sev: 'high' },
        { regex: /\b(send\s+(me\s+)?(a\s+)?photo\s+of\s+(your\s+)?(id|passport|license|document))/gi, label: 'Document Photo Request', sev: 'critical' },
    ];

    const foundPII = [];
    for (const pat of piiPatterns) {
        if (pat.regex.test(text)) foundPII.push(pat.label);
    }
    if (foundPII.length > 0) {
        issues.push({
            severity: 'critical', name: 'Requests Sensitive Personal Data', location: 'Message body',
            description: `The text solicits: ${foundPII.join(', ')}. No legitimate organization requests this via email or unsolicited messages.`,
            snippet: foundPII.join('\n'), fix: 'NEVER share SSN, passwords, credit cards, or ID photos via email, text, or phone.',
            confidence: 'confirmed', attackVector: 'network'
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 4: Sender & Brand Impersonation
    // ═══════════════════════════════════════════════════════════
    const emailRegex = /[\w.+-]+@[\w.-]+\.\w+/gi;
    const emails = text.match(emailRegex) || [];
    for (const email of emails) {
        const domain = email.split('@')[1].toLowerCase();
        const domainBase = domain.replace(/\.(com|org|net|io|co).*$/, '');
        for (const brand of BRANDS) {
            const dist = this._levenshtein(domainBase, brand);
            if (dist > 0 && dist <= 2) {
                issues.push({
                    severity: 'critical', name: 'Spoofed Sender Email', location: 'Email address',
                    description: `"${email}" impersonates ${brand} (Levenshtein distance: ${dist}). The domain is NOT the official ${brand} domain.`,
                    snippet: `${email}\nExpected: @${brand}.com\nSimilarity: ${((1 - dist / brand.length) * 100).toFixed(0)}%`,
                    fix: `Official ${brand} emails come from @${brand}.com. This is a spoofed address.`,
                    confidence: 'confirmed', attackVector: 'network'
                });
                break;
            }
        }
    }

    // Authority / CEO fraud patterns
    const authorityPatterns = [
        /\b(ceo|chief\s+executive|managing\s+director|president|chairman|cfo|cto|coo)\b/gi,
        /\b(irs|internal\s+revenue|tax\s+authority|hmrc|federal\s+reserve|securities\s+commission)\b/gi,
        /\b(tech\s+support|customer\s+service|security\s+team|fraud\s+department|compliance\s+team)\b/gi,
    ];
    for (const pat of authorityPatterns) {
        const m = text.match(pat);
        if (m && (lowerText.includes('urgent') || lowerText.includes('confidential') || lowerText.includes('wire') || lowerText.includes('transfer'))) {
            issues.push({
                severity: 'high', name: 'Authority Impersonation Detected', location: 'Message body',
                description: `The text invokes "${m[0]}" combined with urgency/financial language. This is a common Business Email Compromise (BEC) pattern.`,
                snippet: m[0], fix: 'Verify the request through official channels. Call the person directly using a known phone number — not one from the email.',
                confidence: 'likely', attackVector: 'network'
            });
            break;
        }
    }

    // Generic greeting
    if (/\b(dear\s+(valued\s+)?customer|dear\s+(valued\s+)?user|dear\s+account\s+holder|dear\s+sir|dear\s+madam|dear\s+member)\b/gi.test(text)) {
        issues.push({
            severity: 'low', name: 'Generic Greeting', location: 'Opening',
            description: 'Uses a generic greeting instead of your name. Legitimate companies personalize communications.',
            snippet: text.match(/dear\s+[\w\s]+/gi)?.[0] || 'Generic greeting',
            fix: 'If a company you have an account with sends a generic greeting, it may be a mass phishing campaign.',
            confidence: 'likely', attackVector: 'network'
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 5: Cryptocurrency & Investment Scams
    // ═══════════════════════════════════════════════════════════
    const cryptoPatterns = [
        { regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, name: 'Bitcoin Address Detected' },
        { regex: /\b0x[a-fA-F0-9]{40}\b/g, name: 'Ethereum Address Detected' },
        { regex: /\b(send|transfer|deposit)\s+\d+\s*(btc|eth|bitcoin|ethereum|crypto|usdt|tether)/gi, name: 'Crypto Transfer Request' },
        { regex: /\b(guaranteed\s+return|risk.free\s+invest|double\s+your\s+(money|bitcoin|crypto)|100%\s+profit|passive\s+income|financial\s+freedom)/gi, name: 'Investment Scam Language' },
    ];

    for (const pat of cryptoPatterns) {
        const matches = text.match(pat.regex);
        if (matches) {
            issues.push({
                severity: 'critical', name: pat.name, location: 'Message body',
                description: `${pat.name}: "${matches[0]}". Unsolicited requests involving cryptocurrency or investment guarantees are almost always scams.`,
                snippet: matches[0],
                fix: 'Never send cryptocurrency to unknown addresses. No legitimate investment guarantees 100% returns. Report to local fraud authority.',
                confidence: 'confirmed', attackVector: 'network'
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 6: Phishing Phrase Detection
    // ═══════════════════════════════════════════════════════════
    const phishingPhrases = [
        { regex: /\bverify\s+your\s+(identity|account|information|email|payment)\b/gi, sev: 'high' },
        { regex: /\bconfirm\s+your\s+(identity|account|details|payment|ownership)\b/gi, sev: 'high' },
        { regex: /\bunauthori[sz]ed\s+(access|activity|transaction|login|attempt)\b/gi, sev: 'high' },
        { regex: /\byour\s+account\s+(has\s+been|was)\s+(compromised|hacked|breached|flagged|limited|suspended)\b/gi, sev: 'critical' },
        { regex: /\bclick\s+(here|below|the\s+link)\s+to\s+(verify|confirm|update|restore|unlock|secure)\b/gi, sev: 'high' },
        { regex: /\b(update|verify)\s+your\s+(billing|payment|card)\s+(info|information|details|method)\b/gi, sev: 'high' },
        { regex: /\b(failure\s+to\s+(comply|verify|respond)|your\s+account\s+will\s+be)\b/gi, sev: 'high' },
    ];

    for (const pat of phishingPhrases) {
        const matches = text.match(pat.regex);
        if (matches) {
            issues.push({
                severity: pat.sev, name: 'Common Phishing Phrase', location: 'Message body',
                description: `"${matches[0]}" is a well-known phishing trigger phrase designed to lure victims to fake verification pages.`,
                snippet: matches[0], fix: 'Never click verification links in unsolicited messages. Go to the official website directly.',
                confidence: 'likely', attackVector: 'network'
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 7: AI-Generated Text Detection
    // ═══════════════════════════════════════════════════════════
    if (sentences.length >= 5) {
        const sentLens = sentences.map(s => s.trim().split(/\s+/).length);
        const avgLen = sentLens.reduce((a, b) => a + b, 0) / sentLens.length;
        const variance = sentLens.reduce((s, l) => s + Math.pow(l - avgLen, 2), 0) / sentLens.length;
        const stdDev = Math.sqrt(variance);

        // Vocabulary richness (type-token ratio)
        const allWords = text.toLowerCase().match(/\b[a-z]{3,}\b/g) || [];
        const uniqueWords = new Set(allWords);
        const ttr = uniqueWords.size / (allWords.length || 1);

        // Sentence starter diversity
        const starters = sentences.map(s => s.trim().split(/\s+/)[0]?.toLowerCase()).filter(Boolean);
        const uniqueStarters = new Set(starters);
        const starterDiversity = uniqueStarters.size / (starters.length || 1);

        // Transition word frequency (AI text overuses these)
        const transitions = (text.match(/\b(however|moreover|furthermore|additionally|consequently|therefore|nevertheless|in\s+conclusion|in\s+addition|as\s+a\s+result)\b/gi) || []).length;
        const transitionDensity = transitions / (sentences.length || 1);

        let aiScore = 0;
        const aiSignals = [];

        if (stdDev < 4 && avgLen > 12) { aiScore += 25; aiSignals.push(`Uniform sentence length (σ=${stdDev.toFixed(1)}, μ=${avgLen.toFixed(1)} words)`); }
        if (ttr < 0.4 && allWords.length > 50) { aiScore += 20; aiSignals.push(`Low vocabulary diversity (TTR=${ttr.toFixed(2)})`); }
        if (starterDiversity < 0.5 && starters.length > 5) { aiScore += 15; aiSignals.push(`Repetitive sentence starters (${(starterDiversity * 100).toFixed(0)}% unique)`); }
        if (transitionDensity > 0.3) { aiScore += 15; aiSignals.push(`High transition word density (${(transitionDensity * 100).toFixed(0)}%)`); }

        if (aiScore >= 40) {
            issues.push({
                severity: 'medium', name: 'Likely AI-Generated Text', location: 'Full text',
                description: `Multiple signals suggest this text was AI-generated:\n${aiSignals.map(s => '• ' + s).join('\n')}`,
                snippet: `AI Score: ${aiScore}/100\n${aiSignals.join('\n')}`,
                fix: 'Run through dedicated AI detection tools (GPTZero, Originality.ai) for confirmation. AI text is not inherently malicious but may indicate automation.',
                confidence: aiScore >= 60 ? 'likely' : 'possible', attackVector: 'network'
            });
        } else if (aiScore >= 20) {
            issues.push({
                severity: 'low', name: 'Possible AI-Generated Text', location: 'Full text',
                description: `Some signals suggest possible AI generation:\n${aiSignals.map(s => '• ' + s).join('\n')}`,
                snippet: `AI Score: ${aiScore}/100\n${aiSignals.join('\n')}`,
                fix: 'Consider running through AI detection tools for more thorough analysis.',
                confidence: 'possible', attackVector: 'network'
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 8: Composite Threat Score
    // ═══════════════════════════════════════════════════════════
    if (issues.length === 0) {
        issues.push({
            severity: 'low', name: 'No Threats Detected', location: 'Full text',
            description: 'No phishing, scam, or social engineering indicators were found. Always remain cautious with unsolicited messages.',
            snippet: 'Text appears clean', fix: 'While no threats were detected, verify the sender independently if the message asks you to take any action.',
            confidence: 'confirmed', attackVector: 'network'
        });
    }

    const unique = this._dedup(issues);
    this._sortBySeverity(unique);
    return this._buildResult(unique, 'text');
};
