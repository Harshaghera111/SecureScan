/* ════════════════════════════════════════════════════════════════
   SecureScan v2 — Enterprise Analysis Engine
   Core coordinator, scoring, and reporting
   ════════════════════════════════════════════════════════════════ */

const SecureScanAnalyzer = {

    // ─── Version & Metadata ────────────────────────────────────
    version: '4.0.0',
    engineName: 'SecureScan Deep Intelligence',

    // ─── CVSS-inspired Exploitability Weights ──────────────────
    EXPLOITABILITY: {
        network: 0.85,   // remotely exploitable
        adjacent: 0.62,   // requires network proximity
        local: 0.55,   // requires local access
        physical: 0.20    // requires physical access
    },
    IMPACT_WEIGHTS: {
        critical: 1.0,
        high: 0.75,
        medium: 0.50,
        low: 0.25
    },
    CONFIDENCE_LEVELS: {
        confirmed: { label: 'Confirmed', weight: 1.0, icon: '🔴' },
        likely: { label: 'Likely', weight: 0.8, icon: '🟠' },
        possible: { label: 'Possible', weight: 0.5, icon: '🟡' }
    },

    // ─── CWE Database (embedded subset) ────────────────────────
    CWE: {
        'CWE-20': 'Improper Input Validation',
        'CWE-22': 'Path Traversal',
        'CWE-78': 'OS Command Injection',
        'CWE-79': 'Cross-site Scripting (XSS)',
        'CWE-89': 'SQL Injection',
        'CWE-90': 'LDAP Injection',
        'CWE-94': 'Code Injection',
        'CWE-95': 'Eval Injection',
        'CWE-98': 'Remote File Inclusion',
        'CWE-113': 'HTTP Response Splitting',
        'CWE-200': 'Information Exposure',
        'CWE-209': 'Information Exposure Through Error Messages',
        'CWE-215': 'Information Exposure Through Debug Info',
        'CWE-250': 'Execution with Unnecessary Privileges',
        'CWE-256': 'Plaintext Storage of a Password',
        'CWE-259': 'Hard-Coded Password',
        'CWE-269': 'Improper Privilege Management',
        'CWE-276': 'Incorrect Default Permissions',
        'CWE-284': 'Improper Access Control',
        'CWE-285': 'Improper Authorization',
        'CWE-295': 'Improper Certificate Validation',
        'CWE-311': 'Missing Encryption of Sensitive Data',
        'CWE-312': 'Cleartext Storage of Sensitive Information',
        'CWE-315': 'Cleartext Storage in Cookie',
        'CWE-319': 'Cleartext Transmission of Sensitive Information',
        'CWE-326': 'Inadequate Encryption Strength',
        'CWE-327': 'Use of Broken Crypto Algorithm',
        'CWE-328': 'Reversible One-Way Hash',
        'CWE-330': 'Use of Insufficiently Random Values',
        'CWE-338': 'Use of Weak PRNG',
        'CWE-346': 'Origin Validation Error',
        'CWE-352': 'Cross-Site Request Forgery (CSRF)',
        'CWE-377': 'Insecure Temporary File',
        'CWE-384': 'Session Fixation',
        'CWE-400': 'Uncontrolled Resource Consumption',
        'CWE-434': 'Unrestricted File Upload',
        'CWE-470': 'Unsafe Reflection',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-502': 'Deserialization of Untrusted Data',
        'CWE-521': 'Weak Password Requirements',
        'CWE-522': 'Insufficiently Protected Credentials',
        'CWE-532': 'Information Exposure Through Log Files',
        'CWE-539': 'Information Exposure Through Persistent Cookies',
        'CWE-601': 'Open Redirect',
        'CWE-611': 'XXE (XML External Entity)',
        'CWE-613': 'Insufficient Session Expiration',
        'CWE-614': 'Sensitive Cookie Without Secure Flag',
        'CWE-640': 'Weak Password Recovery',
        'CWE-643': 'XPath Injection',
        'CWE-693': 'Protection Mechanism Failure',
        'CWE-732': 'Incorrect Permission Assignment',
        'CWE-798': 'Hard-Coded Credentials',
        'CWE-862': 'Missing Authorization',
        'CWE-863': 'Incorrect Authorization',
        'CWE-918': 'Server-Side Request Forgery (SSRF)',
        'CWE-942': 'Overly Permissive CORS Policy',
        'CWE-1004': 'Sensitive Cookie Without HttpOnly Flag',
        'CWE-1021': 'Improper Restriction of Rendered UI Layers (Clickjacking)',
    },

    OWASP: {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable & Outdated Components',
        'A07': 'Identification & Authentication Failures',
        'A08': 'Software & Data Integrity Failures',
        'A09': 'Security Logging & Monitoring Failures',
        'A10': 'Server-Side Request Forgery (SSRF)',
    },

    // ─── Enterprise Result Builder (V4 Deep Intelligence) ──────
    _buildResult(issues, type, overrideScore = null) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        let confirmedCount = 0, likelyCount = 0, possibleCount = 0;

        issues.forEach(iss => {
            counts[iss.severity]++;
            if (iss.confidence === 'confirmed') confirmedCount++;
            else if (iss.confidence === 'likely') likelyCount++;
            else possibleCount++;
        });

        // ── V4 Multi-Dimensional Scoring ──
        let score = overrideScore;
        if (score === null) {
            // ── V5 Weighted Additive Scoring Model ──
            let baseScore = 0;
            const flags = {
                rce: false,
                sqli: false,
                pathTraversal: false,
                secrets: false,
                xss: false,
                debug: false,
                authBypass: false
            };

            // 1. Analyze Findings for Specific Risks
            issues.forEach(iss => {
                const name = (iss.name || '').toLowerCase();
                const desc = (iss.description || '').toLowerCase();
                const cwe = iss.cwe || '';

                if (iss._v5_rce || cwe === 'CWE-78' || cwe === 'CWE-94' || name.includes('command') || name.includes('code execution')) flags.rce = true;
                if (cwe === 'CWE-89' || name.includes('sql')) flags.sqli = true;
                if (cwe === 'CWE-22' || name.includes('path') || name.includes('traversal')) flags.pathTraversal = true;
                if (cwe === 'CWE-798' || cwe === 'CWE-256' || name.includes('password') || name.includes('secret') || name.includes('key')) flags.secrets = true;
                if (cwe === 'CWE-79' || name.includes('xss')) flags.xss = true;
                if (name.includes('debug') || name.includes('console')) flags.debug = true;
                if (cwe === 'CWE-284' || cwe === 'CWE-862' || name.includes('auth') || name.includes('idor')) flags.authBypass = true;
            });

            // 2. Additive Weights (Category Based)
            if (flags.rce) baseScore += 30; // Critical RCE
            if (flags.sqli) baseScore += 25; // Critical SQLi
            if (flags.authBypass) baseScore += 25; // Critical Auth Bypass
            if (flags.pathTraversal) baseScore += 20; // Critical Path Traversal
            if (flags.xss) baseScore += 15; // High XSS
            if (flags.secrets) baseScore += 10; // High Secret Leak
            if (flags.debug) baseScore += 5; // Medium Debug

            // 3. Volume-Based Severity Addition (Diminishing Returns)
            // Criticals add 5 pts each (max 20), Highs 3 pts (max 15), Medium 1 pt (max 10)
            baseScore += Math.min(20, counts.critical * 5);
            baseScore += Math.min(15, counts.high * 3);
            baseScore += Math.min(10, counts.medium * 1);

            // 4. Intelligence Multipliers
            const meta = issues[0]?.meta || {};
            // Public exposure risk
            if (meta.isPublicRoute) baseScore *= 1.1;
            // Unprotected sensitive route
            if (meta.authMissing && meta.isSensitive) baseScore *= 1.25;

            // 5. Normalization & Safety Nets
            let finalScore = Math.round(baseScore);

            // Safety Net: Confirmed Critical/High MUST be at least 75/50
            if (counts.critical > 0 && finalScore < 75) finalScore = 75 + counts.critical;
            if (counts.high > 0 && finalScore < 50) finalScore = 50 + counts.high;

            weightedSum = finalScore; // Use this as the result
            // (Normalization factor logic below is removed/bypassed by this direct assignment)

            score = Math.round(weightedSum);

            // Natural cap — never 100 unless truly catastrophic
            const hasCatastrophic = confirmedCount >= 3 && counts.critical >= 2;
            score = hasCatastrophic ? Math.min(98, score) : Math.min(95, score);
        }
        score = Math.max(0, Math.min(100, Math.round(score)));

        let rating;
        if (score >= 76) rating = { label: 'Critical Risk', color: '#ef4444', bg: 'rgba(239,68,68,0.12)' };
        else if (score >= 51) rating = { label: 'High Risk', color: '#f97316', bg: 'rgba(249,115,22,0.12)' };
        else if (score >= 26) rating = { label: 'Medium Risk', color: '#eab308', bg: 'rgba(234,179,8,0.12)' };
        else rating = { label: 'Secure', color: '#22c55e', bg: 'rgba(34,197,94,0.12)' };

        // ── Confidence Index ──
        const totalFindings = issues.length || 1;
        const confidenceIndex = Math.round(
            ((confirmedCount * 100) + (likelyCount * 70) + (possibleCount * 35)) / totalFindings
        );

        // ── Attach CWE descriptions ──
        issues.forEach(iss => {
            if (iss.cwe && this.CWE[iss.cwe]) {
                iss.cweName = this.CWE[iss.cwe];
            }
            if (iss.owasp && this.OWASP[iss.owasp]) {
                iss.owaspName = this.OWASP[iss.owasp];
            }
        });

        const recommendations = this._generateRecommendations(issues, type);

        return {
            score,
            rating,
            counts,
            issues,
            recommendations,
            meta: {
                engine: this.engineName,
                version: this.version,
                analysisType: type,
                totalFindings: issues.length,
                confirmedFindings: confirmedCount,
                likelyFindings: likelyCount,
                possibleFindings: possibleCount,
                confidenceIndex: Math.min(confidenceIndex, 99),
                timestamp: new Date().toISOString()
            }
        };
    },

    // ─── Dynamic Recommendation Engine ─────────────────────────
    _generateRecommendations(issues, type) {
        const recs = [];
        const issueNames = issues.map(i => i.name.toLowerCase());
        const cweIds = issues.map(i => i.cwe).filter(Boolean);
        const has = (keyword) => issueNames.some(n => n.includes(keyword));
        const hasCWE = (id) => cweIds.includes(id);

        if (type === 'code') {
            if (has('sql') || hasCWE('CWE-89'))
                recs.push({ icon: '🔐', title: 'Use Parameterized Queries', desc: 'Replace all string concatenation in SQL with parameterized queries or an ORM to prevent injection attacks.' });
            if (has('xss') || has('cross-site') || hasCWE('CWE-79'))
                recs.push({ icon: '🧹', title: 'Sanitize All Output', desc: 'Escape user input before rendering in HTML. Use textContent, DOMPurify, or template engines with auto-escaping.' });
            if (has('command') || has('exec') || hasCWE('CWE-78'))
                recs.push({ icon: '⚡', title: 'Eliminate Command Injection', desc: 'Never pass user input to shell commands. Use execFile() with whitelisted commands and argument arrays.' });
            if (has('hardcoded') || has('api key') || has('secret') || has('password') || has('credential') || hasCWE('CWE-798'))
                recs.push({ icon: '🔑', title: 'Externalize All Secrets', desc: 'Move API keys, passwords, and tokens to environment variables or a secrets manager. Rotate any exposed keys.' });
            if (has('crypto') || has('weak') || hasCWE('CWE-327'))
                recs.push({ icon: '🔒', title: 'Upgrade Cryptography', desc: 'Replace MD5/SHA1 with SHA-256+. Use bcrypt/argon2 for passwords. Use AES-256-GCM for encryption.' });
            if (has('cors') || hasCWE('CWE-942'))
                recs.push({ icon: '🌐', title: 'Restrict CORS Origins', desc: 'Configure CORS to only allow requests from your trusted domains, never use wildcard (*) in production.' });
            if (has('path') || has('traversal') || hasCWE('CWE-22'))
                recs.push({ icon: '📁', title: 'Validate File Paths', desc: 'Validate and sanitize all file paths. Ensure they resolve within allowed directories. Use allow-lists.' });
            if (has('ssl') || has('tls') || has('certificate') || hasCWE('CWE-295'))
                recs.push({ icon: '🛡️', title: 'Enforce SSL/TLS', desc: 'Never disable SSL verification. Install valid certificates and use HTTPS everywhere.' });
            if (has('deserialization') || hasCWE('CWE-502'))
                recs.push({ icon: '📦', title: 'Secure Deserialization', desc: 'Never deserialize untrusted data. Use JSON instead of native serialization. Validate and type-check all input.' });
            if (has('ssrf') || hasCWE('CWE-918'))
                recs.push({ icon: '🌍', title: 'Prevent SSRF', desc: 'Validate and whitelist all URLs before making server-side requests. Block internal network ranges.' });
            if (has('access') || has('authorization') || has('auth') || hasCWE('CWE-862'))
                recs.push({ icon: '🚪', title: 'Enforce Access Controls', desc: 'Implement proper authorization checks on all endpoints. Use role-based access control (RBAC).' });
            if (has('input') || has('validation') || hasCWE('CWE-20'))
                recs.push({ icon: '✅', title: 'Add Input Validation', desc: 'Validate all incoming data with schemas (Joi, Zod). Check types, lengths, ranges, and formats.' });
            if (has('session') || has('csrf') || hasCWE('CWE-352'))
                recs.push({ icon: '🎫', title: 'Secure Sessions', desc: 'Use anti-CSRF tokens, secure/httpOnly cookies, and proper session expiration.' });
            if (has('redirect') || hasCWE('CWE-601'))
                recs.push({ icon: '↩️', title: 'Prevent Open Redirects', desc: 'Validate redirect URLs against a whitelist. Never redirect to user-controlled URLs without validation.' });
            if (has('upload') || hasCWE('CWE-434'))
                recs.push({ icon: '📎', title: 'Secure File Uploads', desc: 'Validate file types, enforce size limits, rename files, and store outside the web root.' });
            if (recs.length === 0) recs.push({ icon: '✅', title: 'Good Security Posture', desc: 'No major issues found! Continue following security best practices and keep dependencies updated.' });
        } else if (type === 'text') {
            if (has('phishing') || has('lookalike') || has('spoof') || has('homoglyph'))
                recs.push({ icon: '🚫', title: 'Do Not Click Any Links', desc: 'Suspicious links detected. Never click links in unsolicited messages — navigate to official sites directly.' });
            if (has('personal') || has('sensitive') || has('credential') || has('financial'))
                recs.push({ icon: '🔒', title: 'Never Share Personal Data', desc: 'No legitimate company asks for SSN, passwords, or credit cards via email. Report these requests.' });
            if (has('urgency') || has('threat') || has('pressure') || has('time'))
                recs.push({ icon: '⏸️', title: 'Don\'t Rush — Verify First', desc: 'Urgency tactics are designed to make you act without thinking. Take time to verify any claims independently.' });
            if (has('crypto') || has('invest') || has('wallet'))
                recs.push({ icon: '💰', title: 'Crypto Scam Warning', desc: 'Never send cryptocurrency to unknown wallets. Investment guarantees are almost always scams.' });
            if (has('url') || has('domain') || has('http'))
                recs.push({ icon: '🔍', title: 'Check URLs Carefully', desc: 'Always hover over links to see the real URL. Look for misspellings and suspicious domains.' });
            if (has('impersonat') || has('authority') || has('ceo'))
                recs.push({ icon: '👤', title: 'Verify Sender Identity', desc: 'Contact the alleged sender through official channels. Never trust email headers alone.' });
            if (issues.some(i => i.severity === 'critical'))
                recs.push({ icon: '📧', title: 'Report This Message', desc: 'Forward suspected phishing to the impersonated company\'s abuse team and your email provider.' });
            if (recs.length === 0) recs.push({ icon: '✅', title: 'Text Appears Safe', desc: 'No obvious threats detected. Still exercise caution with unsolicited messages.' });
        } else if (type === 'image') {
            if (has('ela') || has('compression') || has('error level'))
                recs.push({ icon: '🔬', title: 'ELA Anomalies Found', desc: 'Different regions show different compression levels, suggesting editing. Compare with known originals.' });
            if (has('noise') || has('smooth') || has('symmetry') || has('pattern'))
                recs.push({ icon: '🔍', title: 'Reverse Image Search', desc: 'Use Google Images or TinEye to find the original source and check for modifications.' });
            if (has('texture') || has('lbp') || has('artifact'))
                recs.push({ icon: '🔬', title: 'Zoom & Inspect Details', desc: 'Look for repeating textures, unnatural edges, and inconsistencies — especially around hair, eyes, and backgrounds.' });
            if (has('frequency') || has('dct'))
                recs.push({ icon: '📊', title: 'Frequency Analysis Anomalies', desc: 'The frequency spectrum shows patterns inconsistent with natural photography. This may indicate AI generation.' });
            recs.push({ icon: '🖼️', title: 'Request Original File', desc: 'Ask for the original unedited photo with full EXIF metadata for proper verification.' });
            recs.push({ icon: '🧪', title: 'Use Specialized Tools', desc: 'For high-confidence detection, use dedicated services like Microsoft Video Authenticator or academic deepfake detectors.' });
        }

        return recs.slice(0, 5);
    },

    // ─── Utility: Levenshtein Distance ─────────────────────────
    _levenshtein(a, b) {
        const m = a.length, n = b.length;
        const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
        for (let i = 0; i <= m; i++) dp[i][0] = i;
        for (let j = 0; j <= n; j++) dp[0][j] = j;
        for (let i = 1; i <= m; i++) {
            for (let j = 1; j <= n; j++) {
                dp[i][j] = a[i - 1] === b[j - 1]
                    ? dp[i - 1][j - 1]
                    : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
            }
        }
        return dp[m][n];
    },

    // ─── Utility: Deduplicate issues ───────────────────────────
    _dedup(issues) {
        const seen = new Set();
        return issues.filter(iss => {
            const key = iss.name + '|' + (iss.location || '');
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    },

    // ─── Utility: Sort by severity ─────────────────────────────
    _sortBySeverity(issues) {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return issues.sort((a, b) => order[a.severity] - order[b.severity]);
    }
};
