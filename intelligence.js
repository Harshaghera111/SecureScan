/* ════════════════════════════════════════════════════════════════
   SecureScan v4 — Intelligence Layer
   Pattern learning, anomaly detection, CVE correlation,
   framework context, false positive suppression
   ════════════════════════════════════════════════════════════════ */

const IntelligenceEngine = {

    // ═══════════════════════════════════════════════════════════
    //  FRAMEWORK DETECTION & CONTEXT
    //  Auto-detect Express, Flask, Django, Spring, Laravel, Rails
    // ═══════════════════════════════════════════════════════════

    FRAMEWORK_SIGNATURES: {
        express: {
            patterns: [/require\s*\(\s*['"]express['"]\)/, /app\s*=\s*express\s*\(/, /app\.(get|post|put|delete|use)\s*\(/],
            safePatterns: { sql: /\?\s*,\s*\[/, xss: /res\.(json|send)\s*\(/ },
            securityMiddleware: ['helmet', 'cors', 'csurf', 'express-rate-limit', 'express-session', 'passport'],
            label: 'Express.js',
            language: 'javascript'
        },
        flask: {
            patterns: [/from\s+flask\s+import/, /Flask\s*\(/, /@app\.route/],
            safePatterns: { sql: /db\.session\.(query|execute)/, xss: /render_template\s*\(/ },
            securityMiddleware: ['flask-login', 'flask-wtf', 'flask-cors', 'flask-limiter', 'flask-talisman'],
            label: 'Flask',
            language: 'python'
        },
        django: {
            patterns: [/from\s+django/, /django\.\w+/, /urlpatterns\s*=/, /models\.Model/],
            safePatterns: { sql: /objects\.(filter|get|all|exclude)/, xss: /\{\{.*\}\}/ }, // Django ORM & auto-escaping
            securityMiddleware: ['CsrfViewMiddleware', 'SecurityMiddleware', 'AuthenticationMiddleware'],
            label: 'Django',
            language: 'python',
            notes: ['Django ORM prevents most SQL injection', 'Templates auto-escape by default']
        },
        spring: {
            patterns: [/import\s+org\.springframework/, /@RestController/, /@RequestMapping/, /@GetMapping|@PostMapping/],
            safePatterns: { sql: /JpaRepository|CrudRepository|@Query/ },
            securityMiddleware: ['@EnableWebSecurity', 'SecurityConfig', 'HttpSecurity'],
            label: 'Spring Boot',
            language: 'java'
        },
        laravel: {
            patterns: [/use\s+Illuminate/, /Route::(get|post|put|delete)/, /Eloquent|Model\s*{/],
            safePatterns: { sql: /DB::table|->where|Eloquent/, xss: /\{\{.*\}\}/ },
            securityMiddleware: ['VerifyCsrfToken', 'Authenticate', 'ThrottleRequests'],
            label: 'Laravel',
            language: 'php'
        },
        rails: {
            patterns: [/class\s+\w+\s*<\s*ApplicationController/, /Rails\.application/, /ActiveRecord/],
            safePatterns: { sql: /\.where\(.*?\?/, xss: /<%=.*%>/ },
            securityMiddleware: ['protect_from_forgery', 'before_action :authenticate'],
            label: 'Ruby on Rails',
            language: 'ruby'
        },
        nextjs: {
            patterns: [/from\s+['"]next/, /getServerSideProps|getStaticProps/, /NextResponse|NextRequest/],
            safePatterns: { xss: /dangerouslySetInnerHTML/ }, // flagged if present
            securityMiddleware: ['middleware.ts', 'next-auth'],
            label: 'Next.js',
            language: 'javascript'
        },
        fastapi: {
            patterns: [/from\s+fastapi\s+import/, /FastAPI\s*\(/, /@app\.(get|post|put|delete)/],
            safePatterns: { sql: /SQLAlchemy|AsyncSession/ },
            securityMiddleware: ['OAuth2PasswordBearer', 'HTTPBearer', 'CORSMiddleware'],
            label: 'FastAPI',
            language: 'python'
        },
    },

    detectFramework(code) {
        const results = [];
        for (const [name, fw] of Object.entries(this.FRAMEWORK_SIGNATURES)) {
            const matchCount = fw.patterns.filter(p => p.test(code)).length;
            if (matchCount >= 2 || (matchCount >= 1 && fw.patterns.length <= 2)) {
                // Check for security middleware
                const detectedMiddleware = fw.securityMiddleware.filter(mw =>
                    new RegExp(mw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(code)
                );

                results.push({
                    name,
                    label: fw.label,
                    language: fw.language,
                    confidence: matchCount / fw.patterns.length,
                    securityMiddleware: detectedMiddleware,
                    hasSecurityConfig: detectedMiddleware.length > 0,
                    safePatterns: fw.safePatterns,
                    notes: fw.notes || []
                });
            }
        }

        // Return best match
        results.sort((a, b) => b.confidence - a.confidence);
        return results.length > 0 ? results[0] : null;
    },

    // ═══════════════════════════════════════════════════════════
    //  CVE CORRELATION ENGINE
    //  Maps detected patterns to known CVEs
    // ═══════════════════════════════════════════════════════════

    CVE_DATABASE: [
        {
            id: 'CVE-2021-44228', name: 'Log4Shell', pattern: /log4j|Log4j|JNDI|jndi:ldap/i, severity: 'critical', cwe: 'CWE-917',
            description: 'Apache Log4j2 JNDI injection allows remote code execution via crafted log messages.'
        },
        {
            id: 'CVE-2021-3129', name: 'Laravel Debug RCE', pattern: /APP_DEBUG\s*=\s*true.*laravel|laravel.*debug.*true/i, severity: 'critical', cwe: 'CWE-94',
            description: 'Laravel with debug mode enabled allows remote code execution via Ignition debug page.'
        },
        {
            id: 'CVE-2019-11358', name: 'jQuery Prototype Pollution', pattern: /jquery.*(\$\.extend|jQuery\.extend)\s*\(\s*true/i, severity: 'high', cwe: 'CWE-1321',
            description: 'jQuery.extend with deep copy enables prototype pollution via crafted objects.'
        },
        {
            id: 'CVE-2022-29078', name: 'EJS SSTI', pattern: /ejs.*render|\.render\s*\(.*req\./i, severity: 'critical', cwe: 'CWE-94',
            description: 'EJS template injection allows server-side code execution via unescaped user input.'
        },
        {
            id: 'CVE-2021-23369', name: 'Handlebars Prototype Pollution', pattern: /handlebars|Handlebars\.compile/i, severity: 'high', cwe: 'CWE-1321',
            description: 'Handlebars template compilation with user input enables prototype pollution.'
        },
        {
            id: 'CVE-2020-7660', name: 'serialize-javascript RCE', pattern: /serialize-javascript|serialize\s*\(/i, severity: 'critical', cwe: 'CWE-502',
            description: 'serialize-javascript allows remote code execution via crafted serialized data.'
        },
        {
            id: 'CVE-2018-16487', name: 'Lodash Prototype Pollution', pattern: /lodash.*merge|_\.merge|_\.defaultsDeep/i, severity: 'high', cwe: 'CWE-1321',
            description: 'Lodash merge/defaultsDeep enables prototype pollution via crafted objects.'
        },
        {
            id: 'CVE-2017-5638', name: 'Apache Struts RCE', pattern: /struts|ActionSupport|struts\.xml/i, severity: 'critical', cwe: 'CWE-78',
            description: 'Apache Struts Content-Type header parsing allows remote code execution.'
        },
        {
            id: 'CVE-2021-21315', name: 'systeminformation Command Injection', pattern: /systeminformation|si\.(cpu|mem|disk|network)/i, severity: 'high', cwe: 'CWE-78',
            description: 'systeminformation package vulnerable to command injection via crafted parameters.'
        },
        {
            id: 'CVE-2019-5413', name: 'Morgan Path Traversal', pattern: /morgan.*req\.url|morgan.*:url/i, severity: 'medium', cwe: 'CWE-22',
            description: 'Morgan logger with user-controlled URL enables log injection and path traversal.'
        },
        {
            id: 'CVE-2023-44270', name: 'PostCSS Line Return Parsing', pattern: /postcss|PostCSS/i, severity: 'medium', cwe: 'CWE-74',
            description: 'PostCSS parsing vulnerability via crafted CSS with line return characters.'
        },
        {
            id: 'CVE-2022-24999', name: 'qs Prototype Pollution', pattern: /require\s*\(\s*['"]qs['"]\)|qs\.parse/i, severity: 'high', cwe: 'CWE-1321',
            description: 'qs package prototype pollution via crafted query string parameters.'
        },
        {
            id: 'CVE-2022-0235', name: 'node-fetch Redirect', pattern: /node-fetch|require\s*\(\s*['"]node-fetch['"]\)/i, severity: 'medium', cwe: 'CWE-601',
            description: 'node-fetch follows redirects with authorization headers, leaking credentials.'
        },
        {
            id: 'CVE-2023-26136', name: 'tough-cookie Prototype Pollution', pattern: /tough-cookie|CookieJar/i, severity: 'medium', cwe: 'CWE-1321',
            description: 'tough-cookie prototype pollution via crafted cookie values.'
        },
        {
            id: 'CVE-2022-25883', name: 'semver ReDoS', pattern: /require\s*\(\s*['"]semver['"]\)|semver\.valid/i, severity: 'medium', cwe: 'CWE-1333',
            description: 'semver package vulnerable to Regular Expression Denial of Service.'
        },
    ],

    correlateCVEs(code) {
        const matches = [];
        for (const cve of this.CVE_DATABASE) {
            if (cve.pattern.test(code)) {
                matches.push({
                    id: cve.id,
                    name: cve.name,
                    severity: cve.severity,
                    cwe: cve.cwe,
                    description: cve.description,
                });
            }
        }
        return matches;
    },

    // ═══════════════════════════════════════════════════════════
    //  ANOMALY DETECTION
    //  Detects unusual code structures and suspicious patterns
    // ═══════════════════════════════════════════════════════════

    detectAnomalies(code, ast) {
        const anomalies = [];
        const lines = code.split('\n');

        // 1. Suspicious naming patterns
        const suspiciousNames = /\b(backdoor|bypass|temp_hack|skip_auth|no_check|disable_security|admin_override|master_key|god_mode|root_access|debug_only|test_only_remove|fixme_remove)\b/gi;
        let nameMatch;
        while ((nameMatch = suspiciousNames.exec(code)) !== null) {
            const lineIdx = code.substring(0, nameMatch.index).split('\n').length;
            anomalies.push({
                type: 'suspicious_naming',
                severity: 'medium',
                line: lineIdx,
                detail: `Suspicious identifier: "${nameMatch[0]}"`,
                confidence: 'likely'
            });
        }

        // 2. Excessive eval/exec usage
        const evalCount = (code.match(/\beval\s*\(/g) || []).length;
        if (evalCount >= 3) {
            anomalies.push({
                type: 'excessive_dynamic_execution',
                severity: 'high',
                detail: `${evalCount} eval() calls detected — unusual pattern suggesting dynamic code generation or obfuscation`,
                confidence: 'likely'
            });
        }

        // 3. Deeply nested callbacks (callback hell → error-prone)
        let maxNesting = 0;
        let currentNesting = 0;
        for (const line of lines) {
            const opens = (line.match(/\{/g) || []).length;
            const closes = (line.match(/\}/g) || []).length;
            currentNesting += opens - closes;
            maxNesting = Math.max(maxNesting, currentNesting);
        }
        if (maxNesting >= 8) {
            anomalies.push({
                type: 'deep_nesting',
                severity: 'low',
                detail: `Maximum nesting depth: ${maxNesting} levels — increases risk of logic errors`,
                confidence: 'confirmed'
            });
        }

        // 4. Obfuscation indicators
        const obfuscationPatterns = [
            { regex: /\\x[0-9a-f]{2}/gi, name: 'hex escape sequences' },
            { regex: /\\u[0-9a-f]{4}/gi, name: 'unicode escapes' },
            { regex: /atob\s*\(|btoa\s*\(|Buffer\.from\s*\(.*,\s*['"]base64['"]\)/g, name: 'base64 encoding/decoding' },
            { regex: /String\.fromCharCode\s*\(/g, name: 'character code construction' },
        ];
        for (const pattern of obfuscationPatterns) {
            const matches = code.match(pattern.regex);
            if (matches && matches.length >= 3) {
                anomalies.push({
                    type: 'obfuscation',
                    severity: 'medium',
                    detail: `${matches.length} instances of ${pattern.name} — possible code obfuscation`,
                    confidence: 'possible'
                });
            }
        }

        // 5. Unusual file operations
        const dangerousOps = code.match(/unlink|rmdir|rm\s+-rf|truncate|format\s+[cCdD]:/g);
        if (dangerousOps && dangerousOps.length >= 2) {
            anomalies.push({
                type: 'destructive_operations',
                severity: 'high',
                detail: `${dangerousOps.length} destructive file operations detected`,
                confidence: 'likely'
            });
        }

        // 6. Network exfiltration patterns
        const exfilPatterns = /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0)/gi;
        const exfilMatches = code.match(exfilPatterns);
        if (exfilMatches && exfilMatches.length >= 3) {
            anomalies.push({
                type: 'network_exfiltration_risk',
                severity: 'medium',
                detail: `${exfilMatches.length} external network requests detected — verify destinations`,
                confidence: 'possible'
            });
        }

        // 7. Large file complexity warning
        if (ast && ast.metrics) {
            if (ast.metrics.cyclomaticComplexity >= 20) {
                anomalies.push({
                    type: 'high_complexity',
                    severity: 'low',
                    detail: `Cyclomatic complexity: ${ast.metrics.cyclomaticComplexity} — high complexity increases vulnerability risk`,
                    confidence: 'confirmed'
                });
            }
        }

        return anomalies;
    },

    // ═══════════════════════════════════════════════════════════
    //  FALSE POSITIVE SUPPRESSION
    //  Context-aware confidence calibration
    // ═══════════════════════════════════════════════════════════

    suppressFalsePositives(issues, code, frameworkContext) {
        return issues.map(issue => {
            let adjustedConfidence = issue.confidence;
            let adjustedSeverity = issue.severity;
            let suppressionReason = null;

            // 1. Test file detection
            const isTestCode = /describe\s*\(|it\s*\(|test\s*\(|expect\s*\(|assert\.|jest\.|mocha|chai|@Test|unittest|pytest/i.test(code);
            if (isTestCode) {
                adjustedSeverity = this._reduceSeverity(adjustedSeverity);
                suppressionReason = 'Test file detected — severity reduced';
            }

            // 2. Framework-safe patterns
            if (frameworkContext && frameworkContext.safePatterns) {
                for (const [vulnType, safePattern] of Object.entries(frameworkContext.safePatterns)) {
                    if (issue.cwe && this._cweMatchesVulnType(issue.cwe, vulnType) && safePattern.test(code)) {
                        if (adjustedConfidence === 'confirmed') adjustedConfidence = 'likely';
                        else if (adjustedConfidence === 'likely') adjustedConfidence = 'possible';
                        suppressionReason = `${frameworkContext.label} framework uses safe pattern for ${vulnType}`;
                    }
                }
            }

            // 3. Django ORM auto-safety for SQL injection
            if (frameworkContext?.name === 'django' && issue.cwe === 'CWE-89') {
                if (/objects\.(filter|get|all|exclude|create|update)\s*\(/i.test(code)) {
                    adjustedConfidence = 'possible';
                    suppressionReason = 'Django ORM provides built-in SQL injection protection';
                }
            }

            // 4. Comment-based threat indicators
            const snippet = issue.snippet || '';
            if (/TODO.*security|FIXME.*vuln|HACK|XXX.*danger/i.test(snippet)) {
                // Developer aware of issue — boost confidence
                if (adjustedConfidence === 'possible') adjustedConfidence = 'likely';
                suppressionReason = 'Developer comment acknowledges security concern';
            }

            // 5. Config/example file detection
            const isConfigExample = /example|sample|demo|template|boilerplate|starter/i.test(code.substring(0, 200));
            if (isConfigExample && adjustedSeverity !== 'critical') {
                adjustedSeverity = this._reduceSeverity(adjustedSeverity);
                suppressionReason = 'Example/template code detected — severity reduced';
            }

            // 6. General Security Library Presence (Heuristic)
            // If security libs are present, reduce confidence of unconfirmed pattern matches
            const hasSecurityLibs = /helmet|cors|csurf|rate-limit|mongo-sanitize|xss-filters|validator|DOMPurify/i.test(code);
            if (hasSecurityLibs && adjustedConfidence === 'possible' && !issue.dataFlow) {
                adjustedConfidence = 'low'; // Downgrade further
                suppressionReason = 'Security libraries detected — manual review recommended';
            }

            // 7. Critical Severity Sanity Check
            // If Critical but only "possible" confidence, downgrade to High unless it's RCE (handled separately)
            if (adjustedSeverity === 'critical' && adjustedConfidence === 'possible' && !issue._v5_rce) {
                adjustedSeverity = 'high';
                suppressionReason = 'Critical severity requires higher confidence — downgraded to High pending verification';
            }

            return {
                ...issue,
                confidence: adjustedConfidence,
                severity: adjustedSeverity,
                suppression: suppressionReason,
                originalConfidence: suppressionReason ? issue.confidence : undefined,
                originalSeverity: suppressionReason ? issue.severity : undefined,
            };
        });
    },

    // ═══════════════════════════════════════════════════════════
    //  EXPLOIT LIKELIHOOD CLASSIFIER
    //  Ranks findings by real-world exploitability
    // ═══════════════════════════════════════════════════════════

    classifyExploitLikelihood(issues, reachability, frameworkContext) {
        return issues.map(issue => {
            let likelihood = 50; // base score out of 100

            // 1. Reachability from public routes
            if (issue._functionName && reachability) {
                const reach = reachability[issue._functionName] || 0.3;
                likelihood += Math.round(reach * 25); // +0 to +25
            }

            // 2. Confidence level impact
            if (issue.confidence === 'confirmed') likelihood += 20;
            else if (issue.confidence === 'likely') likelihood += 10;
            else likelihood -= 10;

            // 3. Attack vector
            if (issue.attackVector === 'network') likelihood += 10;
            else if (issue.attackVector === 'adjacent') likelihood += 5;

            // 4. Framework security middleware present
            if (frameworkContext?.hasSecurityConfig) {
                likelihood -= 10;
            }

            // 5. Severity multiplier
            if (issue.severity === 'critical') likelihood += 15;
            else if (issue.severity === 'high') likelihood += 5;
            else if (issue.severity === 'low') likelihood -= 15;

            // 6. Data-flow confirmed
            if (issue.dataFlow) likelihood += 15;

            // 7. Inter-procedural flow
            if (issue._isInterProcedural) likelihood += 10;

            // Clamp
            likelihood = Math.max(5, Math.min(99, likelihood));

            return {
                ...issue,
                exploitLikelihood: likelihood,
                exploitRating: likelihood >= 75 ? 'Very Likely' : likelihood >= 50 ? 'Likely' : likelihood >= 25 ? 'Possible' : 'Unlikely'
            };
        });
    },

    // ═══════════════════════════════════════════════════════════
    //  INTELLIGENT DEDUPLICATION & ROOT-CAUSE CLUSTERING
    // ═══════════════════════════════════════════════════════════

    intelligentDedup(issues) {
        // Group by root cause: same CWE + same source variable/location
        const clusters = new Map();

        for (const issue of issues) {
            // Generate cluster key based on root cause
            const sourceVar = issue.dataFlow?.variable || issue._taintVariable || '';
            const rootCWE = issue.cwe || 'UNKNOWN';
            const clusterKey = `${rootCWE}::${sourceVar}`;

            if (!clusters.has(clusterKey)) {
                clusters.set(clusterKey, {
                    primary: issue,
                    related: [],
                    rootCause: sourceVar ? `Unsanitized variable: ${sourceVar}` : issue.name
                });
            } else {
                const cluster = clusters.get(clusterKey);

                // Keep the highest-confidence finding as primary
                if (this._confidenceRank(issue.confidence) > this._confidenceRank(cluster.primary.confidence)) {
                    cluster.related.push(cluster.primary);
                    cluster.primary = issue;
                } else {
                    cluster.related.push(issue);
                }
            }
        }

        // Merge pattern + data-flow confirmations
        const result = [];
        for (const [, cluster] of clusters) {
            const primary = { ...cluster.primary };

            if (cluster.related.length > 0) {
                // Enrich primary with data from related findings
                primary._relatedCount = cluster.related.length;
                primary._rootCause = cluster.rootCause;
                primary._clusterSize = cluster.related.length + 1;

                // If any related finding has data-flow confirmation, upgrade
                const hasConfirmed = cluster.related.some(r => r.confidence === 'confirmed');
                if (hasConfirmed && primary.confidence !== 'confirmed') {
                    primary.confidence = 'confirmed';
                    primary._mergedConfirmation = true;
                }

                // Collect all unique locations
                const locations = new Set([primary.location]);
                cluster.related.forEach(r => { if (r.location) locations.add(r.location); });
                if (locations.size > 1) {
                    primary._affectedLocations = Array.from(locations);
                }
            }

            result.push(primary);
        }

        return result;
    },

    // ═══════════════════════════════════════════════════════════
    //  ATTACK SCENARIO GENERATOR
    //  Builds step-by-step exploitation narratives
    // ═══════════════════════════════════════════════════════════

    generateAttackScenarios(issues, frameworkContext) {
        const scenarios = [];

        // Group critical/high issues into attack chains
        const criticalIssues = issues.filter(i => i.severity === 'critical' || i.severity === 'high');

        // Scenario 1: Authentication bypass + data access
        const authIssues = criticalIssues.filter(i =>
            /auth|login|session|csrf|access control/i.test(i.name));
        const dataIssues = criticalIssues.filter(i =>
            /sql|injection|traversal|ssrf/i.test(i.name));

        if (authIssues.length > 0 && dataIssues.length > 0) {
            scenarios.push({
                title: 'Authentication Bypass → Data Exfiltration',
                severity: 'critical',
                steps: [
                    `Attacker exploits ${authIssues[0].name} to bypass authentication`,
                    `Without auth checks, attacker accesses protected endpoints`,
                    `Attacker leverages ${dataIssues[0].name} to extract sensitive data`,
                    `Database contents, user credentials, or internal files are exfiltrated`,
                ],
                impact: 'Complete data breach — all user data and system secrets compromised',
                findings: [...authIssues.slice(0, 2), ...dataIssues.slice(0, 2)].map(i => i.name),
            });
        }

        // Scenario 2: Injection → RCE
        const injectionIssues = criticalIssues.filter(i =>
            /injection|exec|eval|deserialization|command/i.test(i.name));
        if (injectionIssues.length > 0) {
            scenarios.push({
                title: 'Remote Code Execution (RCE) Chain',
                severity: 'critical',
                steps: [
                    `Attacker identifies ${injectionIssues[0].name} on a public endpoint`,
                    `Crafted payload is submitted via user input`,
                    `Server executes attacker-controlled code/commands`,
                    `Attacker gains shell access and full system control`,
                ],
                impact: 'Full server compromise — attacker controls the system',
                findings: injectionIssues.slice(0, 3).map(i => i.name),
            });
        }

        // Scenario 3: Secrets exposure
        const secretIssues = issues.filter(i =>
            /secret|key|password|credential|token/i.test(i.name));
        if (secretIssues.length > 0) {
            scenarios.push({
                title: 'Credential Exposure → Account Takeover',
                severity: 'high',
                steps: [
                    `${secretIssues[0].name} found in source code`,
                    'Attacker clones repository or accesses version control history',
                    'Extracted credentials used to access external services',
                    'Cloud infrastructure, APIs, or databases compromised',
                ],
                impact: 'Third-party service compromise via exposed credentials',
                findings: secretIssues.slice(0, 3).map(i => i.name),
            });
        }

        // Scenario 4: XSS → Session Hijacking
        const xssIssues = criticalIssues.filter(i => /xss|cross-site scripting/i.test(i.name));
        const cookieIssues = issues.filter(i => /cookie|session/i.test(i.name));
        if (xssIssues.length > 0) {
            scenarios.push({
                title: 'XSS → Session Hijacking',
                severity: 'high',
                steps: [
                    `Attacker injects malicious script via ${xssIssues[0].name}`,
                    "Script executes in victim's browser context",
                    `Session cookies ${cookieIssues.length > 0 ? '(missing HttpOnly flag)' : ''} are stolen`,
                    'Attacker impersonates the victim and accesses their account',
                ],
                impact: 'User account takeover — attacker acts as the victim',
                findings: [...xssIssues.slice(0, 2), ...cookieIssues.slice(0, 1)].map(i => i.name),
            });
        }

        return scenarios;
    },

    // ═══════════════════════════════════════════════════════════
    //  PRIVACY-PRESERVING PATTERN LEARNING
    //  Stores only anonymized vulnerability hashes (opt-in)
    // ═══════════════════════════════════════════════════════════

    learnFromScan(issues) {
        try {
            const existing = JSON.parse(localStorage.getItem('securescan_patterns') || '{}');

            for (const issue of issues) {
                // Abstract pattern hash — no raw code stored
                const patternKey = `${issue.cwe || 'UNK'}::${issue.severity}::${issue.confidence}`;
                if (!existing[patternKey]) {
                    existing[patternKey] = { count: 0, lastSeen: null };
                }
                existing[patternKey].count++;
                existing[patternKey].lastSeen = new Date().toISOString();
            }

            existing._scanCount = (existing._scanCount || 0) + 1;
            existing._lastScan = new Date().toISOString();

            localStorage.setItem('securescan_patterns', JSON.stringify(existing));
        } catch (e) {
            // localStorage not available — silently skip
        }
    },

    getPatternInsights() {
        try {
            const data = JSON.parse(localStorage.getItem('securescan_patterns') || '{}');
            if (!data._scanCount) return null;

            const patterns = Object.entries(data)
                .filter(([k]) => !k.startsWith('_'))
                .map(([key, val]) => ({ pattern: key, ...val }))
                .sort((a, b) => b.count - a.count);

            return {
                totalScans: data._scanCount,
                lastScan: data._lastScan,
                topPatterns: patterns.slice(0, 10),
                totalPatternsLearned: patterns.length,
            };
        } catch (e) {
            return null;
        }
    },

    // ═══════════════════════════════════════════════════════════
    //  UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    _reduceSeverity(severity) {
        const map = { critical: 'high', high: 'medium', medium: 'low', low: 'low' };
        return map[severity] || severity;
    },

    _confidenceRank(confidence) {
        return { confirmed: 3, likely: 2, possible: 1 }[confidence] || 0;
    },

    _cweMatchesVulnType(cwe, vulnType) {
        const map = {
            sql: ['CWE-89'],
            xss: ['CWE-79'],
            cmd: ['CWE-78'],
            ssrf: ['CWE-918'],
            path: ['CWE-22'],
        };
        return map[vulnType]?.includes(cwe) || false;
    }
};
