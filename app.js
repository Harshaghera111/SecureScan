/* ============================================================
   SecureScan — Application Logic
   ============================================================ */

(function () {
    'use strict';

    // ── DOM REFS ──
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const pages = {
        landing: $('#page-landing'),
        input: $('#page-input'),
        processing: $('#page-processing'),
        results: $('#page-results'),
    };

    // ── STATE ──
    let currentInputType = 'code';
    let uploadedImageData = null;

    // ════════════════════════════════════════════════════
    //  NAVIGATION
    // ════════════════════════════════════════════════════

    function showPage(pageId) {
        Object.values(pages).forEach(p => p.classList.remove('active'));
        pages[pageId].classList.add('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });

        // Show/hide navbar based on page
        const navbar = $('#navbar');
        if (pageId === 'processing') {
            navbar.style.display = 'none';
        } else {
            navbar.style.display = '';
        }
    }

    // CTA buttons → Input page
    ['#hero-cta-btn', '#nav-cta-btn', '#mobile-cta-btn', '#cta-start-btn'].forEach(sel => {
        const el = $(sel);
        if (el) el.addEventListener('click', (e) => {
            e.preventDefault();
            closeMobileMenu();
            showPage('input');
        });
    });

    // Back buttons
    $('#back-to-landing')?.addEventListener('click', () => showPage('landing'));
    $('#back-to-input')?.addEventListener('click', () => showPage('input'));
    $('#new-scan-btn')?.addEventListener('click', () => showPage('input'));

    // Logo → landing
    $('#nav-logo-btn')?.addEventListener('click', (e) => {
        e.preventDefault();
        showPage('landing');
    });

    // ── Mobile Menu ──
    const mobileMenuBtn = $('#mobile-menu-btn');
    const mobileMenu = $('#mobile-menu');

    function closeMobileMenu() {
        mobileMenu?.classList.remove('open');
    }

    mobileMenuBtn?.addEventListener('click', () => {
        mobileMenu.classList.toggle('open');
    });

    $$('.mobile-link').forEach(link => {
        link.addEventListener('click', closeMobileMenu);
    });

    // ── Navbar scroll effect ──
    window.addEventListener('scroll', () => {
        const navbar = $('#navbar');
        if (window.scrollY > 40) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // ── Smooth scroll for anchor links ──
    $$('a[href^="#"]').forEach(link => {
        link.addEventListener('click', (e) => {
            const targetId = link.getAttribute('href');
            if (targetId === '#') return;
            const target = $(targetId);
            if (target) {
                e.preventDefault();
                closeMobileMenu();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    // ════════════════════════════════════════════════════
    //  HERO STATS COUNTER ANIMATION
    // ════════════════════════════════════════════════════

    function animateCounters() {
        $$('.stat-value[data-count]').forEach(el => {
            const target = parseInt(el.dataset.count);
            const duration = 1500;
            const startTime = performance.now();

            function update(currentTime) {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                el.textContent = Math.floor(target * eased);
                if (progress < 1) requestAnimationFrame(update);
            }
            requestAnimationFrame(update);
        });
    }

    // Trigger counters when hero is visible
    const heroObserver = new IntersectionObserver(
        (entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounters();
                    heroObserver.unobserve(entry.target);
                }
            });
        },
        { threshold: 0.5 }
    );

    const heroStats = $('.hero-stats');
    if (heroStats) heroObserver.observe(heroStats);

    // ════════════════════════════════════════════════════
    //  ENGINE TABS (Landing Page)
    // ════════════════════════════════════════════════════

    $$('.engine-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.engine-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const engine = tab.dataset.engine;
            $$('.engine-panel').forEach(p => p.classList.remove('active'));
            $(`#engine-${engine}`)?.classList.add('active');
        });
    });

    // ════════════════════════════════════════════════════
    //  INPUT PAGE
    // ════════════════════════════════════════════════════

    // ── Input Type Tabs ──
    $$('.input-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.input-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentInputType = tab.dataset.type;

            $$('.input-panel').forEach(p => p.classList.remove('active'));
            $(`#panel-${currentInputType}`)?.classList.add('active');
            validateInput();
        });
    });

    // ── Code Editor ──
    const codeInput = $('#code-input');
    const lineNumbers = $('#line-numbers');

    function updateLineNumbers() {
        if (!codeInput || !lineNumbers) return;
        const lines = codeInput.value.split('\n').length;
        lineNumbers.innerHTML = Array.from({ length: Math.max(lines, 15) }, (_, i) => i + 1).join('<br>');
    }

    codeInput?.addEventListener('input', () => {
        updateLineNumbers();
        validateInput();
    });
    codeInput?.addEventListener('scroll', () => {
        lineNumbers.scrollTop = codeInput.scrollTop;
    });

    // Initialize line numbers
    updateLineNumbers();

    // ── Sample Code ──
    const SAMPLE_CODE = `const express = require('express');
const mysql = require('mysql');
const app = express();

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'admin123',    // Hardcoded credentials
    database: 'myapp'
});

// API Key (hardcoded secret)
const API_KEY = "sk-proj-abc123xyz456_REAL_KEY";

app.get('/user', (req, res) => {
    // SQL Injection vulnerability
    const query = \`SELECT * FROM users WHERE id = \${req.params.id}\`;
    db.query(query, (err, result) => {
        res.send(result);
    });
});

app.get('/search', (req, res) => {
    // XSS vulnerability
    const name = req.query.name;
    res.send(\`<h1>Hello \${name}</h1>\`);
});

app.post('/login', (req, res) => {
    // No rate limiting, no password hashing
    const { username, password } = req.body;
    const query = \`SELECT * FROM users WHERE username='\${username}' AND password='\${password}'\`;
    db.query(query, (err, result) => {
        if (result.length > 0) {
            res.json({ token: 'static_token_123' }); // Static token
        }
    });
});

app.listen(3000);`;

    $('#paste-sample-btn')?.addEventListener('click', () => {
        codeInput.value = SAMPLE_CODE;
        updateLineNumbers();
        validateInput();
    });

    $('#clear-code-btn')?.addEventListener('click', () => {
        codeInput.value = '';
        updateLineNumbers();
        validateInput();
    });

    // ── Text Input ──
    const textInput = $('#text-input');
    const textCharCount = $('#text-char-count');

    textInput?.addEventListener('input', () => {
        textCharCount.textContent = textInput.value.length;
        validateInput();
    });

    const SAMPLE_TEXT = `From: support@paypa1-secure.com
Subject: ⚠️ URGENT: Your Account Has Been Compromised!

Dear Valued Customer,

We have detected unauthorized access to your account. Your account will be SUSPENDED within 24 hours unless you verify your identity immediately.

Click here to verify: http://paypa1-secure.xyz/verify?token=abc123

You must provide the following information:
- Full name
- Social Security Number
- Credit card number
- Account password

This is an automated message from PayPal Security Team.
If you do not respond within 24 hours, your account and funds will be permanently frozen.

Regards,
PayPal Security Department
Reference: #PP-SEC-2026-0215`;

    $('#paste-sample-text-btn')?.addEventListener('click', () => {
        textInput.value = SAMPLE_TEXT;
        textCharCount.textContent = textInput.value.length;
        validateInput();
    });

    // ── Image Upload ──
    const imageDropZone = $('#image-drop-zone');
    const imageFileInput = $('#image-file-input');
    const uploadPlaceholder = $('#upload-placeholder');
    const uploadPreview = $('#upload-preview');
    const previewImage = $('#preview-image');

    $('#browse-image-btn')?.addEventListener('click', () => imageFileInput.click());

    imageDropZone?.addEventListener('click', (e) => {
        if (e.target.closest('#remove-image-btn') || e.target.closest('#browse-image-btn')) return;
        if (!uploadedImageData) imageFileInput.click();
    });

    imageDropZone?.addEventListener('dragover', (e) => {
        e.preventDefault();
        imageDropZone.classList.add('drag-over');
    });

    imageDropZone?.addEventListener('dragleave', () => {
        imageDropZone.classList.remove('drag-over');
    });

    imageDropZone?.addEventListener('drop', (e) => {
        e.preventDefault();
        imageDropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) handleImageFile(file);
    });

    imageFileInput?.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleImageFile(file);
    });

    function handleImageFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            uploadedImageData = e.target.result;
            previewImage.src = uploadedImageData;
            uploadPlaceholder.classList.add('hidden');
            uploadPreview.classList.remove('hidden');
            validateInput();
        };
        reader.readAsDataURL(file);
    }

    $('#remove-image-btn')?.addEventListener('click', (e) => {
        e.stopPropagation();
        uploadedImageData = null;
        previewImage.src = '';
        uploadPreview.classList.add('hidden');
        uploadPlaceholder.classList.remove('hidden');
        imageFileInput.value = '';
        validateInput();
    });

    // ── Validate Input ──
    const analyzeBtn = $('#analyze-btn');

    function validateInput() {
        let hasInput = false;
        if (currentInputType === 'code') hasInput = codeInput.value.trim().length > 0;
        else if (currentInputType === 'text') hasInput = textInput.value.trim().length > 0;
        else if (currentInputType === 'image') hasInput = !!uploadedImageData;

        analyzeBtn.disabled = !hasInput;
    }

    // ════════════════════════════════════════════════════
    //  ANALYZE → PROCESSING → RESULTS
    // ════════════════════════════════════════════════════

    analyzeBtn?.addEventListener('click', () => {
        startAnalysis();
    });

    // ════════════════════════════════════════════════════
    //  COMPLEXITY-BASED TIMING CALCULATOR
    // ════════════════════════════════════════════════════

    function calculateAnalysisComplexity() {
        let inputSize = 0;
        if (currentInputType === 'code') {
            inputSize = (codeInput.value || '').split('\n').length;
        } else if (currentInputType === 'text') {
            inputSize = (textInput.value || '').length;
        } else {
            inputSize = 200; // images default to medium complexity
        }
        // Return base delay per phase in ms
        if (currentInputType === 'code') {
            if (inputSize < 50) return { baseDelay: 700, jitter: 400, label: 'standard' };
            if (inputSize < 200) return { baseDelay: 1100, jitter: 600, label: 'deep' };
            return { baseDelay: 1500, jitter: 800, label: 'comprehensive' };
        }
        if (currentInputType === 'text') {
            if (inputSize < 500) return { baseDelay: 750, jitter: 350, label: 'standard' };
            return { baseDelay: 1100, jitter: 500, label: 'deep' };
        }
        return { baseDelay: 1200, jitter: 600, label: 'deep' };
    }

    // ════════════════════════════════════════════════════
    //  12-PHASE DEEP INTELLIGENCE PIPELINE
    // ════════════════════════════════════════════════════

    let analysisStartTime = 0;

    function startAnalysis() {
        showPage('processing');
        analysisStartTime = performance.now();

        const progressFill = $('#progress-fill');
        const progressPercent = $('#progress-percent');
        const processingStatus = $('#processing-status');
        const confidenceFill = $('#confidence-bar-fill');
        const confidenceValue = $('#confidence-value');

        const complexity = calculateAnalysisComplexity();

        const phases = [
            { id: 'step-tokenize', text: 'Tokenizing & parsing input structure...', progress: 5, confidence: 3 },
            { id: 'step-ast', text: 'Building abstract syntax tree (AST)...', progress: 12, confidence: 8 },
            { id: 'step-cfg', text: 'Generating control-flow graph (CFG)...', progress: 20, confidence: 14 },
            { id: 'step-callgraph', text: 'Constructing inter-procedural call graph...', progress: 28, confidence: 20 },
            { id: 'step-taint', text: 'Identifying taint sources & sinks...', progress: 36, confidence: 30 },
            { id: 'step-interprocedural', text: 'Propagating taint across function boundaries...', progress: 46, confidence: 40 },
            { id: 'step-dataflow', text: 'Tracing data-flow paths through execution graph...', progress: 56, confidence: 50 },
            { id: 'step-patterns', text: 'Matching 25+ OWASP & CWE vulnerability patterns...', progress: 66, confidence: 62 },
            { id: 'step-framework', text: 'Detecting framework context & security config...', progress: 76, confidence: 72 },
            { id: 'step-threat', text: 'Correlating CVEs & threat intelligence data...', progress: 86, confidence: 82 },
            { id: 'step-scoring', text: 'Computing multi-dimensional risk scores...', progress: 94, confidence: 90 },
            { id: 'step-report', text: 'Generating deep intelligence report...', progress: 100, confidence: 96 },
        ];

        // Reset all phases
        phases.forEach(p => {
            const el = document.getElementById(p.id);
            if (el) el.classList.remove('active', 'done');
        });
        progressFill.style.width = '0%';
        progressPercent.textContent = '0%';
        confidenceFill.style.width = '0%';
        confidenceValue.textContent = '0%';

        // Run real analysis in parallel (result arrives while phases animate)
        let analysisResult = null;
        const analysisPromise = runRealAnalysis().then(r => { analysisResult = r; });

        let phaseIndex = 0;

        function nextPhase() {
            // Mark previous phase as done
            if (phaseIndex > 0) {
                const prev = document.getElementById(phases[phaseIndex - 1].id);
                if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
            }

            if (phaseIndex >= phases.length) {
                // All phases done — wait for actual analysis to finish, then show results
                analysisPromise.then(() => {
                    const duration = ((performance.now() - analysisStartTime) / 1000).toFixed(1);
                    if (analysisResult) analysisResult._duration = duration;
                    setTimeout(() => {
                        renderResults(analysisResult);
                        showPage('results');
                    }, 400);
                });
                return;
            }

            const phase = phases[phaseIndex];
            const el = document.getElementById(phase.id);
            if (el) el.classList.add('active');
            processingStatus.textContent = phase.text;
            progressFill.style.width = phase.progress + '%';
            progressPercent.textContent = phase.progress + '%';
            confidenceFill.style.width = phase.confidence + '%';
            confidenceValue.textContent = phase.confidence + '%';

            phaseIndex++;
            setTimeout(nextPhase, complexity.baseDelay + Math.random() * complexity.jitter);
        }

        setTimeout(nextPhase, 500);
    }

    // ════════════════════════════════════════════════════
    //  REAL ANALYSIS ENGINE (via analyzer.js)
    // ════════════════════════════════════════════════════

    async function runRealAnalysis() {
        if (currentInputType === 'code') {
            return SecureScanAnalyzer.analyzeCode(codeInput.value);
        } else if (currentInputType === 'text') {
            return SecureScanAnalyzer.analyzeText(textInput.value);
        } else if (currentInputType === 'image') {
            return await SecureScanAnalyzer.analyzeImage(uploadedImageData);
        }
    }


    // ════════════════════════════════════════════════════
    //  RENDER RESULTS
    // ════════════════════════════════════════════════════

    function renderResults(data) {
        // ── Score gauge ──
        const scoreValue = $('#score-value');
        const gaugeFill = $('#gauge-fill');
        const circumference = 2 * Math.PI * 85; // r = 85

        // Animate score number
        animateNumber(scoreValue, 0, data.score, 1500);

        // Animate gauge arc
        const offset = circumference - (data.score / 100) * circumference;
        setTimeout(() => {
            gaugeFill.style.strokeDashoffset = offset;

            // Dynamic color based on score
            const gauge = $('#score-gauge');
            const gradId = 'gauge-gradient';
            let existingGrad = gauge.querySelector(`#${gradId}`);
            if (!existingGrad) {
                const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
                const grad = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
                grad.id = gradId;
                const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
                stop1.setAttribute('offset', '0%');
                const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
                stop2.setAttribute('offset', '100%');

                if (data.score >= 76) {
                    stop1.setAttribute('stop-color', '#f97316');
                    stop2.setAttribute('stop-color', '#ef4444');
                } else if (data.score >= 51) {
                    stop1.setAttribute('stop-color', '#eab308');
                    stop2.setAttribute('stop-color', '#f97316');
                } else if (data.score >= 26) {
                    stop1.setAttribute('stop-color', '#22c55e');
                    stop2.setAttribute('stop-color', '#eab308');
                } else {
                    stop1.setAttribute('stop-color', '#06b6d4');
                    stop2.setAttribute('stop-color', '#22c55e');
                }

                grad.appendChild(stop1);
                grad.appendChild(stop2);
                defs.appendChild(grad);
                gauge.insertBefore(defs, gauge.firstChild);
            }
        }, 100);

        // ── Rating badge ──
        const ratingEl = $('#score-rating');
        ratingEl.innerHTML = `
            <span class="rating-badge" style="background:${data.rating.bg};color:${data.rating.color}">${data.rating.label}</span>
            <span class="rating-text">${data.score >= 76 ? 'Immediate action required' : data.score >= 51 ? 'Several issues need attention' : 'Minor improvements suggested'}</span>
        `;

        // ── Severity counts ──
        animateNumber($('#count-critical'), 0, data.counts.critical, 800);
        animateNumber($('#count-high'), 0, data.counts.high, 900);
        animateNumber($('#count-medium'), 0, data.counts.medium, 1000);
        animateNumber($('#count-low'), 0, data.counts.low, 1100);

        // ── Analysis meta bar (V4) ──
        const confIdx = data.meta?.confidenceIndex ?? 0;
        const confFill = document.getElementById('result-confidence-fill');
        const confVal = document.getElementById('result-confidence-value');
        if (confFill) confFill.style.width = confIdx + '%';
        if (confVal) confVal.textContent = confIdx + '%';
        const durEl = document.getElementById('result-duration');
        if (durEl) durEl.textContent = (data._duration || '—') + 's';
        const engEl = document.getElementById('result-engine');
        if (engEl) engEl.textContent = (data.meta?.engine || 'SecureScan') + ' v' + (data.meta?.version || '4.0');

        // V4: Framework badge
        if (data._v4 && data._v4.frameworkDetected) {
            const fwEl = document.getElementById('meta-framework');
            const fwVal = document.getElementById('result-framework');
            if (fwEl) fwEl.style.display = '';
            if (fwVal) fwVal.textContent = data._v4.frameworkDetected;
        }
        // V4: CVE count badge
        if (data._v4 && data._v4.cveMatches > 0) {
            const cveEl = document.getElementById('meta-cve-count');
            const cveVal = document.getElementById('result-cve-count');
            if (cveEl) cveEl.style.display = '';
            if (cveVal) cveVal.textContent = data._v4.cveMatches;
        }

        // ── Issues list ──
        const issuesList = $('#issues-list');
        issuesList.innerHTML = '';

        data.issues.forEach((issue, i) => {
            const card = document.createElement('div');
            card.className = 'issue-card';
            card.dataset.severity = issue.severity;
            card.style.animationDelay = `${i * 0.08}s`;

            // Build enterprise metadata badges
            const badges = [];
            if (issue.cwe) badges.push(`<span class="meta-badge cwe" title="${issue.cweName || ''}">${issue.cwe}</span>`);
            if (issue.owasp) badges.push(`<span class="meta-badge owasp" title="${issue.owaspName || ''}">${issue.owasp}</span>`);
            if (issue.confidence) {
                const confColors = { confirmed: '#ef4444', likely: '#f97316', possible: '#eab308' };
                const confIcons = { confirmed: '🔴', likely: '🟠', possible: '🟡' };
                badges.push(`<span class="meta-badge confidence" style="border-color:${confColors[issue.confidence]}">${confIcons[issue.confidence]} ${issue.confidence}</span>`);
            }
            const badgeHtml = badges.length ? `<div class="issue-meta-badges">${badges.join('')}</div>` : '';

            // Build exploit example block
            let exploitHtml = '';
            if (issue.exploit) {
                exploitHtml = `
                    <div class="exploit-example">
                        <div class="exploit-label">⚔️ Exploit Example</div>
                        <pre class="exploit-code"><code>${escapeHtml(issue.exploit)}</code></pre>
                    </div>`;
            }

            // Build remediation code snippet block
            let remediationHtml = '';
            if (issue.remediation) {
                remediationHtml = `
                    <div class="remediation-snippet">
                        <div class="remediation-label">✅ Secure Code</div>
                        <pre class="remediation-code"><code>${escapeHtml(issue.remediation)}</code></pre>
                    </div>`;
            }

            // Build data-flow trace
            let flowHtml = '';
            if (issue.dataFlow && issue.dataFlow.length > 0) {
                const flowSteps = issue.dataFlow.map((step, idx) => {
                    const icon = idx === 0 ? '🟢' : idx === issue.dataFlow.length - 1 ? '🔴' : '→';
                    return `<span class="flow-step">${icon} ${escapeHtml(step)}</span>`;
                }).join('');
                flowHtml = `<div class="data-flow-trace"><div class="flow-label">📊 Data Flow</div><div class="flow-steps">${flowSteps}</div></div>`;
            }

            card.innerHTML = `
                <div class="issue-card-header">
                    <span class="issue-severity-badge ${issue.severity}">${issue.severity}</span>
                    <div class="issue-info">
                        <div class="issue-name">${issue.name}</div>
                        <div class="issue-location">${issue.location || ''}</div>
                    </div>
                    <svg class="issue-toggle" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </div>
                <div class="issue-details">
                    ${badgeHtml}
                    <p class="issue-description">${issue.description}</p>
                    ${flowHtml}
                    <pre class="issue-snippet"><code>${escapeHtml(issue.snippet)}</code></pre>
                    ${exploitHtml}
                    ${remediationHtml}
                    <div class="issue-fix">
                        <div class="issue-fix-label">💡 Recommended Fix</div>
                        <p class="issue-fix-text">${issue.fix}</p>
                    </div>
                </div>
            `;

            card.querySelector('.issue-card-header').addEventListener('click', () => {
                card.classList.toggle('open');
            });

            issuesList.appendChild(card);
        });

        // ── Recommendations ──
        const recList = $('#recommendations-list');
        recList.innerHTML = '';

        data.recommendations.forEach(rec => {
            const card = document.createElement('div');
            card.className = 'rec-card';
            card.innerHTML = `
                <div class="rec-icon">${rec.icon}</div>
                <div>
                    <div class="rec-title">${rec.title}</div>
                    <div class="rec-desc">${rec.desc}</div>
                </div>
            `;
            recList.appendChild(card);
        });

        // ── V4: Attack Scenarios ──
        if (data._attackScenarios && data._attackScenarios.length > 0) {
            const scenarioSection = document.getElementById('attack-scenarios-section');
            const scenarioList = document.getElementById('attack-scenarios-list');
            if (scenarioSection && scenarioList) {
                scenarioSection.style.display = '';
                scenarioList.innerHTML = '';
                data._attackScenarios.forEach(scenario => {
                    const card = document.createElement('div');
                    card.className = 'attack-scenario-card';
                    const stepsHtml = scenario.steps.map((step, idx) =>
                        `<div class="scenario-step"><span class="scenario-step-num">${idx + 1}</span><span>${escapeHtml(step)}</span></div>`
                    ).join('');
                    card.innerHTML = `
                        <div class="scenario-header">
                            <span class="scenario-severity ${scenario.severity}">${scenario.severity}</span>
                            <span class="scenario-title">${escapeHtml(scenario.title)}</span>
                        </div>
                        <div class="scenario-steps">${stepsHtml}</div>
                        <div class="scenario-impact">
                            <strong>Impact:</strong> ${escapeHtml(scenario.impact)}
                        </div>
                    `;
                    scenarioList.appendChild(card);
                });
            }
        }

        // ── Filter buttons ──
        $$('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                $$('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.dataset.filter;

                $$('.issue-card').forEach(card => {
                    if (filter === 'all' || card.dataset.severity === filter) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });
    }

    // ── Helpers ──
    function animateNumber(el, start, end, duration) {
        const startTime = performance.now();
        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.floor(start + (end - start) * eased);
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ── Export Report ──
    $('#export-btn')?.addEventListener('click', () => {
        const reportContent = generateReportText();
        const blob = new Blob([reportContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SecureScan_Report_${new Date().toISOString().slice(0, 10)}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    });

    function generateReportText() {
        const issues = $$('.issue-card');
        let report = '═══════════════════════════════════════\n';
        report += '  SecureScan Security Report\n';
        report += '  Generated: ' + new Date().toLocaleString() + '\n';
        report += '═══════════════════════════════════════\n\n';
        report += `Input Type: ${currentInputType.toUpperCase()}\n`;
        report += `Insecurity Score: ${$('#score-value').textContent}/100\n`;
        report += `Total Issues: ${issues.length}\n\n`;
        report += '───────────────────────────────────────\n';
        report += '  ISSUES FOUND\n';
        report += '───────────────────────────────────────\n\n';

        issues.forEach((card, i) => {
            const severity = card.querySelector('.issue-severity-badge').textContent.toUpperCase();
            const name = card.querySelector('.issue-name').textContent;
            const desc = card.querySelector('.issue-description').textContent;
            const fix = card.querySelector('.issue-fix-text').textContent;
            report += `${i + 1}. [${severity}] ${name}\n`;
            report += `   ${desc}\n`;
            report += `   Fix: ${fix}\n\n`;
        });

        report += '───────────────────────────────────────\n';
        report += '  Report generated by SecureScan\n';
        report += '═══════════════════════════════════════\n';
        return report;
    }

    // ── Intersection Observer for fade-in animations ──
    const fadeObserver = new IntersectionObserver(
        (entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        },
        { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
    );

    $$('[data-aos]').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(24px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        const delay = el.dataset.aosDelay;
        if (delay) el.style.transitionDelay = delay + 'ms';
        fadeObserver.observe(el);
    });

})();
