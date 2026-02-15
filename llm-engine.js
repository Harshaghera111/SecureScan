/* ════════════════════════════════════════════════════════════════
   SecureScan v2 — LLM Intelligence Engine
   Handles AI analysis via OpenAI/Gemini APIs with high-fidelity 
   simulation for demo purposes.
   ════════════════════════════════════════════════════════════════ */

class LLMEngine {
    constructor() {
        this.apiKey = localStorage.getItem('securescan_api_key') || '';
        this.provider = localStorage.getItem('securescan_provider') || 'mock'; // 'openai', 'gemini', 'mock'
        this.model = localStorage.getItem('securescan_model') || 'gpt-4-turbo';
    }

    /**
     * Main entry point for analysis
     * @param {string} content - The code, text, or image (base64) to analyze
     * @param {string} type - 'code', 'text', 'image'
     * @returns {Promise<Object>} - Structured security report
     */
    async analyze(content, type) {
        if (!content) throw new Error("No content provided");

        if (this.provider === 'mock' || !this.apiKey) {
            return this._runSimulation(content, type);
        }

        try {
            if (this.provider === 'openai') {
                return await this._callOpenAI(content, type);
            } else if (this.provider === 'gemini') {
                return await this._callGemini(content, type);
            }
        } catch (error) {
            console.error("LLM API Error:", error);
            // Fallback to simulation on error to prevent app crash
            return this._runSimulation(content, type, error.message);
        }
    }

    /**
     * Update settings
     */
    configure(apiKey, provider, model) {
        this.apiKey = apiKey;
        this.provider = provider;
        this.model = model;
        localStorage.setItem('securescan_api_key', apiKey);
        localStorage.setItem('securescan_provider', provider);
        localStorage.setItem('securescan_model', model);
    }

    // ════════════════════════════════════════════════════
    //  OPENAI INTEGRATION
    // ════════════════════════════════════════════════════
    async _callOpenAI(content, type) {
        const systemPrompt = this._getSystemPrompt(type);

        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.apiKey}`
            },
            body: JSON.stringify({
                model: this.model,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: `Analyze the following ${type}:\n\n${content}` }
                ],
                temperature: 0.1,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error?.message || 'OpenAI API Failed');
        }

        const data = await response.json();
        const jsonStr = data.choices[0].message.content;
        return JSON.parse(jsonStr);
    }

    // ════════════════════════════════════════════════════
    //  GEMINI INTEGRATION
    // ════════════════════════════════════════════════════
    async _callGemini(content, type) {
        // Implementation for Gemini API (structure placeholder)
        // Requires different endpoint and payload structure
        // For now, redirect to OpenAI logical structure or Simulation
        return this._runSimulation(content, type, "Gemini support coming in v2.1");
    }

    // ════════════════════════════════════════════════════
    //  SYSTEM PROMPTS
    // ════════════════════════════════════════════════════
    _getSystemPrompt(type) {
        const basePrompt = `
You are SecureScan AI, an advanced cybersecurity analysis engine.
Your task is to analyze the input and generate a structured JSON security report.

OUTPUT FORMAT (STRICT JSON):
{
  "riskLevel": "SAFE" | "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL",
  "score": <0-100 integer> (higher is more dangerous),
  "summary": "<1 sentence summary>",
  "issues": [
    {
      "severity": "low" | "medium" | "high" | "critical",
      "name": "<Short Title>",
      "description": "<Detailed explanation>",
      "remediation": "<Actionable fix>",
      "snippet": "<Relevant code/text snippet>"
    }
  ],
  "attackScenarios": [
    { "title": "<Scenario Title>", "description": "<How an attacker exploits this>" }
  ]
}
`;
        if (type === 'code') {
            return basePrompt + `
Focus on: SAST (Static Application Security Testing).
Detect: OWASP Top 10, Injection (SQLi, XSS, RCE), Hardcoded Secrets, Logic Flaws, Insecure Deserialization.
Critically analyze data flow. Ignore style issues.`;
        } else if (type === 'text') {
            return basePrompt + `
Focus on: Social Engineering, Phishing, NLP Threat Detection.
Detect: Urgency, Fear tactics, Authority Impersonation, Suspicious Links, Scams.`;
        }
        return basePrompt;
    }

    // ════════════════════════════════════════════════════
    //  SIMULATION MODE (MOCK)
    // ════════════════════════════════════════════════════
    async _runSimulation(content, type, errorMessage = null) {
        // Wait to simulate network latency
        await new Promise(r => setTimeout(r, 2000));

        let mockResponse = {
            riskLevel: "SAFE",
            score: 15,
            summary: "No significant threats detected in the input.",
            issues: [],
            attackScenarios: []
        };

        if (type === 'code') {
            if (content.includes('eval(') || content.includes('exec(')) {
                mockResponse = {
                    riskLevel: "CRITICAL",
                    score: 95,
                    summary: "Critical Remote Code Execution (RCE) vulnerability detected.",
                    issues: [
                        {
                            severity: "critical",
                            name: "Remote Code Execution (RCE)",
                            description: "Use of dangerous function allows arbitrary command execution.",
                            remediation: "Replace eval/exec with safe alternatives.",
                            snippet: "exec(cmd, ...)"
                        }
                    ],
                    attackScenarios: [
                        { title: "Server Takeover", description: "Attacker sends malicious command to gain full shell access." }
                    ]
                };
            } else if (content.includes('SELECT') && content.includes('${')) {
                mockResponse = {
                    riskLevel: "HIGH",
                    score: 85,
                    summary: "SQL Injection vulnerability detected in database query.",
                    issues: [
                        {
                            severity: "high",
                            name: "SQL Injection",
                            description: "Unsanitized user input concatenated directly into SQL query.",
                            remediation: "Use parameterized queries or prepared statements.",
                            snippet: "SELECT * FROM ... ${id}"
                        }
                    ],
                    attackScenarios: [
                        { title: "Data Exfiltration", description: "Attacker dumps entire database by injecting 'OR 1=1'." }
                    ]
                };
            }
        } else if (type === 'text') {
            if (content.toLowerCase().includes('urgent') || content.toLowerCase().includes('suspend')) {
                mockResponse = {
                    riskLevel: "HIGH",
                    score: 88,
                    summary: "High-risk phishing attempt detected using urgency tactics.",
                    issues: [
                        {
                            severity: "high",
                            name: "Psychological Manipulation",
                            description: "Uses urgency ('immediately', 'suspend') to force impulsive action.",
                            remediation: "Do not reply. Verify directly with the service provider.",
                            snippet: "account will be SUSPENDED"
                        },
                        {
                            severity: "medium",
                            name: "Suspicious Link Pattern",
                            description: "Contains link that may spoof legitimate domain.",
                            remediation: "Check URL carefully before clicking.",
                            snippet: "http://paypa1-secure.xyz"
                        }
                    ],
                    attackScenarios: [
                        { title: "Credential Harvesting", description: "Victim clicks link and enters credentials on fake site." }
                    ]
                };
            }
        }

        if (errorMessage) {
            mockResponse.summary += ` [Note: Running in Simulation Mode due to API Error: ${errorMessage}]`;
        } else {
            mockResponse.summary += " [Simulated Analysis]";
        }

        return mockResponse;
    }
}

// Export global instance
window.LLMEngine = new LLMEngine();
