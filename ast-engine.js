/* ════════════════════════════════════════════════════════════════
   SecureScan v4 — Deep Program Analysis Engine
   AST Parser, CFG Builder, Call Graph, Symbol Table,
   Inter-Procedural Taint Tracking
   ════════════════════════════════════════════════════════════════ */

const ASTEngine = {

    // ═══════════════════════════════════════════════════════════
    //  PHASE 1: TOKENIZER / LEXER
    //  Converts source code into token stream
    // ═══════════════════════════════════════════════════════════

    tokenize(code) {
        const tokens = [];
        const lines = code.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();

            // Skip blanks & comments
            if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

            // Function declarations
            const funcMatch = trimmed.match(/(?:async\s+)?(?:function\s+(\w+)|(\w+)\s*(?:=|:)\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))/);
            if (funcMatch) {
                const name = funcMatch[1] || funcMatch[2];
                tokens.push({ type: 'FUNC_DECL', name, line: i + 1, raw: trimmed });
            }

            // Class declarations
            const classMatch = trimmed.match(/class\s+(\w+)/);
            if (classMatch) {
                tokens.push({ type: 'CLASS_DECL', name: classMatch[1], line: i + 1, raw: trimmed });
            }

            // Variable declarations
            const varMatch = trimmed.match(/(?:const|let|var)\s+(\w+)\s*=\s*(.*)/);
            if (varMatch) {
                tokens.push({ type: 'VAR_DECL', name: varMatch[1], value: varMatch[2], line: i + 1, raw: trimmed });
            }

            // Call expressions
            const callMatches = trimmed.matchAll(/(\w+(?:\.\w+)*)\s*\(/g);
            for (const cm of callMatches) {
                tokens.push({ type: 'CALL_EXPR', callee: cm[1], line: i + 1, raw: trimmed });
            }

            // Control flow
            if (/^\s*(if|else\s*if|else)\s*[\({]/.test(trimmed)) {
                tokens.push({ type: 'BRANCH', kind: 'if', line: i + 1 });
            }
            if (/^\s*(for|while|do)\s*[\({]/.test(trimmed)) {
                tokens.push({ type: 'LOOP', line: i + 1 });
            }
            if (/^\s*(try)\s*\{/.test(trimmed)) {
                tokens.push({ type: 'TRY', line: i + 1 });
            }
            if (/^\s*catch\s*\(/.test(trimmed)) {
                tokens.push({ type: 'CATCH', line: i + 1 });
            }
            if (/^\s*(return|throw)\s/.test(trimmed)) {
                tokens.push({ type: 'EXIT', kind: trimmed.startsWith('return') ? 'return' : 'throw', line: i + 1, raw: trimmed });
            }

            // Route definitions (Express/Flask/Django patterns)
            const routeMatch = trimmed.match(/(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)/);
            if (routeMatch) {
                tokens.push({ type: 'ROUTE_DEF', method: routeMatch[1].toUpperCase(), path: routeMatch[2], line: i + 1, raw: trimmed });
            }

            // Middleware usage
            const mwMatch = trimmed.match(/app\.use\s*\(\s*(\w+)/);
            if (mwMatch) {
                tokens.push({ type: 'MIDDLEWARE', name: mwMatch[1], line: i + 1 });
            }

            // Assignments (non-declaration)
            if (!varMatch) {
                const assignMatch = trimmed.match(/^(\w+(?:\.\w+)*)\s*=\s*(.*)/);
                if (assignMatch && !/^(if|else|for|while|return|const|let|var|function|class)$/.test(assignMatch[1])) {
                    tokens.push({ type: 'ASSIGN', target: assignMatch[1], value: assignMatch[2], line: i + 1, raw: trimmed });
                }
            }
        }

        return tokens;
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 2: AST BUILDER
    //  Builds function-scoped abstract syntax tree
    // ═══════════════════════════════════════════════════════════

    buildAST(code) {
        const tokens = this.tokenize(code);
        const lines = code.split('\n');
        const functions = [];
        const globalScope = { vars: [], calls: [], routes: [], middleware: [] };

        // Extract function bodies by brace matching
        for (const token of tokens) {
            if (token.type === 'FUNC_DECL') {
                const funcBody = this._extractFunctionBody(lines, token.line - 1);
                functions.push({
                    name: token.name,
                    line: token.line,
                    endLine: token.line + funcBody.lineCount,
                    params: this._extractParams(lines[token.line - 1]),
                    body: funcBody.body,
                    bodyTokens: this.tokenize(funcBody.body),
                    calls: [],
                    vars: [],
                    taintSources: [],
                    taintSinks: [],
                    returnsTaint: false,
                    isRouteHandler: false,
                    hasAuthMiddleware: false
                });
            }
            if (token.type === 'ROUTE_DEF') globalScope.routes.push(token);
            if (token.type === 'MIDDLEWARE') globalScope.middleware.push(token);
        }

        // Analyze each function
        for (const func of functions) {
            // Extract calls within function
            func.calls = func.bodyTokens
                .filter(t => t.type === 'CALL_EXPR')
                .map(t => t.callee);

            // Extract variables
            func.vars = func.bodyTokens
                .filter(t => t.type === 'VAR_DECL')
                .map(t => ({ name: t.name, value: t.value, line: t.line }));

            // Check if this is a route handler
            func.isRouteHandler = globalScope.routes.some(r =>
                r.raw && r.raw.includes(func.name)
            );
        }

        return {
            functions,
            globalScope,
            tokens,
            lineCount: lines.length
        };
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 3: CONTROL FLOW GRAPH (CFG)
    //  Maps basic blocks and branches
    // ═══════════════════════════════════════════════════════════

    buildCFG(code) {
        const lines = code.split('\n');
        const blocks = [];
        let currentBlock = { id: 0, startLine: 1, lines: [], successors: [], type: 'entry' };
        let blockId = 1;
        let branchStack = [];

        for (let i = 0; i < lines.length; i++) {
            const trimmed = lines[i].trim();
            if (!trimmed) continue;

            // Branch point — close current block, create new
            if (/^\s*(if|else\s*if|else)\s*[\({]/.test(trimmed)) {
                currentBlock.endLine = i;
                blocks.push(currentBlock);
                const branchBlock = { id: blockId++, startLine: i + 1, lines: [trimmed], successors: [], type: 'branch', condition: trimmed };
                blocks.push(branchBlock);
                currentBlock.successors.push(branchBlock.id);
                branchStack.push(branchBlock.id);
                currentBlock = { id: blockId++, startLine: i + 2, lines: [], successors: [], type: 'basic' };
                branchBlock.successors.push(currentBlock.id);
                continue;
            }

            // Loop — back-edge
            if (/^\s*(for|while|do)\s*[\({]/.test(trimmed)) {
                currentBlock.endLine = i;
                blocks.push(currentBlock);
                const loopBlock = { id: blockId++, startLine: i + 1, lines: [trimmed], successors: [], type: 'loop', condition: trimmed };
                blocks.push(loopBlock);
                currentBlock.successors.push(loopBlock.id);
                currentBlock = { id: blockId++, startLine: i + 2, lines: [], successors: [], type: 'loop_body' };
                loopBlock.successors.push(currentBlock.id);
                // Back-edge: loop body → loop header
                currentBlock.successors.push(loopBlock.id);
                continue;
            }

            // Return/throw — terminates block
            if (/^\s*(return|throw)\s/.test(trimmed)) {
                currentBlock.lines.push(trimmed);
                currentBlock.endLine = i + 1;
                currentBlock.type = 'exit';
                blocks.push(currentBlock);
                currentBlock = { id: blockId++, startLine: i + 2, lines: [], successors: [], type: 'unreachable' };
                continue;
            }

            currentBlock.lines.push(trimmed);
        }

        // Close final block
        currentBlock.endLine = lines.length;
        if (currentBlock.lines.length > 0) blocks.push(currentBlock);

        return {
            blocks,
            entryBlock: 0,
            totalBlocks: blocks.length,
            hasUnreachableCode: blocks.some(b => b.type === 'unreachable' && b.lines.length > 0),
            complexity: blocks.filter(b => b.type === 'branch' || b.type === 'loop').length + 1 // cyclomatic
        };
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 4: CALL GRAPH
    //  Maps function-to-function relationships
    // ═══════════════════════════════════════════════════════════

    buildCallGraph(ast) {
        const graph = {};  // funcName → [calledFuncNames]
        const inverse = {}; // funcName → [callerFuncNames]
        const funcNames = new Set(ast.functions.map(f => f.name));

        for (const func of ast.functions) {
            graph[func.name] = [];
            if (!inverse[func.name]) inverse[func.name] = [];

            for (const call of func.calls) {
                const baseName = call.split('.').pop();
                if (funcNames.has(baseName) && baseName !== func.name) {
                    graph[func.name].push(baseName);
                    if (!inverse[baseName]) inverse[baseName] = [];
                    inverse[baseName].push(func.name);
                }
                // Also track method calls
                if (funcNames.has(call)) {
                    if (!graph[func.name].includes(call)) {
                        graph[func.name].push(call);
                    }
                    if (!inverse[call]) inverse[call] = [];
                    if (!inverse[call].includes(func.name)) {
                        inverse[call].push(func.name);
                    }
                }
            }
        }

        return {
            forward: graph,    // who does each function call?
            inverse: inverse,  // who calls each function?
            rootFunctions: ast.functions.filter(f => !inverse[f.name] || inverse[f.name].length === 0).map(f => f.name),
            leafFunctions: ast.functions.filter(f => !graph[f.name] || graph[f.name].length === 0).map(f => f.name),
        };
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 5: SYMBOL TABLE
    //  Cross-scope variable tracking
    // ═══════════════════════════════════════════════════════════

    buildSymbolTable(ast) {
        const table = {};  // varName → { scope, type, line, tainted, used, reassigned }

        // Global scope variables
        for (const token of ast.tokens) {
            if (token.type === 'VAR_DECL') {
                const isInFunction = ast.functions.some(f => token.line >= f.line && token.line <= f.endLine);
                table[token.name] = {
                    scope: isInFunction ? ast.functions.find(f => token.line >= f.line && token.line <= f.endLine)?.name : 'global',
                    line: token.line,
                    value: token.value,
                    tainted: false,
                    used: false,
                    reassigned: false,
                    type: this._inferType(token.value)
                };
            }
        }

        // Function parameters
        for (const func of ast.functions) {
            for (const param of func.params) {
                table[`${func.name}.${param}`] = {
                    scope: func.name,
                    line: func.line,
                    value: null,
                    tainted: false, // will be determined by caller context
                    used: false,
                    reassigned: false,
                    type: 'param'
                };
            }
        }

        // Mark used variables
        for (const token of ast.tokens) {
            if (token.type === 'CALL_EXPR' || token.type === 'ASSIGN') {
                const raw = token.raw || '';
                for (const varName of Object.keys(table)) {
                    const baseName = varName.includes('.') ? varName.split('.').pop() : varName;
                    if (new RegExp('\\b' + baseName + '\\b').test(raw)) {
                        table[varName].used = true;
                    }
                }
            }
        }

        return table;
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 6: INTER-PROCEDURAL TAINT TRACKING
    //  Traces taint across function boundaries via call graph
    // ═══════════════════════════════════════════════════════════

    SOURCE_PATTERNS: [
        /req\.(body|params|query|headers|cookies)\b/,
        /request\.(form|args|json|values|data|files)\b/,
        /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/,
        /process\.(argv|env)\b/,
        /input\s*\(/, /raw_input\s*\(/, /scanf\s*\(/, /gets\s*\(/,
        /getParameter\s*\(/, /getHeader\s*\(/,
        /useSearchParams|useParams|searchParams/,
        /document\.(getElementById|querySelector)\b.*?\.value/,
        /FormData|URLSearchParams/,
        /event\.(target|currentTarget)\.value/,
    ],

    SINK_PATTERNS: [
        { regex: /\b(query|execute|exec|raw)\s*\(/, type: 'sql', cwe: 'CWE-89' },
        { regex: /\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML/, type: 'xss', cwe: 'CWE-79' },
        { regex: /\beval\s*\(|\bnew\s+Function\s*\(/, type: 'code_exec', cwe: 'CWE-94' },
        { regex: /\.exec\s*\(|\.spawn\s*\(|os\.system\s*\(|subprocess/, type: 'cmd_injection', cwe: 'CWE-78' },
        { regex: /readFile|writeFile|fs\.\w+\s*\(/, type: 'path_traversal', cwe: 'CWE-22' },
        { regex: /fetch\s*\(|axios\.\w+\s*\(|requests\.(get|post)/, type: 'ssrf', cwe: 'CWE-918' },
        { regex: /redirect\s*\(|location\.href\s*=/, type: 'open_redirect', cwe: 'CWE-601' },
        { regex: /pickle\.loads|yaml\.load|unserialize/, type: 'deserialization', cwe: 'CWE-502' },
    ],

    SANITIZER_PATTERNS: [
        /DOMPurify\.sanitize/, /encodeURIComponent?\s*\(/, /escapeHtml\s*\(/,
        /htmlspecialchars/, /parseInt\s*\(/, /Number\s*\(/, /parseFloat\s*\(/,
        /validator\.\w+/, /Joi\.\w+|zod\.\w+|yup\.\w+/,
        /\.replace\s*\(.*?[<>"'&]/, /textContent\s*=/, /\.createTextNode/,
        /\?\s*,\s*\[/, /prepared/i, /parameterized/i,
        /sanitize\s*\(/, /escape\s*\(/, /\.trim\s*\(\)\.replace/,
    ],

    interProceduralTaint(ast, callGraph) {
        const results = [];
        const taintedFunctions = new Map(); // funcName → { params: [...], returns: bool }

        // Pass 1: Identify which functions receive tainted data directly
        for (const func of ast.functions) {
            const bodyStr = func.body || '';
            const hasTaintSource = this.SOURCE_PATTERNS.some(p => p.test(bodyStr));

            if (hasTaintSource || func.isRouteHandler) {
                // This function directly handles user input
                taintedFunctions.set(func.name, {
                    params: func.params.filter(p => {
                        // Check if param name appears near a source pattern
                        return /req|request|input|data|body|params|query/.test(p);
                    }),
                    directSource: true,
                    returnsTaint: false
                });

                // Check if function returns tainted data
                const returnLines = bodyStr.split('\n').filter(l => /^\s*return\s/.test(l));
                for (const ret of returnLines) {
                    // Check if return value references a tainted variable
                    const hasTaintedRef = this.SOURCE_PATTERNS.some(p => p.test(ret));
                    if (hasTaintedRef) {
                        taintedFunctions.get(func.name).returnsTaint = true;
                    }
                }
            }
        }

        // Pass 2: Propagate taint through call graph
        let changed = true;
        let iterations = 0;
        while (changed && iterations < 10) {
            changed = false;
            iterations++;

            for (const func of ast.functions) {
                if (taintedFunctions.has(func.name)) continue;

                // Check if any caller passes tainted data to this function
                const callers = callGraph.inverse[func.name] || [];
                for (const callerName of callers) {
                    if (taintedFunctions.has(callerName)) {
                        // Caller is tainted → check if it passes taint to this function
                        const callerFunc = ast.functions.find(f => f.name === callerName);
                        if (callerFunc) {
                            const callsThis = callerFunc.calls.filter(c => c === func.name || c.endsWith('.' + func.name));
                            if (callsThis.length > 0) {
                                taintedFunctions.set(func.name, {
                                    params: func.params,
                                    directSource: false,
                                    propagatedFrom: callerName,
                                    returnsTaint: false
                                });
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        // Pass 3: Find sinks in tainted functions
        for (const [funcName, taintInfo] of taintedFunctions) {
            const func = ast.functions.find(f => f.name === funcName);
            if (!func) continue;

            const bodyLines = (func.body || '').split('\n');
            for (let i = 0; i < bodyLines.length; i++) {
                const line = bodyLines[i];

                // Check for sinks
                for (const sink of this.SINK_PATTERNS) {
                    if (sink.regex.test(line)) {
                        // Check if sanitized
                        const isSanitized = this.SANITIZER_PATTERNS.some(s => s.test(line));
                        if (isSanitized) continue;

                        // Build propagation chain
                        const chain = [funcName];
                        let current = funcName;
                        while (taintedFunctions.get(current)?.propagatedFrom) {
                            current = taintedFunctions.get(current).propagatedFrom;
                            chain.unshift(current);
                        }

                        results.push({
                            type: sink.type,
                            cwe: sink.cwe,
                            sinkFunction: funcName,
                            sinkLine: func.line + i,
                            sinkCode: line.trim(),
                            sourceFunction: chain[0],
                            propagationChain: chain,
                            isDirect: taintInfo.directSource,
                            isInterProcedural: chain.length > 1,
                            confidence: chain.length === 1 ? 'confirmed' : 'likely',
                        });
                    }
                }
            }
        }

        return {
            taintedFunctions: Array.from(taintedFunctions.entries()).map(([name, info]) => ({
                name, ...info
            })),
            interProceduralFlows: results.filter(r => r.isInterProcedural),
            directFlows: results.filter(r => !r.isInterProcedural),
            totalFlows: results.length,
        };
    },

    // ═══════════════════════════════════════════════════════════
    //  PHASE 7: REACHABILITY ANALYSIS
    //  Determines if code is reachable from public routes
    // ═══════════════════════════════════════════════════════════

    analyzeReachability(ast, callGraph) {
        const reachability = {}; // funcName → reachability score (0.0 - 1.0)

        // Route handlers are fully reachable
        for (const func of ast.functions) {
            if (func.isRouteHandler) {
                reachability[func.name] = 1.0;
            }
        }

        // Functions called from route handlers get high reachability
        for (const route of ast.globalScope.routes) {
            const routeRaw = route.raw || '';
            for (const func of ast.functions) {
                if (routeRaw.includes(func.name) && !reachability[func.name]) {
                    reachability[func.name] = 1.0;
                }
            }
        }

        // Propagate reachability through call graph (diminishing)
        let changed = true;
        let iter = 0;
        while (changed && iter < 8) {
            changed = false;
            iter++;
            for (const func of ast.functions) {
                if (reachability[func.name]) continue;
                const callers = callGraph.inverse[func.name] || [];
                let maxCallerReach = 0;
                for (const caller of callers) {
                    if (reachability[caller]) {
                        maxCallerReach = Math.max(maxCallerReach, reachability[caller] * 0.85);
                    }
                }
                if (maxCallerReach > 0) {
                    reachability[func.name] = maxCallerReach;
                    changed = true;
                }
            }
        }

        // Unreachable functions get minimum score
        for (const func of ast.functions) {
            if (!reachability[func.name]) {
                reachability[func.name] = 0.3; // not dead, could be imported
            }
        }

        return reachability;
    },

    // ═══════════════════════════════════════════════════════════
    //  FULL DEEP ANALYSIS (orchestrator)
    // ═══════════════════════════════════════════════════════════

    analyze(code) {
        const ast = this.buildAST(code);
        const cfg = this.buildCFG(code);
        const callGraph = this.buildCallGraph(ast);
        const symbolTable = this.buildSymbolTable(ast);
        const taintResults = this.interProceduralTaint(ast, callGraph);
        const reachability = this.analyzeReachability(ast, callGraph);

        return {
            ast,
            cfg,
            callGraph,
            symbolTable,
            taintResults,
            reachability,
            metrics: {
                totalFunctions: ast.functions.length,
                totalLines: ast.lineCount,
                cyclomaticComplexity: cfg.complexity,
                totalBlocks: cfg.totalBlocks,
                hasUnreachableCode: cfg.hasUnreachableCode,
                interProceduralFlows: taintResults.interProceduralFlows.length,
                taintedFunctions: taintResults.taintedFunctions.length,
            }
        };
    },

    // ═══════════════════════════════════════════════════════════
    //  UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    _extractFunctionBody(lines, startLine) {
        let braceCount = 0;
        let started = false;
        let body = [];
        let lineCount = 0;

        for (let i = startLine; i < lines.length; i++) {
            const line = lines[i];
            for (const ch of line) {
                if (ch === '{') { braceCount++; started = true; }
                if (ch === '}') braceCount--;
            }
            body.push(line);
            lineCount++;
            if (started && braceCount === 0) break;
            if (lineCount > 200) break; // safety limit
        }

        return { body: body.join('\n'), lineCount };
    },

    _extractParams(funcLine) {
        const match = funcLine.match(/\(([^)]*)\)/);
        if (!match) return [];
        return match[1].split(',')
            .map(p => p.trim().replace(/\s*=\s*.*$/, '').replace(/\.\.\./, '').replace(/:\s*\w+/, ''))
            .filter(p => p && p !== '');
    },

    _inferType(value) {
        if (!value) return 'unknown';
        value = value.trim();
        if (/^['"`]/.test(value)) return 'string';
        if (/^\d+(\.\d+)?$/.test(value)) return 'number';
        if (/^(true|false)$/.test(value)) return 'boolean';
        if (/^\[/.test(value)) return 'array';
        if (/^\{/.test(value)) return 'object';
        if (/^(null|undefined)$/.test(value)) return 'null';
        if (/=>\s*\{|function/.test(value)) return 'function';
        if (/new\s+/.test(value)) return 'instance';
        return 'reference';
    }
};
