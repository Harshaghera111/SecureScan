const fs = require('fs');
const path = require('path');
const vm = require('vm');

// Mock Browser Environment
const window = {
    localStorage: {
        getItem: () => "{}",
        setItem: () => { }
    }
};
const navigator = { userAgent: 'Node.js' };
const document = {
    createElement: () => ({ remove: () => { } }),
    getElementById: () => null
};
global.window = window;
global.navigator = navigator;
global.document = document;
global.localStorage = window.localStorage;

// Load Engine Files
const basePath = 'd:/Gitdemo/SecureScan/';
const files = ['ast-engine.js', 'intelligence.js', 'analyzer.js', 'code-analyzer.js'];

files.forEach(file => {
    let content = fs.readFileSync(path.join(basePath, file), 'utf8');
    // Fix for Node.js VM: explicitly expose const declarations to global
    if (file === 'ast-engine.js') content += '; global.ASTEngine = ASTEngine;';
    if (file === 'intelligence.js') content += '; global.IntelligenceEngine = IntelligenceEngine;';
    if (file === 'analyzer.js') content += '; global.SecureScanAnalyzer = SecureScanAnalyzer;';
    vm.runInThisContext(content);
});

// Test Payload 1: RCE in Node.js
const rceCode = `
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/rce', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd, (err, stdout, stderr) => {
        res.send(stdout);
    });
});
`;

// Test Payload 2: Context-Aware (NoSQL suppression)
const contextCode = `
// No Mongo-DB import, but Mongo syntax
db.users.find({ $where: "this.password == '" + req.body.password + "'" });

// SQL syntax, WITH SQL import (mocked)
const mysql = require('mysql');
const query = "SELECT * FROM users WHERE id = " + req.query.id;
mysql.query(query);
`;

const results = {};

// Run RCE Test
const rceResult = SecureScanAnalyzer.analyzeCode(rceCode);
const rceFinal = SecureScanAnalyzer._buildResult(rceResult.issues);
const rceFound = rceResult.issues.some(i => i.name.includes('Remote Code Execution') || i.severity === 'critical');

// Run Context-Aware Test
const ctxResult = SecureScanAnalyzer.analyzeCode(contextCode);
const ctxFinal = SecureScanAnalyzer._buildResult(ctxResult.issues);

const mongoFound = ctxResult.issues.some(i => i.name.includes('NoSQL'));
const sqlFound = ctxResult.issues.some(i => i.name.includes('SQL') || i.cwe === 'CWE-89');

Object.assign(results, {
    rce: {
        found: rceFound,
        score: rceFinal.score,
        issues: rceResult.issues.map(i => i.name)
    },
    context: {
        nosqlSuppressed: !mongoFound,
        sqlFound: sqlFound,
        issues: ctxResult.issues.map(i => i.name)
    }
});
fs.writeFileSync('d:/Gitdemo/SecureScan/verify_result.json', JSON.stringify(results, null, 2));
console.log("Verification complete. Results written to verify_result.json");
