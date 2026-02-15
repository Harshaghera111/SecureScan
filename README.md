# SecureScan - AI Security Analyzer

SecureScan is an AI-powered security analysis tool for code, text, and images. It runs entirely in the browser using client-side JavaScript.

## 🚀 How to Run

### Method 1: Direct Open (Easiest)
Simply double-click `index.html` to open it in your default web browser. No server required.

file:///d:/Gitdemo/SecureScan/index.html

### Method 2: Local Server (Optional)
If you prefer running it on a local server (recommended for better asset loading):

**Using Python:**
```bash
python -m http.server 8000
# Then open http://localhost:8000
```

**Using Node.js:**
```bash
npx serve .
# Then open http://localhost:3000
```

## 🛠️ Verification Script
To verify the core engine logic (headless mode):
```bash
node verify_v5.js
```
This runs the analysis engine against test payloads and outputs results to `verify_result.json`.
