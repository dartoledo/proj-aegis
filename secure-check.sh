#!/usr/bin/env bash
set -eo pipefail

echo "============================================================"
echo "🛡️   AEGIS LOCAL ZERO-COST SECURITY SWEEP"
echo "============================================================"
echo ""

# 1. Secrets detection
echo "=== 1. Checking for hardcoded secrets (Gitleaks) ==="
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks dir . --redact || true
else
    echo "⚠️  gitleaks not found in PATH"
fi
echo ""

# 2. SAST code logic scan
echo "=== 2. Scanning source code logic & AST (Semgrep) ==="
if command -v semgrep >/dev/null 2>&1; then
    semgrep scan --config=auto --quiet --exclude='node_modules' --exclude='.git' || true
else
    echo "⚠️  semgrep not found in PATH"
fi
echo ""

# 3. Supply chain & dependency malware
echo "=== 3. Checking dependencies for malicious patterns (GuardDog & OSV) ==="
if command -v guarddog >/dev/null 2>&1; then
    for pkg in demo/backend/package.json demo/auth/package.json; do
        if [ -f "$pkg" ]; then
            echo "--> Auditing $pkg with GuardDog..."
            guarddog npm verify "$pkg" || true
        fi
    done
    if [ -f "requirements.txt" ]; then
        echo "--> Auditing requirements.txt with GuardDog..."
        guarddog pypi verify requirements.txt || true
    fi
else
    echo "⚠️  guarddog not found in PATH"
fi

if command -v osv-scanner >/dev/null 2>&1; then
    echo "--> Running OSV-Scanner on local manifests..."
    osv-scanner scan -r --x-exclude=node_modules . || true
fi
echo ""

# 4. Binary & archive antivirus scan
echo "=== 4. Scanning archives & binaries for malware (ClamAV) ==="
if command -v clamscan >/dev/null 2>&1; then
    clamscan -r -i --exclude-dir=node_modules --exclude-dir=\.git demo
else
    echo "⚠️  clamscan not found in PATH"
fi
echo ""

echo "============================================================"
echo "✅ Security sweep complete!"
echo "============================================================"
