#!/usr/bin/env bash
set -eo pipefail

export PATH="$HOME/.local/bin:$PATH"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
echo "=== 2. Scanning source code logic & AST (Semgrep Offline) ==="
if command -v semgrep >/dev/null 2>&1; then
    semgrep scan --config="$SCRIPT_DIR/.semgrep/aegis-offline-rules.yaml" --metrics=off --quiet --exclude='node_modules' --exclude='.git' --exclude='.venv' --exclude='dist' --exclude='coverage' . || true
else
    echo "⚠️  semgrep not found in PATH"
fi
echo ""

# 3. Offline SBOM & Vulnerability Scan
echo "=== 3. Offline SBOM Generation & Vulnerability Scan (Syft + Grype) ==="
if command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
    SBOM_FILE="/tmp/aegis-sbom-$$.cdx.json"
    echo "--> Generating local CycloneDX SBOM with Syft (zero external API calls)..."
    syft scan dir:. --exclude '**/node_modules/**' --exclude '**/.git/**' --exclude '**/.venv/**' --exclude '**/dist/**' --exclude '**/coverage/**' -o "cyclonedx-json=$SBOM_FILE" -q
    echo "--> Auditing SBOM against local Grype SQLite vulnerability DB (offline mode)..."
    GRYPE_DB_AUTO_UPDATE=false grype "sbom:$SBOM_FILE" -q || true
    for tarball in demo/auth.tar demo/backend.tar; do
        if [ -f "$tarball" ]; then
            echo "--> Auditing container image archive $tarball with Grype (offline mode)..."
            GRYPE_DB_AUTO_UPDATE=false grype "$tarball" -q || true
        fi
    done
else
    echo "⚠️  syft or grype not found in PATH"
fi
echo ""

# 4. Binary & archive antivirus scan
echo "=== 4. Scanning archives & binaries for malware (ClamAV) ==="
if command -v clamscan >/dev/null 2>&1; then
    clamscan -r -i --exclude-dir=node_modules --exclude-dir=\.git demo || true
else
    echo "⚠️  clamscan not found in PATH"
fi
echo ""

echo "============================================================"
echo "✅ Security sweep complete!"
echo "============================================================"
