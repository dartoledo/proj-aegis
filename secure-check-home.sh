#!/usr/bin/env bash
set -eo pipefail

SCAN_DIR="${1:-$HOME}"
export PATH="$HOME/.local/bin:$PATH"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "🛡️   HOME-WIDE SECURITY AUDIT: $SCAN_DIR"
echo "============================================================"
echo "Started at: $(date)"
echo ""

# Common directory exclusions for deep scanning (avoids multi-GB caches, games, models)
COMMON_EXCLUDES=(
    --exclude-dir=node_modules
    --exclude-dir=\.git
    --exclude-dir=\.cache
    --exclude-dir=\.local
    --exclude-dir=\.config
    --exclude-dir=\.npm
    --exclude-dir=\.nvm
    --exclude-dir=\.yarn
    --exclude-dir=\.lmstudio
    --exclude-dir=\.unsloth
    --exclude-dir=\.steam
    --exclude-dir=snap
    --exclude-dir=\.antigravity-ide
    --exclude-dir=\.gemini
)

SEMGREP_EXCLUDES=(
    --exclude='node_modules'
    --exclude='.git'
    --exclude='.cache'
    --exclude='.local'
    --exclude='.config'
    --exclude='.npm'
    --exclude='.nvm'
    --exclude='.yarn'
    --exclude='.lmstudio'
    --exclude='.unsloth'
    --exclude='.steam'
    --exclude='snap'
    --exclude='.antigravity-ide'
    --exclude='.gemini'
)

SYFT_EXCLUDES=(
    --exclude '**/node_modules/**'
    --exclude '**/.git/**'
    --exclude '**/.cache/**'
    --exclude '**/.local/**'
    --exclude '**/.config/**'
    --exclude '**/.npm/**'
    --exclude '**/.nvm/**'
    --exclude '**/.yarn/**'
    --exclude '**/.lmstudio/**'
    --exclude '**/.unsloth/**'
    --exclude '**/.steam/**'
    --exclude '**/snap/**'
    --exclude '**/.antigravity-ide/**'
    --exclude '**/.gemini/**'
    --exclude '**/.venv/**'
)

# 1. Secrets detection (Gitleaks)
echo "=== 1. Checking for hardcoded secrets (Gitleaks) ==="
if command -v gitleaks >/dev/null 2>&1; then
    # Scan all user directories, project trees, and documents
    find "$SCAN_DIR" -maxdepth 1 -mindepth 1 \
        ! -name ".cache" \
        ! -name ".local" \
        ! -name ".config" \
        ! -name ".npm" \
        ! -name ".nvm" \
        ! -name ".yarn" \
        ! -name ".lmstudio" \
        ! -name ".unsloth" \
        ! -name ".steam" \
        ! -name "snap" \
        ! -name ".antigravity-ide" \
        ! -name ".gemini" \
        ! -name "*.deb*" \
        ! -name "*.tar*" 2>/dev/null | while read -r target; do
        if [ -d "$target" ]; then
            echo "--> Scanning $target with Gitleaks..."
            gitleaks dir "$target" --redact --max-target-megabytes=10 || true
        fi
    done
else
    echo "⚠️  gitleaks not found in PATH"
fi
echo ""

# 2. SAST code logic scan (Semgrep)
echo "=== 2. Scanning source code logic & AST (Semgrep) ==="
if command -v semgrep >/dev/null 2>&1; then
    semgrep scan --config="$SCRIPT_DIR/.semgrep/aegis-offline-rules.yaml" --metrics=off --quiet "${SEMGREP_EXCLUDES[@]}" "$SCAN_DIR" || true
else
    echo "⚠️  semgrep not found in PATH"
fi
echo ""

# 3. Offline SBOM & Vulnerability Audit (Syft + Grype)
echo "=== 3. Offline SBOM & Vulnerability Audit across projects (Syft + Grype) ==="
if command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
    AUDIT_TARGETS=()
    for dir in "$SCAN_DIR"/proj-* "$SCAN_DIR"/local-*; do
        [ -d "$dir" ] && AUDIT_TARGETS+=("$dir")
    done
    if [ ${#AUDIT_TARGETS[@]} -eq 0 ]; then
        AUDIT_TARGETS=("$SCAN_DIR")
    fi
    for target_dir in "${AUDIT_TARGETS[@]}"; do
        SBOM_TMP="/tmp/syft-home-$(basename "$target_dir")-$$.cdx.json"
        echo "--> Generating offline CycloneDX SBOM for $target_dir (Syft)..."
        syft scan "dir:$target_dir" "${SYFT_EXCLUDES[@]}" -o "cyclonedx-json=$SBOM_TMP" -q || true
        if [ -f "$SBOM_TMP" ]; then
            echo "--> Scanning SBOM with Grype (offline SQLite DB)..."
            GRYPE_DB_AUTO_UPDATE=false grype "sbom:$SBOM_TMP" -q || true
            rm -f "$SBOM_TMP"
        fi
    done
else
    echo "⚠️  syft or grype not found in PATH"
fi
echo ""

# 4. Binary & archive antivirus scan (ClamAV)
echo "=== 4. Scanning user files, archives & binaries for malware (ClamAV) ==="
if command -v clamscan >/dev/null 2>&1; then
    # Target top-level user directories, project repos, downloads, desktop
    CLAM_TARGETS=()
    for dir in "$SCAN_DIR"/proj-* "$SCAN_DIR"/local-* "$SCAN_DIR"/Downloads "$SCAN_DIR"/Desktop "$SCAN_DIR"/Documents; do
        if [ -d "$dir" ]; then
            CLAM_TARGETS+=("$dir")
        fi
    done
    if [ ${#CLAM_TARGETS[@]} -eq 0 ]; then
        CLAM_TARGETS=("$SCAN_DIR")
    fi
    echo "--> Running ClamAV on user projects and document paths: ${CLAM_TARGETS[*]}..."
    clamscan -r -i "${COMMON_EXCLUDES[@]}" "${CLAM_TARGETS[@]}" || true
else
    echo "⚠️  clamscan not found in PATH"
fi
echo ""

echo "============================================================"
echo "✅ Home directory security sweep complete!"
echo "============================================================"
