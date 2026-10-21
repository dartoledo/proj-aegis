#!/usr/bin/env bash
set -eo pipefail

SCAN_DIR="${1:-$HOME}"

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

OSV_EXCLUDES=(
    --x-exclude='node_modules'
    --x-exclude='.cache'
    --x-exclude='.local'
    --x-exclude='.config'
    --x-exclude='.npm'
    --x-exclude='.nvm'
    --x-exclude='.yarn'
    --x-exclude='.lmstudio'
    --x-exclude='.unsloth'
    --x-exclude='.steam'
    --x-exclude='snap'
    --x-exclude='.antigravity-ide'
    --x-exclude='.gemini'
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
    semgrep scan --config=auto --quiet "${SEMGREP_EXCLUDES[@]}" "$SCAN_DIR" || true
else
    echo "⚠️  semgrep not found in PATH"
fi
echo ""

# 3. Supply chain & dependency malware (GuardDog & OSV-Scanner)
echo "=== 3. Auditing dependency manifests across projects (GuardDog & OSV) ==="
if command -v guarddog >/dev/null 2>&1; then
    echo "--> Searching for active package manifests in user projects..."
    # Find all package.json and requirements.txt in user project folders (excluding node_modules / cache)
    find "$SCAN_DIR" -maxdepth 4 \
        ! -path "*/node_modules/*" \
        ! -path "*/.cache/*" \
        ! -path "*/.local/*" \
        ! -path "*/.yarn/*" \
        ! -path "*/.npm/*" \
        ! -path "*/.unsloth/*" \
        ! -path "*/.lmstudio/*" \
        ! -path "*/.gemini/*" \
        ! -path "*/.antigravity-ide/*" \
        \( -name "package.json" -o -name "requirements.txt" \) 2>/dev/null | head -n 10 | while read -r manifest; do
        if [[ "$manifest" == *"package.json"* ]]; then
            echo "--> GuardDog scanning $manifest..."
            # -x metadata_mismatch prevents npm optionalDependencies false-alarm
            guarddog npm verify -x metadata_mismatch "$manifest" || true
        elif [[ "$manifest" == *"requirements.txt"* ]]; then
            echo "--> GuardDog scanning $manifest..."
            guarddog pypi verify "$manifest" || true
        fi
    done
else
    echo "⚠️  guarddog not found in PATH"
fi

if command -v osv-scanner >/dev/null 2>&1; then
    echo "--> Running OSV-Scanner across $SCAN_DIR..."
    osv-scanner scan -r "${OSV_EXCLUDES[@]}" "$SCAN_DIR" || true
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
