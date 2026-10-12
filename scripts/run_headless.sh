#!/usr/bin/env bash
# Runs Ghidra headless analysis over the challenge binaries and writes
# reports to reports/. Exits non-zero if an expected result is missing.
#
# Usage: scripts/run_headless.sh [binary dir]   (default: bin)
#
# Ghidra is located through, in order:
#   $GHIDRA_INSTALL_DIR/support/analyzeHeadless
#   Homebrew:  $(brew --prefix ghidra)/libexec/support/analyzeHeadless
#   analyzeHeadless on PATH
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINDIR="$(cd "${1:-$ROOT/bin}" && pwd)"
REPORTS="$ROOT/reports"
SCRIPTS="$ROOT/ghidra_scripts"

find_headless() {
    if [[ -n "${GHIDRA_INSTALL_DIR:-}" && -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]]; then
        echo "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"; return
    fi
    if command -v brew >/dev/null 2>&1 && brew --prefix ghidra >/dev/null 2>&1; then
        local hit
        hit="$(find -L "$(brew --prefix ghidra)" -name analyzeHeadless -type f 2>/dev/null | head -n 1)"
        if [[ -n "$hit" ]]; then echo "$hit"; return; fi
    fi
    if command -v analyzeHeadless >/dev/null 2>&1; then
        command -v analyzeHeadless; return
    fi
    echo "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR." >&2
    exit 1
}

HEADLESS="$(find_headless)"
PROJECT_DIR="$(mktemp -d)"
trap 'rm -rf "$PROJECT_DIR"' EXIT
mkdir -p "$REPORTS"
echo "Using $HEADLESS"

# analyze <binary> [extra -postScript args...]
analyze() {
    local bin="$1"; shift
    local name; name="$(basename "$bin")"
    echo "==> $name"
    "$HEADLESS" "$PROJECT_DIR" labs \
        -import "$BINDIR/$bin" \
        -overwrite \
        -scriptPath "$SCRIPTS" \
        -postScript Triage.java "$REPORTS/$name-triage.md" \
        "$@" \
        -log "$REPORTS/$name-ghidra.log" \
        > "$REPORTS/$name-stdout.log" 2>&1 \
        || { echo "Ghidra failed on $name; see $REPORTS/$name-stdout.log" >&2; exit 1; }
}

analyze 01-keygen
analyze 02-hidden-strings -postScript DecryptStrings.java "$REPORTS/02-hidden-strings-decrypted.txt"
analyze 03-tiny-vm -postScript VmDisassembler.java "$REPORTS/03-tiny-vm-bytecode.txt"

fail=0
expect() {
    if grep -qF -- "$2" "$1"; then
        echo "[PASS] $(basename "$1") contains: $2"
    else
        echo "[FAIL] $(basename "$1") missing: $2"; fail=1
    fi
}

expect "$REPORTS/01-keygen-triage.md" "main()"
expect "$REPORTS/02-hidden-strings-decrypted.txt" "GT{x0r_1s_n0t_encrypt10n}"
expect "$REPORTS/02-hidden-strings-decrypted.txt" "Decrypted 5 string(s)."
expect "$REPORTS/03-tiny-vm-bytecode.txt" "  OK"
expect "$REPORTS/03-tiny-vm-bytecode.txt" "  FAIL"

exit "$fail"
