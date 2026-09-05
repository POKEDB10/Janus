#!/usr/bin/env bash
# ==============================================================================
# Janus — Test Runner Script
# Runs the full test suite with coverage reporting.
#
# Usage:
#   ./run_tests.sh              # run all tests
#   ./run_tests.sh --fast       # skip slow integration tests
#   ./run_tests.sh --coverage   # with HTML coverage report
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Argument parsing ──────────────────────────────────────────────────────────
FAST=false
COVERAGE=false
for arg in "$@"; do
    case "$arg" in
        --fast)     FAST=true ;;
        --coverage) COVERAGE=true ;;
        --help|-h)
            echo "Usage: $0 [--fast] [--coverage]"
            exit 0 ;;
    esac
done

# ── Check virtual environment ─────────────────────────────────────────────────
if [[ -z "${VIRTUAL_ENV:-}" ]] && [[ ! -f ".venv/bin/activate" ]]; then
    echo "⚠️  No virtual environment detected. Creating one..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -q -e ".[dev]"
elif [[ -f ".venv/bin/activate" ]]; then
    source .venv/bin/activate
fi

echo "🧪 Janus Test Suite"
echo "═══════════════════════════════════"
echo "Python: $(python --version)"
echo "Pytest: $(pytest --version 2>&1 | head -1)"
echo ""

# ── Build pytest arguments ────────────────────────────────────────────────────
PYTEST_ARGS=(
    "tests/"
    "-v"
    "--tb=short"
    "--strict-markers"
)

if [[ "$FAST" == "true" ]]; then
    PYTEST_ARGS+=("-m" "not slow and not integration")
    echo "⚡ Fast mode: skipping slow/integration tests"
fi

if [[ "$COVERAGE" == "true" ]]; then
    PYTEST_ARGS+=(
        "--cov=parsing"
        "--cov=ml"
        "--cov=compliance"
        "--cov=backend"
        "--cov=labeling"
        "--cov=reports"
        "--cov-report=term-missing"
        "--cov-report=html:coverage_html"
        "--cov-fail-under=60"  # minimum 60% coverage for the scaffold
    )
    echo "📊 Coverage mode: generating HTML report to coverage_html/"
fi

echo ""
echo "Running: pytest ${PYTEST_ARGS[*]}"
echo "═══════════════════════════════════"

# ── Run tests ─────────────────────────────────────────────────────────────────
if pytest "${PYTEST_ARGS[@]}"; then
    echo ""
    echo "✅ All tests PASSED"
    if [[ "$COVERAGE" == "true" ]]; then
        echo "📊 Coverage report: coverage_html/index.html"
    fi
    exit 0
else
    EXIT_CODE=$?
    echo ""
    echo "❌ Tests FAILED (exit code: $EXIT_CODE)"
    exit $EXIT_CODE
fi
