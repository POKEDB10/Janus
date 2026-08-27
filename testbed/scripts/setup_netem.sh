#!/usr/bin/env bash
# =============================================================================
# Janus Testbed — setup_netem.sh
# =============================================================================
# Applies (or removes) tc netem impairment on a network interface to simulate
# realistic WAN conditions for IPsec traffic analysis.
#
# Usage
#   setup_netem.sh [OPTIONS] <interface>
#
# Options
#   --latency   <ms>       Base one-way latency in milliseconds  (default: 100)
#   --jitter    <ms>       Jitter (±) in milliseconds             (default: 20)
#   --loss      <pct>      Packet loss percentage                  (default: 1)
#   --corrupt   <pct>      Bit corruption percentage               (default: 0.1)
#   --reorder   <pct>      Reorder percentage                      (default: 5)
#   --reorder-corr <pct>   Reorder correlation                     (default: 25)
#   --rate      <kbps>     Bandwidth cap in kbps  0=unlimited       (default: 0)
#   --clean                Remove all qdisc and restore defaults
#   --dry-run              Print commands without executing
#   -h | --help            Show this help message
#
# tc netem parameter → Janus scenario impact table
# ─────────────────────────────────────────────────────────────────────────────
#  netem parameter   │ IKE/ESP effect              │ Affected scenarios
# ─────────────────────────────────────────────────────────────────────────────
#  delay             │ IKE_INIT RTT, SA setup time │ All (timing features)
#  jitter            │ IKE retransmit variability  │ All (jitter labels)
#  loss              │ IKE retransmit triggers      │ All (packet-loss labels)
#  corrupt           │ ESP integrity check failures │ sc09 (SHA1 susceptible)
#  reorder           │ IKE fragment reassembly      │ sc01, sc07 (large IDs)
#  rate              │ throughput cap               │ sc07/sc08 (transport mode)
# ─────────────────────────────────────────────────────────────────────────────
#
# Dependencies: iproute2 (tc), bash >= 4.0
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
LATENCY_MS=100
JITTER_MS=20
LOSS_PCT=1
CORRUPT_PCT=0.1
REORDER_PCT=5
REORDER_CORR=25
RATE_KBPS=0          # 0 = no rate limiting
CLEAN=false
DRY_RUN=false
IFACE=""

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN ]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC}  $*" >&2; }
pass()  { echo -e "${GREEN}[PASS ]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL ]${NC}  $*"; }

# ---------------------------------------------------------------------------
# Helper: run or print a command
# ---------------------------------------------------------------------------
run() {
    if [ "${DRY_RUN}" = true ]; then
        echo "  [DRY-RUN] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
usage() {
    sed -n '/^# Usage/,/^# Dependencies/p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --latency)      LATENCY_MS="$2";    shift 2 ;;
        --jitter)       JITTER_MS="$2";     shift 2 ;;
        --loss)         LOSS_PCT="$2";      shift 2 ;;
        --corrupt)      CORRUPT_PCT="$2";   shift 2 ;;
        --reorder)      REORDER_PCT="$2";   shift 2 ;;
        --reorder-corr) REORDER_CORR="$2";  shift 2 ;;
        --rate)         RATE_KBPS="$2";     shift 2 ;;
        --clean)        CLEAN=true;         shift   ;;
        --dry-run)      DRY_RUN=true;       shift   ;;
        -h|--help)      usage               ;;
        -*)
            error "Unknown option: $1"
            exit 1
            ;;
        *)
            if [ -z "${IFACE}" ]; then
                IFACE="$1"
            else
                error "Unexpected argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate interface
# ---------------------------------------------------------------------------
if [ -z "${IFACE}" ]; then
    error "Interface name required.  Usage: $0 [OPTIONS] <interface>"
    exit 1
fi

if ! ip link show "${IFACE}" &>/dev/null; then
    error "Interface '${IFACE}' not found"
    exit 1
fi

# ---------------------------------------------------------------------------
# --clean: remove all impairment
# ---------------------------------------------------------------------------
if [ "${CLEAN}" = true ]; then
    info "Removing all tc qdisc from ${IFACE}..."
    run tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    run tc qdisc del dev "${IFACE}" ingress 2>/dev/null || true

    # Verify
    QDISCS=$(tc qdisc show dev "${IFACE}" 2>/dev/null | grep -v 'noqueue' || true)
    if [ -z "${QDISCS}" ]; then
        pass "netem removed from ${IFACE} — interface restored to defaults"
    else
        fail "Unexpected qdisc remain on ${IFACE}:"
        echo "${QDISCS}"
        exit 1
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Build the netem command arguments
# ---------------------------------------------------------------------------
info "Configuring netem on ${IFACE}"
info "  Latency : ${LATENCY_MS}ms ± ${JITTER_MS}ms (normal distribution)"
info "  Loss    : ${LOSS_PCT}%"
info "  Corrupt : ${CORRUPT_PCT}%"
info "  Reorder : ${REORDER_PCT}% (corr ${REORDER_CORR}%)"
[ "${RATE_KBPS}" -gt 0 ] && info "  Rate cap: ${RATE_KBPS} kbps"

# Remove existing root qdisc if present (ignore errors)
run tc qdisc del dev "${IFACE}" root 2>/dev/null || true

# Build the netem options string
NETEM_OPTS=(
    delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal
    loss "${LOSS_PCT}%"
    corrupt "${CORRUPT_PCT}%"
    reorder "${REORDER_PCT}%" "${REORDER_CORR}%"
)

# Optionally add rate limiting (uses a TBF child qdisc internally)
if [ "${RATE_KBPS}" -gt 0 ]; then
    NETEM_OPTS+=(rate "${RATE_KBPS}kbit")
fi

# Apply the qdisc
run tc qdisc add dev "${IFACE}" root netem "${NETEM_OPTS[@]}"

# ---------------------------------------------------------------------------
# Verify — read back and compare
# ---------------------------------------------------------------------------
info "Verifying netem settings on ${IFACE}..."
ACTUAL=$(tc qdisc show dev "${IFACE}" 2>/dev/null)

echo "--- tc qdisc output ---"
echo "${ACTUAL}"
echo "-----------------------"

RESULT=0

# Check delay value is present
if echo "${ACTUAL}" | grep -qE "delay [0-9]+"; then
    pass "Delay configured"
else
    fail "Delay not found in qdisc output"
    RESULT=1
fi

# Check loss is present
if echo "${ACTUAL}" | grep -qE "loss [0-9]"; then
    pass "Loss configured"
else
    fail "Loss not found in qdisc output"
    RESULT=1
fi

# Check netem is the active qdisc
if echo "${ACTUAL}" | grep -q "netem"; then
    pass "netem qdisc is active on ${IFACE}"
else
    fail "netem qdisc NOT found on ${IFACE}"
    RESULT=1
fi

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
echo ""
if [ "${RESULT}" -eq 0 ]; then
    pass "=========================================="
    pass " PASS — netem impairment applied to ${IFACE}"
    pass "=========================================="
else
    fail "=========================================="
    fail " FAIL — one or more checks failed"
    fail "=========================================="
    exit 1
fi

# Emit machine-readable summary for CI / orchestration
cat <<JSON
{
  "interface"   : "${IFACE}",
  "latency_ms"  : ${LATENCY_MS},
  "jitter_ms"   : ${JITTER_MS},
  "loss_pct"    : ${LOSS_PCT},
  "corrupt_pct" : ${CORRUPT_PCT},
  "reorder_pct" : ${REORDER_PCT},
  "rate_kbps"   : ${RATE_KBPS},
  "status"      : "PASS"
}
JSON
