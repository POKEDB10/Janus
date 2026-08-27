#!/usr/bin/env bash
# =============================================================================
# Janus Testbed — generate_traffic.sh
# =============================================================================
# Generates labelled IPsec traffic across a scenario peer pair and writes a
# JSON manifest to /dataset/traffic_manifest.json for the Janus ingestion
# pipeline.
#
# Usage
#   generate_traffic.sh [OPTIONS]
#
# Options
#   --scenario   <nn>   Two-digit scenario number, e.g. 01           (required)
#   --target     <ip>   Destination IP for traffic                    (required)
#   --duration   <sec>  Duration of each traffic burst in seconds     (default: 60)
#   --iface      <dev>  Source interface for DSCP marking             (default: eth0)
#   --baseline          Generate unencrypted baseline traffic too
#   --dry-run           Print commands without executing
#   -h | --help         Show this help
#
# DSCP class map (per RFC 2474 / RFC 4594)
#   EF  (46 / 0x2E) → VoIP / real-time audio simulation
#   AF41(34 / 0x22) → Video conferencing simulation
#   CS0 ( 0 / 0x00) → Best-effort / web / default
#   CS6 (48 / 0x30) → Network control / routing management
#
# Manifest schema (/dataset/traffic_manifest.json)
#   {
#     "scenario"   : "01",
#     "timestamp"  : "<ISO-8601>",
#     "entries"    : [
#       { "flow_type": "iperf3_tcp", "dscp": 46, "dscp_name": "EF",
#         "duration_s": 60, "target": "172.20.1.2", "protocol": "TCP",
#         "port": 5201, "baseline": false }
#       ...
#     ]
#   }
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCENARIO=""
TARGET=""
DURATION=60
IFACE="eth0"
BASELINE=false
DRY_RUN=false
DATASET_DIR="${DATASET_DIR:-/dataset}"
MANIFEST_FILE="${DATASET_DIR}/traffic_manifest.json"

# DSCP values (decimal DSCP class, not TOS byte)
DSCP_EF=46    # 0x2E — Expedited Forwarding (VoIP)
DSCP_AF41=34  # 0x22 — Assured Forwarding 41 (video)
DSCP_CS0=0    # 0x00 — Class Selector 0 (default/best-effort)
DSCP_CS6=48   # 0x30 — Class Selector 6 (network control)

# ---------------------------------------------------------------------------
# Colour / log helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO ]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK   ]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC}  $*" >&2; }

run() {
    if [ "${DRY_RUN}" = true ]; then
        echo "  [DRY-RUN] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# JSON manifest helpers
# ---------------------------------------------------------------------------
MANIFEST_ENTRIES=()

manifest_add() {
    # Arguments: flow_type dscp dscp_name protocol port baseline
    local flow_type="$1" dscp="$2" dscp_name="$3" protocol="$4" port="$5" is_baseline="$6"
    MANIFEST_ENTRIES+=("{
      \"flow_type\"   : \"${flow_type}\",
      \"dscp\"        : ${dscp},
      \"dscp_name\"   : \"${dscp_name}\",
      \"duration_s\"  : ${DURATION},
      \"target\"      : \"${TARGET}\",
      \"protocol\"    : \"${protocol}\",
      \"port\"        : ${port},
      \"baseline\"    : ${is_baseline}
    }")
}

manifest_write() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    mkdir -p "${DATASET_DIR}"

    # Join entries with commas
    local joined
    joined=$(printf '%s,\n' "${MANIFEST_ENTRIES[@]}")
    joined="${joined%,}" # strip trailing comma

    cat > "${MANIFEST_FILE}" <<EOF
{
  "scenario"  : "${SCENARIO}",
  "timestamp" : "${ts}",
  "iface"     : "${IFACE}",
  "baseline"  : ${BASELINE},
  "entries"   : [
${joined}
  ]
}
EOF
    ok "Manifest written → ${MANIFEST_FILE}"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
usage() {
    sed -n '/^# Usage/,/^# Manifest schema/p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)  SCENARIO="$2";  shift 2 ;;
        --target)    TARGET="$2";    shift 2 ;;
        --duration)  DURATION="$2";  shift 2 ;;
        --iface)     IFACE="$2";     shift 2 ;;
        --baseline)  BASELINE=true;  shift   ;;
        --dry-run)   DRY_RUN=true;   shift   ;;
        -h|--help)   usage           ;;
        *)
            error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate required args
# ---------------------------------------------------------------------------
if [ -z "${SCENARIO}" ]; then
    error "--scenario is required"
    exit 1
fi

if [ -z "${TARGET}" ]; then
    error "--target is required"
    exit 1
fi

info "=== Janus Traffic Generator ==="
info "Scenario : ${SCENARIO}"
info "Target   : ${TARGET}"
info "Duration : ${DURATION}s per burst"
info "Interface: ${IFACE}"
info "Baseline : ${BASELINE}"

# ---------------------------------------------------------------------------
# Function: set_dscp
# Sets the DSCP mark on outgoing packets via iptables DSCP target.
# The mark is scoped to a specific destination IP + protocol to avoid
# affecting unrelated traffic.
#   $1 = DSCP value (decimal)
#   $2 = protocol (tcp|udp|icmp)
#   $3 = destination port (0 = any)
# ---------------------------------------------------------------------------
set_dscp() {
    local dscp="$1" proto="$2" dport="$3"
    local port_arg=""
    [ "${dport}" -gt 0 ] && port_arg="--dport ${dport}"

    # Remove existing DSCP rule for this proto/port (idempotent)
    iptables -t mangle -D OUTPUT \
        -d "${TARGET}" -p "${proto}" ${port_arg:+${port_arg}} \
        -j DSCP --set-dscp "${dscp}" 2>/dev/null || true

    # Install new rule
    run iptables -t mangle -A OUTPUT \
        -d "${TARGET}" -p "${proto}" ${port_arg:+${port_arg}} \
        -j DSCP --set-dscp "${dscp}"
}

# ---------------------------------------------------------------------------
# Function: clear_dscp_rules
# Removes all DSCP mangle rules targeting the scenario peer.
# ---------------------------------------------------------------------------
clear_dscp_rules() {
    info "Clearing DSCP mangle rules for ${TARGET}..."
    # Flush all OUTPUT mangle rules — fine for isolated testbed containers
    run iptables -t mangle -F OUTPUT 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Function: run_iperf3_server
# Starts iperf3 in server mode on the target (must be SSH-able or exec-able).
# In the testbed, each peer container runs iperf3 -s at startup; this just
# documents the assumed server port.
# ---------------------------------------------------------------------------
IPERF3_PORT=5201

# ---------------------------------------------------------------------------
# Traffic generation loop
# ---------------------------------------------------------------------------

# -- 1. VoIP simulation: small UDP packets, EF DSCP ---
info "--- VoIP (DSCP EF=46, UDP, small packets) ---"
set_dscp "${DSCP_EF}" udp "${IPERF3_PORT}"
run iperf3 \
    --client "${TARGET}" \
    --port "${IPERF3_PORT}" \
    --udp \
    --bandwidth 64k \
    --length 160 \
    --time "${DURATION}" \
    --interval 10 \
    --json \
    > "${DATASET_DIR}/iperf3_sc${SCENARIO}_voip.json" 2>&1 || \
    warn "iperf3 VoIP burst completed (non-zero exit ignored)"
manifest_add "iperf3_udp_voip" "${DSCP_EF}" "EF" "UDP" "${IPERF3_PORT}" "false"
ok "VoIP burst complete"

# -- 2. Video simulation: bulk UDP, AF41 DSCP ---
info "--- Video (DSCP AF41=34, UDP, 5 Mbps) ---"
set_dscp "${DSCP_AF41}" udp "${IPERF3_PORT}"
run iperf3 \
    --client "${TARGET}" \
    --port "${IPERF3_PORT}" \
    --udp \
    --bandwidth 5m \
    --length 1400 \
    --time "${DURATION}" \
    --interval 10 \
    --json \
    > "${DATASET_DIR}/iperf3_sc${SCENARIO}_video.json" 2>&1 || \
    warn "iperf3 video burst completed (non-zero exit ignored)"
manifest_add "iperf3_udp_video" "${DSCP_AF41}" "AF41" "UDP" "${IPERF3_PORT}" "false"
ok "Video burst complete"

# -- 3. Web / bulk TCP: CS0 DSCP ---
info "--- Web/Bulk TCP (DSCP CS0=0, TCP) ---"
set_dscp "${DSCP_CS0}" tcp "${IPERF3_PORT}"
run iperf3 \
    --client "${TARGET}" \
    --port "${IPERF3_PORT}" \
    --time "${DURATION}" \
    --parallel 4 \
    --interval 10 \
    --json \
    > "${DATASET_DIR}/iperf3_sc${SCENARIO}_bulk.json" 2>&1 || \
    warn "iperf3 bulk TCP burst completed"
manifest_add "iperf3_tcp_bulk" "${DSCP_CS0}" "CS0" "TCP" "${IPERF3_PORT}" "false"
ok "Bulk TCP burst complete"

# -- 4. Network management: ICMP, CS6 DSCP ---
info "--- ICMP/Routing (DSCP CS6=48, ICMP) ---"
set_dscp "${DSCP_CS6}" icmp 0
# ping flood for DURATION seconds (requires root / NET_RAW)
run ping \
    -i 0.5 \
    -c $(( DURATION * 2 )) \
    -s 64 \
    -Q $(( DSCP_CS6 << 2 )) \
    "${TARGET}" \
    > "${DATASET_DIR}/ping_sc${SCENARIO}_mgmt.txt" 2>&1 || \
    warn "ping burst complete (non-zero ignored)"
manifest_add "ping_icmp_mgmt" "${DSCP_CS6}" "CS6" "ICMP" "0" "false"
ok "ICMP management burst complete"

# -- 5. Mixed DSCP reverse direction (TCP, initiator→responder then back) ---
info "--- Reverse TCP (DSCP AF41=34, TCP, --reverse) ---"
set_dscp "${DSCP_AF41}" tcp "${IPERF3_PORT}"
run iperf3 \
    --client "${TARGET}" \
    --port "${IPERF3_PORT}" \
    --time "${DURATION}" \
    --reverse \
    --json \
    > "${DATASET_DIR}/iperf3_sc${SCENARIO}_reverse.json" 2>&1 || \
    warn "Reverse TCP burst complete"
manifest_add "iperf3_tcp_reverse" "${DSCP_AF41}" "AF41" "TCP" "${IPERF3_PORT}" "false"
ok "Reverse TCP burst complete"

# ---------------------------------------------------------------------------
# Baseline (unencrypted) traffic — only when --baseline flag is set
# This should run between containers NOT connected over VPN so the capture
# contains unencrypted plaintext for comparison.
# ---------------------------------------------------------------------------
if [ "${BASELINE}" = true ]; then
    info "=== Generating BASELINE (non-VPN) traffic ==="

    BASELINE_PORT=5202  # separate port to avoid mixing with VPN iperf3

    # Plain TCP baseline
    set_dscp "${DSCP_CS0}" tcp "${BASELINE_PORT}"
    run iperf3 \
        --client "${TARGET}" \
        --port "${BASELINE_PORT}" \
        --time "${DURATION}" \
        --json \
        > "${DATASET_DIR}/iperf3_sc${SCENARIO}_baseline_tcp.json" 2>&1 || \
        warn "Baseline TCP done"
    manifest_add "iperf3_tcp_baseline" "${DSCP_CS0}" "CS0" "TCP" "${BASELINE_PORT}" "true"

    # Plain UDP baseline
    set_dscp "${DSCP_EF}" udp "${BASELINE_PORT}"
    run iperf3 \
        --client "${TARGET}" \
        --port "${BASELINE_PORT}" \
        --udp \
        --bandwidth 1m \
        --time "${DURATION}" \
        --json \
        > "${DATASET_DIR}/iperf3_sc${SCENARIO}_baseline_udp.json" 2>&1 || \
        warn "Baseline UDP done"
    manifest_add "iperf3_udp_baseline" "${DSCP_EF}" "EF" "UDP" "${BASELINE_PORT}" "true"

    ok "Baseline traffic generation complete"
fi

# ---------------------------------------------------------------------------
# Clean up DSCP rules
# ---------------------------------------------------------------------------
clear_dscp_rules

# ---------------------------------------------------------------------------
# Write manifest
# ---------------------------------------------------------------------------
manifest_write

info "=== Traffic generation for scenario ${SCENARIO} COMPLETE ==="
