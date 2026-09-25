#!/usr/bin/env bash
# =============================================================================
# Janus Testbed — strongSwan Container Entrypoint
# =============================================================================
# Starts charon (strongSwan IKEv2 daemon) via swanctl and optionally initiates
# an IKE SA if ROLE=initiator.
#
# Environment variables (set by docker-compose.yml)
#   SCENARIO    — two-digit scenario number, e.g. "01"
#   ROLE        — "initiator" or "responder"
#   LOCAL_ID    — IKEv2 identity of this peer
#   REMOTE_ID   — IKEv2 identity of the remote peer
#   LOCAL_ADDR  — IP address of this container
#   REMOTE_ADDR — IP address of the remote container
#   PSK         — pre-shared key (TODO: replace with PKI in production)
# =============================================================================
set -euo pipefail

log() { echo "[entrypoint] $(date '+%T') $*"; }

# ---------------------------------------------------------------------------
# 1. Wait for IP assignment and network readiness
# ---------------------------------------------------------------------------
log "Waiting for network (ROLE=${ROLE:-unknown}, SCENARIO=${SCENARIO:-??})..."
sleep 2

# ---------------------------------------------------------------------------
# 2. Prepare runtime swanctl configuration
#    Host configs in /etc/swanctl/conf.d are read-only templates.
#    We process them into an internal writable directory /etc/swanctl/runtime:
#    - Strip trailing '!' from proposals (invalid syntax in strongSwan 5.9.5 swanctl)
#    - Adjust responder perspective (swap local/remote addresses and IDs, set start_action=trap)
#    - Inject runtime PSK secret
#    - Point /etc/swanctl/swanctl.conf to include runtime/*.conf
# ---------------------------------------------------------------------------
RUNTIME_DIR="/etc/swanctl/runtime"
mkdir -p "${RUNTIME_DIR}"
rm -f "${RUNTIME_DIR}"/*.conf

for cfg in /etc/swanctl/conf.d/*.conf; do
    [ -f "$cfg" ] || continue
    [ "$(basename "$cfg")" = "00_psk_secret.conf" ] && continue
    dest="${RUNTIME_DIR}/$(basename "$cfg")"
    awk -v role="${ROLE:-responder}" '
    BEGIN { in_local=0; in_remote=0; local_id=""; remote_id=""; loc_addr=""; rem_addr=""; }
    {
        if (/proposals/) gsub(/!/, "");
        if (role == "responder" && /start_action[ \t]*=/) {
            sub(/start_action[ \t]*=[ \t]*start/, "start_action = trap");
        }
        lines[NR] = $0;
    }
    /local[ \t]*\{/ { in_local=1; }
    in_local && /id[ \t]*=/ {
        split($0, arr, "=");
        local_id = arr[2];
        gsub(/[ \t\r\n]/, "", local_id);
        local_line = NR;
        in_local = 0;
    }
    /remote[ \t]*\{/ { in_remote=1; }
    in_remote && /id[ \t]*=/ {
        split($0, arr, "=");
        remote_id = arr[2];
        gsub(/[ \t\r\n]/, "", remote_id);
        remote_line = NR;
        in_remote = 0;
    }
    /local_addrs[ \t]*=/ {
        split($0, arr, "=");
        loc_addr = arr[2];
        gsub(/[ \t\r\n]/, "", loc_addr);
        loc_addr_line = NR;
    }
    /remote_addrs[ \t]*=/ {
        split($0, arr, "=");
        rem_addr = arr[2];
        gsub(/[ \t\r\n]/, "", rem_addr);
        rem_addr_line = NR;
    }
    END {
        if (role == "responder") {
            if (local_id != "" && remote_id != "") {
                lines[local_line] = "            id     = " remote_id;
                lines[remote_line] = "            id     = " local_id;
            }
            if (loc_addr != "" && rem_addr != "" && loc_addr != rem_addr) {
                lines[loc_addr_line] = "        local_addrs  = " rem_addr;
                lines[rem_addr_line] = "        remote_addrs = " loc_addr;
            }
        }
        for (i = 1; i <= NR; i++) {
            print lines[i];
        }
    }' "$cfg" > "$dest"
done

SECRETS_FILE="${RUNTIME_DIR}/00_psk_secret.conf"
cat > "${SECRETS_FILE}" <<EOF
secrets {
    ike-sc${SCENARIO} {
        id-1 = "${LOCAL_ID:-}"
        id-2 = "${REMOTE_ID:-}"
        secret = "${PSK:-changeme}"
    }
}
EOF
log "PSK secret written to ${SECRETS_FILE}"

cat > /etc/swanctl/swanctl.conf <<EOF
include runtime/*.conf
EOF

# ---------------------------------------------------------------------------
# 3. Start charon daemon in the background
# ---------------------------------------------------------------------------
sed -i '/socket =/d' /etc/strongswan.d/charon.conf 2>/dev/null || true
rm -f /var/run/charon.vici /var/run/charon/charon.vici

CHARON_BIN="$(command -v charon 2>/dev/null || command -v /usr/lib/ipsec/charon || command -v /usr/sbin/charon || echo /usr/lib/ipsec/charon)"
log "Starting charon daemon (${CHARON_BIN})..."
${CHARON_BIN} &
CHARON_PID=$!
log "charon PID=${CHARON_PID}"

# Give charon time to open the VICI socket and accept commands
for i in $(seq 1 20); do
    if [ -S /var/run/charon.vici ] && [ ! -e /var/run/charon/charon.vici ]; then
        mkdir -p /var/run/charon
        ln -sf /var/run/charon.vici /var/run/charon/charon.vici
    elif [ -S /var/run/charon/charon.vici ] && [ ! -e /var/run/charon.vici ]; then
        ln -sf /var/run/charon/charon.vici /var/run/charon.vici
    fi
    if swanctl --stats >/dev/null 2>&1; then
        log "VICI socket ready (after ${i}s)"
        break
    fi
    sleep 1
done

if [ ! -S /var/run/charon.vici ] && [ ! -S /var/run/charon/charon.vici ]; then
    log "ERROR: VICI socket did not appear — charon may have crashed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Load swanctl connections + credentials
# ---------------------------------------------------------------------------
log "Loading swanctl configuration..."
swanctl --load-all --noprompt || {
    log "WARNING: swanctl --load-all exited non-zero; check config in ${RUNTIME_DIR}/"
}

# List loaded connections for audit trail
log "Loaded connections:"
swanctl --list-conns 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Initiate SA (initiator side only)
# ---------------------------------------------------------------------------
if [ "${ROLE:-responder}" = "initiator" ]; then
    # Wait for the responder container to be ready
    log "Waiting 5s before initiating SA to sc${SCENARIO}-resp (${REMOTE_ADDR:-})..."
    sleep 5

    CONNECTION_NAME="$(swanctl --list-conns 2>/dev/null | awk '/: IKEv/ {sub(/:/, ""); print $1; exit}')"
    [ -z "${CONNECTION_NAME}" ] && CONNECTION_NAME="sc${SCENARIO}"
    CHILD_NAME="$(swanctl --list-conns 2>/dev/null | awk '/: (TUNNEL|TRANSPORT|BEET)/ {sub(/:/, ""); print $1; exit}')"
    TARGET_CHILD="${CHILD_NAME:-${CONNECTION_NAME}}"

    log "Initiating CHILD SA: ${TARGET_CHILD} (conn: ${CONNECTION_NAME})"
    swanctl --initiate --child "${TARGET_CHILD}" \
        --timeout 30 \
        --loglevel 2 \
        || log "WARNING: Initial SA negotiation failed (will retry via reauth)"
fi

# ---------------------------------------------------------------------------
# 6. Keep entrypoint alive — wait for charon to exit
# ---------------------------------------------------------------------------
log "Container running. Waiting for charon (PID=${CHARON_PID})..."
wait "${CHARON_PID}"
log "charon exited — container shutting down"
