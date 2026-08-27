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
sleep 2   # give Docker bridge a moment to assign IP

# ---------------------------------------------------------------------------
# 2. Load the PSK secret into strongSwan secrets (runtime injection)
#    swanctl.conf references the id strings; the actual secret is injected
#    here so it does not have to be baked into a conf file.
#    TODO(uncertain): replace PSK with X.509 certificate authentication
#                     once PKI automation is in place.
# ---------------------------------------------------------------------------
SECRETS_FILE="/etc/swanctl/conf.d/00_psk_secret.conf"
cat > "${SECRETS_FILE}" <<EOF
secrets {
    ike-sc${SCENARIO} {
        id-local  = "${LOCAL_ID:-}"
        id-remote = "${REMOTE_ID:-}"
        secret    = "${PSK:-changeme}"
    }
}
EOF
log "PSK secret written to ${SECRETS_FILE}"

# ---------------------------------------------------------------------------
# 3. Start charon daemon in the background
#    'charon' binary is used directly (not via ipsec starter) so we can
#    control the process lifecycle cleanly.
# ---------------------------------------------------------------------------
log "Starting charon daemon..."
/usr/sbin/charon &
CHARON_PID=$!
log "charon PID=${CHARON_PID}"

# Give charon time to open the VICI socket
for i in $(seq 1 20); do
    if [ -S /var/run/charon/charon.vici ]; then
        log "VICI socket ready (after ${i}s)"
        break
    fi
    sleep 1
done

if [ ! -S /var/run/charon/charon.vici ]; then
    log "ERROR: VICI socket did not appear — charon may have crashed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Load swanctl connections + credentials
# ---------------------------------------------------------------------------
log "Loading swanctl configuration..."
swanctl --load-all --noprompt || {
    log "WARNING: swanctl --load-all exited non-zero; check config in /etc/swanctl/conf.d/"
}

# List loaded connections for audit trail
log "Loaded connections:"
swanctl --list-conns 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Initiate SA (initiator side only)
# ---------------------------------------------------------------------------
if [ "${ROLE:-responder}" = "initiator" ]; then
    # Wait for the responder container to be ready
    log "Waiting 5s before initiating SA to sc${SCENARIO}-resp (${REMOTE_ADDR})..."
    sleep 5

    CONNECTION_NAME="sc${SCENARIO}"
    log "Initiating IKE SA: ${CONNECTION_NAME}"
    swanctl --initiate --child "${CONNECTION_NAME}" \
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
