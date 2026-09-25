# =============================================================================
# Janus Testbed — Makefile
# =============================================================================
# Targets
#   all                Build all images
#   build              docker compose build (no cache)
#   up                 Bring the full testbed up (detached)
#   down               Tear down the testbed
#   capture-scenario   Capture a single scenario  (SCENARIO=01 make capture-scenario)
#   run-all-scenarios  Iterate all 12 scenarios with traffic generation
#   clean              Remove captures + dataset output
#   verify-dscp        Run the DSCP verification helper
#   status             Show running container list
#   logs               Tail logs for a specific scenario (SCENARIO=01 make logs)
#   shell              Open a shell in a scenario container (SCENARIO=01 ROLE=init)
#
# Variables (override on CLI)
#   SCENARIO        Two-digit scenario number, e.g. 01    (default: 01)
#   ROLE            init or resp                          (default: init)
#   CAPTURE_SECS    How long to capture per scenario      (default: 120)
#   TRAFFIC_SECS    Traffic generation duration per burst (default: 60)
#   CAPTURES_DIR    Host path for .pcapng files           (default: ./captures)
#   DATASET_DIR     Host path for labelled dataset        (default: ./dataset)
# =============================================================================

SHELL           := /bin/bash
.SHELLFLAGS     := -euo pipefail -c

# ---------------------------------------------------------------------------
# User-overridable variables
# ---------------------------------------------------------------------------
SCENARIO        ?= 01
ROLE            ?= init
CAPTURE_SECS    ?= 120
TRAFFIC_SECS    ?= 60
CAPTURES_DIR    ?= $(CURDIR)/captures
DATASET_DIR     ?= $(CURDIR)/dataset
DPATH = $(patsubst /mnt/%,/run/desktop/mnt/host/%,$(1))
COMPOSE         := docker compose
COMPOSE_FILE    := docker-compose.yml

# Scenario list — add new IDs here as scenarios are added
ALL_SCENARIOS   := 01 02 03 04 05 06 07 08 09 10 11 12

# Container naming convention
INIT_CONTAINER  = sc$(SCENARIO)-init
RESP_CONTAINER  = sc$(SCENARIO)-resp
CAPTURE_CONTAINER := janus-capture
TRAFFIC_CONTAINER := janus-traffic-gen

# ---------------------------------------------------------------------------
# Colours (ANSI)
# ---------------------------------------------------------------------------
RESET  := \033[0m
BOLD   := \033[1m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
CYAN   := \033[0;36m

define log_info
	@echo -e "$(CYAN)[INFO ]$(RESET)  $(1)"
endef

define log_ok
	@echo -e "$(GREEN)[OK   ]$(RESET)  $(1)"
endef

define log_warn
	@echo -e "$(YELLOW)[WARN ]$(RESET)  $(1)"
endef

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: all build up down \
        capture-scenario run-all-scenarios \
        clean clean-captures clean-dataset \
        verify-dscp status logs shell \
        help dirs

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
all: build
	$(call log_ok,"Build complete.  Run 'make up' to start the testbed.")

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------
help:
	@echo ""
	@echo -e "$(BOLD)Janus Testbed Makefile$(RESET)"
	@echo ""
	@echo "  make build                   Build all Docker images"
	@echo "  make up                      Start the full testbed (detached)"
	@echo "  make down                    Tear down all containers"
	@echo "  make status                  Show running containers"
	@echo "  make logs           SCENARIO=01  Tail logs for sc01-init"
	@echo "  make shell          SCENARIO=01  Open shell in sc01-init"
	@echo "  make capture-scenario SCENARIO=01  Run traffic + capture for one scenario"
	@echo "  make run-all-scenarios          Iterate all $(words $(ALL_SCENARIOS)) scenarios"
	@echo "  make verify-dscp    SCENARIO=01  Check DSCP marking is active"
	@echo "  make clean                   Delete captures + dataset output"
	@echo ""

# ---------------------------------------------------------------------------
# dirs — create host-side output directories
# ---------------------------------------------------------------------------
dirs:
	@mkdir -p "$(CAPTURES_DIR)" "$(DATASET_DIR)"
	$(call log_ok,"Output directories ready")

# ---------------------------------------------------------------------------
# build — build with no cache to ensure fresh layers
# ---------------------------------------------------------------------------
build: dirs
	$(call log_info,"Building strongSwan images...")
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache --pull
	$(call log_ok,"Build complete")

# ---------------------------------------------------------------------------
# up — start all services
# ---------------------------------------------------------------------------
up: dirs
	$(call log_info,"Starting Janus testbed...")
	CAPTURES_DIR=$(call DPATH,$(CAPTURES_DIR)) DATASET_DIR=$(call DPATH,$(DATASET_DIR)) \
	    $(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo ""
	$(call log_ok,"Testbed running.  Use 'make status' to inspect containers.")
	@echo ""
	@echo "  Capture container : $(CAPTURE_CONTAINER)"
	@echo "  Traffic container : $(TRAFFIC_CONTAINER)"
	@echo "  Peer containers   : sc{01..12}-{init,resp}"

# ---------------------------------------------------------------------------
# down — stop + remove containers (volumes preserved)
# ---------------------------------------------------------------------------
down:
	$(call log_info,"Stopping Janus testbed...")
	$(COMPOSE) -f $(COMPOSE_FILE) down --remove-orphans
	$(call log_ok,"Testbed stopped")

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
status:
	@echo -e "$(CYAN)--- Running Janus containers ---$(RESET)"
	@docker ps --filter "name=sc0" \
	           --filter "name=sc1" \
	           --filter "name=janus" \
	    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
	    echo "(no matching containers running)"

# ---------------------------------------------------------------------------
# logs — tail logs for sc<SCENARIO>-<ROLE>
# ---------------------------------------------------------------------------
logs:
	$(call log_info,"Tailing logs for sc$(SCENARIO)-$(ROLE)...")
	@docker logs -f sc$(SCENARIO)-$(ROLE) 2>&1 || \
	    echo "Container sc$(SCENARIO)-$(ROLE) not running"

# ---------------------------------------------------------------------------
# shell — interactive bash in sc<SCENARIO>-<ROLE>
# ---------------------------------------------------------------------------
shell:
	$(call log_info,"Opening shell in sc$(SCENARIO)-$(ROLE)...")
	@docker exec -it sc$(SCENARIO)-$(ROLE) /bin/bash

# ---------------------------------------------------------------------------
# capture-scenario
# ---------------------------------------------------------------------------
# Workflow:
#   1. Confirm the scenario pair is running
#   2. Start a per-scenario tshark capture (ring buffer)
#   3. Exec generate_traffic.sh inside the traffic-gen container
#   4. Wait CAPTURE_SECS then stop tshark
#   5. Report the .pcapng path
# ---------------------------------------------------------------------------
capture-scenario:
	$(call log_info,"=== Scenario $(SCENARIO) capture start ===")

	# Verify initiator container is up
	@docker inspect --format '{{.State.Status}}' $(INIT_CONTAINER) 2>/dev/null | \
	    grep -q running || \
	    (echo "ERROR: $(INIT_CONTAINER) is not running. Run 'make up' first." && exit 1)

	# Start packet capture on the initiator container interface before IKE negotiation
	# (Captures on INIT_CONTAINER eth0 directly, ensuring both IKE handshake and ESP are recorded)
	@docker exec -d $(INIT_CONTAINER) \
	    tcpdump -i eth0 -s 0 -w /captures/sc$(SCENARIO)_$$(date +%Y%m%d_%H%M%S).pcap \
	    "udp port 500 or udp port 4500 or esp" 2>/dev/null || \
	    docker exec -d $(CAPTURE_CONTAINER) \
	        tshark -i eth0 -a duration:$(CAPTURE_SECS) -w /captures/sc$(SCENARIO)_$$(date +%Y%m%d_%H%M%S).pcapng \
	        -f "udp port 500 or udp port 4500 or esp" 2>/dev/null
	$(call log_ok,"Packet capture started on wire")
	@sleep 1

	# Re-negotiate IKE SA while sniffer is running so full IKE_SA_INIT and IKE_AUTH handshake is captured!
	$(call log_info,"Triggering IKE SA negotiation during active capture window...")
	@docker exec $(INIT_CONTAINER) swanctl --terminate --ike sc$(SCENARIO) 2>/dev/null || true
	@sleep 1
	@docker exec $(INIT_CONTAINER) swanctl --initiate --child sc$(SCENARIO) --timeout 15 2>/dev/null || true

	# Get target IP for this scenario from the initiator's environment
	$(eval TARGET_IP := $(shell docker inspect --format \
	    '{{range .Config.Env}}{{if (eq (slice . 0 11) "REMOTE_ADDR")}}{{slice . 12}}{{end}}{{end}}' \
	    $(INIT_CONTAINER) 2>/dev/null || echo "172.20.$(shell echo $(SCENARIO) | sed 's/^0//').2"))

	# Generate traffic from inside the initiator container
	$(call log_info,"Generating traffic from $(INIT_CONTAINER) → $(TARGET_IP)...")
	@docker exec $(INIT_CONTAINER) bash /scripts/generate_traffic.sh \
	    --scenario $(SCENARIO) \
	    --target $(TARGET_IP) \
	    --duration $(TRAFFIC_SECS) || \
	    $(call log_warn,"Traffic generation exited non-zero (partial capture may still be useful)")

	# Stop tcpdump on initiator
	@docker exec $(INIT_CONTAINER) pkill -INT tcpdump 2>/dev/null || true

	$(call log_ok,"Capture + traffic for scenario $(SCENARIO) complete")
	$(call log_info,"Captures in: $(CAPTURES_DIR)/")
	$(call log_info,"Manifest  : $(DATASET_DIR)/traffic_manifest.json")

# ---------------------------------------------------------------------------
# run-all-scenarios — iterate all scenarios sequentially
# ---------------------------------------------------------------------------
run-all-scenarios:
	$(call log_info,"Running all $(words $(ALL_SCENARIOS)) scenarios...")
	@for sc in $(ALL_SCENARIOS); do \
	    echo -e "$(CYAN)--- Scenario $${sc} ---$(RESET)"; \
	    $(MAKE) --no-print-directory capture-scenario SCENARIO=$${sc} \
	        CAPTURE_SECS=$(CAPTURE_SECS) TRAFFIC_SECS=$(TRAFFIC_SECS) || \
	    echo -e "$(YELLOW)[WARN ] Scenario $${sc} failed, continuing$(RESET)"; \
	    sleep 5; \
	done
	$(call log_ok,"All scenarios complete.")

# ---------------------------------------------------------------------------
# verify-dscp
# ---------------------------------------------------------------------------
# Checks that DSCP marks are being preserved through the IPsec tunnel by:
#   1. Sending a single marked packet from the initiator
#   2. Inspecting the capture on the responder side
# TODO(uncertain): Tighten this check to verify DSCP copy_dscp=out behaviour
#                  by comparing inner vs outer header DSCP in the pcap.
# ---------------------------------------------------------------------------
verify-dscp:
	$(call log_info,"Verifying DSCP marking for scenario $(SCENARIO)...")
	@docker exec $(INIT_CONTAINER) bash -c " \
	    iptables -t mangle -A OUTPUT -j DSCP --set-dscp 46; \
	    ping -c 5 -Q \$$((46 << 2)) \
	        \$$(grep REMOTE_ADDR /proc/1/environ 2>/dev/null | cut -d= -f2 || echo 172.20.1.2) \
	        > /tmp/dscp_verify.txt 2>&1; \
	    iptables -t mangle -D OUTPUT -j DSCP --set-dscp 46 2>/dev/null || true; \
	    cat /tmp/dscp_verify.txt; \
	    echo DSCP_VERIFY=DONE; \
	"
	$(call log_ok,"DSCP verification done for scenario $(SCENARIO)")

# ---------------------------------------------------------------------------
# clean-captures
# ---------------------------------------------------------------------------
clean-captures:
	$(call log_warn,"Removing all .pcapng files from $(CAPTURES_DIR)...")
	@find "$(CAPTURES_DIR)" -name "*.pcapng" -delete 2>/dev/null || true
	@find "$(CAPTURES_DIR)" -name "*.pcap"   -delete 2>/dev/null || true
	$(call log_ok,"Captures cleaned")

# ---------------------------------------------------------------------------
# clean-dataset
# ---------------------------------------------------------------------------
clean-dataset:
	$(call log_warn,"Removing dataset output from $(DATASET_DIR)...")
	@find "$(DATASET_DIR)" -name "*.json" -delete 2>/dev/null || true
	@find "$(DATASET_DIR)" -name "*.txt"  -delete 2>/dev/null || true
	$(call log_ok,"Dataset cleaned")

# ---------------------------------------------------------------------------
# clean — remove all output, leave containers running
# ---------------------------------------------------------------------------
clean: clean-captures clean-dataset
	$(call log_ok,"All output cleaned")
