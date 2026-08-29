#!/usr/bin/env python3
"""
verify_dscp_propagation.py
--------------------------
Standalone verification script that checks whether strongSwan's copy_dscp
feature actually propagates the inner IP DSCP field to the outer ESP IP
header in the running Docker/kernel environment.

Usage:
    python verify_dscp_propagation.py \
        --interface eth1 \
        --tunnel-src 10.0.0.1 \
        --tunnel-dst 10.0.0.2

    Optional:
        --timeout 5          # seconds to wait for ESP reply per DSCP probe
        --count  3           # number of probe packets per DSCP value

# TODO(uncertain): copy_dscp propagation is known-flaky on some netns/kernel
# combinations -- must verify in actual Docker environment before trusting
# auto-labels.  Kernel versions < 5.15 have been observed silently stripping
# the DSCP bits on the outer header even when copy_dscp=yes is configured.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

try:
    from scapy.all import (  # type: ignore[import-untyped]
        IP,
        ICMP,
        ESP,
        Raw,
        conf,
        send,
        sniff,
    )
    from scapy.layers.inet import IP as ScapyIP  # noqa: F401 - re-export alias
except ImportError:
    IP = None
    ICMP = None
    ESP = None
    Raw = None
    conf = None
    send = None
    sniff = None
    ScapyIP = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DSCP values to probe, expressed as the 6-bit DSCP value (bits 7..2 of TOS).
# The TOS field is DSCP << 2 (ECN bits left as 0).
DSCP_CLASSES: dict[str, int] = {
    "EF":   46,   # Expedited Forwarding  (RFC 3246)
    "AF41": 34,   # Assured Forwarding 41 (RFC 2597)
    "CS0":  0,    # Class Selector 0 / Best Effort (RFC 2474)
    "CS6":  48,   # Class Selector 6 (Network Control) (RFC 2474)
}

OUTPUT_PATH = Path("/dataset/dscp_verification_result.json")
LOG_FORMAT  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Result for a single DSCP probe class."""
    dscp_class:       str
    dscp_value:       int          # expected 6-bit DSCP
    tos_sent:         int          # TOS byte sent in inner packet
    captured_packets: int          # ESP packets captured during window
    outer_tos_values: list[int]    # TOS bytes seen on outer ESP header
    outer_dscp_values: list[int]   # derived 6-bit DSCP from outer TOS
    passed:           bool
    note:             str = ""


@dataclass
class VerificationReport:
    """Aggregated DSCP propagation verification report."""
    timestamp:        str
    interface:        str
    tunnel_src:       str
    tunnel_dst:       str
    kernel:           str
    results:          list[ProbeResult]
    overall_pass:     bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tos_from_dscp(dscp: int) -> int:
    """Convert a 6-bit DSCP value to the 8-bit IP TOS byte (ECN=0)."""
    return (dscp & 0x3F) << 2


def _dscp_from_tos(tos: int) -> int:
    """Extract the 6-bit DSCP from an 8-bit IP TOS byte."""
    return (tos >> 2) & 0x3F


def _kernel_version() -> str:
    """Return the running kernel version string, if available."""
    try:
        import platform
        return platform.release()
    except Exception:
        return "unknown"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify copy_dscp propagation through a strongSwan IPsec tunnel."
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="Network interface to send probes on and capture ESP traffic from.",
    )
    parser.add_argument(
        "--tunnel-src",
        required=True,
        dest="tunnel_src",
        help="Source IP address of the IPsec tunnel (local gateway outer IP).",
    )
    parser.add_argument(
        "--tunnel-dst",
        required=True,
        dest="tunnel_dst",
        help="Destination IP address of the IPsec tunnel (remote gateway outer IP).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Seconds to listen for ESP packets after each probe burst (default: 5).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="Number of ICMP probe packets to send per DSCP class (default: 3).",
    )
    parser.add_argument(
        "--output",
        default=str(OUTPUT_PATH),
        help=f"Path to write the JSON verification result (default: {OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

class DscpVerifier:
    """
    Sends ICMP probes with specific DSCP markings through the IPsec tunnel
    and inspects the outer ESP IP header to verify copy_dscp propagation.
    """

    def __init__(
        self,
        interface:  str,
        tunnel_src: str,
        tunnel_dst: str,
        timeout:    float = 5.0,
        count:      int   = 3,
    ) -> None:
        self.interface  = interface
        self.tunnel_src = tunnel_src
        self.tunnel_dst = tunnel_dst
        self.timeout    = timeout
        self.count      = count
        self.log        = logging.getLogger(self.__class__.__name__)

        # Tell Scapy which interface to use if available.
        if conf is not None:
            conf.iface = interface  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> VerificationReport:
        """Execute the full verification suite and return a report."""
        if conf is None or sniff is None or send is None:
            raise RuntimeError("Scapy is required for DSCP verification. Install with `pip install scapy`.")

        self.log.info(
            "Starting DSCP propagation verification on interface=%s, "
            "tunnel %s -> %s",
            self.interface,
            self.tunnel_src,
            self.tunnel_dst,
        )

        results: list[ProbeResult] = []
        for cls_name, dscp_val in DSCP_CLASSES.items():
            self.log.info("Probing DSCP class %s (value=%d) ...", cls_name, dscp_val)
            result = self._probe_dscp_class(cls_name, dscp_val)
            results.append(result)
            status = "PASS" if result.passed else "FAIL"
            self.log.info(
                "  %s  outer_dscp=%s  expected=%d  captured=%d pkt(s)",
                status,
                result.outer_dscp_values,
                dscp_val,
                result.captured_packets,
            )

        overall = all(r.passed for r in results)
        report = VerificationReport(
            timestamp    = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            interface    = self.interface,
            tunnel_src   = self.tunnel_src,
            tunnel_dst   = self.tunnel_dst,
            kernel       = _kernel_version(),
            results      = results,
            overall_pass = overall,
        )
        self.log.info(
            "Overall result: %s", "PASS" if overall else "FAIL"
        )
        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _probe_dscp_class(self, cls_name: str, dscp_val: int) -> ProbeResult:
        """
        Send ``self.count`` ICMP packets tagged with *dscp_val*, capture
        the resulting ESP packets on the outer interface, and compare the
        outer DSCP to the expected value.

        The packet is directed at the tunnel destination as a stand-in for
        traffic that will be encapsulated by the kernel IPsec stack.
        The ICMP probe itself may or may not reach the far end -- we only
        care about the ESP wrapper visible on the outer interface.

        Returns a :class:`ProbeResult` describing the outcome.
        """
        tos_byte = _tos_from_dscp(dscp_val)

        # Build inner probe packet.
        inner_pkt = (
            IP(src=self.tunnel_src, dst=self.tunnel_dst, tos=tos_byte)
            / ICMP(type=8, code=0, id=0xDEAD, seq=dscp_val)
            / Raw(load=b"janus-dscp-probe")
        )

        # BPF filter: only grab ESP packets between the two tunnel endpoints.
        bpf_filter = (
            f"esp and host {self.tunnel_src} and host {self.tunnel_dst}"
        )

        captured: list = []

        def _packet_cb(pkt) -> None:  # type: ignore[type-arg]
            if pkt.haslayer(IP):
                captured.append(pkt)

        # Start async sniffer first, then send the probes so we don't miss
        # packets that arrive before send() returns.
        sniffer = sniff(
            iface   = self.interface,
            filter  = bpf_filter,
            prn     = _packet_cb,
            timeout = self.timeout,
            store   = True,
            started_callback=lambda: self.log.debug(
                "Sniffer armed, sending %d probe(s) with TOS=0x%02x",
                self.count,
                tos_byte,
            ),
        )  # type: ignore[call-arg]

        # Give the sniffer thread a moment to arm before firing probes.
        time.sleep(0.05)

        try:
            send(
                inner_pkt,
                iface  = self.interface,
                count  = self.count,
                inter  = 0.1,    # 100 ms between probes
                verbose= False,
            )
        except PermissionError:
            self.log.error(
                "Permission denied when sending packets -- are you running as root?"
            )
            return ProbeResult(
                dscp_class        = cls_name,
                dscp_value        = dscp_val,
                tos_sent          = tos_byte,
                captured_packets  = 0,
                outer_tos_values  = [],
                outer_dscp_values = [],
                passed            = False,
                note              = "PermissionError -- must run as root/CAP_NET_RAW",
            )

        # Block until the sniffer timeout expires.
        sniffer.join()  # type: ignore[union-attr]

        outer_tos:  list[int] = []
        outer_dscp: list[int] = []

        for pkt in captured:
            ip_layer = pkt[IP]
            outer_tos.append(ip_layer.tos)
            outer_dscp.append(_dscp_from_tos(ip_layer.tos))

        # A probe is considered passing if at least one captured ESP packet
        # carries the expected DSCP value in its outer IP header.
        passed = bool(outer_dscp) and any(d == dscp_val for d in outer_dscp)

        note = ""
        if not captured:
            note = (
                "No ESP packets captured -- tunnel may not be up, or "
                "copy_dscp may be stripping/rewriting the outer TOS byte."
            )
        elif not passed:
            note = (
                f"Expected outer DSCP={dscp_val}, got {set(outer_dscp)}. "
                "copy_dscp may not be configured or kernel may not support it."
            )

        return ProbeResult(
            dscp_class        = cls_name,
            dscp_value        = dscp_val,
            tos_sent          = tos_byte,
            captured_packets  = len(captured),
            outer_tos_values  = outer_tos,
            outer_dscp_values = outer_dscp,
            passed            = passed,
            note              = note,
        )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _report_to_dict(report: VerificationReport) -> dict:
    """Serialise the report to a plain Python dict for JSON output."""
    return asdict(report)


def _write_result(report: VerificationReport, output_path: str) -> None:
    """Write the verification report to a JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = _report_to_dict(report)

    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    logging.getLogger(__name__).info("Verification result written to %s", path)


def _print_summary(report: VerificationReport) -> None:
    """Print a human-readable summary table to stdout."""
    print("\n" + "=" * 60)
    print("  DSCP Propagation Verification Report")
    print("=" * 60)
    print(f"  Kernel:     {report.kernel}")
    print(f"  Interface:  {report.interface}")
    print(f"  Tunnel:     {report.tunnel_src} -> {report.tunnel_dst}")
    print(f"  Timestamp:  {report.timestamp}")
    print("-" * 60)
    print(f"  {'Class':<8}  {'DSCP':>4}  {'Captured':>9}  {'OuterDSCP':<18}  {'Result'}")
    print("-" * 60)

    for r in report.results:
        outer_str = str(set(r.outer_dscp_values)) if r.outer_dscp_values else "--"
        status    = "PASS" if r.passed else "FAIL"
        print(
            f"  {r.dscp_class:<8}  {r.dscp_value:>4}  {r.captured_packets:>9}  "
            f"{outer_str:<18}  {status}"
        )
        if r.note:
            print(f"           -> {r.note}")

    print("=" * 60)
    overall_str = "PASS" if report.overall_pass else "FAIL"
    print(f"  Overall: {overall_str}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Entry point.  Returns 0 on overall PASS, 1 on overall FAIL."""
    parser  = _build_parser()
    args    = parser.parse_args()

    logging.basicConfig(
        level  = logging.DEBUG if args.verbose else logging.INFO,
        format = LOG_FORMAT,
        stream = sys.stderr,
    )

    verifier = DscpVerifier(
        interface  = args.interface,
        tunnel_src = args.tunnel_src,
        tunnel_dst = args.tunnel_dst,
        timeout    = args.timeout,
        count      = args.count,
    )

    try:
        report = verifier.run()
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("Interrupted by user.")
        return 2

    _print_summary(report)
    _write_result(report, args.output)

    return 0 if report.overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
