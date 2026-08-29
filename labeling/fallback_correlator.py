#!/usr/bin/env python3
"""
fallback_correlator.py
----------------------
Time-correlation-based packet labeler that assigns DSCP labels to outer ESP
flows by matching them to inner (cleartext) packets by timestamp proximity.

This is the fallback path used when verify_dscp_propagation reports FAIL --
i.e., when copy_dscp is not reliably propagating the inner DSCP value to the
outer IP header.

Algorithm
---------
1. Read all packets from the inner (cleartext) PCAP and index them by
   timestamp.
2. Read all ESP packets from the outer PCAP.
3. For each outer ESP packet, find the inner packet whose timestamp is
   closest and within ``--window-ms`` ms.
4. Assign the DSCP label from the matched inner packet to the outer packet.
5. Group matched pairs into flows keyed by 5-tuple and emit a labeled CSV.

Usage
-----
    python fallback_correlator.py \
        --inner-pcap /dataset/scenario_01/inner.pcap \
        --outer-pcap /dataset/scenario_01/outer.pcap \
        --window-ms  10 \
        --output-csv /dataset/scenario_01/labels.csv

Dependencies
------------
- dpkt  (fast, pure-C PCAP parser -- not Scapy)
- Install:  pip install dpkt
"""

from __future__ import annotations

import argparse
import bisect
import csv
import logging
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import dpkt  # type: ignore[import-untyped]
except ImportError:
    dpkt = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# IP protocol numbers.
PROTO_TCP:  int = 6
PROTO_UDP:  int = 17
PROTO_ICMP: int = 1
PROTO_ESP:  int = 50

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# CSV output columns.
CSV_COLUMNS = [
    "flow_id",
    "spi",
    "sequence_num",
    "timestamp",
    "matched_dscp",
    "correlation_confidence",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class InnerPacket:
    """Parsed cleartext (inner) packet relevant fields."""
    timestamp:  float          # Unix epoch seconds (from PCAP)
    src_ip:     str
    dst_ip:     str
    sport:      Optional[int]  # None for ICMP
    dport:      Optional[int]  # None for ICMP
    proto:      int
    dscp:       int            # 6-bit DSCP value extracted from IP TOS


@dataclass
class OuterPacket:
    """Parsed ESP (outer) packet relevant fields."""
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    spi:         int            # ESP Security Parameter Index (32-bit)
    seq:         int            # ESP sequence number (32-bit)
    outer_dscp:  int            # DSCP from outer IP header (may be 0 if copy_dscp failed)


@dataclass
class MatchedPair:
    """Correlated inner <-> outer packet pair."""
    outer:       OuterPacket
    inner:       InnerPacket
    delta_ms:    float          # |outer.ts - inner.ts| in milliseconds
    flow_key:    tuple          # (src_ip, dst_ip, sport, dport, proto)


@dataclass
class FlowRecord:
    """Aggregated per-flow label record."""
    flow_id:    str
    flow_key:   tuple
    pairs:      list[MatchedPair] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PCAP readers
# ---------------------------------------------------------------------------

def _dscp_from_tos(tos: int) -> int:
    """Extract 6-bit DSCP from the 8-bit IP TOS / Traffic Class byte."""
    return (tos >> 2) & 0x3F


def _ip_str(addr: bytes) -> str:
    """Convert 4-byte big-endian bytes to dotted-decimal string."""
    return ".".join(str(b) for b in addr)


def read_inner_pcap(path: str, log: logging.Logger) -> list[InnerPacket]:
    """
    Parse an inner (cleartext) PCAP file and return a list of
    :class:`InnerPacket` objects for ICMP, TCP, and UDP traffic.

    Parameters
    ----------
    path:
        Absolute or relative path to the PCAP file.
    log:
        Logger instance for diagnostic messages.

    Returns
    -------
    list[InnerPacket]
        Packets sorted by ascending timestamp.
    """
    packets: list[InnerPacket] = []
    skipped = 0

    try:
        fh = open(path, "rb")
    except OSError as exc:
        log.error("Cannot open inner PCAP %s: %s", path, exc)
        raise

    with fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except Exception as exc:
            log.error("Failed to initialise PCAP reader for %s: %s", path, exc)
            raise

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    skipped += 1
                    continue

                ip: dpkt.ip.IP = eth.data
                src = _ip_str(ip.src)
                dst = _ip_str(ip.dst)
                dscp = _dscp_from_tos(ip.tos)
                proto = ip.p

                sport: Optional[int] = None
                dport: Optional[int] = None

                if proto == PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                    tcp: dpkt.tcp.TCP = ip.data
                    sport, dport = tcp.sport, tcp.dport
                elif proto == PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                    udp: dpkt.udp.UDP = ip.data
                    sport, dport = udp.sport, udp.dport
                elif proto == PROTO_ICMP:
                    # ICMP has type/code, not ports; leave them as None.
                    pass
                else:
                    # Unknown transport -- still capture at IP level.
                    log.debug(
                        "Inner pkt proto=%d (not TCP/UDP/ICMP) -- included with "
                        "sport/dport=None",
                        proto,
                    )

                packets.append(
                    InnerPacket(
                        timestamp = ts,
                        src_ip    = src,
                        dst_ip    = dst,
                        sport     = sport,
                        dport     = dport,
                        proto     = proto,
                        dscp      = dscp,
                    )
                )

            except Exception as exc:  # noqa: BLE001
                log.debug("Skipping malformed inner packet: %s", exc)
                skipped += 1

    packets.sort(key=lambda p: p.timestamp)
    log.info(
        "Inner PCAP: parsed %d packet(s), skipped %d.", len(packets), skipped
    )
    return packets


def read_outer_pcap(path: str, log: logging.Logger) -> list[OuterPacket]:
    """
    Parse an outer (tunnel) PCAP file and return ESP packets as
    :class:`OuterPacket` objects.

    The SPI and sequence number are read from the first 8 bytes of the
    ESP payload per RFC 4303 section 2.1.

    Parameters
    ----------
    path:
        Absolute or relative path to the PCAP file.
    log:
        Logger instance.

    Returns
    -------
    list[OuterPacket]
        ESP packets sorted by ascending timestamp.
    """
    packets: list[OuterPacket] = []
    skipped = 0

    try:
        fh = open(path, "rb")
    except OSError as exc:
        log.error("Cannot open outer PCAP %s: %s", path, exc)
        raise

    with fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except Exception as exc:
            log.error("Failed to initialise PCAP reader for %s: %s", path, exc)
            raise

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    skipped += 1
                    continue

                ip: dpkt.ip.IP = eth.data
                if ip.p != PROTO_ESP:
                    skipped += 1
                    continue

                src = _ip_str(ip.src)
                dst = _ip_str(ip.dst)
                outer_dscp = _dscp_from_tos(ip.tos)

                # Parse ESP header: SPI (4 bytes) + Sequence (4 bytes).
                esp_payload: bytes = bytes(ip.data)
                if len(esp_payload) < 8:
                    log.debug(
                        "ESP payload too short (%d bytes) -- skipping.",
                        len(esp_payload),
                    )
                    skipped += 1
                    continue

                spi, seq = struct.unpack("!II", esp_payload[:8])

                packets.append(
                    OuterPacket(
                        timestamp  = ts,
                        src_ip     = src,
                        dst_ip     = dst,
                        spi        = spi,
                        seq        = seq,
                        outer_dscp = outer_dscp,
                    )
                )

            except Exception as exc:  # noqa: BLE001
                log.debug("Skipping malformed outer packet: %s", exc)
                skipped += 1

    packets.sort(key=lambda p: p.timestamp)
    log.info(
        "Outer PCAP: parsed %d ESP packet(s), skipped %d.", len(packets), skipped
    )
    return packets


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

class FallbackCorrelator:
    """
    Correlates outer ESP packets with inner cleartext packets using
    timestamp proximity within a configurable window.

    Parameters
    ----------
    window_ms:
        Maximum allowed |delta-t| in milliseconds for a valid match.
    """

    def __init__(self, window_ms: float = 10.0) -> None:
        self.window_ms  = window_ms
        self.window_sec = window_ms / 1000.0
        self.log        = logging.getLogger(self.__class__.__name__)

    def correlate(
        self,
        inner_packets: list[InnerPacket],
        outer_packets: list[OuterPacket],
    ) -> tuple[list[MatchedPair], list[OuterPacket]]:
        """
        Match each outer ESP packet to the temporally closest inner packet.

        Parameters
        ----------
        inner_packets:
            Sorted list of cleartext packets (ascending by timestamp).
        outer_packets:
            Sorted list of ESP packets (ascending by timestamp).

        Returns
        -------
        matched:
            List of correlated :class:`MatchedPair` objects.
        unmatched:
            Outer packets for which no inner packet fell within the window.
        """
        if not inner_packets:
            self.log.warning(
                "No inner packets -- all outer packets will be unmatched."
            )
            return [], list(outer_packets)

        # Build sorted timestamp index for O(log n) bisect lookups.
        inner_ts_index: list[float] = [p.timestamp for p in inner_packets]

        matched:   list[MatchedPair]  = []
        unmatched: list[OuterPacket]  = []

        for outer in outer_packets:
            best = self._find_closest(outer.timestamp, inner_ts_index, inner_packets)
            if best is None:
                unmatched.append(outer)
                continue

            inner_pkt, delta_sec = best
            delta_ms = delta_sec * 1000.0

            if delta_ms > self.window_ms:
                unmatched.append(outer)
                self.log.debug(
                    "No match within %.1f ms for ESP spi=0x%08x seq=%d "
                    "(closest delta_t=%.3f ms)",
                    self.window_ms,
                    outer.spi,
                    outer.seq,
                    delta_ms,
                )
                continue

            flow_key = (
                inner_pkt.src_ip,
                inner_pkt.dst_ip,
                inner_pkt.sport,
                inner_pkt.dport,
                inner_pkt.proto,
            )

            matched.append(
                MatchedPair(
                    outer    = outer,
                    inner    = inner_pkt,
                    delta_ms = delta_ms,
                    flow_key = flow_key,
                )
            )

        self.log.info(
            "Correlation: %d matched, %d unmatched (window=%.1f ms).",
            len(matched),
            len(unmatched),
            self.window_ms,
        )
        return matched, unmatched

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _find_closest(
        self,
        target_ts: float,
        ts_index:  list[float],
        packets:   list[InnerPacket],
    ) -> Optional[tuple[InnerPacket, float]]:
        """
        Binary-search the sorted ``ts_index`` for the entry nearest to
        ``target_ts`` and return the associated packet and absolute delta-t.

        Returns ``None`` if ``packets`` is empty.
        """
        if not packets:
            return None

        # bisect_left finds the insertion point; check both neighbours.
        pos = bisect.bisect_left(ts_index, target_ts)

        candidates: list[int] = []
        if pos > 0:
            candidates.append(pos - 1)
        if pos < len(ts_index):
            candidates.append(pos)

        best_idx   = min(candidates, key=lambda i: abs(ts_index[i] - target_ts))
        best_pkt   = packets[best_idx]
        best_delta = abs(ts_index[best_idx] - target_ts)
        return best_pkt, best_delta


# ---------------------------------------------------------------------------
# Flow grouping
# ---------------------------------------------------------------------------

def group_into_flows(matched: list[MatchedPair]) -> dict[str, FlowRecord]:
    """
    Group matched pairs by 5-tuple into named flow records.

    Flow IDs are assigned in the order each unique 5-tuple is first seen,
    using a zero-padded integer suffix (e.g., ``flow_000``, ``flow_001``).

    Parameters
    ----------
    matched:
        Correlated inner <-> outer pairs from :meth:`FallbackCorrelator.correlate`.

    Returns
    -------
    dict[str, FlowRecord]
        Mapping of flow_id -> FlowRecord.
    """
    flows:      dict[str, FlowRecord] = {}
    key_to_id:  dict[tuple, str]      = {}
    counter     = 0

    for pair in matched:
        key = pair.flow_key
        if key not in key_to_id:
            flow_id = f"flow_{counter:03d}"
            key_to_id[key] = flow_id
            flows[flow_id] = FlowRecord(flow_id=flow_id, flow_key=key)
            counter += 1

        flows[key_to_id[key]].pairs.append(pair)

    return flows


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _confidence(delta_ms: float, window_ms: float) -> float:
    """
    Compute a [0.0, 1.0] correlation confidence score.

    Score = 1 - (delta_t / window) so that a perfect delta_t=0 gives 1.0
    and a match exactly at the window boundary gives 0.0.  Clamped to [0, 1].
    """
    if window_ms <= 0:
        return 1.0
    score = 1.0 - (delta_ms / window_ms)
    return max(0.0, min(1.0, score))


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(
    flows:     dict[str, FlowRecord],
    output:    str,
    window_ms: float,
    log:       logging.Logger,
) -> None:
    """
    Write the labeled flow data to a CSV file.

    Columns: flow_id, spi, sequence_num, timestamp, matched_dscp,
             correlation_confidence.

    Parameters
    ----------
    flows:
        Flow records produced by :func:`group_into_flows`.
    output:
        Destination CSV file path.
    window_ms:
        Correlation window used (for confidence scoring).
    log:
        Logger instance.
    """
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    row_count = 0

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for flow_id, record in flows.items():
            for pair in record.pairs:
                confidence = _confidence(pair.delta_ms, window_ms)
                writer.writerow(
                    {
                        "flow_id":                flow_id,
                        "spi":                    f"0x{pair.outer.spi:08x}",
                        "sequence_num":           pair.outer.seq,
                        "timestamp":              f"{pair.outer.timestamp:.6f}",
                        "matched_dscp":           pair.inner.dscp,
                        "correlation_confidence": f"{confidence:.4f}",
                    }
                )
                row_count += 1

    log.info("Wrote %d row(s) to %s.", row_count, out_path)


def write_unmatched_log(
    unmatched:  list[OuterPacket],
    output_csv: str,
    log:        logging.Logger,
) -> None:
    """
    Write unmatched outer ESP packets to a sidecar CSV for diagnostics.

    The sidecar is placed alongside the main CSV with a ``_unmatched``
    suffix (e.g., ``labels_unmatched.csv``).

    Parameters
    ----------
    unmatched:
        Outer packets that had no inner match within the time window.
    output_csv:
        Path of the main labels CSV (used to derive sidecar path).
    log:
        Logger instance.
    """
    if not unmatched:
        log.info("No unmatched packets -- sidecar log not created.")
        return

    base    = Path(output_csv)
    sidecar = base.with_name(base.stem + "_unmatched" + base.suffix)

    with sidecar.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "timestamp", "src_ip", "dst_ip",
                "spi", "sequence_num", "outer_dscp",
            ],
        )
        writer.writeheader()
        for pkt in unmatched:
            writer.writerow(
                {
                    "timestamp":    f"{pkt.timestamp:.6f}",
                    "src_ip":       pkt.src_ip,
                    "dst_ip":       pkt.dst_ip,
                    "spi":          f"0x{pkt.spi:08x}",
                    "sequence_num": pkt.seq,
                    "outer_dscp":   pkt.outer_dscp,
                }
            )

    log.info(
        "Wrote %d unmatched packet(s) to %s.", len(unmatched), sidecar
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Time-correlation-based DSCP labeler for outer ESP flows. "
            "Fallback for environments where copy_dscp is unavailable."
        )
    )
    parser.add_argument(
        "--inner-pcap",
        required=True,
        dest="inner_pcap",
        help="Path to inner (cleartext pre-tunnel) PCAP file.",
    )
    parser.add_argument(
        "--outer-pcap",
        required=True,
        dest="outer_pcap",
        help="Path to outer (post-tunnel ESP) PCAP file.",
    )
    parser.add_argument(
        "--window-ms",
        type=float,
        default=10.0,
        dest="window_ms",
        help="Maximum timestamp delta (ms) for a valid inner <-> outer match (default: 10).",
    )
    parser.add_argument(
        "--output-csv",
        required=True,
        dest="output_csv",
        help="Destination CSV file path for labeled flow records.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main() -> int:
    """CLI entry point.  Returns 0 on success, 1 on error."""
    parser = _build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level  = logging.DEBUG if args.verbose else logging.INFO,
        format = LOG_FORMAT,
        stream = sys.stderr,
    )
    log = logging.getLogger(__name__)

    # --- Read PCAPs --------------------------------------------------------
    try:
        inner_packets = read_inner_pcap(args.inner_pcap, log)
        outer_packets = read_outer_pcap(args.outer_pcap, log)
    except OSError:
        return 1

    if not outer_packets:
        log.error("No ESP packets found in outer PCAP -- nothing to label.")
        return 1

    # --- Correlate ---------------------------------------------------------
    correlator = FallbackCorrelator(window_ms=args.window_ms)
    matched, unmatched = correlator.correlate(inner_packets, outer_packets)

    if not matched:
        log.warning(
            "Zero packets matched -- consider increasing --window-ms "
            "(current: %.1f ms) or check that PCAPs overlap in time.",
            args.window_ms,
        )

    # --- Group into flows --------------------------------------------------
    flows = group_into_flows(matched)
    log.info("Identified %d unique flow(s).", len(flows))

    # --- Write outputs -----------------------------------------------------
    write_csv(flows, args.output_csv, args.window_ms, log)
    write_unmatched_log(unmatched, args.output_csv, log)

    return 0


if __name__ == "__main__":
    sys.exit(main())
