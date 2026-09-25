"""
Janus Parsing Engine — ESP Flow Feature Extractor
=================================================
High-throughput, low-memory ESP packet parsing and side-channel statistical feature
extraction using dpkt.

Design principles:
- Uses dpkt (fast, low memory footprint) for high-volume ESP packet parsing.
- Extracts flow-level statistical features across packet size, inter-arrival time (IAT),
  burst distributions, and directionality.
- CRITICAL: STRICTLY EXCLUDES IP addresses and port numbers from feature vectors.
  IP addresses and ports leak identity rather than genuine side-channel signals,
  which corrupts machine learning generalization and SHAP explainability.
"""

from __future__ import annotations

import logging
import math
import struct
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

try:
    import dpkt  # type: ignore[import-untyped]
except ImportError:
    dpkt = None  # Handled with friendly error on execution

from parsing.ike_parser import _extract_ip_layer

log = logging.getLogger(__name__)

# Protocol Constants
IP_PROTO_ESP = 50
IP_PROTO_UDP = 17
IP_PROTO_TCP = 6
UDP_PORT_NATT = 4500


@dataclass
class RawESPPacket:
    """Parsed single ESP packet metadata."""

    timestamp: float
    src_ip: str
    dst_ip: str
    spi: int
    seq_num: int
    wire_length: int
    payload_length: int
    is_natt: bool = False


@dataclass
class FlowKey:
    """Unique key identifying an ESP communication channel between two endpoints."""

    endpoint_a: str
    endpoint_b: str
    spi_forward: int
    spi_reverse: Optional[int] = None

    def matches(self, src: str, dst: str, spi: int) -> bool:
        if (src == self.endpoint_a and dst == self.endpoint_b) or (
            src == self.endpoint_b and dst == self.endpoint_a
        ):
            return spi == self.spi_forward or (self.spi_reverse is not None and spi == self.spi_reverse)
        return False


@dataclass
class ESPFlow:
    """Aggregated bidirectional or unidirectional ESP flow."""

    flow_id: str
    src_ip: str
    dst_ip: str
    spi: int
    packets: list[RawESPPacket] = field(default_factory=list)

    @property
    def start_time(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def end_time(self) -> float:
        return self.packets[-1].timestamp if self.packets else 0.0

    @property
    def duration(self) -> float:
        if len(self.packets) <= 1:
            return 0.0
        return max(0.0, self.end_time - self.start_time)

    def get_packet_trace(self, max_packets: int = 64) -> list[list[float]]:
        """
        Extract raw packet sequence representation as a (3, max_packets) matrix.
        Channels:
          0: signed_norm_length (direction * payload_length / 1500.0, forward=+1.0, reverse=-1.0)
          1: norm_length (payload_length / 1500.0)
          2: log_iat (log1p(delta_t * 1000.0) normalized)
        Padded with zeros if flow has fewer than max_packets packets.
        """
        trace = [[0.0] * max_packets, [0.0] * max_packets, [0.0] * max_packets]
        if not self.packets:
            return trace

        forward_src = self.packets[0].src_ip
        n = min(len(self.packets), max_packets)

        for i in range(n):
            pkt = self.packets[i]
            direction = 1.0 if pkt.src_ip == forward_src else -1.0
            norm_len = min(1.0, float(pkt.payload_length) / 1500.0)
            trace[0][i] = round(direction * norm_len, 4)
            trace[1][i] = round(norm_len, 4)

            if i > 0:
                delta = max(0.0, pkt.timestamp - self.packets[i - 1].timestamp)
                log_iat = min(10.0, math.log1p(delta * 1000.0))
                trace[2][i] = round(log_iat, 4)
            else:
                trace[2][i] = 0.0

        return trace


@dataclass
class ESPStatisticalFeatures:
    """
    Extracted flow-level statistical feature vector.
    CRITICAL: IP addresses and port numbers are strictly excluded from this model.
    """

    # Packet Size Statistics (Bytes)
    pkt_len_min: float
    pkt_len_max: float
    pkt_len_mean: float
    pkt_len_var: float
    pkt_len_std: float
    pkt_len_median: float
    pkt_len_q25: float
    pkt_len_q75: float
    pkt_len_iqr: float

    # Inter-Arrival Time Statistics (Seconds)
    iat_min: float
    iat_max: float
    iat_mean: float
    iat_var: float
    iat_std: float

    # Burst Statistics (Consecutive same-direction packets before direction flip)
    burst_count: int
    burst_len_mean: float
    burst_len_max: float
    burst_bytes_mean: float

    # Flow Duration & Volume
    flow_duration_s: float
    total_packets: int
    total_bytes: int
    packet_rate_pps: float
    byte_rate_bps: float

    # Directionality Ratios
    forward_packet_ratio: float
    forward_byte_ratio: float

    def to_dict(self) -> dict[str, float]:
        """Convert features to a flat float dictionary for ML classifier."""
        return asdict(self)

    def to_feature_list(self, feature_order: Optional[list[str]] = None) -> list[float]:
        """Return feature values in standardized column order."""
        d = self.to_dict()
        if feature_order is None:
            return list(d.values())
        return [float(d.get(name, 0.0)) for name in feature_order]


def _percentile(values: list[float], p: float) -> float:
    """Calculate percentile from a sorted list of floats."""
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    idx = (len(values) - 1) * p
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return float(values[int(idx)])
    weight = idx - lower
    return float(values[lower] * (1.0 - weight) + values[upper] * weight)


def _calculate_stats(values: list[float]) -> tuple[float, float, float, float, float, float, float, float, float]:
    """Return (min, max, mean, var, std, median, q25, q75, iqr)."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    s_vals = sorted(values)
    n = len(s_vals)
    val_min = float(s_vals[0])
    val_max = float(s_vals[-1])
    val_mean = float(sum(s_vals) / n)
    val_var = float(sum((x - val_mean) ** 2 for x in s_vals) / n) if n > 1 else 0.0
    val_std = math.sqrt(val_var)
    val_median = _percentile(s_vals, 0.50)
    val_q25 = _percentile(s_vals, 0.25)
    val_q75 = _percentile(s_vals, 0.75)
    val_iqr = val_q75 - val_q25
    return val_min, val_max, val_mean, val_var, val_std, val_median, val_q25, val_q75, val_iqr


def extract_features_from_flow(flow: ESPFlow) -> ESPStatisticalFeatures:
    """
    Compute statistical feature vector from an ESP flow.
    Excludes IP addresses and ports to prevent side-channel leakage.
    """
    packets = flow.packets
    if not packets:
        return ESPStatisticalFeatures(
            pkt_len_min=0, pkt_len_max=0, pkt_len_mean=0, pkt_len_var=0, pkt_len_std=0,
            pkt_len_median=0, pkt_len_q25=0, pkt_len_q75=0, pkt_len_iqr=0,
            iat_min=0, iat_max=0, iat_mean=0, iat_var=0, iat_std=0,
            burst_count=0, burst_len_mean=0, burst_len_max=0, burst_bytes_mean=0,
            flow_duration_s=0, total_packets=0, total_bytes=0,
            packet_rate_pps=0, byte_rate_bps=0,
            forward_packet_ratio=0, forward_byte_ratio=0,
        )

    # 1. Packet Size Statistics
    lengths = [float(p.payload_length) for p in packets]
    p_min, p_max, p_mean, p_var, p_std, p_med, p_q25, p_q75, p_iqr = _calculate_stats(lengths)

    # 2. Inter-Arrival Time Statistics
    iats: list[float] = []
    for i in range(1, len(packets)):
        delta = max(0.0, packets[i].timestamp - packets[i - 1].timestamp)
        iats.append(delta)

    if iats:
        i_min, i_max, i_mean, i_var, i_std, _, _, _, _ = _calculate_stats(iats)
    else:
        i_min, i_max, i_mean, i_var, i_std = 0.0, 0.0, 0.0, 0.0, 0.0

    # 3. Burst Dynamics (consecutive same-direction packets)
    forward_src = packets[0].src_ip
    bursts: list[list[RawESPPacket]] = []
    current_burst: list[RawESPPacket] = [packets[0]]
    forward_pkts = 0
    forward_bytes = 0
    total_bytes = 0

    for p in packets:
        total_bytes += p.payload_length
        if p.src_ip == forward_src:
            forward_pkts += 1
            forward_bytes += p.payload_length

    for i in range(1, len(packets)):
        p = packets[i]
        prev = packets[i - 1]
        if p.src_ip == prev.src_ip:
            current_burst.append(p)
        else:
            bursts.append(current_burst)
            current_burst = [p]
    if current_burst:
        bursts.append(current_burst)

    burst_count = len(bursts)
    burst_lens = [float(len(b)) for b in bursts]
    burst_bytes = [float(sum(p.payload_length for p in b)) for b in bursts]

    b_len_mean = float(sum(burst_lens) / burst_count) if burst_count > 0 else 0.0
    b_len_max = float(max(burst_lens)) if burst_count > 0 else 0.0
    b_bytes_mean = float(sum(burst_bytes) / burst_count) if burst_count > 0 else 0.0

    # 4. Rates & Ratios
    duration = flow.duration
    total_pkts = len(packets)
    pps = float(total_pkts / duration) if duration > 0 else float(total_pkts)
    bps = float(total_bytes / duration) if duration > 0 else float(total_bytes)

    fwd_pkt_ratio = float(forward_pkts / total_pkts) if total_pkts > 0 else 1.0
    fwd_byte_ratio = float(forward_bytes / total_bytes) if total_bytes > 0 else 1.0

    return ESPStatisticalFeatures(
        pkt_len_min=round(p_min, 4),
        pkt_len_max=round(p_max, 4),
        pkt_len_mean=round(p_mean, 4),
        pkt_len_var=round(p_var, 4),
        pkt_len_std=round(p_std, 4),
        pkt_len_median=round(p_med, 4),
        pkt_len_q25=round(p_q25, 4),
        pkt_len_q75=round(p_q75, 4),
        pkt_len_iqr=round(p_iqr, 4),
        iat_min=round(i_min, 6),
        iat_max=round(i_max, 6),
        iat_mean=round(i_mean, 6),
        iat_var=round(i_var, 6),
        iat_std=round(i_std, 6),
        burst_count=burst_count,
        burst_len_mean=round(b_len_mean, 4),
        burst_len_max=round(b_len_max, 4),
        burst_bytes_mean=round(b_bytes_mean, 4),
        flow_duration_s=round(duration, 4),
        total_packets=total_pkts,
        total_bytes=total_bytes,
        packet_rate_pps=round(pps, 4),
        byte_rate_bps=round(bps, 4),
        forward_packet_ratio=round(fwd_pkt_ratio, 4),
        forward_byte_ratio=round(fwd_byte_ratio, 4),
    )


class ESPFeatureExtractor:
    """
    High-performance PCAP parser for ESP traffic using dpkt.
    """

    def __init__(self, pcap_path: str | Path, include_all_ip: bool = False) -> None:
        self.pcap_path = Path(pcap_path)
        self.include_all_ip = include_all_ip

    def parse_esp_packets(self) -> list[RawESPPacket]:
        """Parse raw ESP packets from PCAP file."""
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        if dpkt is None:
            raise ImportError("dpkt is required for ESP packet extraction. Install with `pip install dpkt`.")

        packets: list[RawESPPacket] = []

        with open(self.pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(f)
                except Exception as exc:
                    log.error("Failed to open PCAP/PCAPNG with dpkt: %s", exc)
                    raise

            datalink = pcap.datalink() if hasattr(pcap, "datalink") and callable(pcap.datalink) else 1

            for ts, buf in pcap:
                try:
                    ip_layer = _extract_ip_layer(buf, datalink)
                    if ip_layer is None or not isinstance(ip_layer, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue

                    src_ip = ".".join(map(str, ip_layer.src)) if isinstance(ip_layer, dpkt.ip.IP) else str(ip_layer.src)
                    dst_ip = ".".join(map(str, ip_layer.dst)) if isinstance(ip_layer, dpkt.ip.IP) else str(ip_layer.dst)
                    wire_len = len(buf)

                    # 1. Native ESP (IP Protocol 50)
                    if ip_layer.p == IP_PROTO_ESP:
                        payload = bytes(ip_layer.data)
                        if len(payload) >= 8:
                            spi, seq = struct.unpack("!II", payload[:8])
                            packets.append(
                                RawESPPacket(
                                    timestamp=float(ts),
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    spi=spi,
                                    seq_num=seq,
                                    wire_length=wire_len,
                                    payload_length=len(payload),
                                    is_natt=False,
                                )
                            )

                    # 2. NAT-T Encapsulated ESP (UDP Port 4500)
                    elif ip_layer.p == IP_PROTO_UDP and isinstance(ip_layer.data, dpkt.udp.UDP):
                        udp_layer = ip_layer.data
                        if udp_layer.sport == UDP_PORT_NATT or udp_layer.dport == UDP_PORT_NATT:
                            udp_payload = bytes(udp_layer.data)
                            # Non-ESP marker for IKE is 4 zero bytes (0x00000000)
                            # If first 4 bytes are non-zero, it is ESP over UDP!
                            if len(udp_payload) >= 8:
                                first_4 = struct.unpack("!I", udp_payload[:4])[0]
                                if first_4 != 0:
                                    spi, seq = struct.unpack("!II", udp_payload[:8])
                                    packets.append(
                                        RawESPPacket(
                                            timestamp=float(ts),
                                            src_ip=src_ip,
                                            dst_ip=dst_ip,
                                            spi=spi,
                                            seq_num=seq,
                                            wire_length=wire_len,
                                            payload_length=len(udp_payload),
                                            is_natt=True,
                                        )
                                    )
                    # 3. Generic IP traffic (for external generalization benchmarking across heterogenous pcaps)
                    elif self.include_all_ip:
                        payload = bytes(ip_layer.data)
                        packets.append(
                            RawESPPacket(
                                timestamp=float(ts),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                spi=int(ip_layer.p),
                                seq_num=0,
                                wire_length=wire_len,
                                payload_length=len(payload),
                                is_natt=False,
                            )
                        )
                except Exception:
                    # Skip malformed packet
                    continue

        return packets

    def extract_flows(self) -> list[ESPFlow]:
        """Group parsed ESP packets into logical flows."""
        packets = self.parse_esp_packets()
        if not packets:
            return []

        # Group by endpoints and SPI
        flow_map: dict[str, list[RawESPPacket]] = defaultdict(list)
        for p in packets:
            # Pair endpoints alphabetically to group bidirectional flows
            endpoints = tuple(sorted([p.src_ip, p.dst_ip]))
            key = f"{endpoints[0]}_{endpoints[1]}_spi_0x{p.spi:08x}"
            flow_map[key].append(p)

        flows: list[ESPFlow] = []
        for idx, (k, pkts) in enumerate(flow_map.items()):
            pkts.sort(key=lambda x: x.timestamp)
            flows.append(
                ESPFlow(
                    flow_id=f"flow_{idx:04d}",
                    src_ip=pkts[0].src_ip,
                    dst_ip=pkts[0].dst_ip,
                    spi=pkts[0].spi,
                    packets=pkts,
                )
            )

        return flows

    def extract_all_flow_features(self) -> list[dict[str, Any]]:
        """
        Extract features for all flows in PCAP.
        Returns list of dictionaries ready for model consumption or JSON serialization.
        """
        flows = self.extract_flows()
        results: list[dict[str, Any]] = []

        for f in flows:
            features = extract_features_from_flow(f)
            results.append(
                {
                    "flow_id": f.flow_id,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "spi": f"0x{f.spi:08x}",
                    "packet_count": len(f.packets),
                    "duration_s": round(f.duration, 4),
                    "features": features.to_dict(),
                    "packet_trace": f.get_packet_trace(max_packets=64),
                }
            )

        return results
