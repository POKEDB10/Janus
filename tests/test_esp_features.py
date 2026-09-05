"""
tests/test_esp_features.py
==========================
Tests for dpkt ESP flow extraction and statistical feature calculation.
Validates strict exclusion of IP addresses and ports from ML feature vectors.
"""

import pytest
from parsing.esp_features import (
    ESPFlow,
    ESPStatisticalFeatures,
    RawESPPacket,
    extract_features_from_flow,
)


def test_ip_port_strictly_excluded_from_features():
    """Verify that IP addresses and port numbers are NEVER in the feature vector."""
    features = ESPStatisticalFeatures(
        pkt_len_min=100.0,
        pkt_len_max=1400.0,
        pkt_len_mean=750.0,
        pkt_len_var=2500.0,
        pkt_len_std=50.0,
        pkt_len_median=750.0,
        pkt_len_q25=500.0,
        pkt_len_q75=1000.0,
        pkt_len_iqr=500.0,
        iat_min=0.001,
        iat_max=0.05,
        iat_mean=0.02,
        iat_var=0.0001,
        iat_std=0.01,
        burst_count=5,
        burst_len_mean=4.0,
        burst_len_max=8.0,
        burst_bytes_mean=3000.0,
        flow_duration_s=10.0,
        total_packets=50,
        total_bytes=37500,
        packet_rate_pps=5.0,
        byte_rate_bps=3750.0,
        forward_packet_ratio=0.5,
        forward_byte_ratio=0.5,
    )

    feat_dict = features.to_dict()
    forbidden_keys = {"src_ip", "dst_ip", "ip_src", "ip_dst", "src_port", "dst_port", "port_src", "port_dst", "ip", "port"}
    
    for key in feat_dict.keys():
        assert key.lower() not in forbidden_keys, f"Found forbidden identifier in feature dict: {key}"
        assert not ("ip" in key.lower() and "iqr" not in key.lower() and "iptfs" not in key.lower()), f"Suspicious IP field in feature dict: {key}"
        assert "port" not in key.lower(), f"Suspicious port field in feature dict: {key}"


def test_extract_features_from_mock_flow():
    """Test statistical aggregation over a sequence of ESP packets."""
    pkts = [
        RawESPPacket(timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", spi=0x1234, seq_num=1, wire_length=150, payload_length=120),
        RawESPPacket(timestamp=1.02, src_ip="10.0.0.1", dst_ip="10.0.0.2", spi=0x1234, seq_num=2, wire_length=150, payload_length=120),
        RawESPPacket(timestamp=1.04, src_ip="10.0.0.2", dst_ip="10.0.0.1", spi=0x1234, seq_num=3, wire_length=150, payload_length=120),
        RawESPPacket(timestamp=1.06, src_ip="10.0.0.2", dst_ip="10.0.0.1", spi=0x1234, seq_num=4, wire_length=150, payload_length=120),
    ]

    flow = ESPFlow(
        flow_id="test_flow_01",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        spi=0x1234,
        packets=pkts,
    )

    features = extract_features_from_flow(flow)

    assert features.total_packets == 4
    assert features.pkt_len_mean == 120.0
    assert features.pkt_len_var == 0.0
    assert features.iat_mean == pytest.approx(0.02, abs=1e-4)
    assert features.burst_count == 2
    assert features.forward_packet_ratio == 0.5
