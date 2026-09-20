"""
Tests for Janus Sequence Model — FlowTraceNet (Tier 1.1)
========================================================
Validates raw packet sequence trace extraction, 1D-CNN forward pass,
FlowTraceClassifier inference, probability normalization, and ensemble soft voting.
"""

from __future__ import annotations

import numpy as np
import pytest

from ml.flow_trace_net import (
    MAX_PACKETS,
    NUM_CHANNELS,
    FlowTraceClassifier,
    build_flow_trace_model,
)
from ml.torch_utils import is_torch_available
from parsing.esp_features import ESPFlow, RawESPPacket


def test_esp_flow_get_packet_trace_empty():
    """Empty flow returns all zeros (3, 64) matrix."""
    flow = ESPFlow(flow_id="f_empty", src_ip="192.168.1.1", dst_ip="192.168.1.2", spi=0x12345678)
    trace = flow.get_packet_trace(max_packets=64)

    assert len(trace) == 3
    assert len(trace[0]) == 64
    assert len(trace[1]) == 64
    assert len(trace[2]) == 64
    assert all(v == 0.0 for row in trace for v in row)


def test_esp_flow_get_packet_trace_bidirectional():
    """Bidirectional packets correctly encode directionality, length, and log IAT."""
    packets = [
        RawESPPacket(
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            spi=0x1111,
            seq_num=1,
            wire_length=500,
            payload_length=450,
        ),
        RawESPPacket(
            timestamp=100.020,  # +20ms
            src_ip="10.0.0.2",  # Reverse direction
            dst_ip="10.0.0.1",
            spi=0x2222,
            seq_num=1,
            wire_length=1200,
            payload_length=1150,
        ),
        RawESPPacket(
            timestamp=100.050,  # +30ms
            src_ip="10.0.0.1",  # Forward direction
            dst_ip="10.0.0.2",
            spi=0x1111,
            seq_num=2,
            wire_length=600,
            payload_length=550,
        ),
    ]
    flow = ESPFlow(
        flow_id="f_bidi",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        spi=0x1111,
        packets=packets,
    )
    trace = flow.get_packet_trace(max_packets=64)

    # First packet: forward (+), len=450/1500=0.3, iat=0
    assert trace[0][0] > 0.0
    assert pytest.approx(trace[1][0], rel=1e-2) == 0.30
    assert trace[2][0] == 0.0

    # Second packet: reverse (-), len=1150/1500~0.767, iat ~ 20ms
    assert trace[0][1] < 0.0
    assert pytest.approx(trace[1][1], rel=1e-2) == (1150.0 / 1500.0)
    assert trace[2][1] > 0.0

    # Third packet: forward (+), len=550/1500~0.367, iat ~ 30ms
    assert trace[0][2] > 0.0
    assert trace[2][2] > 0.0

    # Padding after packet index 2 must be all zero
    for ch in range(3):
        assert all(trace[ch][idx] == 0.0 for idx in range(3, 64))


@pytest.mark.skipif(not is_torch_available(), reason="PyTorch not available")
def test_flow_trace_net_forward_pass():
    """FlowTraceNet forward pass accepts (B, 3, 64) tensor and returns valid logits."""
    import torch

    model = build_flow_trace_model()
    model.eval()

    dummy_input = torch.randn(4, NUM_CHANNELS, MAX_PACKETS)
    with torch.no_grad():
        output = model(dummy_input)

    assert output.shape == (4, 5)
    assert torch.isfinite(output).all()


def test_flow_trace_classifier_predict_proba():
    """FlowTraceClassifier accepts raw trace matrix and returns normalized probabilities."""
    clf = FlowTraceClassifier()
    dummy_trace = np.zeros((NUM_CHANNELS, MAX_PACKETS), dtype=np.float32)
    dummy_trace[0, :5] = [0.1, -0.2, 0.3, -0.4, 0.5]
    dummy_trace[1, :5] = [0.1, 0.2, 0.3, 0.4, 0.5]
    dummy_trace[2, :5] = [0.0, 2.5, 3.0, 2.1, 2.9]

    probs = clf.predict_proba(dummy_trace)
    assert probs.ndim == 1
    assert len(probs) == 5
    assert pytest.approx(float(np.sum(probs)), rel=1e-3) == 1.0
    assert all(0.0 <= p <= 1.0 for p in probs)


def test_flow_classifier_trace_ensemble_fusion():
    """FlowClassifier fuses tabular and sequence trace predictions seamlessly."""
    from ml.classify import FlowClassifier

    classifier = FlowClassifier()
    sample_features = {
        "pkt_len_min": 160.0,
        "pkt_len_max": 220.0,
        "pkt_len_mean": 180.0,
        "pkt_len_var": 30.0,
        "pkt_len_std": 5.47,
        "pkt_len_median": 180.0,
        "pkt_len_q25": 170.0,
        "pkt_len_q75": 190.0,
        "pkt_len_iqr": 20.0,
        "iat_min": 0.018,
        "iat_max": 0.022,
        "iat_mean": 0.020,
        "iat_var": 0.000004,
        "iat_std": 0.002,
        "burst_count": 15,
        "burst_len_mean": 4.0,
        "burst_len_max": 8.0,
        "burst_bytes_mean": 720.0,
        "flow_duration_s": 2.4,
        "total_packets": 120,
        "total_bytes": 21600,
        "packet_rate_pps": 50.0,
        "byte_rate_bps": 9000.0,
        "forward_packet_ratio": 0.5,
        "forward_byte_ratio": 0.5,
    }

    dummy_trace = [[0.12] * 64, [0.12] * 64, [3.0] * 64]

    # Test with packet_trace explicitly passed
    res_with_trace = classifier.classify_flow(sample_features, packet_trace=dummy_trace)
    assert res_with_trace.predicted_label in ["VoIP", "Video", "Web", "Email", "ICMP"]
    assert 0.0 <= res_with_trace.confidence <= 1.0

    # Test with packet_trace embedded in features
    sample_features["packet_trace"] = dummy_trace
    res_embedded = classifier.classify_flow(sample_features)
    assert res_embedded.predicted_label in ["VoIP", "Video", "Web", "Email", "ICMP"]

    # Test with NO trace (graceful degradation to tabular only)
    sample_features.pop("packet_trace", None)
    res_no_trace = classifier.classify_flow(sample_features, packet_trace=None)
    assert res_no_trace.predicted_label in ["VoIP", "Video", "Web", "Email", "ICMP"]
