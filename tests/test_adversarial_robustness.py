"""
Tests for Janus Adversarial Robustness & Evasion Defense (Tier 1.4)
==================================================================
Validates RFC 9347 IP-TFS padding perturbation, Obfuscation Detector TPR >= 98%,
and Mahalanobis OOD distance surge under active evasion attempts.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from ml.eval_adversarial_robustness import (
    ADVERSARIAL_METRICS_PATH,
    apply_iptfs_perturbation,
)
from ml.obfuscation_detect import detector


def test_apply_iptfs_perturbation_properties():
    """Verify that 100% IP-TFS padding collapses variance and standard deviation."""
    sample_flow = {
        "pkt_len_min": 60.0,
        "pkt_len_max": 1400.0,
        "pkt_len_mean": 650.0,
        "pkt_len_var": 45000.0,
        "pkt_len_std": 212.13,
        "iat_mean": 0.035,
        "iat_var": 0.0004,
        "iat_std": 0.02,
        "total_packets": 100,
    }

    # At 0% padding: features remain unchanged
    clean = apply_iptfs_perturbation(sample_flow, padding_ratio=0.0)
    assert clean["pkt_len_var"] == sample_flow["pkt_len_var"]

    # At 100% padding: variance collapses to 0 and mean reaches target MTU (1420)
    fully_padded = apply_iptfs_perturbation(sample_flow, padding_ratio=1.0, target_mtu=1420.0)
    assert fully_padded["pkt_len_var"] == 0.0
    assert fully_padded["pkt_len_std"] == 0.0
    assert fully_padded["pkt_len_mean"] == 1420.0
    assert fully_padded["pkt_len_min"] == 1420.0
    assert fully_padded["pkt_len_max"] == 1420.0


def test_obfuscation_detector_flags_full_iptfs():
    """Verify that detector catches fully shaped flow with high confidence."""
    shaped_features = {
        "pkt_len_min": 1420.0,
        "pkt_len_max": 1420.0,
        "pkt_len_mean": 1420.0,
        "pkt_len_var": 0.0,
        "pkt_len_std": 0.0,
        "iat_mean": 0.020,
        "iat_var": 0.000001,
        "iat_std": 0.001,
        "total_packets": 150,
    }
    res = detector.evaluate_features(shaped_features)

    assert res.is_obfuscated is True
    assert res.confidence >= 0.90
    assert "RFC 9347 IP-TFS" in res.detected_mechanism


def test_adversarial_metrics_artifact():
    """Verify that the adversarial metrics artifact exists and satisfies defense criteria."""
    assert ADVERSARIAL_METRICS_PATH.exists()
    with open(ADVERSARIAL_METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["benchmark_name"] == "Janus Adversarial RFC 9347 IP-TFS Robustness Evaluation"
    assert data["defense_verdict"]["evasion_detection_successful"] is True
    assert data["full_iptfs_obfuscation_tpr"] >= 0.98
    assert data["full_iptfs_mahalanobis_distance"] >= 40.0
