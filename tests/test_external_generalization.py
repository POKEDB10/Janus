"""
Tests for Janus External Generalization & The 100% Defense (Tier 1.3)
====================================================================
Verifies that external public PCAPs are strictly loaded from dataset/public_pcaps/
(excluding samples/*), that all external out-of-domain flows are intercepted by
the Ledoit-Wolf Calibrator, and that in-domain OOD false positive rate is < 5%.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from ml.classify import FlowClassifier
from ml.eval_external_generalization import (
    REPORT_PATH,
    evaluate_external_public_pcaps,
    evaluate_indomain_holdout,
)


def test_samples_directory_strictly_excluded():
    """Verify that evaluate_external_public_pcaps never loads pcaps from samples/."""
    classifier = FlowClassifier()
    res = evaluate_external_public_pcaps(classifier)

    assert res["samples_excluded"] is True
    for evaluated_file in res["evaluated_pcaps"]:
        assert "samples" not in evaluated_file.lower()
        # Must be genuine public capture names
        assert any(
            prefix in evaluated_file
            for prefix in ["wireshark_http_sample", "wireshark_icmp_frags", "wireshark_ikev2_aes_gcm"]
        )


def test_external_pcap_ood_interception_rate():
    """Verify that 100% of out-of-domain public PCAP flows are intercepted as OOD."""
    classifier = FlowClassifier()
    res = evaluate_external_public_pcaps(classifier)

    assert res["total_external_flows"] >= 3
    assert res["total_ood_intercepted"] == res["total_external_flows"]
    assert res["ood_interception_rate"] >= 0.95
    assert res["raw_high_conf_hallucinations_prevented"] >= 1

    # Verify that each intercepted flow carries the OOD warning
    for f in res["flows"]:
        assert f["is_ood_intercepted"] is True
        assert f["mahalanobis_distance"] is not None
        assert f["mahalanobis_distance"] > f["distance_threshold"]


def test_indomain_ood_false_positive_rate():
    """Verify that in-domain flows have low OOD false positive rate (< 5%)."""
    classifier = FlowClassifier()
    res = evaluate_indomain_holdout(classifier, max_eval_flows=100)

    assert res["accuracy"] >= 0.95
    assert res["ood_false_positive_rate"] < 0.05
    assert res["in_domain_safety_confirmed"] is True


def test_external_generalization_report_artifact():
    """Verify that the benchmark report artifact exists and contains valid metrics."""
    assert REPORT_PATH.exists()
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["benchmark_name"] == "Janus External Generalization & The 100% Defense Benchmark"
    assert data["defense_verdict"]["in_domain_accuracy"] == 1.0
    assert data["defense_verdict"]["external_ood_interception_rate"] == 1.0
    assert data["external_public_corpus"]["samples_excluded"] is True


def test_external_flow_breakdown_transparency():
    """Verify that external flows distinguish genuine IPsec ESP from non-ESP controls with caveats."""
    classifier = FlowClassifier()
    res = evaluate_external_public_pcaps(classifier)

    summary = res["flow_breakdown_summary"]
    assert summary["genuine_ipsec_esp_count"] == 2
    assert summary["genuine_ipsec_esp_uncalibrated_payload_accuracy"] == 1.0
    assert summary["genuine_ipsec_esp_ood_intercepted"] == 2
    assert summary["non_esp_control_count"] == 3
    assert summary["non_esp_control_ood_intercepted"] == 3

    assert len(res["genuine_ipsec_esp_flows"]) == 2
    for esp_flow in res["genuine_ipsec_esp_flows"]:
        assert esp_flow["category"] == "genuine_ipsec_esp"
        assert esp_flow["raw_uncalibrated_prediction"] == "ICMP"
        assert esp_flow["is_ood_intercepted"] is True

    assert len(res["non_esp_control_flows"]) == 3
    for ctrl_flow in res["non_esp_control_flows"]:
        assert ctrl_flow["category"] == "non_esp_control"
        assert ctrl_flow["is_ood_intercepted"] is True

    assert len(res["methodological_caveats"]) == 3

