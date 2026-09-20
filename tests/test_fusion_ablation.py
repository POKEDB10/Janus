"""
tests/test_fusion_ablation.py
=============================
Tests verifying empirical model ablation and fusion weight tuning results:
1. Validates presence and structure of ml/artifacts/fusion_ablation_metrics.json
2. Asserts standalone metrics for both Tabular Deep Ensemble and FlowTraceNet 1D-CNN
3. Validates optimal fusion weight selection (0.70 Tabular / 0.30 Sequence)
4. Asserts resilience across network stress perturbation levels
"""

import json
from pathlib import Path
import pytest

from ml.eval_fusion_ablation import FUSION_METRICS_PATH, FUSION_REPORT_PATH


def test_fusion_metrics_file_exists():
    """Verify that fusion ablation metrics file exists and is populated."""
    assert FUSION_METRICS_PATH.exists(), f"Missing {FUSION_METRICS_PATH}"
    with open(FUSION_METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "models_evaluated" in data
    assert "tabular_deep_ensemble" in data["models_evaluated"]
    assert "flow_trace_net_1d_cnn" in data["models_evaluated"]
    assert "fused_multimodal_ensemble" in data["models_evaluated"]
    assert "fusion_weight_sweep" in data
    assert "network_stress_ablation" in data


def test_standalone_model_metrics():
    """Verify standalone metrics for both models are measured and documented."""
    with open(FUSION_METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    models = data["models_evaluated"]
    tab = models["tabular_deep_ensemble"]
    seq = models["flow_trace_net_1d_cnn"]
    fused = models["fused_multimodal_ensemble"]

    # Standalone tabular metrics
    assert "standalone_clean_accuracy" in tab
    assert tab["standalone_clean_accuracy"] >= 0.95
    assert tab["standalone_clean_macro_f1"] >= 0.95
    assert "standalone_clean_log_loss" in tab

    # Standalone sequence metrics
    assert "standalone_clean_accuracy" in seq
    assert seq["standalone_clean_accuracy"] >= 0.95
    assert seq["standalone_clean_macro_f1"] >= 0.95
    assert "standalone_clean_log_loss" in seq

    # Tuned optimal weights
    assert fused["tuned_optimal_tabular_weight"] == 0.70
    assert fused["tuned_optimal_sequence_weight"] == 0.30
    assert fused["fused_clean_accuracy"] >= 0.99


def test_stress_ablation_robustness():
    """Verify that the fused ensemble retains high accuracy under network variance."""
    with open(FUSION_METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    stress = data["network_stress_ablation"]
    assert len(stress) >= 4

    # Baseline regime
    clean = stress[0]
    assert clean["fused_ensemble_accuracy"] == 1.0

    # Severe stress regime: fused ensemble should meet or beat tabular accuracy
    severe = stress[3]
    assert severe["fused_ensemble_accuracy"] >= severe["tabular_accuracy"]
    assert severe["fused_ensemble_accuracy"] > severe["sequence_accuracy"]
