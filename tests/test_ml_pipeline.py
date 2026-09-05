"""
tests/test_ml_pipeline.py
=========================
Tests for the ML flow classifier, synthetic dataset generator, SHAP explainer,
and RFC 9347 IP-TFS obfuscation detector.
"""

import numpy as np
import pytest
from ml.classify import FlowClassifier, classifier
from ml.obfuscation_detect import ObfuscationDetector, detector
from ml.train import (
    FEATURE_NAMES,
    TARGET_CLASSES,
    generate_synthetic_dataset,
    train_classifier,
)


def test_synthetic_dataset_generation():
    """Verify synthetic dataset generator produces correct shape and label bounds."""
    X, y = generate_synthetic_dataset(num_samples_per_class=20)
    assert X.shape == (20 * len(TARGET_CLASSES), len(FEATURE_NAMES))
    assert len(y) == 20 * len(TARGET_CLASSES)
    assert set(np.unique(y)) == set(range(len(TARGET_CLASSES)))
    assert not np.isnan(X).any()


def test_train_and_inference():
    """Train classifier and evaluate inference on sample feature vectors."""
    model, metrics = train_classifier(save_artifacts=False)
    assert metrics["accuracy"] >= 0.70

    voip_features = {
        "pkt_len_min": 160.0,
        "pkt_len_max": 220.0,
        "pkt_len_mean": 180.0,
        "pkt_len_var": 25.0,
        "pkt_len_std": 5.0,
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
        "flow_duration_s": 5.0,
        "total_packets": 250,
        "total_bytes": 45000,
        "packet_rate_pps": 50.0,
        "byte_rate_bps": 9000.0,
        "forward_packet_ratio": 0.5,
        "forward_byte_ratio": 0.5,
    }

    res = classifier.classify_flow(voip_features)
    assert res.predicted_label in TARGET_CLASSES
    assert 0.0 <= res.confidence <= 1.0
    assert not res.is_obfuscated


def test_obfuscation_detector_iptfs():
    """Detect constant-rate uniform-size flow as RFC 9347 IP-TFS."""
    obf_features = {
        "pkt_len_min": 1420.0,
        "pkt_len_max": 1420.0,
        "pkt_len_mean": 1420.0,
        "pkt_len_var": 0.0,
        "iat_mean": 0.010,
        "iat_std": 0.0005,
        "total_packets": 200,
    }

    res = detector.evaluate_features(obf_features)
    assert res.is_obfuscated is True
    assert "RFC 9347" in res.detected_mechanism or "IP-TFS" in res.detected_mechanism


def test_obfuscation_suppresses_classification():
    """When obfuscation is detected, classifier must label as Obfuscated / possible IP-TFS."""
    obf_features = {
        "pkt_len_min": 1420.0,
        "pkt_len_max": 1420.0,
        "pkt_len_mean": 1420.0,
        "pkt_len_var": 0.0,
        "iat_mean": 0.010,
        "iat_std": 0.0005,
        "total_packets": 200,
        "flow_duration_s": 2.0,
    }

    res = classifier.classify_flow(obf_features)
    assert res.is_obfuscated is True
    assert "Obfuscated" in res.predicted_label


def test_anti_hallucination_ood_detection():
    """Verify extreme anomaly features trigger OOD detection rather than false confidence."""
    from ml.confidence_calibrator import AntiHallucinationCalibrator
    calibrator = AntiHallucinationCalibrator()
    X_ref, y_ref = generate_synthetic_dataset(num_samples_per_class=30)
    calibrator.fit_reference_distribution(X_ref, y_ref)

    # Extreme out-of-distribution vector
    extreme_ood = np.full((len(FEATURE_NAMES),), 999999.0, dtype=np.float32)
    fake_probs = np.array([0.90, 0.025, 0.025, 0.025, 0.025], dtype=np.float32)

    is_valid, conf, status = calibrator.evaluate_prediction(extreme_ood, 0, fake_probs)
    assert is_valid is False
    assert status == "OUT_OF_DISTRIBUTION_ANOMALY"


def test_continuous_learner_staging():
    """Verify continuous learner stages high-confidence flows correctly."""
    from ml.continuous_learner import ContinuousLearner
    learner = ContinuousLearner(buffer_threshold=1000) # High threshold to avoid auto-retrain during unit test
    staged = learner.stage_flow_sample(
        flow_id="test_flow_001",
        features={"pkt_len_mean": 180.0, "iat_mean": 0.020},
        predicted_class="VoIP",
        confidence=0.98,
        is_verified=True,
    )
    assert staged is False # Not triggered retrain because threshold is 1000, but staged into buffer
    staged_flows = learner._load_buffer()
    assert any(f.get("flow_id") == "test_flow_001" for f in staged_flows)

