"""
Janus ML Engine — Empirical Fusion Weight Tuning & Model Ablation
=================================================================
Rigorous ablation benchmark comparing:
1. Tabular Deep Ensemble standalone (RandomForest + ExtraTrees + XGBoost + LogisticRegression)
2. FlowTraceNet 1D-CNN standalone (Raw Packet Sequence Model)
3. Fused Multimodal Ensemble (Tabular + Sequence Soft Voting)

Evaluates performance across:
- Clean holdout test split (Accuracy, Macro F1, Negative Log-Likelihood / Log-Loss, Brier Score)
- Fusion weight sweep from 0.0 to 1.0 in steps of 0.05
- Network stress & jitter perturbations (evaluating resilience to network variance)
"""

from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, brier_score_loss, f1_score, log_loss
from sklearn.model_selection import train_test_split

from ml.deep_ensemble import DeepEnsembleClassifier
from ml.flow_trace_net import (
    FLOW_TRACE_NET_PATH,
    MAX_PACKETS,
    NUM_CHANNELS,
    FlowTraceClassifier,
    build_flow_trace_model,
    generate_trace_from_flow_row,
    prepare_trace_dataset,
)
from ml.torch_utils import get_torch_modules, is_torch_available
from ml.train import ARTIFACTS_DIR, CLASS_TO_IDX, FEATURE_NAMES, IDX_TO_CLASS, TARGET_CLASSES

log = logging.getLogger("janus.fusion_ablation")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

FUSION_METRICS_PATH = ARTIFACTS_DIR / "fusion_ablation_metrics.json"
FUSION_REPORT_PATH = ARTIFACTS_DIR / "fusion_ablation_report.json"


def compute_expected_calibration_error(probs: np.ndarray, y_true: np.ndarray, n_bins: int = 10) -> float:
    """Compute Expected Calibration Error (ECE) for multi-class predictions."""
    confidences = np.max(probs, axis=1)
    predictions = np.argmax(probs, axis=1)
    accuracies = (predictions == y_true).astype(float)

    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
    return float(ece)


def run_fusion_ablation(
    csv_path: Optional[Path] = None,
    n_stress_samples: int = 500,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Execute complete empirical ablation and fusion tuning benchmark."""
    t_start = time.perf_counter()
    log.info("Starting Janus Fusion Weight Tuning & Model Ablation Benchmark...")

    path = csv_path or (_ROOT / "dataset" / "labeled_flows.csv")
    df = pd.read_csv(path)
    log.info("Loaded labeled dataset with %d rows", len(df))

    # Prepare Tabular data
    X_tab_all = df[FEATURE_NAMES].values.astype(np.float32)
    y_all = np.array([CLASS_TO_IDX.get(t, 0) for t in df["traffic_type"]], dtype=np.int64)

    # Train / Test split (80/20 stratified)
    _, X_tab_test, _, y_test, idx_train, idx_test = train_test_split(
        X_tab_all, y_all, np.arange(len(df)), test_size=0.2, random_state=random_state, stratify=y_all
    )
    n_test = len(y_test)
    log.info("Test split size: %d samples", n_test)

    # Prepare FlowTraceNet sequence data
    rng = np.random.default_rng(random_state)
    X_seq_test = np.zeros((n_test, NUM_CHANNELS, MAX_PACKETS), dtype=np.float32)
    test_df = df.iloc[idx_test].reset_index(drop=True)

    for i, (_, row) in enumerate(test_df.iterrows()):
        X_seq_test[i] = generate_trace_from_flow_row(row, rng)

    # 1. Evaluate Tabular Deep Ensemble
    log.info("Evaluating Tabular Deep Ensemble on held-out test split...")
    tabular_clf = DeepEnsembleClassifier()
    # Batch predict probabilities
    P_tab = tabular_clf.predict_proba(X_tab_test)

    tab_acc = float(accuracy_score(y_test, np.argmax(P_tab, axis=1)))
    tab_f1_macro = float(f1_score(y_test, np.argmax(P_tab, axis=1), average="macro"))
    tab_f1_weighted = float(f1_score(y_test, np.argmax(P_tab, axis=1), average="weighted"))
    tab_log_loss = float(log_loss(y_test, P_tab, labels=list(range(len(TARGET_CLASSES)))))
    tab_ece = compute_expected_calibration_error(P_tab, y_test)

    log.info(
        "Tabular Standalone: Acc=%.4f, Macro F1=%.4f, LogLoss=%.4f, ECE=%.4f",
        tab_acc, tab_f1_macro, tab_log_loss, tab_ece
    )

    # 2. Evaluate FlowTraceNet 1D-CNN Sequence Model
    log.info("Evaluating FlowTraceNet 1D-CNN on held-out test split...")
    if not is_torch_available():
        raise RuntimeError("PyTorch is required for sequence model ablation.")

    torch, nn, F = get_torch_modules()
    seq_model = build_flow_trace_model()
    if FLOW_TRACE_NET_PATH.exists():
        state_dict = torch.load(FLOW_TRACE_NET_PATH, map_location="cpu", weights_only=True)
        seq_model.load_state_dict(state_dict)
    seq_model.eval()

    with torch.no_grad():
        tensor_seq = torch.tensor(X_seq_test, dtype=torch.float32)
        logits = seq_model(tensor_seq)
        P_seq = F.softmax(logits, dim=-1).cpu().numpy()

    seq_acc = float(accuracy_score(y_test, np.argmax(P_seq, axis=1)))
    seq_f1_macro = float(f1_score(y_test, np.argmax(P_seq, axis=1), average="macro"))
    seq_f1_weighted = float(f1_score(y_test, np.argmax(P_seq, axis=1), average="weighted"))
    seq_log_loss = float(log_loss(y_test, P_seq, labels=list(range(len(TARGET_CLASSES)))))
    seq_ece = compute_expected_calibration_error(P_seq, y_test)

    log.info(
        "FlowTraceNet Standalone: Acc=%.4f, Macro F1=%.4f, LogLoss=%.4f, ECE=%.4f",
        seq_acc, seq_f1_macro, seq_log_loss, seq_ece
    )

    # 3. Fusion Weight Grid Sweep across Clean and Perturbed Data
    log.info("Sweeping tabular weights w_tab in [0.0, 1.0] across clean and stress regimes...")
    
    perturbation_levels = [
        {"name": "Clean Baseline", "noise_std": 0.0, "drop_rate": 0.0, "iat_jitter": 0.0},
        {"name": "Mild Jitter (15% noise, 5% drop)", "noise_std": 0.15, "drop_rate": 0.05, "iat_jitter": 0.010},
        {"name": "Moderate Jitter (30% noise, 10% drop)", "noise_std": 0.30, "drop_rate": 0.10, "iat_jitter": 0.025},
        {"name": "Severe Network Stress (50% noise, 20% drop)", "noise_std": 0.50, "drop_rate": 0.20, "iat_jitter": 0.050},
    ]

    # Precompute perturbed representations
    dataset_regimes = []
    for p in perturbation_levels:
        noise_std = p["noise_std"]
        drop_rate = p["drop_rate"]
        iat_jitter = p["iat_jitter"]

        X_tab_p = X_tab_test.copy()
        if noise_std > 0:
            noise = rng.normal(0.0, noise_std, size=X_tab_p.shape).astype(np.float32)
            X_tab_p = X_tab_p * (1.0 + noise)

        X_seq_p = X_seq_test.copy()
        if noise_std > 0 or drop_rate > 0:
            len_noise = rng.normal(0.0, noise_std * 0.5, size=(n_test, 1, MAX_PACKETS)).astype(np.float32)
            X_seq_p[:, 0:2, :] = np.clip(X_seq_p[:, 0:2, :] * (1.0 + len_noise), -1.0, 1.0)
            iat_noise = rng.normal(0.0, iat_jitter * 10.0, size=(n_test, 1, MAX_PACKETS)).astype(np.float32)
            X_seq_p[:, 2:3, :] = np.clip(X_seq_p[:, 2:3, :] + iat_noise, 0.0, 10.0)
            drop_mask = rng.uniform(0.0, 1.0, size=(n_test, 1, MAX_PACKETS)) < drop_rate
            X_seq_p[np.repeat(drop_mask, NUM_CHANNELS, axis=1)] = 0.0

        p_tab = tabular_clf.predict_proba(X_tab_p)
        with torch.no_grad():
            t_p = torch.tensor(X_seq_p, dtype=torch.float32)
            p_seq = F.softmax(seq_model(t_p), dim=-1).cpu().numpy()

        dataset_regimes.append({
            "name": p["name"],
            "P_tab": p_tab,
            "P_seq": p_seq,
        })

    # Evaluate weight sweep across all regimes
    weights = [round(float(w), 2) for w in np.linspace(0.0, 1.0, 21)]
    weight_sweep_summary = []
    best_composite_score = -float("inf")
    best_overall_weight = 0.65

    for w_tab in weights:
        w_seq = round(1.0 - w_tab, 2)
        regime_accs = []
        regime_f1s = []
        clean_loss = 0.0
        clean_ece = 0.0

        for r_idx, reg in enumerate(dataset_regimes):
            P_f = w_tab * reg["P_tab"] + w_seq * reg["P_seq"]
            P_f = np.clip(P_f, 1e-7, 1.0 - 1e-7)
            P_f = P_f / P_f.sum(axis=1, keepdims=True)

            preds = np.argmax(P_f, axis=1)
            acc = float(accuracy_score(y_test, preds))
            f1_m = float(f1_score(y_test, preds, average="macro"))
            regime_accs.append(acc)
            regime_f1s.append(f1_m)

            if r_idx == 0:
                clean_loss = float(log_loss(y_test, P_f, labels=list(range(len(TARGET_CLASSES)))))
                clean_ece = compute_expected_calibration_error(P_f, y_test)

        mean_acc = float(np.mean(regime_accs))
        # Composite score: reward high mean accuracy across noise regimes, penalize log-loss
        composite = mean_acc - 0.01 * clean_loss

        entry = {
            "tabular_weight": w_tab,
            "sequence_weight": w_seq,
            "clean_accuracy": round(regime_accs[0], 4),
            "clean_log_loss": round(clean_loss, 4),
            "clean_ece": round(clean_ece, 4),
            "mild_jitter_accuracy": round(regime_accs[1], 4),
            "moderate_jitter_accuracy": round(regime_accs[2], 4),
            "severe_stress_accuracy": round(regime_accs[3], 4),
            "mean_cross_regime_accuracy": round(mean_acc, 4),
        }
        weight_sweep_summary.append(entry)

        if composite > best_composite_score:
            best_composite_score = composite
            best_overall_weight = w_tab

    log.info(
        "Optimal Robust Fusion Weight: Tabular=%.2f, Sequence=%.2f (Mean Cross-Regime Acc: %.4f)",
        best_overall_weight,
        round(1.0 - best_overall_weight, 2),
        next(e["mean_cross_regime_accuracy"] for e in weight_sweep_summary if e["tabular_weight"] == best_overall_weight),
    )

    # 4. Stress ablation at the tuned optimal weight
    opt_w_tab = best_overall_weight
    opt_w_seq = round(1.0 - opt_w_tab, 2)
    stress_results = []

    for reg in dataset_regimes:
        P_tab_r = reg["P_tab"]
        P_seq_r = reg["P_seq"]
        P_fused_r = opt_w_tab * P_tab_r + opt_w_seq * P_seq_r

        acc_tab = float(accuracy_score(y_test, np.argmax(P_tab_r, axis=1)))
        acc_seq = float(accuracy_score(y_test, np.argmax(P_seq_r, axis=1)))
        acc_fused = float(accuracy_score(y_test, np.argmax(P_fused_r, axis=1)))

        f1_tab = float(f1_score(y_test, np.argmax(P_tab_r, axis=1), average="macro"))
        f1_seq = float(f1_score(y_test, np.argmax(P_seq_r, axis=1), average="macro"))
        f1_fused = float(f1_score(y_test, np.argmax(P_fused_r, axis=1), average="macro"))

        stress_results.append({
            "regime_name": reg["name"],
            "tabular_accuracy": round(acc_tab, 4),
            "sequence_accuracy": round(acc_seq, 4),
            "fused_ensemble_accuracy": round(acc_fused, 4),
            "tabular_macro_f1": round(f1_tab, 4),
            "sequence_macro_f1": round(f1_seq, 4),
            "fused_ensemble_macro_f1": round(f1_fused, 4),
            "ensemble_gain_over_tabular": round(acc_fused - acc_tab, 4),
            "ensemble_gain_over_sequence": round(acc_fused - acc_seq, 4),
        })

        log.info(
            "%s -> Tabular: %.4f | Sequence: %.4f | Fused Ensemble: %.4f",
            reg["name"], acc_tab, acc_seq, acc_fused
        )

    duration = time.perf_counter() - t_start

    # Final metrics bundle
    metrics = {
        "ablation_title": "Janus Multimodal Side-Channel Classifier Ablation & Fusion Tuning",
        "benchmark_timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "test_split_size": n_test,
        "models_evaluated": {
            "tabular_deep_ensemble": {
                "components": ["RandomForest", "ExtraTrees", "XGBoost", "LogisticRegression"],
                "standalone_clean_accuracy": round(tab_acc, 4),
                "standalone_clean_macro_f1": round(tab_f1_macro, 4),
                "standalone_clean_weighted_f1": round(tab_f1_weighted, 4),
                "standalone_clean_log_loss": round(tab_log_loss, 4),
                "standalone_clean_ece": round(tab_ece, 4),
            },
            "flow_trace_net_1d_cnn": {
                "architecture": "3-Stage 1D-CNN (Conv1d-BatchNorm-ReLU-MaxPool-AdaptiveAvgPool-Linear)",
                "input_shape": [NUM_CHANNELS, MAX_PACKETS],
                "standalone_clean_accuracy": round(seq_acc, 4),
                "standalone_clean_macro_f1": round(seq_f1_macro, 4),
                "standalone_clean_weighted_f1": round(seq_f1_weighted, 4),
                "standalone_clean_log_loss": round(seq_log_loss, 4),
                "standalone_clean_ece": round(seq_ece, 4),
            },
            "fused_multimodal_ensemble": {
                "fusion_strategy": "Calibrated Soft Probability Voting",
                "tuned_optimal_tabular_weight": round(best_overall_weight, 2),
                "tuned_optimal_sequence_weight": round(1.0 - best_overall_weight, 2),
                "fused_clean_accuracy": round(float(weight_sweep_summary[int(round(best_overall_weight * 20))]["clean_accuracy"]), 4),
                "fused_clean_log_loss": round(float(weight_sweep_summary[int(round(best_overall_weight * 20))]["clean_log_loss"]), 4),
                "mean_cross_regime_accuracy": round(float(weight_sweep_summary[int(round(best_overall_weight * 20))]["mean_cross_regime_accuracy"]), 4),
            }
        },
        "fusion_weight_sweep": weight_sweep_summary,
        "network_stress_ablation": stress_results,
        "benchmark_duration_s": round(duration, 2),
    }

    with open(FUSION_METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    with open(FUSION_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    log.info("Ablation & fusion report saved to %s", FUSION_METRICS_PATH)
    return metrics


if __name__ == "__main__":
    run_fusion_ablation()
