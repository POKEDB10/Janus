"""
Janus AI Engine — High-Capacity Deep Tabular Ensemble (FlowDeepNet)
==================================================================
Combines a 4-layer Deep Tabular Neural Network (MLP 1024->512->256->128)
with a 2,500-estimator Deep Tree Forest (RandomForest, ExtraTrees, XGBoost)
to provide high-capacity, non-linear representation for encrypted flow telemetry.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    import xgboost as xgb
except ImportError:
    xgb = None

from ml.train import (
    ARTIFACTS_DIR,
    CLASS_TO_IDX,
    FEATURE_NAMES,
    IDX_TO_CLASS,
    TARGET_CLASSES,
)

log = logging.getLogger(__name__)

DEEP_ENSEMBLE_PATH = ARTIFACTS_DIR / "deep_ensemble.joblib"


def build_deep_tabular_ensemble() -> VotingClassifier:
    """Construct multi-stage deep tabular neural network + deep forest ensemble."""
    rf = RandomForestClassifier(
        n_estimators=1000,
        max_depth=20,
        min_samples_split=2,
        n_jobs=-1,
        random_state=42,
    )
    et = ExtraTreesClassifier(
        n_estimators=1000,
        max_depth=20,
        min_samples_split=2,
        n_jobs=-1,
        random_state=42,
    )
    mlp_pipe = Pipeline([
        ("scaler", StandardScaler()),
        (
            "mlp",
            MLPClassifier(
                hidden_layer_sizes=(1024, 512, 256, 128),
                activation="relu",
                solver="adam",
                alpha=1e-4,
                batch_size=64,
                learning_rate_init=1e-3,
                max_iter=250,
                early_stopping=True,
                n_iter_no_change=10,
                random_state=42,
            ),
        ),
    ])
    
    estimators = [
        ("rf", rf),
        ("et", et),
        ("mlp", mlp_pipe),
    ]
    weights = [1.0, 1.0, 1.5]

    if xgb is not None:
        xgb_clf = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=8,
            learning_rate=0.03,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=2,
            random_state=42,
        )
        estimators.append(("xgb", xgb_clf))
        weights.append(2.0)

    return VotingClassifier(
        estimators=estimators,
        voting="soft",
        weights=weights,
    )


def train_deep_ensemble(
    csv_path: Optional[Path] = None,
    save_path: Optional[Path] = None,
) -> Tuple[VotingClassifier, dict[str, Any]]:
    """Train high-capacity Deep Tabular Ensemble on labeled flow dataset."""
    path = csv_path or Path(__file__).resolve().parent.parent / "dataset" / "labeled_flows.csv"
    out_path = save_path or DEEP_ENSEMBLE_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)

    log.info("Loading flows from %s for Deep Ensemble training...", path)
    df = pd.read_csv(path)
    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = np.array([CLASS_TO_IDX.get(t, 0) for t in df["traffic_type"]], dtype=np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log.info("Training 2,500-Estimator Deep Forest & 4-Layer Deep Neural MLP on %d flows...", len(X_train))
    t0 = time.perf_counter()
    ensemble = build_deep_tabular_ensemble()
    ensemble.fit(X_train, y_train)
    t_train = time.perf_counter() - t0

    preds = ensemble.predict(X_test)
    probs = ensemble.predict_proba(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, average="weighted")

    # Serialize full uncompressed model artifact (~13.5MB - 35MB)
    joblib.dump(ensemble, out_path, compress=0)
    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    log.info("Deep Ensemble saved to %s (Size: %.2f MB) | Accuracy: %.4f, F1: %.4f in %.2fs", out_path, size_mb, acc, f1, t_train)

    metrics = {
        "model_name": "FlowDeepNet (2500-Estimator Deep Forest + 4-Layer Neural MLP)",
        "model_size_mb": round(size_mb, 2),
        "total_training_flows": len(X_train),
        "holdout_test_flows": len(X_test),
        "accuracy": round(float(acc), 4),
        "f1_score": round(float(f1), 4),
        "training_time_s": round(t_train, 2),
    }

    metrics_path = ARTIFACTS_DIR / "deep_ensemble_metrics.json"
    import json
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return ensemble, metrics


class DeepEnsembleClassifier:
    """Wrapper for fast inference with the high-capacity deep ensemble."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or DEEP_ENSEMBLE_PATH
        self.model: Optional[VotingClassifier] = None
        self._load()

    def _load(self) -> None:
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                log.info("Loaded Deep Tabular Ensemble (%.2f MB)", os.path.getsize(self.model_path) / (1024 * 1024))
            except Exception as exc:
                log.warning("Could not load deep ensemble: %s", exc)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            self._load()
        if self.model is not None:
            return self.model.predict_proba(X)
        # Fallback uniform
        return np.full((X.shape[0], len(TARGET_CLASSES)), 1.0 / len(TARGET_CLASSES))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    train_deep_ensemble()
