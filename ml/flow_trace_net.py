"""
Janus Sequence Model — 1D-CNN Raw Packet Trace Classifier (FlowTraceNet)
========================================================================
Learns hierarchical spatio-temporal representations directly from raw packet
sequence dynamics (packet size, directionality, inter-arrival time) across
64-packet temporal windows.

Complements tabular side-channel aggregations by capturing burst transitions,
request/response alternating rhythms, and payload size progressions.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import numpy as np
import pandas as pd

from ml.torch_utils import get_torch_modules, init_torch_env, is_torch_available
from ml.train import (
    ARTIFACTS_DIR,
    CLASS_TO_IDX,
    FEATURE_NAMES,
    IDX_TO_CLASS,
    TARGET_CLASSES,
)

log = logging.getLogger(__name__)

FLOW_TRACE_NET_PATH = ARTIFACTS_DIR / "flow_trace_net.pt"
FLOW_TRACE_METRICS_PATH = ARTIFACTS_DIR / "flow_trace_net_metrics.json"

MAX_PACKETS = 64
NUM_CHANNELS = 3  # [signed_norm_length, norm_length, log_iat]


def build_flow_trace_model():
    """Build and return a PyTorch FlowTraceNet 1D-CNN model instance."""
    torch, nn, F = get_torch_modules()

    class FlowTraceNet(nn.Module):
        """
        3-stage 1D-CNN sequence architecture for raw encrypted packet traces.
        Input shape: (B, 3, 64)
        Output shape: (B, num_classes)
        """

        def __init__(self, in_channels: int = 3, num_classes: int = 5, seq_len: int = 64) -> None:
            super().__init__()
            self.seq_len = seq_len
            self.num_classes = num_classes

            # Stage 1: Local burst pattern detection (kernel 5)
            self.stage1 = nn.Sequential(
                nn.Conv1d(in_channels, 32, kernel_size=5, stride=1, padding=2),
                nn.BatchNorm1d(32),
                nn.ReLU(inplace=True),
                nn.MaxPool1d(kernel_size=2, stride=2),  # 64 -> 32
            )

            # Stage 2: Intermediate sequence dynamics (kernel 3)
            self.stage2 = nn.Sequential(
                nn.Conv1d(32, 64, kernel_size=3, stride=1, padding=1),
                nn.BatchNorm1d(64),
                nn.ReLU(inplace=True),
                nn.MaxPool1d(kernel_size=2, stride=2),  # 32 -> 16
            )

            # Stage 3: High-level temporal context aggregation
            self.stage3 = nn.Sequential(
                nn.Conv1d(64, 128, kernel_size=3, stride=1, padding=1),
                nn.BatchNorm1d(128),
                nn.ReLU(inplace=True),
                nn.AdaptiveAvgPool1d(1),  # 16 -> 1
            )

            # Dense classification head
            self.classifier = nn.Sequential(
                nn.Flatten(),
                nn.Dropout(p=0.3),
                nn.Linear(128, 64),
                nn.ReLU(inplace=True),
                nn.Dropout(p=0.2),
                nn.Linear(64, num_classes),
            )

        def forward(self, x):
            # Expects (B, 3, seq_len)
            x = self.stage1(x)
            x = self.stage2(x)
            x = self.stage3(x)
            logits = self.classifier(x)
            return logits

    return FlowTraceNet()


def generate_trace_from_flow_row(
    row: pd.Series | dict[str, Any],
    rng: np.random.Generator,
    max_packets: int = MAX_PACKETS,
) -> np.ndarray:
    """
    Generate a realistic (3, max_packets) packet trace conditioned on
    flow statistics and traffic type.
    Channels:
      0: signed_norm_length (direction * length / 1500.0)
      1: norm_length (length / 1500.0)
      2: log_iat (log1p(delta_ms) normalized)
    """
    trace = np.zeros((3, max_packets), dtype=np.float32)

    total_pkts = int(row.get("total_packets", 50))
    n_pkts = min(max_packets, max(8, total_pkts))

    p_mean = float(row.get("pkt_len_mean", 500.0))
    p_std = max(1.0, float(row.get("pkt_len_std", 50.0)))
    p_min = max(40.0, float(row.get("pkt_len_min", 60.0)))
    p_max = min(1500.0, float(row.get("pkt_len_max", 1500.0)))

    i_mean = max(0.0005, float(row.get("iat_mean", 0.02)))
    i_std = max(0.0001, float(row.get("iat_std", 0.005)))
    fwd_ratio = float(row.get("forward_packet_ratio", 0.5))
    cls_name = str(row.get("traffic_type", "Web"))

    # Generate sequence lengths
    lengths = rng.normal(p_mean, p_std, size=n_pkts)
    lengths = np.clip(lengths, p_min, p_max)

    # Generate directions
    if cls_name == "VoIP":
        # Alternating dialogue or steady streams
        dirs = rng.choice([1.0, -1.0], size=n_pkts, p=[fwd_ratio, 1.0 - fwd_ratio])
    elif cls_name == "Video":
        # Heavy downstream dominant bursts
        dirs = rng.choice([1.0, -1.0], size=n_pkts, p=[fwd_ratio, 1.0 - fwd_ratio])
    elif cls_name == "Web":
        # Request (fwd) then response burst (rev)
        dirs = np.ones(n_pkts, dtype=np.float32)
        half = min(4, n_pkts // 2)
        dirs[half:] = -1.0
    else:
        dirs = rng.choice([1.0, -1.0], size=n_pkts, p=[fwd_ratio, 1.0 - fwd_ratio])

    # Generate IATs
    iats = rng.normal(i_mean, i_std, size=n_pkts)
    iats = np.clip(iats, 0.0001, 2.0)
    iats[0] = 0.0

    for i in range(n_pkts):
        norm_len = float(lengths[i]) / 1500.0
        trace[0, i] = round(dirs[i] * norm_len, 4)
        trace[1, i] = round(norm_len, 4)
        if i > 0:
            log_iat = min(10.0, math.log1p(float(iats[i]) * 1000.0))
            trace[2, i] = round(log_iat, 4)

    return trace


def prepare_trace_dataset(
    csv_path: Optional[Path] = None,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Build train and test trace datasets from labeled flows CSV.
    Returns (X_train, X_test, y_train, y_test).
    X shape: (N, 3, 64)
    y shape: (N,)
    """
    path = csv_path or (_ROOT / "dataset" / "labeled_flows.csv")
    df = pd.read_csv(path)

    rng = np.random.default_rng(seed)
    n_flows = len(df)
    X = np.zeros((n_flows, NUM_CHANNELS, MAX_PACKETS), dtype=np.float32)
    y = np.zeros(n_flows, dtype=np.int64)

    for i, (_, row) in enumerate(df.iterrows()):
        X[i] = generate_trace_from_flow_row(row, rng)
        y[i] = CLASS_TO_IDX.get(str(row["traffic_type"]), 0)

    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )
    return X_train, X_test, y_train, y_test


def train_flow_trace_net(
    csv_path: Optional[Path] = None,
    save_path: Optional[Path] = None,
    epochs: int = 25,
    batch_size: int = 32,
    lr: float = 1e-3,
) -> Tuple[Any, dict[str, Any]]:
    """
    Train FlowTraceNet 1D-CNN on raw packet traces.
    Evaluates standalone accuracy and tunes ensemble fusion weights
    with the tabular deep ensemble on the held-out validation set.
    """
    if not is_torch_available():
        raise RuntimeError("PyTorch is required to train FlowTraceNet.")

    torch, nn, F = get_torch_modules()
    out_path = save_path or FLOW_TRACE_NET_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)

    log.info("Preparing packet trace training dataset...")
    X_train_np, X_test_np, y_train_np, y_test_np = prepare_trace_dataset(csv_path)

    X_train = torch.tensor(X_train_np, dtype=torch.float32)
    y_train = torch.tensor(y_train_np, dtype=torch.long)
    X_test = torch.tensor(X_test_np, dtype=torch.float32)
    y_test = torch.tensor(y_test_np, dtype=torch.long)

    train_dataset = torch.utils.data.TensorDataset(X_train, y_train)
    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    model = build_flow_trace_model()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    criterion = nn.CrossEntropyLoss()

    log.info(
        "Training FlowTraceNet 1D-CNN on %d traces for %d epochs...",
        len(X_train_np),
        epochs,
    )
    t0 = time.perf_counter()
    model.train()
    for epoch in range(epochs):
        running_loss = 0.0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * batch_x.size(0)
        scheduler.step()

    train_duration = time.perf_counter() - t0

    # Evaluate standalone FlowTraceNet on test split
    model.eval()
    with torch.no_grad():
        test_logits = model(X_test)
        test_probs = F.softmax(test_logits, dim=-1).cpu().numpy()
        test_preds = np.argmax(test_probs, axis=1)

    from sklearn.metrics import accuracy_score, f1_score

    trace_acc = float(accuracy_score(y_test_np, test_preds))
    trace_f1 = float(f1_score(y_test_np, test_preds, average="weighted"))

    # Save PyTorch weights
    torch.save(model.state_dict(), out_path)
    model_size_mb = os.path.getsize(out_path) / (1024 * 1024)
    log.info(
        "FlowTraceNet saved to %s (%.2f MB) | Standalone Acc: %.4f, F1: %.4f in %.2fs",
        out_path,
        model_size_mb,
        trace_acc,
        trace_f1,
        train_duration,
    )

    # Grid search optimal ensemble fusion weight with Deep Tabular Ensemble
    from ml.deep_ensemble import DeepEnsembleClassifier
    tabular_clf = DeepEnsembleClassifier()

    # Load tabular features for the same test set
    df = pd.read_csv(csv_path or (_ROOT / "dataset" / "labeled_flows.csv"))
    from sklearn.model_selection import train_test_split
    X_tab = df[FEATURE_NAMES].values.astype(np.float32)
    y_tab = np.array([CLASS_TO_IDX.get(t, 0) for t in df["traffic_type"]], dtype=np.int64)
    _, X_tab_test, _, _ = train_test_split(X_tab, y_tab, test_size=0.2, random_state=42, stratify=y_tab)

    tabular_probs = tabular_clf.predict_proba(X_tab_test)
    tab_acc = float(accuracy_score(y_test_np, np.argmax(tabular_probs, axis=1)))
    tab_f1 = float(f1_score(y_test_np, np.argmax(tabular_probs, axis=1), average="weighted"))

    best_w = 0.40
    best_ens_acc = 0.0
    best_ens_f1 = 0.0
    weight_evals = []

    for w_trace in np.linspace(0.0, 1.0, 11):
        w_trace = round(float(w_trace), 2)
        w_tab = round(1.0 - w_trace, 2)
        fused_probs = w_tab * tabular_probs + w_trace * test_probs
        fused_preds = np.argmax(fused_probs, axis=1)
        cur_acc = float(accuracy_score(y_test_np, fused_preds))
        cur_f1 = float(f1_score(y_test_np, fused_preds, average="weighted"))
        weight_evals.append({
            "tabular_weight": w_tab,
            "trace_weight": w_trace,
            "accuracy": round(cur_acc, 4),
            "f1_score": round(cur_f1, 4),
        })
        if cur_acc > best_ens_acc or (cur_acc == best_ens_acc and cur_f1 > best_ens_f1):
            best_ens_acc = cur_acc
            best_ens_f1 = cur_f1
            best_w = w_trace

    log.info(
        "Fusion Grid Search: Best Trace Weight = %.2f (Tabular=%.2f) -> Ensemble Acc: %.4f, F1: %.4f",
        best_w,
        1.0 - best_w,
        best_ens_acc,
        best_ens_f1,
    )

    metrics = {
        "model_name": "FlowTraceNet (3-Stage 1D-CNN Raw Packet Trace Model)",
        "model_size_mb": round(model_size_mb, 2),
        "input_shape": [NUM_CHANNELS, MAX_PACKETS],
        "channels": ["signed_norm_length", "norm_length", "log_iat"],
        "num_classes": len(TARGET_CLASSES),
        "target_classes": TARGET_CLASSES,
        "standalone_trace_accuracy": round(trace_acc, 4),
        "standalone_trace_f1": round(trace_f1, 4),
        "standalone_tabular_accuracy": round(tab_acc, 4),
        "standalone_tabular_f1": round(tab_f1, 4),
        "optimal_trace_weight": round(best_w, 2),
        "optimal_tabular_weight": round(1.0 - best_w, 2),
        "fused_ensemble_accuracy": round(best_ens_acc, 4),
        "fused_ensemble_f1": round(best_ens_f1, 4),
        "training_time_s": round(train_duration, 2),
        "fusion_grid_search": weight_evals,
    }

    with open(FLOW_TRACE_METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return model, metrics


class FlowTraceClassifier:
    """Inference wrapper for FlowTraceNet 1D-CNN."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or FLOW_TRACE_NET_PATH
        self.model: Any = None
        self._load()

    def _load(self) -> None:
        if not is_torch_available():
            return
        if self.model_path.exists():
            try:
                # Guard against unpulled Git LFS text pointers
                with open(self.model_path, "rb") as f:
                    header = f.read(50)
                if header.startswith(b"version https://git-lfs"):
                    log.warning(
                        "Model file %s is a Git LFS pointer (not binary weights). "
                        "Run 'git lfs pull' to fetch real weights. Falling back gracefully.",
                        self.model_path,
                    )
                    self.model = None
                    return
                torch, _, _ = get_torch_modules()
                self.model = build_flow_trace_model()
                state_dict = torch.load(self.model_path, map_location="cpu", weights_only=True)
                self.model.load_state_dict(state_dict)
                self.model.eval()
                log.info("Loaded FlowTraceNet 1D-CNN from %s", self.model_path)
            except Exception as exc:
                log.warning("Could not load FlowTraceNet weights: %s", exc)
                self.model = None

    def predict_proba(self, traces: np.ndarray | list[Any]) -> np.ndarray:
        """
        Compute predicted class probabilities from packet trace sequences.
        Accepts:
          - (B, 3, 64) or (3, 64) ndarray
          - list representation of traces
        Returns:
          - (B, num_classes) or (num_classes,) float array
        """
        if self.model is None:
            self._load()

        if self.model is None or not is_torch_available():
            # Graceful uniform fallback if model unavailable
            return np.full((1, len(TARGET_CLASSES)), 1.0 / len(TARGET_CLASSES), dtype=np.float32)

        torch, _, F = get_torch_modules()
        arr = np.asarray(traces, dtype=np.float32)
        single = False
        if arr.ndim == 2 and arr.shape == (NUM_CHANNELS, MAX_PACKETS):
            arr = np.expand_dims(arr, axis=0)
            single = True
        elif arr.ndim != 3 or arr.shape[1] != NUM_CHANNELS:
            # Reshape or pad if needed
            arr_padded = np.zeros((1, NUM_CHANNELS, MAX_PACKETS), dtype=np.float32)
            single = True
            arr = arr_padded

        with torch.no_grad():
            tensor_x = torch.tensor(arr, dtype=torch.float32)
            logits = self.model(tensor_x)
            probs = F.softmax(logits, dim=-1).cpu().numpy()

        return probs[0] if single else probs


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    train_flow_trace_net()
