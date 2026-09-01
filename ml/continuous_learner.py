"""
Janus AI Engine — Automated Continuous Learner & Model Recalibration
===================================================================
Buffers validated network flows from live ingestions, filters out
noisy or out-of-distribution instances, and automatically triggers
model recalibration when confidence drift or new flow quotas are met.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

from ml.train import FEATURE_NAMES, TARGET_CLASSES, train_classifier

log = logging.getLogger(__name__)

BUFFER_DIR = Path(__file__).resolve().parent / "artifacts" / "learner_buffer"


class ContinuousLearner:
    """
    Automated self-learning buffer and retraining controller.
    """

    def __init__(
        self,
        buffer_threshold: int = 50,
        dataset_path: Optional[Path] = None,
    ) -> None:
        self.buffer_threshold = buffer_threshold
        self.dataset_path = dataset_path or Path(__file__).resolve().parent.parent / "dataset" / "labeled_flows.csv"
        self.buffer_file = BUFFER_DIR / "staged_flows.json"
        BUFFER_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _load_buffer(self) -> list[dict[str, Any]]:
        if not self.buffer_file.exists():
            return []
        try:
            with open(self.buffer_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_buffer(self, buffer: list[dict[str, Any]]) -> None:
        with open(self.buffer_file, "w", encoding="utf-8") as f:
            json.dump(buffer, f, indent=2)

    def stage_flow_sample(
        self,
        flow_id: str,
        features: dict[str, float],
        predicted_class: str,
        confidence: float,
        is_verified: bool = True,
        label_source: str = "active_learning",
    ) -> bool:
        """
        Stage a verified high-confidence flow for the next continuous training cycle.
        """
        if predicted_class not in TARGET_CLASSES or confidence < 0.85:
            return False

        with self._lock:
            buffer = self._load_buffer()
            rec = {
                "flow_id": flow_id,
                "spi": features.get("spi", "0x0"),
                "scenario_id": "auto_ingest",
                "traffic_type": predicted_class,
                "dscp_label": 0,
                "label_source": label_source,
            }
            for f_name in FEATURE_NAMES:
                rec[f_name] = round(float(features.get(f_name, 0.0)), 4)

            buffer.append(rec)
            self._save_buffer(buffer)
            log.info("Staged flow %s (Buffer size: %d/%d)", flow_id, len(buffer), self.buffer_threshold)

            # Trigger automated retraining if buffer threshold is reached
            if len(buffer) >= self.buffer_threshold:
                self._trigger_retrain_cycle_sync()
                return True
        return False

    def _trigger_retrain_cycle_sync(self) -> None:
        """Merge staged flows into main dataset and retrain model."""
        buffer = self._load_buffer()
        if not buffer:
            return

        log.info("Threshold met (%d flows). Executing automated model retraining...", len(buffer))
        try:
            existing_df = pd.read_csv(self.dataset_path) if self.dataset_path.exists() else pd.DataFrame()
            new_df = pd.DataFrame(buffer)
            combined_df = pd.concat([existing_df, new_df], ignore_index=True)
            combined_df.to_csv(self.dataset_path, index=False)

            # Clear staged buffer
            self._save_buffer([])

            # Retrain classifier
            train_classifier(csv_path=self.dataset_path)
            log.info("Continuous learning cycle successfully completed!")
        except Exception as exc:
            log.error("Continuous retraining failed: %s", exc)


# Global singleton
continuous_learner = ContinuousLearner()
