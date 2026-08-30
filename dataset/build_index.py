#!/usr/bin/env python3
"""
Janus — Dataset Index Generator
================================
Scans the /dataset directory for labeled CSV files from all scenarios,
merges them into a single labeled_flows.csv with a consistent schema,
and produces a scenario_manifest.json index file.

Run after all scenario captures are complete:
    python dataset/build_index.py --dataset-dir /dataset

Output:
    /dataset/labeled_flows.csv        — merged labeled dataset
    /dataset/scenario_manifest.json   — index of all captured scenarios
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Expected columns in each per-scenario labeled CSV
REQUIRED_COLUMNS = [
    "flow_id",
    "spi",
    "scenario_id",
    "traffic_type",
    "dscp_label",
    "label_source",   # 'auto' (copy_dscp) or 'correlator' (fallback)
    # Feature columns (must match FlowFeatures dataclass in parsing/esp_features.py)
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_mean",
    "pkt_size_variance",
    "iat_min_ms",
    "iat_max_ms",
    "iat_mean_ms",
    "iat_variance_ms",
    "burst_size_min",
    "burst_size_max",
    "burst_size_mean",
    "burst_size_variance",
    "flow_duration_sec",
    "total_packets",
    "total_bytes",
    "directionality_ratio",
    "dscp_outer",
    "spi_value",
    "seq_num_min",
    "seq_num_max",
    "possible_iptfs",
]

# EXCLUDED from feature set (never include in labeled_flows.csv feature columns):
# - ip_src, ip_dst, src_port, dst_port
# Reason: These leak identity information and corrupt SHAP explanations.
# The compliance engine uses SPI and IKE metadata instead.


def load_scenario_csv(csv_path: Path, scenario_id: str) -> pd.DataFrame:
    """Load a per-scenario labeled CSV and validate its schema."""
    df = pd.read_csv(csv_path)

    # Inject scenario_id if missing (backward compat)
    if "scenario_id" not in df.columns:
        df["scenario_id"] = scenario_id

    # Check required columns
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        logger.warning(
            "Scenario %s CSV missing columns: %s — will fill with NaN",
            scenario_id,
            missing,
        )
        for col in missing:
            df[col] = float("nan")

    return df[REQUIRED_COLUMNS]


def load_scenario_metadata(scenario_dir: Path) -> dict:
    """Load metadata.json for a scenario if present."""
    meta_path = scenario_dir / "metadata.json"
    if meta_path.exists():
        with meta_path.open() as f:
            return json.load(f)
    return {"scenario_id": scenario_dir.name, "status": "unknown"}


def build_index(dataset_dir: Path) -> tuple[pd.DataFrame, dict]:
    """
    Walk dataset_dir for scenario subdirectories, merge all labeled CSVs.

    Returns:
        merged DataFrame, manifest dict
    """
    scenario_dirs = sorted(
        [d for d in dataset_dir.iterdir() if d.is_dir() and d.name.startswith("scenario_")]
    )

    if not scenario_dirs:
        logger.error("No scenario directories found in %s", dataset_dir)
        sys.exit(1)

    all_dfs: list[pd.DataFrame] = []
    manifest: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_scenarios": 0,
        "scenarios": [],
    }

    for scenario_dir in scenario_dirs:
        scenario_id = scenario_dir.name.replace("scenario_", "")
        csv_path = scenario_dir / "labeled_flows.csv"

        if not csv_path.exists():
            logger.warning("Scenario %s: no labeled_flows.csv found, skipping", scenario_id)
            continue

        logger.info("Loading scenario %s from %s", scenario_id, csv_path)
        df = load_scenario_csv(csv_path, scenario_id)
        all_dfs.append(df)

        meta = load_scenario_metadata(scenario_dir)
        meta["flow_count"] = len(df)
        meta["label_sources"] = df["label_source"].value_counts().to_dict()
        meta["traffic_type_distribution"] = df["traffic_type"].value_counts().to_dict()
        manifest["scenarios"].append(meta)

    if not all_dfs:
        logger.error("No labeled CSVs found in any scenario directory")
        sys.exit(1)

    merged = pd.concat(all_dfs, ignore_index=True)
    manifest["total_scenarios"] = len(all_dfs)
    manifest["total_flows"] = len(merged)
    manifest["traffic_type_distribution"] = merged["traffic_type"].value_counts().to_dict()
    manifest["label_source_distribution"] = merged["label_source"].value_counts().to_dict()

    logger.info(
        "Merged %d scenarios, %d total flows",
        len(all_dfs),
        len(merged),
    )
    return merged, manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Janus labeled dataset index")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("/dataset"),
        help="Path to the dataset directory (default: /dataset)",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Output CSV path (default: <dataset-dir>/labeled_flows.csv)",
    )
    parser.add_argument(
        "--output-manifest",
        type=Path,
        default=None,
        help="Output manifest JSON path (default: <dataset-dir>/scenario_manifest.json)",
    )
    args = parser.parse_args()

    dataset_dir = args.dataset_dir
    output_csv = args.output_csv or (dataset_dir / "labeled_flows.csv")
    output_manifest = args.output_manifest or (dataset_dir / "scenario_manifest.json")

    if not dataset_dir.exists():
        logger.error("Dataset directory does not exist: %s", dataset_dir)
        sys.exit(1)

    merged, manifest = build_index(dataset_dir)

    merged.to_csv(output_csv, index=False)
    logger.info("Wrote merged dataset to %s (%d rows)", output_csv, len(merged))

    with output_manifest.open("w") as f:
        json.dump(manifest, f, indent=2)
    logger.info("Wrote manifest to %s", output_manifest)


if __name__ == "__main__":
    main()
