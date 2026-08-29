"""
Janus Dataset Engine — Legal Public PCAP Downloader & Ingestor
==============================================================
Legally scrapes and downloads open-source research PCAPs from public
repositories (e.g. Wireshark Sample Captures, University / CTU datasets),
extracts ESP statistical flow features via dpkt, and integrates them
into the Janus training corpus with source provenance tracking.
"""

from __future__ import annotations

import argparse
import gzip
import logging
import shutil
import sys
import urllib.request
from pathlib import Path
from typing import Any, Optional

# Add project root to sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from ml.train import FEATURE_NAMES, TARGET_CLASSES
from parsing.esp_features import ESPFeatureExtractor

log = logging.getLogger(__name__)

PUBLIC_PCAP_SOURCES = [
    {
        "id": "wireshark_ikev2_aes_gcm",
        "name": "Wireshark Sample Captures — Site-to-Site IKEv2 AES-GCM",
        "url": "https://wiki.wireshark.org/uploads/c45aa4606b860d707db92e180c147001/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng",
        "expected_class": "Web",
        "description": "Site-to-site IKEv2 IPsec VPN with AES-256-GCM sample capture",
    },
    {
        "id": "wireshark_http_sample",
        "name": "Wireshark Sample Captures — HTTP Web Traffic",
        "url": "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap",
        "expected_class": "Web",
        "description": "Plain HTTP request and response cycle trace",
    },
    {
        "id": "wireshark_icmp_frags",
        "name": "Wireshark Sample Captures — IPv4 ICMP Fragments",
        "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ipv4frags.pcap",
        "expected_class": "ICMP",
        "description": "ICMP echo request/response packets with fragmentation",
    },
]

CORPUS_DIR = Path(__file__).resolve().parent / "public_pcaps"


class PublicPCAPIngestor:
    """
    Downloads and extracts statistical features from public research PCAPs.
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = output_dir or CORPUS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def download_source(self, source: dict[str, str], timeout_s: int = 15) -> Optional[Path]:
        """Download single public PCAP file with error handling."""
        pcap_path = self.output_dir / f"{source['id']}.pcap"
        if pcap_path.exists() and pcap_path.stat().st_size > 0:
            log.info("PCAP already cached locally: %s", pcap_path)
            return pcap_path

        log.info("Fetching public PCAP: %s from %s...", source["name"], source["url"])
        try:
            req = urllib.request.Request(
                source["url"],
                headers={"User-Agent": "Janus-Security-Research-Ingestor/1.0 (Academic/Hackathon Evaluation)"},
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as response, open(pcap_path, "wb") as f:
                f.write(response.read())
            log.info("Downloaded %d bytes to %s", pcap_path.stat().st_size, pcap_path)
            return pcap_path
        except Exception as exc:
            log.warning("Could not download %s: %s", source["url"], exc)
            return None

    def extract_features_from_pcap(self, pcap_path: Path, expected_class: str) -> list[dict[str, Any]]:
        """Extract 25D ESP/IP features from downloaded PCAP."""
        try:
            extractor = ESPFeatureExtractor(pcap_path)
            flows = extractor.extract_all_flow_features()
            records = []
            for idx, flow in enumerate(flows):
                feats = flow.get("features", {})
                rec = {
                    "flow_id": f"pub_{pcap_path.stem}_{idx:03d}",
                    "spi": flow.get("spi", "0x0"),
                    "scenario_id": "public_corpus",
                    "traffic_type": expected_class if expected_class in TARGET_CLASSES else "Web",
                    "dscp_label": 0,
                    "label_source": "public_corpus",
                }
                for f_name in FEATURE_NAMES:
                    rec[f_name] = round(float(feats.get(f_name, 0.0)), 4)
                records.append(rec)
            return records
        except Exception as exc:
            log.error("Failed to parse PCAP %s: %s", pcap_path, exc)
            return []

    def run_ingestion(self) -> int:
        """Execute full scrape and extraction workflow."""
        all_new_records = []
        for src in PUBLIC_PCAP_SOURCES:
            pcap_file = self.download_source(src)
            if pcap_file and pcap_file.exists():
                records = self.extract_features_from_pcap(pcap_file, src["expected_class"])
                all_new_records.extend(records)
                log.info("Extracted %d flow records from %s", len(records), pcap_file.name)

        if all_new_records:
            csv_path = Path(__file__).resolve().parent / "labeled_flows.csv"
            existing_df = pd.read_csv(csv_path) if csv_path.exists() else pd.DataFrame()
            new_df = pd.DataFrame(all_new_records)
            combined_df = pd.concat([existing_df, new_df], ignore_index=True)
            combined_df.to_csv(csv_path, index=False)
            log.info("Appended %d new public flows to %s (Total flows: %d)", len(new_df), csv_path, len(combined_df))
            return len(all_new_records)
        return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ingestor = PublicPCAPIngestor()
    ingestor.run_ingestion()
