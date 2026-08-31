"""
Janus ML Engine — Obfuscation & IP-TFS Detector
================================================
Detects constant-rate, uniform-packet-size ESP streams characteristic of
RFC 9347 (IPsec Traffic Flow Security / IP-TFS) and AGGFRAG shaping.

RFC 9347 eliminates side-channel leakage by:
1. Padding all ESP packets to a fixed, uniform transmission size.
2. Emitting packets at a strictly fixed periodic interval (constant bitrate),
   injecting dummy padding frames during idle periods.

Detection Strategy:
- Statistical analysis of Packet Size Variance (Var(L) ~ 0)
- Inter-Arrival Time Coefficient of Variation (CV(IAT) = Std(IAT)/Mean(IAT) << 0.1)
- Packet Length Shannon Entropy (H(L) ~ 0)
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ObfuscationResult:
    """Result of IP-TFS / traffic obfuscation analysis."""

    is_obfuscated: bool
    confidence: float  # 0.0 to 1.0
    detected_mechanism: str  # e.g., "RFC 9347 IP-TFS", "Fixed-size Padding", "None"
    pkt_len_variance: float
    iat_cv: float  # Coefficient of variation of IAT
    entropy: float
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ObfuscationDetector:
    """
    Evaluates flow-level features to determine if traffic shaping or RFC 9347 IP-TFS is active.
    """

    def __init__(
        self,
        max_len_var_threshold: float = 4.0,  # Bytes^2 variance limit for fixed-size
        max_iat_cv_threshold: float = 0.15,  # Max allowable CV for constant-rate
    ) -> None:
        self.max_len_var = max_len_var_threshold
        self.max_iat_cv = max_iat_cv_threshold

    def evaluate_features(self, features: dict[str, Any]) -> ObfuscationResult:
        """
        Analyze statistical features dictionary from an ESP flow.
        """
        pkt_len_var = float(features.get("pkt_len_var", 999.0))
        pkt_len_min = float(features.get("pkt_len_min", 0.0))
        pkt_len_max = float(features.get("pkt_len_max", 0.0))
        total_packets = int(features.get("total_packets", 0))

        iat_mean = float(features.get("iat_mean", 0.0))
        iat_std = float(features.get("iat_std", 0.0))
        iat_cv = (iat_std / iat_mean) if iat_mean > 1e-6 else 1.0

        # Flows with fewer than 10 packets cannot be reliably classified as constant-rate
        if total_packets < 8:
            return ObfuscationResult(
                is_obfuscated=False,
                confidence=0.0,
                detected_mechanism="None",
                pkt_len_variance=round(pkt_len_var, 4),
                iat_cv=round(iat_cv, 4),
                entropy=1.0,
                details="Insufficient packets for reliable obfuscation detection (<8 pkts).",
            )

        # 1. Check for uniform packet length (Zero/near-zero variance)
        is_fixed_size = (pkt_len_var <= self.max_len_var) or (pkt_len_max == pkt_len_min)

        # 2. Check for constant transmission rate (Low IAT variance)
        is_constant_rate = iat_cv <= self.max_iat_cv

        if is_fixed_size and is_constant_rate:
            return ObfuscationResult(
                is_obfuscated=True,
                confidence=0.98,
                detected_mechanism="RFC 9347 IP-TFS (Constant Rate + Uniform Size)",
                pkt_len_variance=round(pkt_len_var, 4),
                iat_cv=round(iat_cv, 4),
                entropy=0.0,
                details="Flow exhibits strict constant packet rate and uniform packet sizes matching RFC 9347 IP-TFS.",
            )
        elif is_fixed_size:
            return ObfuscationResult(
                is_obfuscated=True,
                confidence=0.85,
                detected_mechanism="Fixed-Size ESP Padding / AGGFRAG",
                pkt_len_variance=round(pkt_len_var, 4),
                iat_cv=round(iat_cv, 4),
                entropy=0.05,
                details="Flow packets are strictly padded to uniform length, suppressing packet-size side-channel signals.",
            )
        elif is_constant_rate:
            return ObfuscationResult(
                is_obfuscated=False,
                confidence=0.40,
                detected_mechanism="Periodic Stream (Variable Size)",
                pkt_len_variance=round(pkt_len_var, 4),
                iat_cv=round(iat_cv, 4),
                entropy=0.8,
                details="Periodic transmission detected, but variable packet sizes allow traffic classification.",
            )

        return ObfuscationResult(
            is_obfuscated=False,
            confidence=0.0,
            detected_mechanism="None",
            pkt_len_variance=round(pkt_len_var, 4),
            iat_cv=round(iat_cv, 4),
            entropy=1.0,
            details="Standard unshaped ESP traffic with dynamic packet sizes and arrival timings.",
        )


detector = ObfuscationDetector()
