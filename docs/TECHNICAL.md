# Janus Technical Documentation
# IPsec VPN Protocol Analyzer — Architecture & Implementation Guide

## Table of Contents
1. [System Architecture](#system-architecture)
2. [Module Reference](#module-reference)
3. [Data Flow](#data-flow)
4. [Compliance Rule Engine](#compliance-rule-engine)
5. [ML Pipeline](#ml-pipeline)
6. [API Reference](#api-reference)
7. [Known Limitations & TODOs](#known-limitations)

---

## 1. System Architecture

Janus implements a 5-stage pipeline:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 1: Testbed & Dataset Generation                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ strongSwan   │  │ tc netem     │  │ iperf3 / tcpreplay /     │  │
│  │ Docker pairs │→ │ 100ms/±20ms/ │→ │ custom ICMP/HTTP/VoIP    │  │
│  │ (12 configs) │  │ 1% loss      │  │ traffic generators        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────────┘
                             │ PCAP files (inner + outer)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 2: Capture & Labeling                                         │
│  ┌──────────────────┐  ┌───────────────────────────────────────┐   │
│  │ tcpdump/tshark   │  │ DSCP Auto-label (copy_dscp=out)       │   │
│  │ parallel capture │  │ OR Fallback: Time-correlation (10ms   │   │
│  │ inner + outer    │  │ window matching inner→outer packets)   │   │
│  └──────────────────┘  └───────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Labeled PCAP + CSV
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 3: Parallel Analysis                                          │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐    │
│  │ IKE Parser (tshark JSON) │  │ ESP Feature Extractor (dpkt) │    │
│  │ • Exchange types         │  │ • Pkt size stats             │    │
│  │ • Algorithm proposals    │  │ • IAT stats                  │    │
│  │ • DH groups              │  │ • Burst distributions        │    │
│  │ • Auth methods           │  │ • Directionality ratio       │    │
│  │ • SA lifetimes           │  │ • Flow duration              │    │
│  └──────────────────────────┘  └──────────────────────────────┘    │
└──────────┬────────────────────────────┬────────────────────────────┘
           │ IKE params                 │ Flow features
           ▼                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 4: Compliance + ML                                            │
│  ┌────────────────────────────┐  ┌────────────────────────────┐    │
│  │ Deterministic Rule Engine  │  │ XGBoost Classifier         │    │
│  │ (RFC 8221, RFC 8247,       │  │ + SHAP TreeExplainer       │    │
│  │  NIST SP 800-77 Rev.1)     │  │ + Obfuscation Detection    │    │
│  │ → 0-100 risk score         │  │ → Traffic type + confidence│    │
│  │ → Per-finding risk tags    │  │ → Feature attribution      │    │
│  └────────────────────────────┘  └────────────────────────────┘    │
└──────────┬────────────────────────────┬────────────────────────────┘
           │ Compliance report          │ Classification results
           ▼                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 5: Dashboard + Reports                                        │
│  ┌──────────────────────┐  ┌──────────────────────────────────┐    │
│  │ React + Recharts     │  │ ReportLab PDF Reports            │    │
│  │ Interactive Dashboard │  │ • Executive summary (3-5 pages) │    │
│  │ • Compliance view    │  │ • Technical report (10-20 pages) │    │
│  │ • Flow classifier    │  │                                  │    │
│  │ • SHAP explanations  │  │                                  │    │
│  └──────────────────────┘  └──────────────────────────────────┘    │
│  FastAPI Backend (async)                                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Reference

### `parsing/ike_parser.py` — IKEParser
Wraps `tshark -T json` to parse IKE/ISAKMP handshakes. Uses tshark only for IKE (low volume, needs deep dissection). **Not** PyShark (memory leaks + TSharkCrashException under load).

**Key method:**
```python
IKEParser.parse_pcap(path: str) -> list[dict]
```

Returns parsed IKE sessions with: exchange_type, version, proposals (enc_alg, auth_alg, prf_alg, dh_group), spis, auth_method, fragmentation, sa_lifetime.

### `parsing/esp_features.py` — ESPFeatureExtractor
Uses **dpkt** (not Scapy, not PyShark) for high-performance ESP header/metadata extraction. This is the hot path — processes large PCAPs at high speed.

**Feature set** (per flow, grouped by SPI):
| Feature | Type | Description |
|---------|------|-------------|
| pkt_size_{min,max,mean,variance} | float | Packet size statistics |
| iat_{min,max,mean,variance}_ms | float | Inter-arrival time stats |
| burst_size_{min,max,mean,variance} | float | Consecutive same-direction packet counts |
| flow_duration_sec | float | First → last packet timespan |
| total_packets | int | Count of ESP packets in flow |
| total_bytes | int | Sum of ESP payload bytes |
| directionality_ratio | float | A→B packets / total packets |
| dscp_outer | int | DSCP from outer IP header |
| possible_iptfs | bool | IP-TFS/AGGFRAG obfuscation flag |

**Excluded** (by design): `ip_src`, `ip_dst`, `src_port`, `dst_port` — identity leaks + corrupt SHAP.

### `ml/train.py` — Training pipeline
- XGBoost `XGBClassifier` with 5-fold stratified CV
- Labels: VoIP, Video, Web, Email, ICMP, Obfuscated
- Saves: `ml/models/xgb_classifier.json`, `label_encoder.pkl`, `feature_columns.json`

### `ml/classify.py` — JanusClassifier
- Loads trained XGBoost model
- Per-flow: `classify_flow()` → `ClassificationResult`
- Per-flow: `explain_flow()` → `SHAPExplanation` (SHAP TreeExplainer, millisecond range)
- Global: `global_importance()` → feature_importances_ dict
- Obfuscation check runs **before** XGBoost — obfuscated flows skip ML classification

### `ml/obfuscation_detect.py` — IP-TFS Detection
Detects constant-rate, uniform-packet-size ESP (RFC 9347 IP-TFS signature):
- `packet_size_variance < 100` AND `iat_variance_ms < 5` → "Obfuscated / possible IP-TFS"
- Thresholds are heuristic — calibrate against real RFC 9347 captures

### `compliance/rules.py` — Rule Registry
Data-driven rule definitions (not hardcoded string matching). Uses enums and dataclasses.
**Source of truth:** Only RFC 8221, RFC 8247, NIST SP 800-77 Rev.1 — no invented clauses.

### `compliance/score.py` — ComplianceEngine
Deterministic scoring:
- Start: 100 points
- CRITICAL finding: -30 (max -60 total for multiple)
- HIGH: -15, MEDIUM: -8, LOW: -2
- Floor: 0
- Score interpretation: ≥90 SECURE, 70-89 ACCEPTABLE, 50-69 NEEDS_REVIEW, <50 INSECURE

---

## 3. Data Flow

### PCAP → Features → Classification
```
input.pcap
    │
    ├── [tshark] → IKE packets → IKEParser → ike_session_params.json
    │                                             │
    └── [dpkt]  → ESP packets → ESPFeatureExtractor → flow_features.csv
                                                          │
                                          ┌───────────────┴────────────────┐
                                          │                                 │
                                  ObfuscationDetect                  XGBClassifier
                                          │                                 │
                                   possible_iptfs=True?          classify() + SHAP
                                          │                                 │
                                   "Obfuscated/IP-TFS"           ClassificationResult
                                          │                                 │
                                          └───────────────┬────────────────┘
                                                          │
                                              ComplianceEngine.score()
                                                          │
                                              ComplianceReport (0-100)
                                                          │
                                              ReportGenerator → PDF
```

---

## 4. Compliance Rule Engine

The rule engine is **purely deterministic** — no ML. It evaluates extracted IKE/ESP parameters against the compliance table:

| Algorithm / Parameter | Standard | Status | Risk if violated |
|----------------------|----------|--------|-----------------|
| ENCR_AES_GCM_16 | RFC 8221 | MUST | (preferred) |
| ENCR_AES_CBC | RFC 8221 | MUST | Suboptimal (not AEAD) |
| ENCR_CHACHA20_POLY1305 | RFC 8221 | SHOULD | — |
| ENCR_3DES | RFC 8221 | SHOULD NOT | **HIGH** (SWEET32) |
| ENCR_BLOWFISH/RC5/IDEA | RFC 8221 | MUST NOT | **CRITICAL** |
| AUTH_HMAC_SHA2_256_128 | RFC 8221 | MUST | — |
| AUTH_HMAC_SHA1_96 | RFC 8221 | MUST- | **MEDIUM/HIGH** (deprecated) |
| AUTH_NONE w/o AEAD | RFC 8221 | MUST NOT | **CRITICAL** |
| AUTH_HMAC_MD5_96 | RFC 8221 | MUST NOT | **CRITICAL** |
| DH Group 14 (2048-MODP) | RFC 8247 | SHOULD+ | Acceptable baseline |
| DH Group 19 (256-ECP) | RFC 8247 | RECOMMENDED | — |
| DH Group 20 (384-ECP) | RFC 8247 | RECOMMENDED | — |
| DH Groups 1, 2, 5 | RFC 8247 | MUST NOT | **CRITICAL** (Logjam) |
| RSA key < 2048 bit | NIST 800-77 | — | **CRITICAL** |
| SA lifetime > 8h or < 1h | NIST 800-77 | — | **MEDIUM** |
| PFS disabled | NIST 800-77 | — | **HIGH** |

> **Important:** The rule engine evaluates ONLY parameters from the table above.
> No additional rules are implied or invented.

---

## 5. ML Pipeline

### Feature Selection Rationale
Excluded features: IP addresses, port numbers.
- **Why:** These are identity markers, not traffic-behavior signals. Including them would mean the model learns "this IP is always VoIP" rather than "this traffic pattern looks like VoIP." It also corrupts SHAP explanations — the most important feature would always be "src_ip" which tells us nothing about the underlying protocol.

### SHAP Explanations
- **TreeExplainer** (not KernelExplainer) — runs in millisecond range on shallow XGBoost
- Per-prediction: which features pushed this flow toward "VoIP" vs. the baseline?
- Global: `model.feature_importances_` — aggregate "what does this model generally rely on?"

### Obfuscation Detection (IP-TFS / RFC 9347)
IP-TFS pads and rate-shapes ESP to look like constant-bitrate traffic. Detection signature:
1. Low packet size variance (near-constant padding to fixed size)
2. Low inter-arrival time variance (constant send rate)
These flows are labeled "Obfuscated/IP-TFS" and skipped by the XGBoost classifier.

> **TODO(uncertain):** Thresholds (size_variance < 100, iat_variance < 5ms) are heuristic.
> Calibrate against real RFC 9347 IP-TFS captures before claiming confidence.

---

## 6. API Reference

The FastAPI backend auto-generates Swagger docs at `http://localhost:8000/docs`.

### Key Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/upload` | Upload .pcap/.pcapng file |
| GET | `/api/analysis/{id}/status` | Poll pipeline status |
| GET | `/api/analysis/{id}/results` | Full analysis results |
| GET | `/api/analysis/{id}/flows` | Paginated flow list |
| GET | `/api/analysis/{id}/flow/{fid}` | Single flow + SHAP |
| GET | `/api/compliance/{id}` | Compliance report |
| POST | `/api/compliance/check` | Ad-hoc compliance check |
| POST | `/api/report/{id}/generate` | Generate PDFs |
| GET | `/api/report/{id}/executive` | Download executive PDF |
| GET | `/api/report/{id}/technical` | Download technical PDF |

### Analysis Pipeline States
`INIT` → `PARSING` → `CLASSIFYING` → `SCORING` → `DONE` | `ERROR`

---

## 7. Known Limitations & TODOs

### Critical (must verify before demo)
- **DSCP propagation**: `copy_dscp = out` is known-flaky on some netns/kernel combos.
  Run `labeling/verify_dscp_propagation.py` FIRST. Fallback: `labeling/fallback_correlator.py`.
- **tshark field names**: Algorithm field names in tshark JSON vary by version.
  Review `compliance/rules.py::normalize_algorithm_name()` against actual tshark output.
- **IP-TFS thresholds**: Obfuscation detection thresholds are heuristic — calibrate.

### High Priority (before SIH demo)
- **Live capture**: Currently stubbed. Requires NET_ADMIN in backend container.
- **ML model training**: Model doesn't exist until dataset is generated and `ml/train.py` runs.
- **PKI for testbed**: Currently using PSK. Switch to certificate-based auth for realistic IKE captures.
- **PFS detection**: Verify that omitting dh_groups in swanctl child config actually disables PFS.

### Known Gaps
- Single-session state store (in-memory dict) — restarting backend loses all results.
- No authentication on any endpoint (single-user tool, but document clearly).
- ReportLab pie chart quality may need react-to-print fallback for demo.
- tcpreplay requires actual VoIP/video PCAPs in the testbed — these must be sourced separately.

### Architecture Decisions (deliberate)
| Decision | Rationale |
|----------|-----------|
| dpkt for ESP, tshark for IKE | dpkt: speed + low memory for hot path. tshark: deep IKE dissection for low-volume handshakes |
| No PyShark | Known memory leaks + TSharkCrashException under sustained load |
| No Scapy for bulk | 100x slower than dpkt, OOMs on large PCAPs |
| XGBoost not deep learning | Fast SHAP support (TreeExplainer, ms range); sufficient for flow-level features |
| Exclude IP/port from features | Prevents identity leakage; preserves SHAP interpretability |
| ReportLab not WeasyPrint | WeasyPrint CSS flex/grid rendering flaky; pagination bugs under time pressure |
| FastAPI not Streamlit | Matches SIH pitch deck; provides real API for judges to probe via Swagger |
