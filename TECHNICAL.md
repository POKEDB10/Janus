# Project Janus — Technical Architecture & Protocol Specification

**Smart India Hackathon 2026 | Problem Statement SIH26160 (NTRO)**  
**Team: Cipher Ops**  
**System:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

---

## 1. System Overview

**Janus** is an autonomous protocol assessment framework for IPsec VPNs. It resolves the fundamental tension in encrypted network inspection by decoupling security evaluation into two synergistic pipelines:

1. **Deterministic Cryptographic Handshake Assessment:** Dissects IKEv1/IKEv2 SA negotiation payloads against formal standards (RFC 8221, RFC 8247, NIST SP 800-77 Rev. 1).
2. **AI-Driven Side-Channel Traffic Classification:** Extracts 25 statistical dimensions from outer ESP streams (strictly excluding IP addresses and port numbers) to classify traffic classes (VoIP, Video, Web, Email, ICMP) and identify RFC 9347 IP-TFS traffic flow obfuscation.

```
                             ┌──────────────────────────────────────┐
                             │       PCAP / PCAPng Input            │
                             └──────────────────┬───────────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │                                                     │
         [UDP 500 / 4500 IKE Packets]                              [IP Protocol 50 ESP]
                     │                                                     │
                     ▼                                                     ▼
    ┌─────────────────────────────────┐                   ┌─────────────────────────────────┐
    │  tshark JSON Dissector          │                   │  dpkt High-Throughput Engine    │
    │  - SA Proposals & Transforms    │                   │  - 25 Statistical Dimensions    │
    │  - DH Group & Auth Validation   │                   │  - Directionality & Burst Stats │
    └────────────────┬────────────────┘                   └────────────────┬────────────────┘
                     │                                                     │
                     ▼                                                     ▼
    ┌─────────────────────────────────┐                   ┌─────────────────────────────────┐
    │  Deterministic Compliance Engine│                   │  AI Classifier & SHAP Engine    │
    │  - RFC 8221 (ESP Algorithms)    │                   │  - XGBoost 5-Class Classifier   │
    │  - RFC 8247 (IKEv2 Algorithms)  │                   │  - SHAP TreeExplainer Live      │
    │  - NIST SP 800-77 Rev. 1        │                   │  - RFC 9347 IP-TFS Detector     │
    │  - MITRE ATT&CK Mapping         │                   │                                 │
    └────────────────┬────────────────┘                   └────────────────┬────────────────┘
                     │                                                     │
                     └──────────────────────────┬──────────────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │  FastAPI Backend REST Services  │
                               │  - Progress Polling & Reports   │
                               │  - Executive & Technical PDFs   │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │  React + Recharts Dashboard     │
                               └─────────────────────────────────┘
```

---

## 2. Cryptographic Compliance Matrix

The deterministic compliance engine strictly evaluates configurations against the normative RFC specifications:

### ESP Encryption & Authentication (RFC 8221)
| Algorithm | Level | Category | Vulnerability / Security Implication |
|---|---|---|---|
| `ENCR_AES_GCM_16` | **MUST** | AEAD | Preferred modern AEAD cipher with built-in integrity. |
| `ENCR_AES_CBC` | **MUST** | Cipher | Legacy interoperability baseline; requires dedicated HMAC. |
| `ENCR_CHACHA20_POLY1305` | **SHOULD** | AEAD | High-performance AEAD for environments lacking AES-NI. |
| `ENCR_3DES` | **SHOULD NOT** | Cipher | Vulnerable to SWEET32 (64-bit block birthday collisions). |
| `ENCR_BLOWFISH / RC5 / IDEA / DES` | **MUST NOT** | Cipher | Cryptographically broken; flagged Critical. |
| `AUTH_HMAC_SHA2_256_128` | **MUST** | Auth | Modern baseline message authentication. |
| `AUTH_HMAC_SHA1_96` | **MUST-** | Auth | Deprecated due to SHA-1 theoretical collision risks. |
| `AUTH_NONE` | **MUST NOT** | Auth | Critical vulnerability unless explicitly paired with an AEAD cipher. |
| `AUTH_HMAC_MD5_96` | **MUST NOT** | Auth | Cryptographically broken MD5 collisions; flagged Critical. |

### IKEv2 Key Exchange & Forward Secrecy (RFC 8247 & NIST SP 800-77 Rev. 1)
| Parameter | Level | Guidance |
|---|---|---|
| `DH Group 19 (256-bit ECP)` | **RECOMMENDED** | NIST P-256 Elliptic Curve Diffie-Hellman. |
| `DH Group 20 (384-bit ECP)` | **RECOMMENDED** | NIST P-384 Elliptic Curve Diffie-Hellman. |
| `DH Group 14 (2048-bit MODP)` | **SHOULD+** | Minimum acceptable MODP baseline. |
| `DH Group 1, 2, 5 (<2048-bit)` | **MUST NOT** | Logjam precomputation vulnerability; flagged Critical. |
| `RSA Key Length < 2048-bit` | **CRITICAL** | Substandard public key length. |
| `SA Lifetime Window` | **RECOMMENDED** | Must be rotated within a 1h to 8h window. |
| `Perfect Forward Secrecy (PFS)` | **REQUIRED** | Flagged High risk if Phase 2 PFS is disabled. |

---

## 3. Statistical ML Feature Dimensions (Zero Identity Leakage)

To avoid leaking identity information and corrupting SHAP attributions, IP addresses and port numbers are strictly excluded from the feature set:

1. `pkt_len_min`: Minimum observed packet length (bytes)
2. `pkt_len_max`: Maximum observed packet length (bytes)
3. `pkt_len_mean`: Arithmetic mean of packet lengths
4. `pkt_len_var`: Variance of packet lengths
5. `pkt_len_std`: Standard deviation of packet lengths
6. `pkt_len_median`: 50th percentile of packet lengths
7. `pkt_len_q25`: 25th percentile (1st quartile)
8. `pkt_len_q75`: 75th percentile (3rd quartile)
9. `pkt_len_iqr`: Interquartile range ($Q_{75} - Q_{25}$)
10. `iat_min`: Minimum inter-arrival time between consecutive packets (seconds)
11. `iat_max`: Maximum inter-arrival time (seconds)
12. `iat_mean`: Mean inter-arrival time (seconds)
13. `iat_var`: Variance of inter-arrival times
14. `iat_std`: Standard deviation of inter-arrival times
15. `burst_count`: Total count of unidirectional packet bursts
16. `burst_len_mean`: Average number of packets per burst
17. `burst_len_max`: Maximum packets observed in a single burst
18. `burst_bytes_mean`: Mean byte volume per burst
19. `flow_duration_s`: Total flow duration from first to last packet
20. `total_packets`: Total packet count in the flow
21. `total_bytes`: Total byte volume in the flow
22. `packet_rate_pps`: Packet throughput ($Packets / Duration$)
23. `byte_rate_bps`: Byte throughput ($Bytes / Duration$)
24. `forward_packet_ratio`: Forward packets / Total packets
25. `forward_byte_ratio`: Forward bytes / Total bytes

---

## 4. Testbed Scenario Matrix

All 12 scenario configurations reside under `testbed/configs/scenario_01` through `scenario_12`:

- **Scenario 01:** Modern Hardened (AES-256-GCM + DH19 + PFS on + 1h rotation)
- **Scenario 02:** Standard Interop (AES-256-CBC + HMAC-SHA256 + DH14 + PFS on)
- **Scenario 03:** High Performance (ChaCha20-Poly1305 + DH19 + PFS on)
- **Scenario 04:** Critical Vulnerability (3DES-CBC + HMAC-MD5 + DH2 + PFS off)
- **Scenario 05:** Legacy Suboptimal (AES-128-CBC + HMAC-SHA1 + DH14)
- **Scenario 06:** High-Security Suite B (AES-256-GCM + DH20 + 3072-bit RSA)
- **Scenario 07:** Traffic Flow Security (AES-256-GCM + RFC 9347 IP-TFS)
- **Scenario 08:** Transport Mode Baseline (AES-256-GCM + Host-to-Host)
- **Scenario 09:** IPv6 Modern Tunnel (AES-256-GCM + Dual-Stack IPv6)
- **Scenario 10:** Insecure Lifetime (AES-256-GCM + 24h SA lifetime)
- **Scenario 11:** Deprecated Cipher (Blowfish-CBC + HMAC-SHA256 + DH14)
- **Scenario 12:** Missing Authentication (AES-128-CBC + AUTH_NONE)
