# Janus — AI-Powered IPsec Protocol Analyzer & Security Assessment Framework

[![Tests](https://img.shields.io/badge/pytest-47%20passed-emerald)](STATUS.md)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SIH2026](https://img.shields.io/badge/SIH-2026-indigo)](https://www.sih.gov.in)
[![NTRO](https://img.shields.io/badge/Problem-SIH26160-red)](file:///c:/Users/soulp/Desktop/Projects/Janus/TECHNICAL.md)

**Team: Cipher Ops**  
**Smart India Hackathon 2026 | Problem Statement SIH26160 (NTRO)**

---

## 🎯 Executive Summary

**Project Janus** is an end-to-end autonomous protocol assessment framework designed to evaluate IPsec VPN security postures. It unites deterministic cryptographic compliance scoring against formal RFC standards with machine learning side-channel traffic classification and real-time SHAP explainability.

---

## 🏗️ 5-Stage Architecture

```
[1. Testbed & Generation] -> [2. Capture & Labeling] -> [3. Hybrid Dissection] -> [4. AI & Compliance] -> [5. Dashboard & Reports]
 strongSwan 5.7+ (VICI)       copy_dscp / TOS          dpkt ESP statistics       XGBoost + SHAP live      React + Recharts
 tc netem WAN shaping         Fallback Correlator      tshark JSON IKE parser    RFC 8221, RFC 8247       ReportLab PDF Exports
 12 Pre-built Scenarios       Zero-correlation label   Zero IP/Port vectors      NIST SP 800-77 Rev. 1    FastAPI REST Backend
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- Docker and Docker Compose (for live testbed simulation)

### 2. Backend API
```bash
# Install Python dependencies
pip install -r requirements.txt  # or: pip install fastapi uvicorn pydantic dpkt xgboost shap scikit-learn reportlab aiofiles

# Start FastAPI server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- Interactive OpenAPI Swagger UI: `http://localhost:8000/docs`

### 3. Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
- Interactive Web Dashboard: `http://localhost:5173`

### 4. Run Automated Test Suite
```bash
python -m pytest -v
```

---

## 📊 Feature Highlights

- **Zero-Hallucination Compliance Engine:** Scored against RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1 with exact CVE tags (SWEET32, Logjam, MD5 collisions).
- **Compliance-RAG Explainer:** Hybrid BM25 + Dense retrieval over 441 section chunks from 11 RFC/NIST/STIG standards with grounded, verifiable natural-language justifications.
- **Identity-Safe ML Classifier:** 25 statistical dimensions strictly excluding IP addresses and port numbers, evaluated by FlowDeepNet (13.52 MB ensemble) and fast XGBoost with live SHAP local attribution.
- **Anti-Hallucination & OOD Guardrail:** Mahalanobis distance rejection preventing ungrounded classification of anomalous or corrupted traffic.
- **RFC 9347 IP-TFS Obfuscation Detection:** Detects constant-rate, uniform-size packet streams and suppresses classification to avoid false positives.
- **Dual PDF Reporting:** Generates CISO Executive Briefings and Deep Technical Security Assessments with MITRE ATT&CK Threat Matrices and auto-generated strongSwan `swanctl.conf` remediation snippets.

---

## 📚 Documentation
- Detailed Technical Specification: [`TECHNICAL.md`](TECHNICAL.md)
- Complete Verification & Status Audit: [`STATUS.md`](STATUS.md)
