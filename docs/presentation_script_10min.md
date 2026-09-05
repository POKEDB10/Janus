# 🎙️ Project Janus: Complete 10-Minute Presentation & Live Demo Script

**Smart India Hackathon 2026 | Problem Statement: SIH26160 (NTRO)**  
**Project:** Janus — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework  
**Team:** CipherOps | **Category:** Software / Cybersecurity  

---

## ⏱️ Master 10-Minute Timeline & Cue Sheet

| Time | Phase | Focus / Media | Key Action / Screen |
|---|---|---|---|
| **0:00 – 1:00** | **Slide 1 & Slide 2** | The Problem, The Hook & Core Philosophy | Title Slide → Solution Pipeline Overview |
| **1:00 – 2:30** | **Slide 2 & Slide 3** | Deep Tech: Data Collection & 12 Netem Profiles | Ground-Truth Lab, DSCP propagation, 10,000 flows |
| **2:30 – 4:00** | **Slide 3 & Slide 4** | The AI Engine: FlowDeepNet, SHAP & OOD Guardrail | 13.52 MB Ensemble, 25 dimensions, Anti-Hallucination |
| **4:00 – 5:30** | **LIVE DEMO Part 1** | Compliance Audit & Automated Remediation | Website (`/compliance/scenario_04`): Grade F, `swanctl.conf` |
| **5:30 – 7:00** | **LIVE DEMO Part 2** | AI Flow Analysis, Live SHAP & OOD in Action | Website (`/analysis`): Traffic pie, table, SHAP waterfall |
| **7:00 – 8:00** | **LIVE DEMO Part 3** | Side-by-Side Comparison & Dual PDF Reports | Website (`/compare` & `/report`): Radar chart, PDF exports |
| **8:00 – 9:00** | **Slide 5 & Slide 6** | Impact, Defense Viability & Research Grounding | NTRO deployment, RFC 8221/8247, ACM/NSF backing |
| **9:00 – 10:00**| **Closing & Q&A** | Summary Punchline & Judge Defense | Q&A readiness, handling the toughest questions |

---

## 🎬 Section 1: The Hook, The Problem & Core Architecture (0:00 – 1:00)

### 🖥️ Display: Slide 1 (Title) → Transition to Slide 2 (Solution Pipeline)
*(Speaker stands confidently, clicks to Slide 1, speaks clearly and measuredly)*

> **SPEAKER (0:00 – 0:35):**  
> *"Good morning, respected judges and technical evaluators. We are **Team CipherOps**, presenting our solution for Problem Statement **SIH26160 by NTRO**: **Project Janus — an AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**.*  
>  
> *Across national defense networks, intelligence communications, and enterprise backbones, IPsec is the foundational encryption protocol. But security auditors face a massive paradox:*  
> *1. **Handshakes are complex**: Tunnel configurations are buried inside multi-stage IKE exchanges, and legacy misconfigurations often slip past manual reviews unnoticed.*  
> *2. **Encrypted payloads are opaque**: Once the tunnel is established, deep packet inspection (DPI) is blind without decrypting traffic or possessing private keys.*  
> *3. **Most AI security tools hallucinate**: They claim to 'decrypt' traffic with black-box neural nets, which breaks cryptographic reality, or they guess classifications with false confidence."*

### 🖥️ Display: Slide 2 (Idea Title & Solution Pipeline)
*(Point to the 4-stage pipeline diagram)*

> **SPEAKER (0:35 – 1:00):**  
> *"Our core design philosophy in Janus is what we call **Honest & Grounded Engineering**:  
> - **We parse what is visible deterministically**: Evaluating IKE handshakes directly against formal standards like RFC 8221, RFC 8247, and NIST SP 800-77.  
> - **We infer only what is encrypted using statistical side-channels**: Classifying application traffic purely from packet dynamics without ever attempting decryption or leaking IP identities.  
> - **We refuse to guess**: Backed by a mathematical anti-hallucination guardrail that rejects out-of-distribution anomalies.  
>  
> Let’s look at how we built the data foundation for this system."*

---

## 🔬 Section 2: Data Collection, DSCP Tagging & The 10,000-Flow Dataset (1:00 – 2:30)

### 🖥️ Display: Slide 2 (Middle) → Slide 3 (Technical Approach)

> **SPEAKER (1:00 – 1:45):**  
> *"Every machine learning system lives or dies by its ground truth. One of the biggest obstacles in IPsec research is the **'No-Data Bottleneck'** — sensitive government and enterprise VPN traffic cannot be shared publicly.  
>  
> To solve this, we engineered an autonomous, containerized **Docker Testbed running strongSwan 5.7+ with VICI automation**. We didn’t just generate flat synthetic traffic; we built **12 distinct network impairment profiles using Linux kernel `tc netem`**:  
> - Emulating real WAN conditions: 5 to 80 millisecond delays, 2 to 15 millisecond jitter, packet loss from 0.1% to 2.5%, and MTU fragmentation down to 1280 bytes.  
> - Generating rich multi-modal application streams: G.711, G.729, and Opus VoIP codecs, adaptive bitrate video streams, HTTP/2 multiplexed web traffic, bulk email transfers with human think-time pauses, and periodic ICMP keepalives."*

> **SPEAKER (1:45 – 2:30):**  
> *"Now, how did we label encrypted ESP traffic without human bias?  
> We implemented a dual-labeling pipeline:  
> 1. **Kernel DSCP Outer Header Propagation (`copy_dscp = out`)**: Inside the testbed, application traffic was tagged with standard Differentiated Services Code Points (like `EF=46` for VoIP, `AF41=34` for Video). In Linux kernels 5.15+, strongSwan copies this tag to the outer, unencrypted IP header of the ESP packet, creating automated, hardware-level ground-truth labels.  
> 2. **Fallback Correlator**: For kernels that strip outer DSCP bits, we built an out-of-band timestamp-based flow correlator.  
> 3. **Real-World Wireshark Corpus**: We supplemented our 12 testbed profiles with legal, public captures from the Wireshark Wiki corpus (including real-world IKEv2 AES-GCM captures).  
>  
> The result is a balanced, curated master dataset of **10,000 labeled flows** — exactly 2,000 per class — establishing an open, reproducible research benchmark."*

---

## 🧠 Section 3: The AI Engine: FlowDeepNet, Live SHAP & Anti-Hallucination (2:30 – 4:00)

### 🖥️ Display: Slide 3 (AI/ML Stack) & Slide 4 (Challenges & Solutions)

> **SPEAKER (2:30 – 3:15):**  
> *"When looking at encrypted ESP packets, how do we classify them without inspecting payload data?  
>  
> **Privacy-by-Design**: Our high-throughput feature extractor extracts **25 statistical dimensions** across packet size distributions, inter-arrival times, burst dynamics, and directionality ratios. **We strictly discard IP addresses, MAC addresses, and port numbers.** This guarantees zero identity leakage and prevents the model from cheating by memorizing server IPs.  
>  
> To power inference, we deployed a **Dual-Engine Fusion Architecture**:  
> 1. **Regularized XGBoost Engine**: Optimized for sub-millisecond, real-time throughput.  
> 2. **FlowDeepNet (13.52 MB Deep Tabular Ensemble)**: Combining 1,000 Random Forest trees, 1,000 ExtraTrees, and a 4-layer Neural MLP (1024→512→256→128).  
> 3. Both models vote with 50/50 soft probability fusion, capturing subtle non-linear tabular interactions that simple models miss."*

> **SPEAKER (3:15 – 4:00):**  
> *"Now, in high-stakes defense environments, two critical questions arise:  
> **First: Why should an analyst trust the AI?**  
> We embedded live **SHAP TreeExplainer** into the pipeline. Every single flow prediction is mathematically decomposed into additive feature contributions in milliseconds. The analyst sees exactly which microsecond timing gap or packet length IQR pushed the model towards VoIP or Video.  
>  
> **Second: What if an attacker sends malformed packets or custom VPN tools?**  
> In standard ML, models hallucinate a high-confidence false label. Janus implements an **Anti-Hallucination Guardrail (`AntiHallucinationCalibrator`)**:  
> We map class centroids in $\mathbb{R}^{25}$ and compute the **Mahalanobis feature distance**. If incoming traffic lies outside our calibrated boundary (tuned to 45.0 to handle real-world network jitter), Janus explicitly flags the traffic as **'Uncertain / Out-of-Distribution'** and alerts the analyst instead of guessing.  
>  
> We also have an **RFC 9347 IP-TFS Detector** that recognizes constant-rate, uniform-size traffic shaping and immediately suppresses classification to prevent side-channel false positives.  
>  
> Let’s see this live in action on the platform."*

---

## 💻 Section 4: LIVE DEMO Part 1 — Compliance Engine & Auto-Remediation (4:00 – 5:30)

### 🖥️ Switch Screen to Browser: `http://localhost:5173/`
*(Presenter smoothly switches to the web browser. Show the dark-navy Janus Dashboard)*

> **SPEAKER (4:00 – 4:30):**  
> *"Here is the live **Janus Interactive Web Platform**, backed by our asynchronous FastAPI REST engine.  
>  
> On the home dashboard, you see the full 5-stage architecture and our 12 pre-profiled testbed scenarios spanning hardened government configurations down to legacy vulnerable tunnels.  
>  
> Let’s click into **Scenario 4: Legacy 3DES + MD5**."*

### 🖱️ Action: Click "Inspect" on Scenario 4 (Navigates to `/compliance/scenario_04`)
*(Point to the Radial Score Gauge and Critical Findings)*

> **SPEAKER (4:30 – 5:00):**  
> *"Notice the immediate verdict: **Score 25/100, Grade F — CRITICAL RISK**.  
>  
> Janus evaluated the handshake against **RFC 8221 (ESP), RFC 8247 (IKEv2), and NIST SP 800-77 Rev. 1**. It deterministically identified:  
> - **CVE-2016-2183 (SWEET32)**: 3DES uses 64-bit blocks vulnerable to birthday attack collisions after $2^{32}$ blocks.  
> - **Logjam Attack (CVE-2015-4000)**: Diffie-Hellman Group 2 (MODP-1024) is precomputable by nation-state actors.  
> - **MD5 Collision Attacks**: Weak HMAC integrity.  
> - **Excessive SA Lifetime**: 24-hour key lifetime without PFS."*

### 🖱️ Action: Scroll down to "Automated strongSwan Remediation Configuration" & Click "Copy"
*(Point to the generated `swanctl.conf` code snippet)*

> **SPEAKER (5:00 – 5:30):**  
> *"Most security scanners stop at telling you that you’re vulnerable. **Janus fixes it automatically.**  
>  
> Here, our automated remediation generator outputs a production-ready **strongSwan 5.7+ `swanctl.conf` configuration snippet**. It automatically upgrades the cipher to `aes256gcm16-ecp256!`, enables DH Group 19 (ECP-256), enforces 4-hour rekeying, and sets `copy_dscp = out`.  
>  
> An administrator can click **Copy**, paste it into their gateway, reload strongSwan with `swanctl --load-all`, and the tunnel is instantly hardened to NIST compliance.  
>  
> Furthermore, if an auditor needs natural language justification, clicking **'Explain Finding'** triggers our local **Compliance-RAG Engine**, retrieving primary clauses from RFC 8247 with **100% citation precision**."*

---

## 📊 Section 5: LIVE DEMO Part 2 — FlowDeepNet AI Classification & Live SHAP (5:30 – 7:00)

### 🖱️ Action: Click "Analysis" tab in the sub-nav (Navigates to `/analysis/scenario_01`)

> **SPEAKER (5:30 – 6:15):**  
> *"Now let’s navigate to the **AI Traffic Classifier & Side-Channel Analysis** view.  
>  
> Here, the encrypted flows from the capture have been extracted and processed by the FlowDeepNet ensemble.  
> - On the left, our **Class Distribution** shows the breakdown across VoIP, Video, Web, Email, and ICMP.  
> - In the center, our **Threat & Confidence Timeline** plots the real-time classification certainty across each sequential flow.  
> - In the table below, each ESP flow is mapped with its SPI (Security Parameter Index), packet count, duration, and classified traffic type."*

### 🖱️ Action: Click on the first flow (e.g. `flow_0001` or `flow_0002`)
*(Scroll down to the SHAP Local Feature Attribution section)*

> **SPEAKER (6:15 – 7:00):**  
> *(Point to the SHAP Waterfall Bar Chart)*  
> *"Look at this drawer below. When I select this flow, our embedded **SHAP TreeExplainer** renders an exact feature attribution waterfall chart:  
> - **Red bars** indicate statistical features that pushed the prediction toward the target class. Here, a low packet length IQR and steady inter-arrival times strongly indicated VoIP audio packets.  
> - **Blue bars** show features that penalized the score.  
>  
> If an adversary tries to run traffic obfuscation via RFC 9347 (IP-TFS), the status pill flags **'RFC 9347 IP-TFS Active'**, warning the analyst that packet timing is being artificially shaped.  
>  
> We can also click **'Export CSV'** at the top right to immediately download the raw flow predictions and SHAP values for offline forensic audit."*

---

## 📈 Section 6: LIVE DEMO Part 3 — Side-by-Side Comparison & Executive PDFs (7:00 – 8:00)

### 🖱️ Action: Click "Compare" in the top navbar (Navigates to `/compare`)

> **SPEAKER (7:00 – 7:35):**  
> *(Show Scenario 1 on Left vs. Scenario 4 on Right)*  
> *"In a multi-tunnel enterprise or defense node, auditors need to benchmark tunnels against each other.  
>  
> We built the **Scenario Comparison Tool**:  
> Here we have **Scenario 1 (Modern Hardened IKEv2, 98% Grade A)** placed directly alongside **Scenario 4 (Legacy 3DES, 25% Grade F)**.  
> - The interactive **Radar Chart** visualizes cryptographic strength across Encryption, Integrity, Key Exchange, SA Lifetime, and PFS.  
> - The parameter diff table highlights exactly where the failure occurs: AES-GCM vs 3DES-CBC, ECP-256 vs MODP-1024, PFS Enabled vs Disabled.  
> This allows decision-makers to conduct pre-deployment versus post-deployment audits in seconds."*

### 🖱️ Action: Click "Report" tab (Navigates to `/report/scenario_04`) & Click "Download Technical PDF"
*(Show the downloaded PDF on screen)*

> **SPEAKER (7:35 – 8:00):**  
> *"Finally, Janus bridges the communication gap between technical engineers and executive leadership:  
> - **Executive Briefing PDF**: A 1-to-2 page high-level briefing with overall risk posture, letter grades, and business impact for CISOs and directors.  
> - **Technical Security Assessment PDF**: A comprehensive, multi-page dossier featuring packet-level IKE dissections, MITRE ATT&CK threat mapping, and the exact `swanctl.conf` remediation block.  
> Both PDFs are compiled directly via ReportLab with verifiable digital integrity."*

---

## 🛡️ Section 7: Impact, Defense Relevance & Standards Grounding (8:00 – 9:00)

### 🖥️ Switch Screen back to PowerPoint: Slide 5 (Impact) & Slide 6 (Research References)

> **SPEAKER (8:00 – 8:40):**  
> *"Returning to the strategic impact of this solution:  
> For **NTRO and national security agencies**, Janus delivers 5 immediate breakthroughs:  
> 1. **Eliminates the Expert Bottleneck**: Replaces hours of tedious packet inspection by specialized cryptographers with an automated, 10-second passive audit.  
> 2. **Zero Operational Disruption**: Janus is 100% passive. It requires no endpoint agent, no tunnel downtime, and no access to private encryption keys.  
> 3. **Quantum-Vulnerability Readiness**: It explicitly flags classical Diffie-Hellman groups and RSA keys that will be immediately vulnerable to Shor’s algorithm on cryptanalytically relevant quantum computers.  
> 4. **Empirically Validated Test Suite**: 47 automated unit and integration tests executing in 10 seconds, proving complete pipeline determinism.  
> 5. **Open & Sovereign**: Built on open-source standards (Python, strongSwan, dpkt, FastAPI, React), removing dependency on expensive proprietary foreign appliances."*

> **SPEAKER (8:40 – 9:00):**  
> *(Point to Slide 6)*  
> *"Our methodology is grounded in academic literature published in **ACM Digital Library and NSF Research Repositories** on privacy-preserving encrypted traffic classification, alongside official IETF and NIST standards.  
> Janus turns raw, impenetrable packet captures into transparent, quantifiable, and remediable cybersecurity intelligence."*

---

## 🏆 Section 8: Closing Statement & Ready for Q&A (9:00 – 10:00)

> **SPEAKER (9:00 – 9:20):**  
> *"To conclude:  
> **Janus does not hallucinate. Janus does not break encryption keys. Janus empowers security analysts with deterministic standards compliance, explainable AI, and instant remediation.**  
>  
> The system is fully functional, thoroughly tested, container-ready, and available for live testing.  
>  
> Thank you, and we are now eager to take your questions."*

---

## 🎯 Emergency Q&A Defense Sheet (For Tough Judge Inquiries)

Have these concise answers ready if the judges challenge your methodology:

### Q1: "How do you know the ML model isn't just memorizing server IP addresses or ports?"
> **YOUR ANSWER:**  
> *"Our feature extraction pipeline in `parsing/esp_features.py` strictly filters out IP headers and UDP/TCP port numbers before vectorization. The feature vector consists entirely of 25 statistical dimensions: inter-arrival time moments (mean, variance, skewness, min/max), packet length IQR, burst ratios, and forward/reverse byte ratios. If you run the model against entirely different IP subnets, classification accuracy remains unchanged because the model evaluates traffic behavior, not network identifiers."*

### Q2: "Can you actually decrypt ESP packets? If not, how do you verify compliance?"
> **YOUR ANSWER:**  
> *"We do not decrypt ESP packets — in fact, claiming to decrypt live AES-256 without keys would be cryptographically impossible. Compliance is evaluated during the **IKEv2 handshake (RFC 7296)**, where cryptographic proposals, transform IDs, Diffie-Hellman groups, and SA lifetimes are negotiated in plain text. Once the tunnel is established, we use side-channel timing and sizing on the encrypted ESP stream solely to classify the traffic type (VoIP, Video, Web) and check for RFC 9347 IP-TFS traffic flow obfuscation."*

### Q3: "What happens if an adversary intentionally pads packets to fool your AI?"
> **YOUR ANSWER:**  
> *"That is precisely why we built the **RFC 9347 IP-TFS (Traffic Flow Security) Detector**. When traffic padding or constant-rate shaping is applied, packet size variance drops to near-zero and inter-arrival times become strictly periodic. Instead of naively outputting an incorrect classification, Janus identifies the signature of AGGFRAG shaping, labels the flow as 'Obfuscated / possible IP-TFS', and suppresses classification so analysts are not misled."*

### Q4: "Why use both XGBoost and FlowDeepNet? Isn't one model enough?"
> **YOUR ANSWER:**  
> *"They solve complementary engineering challenges: XGBoost operates with sub-millisecond latency and allows exact tree path decomposition via SHAP TreeExplainer for per-packet local explainability. FlowDeepNet is a 13.52 MB ensemble incorporating 2,000 trees across Random Forest and ExtraTrees with a 4-layer MLP that captures deeper multi-modal distributions across our 12 network impairment scenarios. Soft-voting them 50/50 achieves peak generalization while retaining millisecond explainability."*

### Q5: "How does your RAG explainer avoid hallucinating compliance rules?"
> **YOUR ANSWER:**  
> *"Our Compliance-RAG engine uses a strict 3-tier citation verification pipeline over 441 section chunks from 11 authoritative standards (RFC 8221, RFC 8247, NIST SP 800-77, STIG). If an LLM response cites a clause that does not exactly match an indexed standard section, our citation verifier rejects it. In empirical benchmarks across 34 held-out evaluation queries, our engine achieves **100% citation precision** and has a deterministic grounded fallback that operates even when local LLM daemons are offline."*
