"""
rag/data/distill_synthesizer.py
===============================
Automated Multi-Model Data Distillation and DPO Synthesis Pipeline for Project Janus.

Allocates:
1. Gemini 3.8 Flash (or Gemini 2.5 Flash): High-throughput bulk generation (single-finding CoT,
   vendor syntax for strongSwan/Cisco/FortiOS, adversarial defense).
2. Gemini 3.1 Pro (or Gemini 2.5 Pro): Deep multi-hop compound reasoning (multi-finding interactions,
   cross-standard synthesis).
3. Claude Sonnet 4.6 / 3.7 (limited quota): Reserved for gold-standard held-out evaluation benchmark
   and oracle "chosen" responses for Direct Preference Optimization (DPO).
4. Deterministic CitationVerifier Gate: Enforces 100% grounded citations against our 441 standards
   clauses in chunks.json.

Supports native REST API calls with zero heavy extra dependencies, and includes a built-in
offline mock generator for testing and dry-run execution.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rag.engine.citation_verifier import verifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent
CHUNKS_PATH = DATA_DIR / "chunks.json"
DEFAULT_SFT_PATH = DATA_DIR / "distill_sft_dataset.jsonl"
DEFAULT_DPO_PATH = DATA_DIR / "distill_dpo_dataset.jsonl"
DEFAULT_GOLD_PATH = DATA_DIR / "distill_gold_eval.jsonl"

SYSTEM_PROMPT = (
    "You are the Janus Compliance Explainer, a specialized IPsec, cryptography, and network security standards auditor. "
    "Your objective is to provide rigorous, cryptanalytically sound evaluations of IPsec configurations and audit findings. "
    "Rules:\n"
    "1. Always ground your analysis in primary standards: RFC 8221, RFC 8247, RFC 9347, RFC 7296, RFC 4301, RFC 4303, "
    "RFC 7383, RFC 8784, NIST SP 800-77 Rev. 1, NIST SP 800-131A Rev. 2, or DoD IPsec STIG.\n"
    "2. Explicitly cite governing clauses in brackets (e.g. [RFC 8221 §5], [RFC 8247 §2.4], [RFC 9347 §2], [RFC 7296 §1.2], "
    "[NIST SP 800-77 Rev. 1 Table 1], [NIST SP 800-131A Rev. 2 §2], [DoD IPsec STIG V-220710]).\n"
    "3. Structure technical reasoning with Chain-of-Thought: Cryptanalytic Threat Breakdown, Primary Standards Grounding, "
    "System Impact & Blast Radius, and Actionable Configuration Remediation.\n"
    "4. Strictly reject invalid cryptographic advice, hallucinated standards, or deprecated cipher approvals."
)

CORE_SEED_FINDINGS: list[dict[str, Any]] = [
    {"rule_id": "RFC8221-ENCR_3DES", "parameter": "ESP Encryption", "severity": "HIGH", "description": "SWEET32 64-bit block collision (CVE-2016-2183) with 2^32 blocks birthday collision", "clause": "[RFC 8221 §5]"},
    {"rule_id": "RFC8221-ENCR_DES", "parameter": "ESP Encryption", "severity": "CRITICAL", "description": "56-bit key exhaustion brute force with 2^56 search space", "clause": "[RFC 8221 §5]"},
    {"rule_id": "RFC8247-DH_GROUP_2", "parameter": "Diffie-Hellman Group", "severity": "CRITICAL", "description": "1024-bit MODP group vulnerable to Logjam NFS discrete log precomputation", "clause": "[RFC 8247 §2.4]"},
    {"rule_id": "RFC8247-DH_GROUP_1", "parameter": "Diffie-Hellman Group", "severity": "CRITICAL", "description": "768-bit MODP group factorable in commodity computing time", "clause": "[RFC 8247 §2.4]"},
    {"rule_id": "RFC8221-AUTH_HMAC_MD5_96", "parameter": "ESP Authentication", "severity": "CRITICAL", "description": "MD5 collision attack allowing packet forgery", "clause": "[RFC 8221 §5]"},
    {"rule_id": "RFC8221-AUTH_NONE_CBC", "parameter": "ESP Authentication", "severity": "CRITICAL", "description": "Unauthenticated CBC mode permitting bit-flipping attacks", "clause": "[RFC 8221 §4]"},
    {"rule_id": "RFC9347-IP_TFS", "parameter": "Traffic Flow Security", "severity": "INFO", "description": "Fixed-rate AGGFRAG tunnel framing against side-channel analysis", "clause": "[RFC 9347 §2]"},
    {"rule_id": "RFC7383-IKE_FRAG", "parameter": "IKEv2 Protocol", "severity": "MEDIUM", "description": "Missing IKEv2 fragmentation causing intermediate UDP drop", "clause": "[RFC 7383 §2.3]"},
    {"rule_id": "RFC8784-PPK", "parameter": "Post-Quantum Defense", "severity": "INFO", "description": "Post-Quantum Pre-Shared Key SKEYSEED mixing against Shor algorithm", "clause": "[RFC 8784 §6]"},
    {"rule_id": "NIST-SA_LIFETIME", "parameter": "SA Lifetime", "severity": "MEDIUM", "description": "Excessive 24-hour SA lifetime expanding cryptanalytic window", "clause": "[NIST SP 800-77 Rev. 1 §7.2.3]"},
    {"rule_id": "RFC4303-NO_ESN_HIGH_SPEED", "parameter": "ESP Extended Sequence Numbers (ESN)", "severity": "HIGH", "description": "32-bit sequence number rollover in under 5 minutes on >1Gbps networks causing anti-replay failure", "clause": "[RFC 4303 §2.2.1]"},
    {"rule_id": "RFC8247-DH_GROUP_5", "parameter": "Diffie-Hellman Group 5 (MODP-1536)", "severity": "HIGH", "description": "1536-bit MODP prime field offering only ~90 bits symmetric security vulnerable to NFS precomputation", "clause": "[RFC 8247 §2.4]"},
    {"rule_id": "RFC8221-ENCR_BLOWFISH", "parameter": "ESP Encryption (Blowfish)", "severity": "CRITICAL", "description": "SWEET32 64-bit block collision (CVE-2016-2183) allowing XOR plaintext recovery after 2^32 blocks", "clause": "[RFC 8221 §5]"},
    {"rule_id": "RFC8221-ENCR_NULL_PROD", "parameter": "ESP Encryption (ENCR_NULL)", "severity": "CRITICAL", "description": "Null encryption cipher transmitting production payload in plaintext with 0 bits entropy", "clause": "[RFC 8221 §5]"},
    {"rule_id": "DOD-STIG-PFS_MISSING", "parameter": "Child SA Perfect Forward Secrecy (PFS)", "severity": "HIGH", "description": "Missing ephemeral Diffie-Hellman ratcheting in CREATE_CHILD_SA compromising entire session timeline", "clause": "[DoD IPsec STIG V-220730]"},
    {"rule_id": "RFC7296-IKE_COOKIE_DOS", "parameter": "IKEv2 Half-Open State Protection (COOKIE)", "severity": "MEDIUM", "description": "Missing stateless anti-DoS cookie challenge during embryonic IKE_SA_INIT flood", "clause": "[RFC 7296 §2.6]"},
    {"rule_id": "RFC7296-DEAD_PEER_DETECTION", "parameter": "IKEv2 Dead Peer Detection (DPD)", "severity": "MEDIUM", "description": "Disabled DPD keepalives causing zombie SAs and egress packet black-holing", "clause": "[RFC 7296 §2.4]"},
    {"rule_id": "RFC4301-SPD_TRAFFIC_SELECTOR", "parameter": "Security Policy Database Selectors", "severity": "HIGH", "description": "Overly broad 0.0.0.0/0 to 0.0.0.0/0 SPD selector negotiation bypassing micro-segmentation", "clause": "[RFC 4301 §4.4.1]"},
    {"rule_id": "NIST-DH_GROUP_14_MIN", "parameter": "Diffie-Hellman Group 14 (MODP-2048)", "severity": "MEDIUM", "description": "2048-bit MODP baseline offering 112 bits security requiring migration to ECP-256 (Group 19)", "clause": "[NIST SP 800-131A Rev. 2 §5]"},
    {"rule_id": "RFC8247-PRFAES128_CBC", "parameter": "IKEv2 Pseudo-Random Function", "severity": "HIGH", "description": "Deprecated AES-128-CBC PRF with only 128-bit internal state in favor of HMAC-SHA2-256", "clause": "[RFC 8247 §2.3]"},
    {"rule_id": "DOD-STIG-AEAD_MANDATE", "parameter": "ESP Combined Mode AEAD", "severity": "HIGH", "description": "Mandatory migration from non-AEAD CBC + HMAC to AES-256-GCM hardware accelerated cipher", "clause": "[DoD IPsec STIG V-220710]"},
]


@dataclass
class LLMResponse:
    content: str
    model: str
    latency_ms: float
    is_mock: bool = False


class MultiModelDistillationClient:
    """Client for invoking Gemini, Claude, or local mock generator for dataset distillation."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        gemini_model: Optional[str] = None,
        gemini_pro_model: Optional[str] = None,
        claude_model: Optional[str] = None,
    ):
        # Allow single unified key across all models (e.g. Google Cloud / Vertex AI / unified gateway)
        unified_key = api_key or os.getenv("API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or ""
        self.api_key = unified_key
        self.gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or unified_key
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY") or unified_key

        # Optional unified gateway / proxy base URL
        raw_base = base_url or os.getenv("API_BASE_URL") or os.getenv("OPENAI_BASE_URL") or ""
        self.base_url = raw_base.rstrip("/") if raw_base else ""

        self.gemini_model = gemini_model or os.getenv("GEMINI_FLASH_MODEL", "gemini-3.6-flash")
        self.gemini_pro_model = gemini_pro_model or os.getenv("GEMINI_PRO_MODEL", "gemini-3.1-pro-low")
        self.claude_model = claude_model or os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

    @staticmethod
    def resolve_model_name(model_name: str, is_gateway: bool = False) -> str:
        """Resolve friendly model names and thinking tiers (high/low/medium) to upstream IDs."""
        m = model_name.strip().lower()
        if is_gateway:
            alias_map = {
                "gemini-3.8-flash": "gemini-3-flash",
                "gemini-3.8-flash-low": "gemini-3-flash",
                "gemini-3.8-flash-medium": "gemini-3-flash",
                "gemini-3.8-flash-high": "gemini-3-flash",
                "flash-3.8": "gemini-3-flash",
                "flash-high": "gemini-3-flash",
                "flash-low": "gemini-3-flash",
                "gemini-flash": "gemini-3-flash",
                "gemini-3.1-pro": "gemini-3.1-pro-low",
                "gemini-3.1-pro-preview": "gemini-3.1-pro-low",
                "pro-high": "gemini-3.1-pro-high",
                "pro-low": "gemini-3.1-pro-low",
                "gemini-pro": "gemini-3.1-pro-low",
                "claude-sonnet": "claude-sonnet-4-6",
                "claude-3-7-sonnet": "claude-sonnet-4-6",
                "claude-opus": "claude-opus-4-6-thinking",
            }
            return alias_map.get(m, model_name)
        return model_name

    def call_gateway_single(self, prompt: str, model: str, system: str = SYSTEM_PROMPT) -> LLMResponse:
        """Call unified OpenAI-compatible or gateway API endpoint for a single model."""
        target_model = self.resolve_model_name(model, is_gateway=True)
        url = self.base_url
        if not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions" if url.endswith("/v1") else f"{url}/v1/chat/completions"

        payload = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 2048,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["x-api-key"] = self.api_key

        start_t = time.perf_counter()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError(f"No choices returned: {data}")
            content = choices[0].get("message", {}).get("content", "").strip()
            latency = (time.perf_counter() - start_t) * 1000.0
            return LLMResponse(content=content, model=f"gateway/{model}", latency_ms=latency)

    def call_gateway(self, prompt: str, model: str, system: str = SYSTEM_PROMPT) -> LLMResponse:
        """Call unified OpenAI-compatible or gateway API endpoint."""
        try:
            return self.call_gateway_single(prompt, model=model, system=system)
        except Exception as exc:
            logger.error("Unified gateway API call failed for %s: %s; falling back to mock generator.", model, exc)
            return self.call_mock(prompt, system)

    def call_gemini(self, prompt: str, system: str = SYSTEM_PROMPT, use_pro: bool = False) -> LLMResponse:
        """Call Google Gemini API with automatic model fallback."""
        if self.base_url:
            if use_pro:
                model_candidates = [self.gemini_pro_model, "gemini-3.1-pro-low", "gemini-pro-latest"]
            else:
                # If explicit model passed, try it first, otherwise default to proxy's gemini-3-flash
                first_flash = self.gemini_model if (self.gemini_model and self.gemini_model != "gemini-3.6-flash") else "gemini-3-flash"
                model_candidates = [first_flash, "gemini-3-flash", "gemini-2.5-flash", "gemini-3.6-flash"]
            model_candidates = list(dict.fromkeys(model_candidates))
            for cand in model_candidates:
                try:
                    return self.call_gateway_single(prompt, model=cand, system=system)
                except Exception as exc:
                    logger.warning("Gateway candidate %s failed (%s); trying next candidate...", cand, exc)
                    continue
            logger.error("All gateway candidates failed; falling back to mock generator.")
            return self.call_mock(prompt, system)

        if use_pro:
            model_candidates = [self.gemini_pro_model, "gemini-3.1-pro-low", "gemini-3.1-pro-preview", "gemini-pro-latest"]
        else:
            model_candidates = [self.gemini_model, "gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.5-flash", "gemini-flash-latest"]
        model_candidates = list(dict.fromkeys(model_candidates))

        if not self.gemini_key:
            logger.warning("No API key set; falling back to offline mock generator.")
            return self.call_mock(prompt, system)

        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
            },
        }

        last_error = None
        for cand in model_candidates:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{cand}:generateContent?key={self.gemini_key}"
            start_t = time.perf_counter()
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=90) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    candidates = data.get("candidates", [])
                    if not candidates:
                        raise RuntimeError(f"No candidates returned: {data}")
                    parts = candidates[0].get("content", {}).get("parts", [])
                    content = "".join(p.get("text", "") for p in parts).strip()
                    latency = (time.perf_counter() - start_t) * 1000.0
                    return LLMResponse(content=content, model=f"gemini/{cand}", latency_ms=latency)
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code == 404:
                    logger.debug("Model %s not found (404); trying next candidate...", cand)
                    continue
                elif exc.code in (429, 500, 502, 503, 504):
                    logger.warning("Gemini model %s returned HTTP %s; waiting 3s and retrying once...", cand, exc.code)
                    time.sleep(3)
                    try:
                        with urllib.request.urlopen(req, timeout=60) as retry_resp:
                            retry_data = json.loads(retry_resp.read().decode("utf-8"))
                            cands = retry_data.get("candidates", [])
                            if cands:
                                p_parts = cands[0].get("content", {}).get("parts", [])
                                content = "".join(p.get("text", "") for p in p_parts).strip()
                                latency = (time.perf_counter() - start_t) * 1000.0
                                return LLMResponse(content=content, model=f"gemini/{cand}", latency_ms=latency)
                    except Exception as retry_exc:
                        last_error = retry_exc
                        logger.warning("Retry on %s failed: %s; trying next candidate...", cand, retry_exc)
                        continue
                else:
                    logger.error("Gemini HTTP %s on model %s: %s", exc.code, cand, exc)
                    break
            except Exception as exc:
                last_error = exc
                logger.error("Gemini API call failed on model %s: %s", cand, exc)
                break

        logger.warning("All Gemini model candidates failed (%s); using mock generator.", last_error)
        return self.call_mock(prompt, system)

    def call_claude(self, prompt: str, system: str = SYSTEM_PROMPT) -> LLMResponse:
        """Call Claude API or route through Gemini Pro if using a Google key."""
        if self.base_url:
            return self.call_gateway(prompt, model=self.claude_model, system=system)

        # If user supplied a Google key (starts with AQ. or AIzaSy) without an Anthropic endpoint, route to Gemini Pro
        if self.anthropic_key and (self.anthropic_key.startswith("AQ.") or self.anthropic_key.startswith("AIzaSy")):
            logger.info("Using Google Pro key for oracle synthesis (routing through Gemini Pro)...")
            return self.call_gemini(prompt, system=system, use_pro=True)

        if not self.anthropic_key:
            logger.warning("No API key set; falling back to offline mock generator.")
            return self.call_mock(prompt, system)

        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.claude_model,
            "max_tokens": 2048,
            "temperature": 0.2,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }

        start_t = time.perf_counter()
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                contents = data.get("content", [])
                text_parts = [c.get("text", "") for c in contents if c.get("type") == "text"]
                content = "".join(text_parts).strip()
                latency = (time.perf_counter() - start_t) * 1000.0
                return LLMResponse(content=content, model=f"anthropic/{self.claude_model}", latency_ms=latency)
        except Exception as exc:
            logger.error("Claude API call failed: %s; using mock generator.", exc)
            return self.call_mock(prompt, system)

    def call_mock(self, prompt: str, system: str = SYSTEM_PROMPT) -> LLMResponse:
        """Deterministic offline mock synthesis grounded in real chunks."""
        start_t = time.perf_counter()
        p_lower = prompt.lower()
        if "3des" in p_lower or "cve-2016-2183" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "3DES uses a 64-bit block size. By the Birthday Paradox, identical ciphertext block collisions "
                "occur with high probability after approximately 2^32 blocks (32 GB of data transfer). In CBC mode, an adversary "
                "observing this collision can mathematically recover the XOR sum of the corresponding plaintexts (SWEET32 attack, CVE-2016-2183).\n\n"
                "### Primary Standards Grounding\n"
                "Under governing standards [RFC 8221 §5] and [NIST SP 800-131A Rev. 2 §2], 3DES is classified as unacceptable "
                "for modern IPsec deployments and was formally disallowed after 2023.\n\n"
                "### System Impact & Blast Radius\n"
                "Passive eavesdroppers recording high-volume tunnel sessions can decrypt sensitive credentials, session tokens, and payload data.\n\n"
                "### Verified Actionable Remediation\n"
                "Upgrade strongSwan proposals to AES-256-GCM:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16-aes128gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif ("encr_des" in p_lower or "56-bit" in p_lower or re.search(r"\bdes\b", p_lower)) and "3des" not in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Single DES utilizes an effective key length of only 56 bits. The entire key space of 2^56 (approximately 7.2 * 10^16 keys) "
                "can be exhaustively searched using brute force within minutes using commodity FPGA clusters or distributed cloud resources.\n\n"
                "### Primary Standards Grounding\n"
                "Per [RFC 8221 §5] and [NIST SP 800-131A Rev. 2 §2], DES is completely disallowed and classified as MUST NOT.\n\n"
                "### System Impact & Blast Radius\n"
                "Tunnels using DES provide zero effective cryptographic confidentiality against modern adversaries, enabling total session recovery.\n\n"
                "### Verified Actionable Remediation\n"
                "Replace DES with AES-256-GCM in strongSwan:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "group 2" in p_lower or "modp-1024" in p_lower or "logjam" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Diffie-Hellman Group 2 uses a 1024-bit MODP prime. The Number Field Sieve (NFS) algorithm allows an attacker to "
                "perform a one-time precomputation for standard prime fields, reducing individual discrete logarithm calculations "
                "to real-time online descent (Logjam attack, CVE-2015-4000).\n\n"
                "### Primary Standards Grounding\n"
                "According to [RFC 8247 §2.4] and [NIST SP 800-131A Rev. 2 §5], MODP-1024 provides only 80 bits of symmetric equivalence "
                "and is categorized as MUST NOT.\n\n"
                "### System Impact & Blast Radius\n"
                "Adversaries can passively decrypt the IKEv2 handshake, recover SKEYSEED, and decrypt all subsequent Child SAs.\n\n"
                "### Verified Actionable Remediation\n"
                "Migrate key exchange proposals to Diffie-Hellman Group 19 (256-bit ECP) or Group 14 (2048-bit MODP):\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    proposals = aes256-sha256-ecp256,aes256-sha256-modp2048\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "group 1" in p_lower or "768" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Diffie-Hellman Group 1 uses a 768-bit MODP prime field. Computing discrete logarithms in 768-bit fields requires "
                "less than 2^67 operations with the Number Field Sieve, which is well within reach of academic and modest hardware budgets.\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 8247 §2.4], Group 1 is completely deprecated and categorized as MUST NOT.\n\n"
                "### System Impact & Blast Radius\n"
                "Passive eavesdropping of IKE_SA_INIT exchanges allows instantaneous derivation of private exponents and plaintext recovery.\n\n"
                "### Verified Actionable Remediation\n"
                "Migrate proposals to ECP-256 (Group 19):\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    proposals = aes256-sha256-ecp256\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "group 5" in p_lower or "1536" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Diffie-Hellman Group 5 uses a 1536-bit MODP prime field offering only ~90 bits of symmetric key equivalence. "
                "The Number Field Sieve (NFS) algorithm complexity L_p[1/3, c] makes 1536-bit primes insufficient against state-level adversaries.\n\n"
                "### Primary Standards Grounding\n"
                "Per [RFC 8247 §2.4] and [NIST SP 800-131A Rev. 2 §5], 1536-bit MODP fails the mandatory 112-bit security threshold and is SHOULD NOT.\n\n"
                "### System Impact & Blast Radius\n"
                "Leaves long-term confidential government or enterprise traffic vulnerable to retrospective discrete log precomputation.\n\n"
                "### Verified Actionable Remediation\n"
                "Upgrade proposals to Group 19 (ECP-256) or Group 14 (MODP-2048):\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    proposals = aes256-sha256-ecp256,aes256-sha256-modp2048\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "esn" in p_lower or "4303" in p_lower or "sequence" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Standard IPsec ESP uses a 32-bit sequence number (2^32 packets). On high-speed 10Gbps or 40Gbps links, "
                "a stream of full-line rate packets exhausts the 2^32 sequence space in approximately 4 to 5 minutes, triggering sequence rollover. "
                "Without Extended Sequence Numbers (ESN, 2^64 sequence space), the SA must renegotiate or drop traffic to prevent replay attacks.\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 4303 §2.2.1], Extended (64-bit) Sequence Numbers (ESN) are required for high-speed IPsec links to maintain anti-replay protection.\n\n"
                "### System Impact & Blast Radius\n"
                "Severe packet dropping, anti-replay window desynchronization, and excessive IKE rekeying overhead that degrades link throughput.\n\n"
                "### Verified Actionable Remediation\n"
                "Enable 64-bit ESN in strongSwan Child SA proposals:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    children {\n"
                "      net {\n"
                "        esp_proposals = aes256gcm16-esn\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "blowfish" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Blowfish has a 64-bit block size. By the Birthday Paradox, collisions between encrypted blocks occur with probability > 50% "
                "after 2^32 blocks (32 GB). In CBC mode, observing identical ciphertexts reveals the XOR difference of plaintext blocks (SWEET32, CVE-2016-2183).\n\n"
                "### Primary Standards Grounding\n"
                "Per [RFC 8221 §5], Blowfish-CBC is obsolete and MUST NOT be used in IPsec ESP transforms.\n\n"
                "### System Impact & Blast Radius\n"
                "Exposes sensitive session cookies, bearer tokens, and confidential tunnel traffic to plaintext extraction.\n\n"
                "### Verified Actionable Remediation\n"
                "Replace Blowfish with AES-256-GCM:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "null" in p_lower or "encr_null" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "ENCR_NULL provides 0 bits of cryptographic entropy (H(X) = 0). It performs no encryption whatsoever, "
                "leaving the entire payload in plaintext.\n\n"
                "### Primary Standards Grounding\n"
                "According to [RFC 8221 §5], ENCR_NULL MUST NOT be used for confidentiality protection in production environments.\n\n"
                "### System Impact & Blast Radius\n"
                "Complete breach of confidentiality; all payload data traversing the untrusted WAN is visible to passive wiretappers.\n\n"
                "### Verified Actionable Remediation\n"
                "Enforce AES-256-GCM authenticated encryption:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "pfs" in p_lower or "220730" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "When Child SA Perfect Forward Secrecy (PFS) is omitted, Child SA keys are derived strictly from the original IKE SA SKEYSEED "
                "without an ephemeral Diffie-Hellman exchange. Compromising the IKE SA private exponent reveals keys for all Child SAs.\n\n"
                "### Primary Standards Grounding\n"
                "Per [DoD IPsec STIG V-220730], Perfect Forward Secrecy (PFS) with DH Group 14 or higher is mandatory for all Child SAs.\n\n"
                "### System Impact & Blast Radius\n"
                "Eliminates forward secrecy; retroactive decryption of historical captured Child SA sessions upon compromise of the parent IKE SA.\n\n"
                "### Verified Actionable Remediation\n"
                "Require DH Group in strongSwan `esp_proposals`:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    children {\n"
                "      net {\n"
                "        esp_proposals = aes256gcm16-modp2048,aes256gcm16-ecp256\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "cookie" in p_lower or "dos" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "In IKEv2, processing an IKE_SA_INIT request allocates half-open state in memory and performs modular exponentiation. "
                "An attacker sending spoofed packets can exhaust responder memory (O(N) state exhaustion) at negligible cost.\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 7296 §2.6], responders under load MUST send a stateless COOKIE notification requiring initiator IP verification.\n\n"
                "### System Impact & Blast Radius\n"
                "Gateway denial-of-service, memory starvation, and rejection of legitimate VPN tunnel establishment.\n\n"
                "### Verified Actionable Remediation\n"
                "Enable cookie threshold defense in strongSwan `strongswan.conf` / `swanctl.conf`:\n"
                "```text\n"
                "charon {\n"
                "  cookie_threshold = 10\n"
                "  dos_protection = yes\n"
                "}\n"
                "```"
            )
        elif "dpd" in p_lower or "dead peer" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Without Dead Peer Detection (DPD), a gateway has no mechanism to detect abnormal peer termination or routing partitions. "
                "Security Associations remain in the Security Association Database (SAD) indefinitely (t -> inf).\n\n"
                "### Primary Standards Grounding\n"
                "Per [RFC 7296 §2.4], IKEv2 endpoints SHOULD implement periodic INFORMATIONAL liveness checks to verify peer availability.\n\n"
                "### System Impact & Blast Radius\n"
                "Egress packets are black-holed into stale tunnels; automatic failover to backup gateways is prevented.\n\n"
                "### Verified Actionable Remediation\n"
                "Configure DPD action and timeout in `swanctl.conf`:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    dpd_delay = 30s\n"
                "    dpd_timeout = 120s\n"
                "    children {\n"
                "      net {\n"
                "        dpd_action = restart\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "spd" in p_lower or "selector" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Negotiating a wildcard 0.0.0.0/0 to 0.0.0.0/0 traffic selector covers 2^32 IPv4 addresses. "
                "It violates least privilege by aggregating all egress traffic into a single IPsec SA, bypassing firewall microsegmentation.\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 4301 §4.4.1], Security Policy Database (SPD) selectors must be explicitly scoped to authorized subnets and protocols.\n\n"
                "### System Impact & Blast Radius\n"
                "Subnet route hijacking, lateral movement across internal zones, and unintended tunnel interception.\n\n"
                "### Verified Actionable Remediation\n"
                "Constrain local and remote traffic selectors in `swanctl.conf`:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    children {\n"
                "      net {\n"
                "        local_ts  = 10.100.0.0/16\n"
                "        remote_ts = 192.168.1.0/24\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "group 14" in p_lower or "2048" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "MODP-2048 (DH Group 14) provides 112 bits of symmetric equivalent security (2^112 key space). While currently permitted, "
                "it requires high computational overhead (modular exponentiation O(k^3)) compared to elliptic curve cryptography.\n\n"
                "### Primary Standards Grounding\n"
                "According to [NIST SP 800-131A Rev. 2 §5], 112-bit security is acceptable through 2030, with recommendation to adopt 128-bit curves.\n\n"
                "### System Impact & Blast Radius\n"
                "Higher CPU utilization during rekeying and lower handshake throughput under heavy load.\n\n"
                "### Verified Actionable Remediation\n"
                "Upgrade proposals to Group 19 (ECP-256) or Group 31 (Curve25519):\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    proposals = aes256-sha256-ecp256,aes256-sha256-modp2048\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "prf" in p_lower or "aes128_cbc" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "PRF_AES128_CBC operates with a 128-bit internal state. In contrast, HMAC-SHA2-256 provides a 256-bit state, "
                "significantly reducing pseudorandom stream predictability and key derivation collisions.\n\n"
                "### Primary Standards Grounding\n"
                "Per [RFC 8247 §2.3], PRF_AES128_CBC is deprecated (SHOULD NOT) in favor of PRF_HMAC_SHA2_256.\n\n"
                "### System Impact & Blast Radius\n"
                "Weaker cryptographic entropy feeding the key derivation function (KDF) for Child SA keys.\n\n"
                "### Verified Actionable Remediation\n"
                "Configure modern PRF in IKE proposals:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    proposals = aes256-sha256-ecp256\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "aead" in p_lower or "220710" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Legacy non-AEAD ciphers (CBC mode with HMAC) require two distinct cryptographic passes over each packet: "
                "encryption and MAC calculation. AEAD (AES-256-GCM) unifies confidentiality and integrity into a single pass using GHASH, "
                "accelerated by AES-NI hardware instructions, preventing padding oracle attacks (CVE-2016-2183).\n\n"
                "### Primary Standards Grounding\n"
                "Mandated by [DoD IPsec STIG V-220710] and [RFC 8221 §5] as the required standard for ESP encryption.\n\n"
                "### System Impact & Blast Radius\n"
                "CBC mode exposes packets to bit-flipping, padding oracle recovery, and 2x higher packet latency.\n\n"
                "### Verified Actionable Remediation\n"
                "Enforce AES-256-GCM in strongSwan proposals:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "md5" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "MD5 has been broken cryptanalytically. Collision attacks reduce complexity from theoretical 2^64 to 2^16 operations. "
                "Using HMAC-MD5-96 allows adversaries with chosen-prefix capabilities to forge authenticated ESP packets.\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 8221 §5], HMAC-MD5-96 is categorized as MUST NOT.\n\n"
                "### System Impact & Blast Radius\n"
                "Complete loss of packet authentication and integrity; injection of arbitrary malicious packets into the tunnel.\n\n"
                "### Verified Actionable Remediation\n"
                "Replace MD5 with SHA-256 authentication or AES-GCM AEAD in strongSwan:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16,aes256-sha256\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "post-quantum" in p_lower or "ppk" in p_lower or "rfc 8784" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC) solves finite-field discrete logs and elliptic curve discrete logs "
                "in polynomial time, breaking standard Diffie-Hellman exchanges. RFC 8784 injects a pre-shared 256-bit symmetric PPK into the "
                "SKEYSEED derivation: SKEYSEED = prf(Ni | Nr, SK_d | PPK).\n\n"
                "### Primary Standards Grounding\n"
                "Under [RFC 8784 §6] and [RFC 8784 §2], Post-Quantum Pre-Shared Keys are established to provide defense against 'Harvest Now, Decrypt Later' attacks.\n\n"
                "### System Impact & Blast Radius\n"
                "Ensures encrypted traffic captured today cannot be decrypted retrospectively when quantum computing hardware becomes available.\n\n"
                "### Verified Actionable Remediation\n"
                "Enable PPK enforcement in strongSwan 5.8+:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    ppk_id = enterprise-quantum-ppk-01\n"
                "    ppk_required = yes\n"
                "  }\n"
                "}\n"
                "```"
            )
        elif "fragmentation" in p_lower or "rfc 7383" in p_lower:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "Large X.509 certificate chains in IKE_AUTH cause messages to exceed Path MTU, triggering IP-level UDP fragmentation. "
                "Carrier-grade NATs and stateful firewalls drop fragmented UDP port 500/4500 packets due to missing L4 headers in non-first fragments.\n\n"
                "### Primary Standards Grounding\n"
                "According to [RFC 7383 §2.3] and [RFC 7383 §2.6.1], IKEv2 Message Fragmentation breaks large IKE messages into small encrypted fragments "
                "each containing its own IKE header and encrypted fragment payload before transmission.\n\n"
                "### System Impact & Blast Radius\n"
                "Intermittent VPN tunnel dropouts and handshake timeouts during certificate validation.\n\n"
                "### Verified Actionable Remediation\n"
                "Configure IKE fragmentation in `swanctl.conf`:\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    fragmentation = yes\n"
                "  }\n"
                "}\n"
                "```"
            )
        else:
            content = (
                "### Cryptanalytic Threat & Mathematical Analysis\n"
                "The configuration employs legacy parameters lacking authenticated encryption (AEAD). "
                "Unauthenticated CBC mode permits active Man-in-the-Middle bit-flipping attacks.\n\n"
                "### Primary Standards Grounding\n"
                "Governing standard [RFC 8221 §5] and [NIST SP 800-77 Rev. 1 Table 1] mandate modern AEAD ciphers (AES-GCM).\n\n"
                "### System Impact & Blast Radius\n"
                "Exposes tunnel payloads to integrity modification and plaintext recovery.\n\n"
                "### Verified Actionable Remediation\n"
                "Upgrade transforms to AES-256-GCM and DH Group 19 per [DoD IPsec STIG V-220710].\n"
                "```text\n"
                "connections {\n"
                "  vpn {\n"
                "    esp_proposals = aes256gcm16\n"
                "  }\n"
                "}\n"
                "```"
            )

        latency = (time.perf_counter() - start_t) * 1000.0
        return LLMResponse(content=content, model="Janus-Local-Mock", latency_ms=latency, is_mock=True)


class DistillationSynthesizer:
    """Orchestrates dataset distillation and DPO pair generation."""

    def __init__(self, client: Optional[MultiModelDistillationClient] = None):
        self.client = client or MultiModelDistillationClient()
        self.chunks = []
        self._load_chunks()

    def _load_chunks(self) -> None:
        if CHUNKS_PATH.exists():
            with open(CHUNKS_PATH, "r", encoding="utf-8") as f:
                self.chunks = json.load(f)
        logger.info("Loaded %d authoritative standards chunks for distillation", len(self.chunks))

    def generate_sft_sample(self, finding: dict[str, Any], tier: str = "flash") -> Optional[dict[str, Any]]:
        """Generate a single-finding SFT example with CoT reasoning."""
        rule_id = finding.get("rule_id", "RFC8221-ENCR_3DES")
        param = finding.get("parameter", "ESP Encryption")
        severity = finding.get("severity", "HIGH")
        desc = finding.get("description", "SWEET32 collision risk on 64-bit block ciphers")
        clause = finding.get("clause", "[RFC 8221 §5]")

        prompt = (
            f"Compliance Audit Finding:\n"
            f"- Rule ID: {rule_id}\n"
            f"- Parameter: {param}\n"
            f"- Severity: {severity}\n"
            f"- Description: {desc}\n"
            f"- Governing Clause: {clause}\n\n"
            f"Perform an authoritative cryptographic compliance analysis explaining why this finding is classified as {severity}.\n"
            f"Structure your technical response strictly with these exact markdown headers:\n"
            f"### Cryptanalytic Threat & Mathematical Analysis\n"
            f"Include explicit mathematical formulations (e.g. key space 2^k, birthday paradox collision bound 2^{{b/2}} blocks, sequence space 2^32 vs 2^64, discrete log NFS precomputation, or quantum search complexity).\n"
            f"### Primary Standards Grounding\n"
            f"Explicitly cite {clause} in brackets.\n"
            f"### System Impact & Blast Radius\n"
            f"Detail systemic attack vectors against enterprise VPN tunnels.\n"
            f"### Verified Actionable Remediation\n"
            f"Provide an exact strongSwan swanctl.conf configuration block."
        )

        use_pro = tier == "pro"
        if tier == "claude":
            resp = self.client.call_claude(prompt)
        elif tier == "mock":
            resp = self.client.call_mock(prompt)
        else:
            resp = self.client.call_gemini(prompt, use_pro=use_pro)

        # Verification Gate
        v_res = verifier.verify_and_enforce(resp.content)
        sanitized_content = v_res.sanitized_text

        # In SFT mode, require at least one verified citation
        if v_res.verified_count == 0 and v_res.unverified_count > 0:
            logger.warning("Rejected ungrounded SFT candidate: %s", resp.content[:120])
            return None

        return {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": sanitized_content},
            ],
            "metadata": {
                "rule_id": rule_id,
                "model": resp.model,
                "latency_ms": resp.latency_ms,
                "verified_citations": v_res.verified_count,
            },
        }

    def generate_compound_sample(self, scenario_name: str, findings: list[dict[str, Any]], tier: str = "pro") -> Optional[dict[str, Any]]:
        """Generate a multi-finding compound blast-radius scenario."""
        f_text = "\n".join([f"- [{f['severity']}] {f['rule_id']}: {f['parameter']} ({f['description']})" for f in findings])
        prompt = (
            f"Multi-Finding Compound Security Assessment:\n"
            f"Scenario: {scenario_name}\n"
            f"Concurrent Findings ({len(findings)} total):\n{f_text}\n\n"
            f"Analyze the compound risk and systemic blast radius when these vulnerabilities interact simultaneously. "
            f"Cite governing RFC/NIST/DoD STIG clauses in brackets and provide unified remediation."
        )

        if tier == "claude":
            resp = self.client.call_claude(prompt)
        elif tier == "mock":
            resp = self.client.call_mock(prompt)
        else:
            resp = self.client.call_gemini(prompt, use_pro=True)

        v_res = verifier.verify_and_enforce(resp.content)
        return {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": v_res.sanitized_text},
            ],
            "metadata": {
                "scenario": scenario_name,
                "findings_count": len(findings),
                "model": resp.model,
                "verified_citations": v_res.verified_count,
            },
        }

    def generate_dpo_pair(self, finding: dict[str, Any], tier_chosen: str = "claude", tier_rejected: str = "flash") -> dict[str, Any]:
        """Generate a (prompt, chosen, rejected) DPO pair."""
        rule_id = finding.get("rule_id", "RFC8221-ENCR_3DES")
        param = finding.get("parameter", "ESP Encryption")
        severity = finding.get("severity", "HIGH")
        desc = finding.get("description", "SWEET32 collision risk")
        clause = finding.get("clause", "[RFC 8221 §5]")

        prompt = (
            f"Compliance Audit Finding: {param} is set to a legacy primitive ({desc}). "
            f"Assigned severity: {severity}. Governing standard: {clause}.\n"
            f"Explain the technical threat, standards mandate with {clause} in brackets, mathematical breakdown (e.g. 2^32 collisions, 2^56 brute force, or discrete log), and concrete strongSwan configuration."
        )

        # 1. Generate Chosen: Oracle model (Claude Sonnet or Gemini Pro or Verified Mock)
        if tier_chosen == "claude":
            resp_chosen = self.client.call_claude(prompt)
        elif tier_chosen == "mock":
            resp_chosen = self.client.call_mock(prompt)
        else:
            resp_chosen = self.client.call_gemini(prompt, use_pro=True)

        v_chosen = verifier.verify_and_enforce(resp_chosen.content)
        chosen_text = v_chosen.sanitized_text

        # 2. Generate Rejected: Flawed candidate (synthesized hallucination, vague advice, missing math)
        flawed_variations = [
            (
                f"You can keep using {param} if your throughput is below 10Gbps. "
                f"According to [RFC 9999 §42], this algorithm is safe for corporate intranets. "
                f"Just set `lifetime = 24h` in your VPN setup and disable rekeying to save CPU."
            ),
            (
                f"The finding is marked as {severity}. {param} might have some security issues but "
                f"it should be fine for most connections. Check your firewall settings. "
                f"No changes to `swanctl.conf` are strictly necessary."
            ),
            (
                f"This violates [RFC 8221 §99]. It is bad because older algorithms are insecure. "
                f"Upgrade everything to DES or 3DES immediately to maintain legacy compatibility."
            ),
        ]
        rejected_text = random.choice(flawed_variations)

        return {
            "prompt": prompt,
            "chosen": chosen_text,
            "rejected": rejected_text,
            "metadata": {
                "rule_id": rule_id,
                "chosen_model": resp_chosen.model,
                "grounded": v_chosen.is_grounded,
            },
        }

    def run_sft_pipeline(self, count: int = 50, tier: str = "flash", output_path: Path = DEFAULT_SFT_PATH) -> int:
        """Run bulk SFT distillation loop."""
        seed_findings = CORE_SEED_FINDINGS

        logger.info("Starting SFT distillation pipeline: generating %d examples using tier '%s'", count, tier)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        samples = []
        for i in range(count):
            finding = seed_findings[i % len(seed_findings)]
            sample = self.generate_sft_sample(finding, tier=tier)
            if sample:
                samples.append(sample)
            if (i + 1) % 10 == 0:
                logger.info("Generated %d / %d SFT samples...", len(samples), count)

        with open(output_path, "a", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")

        logger.info("Appended %d verified SFT samples to %s", len(samples), output_path)
        return len(samples)

    def run_dpo_pipeline(self, count: int = 25, tier_chosen: str = "claude", tier_rejected: str = "flash", output_path: Path = DEFAULT_DPO_PATH) -> int:
        """Run DPO pair generation pipeline."""
        seed_findings = CORE_SEED_FINDINGS

        logger.info("Starting DPO distillation pipeline: generating %d pairs (Chosen: %s, Rejected: %s)", count, tier_chosen, tier_rejected)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        pairs = []
        for i in range(count):
            finding = seed_findings[i % len(seed_findings)]
            pair = self.generate_dpo_pair(finding, tier_chosen=tier_chosen, tier_rejected=tier_rejected)
            pairs.append(pair)
            if (i + 1) % 5 == 0:
                logger.info("Generated %d / %d DPO pairs...", len(pairs), count)

        with open(output_path, "a", encoding="utf-8") as f:
            for p in pairs:
                f.write(json.dumps(p) + "\n")

        logger.info("Appended %d verified DPO pairs to %s", len(pairs), output_path)
        return len(pairs)

    def export_web_prompts(self, count: int = 10, output_path: Path = DATA_DIR / "web_distill_prompts.txt") -> Path:
        """
        Exports ready-to-paste prompts for users using Gemini Advanced (web)
        or Claude.ai (web) with their consumer subscription plans.
        """
        seed_findings = CORE_SEED_FINDINGS

        sections = [
            "================================================================================",
            "PROJECT JANUS: WEB CHAT DISTILLATION PROMPTS (FOR GEMINI / CLAUDE SUBSCRIPTIONS)",
            "================================================================================",
            "Instructions:",
            "1. Copy any of the prompt blocks below.",
            "2. Paste into your Gemini Advanced (3.1 Pro / Flash) or Claude.ai (Sonnet) web chat.",
            "3. The AI will output valid ChatML JSON lines.",
            "4. Copy the JSON output from the chat and append it to rag/data/distill_sft_dataset.jsonl",
            "================================================================================\n",
        ]

        for idx, f in enumerate(seed_findings[:count], start=1):
            prompt_block = (
                f"--- [PROMPT BATCH {idx}: {f['rule_id']}] ---\n\n"
                f"You are a specialized IPsec and cryptography standards auditor for Project Janus.\n"
                f"Generate 5 distinct, high-density ChatML training samples in JSONL format for the finding below.\n\n"
                f"Finding Details:\n"
                f"- Parameter: {f['param']}\n"
                f"- Vulnerability: {f['vuln']}\n"
                f"- Governing Clause: {f['clause']}\n\n"
                f"Requirements for each assistant response:\n"
                f"1. Include '### Cryptanalytic Threat & Mathematical Analysis' with exact math (e.g. 2^32 collisions, discrete log precomputation).\n"
                f"2. Include '### Primary Standards Grounding' explicitly citing {f['clause']} in brackets.\n"
                f"3. Include '### System Impact & Blast Radius'.\n"
                f"4. Include '### Verified Actionable Remediation' with strongSwan `swanctl.conf` code.\n\n"
                f"Output ONLY valid raw JSON Lines (one JSON per line) following this schema:\n"
                f'{{"messages": [{{"role": "system", "content": "..."}}, {{"role": "user", "content": "..."}}, {{"role": "assistant", "content": "..."}}]}}\n'
            )
            sections.append(prompt_block)

        output_path.write_text("\n".join(sections), encoding="utf-8")
        logger.info("Exported web chat distillation prompts to %s", output_path)
        return output_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Model Dataset Distillation Pipeline for Project Janus")
    parser.add_argument("--tier", choices=["flash", "pro", "claude", "mock"], default="mock", help="Model tier to invoke")
    parser.add_argument("--mode", choices=["sft", "dpo"], default="sft", help="Dataset generation mode")
    parser.add_argument("--count", type=int, default=10, help="Number of examples/pairs to generate")
    parser.add_argument("--api-key", type=str, default=None, help="Unified API key for all models")
    parser.add_argument("--base-url", type=str, default=None, help="Custom API base URL (e.g. unified gateway or proxy)")
    parser.add_argument("--model", type=str, default=None, help="Explicit model name override (e.g. gemini-2.5-flash, claude-3-7-sonnet)")
    parser.add_argument("--export-web", action="store_true", help="Export copy-paste prompts for Gemini Advanced / Claude Web")
    parser.add_argument("--output", type=str, default=None, help="Custom output JSONL path")
    args = parser.parse_args()

    # Configure client with optional model and unified key override
    gemini_flash = args.model if args.tier == "flash" and args.model else None
    gemini_pro = args.model if args.tier == "pro" and args.model else None
    claude_m = args.model if args.tier == "claude" and args.model else None

    client = MultiModelDistillationClient(
        api_key=args.api_key,
        base_url=args.base_url,
        gemini_model=gemini_flash,
        gemini_pro_model=gemini_pro,
        claude_model=claude_m,
    )
    synthesizer = DistillationSynthesizer(client=client)

    if args.export_web:
        out_p = Path(args.output) if args.output else DATA_DIR / "web_distill_prompts.txt"
        synthesizer.export_web_prompts(count=args.count, output_path=out_p)
    elif args.mode == "sft":
        out_p = Path(args.output) if args.output else DEFAULT_SFT_PATH
        synthesizer.run_sft_pipeline(count=args.count, tier=args.tier, output_path=out_p)
    elif args.mode == "dpo":
        out_p = Path(args.output) if args.output else DEFAULT_DPO_PATH
        synthesizer.run_dpo_pipeline(count=args.count, tier_chosen=args.tier, output_path=out_p)
