"""
tests/conftest.py
=================
Shared pytest fixtures for the Janus test suite.

Fixtures
--------
sample_ike_tshark_json       – Realistic tshark JSON for IKEv2 SA_INIT (strong config).
sample_weak_ike_tshark_json  – tshark JSON for IKEv2 with 3DES / MD5 / DH-2 (weak config).
sample_esp_pcap_bytes        – Minimal synthetic PCAP bytes containing 50 mock ESP packets.
sample_flow_features         – Dict matching the FlowFeatures dataclass fields.
sample_obfuscated_features   – Dict with near-constant packet sizes and IATs (IP-TFS suspect).
mock_xgb_model               – Tiny XGBoost classifier trained on synthetic 8-feature data.
async_client                 – httpx.AsyncClient wired to the Janus FastAPI app via
                               ASGITransport.
"""

from __future__ import annotations

import io
import struct
from typing import Any, Dict, List

import numpy as np
import pytest
import pytest_asyncio


# ---------------------------------------------------------------------------
# Helpers — minimal libpcap builder
# ---------------------------------------------------------------------------

def _pcap_global_header() -> bytes:
    """Return a standard libpcap global header (little-endian, link-type Ethernet)."""
    magic = 0xA1B2C3D4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # LINKTYPE_ETHERNET
    return struct.pack("<IHHiIII", magic, version_major, version_minor,
                       thiszone, sigfigs, snaplen, network)


def _pcap_packet_record(payload: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    """Wrap *payload* in a libpcap packet record."""
    orig_len = len(payload)
    incl_len = min(orig_len, 65535)
    header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
    return header + payload[:incl_len]


def _fake_esp_ethernet_frame(seq: int, size: int = 200) -> bytes:
    """
    Build a minimal Ethernet/IPv4/ESP frame of approximately *size* bytes.

    Layout
    ------
    Ethernet (14 B) | IPv4 (20 B) | ESP SPI+SEQ (8 B) | padding
    Protocol 50 = ESP.  DSCP is always 0 for simplicity.
    """
    eth_dst = b"\xff\xff\xff\xff\xff\xff"
    eth_src = b"\x00\x0c\x29\x00\x00\x01"
    ethertype = b"\x08\x00"  # IPv4

    total_ip_len = max(28, size - 14)  # ensure at least IP + ESP headers fit
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                    # version=4, IHL=5
        0x00,                    # DSCP=0, ECN=0
        total_ip_len,
        seq & 0xFFFF,            # identification
        0x4000,                  # DF flag, no fragment offset
        64,                      # TTL
        50,                      # protocol = ESP
        0,                       # checksum (fake — not validated in tests)
        b"\xc0\xa8\x01\x01",    # src 192.168.1.1
        b"\xc0\xa8\x01\x02",    # dst 192.168.1.2
    )

    # ESP header: 4-byte SPI + 4-byte sequence number
    esp_header = struct.pack("!II", 0xDEADBEEF, seq)

    payload_size = max(0, total_ip_len - 20 - 8)
    esp_payload = bytes(payload_size)

    return eth_dst + eth_src + ethertype + ip_header + esp_header + esp_payload


# ---------------------------------------------------------------------------
# IKEv2 SA_INIT tshark mock JSON — STRONG config
# ---------------------------------------------------------------------------

_IKE_STRONG_PACKET: Dict[str, Any] = {
    "_index": "packets-2026-09-01",
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.time_epoch": "1756700000.000000",
            },
            "ip": {
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "ip.dsfield.dscp": "0",
                "ip.proto": "17",
            },
            "udp": {"udp.srcport": "500", "udp.dstport": "500"},
            "isakmp": {
                "isakmp.version": "2.0",
                "isakmp.exchangetype": "34",        # IKE_SA_INIT
                "isakmp.init_spi": "1234567890abcdef",
                "isakmp.resp_spi": "fedcba0987654321",
                "isakmp.flags.initiator": "1",
                "isakmp.sa": {
                    "isakmp.prop.protoid": "1",     # IKE protocol
                    "isakmp.prop.transforms": [
                        {
                            "isakmp.tf.type": "3",          # ENCR
                            "isakmp.tf.alg": "20",          # ENCR_AES_GCM_16
                            "isakmp.tf.attr.keylen": "256",
                            "isakmp.tf.attr.alg_name": "aes256gcm16",
                        },
                        {
                            "isakmp.tf.type": "2",          # PRF
                            "isakmp.tf.alg": "7",           # PRF_HMAC_SHA2_384
                            "isakmp.tf.attr.alg_name": "prfsha384",
                        },
                        {
                            "isakmp.tf.type": "4",          # DH group
                            "isakmp.tf.alg": "19",          # ECP-256 (group 19)
                            "isakmp.tf.attr.alg_name": "ecp256",
                        },
                    ],
                },
                "isakmp.ke": {"isakmp.ke.dh_group": "19"},
                "isakmp.nonce": {
                    "isakmp.nonce.data": "aabbccddeeff00112233445566778899",
                },
            },
        }
    },
}

# ---------------------------------------------------------------------------
# IKEv2 SA_INIT tshark mock JSON — WEAK config (3DES / MD5 / DH-2)
# ---------------------------------------------------------------------------

_IKE_WEAK_PACKET: Dict[str, Any] = {
    "_index": "packets-2026-09-01",
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.time_epoch": "1756700001.000000",
            },
            "ip": {
                "ip.src": "10.0.0.3",
                "ip.dst": "10.0.0.4",
                "ip.dsfield.dscp": "0",
                "ip.proto": "17",
            },
            "udp": {"udp.srcport": "500", "udp.dstport": "500"},
            "isakmp": {
                "isakmp.version": "2.0",
                "isakmp.exchangetype": "34",
                "isakmp.init_spi": "aabbccddeeff0011",
                "isakmp.resp_spi": "1122334455667788",
                "isakmp.flags.initiator": "1",
                "isakmp.sa": {
                    "isakmp.prop.protoid": "1",
                    "isakmp.prop.transforms": [
                        {
                            "isakmp.tf.type": "3",          # ENCR
                            "isakmp.tf.alg": "3",           # ENCR_3DES
                            "isakmp.tf.attr.alg_name": "3des",
                        },
                        {
                            "isakmp.tf.type": "1",          # INTEG / AUTH
                            "isakmp.tf.alg": "1",           # AUTH_HMAC_MD5_96
                            "isakmp.tf.attr.alg_name": "hmac-md5",
                        },
                        {
                            "isakmp.tf.type": "4",          # DH group
                            "isakmp.tf.alg": "2",           # 1024-bit MODP (group 2)
                            "isakmp.tf.attr.alg_name": "modp1024",
                        },
                    ],
                },
                "isakmp.ke": {"isakmp.ke.dh_group": "2"},
                "isakmp.nonce": {
                    "isakmp.nonce.data": "deadbeefdeadbeefdeadbeef",
                },
            },
        }
    },
}


@pytest.fixture
def sample_ike_tshark_json() -> List[Dict[str, Any]]:
    """
    A one-element list mimicking tshark's ``-T json`` output for a single
    IKEv2 SA_INIT packet with AES-256-GCM / SHA-384 / ECP-256 (group 19).
    """
    return [_IKE_STRONG_PACKET]


@pytest.fixture
def sample_weak_ike_tshark_json() -> List[Dict[str, Any]]:
    """
    A one-element list mimicking tshark's ``-T json`` output for a single
    IKEv2 SA_INIT packet with 3DES / HMAC-MD5 / DH group 2.
    """
    return [_IKE_WEAK_PACKET]


# ---------------------------------------------------------------------------
# Synthetic PCAP bytes — 50 ESP packets of varied sizes
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_esp_pcap_bytes() -> bytes:
    """
    Minimal libpcap byte-string containing 50 fake Ethernet/IPv4/ESP packets.

    Packet sizes vary between 128 and 1 400 bytes (seeded RNG for reproducibility).
    Timestamps advance 1 second per packet so IAT = 1 s (uniform).
    """
    buf = io.BytesIO()
    buf.write(_pcap_global_header())
    rng = np.random.default_rng(seed=42)
    sizes: List[int] = rng.integers(128, 1400, size=50).tolist()
    for i, sz in enumerate(sizes):
        frame = _fake_esp_ethernet_frame(seq=i, size=int(sz))
        buf.write(_pcap_packet_record(frame, ts_sec=i, ts_usec=0))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# FlowFeatures dict — matches parsing/esp_features.py FlowFeatures dataclass
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_flow_features() -> Dict[str, Any]:
    """
    A dict whose keys exactly mirror the ``FlowFeatures`` dataclass fields.
    Deliberately excludes ``ip_src`` and ``ip_dst`` to validate their absence.
    """
    return {
        # Packet-size statistics
        "pkt_size_min": 128.0,
        "pkt_size_max": 1400.0,
        "pkt_size_mean": 512.0,
        "pkt_size_var": 18500.0,
        # Inter-arrival time statistics (seconds)
        "iat_min": 0.0005,
        "iat_max": 0.25,
        "iat_mean": 0.05,
        "iat_var": 0.0012,
        # Burst statistics
        "burst_count": 8,
        "burst_mean_size": 3.0,
        # Flow-level metadata
        "pkt_count": 50,
        "duration_s": 2.5,
        "bytes_per_second": 10240.0,
        "pkts_per_second": 20.0,
        # ESP / outer-IP header fields
        "spi": 0xDEADBEEF,
        "dscp": 0,
        # Obfuscation hint — not set for normal traffic
        "possible_iptfs": False,
    }


@pytest.fixture
def sample_obfuscated_features() -> Dict[str, Any]:
    """
    Flow features with near-constant packet sizes and inter-arrival times —
    the hallmark of IP-TFS / traffic-flow-confidentiality padding (RFC 9347).
    ``possible_iptfs`` is pre-set to True as the extractor would set it.
    """
    return {
        "pkt_size_min": 1498.0,
        "pkt_size_max": 1500.0,
        "pkt_size_mean": 1499.0,
        "pkt_size_var": 0.5,          # ~zero variance
        "iat_min": 0.009990,
        "iat_max": 0.010010,
        "iat_mean": 0.010000,
        "iat_var": 0.0000001,          # ~zero IAT variance
        "burst_count": 0,
        "burst_mean_size": 0.0,
        "pkt_count": 200,
        "duration_s": 2.0,
        "bytes_per_second": 149900.0,
        "pkts_per_second": 100.0,
        "spi": 0xCAFEBABE,
        "dscp": 0,
        "possible_iptfs": True,
    }


# ---------------------------------------------------------------------------
# Tiny XGBoost classifier fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_xgb_model():
    """
    A minimal ``XGBClassifier`` trained on 200 synthetic 8-feature samples
    with binary labels.  The model is intentionally tiny (10 trees, depth 3)
    so fixture setup is fast.

    Skips automatically if xgboost is not installed.
    """
    pytest.importorskip("xgboost", reason="xgboost not installed — skipping XGBoost fixture")
    import xgboost as xgb  # noqa: PLC0415

    rng = np.random.default_rng(seed=0)
    X = rng.standard_normal((200, 8)).astype(np.float32)
    # Simple separable label: positive half-space in first two features
    y = ((X[:, 0] + X[:, 1]) > 0).astype(int)

    clf = xgb.XGBClassifier(
        n_estimators=10,
        max_depth=3,
        eval_metric="logloss",
        random_state=0,
    )
    clf.fit(X, y)
    return clf


# ---------------------------------------------------------------------------
# FastAPI async test client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def async_client():
    """
    ``httpx.AsyncClient`` connected to the Janus FastAPI app through
    ``ASGITransport`` — no network socket required.

    Skips the test automatically when httpx or ``backend.app`` cannot be
    imported (e.g., in a minimal CI environment without the full backend deps).
    """
    httpx = pytest.importorskip("httpx", reason="httpx not installed — skipping API tests")
    try:
        from backend.app import app  # noqa: PLC0415
    except ImportError:
        pytest.skip("backend.app not importable — skipping API tests")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client
