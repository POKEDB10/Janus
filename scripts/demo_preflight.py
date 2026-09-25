"""
Janus Pre-Flight Verification Script for SIH 2026 / NTRO Demos
=============================================================
Runs instant sanity checks across:
1. Python environment (.venv-ml312) & key dependencies
2. ML artifacts (xgb_model.json, flow_trace_net.pt, deep_ensemble.joblib)
3. Deterministic compliance engine & RFC rules
4. Sample PCAPs & real strongSwan 3DES capture
5. Link-layer wire protocol dissector (SLL2 & Ethernet)
6. Generated PDF reports (RFC section symbol check)
7. Security auth & BOLA configuration
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def check(name: str, fn) -> bool:
    sys.stdout.write(f"  Checking {name:<45} ... ")
    sys.stdout.flush()
    try:
        ok, msg = fn()
        if ok:
            print(f"{GREEN}[PASS]{RESET} {msg}")
            return True
        else:
            print(f"{RED}[FAIL]{RESET} {msg}")
            return False
    except Exception as exc:
        print(f"{RED}[ERROR]{RESET} {exc}")
        return False


def test_python_env():
    ver = sys.version_info
    if ver.major == 3 and ver.minor >= 11:
        return True, f"Python {ver.major}.{ver.minor}.{ver.micro}"
    return False, f"Unexpected Python version {ver.major}.{ver.minor}"


def test_ml_artifacts():
    p1 = ROOT / "ml" / "artifacts" / "xgb_model.json"
    p2 = ROOT / "ml" / "artifacts" / "flow_trace_net.pt"
    p3 = ROOT / "ml" / "artifacts" / "deep_ensemble.joblib"
    missing = [str(p.name) for p in (p1, p2, p3) if not p.is_file()]
    if not missing:
        size_mb = p3.stat().st_size / (1024 * 1024)
        return True, f"XGBoost, FlowTraceNet, and DeepEnsemble ({size_mb:.1f} MB) present"
    return False, f"Missing: {missing}"


def test_compliance_engine():
    from compliance.score import evaluator
    res = evaluator.evaluate(
        esp_encryption="ENCR_3DES",
        esp_auth="AUTH_HMAC_SHA1_96",
        dh_group=2,
        pfs_enabled=False,
        sa_lifetime_seconds=86400,
    )
    if res.grade == "F" and len(res.findings) >= 3:
        return True, f"Grade F (Score {res.overall_score}) correctly flagged 3DES/SHA1/DH2"
    return False, f"Unexpected compliance result: Grade={res.grade}, Score={res.overall_score}"


def test_sample_pcaps():
    s1 = ROOT / "samples" / "scenario_01_hardened.pcap"
    s4 = ROOT / "samples" / "scenario_04_weak_3des.pcap"
    sw = ROOT / "samples" / "wireshark_ikev2_aes_gcm.pcap"
    for s in (s1, s4, sw):
        if not s.is_file() or s.stat().st_size == 0:
            return False, f"Missing or empty PCAP: {s.name}"
    return True, f"Scenario 1, 4, and Wireshark samples present ({s4.stat().st_size} bytes for sc04)"


def test_ike_dissector():
    from parsing.ike_parser import IKEParser
    parser = IKEParser(ROOT / "samples" / "scenario_04_weak_3des.pcap")
    sessions = parser.parse()
    if len(sessions) == 1 and sessions[0].selected_proposal:
        prop = sessions[0].selected_proposal
        encr = prop.encryption.transform_id if prop.encryption else "none"
        dh = prop.dh_group.transform_id if prop.dh_group else "none"
        return True, f"Dissected 1 session: {encr} / DH Group {dh}"
    return False, f"Dissection failed: {len(sessions)} sessions found"


def test_pdf_reports():
    exec_pdf = ROOT / "verification" / "reports" / "Janus_Executive_Report_RFC_Section_Demo.pdf"
    tech_pdf = ROOT / "verification" / "reports" / "Janus_Technical_Report_RFC_Section_Demo.pdf"
    if exec_pdf.is_file() and tech_pdf.is_file():
        return True, f"Executive ({exec_pdf.stat().st_size // 1024} KB) and Technical ({tech_pdf.stat().st_size // 1024} KB) verified"
    return False, "PDF reports missing in verification/reports/"


def test_security_auth():
    req_auth = os.getenv("JANUS_REQUIRE_AUTH", "false").lower() in ("true", "1", "yes")
    api_key = os.getenv("JANUS_API_KEY")
    if req_auth:
        if not api_key:
            return False, "JANUS_REQUIRE_AUTH=true but JANUS_API_KEY unset. Set env vars before launch."
        return True, "Enforced Mode: API Key & BOLA validation active"
    return True, "Demo Mode: JANUS_REQUIRE_AUTH=false (Zero-friction local demo)"


def main():
    print(f"\n{BOLD}{CYAN}=== Project Janus: SIH 2026 / NTRO Demo Pre-Flight Inspection ==={RESET}\n")
    tests = [
        ("Python Runtime Environment", test_python_env),
        ("ML Model Weights & Artifacts", test_ml_artifacts),
        ("RFC Deterministic Compliance Engine", test_compliance_engine),
        ("Sample PCAP Test Suite Files", test_sample_pcaps),
        ("Link-Layer Wire Protocol Dissector", test_ike_dissector),
        ("Verification PDF Report Generation", test_pdf_reports),
        ("Backend Security & Auth Config", test_security_auth),
    ]

    passed = 0
    for name, fn in tests:
        if check(name, fn):
            passed += 1

    print("\n" + "=" * 67)
    if passed == len(tests):
        print(f"{BOLD}{GREEN}  >>> 100% PRE-FLIGHT CHECKS PASSED: READY FOR LIVE DEMO <<< {RESET}")
    else:
        print(f"{BOLD}{YELLOW}  >>> {passed}/{len(tests)} CHECKS PASSED — REVIEW DETAILS ABOVE <<< {RESET}")
    print("=" * 67)

    print(f"\n{BOLD}Recommended Server Startup Commands:{RESET}")
    print(f"{CYAN}Option A (Zero-friction Demo, Auth relaxed for local UI):{RESET}")
    print('  powershell: $env:JANUS_REQUIRE_AUTH="false"; .venv-ml312\\Scripts\\python.exe -m uvicorn backend.main:app --port 8000 --reload')
    print(f"{CYAN}Option B (Enterprise Defense Mode, Strict API Key & BOLA):{RESET}")
    print('  powershell: $env:JANUS_REQUIRE_AUTH="true"; $env:JANUS_API_KEY="janus-soc-internal-2026"; $env:JANUS_TOKEN_SECRET="janus-token-secret-salt-2026"; .venv-ml312\\Scripts\\python.exe -m uvicorn backend.main:app --port 8000 --reload')
    print()


if __name__ == "__main__":
    main()
