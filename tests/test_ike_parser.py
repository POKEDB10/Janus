"""
tests/test_ike_parser.py
========================
Tests for IKE handshake dissection, transform parsing, and fallback handling.
"""

import pytest
from pathlib import Path
from parsing.ike_parser import IKEParser, IKESession, Proposal, Transform


def test_fallback_ike_parser():
    """Verify fallback parser generates compliant representative IKEv2 session."""
    parser = IKEParser("non_existent_file.pcap")
    sessions = parser._fallback_parse()
    assert len(sessions) == 1
    s0 = sessions[0]
    assert s0.version == "IKEv2"
    assert s0.selected_proposal is not None
    assert s0.selected_proposal.encryption is not None
    assert "AES" in s0.selected_proposal.encryption.transform_id
    assert s0.selected_proposal.dh_group is not None
    assert s0.selected_proposal.dh_group.transform_id == "19"


def test_tshark_json_processing(sample_ike_tshark_json):
    """Verify parsing of structured tshark JSON packets into IKESession models."""
    parser = IKEParser("dummy.pcap")
    sessions = parser._process_tshark_json(sample_ike_tshark_json)
    
    assert len(sessions) == 1
    session = sessions[0]
    assert session.initiator_spi == "1234567890abcdef"
    assert session.responder_spi == "fedcba0987654321"
    assert len(session.proposals_offered) >= 1
    
    prop = session.proposals_offered[0]
    assert prop.encryption is not None
    assert "aes" in prop.encryption.transform_id.lower()
    assert prop.dh_group is not None
    assert "19" in prop.dh_group.transform_id or "ecp256" in prop.dh_group.transform_id.lower()


def test_weak_tshark_json_processing(sample_weak_ike_tshark_json):
    """Verify parsing of 3DES / MD5 / DH-2 weak IKE handshake from tshark JSON."""
    parser = IKEParser("dummy.pcap")
    sessions = parser._process_tshark_json(sample_weak_ike_tshark_json)
    
    assert len(sessions) == 1
    session = sessions[0]
    assert session.initiator_spi == "aabbccddeeff0011"
    assert len(session.proposals_offered) >= 1
    
    prop = session.proposals_offered[0]
    assert prop.encryption is not None
    assert "3" in prop.encryption.transform_id or "3des" in prop.encryption.transform_id.lower()
    assert prop.integrity is not None
    assert "md5" in prop.integrity.transform_id.lower() or "1" in prop.integrity.transform_id
