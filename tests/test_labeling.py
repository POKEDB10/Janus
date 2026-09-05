"""
tests/test_labeling.py
======================
Tests for DSCP bit-manipulation helpers and labeling verification tools.
"""

import pytest
from labeling.verify_dscp_propagation import _dscp_from_tos, _tos_from_dscp, DSCP_CLASSES


def test_dscp_and_tos_conversions():
    """Verify bit shift conversion between 6-bit DSCP and 8-bit TOS."""
    for cls_name, dscp_val in DSCP_CLASSES.items():
        tos = _tos_from_dscp(dscp_val)
        assert tos == (dscp_val << 2)
        recovered_dscp = _dscp_from_tos(tos)
        assert recovered_dscp == dscp_val


def test_specific_dscp_values():
    """Verify specific standard DSCP classes (EF = 46 -> TOS 184, AF41 = 34 -> TOS 136)."""
    assert _tos_from_dscp(46) == 184
    assert _dscp_from_tos(184) == 46

    assert _tos_from_dscp(0) == 0
    assert _dscp_from_tos(0) == 0

    assert _tos_from_dscp(34) == 136
    assert _dscp_from_tos(136) == 34
