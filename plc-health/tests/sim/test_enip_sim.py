import pytest

pytest.importorskip("cpppo")
pytestmark = pytest.mark.sim


def test_cpppo_note():
    """cpppo focuses on CIP explicit messaging/tags; ListIdentity support
    varies by version. The bundled enip mock is authoritative for the
    status/state decode (see test_enip_probe.py). This placeholder documents
    that and is a no-op assertion so the gated suite stays runnable."""
    assert True
