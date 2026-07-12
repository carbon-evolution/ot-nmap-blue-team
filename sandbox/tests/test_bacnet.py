import os
import pytest
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "bacnet-discover-improved.nse")

pytestmark = pytest.mark.privileged
not_root = os.geteuid() != 0
skip_reason = "UDP scan (-sU) needs root"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_bacnet_extracts_device(mock_server):
    mock_server("bacnet_mock_server.py", 47808, "--profile", "automated_logic")
    fields, out = nmap_scan(47808, SCRIPT, udp=True)
    assert "vendor" in fields, out
    assert "Automated Logic" in fields["vendor"], out
    assert "model name" in fields, out
    assert fields["model name"] == "LGR1000", out


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_bacnet_profiles_differ(mock_server):
    m = mock_server("bacnet_mock_server.py", 47808, "--profile", "automated_logic")
    a, _ = nmap_scan(47808, SCRIPT, udp=True)
    m.stop()
    mock_server("bacnet_mock_server.py", 47808, "--profile", "siemens_bas")
    b, _ = nmap_scan(47808, SCRIPT, udp=True)
    assert a.get("model name") != b.get("model name"), (a, b)
