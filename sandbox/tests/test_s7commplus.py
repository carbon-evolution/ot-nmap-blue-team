import os
import pytest
from conftest import SCRIPTS, nmap_scan

SCRIPT = os.path.join(SCRIPTS, "s7comm-plus-info-improved.nse")

pytestmark = pytest.mark.privileged
not_root = os.geteuid() != 0
skip_reason = "port 102 (<1024) needs root"


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_s7commplus_extracts_module(mock_server):
    mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1200")
    fields, out = nmap_scan(102, SCRIPT)
    assert "module" in fields, out
    assert "6ES7 212" in fields["module"], out
    assert "version" in fields, out
    assert fields["version"] == "4.4.0", out


@pytest.mark.skipif(not_root, reason=skip_reason)
def test_s7commplus_profiles_differ(mock_server):
    m = mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1200")
    a, _ = nmap_scan(102, SCRIPT)
    m.stop()
    mock_server("s7commplus_mock_server.py", 102, "--profile", "s7_1500")
    b, _ = nmap_scan(102, SCRIPT)
    assert a.get("module") != b.get("module"), (a, b)
