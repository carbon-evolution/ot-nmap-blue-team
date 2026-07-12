"""Mock-driven tests for the 7 "standard" OT NSE scripts.

All 7 protocols are emulated (or attempted) by the all-in-one mock
``sandbox/ot_mock_servers.py``, which binds FIXED ports and takes protocol
flags instead of ``--port`` -- hence every launch here uses
``inject_port=False``.

Verification status of the asserted field labels (see task report):
  * fox, pcworx  -> verified LIVE (mock + nmap) on this host; tests PASS.
  * modbus       -> verified by CODE-READING the mock response builder and the
                    NSE parser (port 502 needs root; cannot bind locally).
  * hartip       -> the published NSE has a redacted Command 0 payload
                    ("[REDACTED]" inside stdnse.fromhex), so it cannot complete
                    the exchange -> xfail.
  * profinet     -> PNIO-CM is UDP-only (portrule "udp" + nmap.new_socket("udp"));
                    the harness nmap_scan is TCP-only -> xfail.
  * mms          -> the mock's canned BER responses contain "[REDACTED]", so
                    bytes.fromhex() raises and no MMS PDU is returned even under
                    root -> xfail (also binds privileged port 102).
  * dnp3         -> ot_mock_servers.py has no DNP3 emulation -> xfail.
"""

import os

import pytest

from conftest import SCRIPTS, nmap_scan

MOCK = "ot_mock_servers.py"


def _script(name):
    return os.path.join(SCRIPTS, name)


# ── Unprivileged, verified LIVE ──────────────────────────────────────────────

def test_fox(mock_server):
    mock_server(MOCK, 1911, "--fox", inject_port=False)
    fields, out = nmap_scan(1911, _script("fox-info-improved.nse"))
    # Real labels emitted by fox-info-improved (verified live).
    assert fields.get("fox.version") == "1.0.1", out
    assert "hostname" in fields, out


def test_pcworx(mock_server):
    mock_server(MOCK, 1962, "--pcworx", inject_port=False)
    fields, out = nmap_scan(1962, _script("pcworx-info-improved.nse"))
    # Real labels emitted by pcworx-info-improved (verified live).
    assert fields.get("plc type") == "ILC 330 ETH", out
    assert "firmware version" in fields, out


# ── Privileged (port < 1024), verified by CODE-READING ───────────────────────

@pytest.mark.privileged
@pytest.mark.skipif(os.geteuid() != 0, reason="port <1024 needs root")
def test_modbus(mock_server):
    mock_server(MOCK, 502, "--modbus", inject_port=False)
    fields, out = nmap_scan(502, _script("modbus-discover-improved.nse"))
    # modbus-discover nests results under "sid 0x1"; parse_fields flattens the
    # labels. The mock answers Read Device Identification (func 0x2B) with
    # vendor "Schneider Elec", product "PM710", revision "v03.110".
    assert "device identification" in fields, out
    assert "Schneider Elec" in fields["device identification"], out


# ── xfail: script/mock cannot be faithfully driven by the TCP harness ────────

@pytest.mark.xfail(reason="published hartip NSE has a redacted ([REDACTED]) "
                          "Command 0 payload; fromhex yields nil so the "
                          "exchange cannot complete", strict=False)
def test_hartip(mock_server):
    mock_server(MOCK, 5094, "--hartip", inject_port=False)
    fields, out = nmap_scan(5094, _script("hartip-info-improved.nse"))
    # Real label if the script could complete Command 0.
    assert "manufacturer id" in fields, out


@pytest.mark.xfail(reason="profinet-cm is UDP-only (portrule 'udp'); harness "
                          "nmap_scan is TCP-only", strict=False)
def test_profinet(mock_server):
    mock_server(MOCK, 34964, "--profinet", inject_port=False)
    fields, out = nmap_scan(34964, _script("profinet-cm-lookup-improved.nse"))
    assert "devicename" in fields, out


@pytest.mark.privileged
@pytest.mark.xfail(reason="ot_mock_servers MMS responses are redacted "
                          "([REDACTED]); bytes.fromhex raises so no MMS PDU is "
                          "returned even as root (also binds privileged port 102)",
                   strict=False)
def test_mms(mock_server):
    mock_server(MOCK, 102, "--mms", inject_port=False)
    fields, out = nmap_scan(102, _script("iec61850-mms-improved.nse"))
    assert "vendorname" in fields, out


@pytest.mark.xfail(reason="ot_mock_servers.py provides no DNP3 emulation "
                          "(no --dnp3 flag)", strict=False)
def test_dnp3(mock_server):
    mock_server(MOCK, 20000, "--dnp3", inject_port=False)
    fields, out = nmap_scan(20000, _script("dnp3-advanced-info.nse"))
    assert "source address" in fields, out
