# OT NSE Script Test Sandbox

Mock servers and sample output for testing improved OT NSE scripts.

## Quick Start

```bash
# Start mock servers (original)
python3 ot_mock_servers.py --all

# Start lesser-known protocol mock servers (individual)
python3 melsecq_mock_server.py
python3 opcua_mock_server.py
python3 proconos_mock_server.py
python3 gesrtp_mock_server.py
python3 redlion_mock_server.py
python3 ffhse_mock_server.py

# In another terminal, run tests
nmap -p 1911 --script ../improved-scripts/fox-info-improved.nse 127.0.0.1
nmap -p 1962 --script ../improved-scripts/pcworx-info-improved.nse 127.0.0.1
nmap -p 5094 --script ../improved-scripts/hartip-info-improved.nse 127.0.0.1
nmap -p 5007 --script ../improved-scripts/lesser-known/melsecq-info-improved.nse 127.0.0.1
nmap -p 4840 --script ../improved-scripts/lesser-known/opcua-discovery-improved.nse 127.0.0.1
nmap -p 20547 --script ../improved-scripts/lesser-known/proconos-info-improved.nse 127.0.0.1
nmap -p 18245 --script ../improved-scripts/lesser-known/gesrtp-info-improved.nse 127.0.0.1
nmap -p 1089 --script ../improved-scripts/lesser-known/ff-hse-discover-improved.nse 127.0.0.1

# Run all tests at once
./run_tests.sh
```

## Mock Servers

| Server | Port | Protocol | Status |
|--------|------|----------|--------|
| Fox    | 1911 | TCP      | ✅ Works |
| PCWorx | 1962 | TCP      | ✅ Works |
| HART-IP| 5094 | TCP      | ⚠️ Needs debug |
| Modbus | 502  | TCP      | ❌ Needs root |
| MMS    | 102  | TCP      | ❌ Needs root |
| PROFINET | 34964 | UDP    | ⚠️ Needs debug |
| **MELSEC-Q** | **5007** | **TCP** | **✅ Works** |
| **OPC UA** | **4840** | **TCP** | **✅ Works** |
| **ProConOS** | **20547** | **TCP** | **✅ Works** |
| **GE SRTP** | **18245** | **TCP** | **✅ Works** |
| **Red Lion** | **789** | **TCP** | **✅ Needs root (<1024)** |
| **FF HSE** | **1089** | **TCP** | **✅ Works** |

## Sample Output

The `output/` directory contains sample output for each improved script:

- `fox-info-improved.txt` — captured from live mock server
- `pcworx-info-improved.txt` — captured from live mock server
- `modbus-discover-improved.txt` — realistic sample (needs root for sandbox)
- `hartip-info-improved.txt` — realistic sample (WIP sandbox)
- `iec61850-mms-improved.txt` — realistic sample (needs root for sandbox)
- `profinet-cm-lookup-improved.txt` — realistic sample (WIP sandbox)

Test results for the new lesser-known protocol scripts are in `test-results/README.md`.

## Running with Privileged Ports

Ports 102, 502, and 789 require root. Use `sudo`:

```bash
sudo ./run_tests.sh --sudo
```

For Red Lion on port 789 specifically:
```bash
sudo python3 redlion_mock_server.py 127.0.0.1 789
```

## Mock Server Details

The mock servers simulate each OT protocol just enough to get a response from
the NSE scripts. They are:

- **Threaded** — handles one connection per thread
- **Minimal** — only respond to the exact probes the NSE scripts send
- **Loopback only** — bind to 127.0.0.1 or 0.0.0.0

### Architecture

```
ot_mock_servers.py
├── modbus_server()     → modbus_handle_client()   — TCP 502
├── hartip_server()     → hartip_handle_client()   — TCP 5094
├── fox_server()        → fox_handle_client()      — TCP 1911
├── pcworx_server()     → pcworx_handle_client()   — TCP 1962
├── mms_server()        → mms_handle_client()      — TCP 102
└── profinet_server()   (UDP)                      — UDP 34964

# Lesser-known protocol mock servers (standalone files):
├── melsecq_mock_server.py         — TCP 5007
├── opcua_mock_server.py           — TCP 4840
├── proconos_mock_server.py        — TCP 20547
├── gesrtp_mock_server.py          — TCP 18245
├── redlion_mock_server.py         — TCP 789
└── ffhse_mock_server.py           — TCP 1089
```

Each handler implements the minimum protocol exchange needed for the
corresponding NSE script to produce output.
