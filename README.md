# OT Nmap Blue Team — Improved NSE Scripts for OT/ICS Protocol Discovery

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Honeypot-Grade](https://img.shields.io/badge/Honeypot-Grade-purple)](sandbox/)
[![NSE](https://img.shields.io/badge/NSE-16%20scripts-blue)](improved-scripts/)

<p align="center">
  <img src="banner.png" alt="OT Nmap Blue Team — Honeypot-Grade ICS Protocol Emulation" width="100%">
</p>

A collection of **improved Nmap NSE (Scripting Engine) scripts** for discovering, fingerprinting, and auditing OT/ICS (Operational Technology / Industrial Control Systems) protocols. Designed for **blue-team security assessments**, asset inventory, and vulnerability management.

> ⚡ **Honeypot-Grade Mock Servers**: All 9 standalone protocol servers (GE SRTP, OPC UA, Red Lion, FF HSE, MELSEC-Q, ProConOS, EtherNet/IP, BACnet/IP, S7comm-plus) are built as **production-quality honeypots** — full protocol state machines, profile-based device identities, register/tag read-write, alarm engines, detection logging, and scan delay simulation. See [sandbox README](sandbox/) for details.

Covers **16 protocol families** including DNP3, Modbus, Fox, PCWorx, HART-IP, IEC 61850 MMS, PROFINET, EtherNet/IP CIP, BACnet/IP, S7comm-plus, GE SRTP, OPC UA, MELSEC-Q, ProConOS, Red Lion Crimson, and Foundation Fieldbus HSE.

> ⚠️ **DISCLAIMER**: These scripts are provided for **authorized security assessments only**. You MUST test these scripts in a **controlled lab environment first** before using them on any operational network. Running these scripts against production OT systems may cause unexpected behavior. The authors assume no liability for misuse or damage.

---

## Table of Contents

- [Getting Started](#-getting-started)
- [Blue Team Purpose](#-blue-team-purpose)
- [Script Catalog](#-script-catalog)
- [What Information Can These Scripts Extract?](#-what-information-can-these-scripts-extract)
- [Nmap Script Location by OS](#-nmap-script-location-by-os)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [Testing with Mock Servers](#-testing-with-mock-servers)
- [Automated Tests & CI](#-automated-tests--ci)
- [Asset Inventory Pipeline](#-asset-inventory-pipeline)
- [Methodology & Safety](#-methodology--safety)
- [Project Structure](#-project-structure)
- [Changelog](#-changelog)
- [License](#-license)

---

## 🚦 Getting Started

This repo has **three things you can do**. Pick the one that matches your goal.

**Requirements:** `nmap` (7.9+), `python3` (3.8+). No Python packages to install — everything is standard library. `luac`/`lua5.4` is optional (only for the syntax gate).

```bash
git clone https://github.com/carbon-evolution/ot-nmap-blue-team.git
cd ot-nmap-blue-team
```

### 1. Scan real OT devices (the NSE scripts)

Point the improved scripts at a device or subnet. Everything is **T1-safe / read-only** — identity queries only. See [Installation](#-installation) to copy the scripts into nmap's search path, or run them by full path:

```bash
# One protocol, one host
nmap -p 44818 --script improved-scripts/enip-identity-improved.nse 192.168.1.50

# All 16 protocols across a subnet (see Usage Examples for the full command)
nmap -sU -sT -p T:44818,502,102,1911,1962,5094,20000,5007,4840,18245,20547,1089,789,U:47808,34964 \
  --script improved-scripts/,improved-scripts/lesser-known/ 192.168.1.0/24
```
> UDP protocols (BACnet 47808, PROFINET 34964) and privileged ports (< 1024, e.g. Modbus 502, MMS/S7comm 102, Red Lion 789) require running nmap as **root/sudo**.

### 2. Try it safely against the honeypot mocks (no real hardware)

Every script has a Python **honeypot mock** so you can see it work with zero risk:

```bash
# Terminal A — start a mock device
python3 sandbox/enip_mock_server.py --port 44818 --profile controllogix

# Terminal B — scan it
nmap -p 44818 --script improved-scripts/enip-identity-improved.nse 127.0.0.1
```
See [Testing with Mock Servers](#-testing-with-mock-servers). To run the full automated test suite, see [Automated Tests & CI](#-automated-tests--ci).

### 3. Build an asset inventory (the pipeline)

Turn scan results into a normalized, CVE-annotated **asset inventory** (JSON/CSV):

```bash
# Parse a saved nmap XML (capture one with:  nmap ... -oX scan.xml)
python3 -m assetinv parse scan.xml --cve

# Or scan and inventory in one step
python3 -m assetinv scan 192.168.1.50 --ports 44818 \
  --script improved-scripts/enip-identity-improved.nse --cve --format csv -o inventory.csv
```
See [Asset Inventory Pipeline](#-asset-inventory-pipeline). Run `python3 -m assetinv` from the `asset-inventory/` directory (or add it to `PYTHONPATH`).

---

## 🛡 Blue Team Purpose

These scripts are intended for **defensive security purposes**:

- **Asset Inventory**: Discover and identify OT devices on your network — PLCs, RTUs, HMIs, IEDs, historians
- **Vulnerability Management**: Identify firmware versions and model numbers to correlate against known CVEs
- **Change Detection**: Monitor for unauthorized devices or configuration changes in OT environments
- **Network Segmentation Verification**: Confirm that only authorized OT protocols are accessible from IT zones
- **Incident Response**: Rapidly fingerprint OT devices during a security incident
- **Compliance Auditing**: Validate that OT asset inventories are accurate and up-to-date

### ❌ NOT for Offensive Use

These are **T1-safe (read-only)** scripts that query device identification information. They do NOT:
- Modify device configuration
- Write to device memory
- Start/stop industrial processes
- Attempt authentication bypass or exploitation

However, any network scan carries inherent risk. **Always test in a lab first.**

---

## 📜 Script Catalog

### Standard OT Protocols (`improved-scripts/`)

| Script | Protocol | Port | Extracts |
|--------|----------|------|----------|
| `dnp3-advanced-info.nse` | DNP3 | TCP 20000 | Device attributes, DNP3 version, application level, object support |
| `modbus-discover-improved.nse` | Modbus | TCP 502 | Device ID, vendor name, product code, major/minor revision |
| `fox-info-improved.nse` | Fox (Tunneling) | TCP 1911 | Fox protocol version, device name, vendor |
| `pcworx-info-improved.nse` | PCWorx | TCP 1962 | PLC model, firmware, runtime version |
| `hartip-info-improved.nse` | HART-IP | TCP 5094 | Device type, manufacturer ID, HART revision, device ID |
| `iec61850-mms-improved.nse` | IEC 61850 MMS | TCP 102 | Logical device nodes, server identity, model name |
| `profinet-cm-lookup-improved.nse` | PROFINET CM | UDP 34964 | Station name, vendor, device type, IP config |
| `enip-identity-improved.nse` | EtherNet/IP CIP | TCP 44818 | Vendor, product name, serial number, device type, product code, revision, device state |
| `bacnet-discover-improved.nse` | BACnet/IP | UDP 47808 | Vendor (name + id), model name, firmware, application software, object name, location, description |
| `s7comm-plus-info-improved.nse` | S7comm-plus (S7-1200/1500) | TCP 102 | Module (order/MLFB), module type, firmware version, serial number, system name |

### Lesser-Known OT Protocols (`improved-scripts/lesser-known/`)

| Script | Protocol | Port | Extracts |
|--------|----------|------|----------|
| `gesrtp-info-improved.nse` | GE SRTP | TCP 18245 | PLC model (e.g. IC695CPE302), firmware version (e.g. V9.50), CPU type, status |
| `opcua-discovery-improved.nse` | OPC UA | TCP 4840 | Application name, application URI, product URI, gateway server URI, discovery profiles, available endpoints |
| `melsecq-info-improved.nse` | MELSEC-Q | TCP 5007 | PLC type (e.g. Q03UDVCPU), series name, firmware version |
| `proconos-info-improved.nse` | ProConOS | TCP 20547 | Runtime version (e.g. ProConOS V3.0.1040), PLC model (e.g. ADAM5510KW), project name, source code status |
| `ff-hse-discover-improved.nse` | FF HSE | TCP 1089 | Device name, vendor name, device tag, HSE version, software revision, stack version, MAC address |
| `redlion-cr3-info-improved.nse` | Red Lion Crimson | TCP 789 | Model (e.g. G310C2), firmware (e.g. Crimson 3.2), part number, vendor name |

---

## 🔍 What Information Can These Scripts Extract?

| Script | Output Fields |
|--------|---------------|
| `dnp3-advanced-info` | Device attributes, DNP3 versions, object types, application layer info, supported functions |
| `modbus-discover-improved` | Device ID, Vendor, Product Code, Major/Minor Revision |
| `fox-info-improved` | Protocol version, Device Name, Vendor |
| `pcworx-info-improved` | PLC Model, Firmware, Runtime |
| `hartip-info-improved` | Device Type, Manufacturer, HART Revision, Device ID |
| `iec61850-mms-improved` | Logical Device Nodes, Server Identity, Model |
| `profinet-cm-lookup-improved` | Station Name, Vendor, Device Type, IP Config |
| `enip-identity-improved` | **Vendor**, **Product Name**, **Serial Number**, **Device Type**, **Product Code**, **Revision**, **Device State** |
| `bacnet-discover-improved` | **Vendor**, **Model Name**, **Firmware**, **Application Software**, **Object Name**, **Location**, **Description** |
| `s7comm-plus-info-improved` | **Module**, **Module Type**, **Version**, **Serial Number**, **System Name** |
| `gesrtp-info-improved` | **PLC Model**, **Firmware Version**, **CPU Type**, **PLC Status** |
| `opcua-discovery-improved` | **Application Name**, **Application URI**, **Product URI**, **Endpoints** |
| `melsecq-info-improved` | **PLC Type**, **Series**, **Firmware** |
| `proconos-info-improved` | **Runtime**, **PLC Model**, **Project Name**, **Source Status** |
| `ff-hse-discover-improved` | **Device Name**, **Vendor**, **Device Tag**, **HSE Version**, **Software Rev**, **Stack** |
| `redlion-cr3-info-improved` | **Model**, **Firmware**, **Part Number**, **Vendor** |

---

## 📂 Nmap Script Location by OS

### Linux (Debian/Ubuntu)
```bash
# System-wide installation (requires root)
/usr/share/nmap/scripts/

# User-local installation
~/.nmap/scripts/
```

### Linux (Red Hat / Fedora / CentOS)
```bash
# System-wide installation (requires root)
/usr/share/nmap/scripts/

# User-local installation
~/.nmap/scripts/
```

### macOS (Homebrew)
```bash
# System-wide installation
/opt/homebrew/share/nmap/scripts/    # Apple Silicon (M1/M2/M3/M4)
/usr/local/share/nmap/scripts/       # Intel

# User-local installation
~/.nmap/scripts/
```

### Windows
```batch
:: System-wide (Nmap installed in Program Files)
C:\Program Files\Nmap\scripts\

:: User-local
%USERPROFILE%\.nmap\scripts\
```

---

## 📥 Installation

### Option 1: Quick Copy (Recommended)

```bash
# Clone the repo
git clone https://github.com/carbon-evolution/ot-nmap-blue-team.git
cd ot-nmap-blue-team

# Copy scripts to nmap directory
# Linux:
cp improved-scripts/*.nse ~/.nmap/scripts/
cp improved-scripts/lesser-known/*.nse ~/.nmap/scripts/

# macOS (Apple Silicon):
cp improved-scripts/*.nse ~/.nmap/scripts/
cp improved-scripts/lesser-known/*.nse ~/.nmap/scripts/

# Update script database
nmap --script-updatedb

# Verify installation
nmap --script-help dnp3-advanced-info
```

### Option 2: Run Directly (No Installation)

```bash
# Run without copying (specify full path)
nmap -p 502 --script /path/to/modbus-discover-improved.nse <target>
```

---

## 🚀 Usage Examples

### Basic Host Scan
```bash
# Scan a single host for all 16 supported OT protocols (TCP + UDP).
# Needs root/sudo for the UDP scan (-sU) and the privileged ports (<1024).
sudo nmap -sT -sU \
  -p T:502,1911,1962,5094,102,20000,44818,18245,20547,1089,789,4840,5007,U:47808,34964 \
  --script improved-scripts/,improved-scripts/lesser-known/ \
  <target>
```
> `--script improved-scripts/,improved-scripts/lesser-known/` loads every `.nse` in those folders; nmap runs only the ones whose port/service matches. If you copied the scripts into nmap's search path (see [Installation](#-installation)), you can use the script names instead of paths.

### Scan Specific Protocol
```bash
# OPC UA discovery
nmap -p 4840 --script opcua-discovery-improved.nse 192.168.1.100

# GE SRTP PLC identification
nmap -p 18245 --script gesrtp-info-improved.nse 192.168.1.100

# MELSEC-Q PLC info
nmap -p 5007 --script melsecq-info-improved.nse 192.168.1.100
```

### Subnet Scan
```bash
# Scan an entire OT subnet; -oA saves normal/grepable/XML (ot-scan.xml feeds
# the asset-inventory pipeline below).
sudo nmap -sT -sU \
  -p T:502,1911,1962,5094,102,20000,44818,18245,20547,1089,789,4840,5007,U:47808,34964 \
  --script improved-scripts/,improved-scripts/lesser-known/ \
  --open -oA ot-scan \
  192.168.1.0/24

# Then build the inventory from the XML nmap just wrote:
python3 -m assetinv parse ot-scan.xml --cve -o inventory.json
```

### Sample Output
```
PORT      STATE  SERVICE
4840/tcp  open   opcua-tcp
| opcua-discovery-improved:
|   Application Name: OPC UA Mock Server
|   Application URI: urn:OPCUA:MockServer
|   Product URI: urn:OPCUA:MockServer:product
|   Gateway Server URI: urn:OPCUA:MockServer:gateway
|   Discovery Profile: http://opcfoundation.org/UA-Profile/Discovery/Register
|_  Endpoints available: 2

PORT      STATE  SERVICE
18245/tcp open   ge-srtp
| gesrtp-info-improved:
|   PLC Model: GE PACSystems RX3i
|   Firmware Version: V9.50
|   CPU Type: IC695CPE302
|_  PLC Status: Running

PORT      STATE  SERVICE
789/tcp  open   redlion-crimson
| redlion-cr3-info-improved:
|   Model: G310C2
|   Firmware: Crimson 3.2
|   Part Number: MNGR-BASE
|_  Vendor: Red Lion Controls
```

---

## 🧪 Testing with Mock Servers

> 🔥 **Honeypot-Grade Emulation**: 9 of the protocol servers are built as full-fledged **honeypots** — complete state machines, profile-based device identities, session tracking, memory/register read-write, alarm engines, and structured detection logging. They're indistinguishable from real OT devices during NSE scanning.

This repository includes Python mock servers for every NSE script, enabling safe testing without connecting to real OT devices.

### Prerequisites
```bash
python3          # Any recent Python 3.x
nmap             # For running the NSE scripts
```

### Quick Test
```bash
cd sandbox/

# Start the 6 lesser-known honeypot servers
# NOTE: Red Lion listens on TCP 789 (a privileged port), so its server
# must be started with sudo. The NSE portrule is pinned to 789.
python3 melsecq_mock_server.py --port 5007 &
python3 opcua_mock_server.py --port 4840 --profile siemens_s7 &
python3 gesrtp_mock_server.py --port 18245 --profile rx3i &
sudo python3 redlion_mock_server.py --port 789 --model G310C2 &
python3 ffhse_mock_server.py --port 1089 --profile flow &
python3 proconos_mock_server.py --port 20547 &

# In another terminal, run NSE tests against all 6
nmap -p 5007 --script ../improved-scripts/lesser-known/melsecq-info-improved.nse 127.0.0.1
nmap -p 4840 --script ../improved-scripts/lesser-known/opcua-discovery-improved.nse 127.0.0.1
nmap -p 18245 --script ../improved-scripts/lesser-known/gesrtp-info-improved.nse 127.0.0.1
nmap -p 789 --script ../improved-scripts/lesser-known/redlion-cr3-info-improved.nse 127.0.0.1
nmap -p 1089 --script ../improved-scripts/lesser-known/ff-hse-discover-improved.nse 127.0.0.1
nmap -p 20547 --script ../improved-scripts/lesser-known/proconos-info-improved.nse 127.0.0.1

# Clean up
kill %1 %2 %3 %4 %5 %6
```

### Mock Server Reference

All 9 standalone protocol servers are built to **honeypot-grade** — they go beyond static responses with realistic state machines, profile-based device identities, detection logging, and scan delay simulation.

| Mock Server | Protocol | Port | Honeypot Features | Notes |
|-------------|----------|------|-------------------|-------|
| `ot_mock_servers.py` | All standard protocols | Various | — | All-in-one server (thin/legacy) |
| `melsecq_mock_server.py` | MELSEC-Q | 5007 | Profiles, detection logging, scan delay | Standalone |
| `opcua_mock_server.py` | OPC UA | 4840 | Full HEL→ACK→OPN→MSG→CLO state machine, FindServers/GetEndpoints/Read/Browse/Write handlers, 3 profiles, address space, detection logging | Standalone |
| `proconos_mock_server.py` | ProConOS | 20547 | Profiles, detection logging, scan delay | Standalone |
| `gesrtp_mock_server.py` | GE SRTP | 18245 | Full INIT→REQ state machine, SSTAT/LSTAT/CONFIG_INFO/MEM_READ/MEM_WRITE services, 3 profiles, connection tracking, detection logging, UDP support | Standalone |
| `ffhse_mock_server.py` | FF HSE | 1089 | SM_IDENTIFY/MA_IDENTIFY/LREQ/LRES/LFIN/FMS_READ handlers, alarm engine, PV drift simulation, 4 profiles, detection logging | Standalone |
| `redlion_mock_server.py` | Red Lion | 789 | Per-profile device identity + tag database, STX command set (read/write tags, login, config), write tag logging (0x12), scan delay, 4 profiles | Requires root (<1024) |
| `enip_mock_server.py` | EtherNet/IP CIP | 44818 | ListIdentity (0x0063) CPF Identity response, 3 profiles (ControlLogix/Micro850/OMRON NX), detection logging, scan delay, SIGTERM shutdown | Standalone |
| `bacnet_mock_server.py` | BACnet/IP | 47808/udp | ReadProperty answers for 8 Device-object identity properties (char-string + unsigned tags), 3 BAS profiles, TCP readiness listener, detection logging | Standalone (UDP) |
| `s7commplus_mock_server.py` | S7comm-plus | 102 | COTP CR/CC + S7comm setup + SZL 0x11/0x1C identity responses at fixed offsets, 2 profiles (S7-1200/1500), detection logging | Requires root (<1024) |

### What Makes Them Honeypot-Grade

The 9 standalone servers go far beyond simple canned responses:

| Capability | What It Means |
|------------|---------------|
| **Full protocol state machines** | Multi-message handshakes (OPC UA: HEL→ACK→OPN→MSG→CLO, GE SRTP: INIT→REQ→ACK, FF HSE: LREQ→LRES→LFIN) not just single-shot replies |
| **Profile-based device identity** | Each `--profile` changes the device model, vendor, firmware, serial number, MAC address — emulating different real products |
| **Memory & register read/write** | GE SRTP MEM_READ/MEM_WRITE (services 15/16), OPC UA Read/Browse/Write (services 631/525/634), Red Lion tag read/write (commands 0x02/0x12) |
| **Per-profile tag databases** | Red Lion has 4 profile-specific HMI tag sets (TankLevel, PumpSpeed, Temperature, etc.) with realistic float/int/bool values |
| **Alarm engines** | FF HSE generates simulated process alarms (HI_TEMP, HH_PRESSURE, SENSOR_FAIL) with weighted severity and active alarm reporting via LRES |
| **Detection logging** | Every connection, probe, service request, and tag read/write is timestamped and logged with DETECTION severity — ready for SIEM ingestion |
| **Scan delay simulation** | Random 5–200ms response jitter per protocol to avoid script-like instant replies that fingerprint mock servers |
| **Graceful degradation** | TCP fragmentation handling (`recv_exactly`), connection reset recovery, proper error codes for invalid requests — behaves like a real device |

### Test Results

All 16 scripts have been tested against their corresponding mock servers. See `sandbox/test-results/README.md` for detailed output.

### ✅ Automated Tests & CI

A `pytest` harness in `sandbox/tests/` boots each mock server as a subprocess, runs the matching NSE script against it with real `nmap`, and asserts that the script extracts the expected named fields — and, for profile-capable devices, that different device profiles produce different output. GitHub Actions runs a `luac -p` syntax gate over all 16 scripts plus the full suite on every push and pull request.

```bash
cd sandbox/tests
pip install -r requirements.txt
python3 -m pytest -m "not privileged" -v      # scripts on ports > 1024, no root needed
sudo python3 -m pytest -m privileged -v        # Red Lion (789), Modbus (502), MMS (102)
```

Tests marked `privileged` bind a port below 1024 or require a UDP scan (`nmap -sU`), and are skipped unless run as root (they run as root in CI) — this covers Red Lion, Modbus, IEC 61850 MMS, S7comm-plus (TCP < 1024) and BACnet/IP (UDP). A few standard-protocol tests are declared `xfail` with an explicit reason — HART-IP and MMS because the published mock/script payloads are redacted; DNP3 has no emulation in the all-in-one mock; and PROFINET-CM because its NSE parses the pcap layer-3 frame while the all-in-one mock encodes fields at payload-relative offsets (a byte-offset mismatch). Every one of the 16 scripts has a test, so a parser regression or a field-label mismatch turns the CI run red.

---

## 📋 Asset Inventory Pipeline

The [`asset-inventory/`](asset-inventory/) package (`assetinv`) turns raw scan results from these 16 scripts into a normalized, CVE-annotated **asset inventory** — JSON or CSV. It parses nmap's `-oX` XML, maps each script's fields into a canonical device schema, and (optionally) correlates against an offline curated ICS-CVE bundle. Standard library only.

```bash
# Parse a captured nmap XML into a CVE-annotated inventory
python3 -m assetinv parse scan.xml --cve

# Or run a live scan end-to-end
python3 -m assetinv scan 10.0.0.5 --ports 44818 \
    --script improved-scripts/enip-identity-improved.nse --cve --format csv -o inventory.csv
```

CVE hints are **non-authoritative** ("verify against vendor/CISA advisories") and sourced from a bundled, editable JSON file. See the [asset-inventory README](asset-inventory/README.md) for the schema, the bundle format, and how to update it. This is Phase 3 of the project.

---

## 🧭 Methodology & Safety

### Threat Level Classification

| Level | Description | Allowed by These Scripts |
|-------|-------------|-------------------------|
| **T1 (Basic Read)** | Read device identity only | ✅ Yes — all scripts are T1-safe |
| **T2 (Advanced Read)** | Read configuration, logs | ❌ No |
| **T3 (Basic Write)** | Modify non-critical settings | ❌ No |
| **T4 (Advanced Write)** | Modify critical parameters | ❌ No |

### Best Practices for OT Scanning

1. **Test first**: Always run scripts against mock servers (included) before any live scan
2. **Start narrow**: Scan a single host, single protocol first to verify expected output
3. **Rate limit**: Use `--max-rate 10 --scan-delay 1s` to avoid overwhelming devices
4. **Log everything**: Always use `-oA <output_prefix>` to save results
5. **Coordinate**: Inform OT stakeholders before any scan
6. **Document**: Keep records of what was scanned, when, and why

```bash
# Safe scan template
nmap -p <ports> --script <scripts> --max-rate 10 --scan-delay 1s -oA ot-scan <target>
```

---

## 📁 Project Structure

```
ot-nmap-blue-team/
├── LICENSE                       # MIT License
├── README.md                     # This file
├── .gitignore
├── .github/workflows/ci.yml      # GitHub Actions: luac gate + pytest suites
│
├── improved-scripts/             # 16 NSE scripts (standard protocols)
│   ├── dnp3-advanced-info.nse
│   ├── modbus-discover-improved.nse
│   ├── fox-info-improved.nse
│   ├── pcworx-info-improved.nse
│   ├── hartip-info-improved.nse
│   ├── iec61850-mms-improved.nse
│   ├── profinet-cm-lookup-improved.nse
│   ├── enip-identity-improved.nse        # Phase 2: EtherNet/IP CIP
│   ├── bacnet-discover-improved.nse      # Phase 2: BACnet/IP
│   ├── s7comm-plus-info-improved.nse     # Phase 2: S7comm-plus
│   │
│   └── lesser-known/             # NSE scripts (lesser-known protocols)
│       ├── gesrtp-info-improved.nse
│       ├── opcua-discovery-improved.nse
│       ├── melsecq-info-improved.nse
│       ├── proconos-info-improved.nse
│       ├── ff-hse-discover-improved.nse
│       └── redlion-cr3-info-improved.nse
│
├── sandbox/                      # Honeypot mock servers + pytest harness
│   ├── ot_mock_servers.py        # all-in-one (standard protocols)
│   ├── melsecq_mock_server.py    # 9 standalone honeypot mocks:
│   ├── opcua_mock_server.py
│   ├── proconos_mock_server.py
│   ├── gesrtp_mock_server.py
│   ├── ffhse_mock_server.py
│   ├── redlion_mock_server.py
│   ├── enip_mock_server.py       # Phase 2
│   ├── bacnet_mock_server.py     # Phase 2
│   ├── s7commplus_mock_server.py # Phase 2
│   └── tests/                    # Phase 1: pytest mock-driven suite
│       ├── conftest.py           # mock_server + nmap_scan fixtures
│       └── test_*.py             # one per script
│
├── asset-inventory/              # Phase 3: scan -> inventory pipeline
│   ├── assetinv/                 # stdlib package (runner/parser/normalizer/
│   │   └── data/ics_cve_hints.json #   cve/export/cli) + offline CVE bundle
│   ├── tests/                    # unit + end-to-end integration tests
│   └── README.md
│
├── docs/superpowers/             # Design specs + implementation plans (per phase)
│   ├── specs/
│   └── plans/
│
├── scada-tools/                  # Third-party SCADA tools (reference)
├── ICS-Discovery-Tools/          # Community ICS discovery scripts
└── Redpoint/                     # Redpoint OT security tools (upstream bases)
```

## 📚 Documentation

- [OT-Nmap-Blue-Team-Reference.md](OT-Nmap-Blue-Team-Reference.md) — Comprehensive OT scanning reference
- [Lesser-Known-Protocols-Reference.md](Lesser-Known-Protocols-Reference.md) — Coverage gaps & protocol details
- [NSE-Script-Catalog-Detailed.md](NSE-Script-Catalog-Detailed.md) — Full script catalog
- [OT-Port-Protocol-Matrix.md](OT-Port-Protocol-Matrix.md) — Port/protocol mapping matrix
- [Blue-Team-Methodology-Research.md](Blue-Team-Methodology-Research.md) — OT scanning methodology
- [DNP3-NSE-Deep-Dive.md](DNP3-NSE-Deep-Dive.md) — DNP3 protocol deep dive
- [DNP3-Advanced-Script-Report.md](DNP3-Advanced-Script-Report.md) — DNP3 script report
- [NSE-Script-Code-Review.md](NSE-Script-Code-Review.md) — Code review of third-party NSE scripts

---

## 📅 Changelog

The project was built in three planned phases. Design specs and implementation
plans for each live in [`docs/superpowers/`](docs/superpowers/).

### Phase 3 — Asset-Inventory Pipeline · 2026-07-12
- Added the [`asset-inventory/`](asset-inventory/) package (`assetinv`, standard
  library only): a pipeline that turns NSE scan results into a normalized,
  CVE-annotated asset inventory (JSON/CSV).
- Modules: `runner` (nmap `-oX` or a saved XML) → `parser` → `normalizer`
  (maps all 16 scripts' labels into one canonical `Asset` schema) → `cve`
  (offline curated ICS-CVE bundle, non-authoritative hints) → `export` →
  `cli` (`scan` / `parse` subcommands).
- Seeded the CVE bundle with real CISA-advisory CVEs (Rockwell Logix, Siemens
  S7-1200/1500). Added a full pytest suite incl. an unprivileged end-to-end
  integration test, wired into CI.

### Phase 2 — Three New Protocols · 2026-07-12
- Added **EtherNet/IP CIP** (`enip-identity-improved`, TCP 44818),
  **BACnet/IP** (`bacnet-discover-improved`, UDP 47808), and **S7comm-plus**
  (`s7comm-plus-info-improved`, TCP 102) — each with a honeypot mock and tests.
  Script count **13 → 16**; standalone honeypot mocks **6 → 9**.
- Ported the new scripts off the removed nmap `bin` API to
  `string.pack`/`string.unpack`.
- Extended the test harness with a **UDP scan path** (`nmap -sU`) so BACnet is
  testable. PROFINET-CM remains `xfail` (documented mock/NSE byte-offset gap).

### Phase 1 — Test Harness & CI · 2026-07-11 → 2026-07-12
- Built a `pytest` **mock-driven harness** (`sandbox/tests/`): boots each mock
  and asserts the matching NSE extracts the right fields, including
  profile-difference checks.
- Added **GitHub Actions CI**: a `luac -p` syntax gate over every script plus
  the full test suite on each push/PR.
- Fixed real bugs the harness surfaced: 4 scripts crashed at runtime on
  nmap 7.9x/Lua 5.4 (removed `bin`/`bit32` APIs) — ported them; FF HSE now
  extracts named device fields from its labeled banner; OPC UA mock varies its
  ACK per profile; Modbus test reconciled to the mock's real output.

### Initial Release · 2026-07-11
- 13 improved NSE discovery scripts for OT/ICS protocols (DNP3, Modbus, Fox,
  PCWorx, HART-IP, IEC 61850 MMS, PROFINET, GE SRTP, OPC UA, MELSEC-Q, ProConOS,
  Red Lion Crimson, FF HSE), 6 honeypot-grade mock servers, and reference docs.
- Fixed an FF HSE `string.unpack` crash and corrected the README quick-test
  launch commands.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! If you'd like to add support for additional OT protocols, improve existing scripts, or fix bugs:

1. Fork the repository
2. Create a feature branch
3. Add your changes (include mock server for testing)
4. Submit a Pull Request

### Protocol Addition Checklist

- [ ] NSE script following existing patterns (big-endian wire format, robust error handling)
- [ ] Python mock server for testing
- [ ] Test results in `sandbox/test-results/`
- [ ] Updated all relevant documentation
