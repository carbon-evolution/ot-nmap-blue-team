# OT Nmap Blue Team — Improved NSE Scripts for OT/ICS Protocol Discovery

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Honeypot-Grade](https://img.shields.io/badge/Honeypot-Grade-purple)](sandbox/)
[![NSE](https://img.shields.io/badge/NSE-13%20scripts-blue)](improved-scripts/)

<p align="center">
  <img src="banner.png" alt="OT Nmap Blue Team — Honeypot-Grade ICS Protocol Emulation" width="100%">
</p>

A collection of **improved Nmap NSE (Scripting Engine) scripts** for discovering, fingerprinting, and auditing OT/ICS (Operational Technology / Industrial Control Systems) protocols. Designed for **blue-team security assessments**, asset inventory, and vulnerability management.

> ⚡ **Honeypot-Grade Mock Servers**: All 6 lesser-known protocol servers (GE SRTP, OPC UA, Red Lion, FF HSE, MELSEC-Q, ProConOS) are built as **production-quality honeypots** — full protocol state machines, profile-based device identities, register/tag read-write, alarm engines, detection logging, and scan delay simulation. See [sandbox README](sandbox/) for details.

Covers **13 protocol families** including DNP3, Modbus, Fox, PCWorx, HART-IP, IEC 61850 MMS, PROFINET, GE SRTP, OPC UA, MELSEC-Q, ProConOS, Red Lion Crimson, and Foundation Fieldbus HSE.

> ⚠️ **DISCLAIMER**: These scripts are provided for **authorized security assessments only**. You MUST test these scripts in a **controlled lab environment first** before using them on any operational network. Running these scripts against production OT systems may cause unexpected behavior. The authors assume no liability for misuse or damage.

---

## Table of Contents

- [Blue Team Purpose](#-blue-team-purpose)
- [Script Catalog](#-script-catalog)
- [What Information Can These Scripts Extract?](#-what-information-can-these-scripts-extract)
- [Nmap Script Location by OS](#-nmap-script-location-by-os)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [Testing with Mock Servers](#-testing-with-mock-servers)
- [Methodology & Safety](#-methodology--safety)
- [Project Structure](#-project-structure)
- [License](#-license)

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
# Scan a single host for all supported OT protocols
nmap -p 502,1911,1962,5094,102,20000,5007,4840,18245,20547,1089,789 \
  --script dnp3-advanced-info,modbus-discover-improved,fox-info-improved,\
pcworx-info-improved,hartip-info-improved,iec61850-mms-improved,\
gesrtp-info-improved,opcua-discovery-improved,melsecq-info-improved,\
proconos-info-improved,ff-hse-discover-improved,redlion-cr3-info-improved \
  <target>
```

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
# Scan entire OT subnet for all supported protocols
nmap -p 502,1911,1962,5094,102,20000,5007,4840,18245,20547,1089,789 \
  --open -oA ot-scan \
  192.168.1.0/24
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

> 🔥 **Honeypot-Grade Emulation**: 6 of the protocol servers are built as full-fledged **honeypots** — complete state machines, profile-based device identities, session tracking, memory/register read-write, alarm engines, and structured detection logging. They're indistinguishable from real OT devices during NSE scanning.

This repository includes Python mock servers for every NSE script, enabling safe testing without connecting to real OT devices.

### Prerequisites
```bash
python3          # Any recent Python 3.x
nmap             # For running the NSE scripts
```

### Quick Test
```bash
cd sandbox/

# Start all 6 honeypot-grade servers
python3 melsecq_mock_server.py --port 5007 &
python3 opcua_mock_server.py --port 4840 --profile siemens_s7 &
python3 gesrtp_mock_server.py --port 18245 --profile rx3i &
python3 redlion_mock_server.py --port 44818 --profile g310c2 &
python3 ffhse_mock_server.py --port 1089 --profile tic101 &
python3 proconos_mock_server.py --port 20547 &

# In another terminal, run NSE tests against all 6
nmap -p 5007 --script ../improved-scripts/lesser-known/melsecq-info-improved.nse 127.0.0.1
nmap -p 4840 --script ../improved-scripts/lesser-known/opcua-discovery-improved.nse 127.0.0.1
nmap -p 18245 --script ../improved-scripts/lesser-known/gesrtp-info-improved.nse 127.0.0.1
nmap -p 44818 --script ../improved-scripts/lesser-known/redlion-cr3-info-improved.nse 127.0.0.1
nmap -p 1089 --script ../improved-scripts/lesser-known/ff-hse-discover-improved.nse 127.0.0.1
nmap -p 20547 --script ../improved-scripts/lesser-known/proconos-info-improved.nse 127.0.0.1

# Clean up
kill %1 %2 %3 %4 %5 %6
```

### Mock Server Reference

All 6 lesser-known protocol servers are built to **honeypot-grade** — they go beyond static responses with realistic state machines, profile-based device identities, detection logging, and scan delay simulation.

| Mock Server | Protocol | Port | Honeypot Features | Notes |
|-------------|----------|------|-------------------|-------|
| `ot_mock_servers.py` | All standard protocols | Various | — | All-in-one server (thin/legacy) |
| `melsecq_mock_server.py` | MELSEC-Q | 5007 | Profiles, detection logging, scan delay | Standalone |
| `opcua_mock_server.py` | OPC UA | 4840 | Full HEL→ACK→OPN→MSG→CLO state machine, FindServers/GetEndpoints/Read/Browse/Write handlers, 3 profiles, address space, detection logging | Standalone |
| `proconos_mock_server.py` | ProConOS | 20547 | Profiles, detection logging, scan delay | Standalone |
| `gesrtp_mock_server.py` | GE SRTP | 18245 | Full INIT→REQ state machine, SSTAT/LSTAT/CONFIG_INFO/MEM_READ/MEM_WRITE services, 3 profiles, connection tracking, detection logging, UDP support | Standalone |
| `ffhse_mock_server.py` | FF HSE | 1089 | SM_IDENTIFY/MA_IDENTIFY/LREQ/LRES/LFIN/FMS_READ handlers, alarm engine, PV drift simulation, 4 profiles, detection logging | Standalone |
| `redlion_mock_server.py` | Red Lion | 789 | Per-profile device identity + tag database, STX command set (read/write tags, login, config), write tag logging (0x12), scan delay, 4 profiles | Requires root (<1024) |

### What Makes Them Honeypot-Grade

The 6 standalone servers go far beyond simple canned responses:

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

All 13 scripts have been tested against their corresponding mock servers. See `sandbox/test-results/README.md` for detailed output.

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
│
├── improved-scripts/             # NSE scripts (standard protocols)
│   ├── dnp3-advanced-info.nse
│   ├── modbus-discover-improved.nse
│   ├── fox-info-improved.nse
│   ├── pcworx-info-improved.nse
│   ├── hartip-info-improved.nse
│   ├── iec61850-mms-improved.nse
│   ├── profinet-cm-lookup-improved.nse
│   │
│   └── lesser-known/             # NSE scripts (lesser-known protocols)
│       ├── gesrtp-info-improved.nse
│       ├── opcua-discovery-improved.nse
│       ├── melsecq-info-improved.nse
│       ├── proconos-info-improved.nse
│       ├── ff-hse-discover-improved.nse
│       └── redlion-cr3-info-improved.nse
│
├── sandbox/                      # Mock servers and tests
│   ├── ot_mock_servers.py
│   ├── melsecq_mock_server.py
│   ├── opcua_mock_server.py
│   ├── proconos_mock_server.py
│   ├── gesrtp_mock_server.py
│   ├── ffhse_mock_server.py
│   ├── redlion_mock_server.py
│   ├── test_runner.sh
│   └── test-results/
│       └── README.md
│
├── scada-tools/                  # Third-party SCADA tools (reference)
├── ICS-Discovery-Tools/          # Community ICS discovery scripts
└── Redpoint/                     # Redpoint OT security tools
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
