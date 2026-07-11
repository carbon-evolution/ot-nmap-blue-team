# Closing the OT Blind Spot: 13 Improved NSE Scripts for Industrial Protocol Discovery

**Date:** 2026-07-11
**Platform:** LinkedIn
**Author:** Arthur Lin

---

## The OT Discovery Gap

Ask any OT security practitioner: *what percentage of your network do you have an accurate asset inventory for?*

The honest answer is almost never 100%. OT networks run on proprietary protocols that general-purpose scanners don't understand. Most security teams rely on Nmap for discovery, but Nmap's official script library covers roughly **30% of the 50+ known OT/ICS protocols**. The remaining 70% — protocols used in power turbine controls, automotive assembly lines, semiconductor manufacturing, and oil & gas pipelines — are invisible to standard scans.

The community has filled some gaps with unofficial NSE scripts on GitHub. But many of these scripts have issues:
- Broken handshake sequences that cause connection hangs
- Missing field extraction (returning "device detected" instead of model/firmware/CPU)
- No proper error handling for unresponsive devices
- No reliable `match.ip` port identification
- Incomplete protocol coverage that misses key identification services

This project addresses those gaps head-on.

---

## The Lesser-Known Protocols — Why They Matter

The six **Lesser-Known Protocols** documented in this project represent protocols that are widely deployed in critical infrastructure but have **minimal or broken NSE coverage** in the official Nmap distribution:

| Protocol | Where You'll Find It | What It Controls |
|----------|---------------------|------------------|
| **GE SRTP** (TCP 18245) | Power generation, water treatment | GE PACSystems, Mark VI/VII/VIII turbine control systems |
| **OPC UA Binary** (TCP 4840) | Everywhere — universal SCADA integration | Siemens S7, Rockwell Logix, Schneider, and virtually all modern ICS |
| **MELSEC-Q** (TCP 5007) | East Asian manufacturing | Toyota supply chain, TSMC semiconductor fabs, automotive assembly |
| **ProConOS** (TCP 20547) | Building management, process control | Advantech ADAM PLCs, KW-Software runtime |
| **Red Lion Crimson** (TCP 789) | HMI/SCADA gateways | Red Lion G3xx HMI panels — protocol translation for legacy systems |
| **FF HSE** (TCP 1089) | Process industries (chemical, refining) | Foundation Fieldbus HSE linking field instruments to DCS |

These aren't obscure lab protocols — they're running in your supply chain, your power grid, and your manufacturing lines. And most blue teams have no way to discover them.

---

## What Each Script Extracts — And What Was Improved

### GE SRTP (`gesrtp-info-improved.nse`)

**What it extracts:** PLC Model (e.g. IC695CPE302), Firmware Version (e.g. V9.50), CPU Type, PLC Status (Running/Stopped)

**Improvements over community versions:**
- Two-phase INIT → INIT_ACK handshake with proper timeout handling
- PLC_SSTAT service probe for status and identification
- PLC_LSTAT fallback for additional CPU details
- Community scripts often hang after the INIT phase or miss the REQ/REQ_ACK sequence entirely
- Proper hex-level response parsing instead of pattern matching on raw bytes

**Blue team use case:** Identify all GE PLCs in your power generation environment. Correlate firmware versions against CVEs (e.g. ICSA-21-105-02 affecting GE PACSystems).

### OPC UA Discovery (`opcua-discovery-improved.nse`)

**What it extracts:** Application Name, Application URI, Product URI, Gateway Server URI, Discovery Profile URLs, Number of Available Endpoints

**Improvements over community versions:**
- Full HEL → ACK → OPN → MSG handshake (community versions often skip the OPN handshake and fail against real devices)
- FindServers (service ID 422) + GetEndpoints (service ID 428) dual query
- Extracts gateway server URI and discovery profile URLs — fields many scripts miss
- Handles variable-length OPC UA Binary chunk encoding correctly

**Blue team use case:** Map all OPC UA servers in your SCADA network. The application URI and product URI identify the vendor and software stack — critical for vulnerability assessment.

### MELSEC-Q (`melsecq-info-improved.nse`)

**What it extracts:** PLC Type (e.g. Q03UDVCPU), Series Name (e.g. MELSEC-Q Series), Firmware Version

**Improvements over community versions:**
- Proper 3E-frame MC protocol construction with correct subcommand codes
- CPU type read command (0x0101) decoded into human-readable model names
- Original community script returns raw hex bytes — this script decodes them into actual model numbers

**Blue team use case:** Manufacturing asset discovery. Q03UDVCPU vs Q26UDVCPU indicates different processing capacity and patch status. Identifies firmware for CVE correlation.

### FF HSE (`ff-hse-discover-improved.nse`)

**What it extracts:** Device Name, Vendor Name, Device Tag, HSE Version, Software Revision, Stack Version, MAC Address

**Improvements over community versions:**
- Complete SM_IDENTIFY + MA_IDENTIFY dual query sequence with LREQ session establishment
- Extracts 7 distinct fields — community alternatives typically return only 2-3
- Full DD (Device Description) string parsing for manufacturer/model identification

**Blue team use case:** Process industry asset inventory. Device tag field maps to physical location (e.g. TIC-101 = Temperature Indicator Controller #101).

### ProConOS (`proconos-info-improved.nse`)

**What it extracts:** Runtime Version (e.g. ProConOS V3.0.1040), PLC Model (e.g. ADAM5510KW), Project Name, Source Code Protection Status

**Improvements over community versions:**
- Multi-probe sequence — runtime version query + PLC model query + project name extraction
- Parses source code protection status (protected/unprotected) — a security-relevant field
- Community coverage is essentially non-existent for this protocol

**Blue team use case:** Identify unprotected ProConOS projects whose source code could be extracted by an attacker. Flag outdated runtimes with known vulnerabilities.

### Red Lion Crimson (`redlion-cr3-info-improved.nse`)

**What it extracts:** Model (e.g. G310C2), Firmware (e.g. Crimson 3.2), Part Number (e.g. MNGR-BASE), Vendor (Red Lion Controls)

**Improvements over community versions:**
- Dual-mode detection: legacy 16-byte zero probe + STX-framed command (0x01 Read Device Info)
- Falls back gracefully if one probe method fails
- Extracts part number — omitted by community alternatives

**Blue team use case:** Identify Red Lion HMI gateways that bridge OT and IT networks. These devices often have network access to both zones — a critical security boundary.

---

## How Blue Teams Can Use This

### 1. Asset Inventory

Run all 13 scripts against your OT subnets to discover devices you didn't know existed:

```bash
nmap -p 502,1911,1962,5094,102,20000,5007,4840,18245,20547,1089,789,34964 \
  --script dnp3-advanced-info,modbus-discover-improved,fox-info-improved,\
pcworx-info-improved,hartip-info-improved,iec61850-mms-improved,\
profinet-cm-lookup-improved,gesrtp-info-improved,opcua-discovery-improved,\
melsecq-info-improved,proconos-info-improved,ff-hse-discover-improved,\
redlion-cr3-info-improved --open -oA ot-asset-scan 192.168.0.0/23
```

Each script returns **structured output** with specific device details — not just "port is open." You'll get model numbers, firmware versions, serial numbers, and vendor names that can feed your CMDB or asset management system.

### 2. Vulnerability Correlation

The firmware versions and model numbers extracted by these scripts map directly to ICS-CERT advisories and vendor security bulletins. When you know a GE PACSystems RX3i is running firmware V9.50, you can immediately check:

- ICSA-21-105-02 (GE PACSystems authentication bypass)
- ICSA-22-209-03 (GE Logic execution)
- Vendor-specific CVEs

### 3. Change Detection

Schedule regular scans and diff the output. A new OPC UA endpoint appearing on the network, a Red Lion HMI with a different firmware version, or an unexpected ProConOS runtime — these are all indicators of configuration drift or unauthorized devices.

Run the baseline scan, save the output, and use `nmap --script` with `-oG` (grepable output) for easy diffing.

### 4. Segmentation Validation

Confirm that OT protocols are only accessible from authorized zones. Scan from your IT network segment — if you get responses on TCP 18245 (GE SRTP) or TCP 789 (Red Lion), your segmentation is failing.

---

## Why the Mock Servers Matter

Every script in this project has a corresponding **honeypot-grade mock server** in the `sandbox/` directory. This means you can:

- **Train your SOC** without connecting to a real PLC
- **Validate script behavior** before a production scan
- **Test detection rules** against realistic protocol traffic
- **Practice incident response** on simulated OT compromises

The mock servers aren't simple canned responders. They run full protocol state machines, maintain session state, support multiple device profiles, and log every probe as a structured DETECTION event. They're designed to be indistinguishable from real OT devices during NSE scanning.

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/carbon-evolution/ot-nmap-blue-team.git
cd ot-nmap-blue-team

# Copy scripts to Nmap directory
cp improved-scripts/*.nse ~/.nmap/scripts/
cp improved-scripts/lesser-known/*.nse ~/.nmap/scripts/
nmap --script-updatedb

# Test against the mock servers (no real devices needed)
cd sandbox/
python3 ot_mock_servers.py --all-lesser-known &

# In another terminal, run any script
nmap -p 18245 --script gesrtp-info-improved.nse 127.0.0.1
# Output: PLC Model, Firmware Version, CPU Type, Status
```

**Zero dependencies.** The mock servers use only Python 3 standard library. The NSE scripts use only standard Nmap libraries. No pip install, no npm install, no Docker.

---

## Conclusion

OT asset discovery doesn't have to be a blind spot. These 13 improved scripts close the coverage gap for the protocols that matter most in critical infrastructure — and the accompanying honeypot-grade mock servers give every blue team a safe place to practice.

The complete project is open source under MIT license at **github.com/carbon-evolution/ot-nmap-blue-team**.

*You can't defend what you can't discover.*

#OTSecurity #BlueTeam #Nmap #NSE #ICS #ICSsecurity #IndustrialControlSystems #SCADA #CyberSecurity #AssetDiscovery #Honeypot
