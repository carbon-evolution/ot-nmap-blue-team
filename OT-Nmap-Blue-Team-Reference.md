# OT/ICS Blue Team Nmap Reference
## Storyline, Methodology & Complete NSE Script Catalog

> **Based on:** Screenshot `Screenshot 2026-07-11 at 7.25.45 AM.png`
> **Generated:** 2026-07-11 | **Model:** deepseek-v4-flash-free

---

## PART 1: THE BLUE TEAM STORYLINE

### Act I: The Invisible Battlefield

Every OT network starts the same way — built by engineers, for reliability, not security. PLCs, RTUs, HMIs, historians, and field devices communicate through air-gapped (or "air-gapped") networks using protocols designed decades ago: Modbus, DNP3, PROFINET, EtherNet/IP, and hundreds of vendor-specific variants.

The Blue Team's challenge is existential: **you cannot defend what you cannot see.**

Unlike IT networks where Active Directory, endpoint agents, and cloud APIs provide visibility, OT networks are dark. Many have no asset inventory. Many run firmware versions that haven't been updated in a decade. Many use protocols with zero authentication.

The attackers know this. Since Stuxnet (2010), every major APT group — from Sandworm to Dragonfly to Volt Typhoon — has added OT-specific capabilities. Ransomware groups now specifically target ICS environments for extortion leverage (Colonial Pipeline 2021, Colonial 2022, Clorox 2023, CDE 2024).

### Act II: The Blue Team's First Move — Passive Reconnaissance

Before any packet hits the wire, the Blue Team listens. Passive reconnaissance is the safest approach in an OT environment where a mis-timed scan can trip a relay or halt a production line.

**Passive listening tools:**
- `nmap --script broadcast-listener` — sniff broadcast traffic (CDP, HSRP, ARP, DHCP)
- `nmap --script targets-sniffer` — passive network discovery from observed traffic
- WireShark / tcpdump — full packet capture for protocol analysis

This phase answers: *What's already talking? What protocols are in use? What are the MAC OUI vendors?*

### Act III: Controlled Active Discovery

Once the passive baseline is established, the Blue Team moves to active scanning with deliberate speed control:

1. **ARP scan** (safest local subnet discovery): `nmap -sn -PR 192.168.1.0/24`
2. **ICMP discovery** (validate hosts): `nmap -sn -PE 192.168.1.0/24`
3. **Top-10 TCP ports** (quick reconnaissance): `nmap 192.168.1.0/24 --top-ports 10`
4. **Protocol-specific probes** — targeted by known OT ports

**Key OT commandments:**
- ⚠️ **NEVER** use `-T5` or `-T4` in production OT environments — use `-T2` (Polite) or `-T1` (Sneaky)
- ⚠️ **NEVER** use a `vuln` or `dos` category script against live industrial equipment
- ⚠️ **ALWAYS** coordinate with operations and obtain written authorization
- ⚠️ **ALWAYS** have a maintenance window or run after hours
- ✅ **PREFER** single-target scans over subnet sweeps when poking at fragile devices

### Act IV: Asset Identification & Fingerprinting

Each open port reveals a protocol. Each protocol reveals a device type. Each device reveals a vendor and model.

The Blue Team fingerprints every asset:

| Phase | Action | Tool |
|-------|--------|------|
| 1 | Discover open ports | `nmap -p- -T2 <target>` |
| 2 | Identify OT services | `nmap -p <ports> -sV <target>` |
| 3 | Fingerprint protocol details | Dedicated NSE scripts (see Part 2) |
| 4 | Capture banners | `--script banner` |
| 5 | Detect OS | `nmap -O <target>` (if safe for device) |

### Act V: Risk Assessment

With assets identified, the Blue Team assesses risk:

1. **Known vulnerabilities** — check firmware versions against CVE databases (NVD, ICS-CERT)
2. **Configuration weaknesses** — default credentials, unnecessary services, plaintext protocols
3. **Network exposure** — devices accessible from IT network / internet?
4. **Protocol risks** — unauthenticated protocols (Modbus, DNP3 without secure auth)
5. **MITRE ATT&CK for ICS mapping** — which techniques could target this device?

### Act VI: Continuous Monitoring

The OT asset inventory feeds into:
- **SIEM** (Wazuh, Splunk, ArcSight) — correlate Nmap findings with logs
- **Vulnerability management** (DefectDojo, Dependency-Track) — track CVEs per device
- **Network monitoring** (Suricata, Zeek) — detect protocol anomalies
- **OT-specific** (Claroty, Nozomi, Dragos, Microsoft Defender for IoT) — deep protocol analysis

---

## PART 2: COMPLETE OT PORT & NSE SCRIPT CATALOG

### 2A: Official Nmap NSE Scripts — Dedicated OT Protocol Scripts

These 17 scripts are **purpose-built** for OT/ICS/SCADA/BMS protocol identification and enumeration. They are part of the official Nmap distribution (611 scripts total, ~2.8% OT-specific).

| # | Script | Protocol | Default Port | Transport | Category | Description | Output |
|---|--------|----------|-------------|-----------|----------|-------------|--------|
| 1 | `modbus-discover` | Modbus | 502 | TCP | discovery, intrusive | Enumerate slave IDs (sids), device info, vendor, firmware | Slave ID, device identification, vendor, firmware version |
| 2 | `s7-info` | Siemens S7 | 102 | TCP | discovery, safe | Enumerate Siemens S7 PLC info | Basic hardware, system name, copyright, version, module type, serial number |
| 3 | `enip-info` | EtherNet/IP (CIP) | 44818 | TCP | discovery, safe | Identify EtherNet/IP devices, send Request Identity | Device type, vendor (Rockwell/AB), product name, serial, revision, status, state, IP |
| 4 | `bacnet-info` | BACnet | 47808 | UDP | discovery, safe | Discover and enumerate BACnet devices | Vendor ID, vendor name, instance number, firmware, app software, object name, model, description, location |
| 5 | `fox-info` | Tridium Niagara Fox | 1911 | TCP | discovery, safe | Enumerate Tridium Niagara BAS systems | Fox version, hostname, app name/version, VM, OS, timezone, host ID, VM UUID, brand |
| 6 | `iec-identify` | IEC 60870-5-104 | 2404 | TCP | discovery, intrusive | Identify IEC 104 ICS protocol, send TESTFR/STARTDT, general interrogation | ASDU address, information object count |
| 7 | `iec61850-mms` | IEC 61850 MMS | 102 | TCP | discovery, intrusive | Query IEC 61850-8-1 MMS server | Model name, vendor name, serial number, firmware version, product family, configuration |
| 8 | `hartip-info` | HART-IP | 5094 | TCP | discovery, intrusive | Enumerate HART field device gateways | Long tag, expanded device type, manufacturer, device ID, revisions, HART protocol version |
| 9 | `pcworx-info` | PCWorx (Phoenix Contact) | 1962 | TCP | discovery | Enumerate Phoenix Contact PLCs | PLC type, model number, firmware version/date/time |
| 10 | `omron-info` | Omron FINS | 9600 | TCP/UDP | discovery, safe | Enumerate Omron PLCs via FINS protocol | Controller model, version, program area size, IOM size, DM words, timer/counter, memory card |
| 11 | `mqtt-subscribe` | MQTT | 1883, 8883 | TCP | discovery, safe | Subscribe to MQTT broker topics and dump messages | Brokers version, topics, payloads, connected clients, uptime, heap usage |
| 12 | `coap-resources` | CoAP | 5683 | UDP | discovery, safe | Enumerate CoAP endpoint resources | Available resources, content types, attributes |
| 13 | `knx-gateway-info` | KNX | 3671 | UDP | discovery, safe | Identify KNX gateways | KNX gateway device identification |
| 14 | `knx-gateway-discover` | KNX | 3671 | UDP | broadcast, discovery | Discover KNX gateways on local network | KNX gateway discovery via broadcast |
| 15 | `profinet-cm-lookup` | PROFINET | 34962-34964 | UDP | discovery, intrusive | PROFINET Context Manager device lookup | PROFINET device identification |
| 16 | `multicast-profinet-discovery` | PROFINET | 34962-34964 | UDP | broadcast, discovery | Discover PROFINET devices via multicast | PROFINET device discovery |
| 17 | `stuxnet-detect` | Siemens S7 (Stuxnet) | 102 | TCP | discovery, intrusive | Check for Stuxnet-related indicators on S7 devices | Stuxnet compromise indicators |

### 2B: Supplementary NSE Scripts Useful for OT Discovery

These are NOT OT-specific but are essential for building a complete OT asset inventory:

| Category | Script | OT Use Case |
|----------|--------|-------------|
| **Discovery** | `broadcast-listener` | Sniff broadcast traffic to passively discover OT devices (CDP, HSRP, ARP, DHCP, more) |
| **Discovery** | `targets-sniffer` | Passive sniffing — discover hosts without active scanning |
| **Discovery** | `broadcast-ping` | Discover hosts via broadcast ping ethernet frames |
| **Discovery** | `broadcast-upnp-info` | Discover UPnP-enabled industrial devices |
| **Discovery** | `broadcast-wsdd-discover` | WS-Discovery for industrial web services |
| **Discovery** | `wsdd-discover` | Web Services Dynamic Discovery — find WCF/industrial web services |
| **Discovery** | `banner` | Banner grab — identify OT services by banners |
| **Discovery** | `upnp-info` | UPnP information from devices |
| **Discovery** | `tftp-enum` | Enumerate TFTP (often used in OT for firmware config transfers) |
| **Discovery** | `dhcp-discover` | DHCP info — identify DHCP servers in OT network |
| **Discovery** | `nbstat` | NetBIOS — discover Windows-based HMI/engineering workstations |
| **Version** | `fingerprint-strings` | Extract readable strings from unknown services (OT devices with unknown protocols) |
| **Version** | `clock-skew` | Analyze clock skew — helps identify device type |
| **Auth** | `ftp-anon` | Check for anonymous FTP on OT devices |
| **Auth** | `telnet-brute` | Telnet brute force (common on legacy OT devices) |
| **Auth** | `snmp-info` | SNMP info — widely used in OT for device monitoring |
| **Auth** | `snmp-brute` | SNMP community string brute force |
| **Auth** | `snmp-interfaces` | Enumerate SNMP network interfaces |
| **Auth** | `snmp-sysdescr` | System description via SNMP |
| **Auth** | `snmp-processes` | Running processes via SNMP |
| **Auth** | `http-default-accounts` | Default credentials on industrial web interfaces |
| **Safety** | `stuxnet-detect` | Stuxnet-related indicators on Siemens S7 systems |

### 2C: OT Protocol → Port → NSE Script Master Table

Every known OT/ICS/BMS protocol port with applicable Nmap scanning options:

| Protocol | Port(s) | Transport | Dedicated NSE Script | Other Nmap Techniques | Category (Safety) |
|----------|---------|-----------|---------------------|----------------------|-------------------|
| **Siemens S7** | 102 | TCP | `s7-info`, `iec61850-mms` | `-sV` version detection | Safe / Intrusive |
| **Modbus** | 502 | TCP | `modbus-discover` | `-sV` version detection | Intrusive |
| **Red Lion** | 789 | TCP | — | `-sV`, `banner` | Safe |
| **Foundation Fieldbus** | 1089-1091 | TCP | — | `-sV`, `banner` | Safe |
| **Tridium Niagara Fox** | 1911 | TCP | `fox-info` | `-sV` version detection | Safe |
| **PCWorx (Phoenix Contact)** | 1962 | TCP | `pcworx-info` | `-sV` version detection | Safe |
| **IEC 60870-5-104** | 2404 | TCP | `iec-identify` | `-sV` version detection | Intrusive |
| **MQTT** | 1883, 8883 | TCP | `mqtt-subscribe` | `-sV`, `banner` | Safe |
| **MQTT-SN** | 1884 | UDP | — | `-sV` | Safe |
| **OPC UA (Binary)** | 4840 | TCP | — | `-sV`, `banner` | Safe |
| **OPC UA (TLS)** | 4843 | TCP | — | `-sV`, `ssl-*` scripts | Safe |
| **MELSEC-Q / Mitsubishi** | 5007 | TCP | — | `-sV`, `banner` | Safe |
| **HART-IP** | 5094 | TCP | `hartip-info` | `-sV`, `banner` | Intrusive |
| **EtherNet/IP (CIP)** | 44818 | TCP | `enip-info` | `-sV` version detection | Safe |
| **EtherNet/IP (UDP)** | 2222 | UDP | — | `-sV` | Safe |
| **Siemens SIMATIC** | 5051-5052 | TCP | — | `-sV` | Safe |
| **BACnet** | 47808 | UDP | `bacnet-info` | `-sV` version detection | Safe |
| **DNP3** | 20000 | TCP | ⚠️ No official script (see 2D) | `-sV` version detection, `banner` | Safe |
| **ProConOS** | 20547 | TCP | — | `-sV`, `banner` | Safe |
| **PROFINET IO (RPC)** | 34962-34964 | UDP | `profinet-cm-lookup`, `multicast-profinet-discovery` | `-sV` | Intrusive / Broadcast |
| **PROFINET DCP** | — | L2 | — | — | |
| **GE SRTP** | 18245 | TCP | — | `-sV`, `banner` | Safe |
| **Omron FINS** | 9600 | TCP/UDP | `omron-info` | `-sV` version detection | Safe |
| **Omron FINS (UDP)** | 9600 | UDP | `omron-info` | `-sV` version detection | Safe |
| **KNX** | 3671 | UDP | `knx-gateway-info`, `knx-gateway-discover` | `-sV` | Safe |
| **CoAP** | 5683 | UDP | `coap-resources` | `-sV` version detection | Safe |
| **CoAP (DTLS)** | 5684 | UDP | — | `-sV` | Safe |
| **IEC 61850 GOOSE** | — | L2 (EtherType 0x88B8) | — | Use Wireshark, not Nmap | — |
| **IEC 61850 SV** | — | L2 (EtherType 0x88BA) | — | Use Wireshark, not Nmap | — |
| **Modbus UDP (Modbus/TCP alt)** | 502 | UDP | — | `-sU -p 502` | Intrusive |
| **CANopen / CAN** | — | L2 | — | Not detectable via Nmap | — |
| **DeviceNet** | — | L2 | — | Not detectable via Nmap | — |
| **ControlNet** | — | L2 | — | Not detectable via Nmap | — |
| **EtherCAT** | — | L2 (EtherType 0x88A4) | — | Not detectable via Nmap | — |
| **CC-Link IE** | — | L2 | — | Not detectable via Nmap | — |
| **LonWorks** | — | L2 / 1628 | — | Not detectable via Nmap | — |
| **SERCOS III** | — | L2 | — | Not detectable via Nmap | — |
| **POWERLINK** | — | L2 | — | Not detectable via Nmap | — |
| **FL-net** | 55000-55003 | UDP | — | `-sU -p 55000-55003` | Safe |
| **CIP Safety** | 44818 | TCP | — | Reuses enip-info | Safe |
| **HART (legacy)** | — | Analog 4-20mA | — | Not detectable via Nmap | — |
| **BSAP (Bristol)** | — | Serial/TCP | — | `-sV`, `banner` | Safe |
| **DF1 (Allen-Bradley)** | — | Serial / 44818 | — | Reaches CIP via enip-info | Safe |
| **AS-Interface** | — | L2 | — | Not detectable via Nmap | — |
| **VXI-11** | 111 | TCP | — | Use `rpcinfo` script | Safe |

### 2D: Community & Third-Party OT NSE Scripts

These are NOT in the official Nmap distribution but are available on GitHub:

| Script | Protocol | Target Port | Source | Description |
|--------|----------|-------------|--------|-------------|
| `dnp3-info.nse` (community) | DNP3 | 20000 TCP | github.com/atimorin/nmap-nse-dnp3 | Enumerate DNP3 outstation — reads application layer info, object addresses, device attributes |
| `opcua-info.nse` | OPC UA | 4840 TCP | github.com/neonlabs/opcua-nmap | Enumerate OPC UA server endpoints, security modes |
| `profibus-detect.nse` | PROFIBUS | — | Various community repos | Detection methods (limited — PROFIBUS is L2/serial) |
| `codesys-info.nse` | CODESYS | 2455 TCP | Community scripts | Identify CODESYS runtime on PLCs |
| `melsec-info.nse` | MELSEC-Q | 5007 TCP | Community scripts | Enumerate Mitsubishi Electric PLC info |
| `srtp-info.nse` | GE SRTP | 18245 TCP | Community scripts | Enumerate GE PLC information |
| `dnp3-brute.nse` | DNP3 | 20000 TCP | Security research | Brute force DNP3 secure auth |
| `bacnet-brute.nse` | BACnet | 47808 UDP | Community | Brute force BACnet object IDs |

> **Note on community scripts:** Several scripts in this reference (marked *Third-party* in 2C) are **not in the official nmap distribution**. These include `iec-identify`, `dnp3-info`, `dnp3-enumerate`, `melsec-q`, `ge-srtp`, and others from the Redpoint/scada-tools/ICS-Discovery-Tools repos. To use them via `--script <name>`:
> - **Linux/macOS:** Copy to `~/.nmap/scripts/` then run `nmap --script-updatedb`
> - **Windows:** Copy to `%USERPROFILE%\.nmap\scripts\` then run `nmap --script-updatedb`
> - **Portable (any OS):** Use full path — `--script /path/to/script.nse`

### 2E: Protocols NOT Detectable by Nmap

These OT protocols operate at Layer 2 (Ethernet) or below — Nmap cannot discover them:

| Protocol | Stack Layer | Alternative Discovery Method |
|----------|-------------|------------------------------|
| **EtherCAT** | L2 (EtherType 0x88A4) | Wireshark, EtherCAT master scanning tools |
| **PROFINET RT/IRT** | L2 (VLAN + EtherType) | Wireshark, PROFINET IO scanner |
| **IEC 61850 GOOSE** | L2 (EtherType 0x88B8) | Wireshark dissector, GOOSE-specific tools |
| **IEC 61850 Sampled Values** | L2 (EtherType 0x88BA) | Wireshark, SV-specific tools |
| **CANopen / CAN bus** | L2 / Physical | CAN bus adapter + tools (candump, can-utils) |
| **DeviceNet** | L2 / Physical | DeviceNet scanner |
| **ControlNet** | L2 / Physical | ControlNet specific tools |
| **AS-Interface** | Physical | AS-i master scanner |
| **SERCOS III** | L2 | SERCOS III analysis tools |
| **POWERLINK** | L2 | openPOWERLINK tools |
| **CC-Link / CC-Link IE** | L2 | Mitsubishi diagnostic tools |
| **LonWorks** | L2 / PL20 | LonScanner, LonMaker |
| **Modbus RTU/ASCII** | Serial (RS-232/485) | Serial-to-TCP gateway then scan Modbus port |
| **HART (analog)** | Analog 4-20mA + HART | HART modem, FieldComm Group tools |
| **Profibus DP/PA** | Serial / RS-485 | Profibus analyzer (ProfiTrace) |

---

### 2F: NSE Script Location by Operating System

All official NSE scripts ship with nmap. Where they live depends on your OS:

| OS | Installation Method | Official NSE Scripts Directory |
|----|-------------------|-------------------------------|
| **macOS** | Homebrew (`brew install nmap`) | `/opt/homebrew/share/nmap/scripts/` |
| **Linux (Debian/Ubuntu)** | `apt install nmap` | `/usr/share/nmap/scripts/` |
| **Linux (RHEL/Fedora)** | `dnf install nmap` | `/usr/share/nmap/scripts/` |
| **Linux (Arch)** | `pacman -S nmap` | `/usr/share/nmap/scripts/` |
| **Windows** | Installer from nmap.org | `C:\Program Files (x86)\Nmap\scripts\` |
| **Windows (Chocolatey)** | `choco install nmap` | `C:\ProgramData\chocolatey\lib\nmap\tools\nmap\scripts\` |
| **Any OS (user scripts)** | Manual download | `~/.nmap/scripts/` (Linux/macOS) or `%USERPROFILE%\AppData\Roaming\nmap\scripts\` (Windows) |

**How to verify on your system:**
```bash
# Linux/macOS — find the script directory
nmap --script-updatedb 2>&1 | head -1
ls $(dirname $(which nmap))/../share/nmap/scripts/ | grep -E 's7-info|modbus-discover|bacnet-info'

# Windows (PowerShell)
Get-ChildItem "$env:ProgramFiles\Nmap\scripts\" | Where-Object Name -match 's7-info|modbus-discover|bacnet-info'
```

**All 12 scripts from the OT fingerprint command are official** and ship with every nmap installation — no extra download needed:
```
s7-info         → ships with nmap (TCP 102, Siemens S7)
modbus-discover → ships with nmap (TCP 502, Modbus)
enip-info       → ships with nmap (TCP 44818, EtherNet/IP)
fox-info        → ships with nmap (TCP 1911, Tridium Fox)
hartip-info     → ships with nmap (TCP 5094, HART-IP)
pcworx-info     → ships with nmap (TCP 1962, Phoenix Contact PCWorx)
omron-info      → ships with nmap (TCP/UDP 9600, Omron FINS)
iec61850-mms    → ships with nmap (TCP 102, IEC 61850 MMS)
bacnet-info     → ships with nmap (UDP 47808, BACnet)
mqtt-subscribe  → ships with nmap (TCP 1883, MQTT)
knx-gateway-info → ships with nmap (UDP 3671, KNXnet/IP)
```

**One exception — `iec-identify`** is a **community script** (not in official nmap). It lives in:
- This project: `scada-tools/iec-identify.nse`
- Original source: `github.com/atimorin/scada-tools`

To use it as `--script iec-identify` (without a path prefix), copy it to your user scripts directory:
```bash
# Linux/macOS
cp scada-tools/iec-identify.nse ~/.nmap/scripts/
nmap --script-updatedb

# Windows (PowerShell)
Copy-Item scada-tools\iec-identify.nse "$env:USERPROFILE\.nmap\scripts\"
nmap --script-updatedb
```

**Community scripts from this project** (`Redpoint/`, `ICS-Discovery-Tools/`, `scada-tools/`) that you want to use in the field must also be copied to `~/.nmap/scripts/` and registered via `nmap --script-updatedb` before they will resolve by name.

---

### 2G: How to Run NSE Scripts

`.nse` files are **Nmap Scripting Engine** scripts written in Lua. They are run exclusively by **nmap** — you do not need a separate Lua installation.

**Basic usage:**
```bash
# By name (after copying to ~/.nmap/scripts/ and running nmap --script-updatedb)
nmap --script modbus-discover -p 502 <target>

# By file path (portable — no install needed)
nmap --script /path/to/modbus-discover-improved.nse -p 502 <target>

# Apply to matching port (most OT scripts declare their port in the script itself)
nmap --script s7-info -p 102 <target>
```

**Running custom/improved scripts from this project:**

The `improved-scripts/` directory contains enhanced versions of official OT NSE scripts. Use them with a path:

```bash
# Modbus with custom timeout + SID range
nmap --script improved-scripts/modbus-discover-improved.nse \
  --script-args 'modbus-discover.timeout=5000,modbus-discover.sid-start=1,modbus-discover.sid-end=20' \
  -p 502 <target>

# HART-IP with timeout
nmap --script improved-scripts/hartip-info-improved.nse \
  --script-args 'hartip-info.timeout=3000' \
  -p 5094 <target>

# IEC 61850 MMS (default timeout raised to 5000ms)
nmap --script improved-scripts/iec61850-mms-improved.nse -p 102 <target>

# All improved scripts at once
nmap --script improved-scripts/*.nse -p 502,102,5094,1962,1911,34962-34964 <target>
```

**Non-aggressive mode for production OT:**
```bash
# Scan only SIDs 1-10 (instead of all 246)
nmap --script improved-scripts/modbus-discover-improved.nse \
  --script-args 'modbus-discover.sid-start=1,modbus-discover.sid-end=10' \
  -p 502 <target>
```

**Script arguments (`--script-args`):**
| Pattern | Example | Effect |
|---------|---------|--------|
| `key=value` | `modbus-discover.timeout=5000` | Sets script-specific timeout (ms) |
| `key1=val1,key2=val2` | `sid-start=1,sid-end=50` | Multiple comma-separated args |
| `key=val -p <port>` | `-p 502` | Script only runs on matching ports |
| No args | — | Uses sensible defaults (backward compatible) |

**Install custom scripts system-wide (optional):**
```bash
# Linux/macOS — copy to user scripts directory
cp improved-scripts/*.nse ~/.nmap/scripts/
nmap --script-updatedb

# Windows (PowerShell)
Copy-Item improved-scripts\*.nse "$env:USERPROFILE\.nmap\scripts\"
nmap --script-updatedb

# Now run by name (e.g. --script modbus-discover-improved)
```

> **Key point:** NSE scripts are **Lua programs** interpreted by nmap's built-in Lua 5.3 runtime. The interpreter provides all networking (`comm`, `nmap`), argument parsing (`stdnse.get_script_args`), and output (`stdnse.format_output`) libraries. You do not run them with `lua` or `luajit` — only with `nmap --script`.

---

## PART 3: BLUE TEAM SCAN METHODOLOGY

### Phase 1: Passive Reconnaissance

```bash
# Listen to broadcast traffic to discover OT devices passively
nmap --script broadcast-listener -T2

# Passive host discovery — sniff without sending
nmap --script targets-sniffer

# SNMP poll existing switches to discover MACs (if SNMP configured)
snmpwalk -v2c -c public <switch-ip> 1.3.6.1.2.1.17.4.3.1.1
```

### Phase 2: Non-Intrusive Port Discovery

```bash
# ARP scan (safest — local subnet only)
nmap -sn -PR 192.168.1.0/24

# ICMP discovery
nmap -sn -PE 192.168.1.0/24

# Slow, polite service scan
nmap -T2 -sV -p 102,502,789,1911,1962,2404,4840,5007,5094,9600,18245,20000,20547,44818,47808 \
  192.168.1.100 -oA nmap-output/nmap-ot-services
```

### Phase 3: OT Protocol Fingerprinting

```bash
# Run ALL safe OT NSE scripts on identified OT hosts
nmap -T2 -sV \
  -p 102 --script s7-info \
  -p 502 --script modbus-discover \
  -p 44818 --script enip-info \
  -p 1911 --script fox-info \
  -p 5094 --script hartip-info \
  -p 1962 --script pcworx-info \
  -p 9600 --script omron-info \
  -p 2404 --script iec-identify \
  -p 102 --script iec61850-mms \
  -p 47808 -sU --script bacnet-info \
  -p 1883 --script mqtt-subscribe \
  -p 3671 -sU --script knx-gateway-info \
  192.168.1.100 -oA nmap-output/nmap-ot-fingerprint
```

### Phase 4: Speed Control for Production OT

```bash
# T2 — Polite mode for production OT
nmap -T2 --scan-delay 5s --max-parallelism 1 <target>

# T1 — Sneaky mode for very sensitive equipment
nmap -T1 --scan-delay 10s --max-retries 0 <target>

# Per-port delay to avoid overwhelming fragile PLCs
nmap --scan-delay 5s --max-scan-delay 10s --min-rate 10 <target>
```

### Phase 5: Output & Documentation

```bash
# All output formats
-oN nmap-output.nmap    # Normal text
-oX nmap-output.xml     # XML (import to SIEM, DefectDojo)
-oG nmap-output.gnmap   # Grepable (scriptable parsing)

# Example: Full OT discovery in one command
sudo nmap -T2 -Pn -sS -sU \
  -p 102,502,789,1911,1962,2404,4840,4843,5007,5094,9600,18245,20000,20547,44818 \
  -sU -p 3671,5683,47808,55000-55003 \
  --script bacnet-info,s7-info,enip-info,fox-info,iec-identify,iec61850-mms,hartip-info,pcworx-info,omron-info,knx-gateway-info,mqtt-subscribe \
  192.168.1.0/24 \
  -oA nmap-output/ot-full-discovery
```

### Phase 6: Risk Assessment Workflow

```bash
# 1. Identify all OT devices
# 2. Extract firmware versions from NSE output
# 3. Cross-reference with ICS-CERT advisories
#    https://www.cisa.gov/news-events/ics-advisories
# 4. Import findings into DefectDojo or DTrack:
#    nmap-to-defectdojo: python3 manage.py import_scan_results --scan-type "Nmap Scan"
# 5. Map to MITRE ATT&CK for ICS:
#    T0842 (Network Sniffing), T0846 (Remote System Discovery),
#    T0883 (Internet Accessible Device), T0890 (Emulation for Impact)
```

---

## PART 4: SAFETY GUIDE — OT SCAN BEST PRACTICES

### ✅ Safe (Production-OK) Nmap Practices

| Practice | Command |
|----------|---------|
| Polite timing | `-T2` |
| Sneaky timing for fragile PLCs | `-T1 --scan-delay 10s` |
| Skip host discovery (firewalled OT) | `-Pn` |
| Limit parallel probes | `--max-parallelism 1` |
| Limit retries | `--max-retries 0` or `1` |
| Single target scanning | Always prefer over subnet sweeps |
| Read-only discovery | Use `-sV` and `safe` category scripts only |
| Safe script category only | `--script safe` |

### ❌ NEVER Do in Production OT

| Practice | Why |
|----------|-----|
| `-T4` or `-T5` | Aggressive timing can DoS fragile devices |
| `--script vuln` or `--script exploit` | Exploit scripts can crash PLCs |
| `--script dos` | Denial of Service — exactly what it sounds like |
| `--script intrusive` without authorization | Intrusive scripts may cause unintended writes |
| Fuzzing scripts (`http-form-fuzzer`, `dns-fuzz`) | Can crash control logic |
| Broad subnet+all-ports scan during production | Uncontrolled discovery scan may overload devices |
| UDP scan on production network without warning | `-sU` is slow and can affect some devices |

### ⚠️ Intrusive OT NSE Scripts — Use Only in Lab/Maintenance

| Script | Risk |
|--------|------|
| `modbus-discover` | Enumerates slave IDs — some legacy devices react poorly to unexpected requests |
| `iec-identify` | Sends TESTFR and STARTDT — could interfere with active IEC 104 sessions |
| `iec61850-mms` | Sends MMS initiate/identify/read — safe in most cases but monitor |
| `hartip-info` | Establishes HART session — read-only but starts stateful connection |
| `stuxnet-detect` | Checks for Stuxnet artifacts — read-only, safe |
| `profinet-cm-lookup` | PROFINET CM lookup — may cause brief network chatter |

---

## PART 5: QUICK REFERENCE — TOP COMMANDS FROM SCREENSHOT

| Purpose | Command |
|---------|---------|
| ARP scan (safest local subnet) | `nmap -sn -PR 192.168.1.0/24` |
| Basic ping sweep | `nmap -sn 192.168.1.0/24` |
| ICMP-only discovery | `nmap -sn -PE 192.168.1.0/24` |
| Passive broadcast listener | `nmap --script broadcast-listener` |
| Single host all TCP ports | `nmap 192.168.1.1 -p-` |
| Top 10 TCP ports subnet | `nmap 192.168.1.0/24 --top-ports 10` |
| Modbus scan | `nmap 192.168.1.0/24 -p 502` |
| With scan delay (safe OT) | `nmap 192.168.1.1 --scan-delay 5s` |
| Single packet at a time | `nmap 192.168.1.1 --max-parallelism 1` |
| Modbus enumerate | `nmap -p 502 --script modbus-discover` |
| EtherNet/IP enumerate | `nmap -p 44818 --script enip-info` |
| Siemens S7 info | `nmap -p 102 --script s7-info` |
| IEC 60870-5-104 | `nmap -p 2404 --script iec-identify` |
| IEC 61850 MMS | `nmap -p 102 --script iec61850-mms` |
| BACnet discovery | `nmap -sU -p 47808 --script bacnet-info` |
| Tridium Fox | `nmap -p 1911 --script fox-info` |
| HART-IP | `nmap -p 5094 --script hartip-info` |
| PCWorx PLC | `nmap -p 1962 --script pcworx-info` |
| Omron FINS | `nmap -sU -p 9600 --script omron-info` |
| MQTT subscribe | `nmap -p 1883 --script mqtt-subscribe` |
| CoAP resources | `nmap -sU -p 5683 --script coap-resources` |
| KNX gateway | `nmap -sU -p 3671 --script knx-gateway-info` |
| PROFINET CM lookup | `nmap -sU -p 34962-34964 --script profinet-cm-lookup` |
| Export normal | `-oN filename.nmap` |
| Export XML | `-oX filename.xml` |
| Export grepable | `-oG filename.gnmap` |
| All formats | `-oA prefix` |

---

## APPENDIX: OT Protocol Risk Summary

| Protocol | Authentication | Encryption | Nmap Detectable | Risk Level |
|----------|---------------|------------|-----------------|------------|
| **Modbus** | None | None | ✅ Dedicated | 🔴 Critical |
| **DNP3** | Optional (Secure Auth) | Optional | ⚠️ Community script | 🟠 High |
| **Siemens S7** | Optional (basic) | None | ✅ Dedicated | 🟠 High |
| **EtherNet/IP (CIP)** | Optional | Optional | ✅ Dedicated | 🟠 High |
| **PROFINET** | None | None | ✅ Dedicated | 🔴 Critical |
| **IEC 60870-5-104** | Optional | None | ✅ Dedicated | 🟠 High |
| **IEC 61850 MMS** | Optional (ACSI) | None | ✅ Dedicated | 🟠 High |
| **BACnet** | Optional | None | ✅ Dedicated | 🟠 High |
| **MQTT** | Optional (username/pw) | Optional (TLS) | ✅ Dedicated | 🟠 High |
| **CoAP** | Optional (DTLS) | Optional (DTLS) | ✅ Dedicated | 🟡 Medium |
| **HART-IP** | Optional | Optional | ✅ Dedicated | 🟡 Medium |
| **OPC UA** | Yes (X.509) | Yes (TLS) | ⚠️ Partial | 🟢 Low |
| **Tridium Fox** | Optional | None | ✅ Dedicated | 🟠 High |
| **Omron FINS** | None | None | ✅ Dedicated | 🔴 Critical |
| **KNX** | Optional | Optional | ✅ Dedicated | 🟡 Medium |
| **EtherCAT** | None | None | ❌ Not Nmap | 🔴 Critical |

---

> **Practice targets:**
> - github.com/zakharb/labshock — Shock PLC Honeypot
> - github.com/mushorg/conpot — ICS Honeypot
> - github.com/mikeholcomb — OT/ICS cybersecurity resources
