# Lesser-Known & Emerging OT Protocols — NSE Coverage & Detection Gaps

> **Source:** nmap.org NSE documentation, protocol standards, open-source research
> **Retrieved:** 2026-07-11

---

## Summary: The Gap

**Official OT NSE scripts cover 17 protocol/device families.** There are **50+ known OT/ICS protocols** in active use worldwide. The official nmap distribution covers **~30%** of the OT protocol landscape. The remaining 70% require community scripts, custom NSE development, Wireshark dissectors, or dedicated OT scanning tools.

### 📦 Improved NSE Scripts (This Project)

Six improved NSE scripts have been developed for lesser-known OT protocols, each with a companion Python mock server for testing:

| Protocol | Port | Script | Mock Server | Status |
|----------|------|--------|-------------|--------|
| GE SRTP | 18245 | `gesrtp-info-improved.nse` | `gesrtp_mock_server.py` | ✅ Tested |
| OPC UA | 4840 | `opcua-discovery-improved.nse` | `opcua_mock_server.py` | ✅ Tested |
| MELSEC-Q | 5007 | `melsecq-info-improved.nse` | `melsecq_mock_server.py` | ✅ Tested |
| ProConOS | 20547 | `proconos-info-improved.nse` | `proconos_mock_server.py` | ✅ Tested |
| FF HSE | 1089 | `ff-hse-discover-improved.nse` | `ffhse_mock_server.py` | ✅ Tested |
| Red Lion Crimson | 789 | `redlion-cr3-info-improved.nse` | `redlion_mock_server.py` | ✅ Tested |

**Location:** `improved-scripts/lesser-known/` (NSE scripts) and `sandbox/` (mock servers + test results)

This document catalogs every discoverable protocol, its NSE coverage status, and alternative detection methods.

---

## Protocols with NO Official NSE Script

### 1. DNP3 — Distributed Network Protocol (TCP 20000, UDP 20000)

| Field | Value |
|-------|-------|
| **Standard** | IEEE 1815 (DNP3) |
| **Industries** | Electric utilities, water/wastewater, oil & gas |
| **NSE Coverage** | ❌ None in official distribution |
| **Alternative** | `atimorin/nmap-nse-dnp3` on GitHub; `plcscan`; Wireshark dissector |
| **Detection** | `nmap -p 20000 -sV --version-intensity 9` (basic banner, no detail) |
| **Risk** | T1-safe (read-only), T3 for direct operate (never on production) |

DNP3 is the **most glaring gap** in official OT NSE coverage — the dominant protocol for North American power grids has zero official script support.

---

### 2. Mitsubishi MELSEC / Q Series (TCP 5007)

| Field | Value |
|-------|-------|
| **Standard** | Mitsubishi proprietary (MC protocol / 3E frame) |
| **Industries** | Manufacturing, automotive, semiconductor |
| **NSE Coverage** | ✅ `melsecq-info-improved.nse` in `improved-scripts/lesser-known/` |
| **Alternative** | Community scripts (mitsubishi.nse on GitHub); `plcscan` |
| **Detection** | `nmap -p 5007 --script melsecq-info-improved.nse` |
| **Risk** | T1 with read-only commands; T3 for write (never on production) |

MELSEC/Q is pervasive in East Asian manufacturing (Toyota, TSMC supply chain) — a major blind spot. The improved script performs a MC protocol 3E-frame handshake to extract PLC type, series name, and firmware version.

---

### 3. GE SRTP — Service Request Transport Protocol (TCP 18245)

| Field | Value |
|-------|-------|
| **Standard** | GE proprietary |
| **Industries** | Power generation, water, manufacturing (GE PACSystems, 90-70) |
| **NSE Coverage** | ✅ `gesrtp-info-improved.nse` in `improved-scripts/lesser-known/` |
| **Alternative** | Community SRTP scripts on GitHub; `plcscan` |
| **Detection** | `nmap -p 18245 --script gesrtp-info-improved.nse` |
| **Risk** | T1 read-only (ident only); T3 for register writes |

GE SRTP is used in Mark VI/VII/VIII turbine control systems — critical for power generation. The improved script performs a two-phase INIT/INIT_ACK handshake then sends PLC_SSTAT to extract model, firmware, and CPU type.

---

### 4. ProConOS / MultiProg (TCP 20547)

| Field | Value |
|-------|-------|
| **Standard** | KW-Software / Phoenix Contact proprietary |
| **Industries** | Machine building, process control |
| **NSE Coverage** | ✅ `proconos-info-improved.nse` in `improved-scripts/lesser-known/` |
| **Alternative** | Community scripts (proconos.nse on GitHub); `plcscan` |
| **Detection** | `nmap -p 20547 --script proconos-info-improved.nse` |

---

### 5. OPC UA (TCP 4840, 4841, 4843)

| Field | Value |
|-------|-------|
| **Standard** | IEC 62541 |
| **Industries** | All — de facto standard for OT data exchange |
| **NSE Coverage** | ✅ `opcua-discovery-improved.nse` in `improved-scripts/lesser-known/` |
| **Alternative** | UaExpert; `opcua-asyncio` (Python) |
| **Detection** | `nmap -p 4840 --script opcua-discovery-improved.nse` |
| **Risk** | T1 (discovery endpoints are read-only by specification) |

OPC UA is the **most important missing script** — it's the integration backbone almost everywhere. The improved script performs HEL/ACK handshake then sends a FindServers request to extract application name, URI, and endpoint details.

---

### 6. ICCP / IEC 60870-6 TASE.2 (TCP 4000)

| Field | Value |
|-------|-------|
| **Standard** | IEC 60870-6 (TASE.2 / ICCP) |
| **Industries** | Electric utilities (control center-to-control center comms) |
| **NSE Coverage** | ❌ None |
| **Detection** | `nmap -p 4000 -sV --version-intensity 9`; MMS-type behavior |
| **Alternative** | Wireshark MMS dissector (protocol shares roots with MMS) |

---

### 7. Foundation Fieldbus HSE (TCP 1089-1091)

| Field | Value |
|-------|-------|
| **Standard** | IEC 61158, FF-586 |
| **Industries** | Process control (refineries, chemical plants) |
| **NSE Coverage** | ✅ `ff-hse-discover-improved.nse` in `improved-scripts/lesser-known/` |
| **Detection** | `nmap -p 1089 --script ff-hse-discover-improved.nse` |
| **Note** | Often tunneled or on isolated network segments |

---

### 8. EtherNet/IP — Additional Details (Not in NSE scope)

The `enip-info` script covers basic identity, but **NOT**:

- CIP object tree enumeration
- CIP safety data access
- CIP Motion configuration
- CIP Sync (IEEE 1588 PTP)

For deeper EtherNet/IP inspection, use: **CIPster**, **pycomm3**, or **Wireshark CIP dissector**.

---

### 9. BACnet — Additional Details

The `bacnet-info` script covers basic device/object enumeration, but **NOT**:

- BACnet schedule/calendar enumeration
- BACnet alarm/event log extraction
- BACnet trending data readback
- BACnet Secure Connect (BACnet/SC on port 48000)

---

### 10. S7 Protocol — Additional Details

The `s7-info` script reads identity information only. It does **NOT**:

- Enumerate S7 block types (OB, DB, FC, FB)
- Read DB contents
- Detect S7-1200/1500 secure configuration status
- Identify commissioning passwords

For deeper S7 inspection: **s7scan.py**, **Snap7**, or **python-snap7**.

---

## Protocols NOT Detectable by Nmap (Layer 2)

These protocols use raw Ethernet frames and require dedicated analyzers:

| Protocol | EtherType | Common Use |
|----------|-----------|-----------|
| **EtherCAT** | 0x88A4 | Motion control (Beckhoff, Omron) |
| **PROFINET RT** | 0x8892 | Factory automation (Siemens) |
| **PROFINET IRT** | 0x8892 | Isochronous motion control |
| **EtherNet/IP (CIP)** | 0x0800 (IP) | Factory automation |
| **POWERLINK** | 0x88AB | Motion control (B&R) |
| **SERCOS III** | 0x88CD | Motion control (Bosch Rexroth) |
| **GOOSE** | 0x88B8 | Substation automation (IEC 61850) |
| **Sampled Values** | 0x88BA | Substation automation (IEC 61850-9-2) |
| **CIP Safety** | 0x883C | Safety over CIP networks |
| **PROFIsafe** | 0x8863 | Safety over PROFINET |
| **Modbus RTU/ASCII** | N/A (serial) | Serial Modbus (when gateway-converted to IP) |
| **HART (4-20mA)** | N/A (analog) | Process instrumentation (when loop-powered) |
| **IO-Link** | N/A (serial) | Smart sensor/actuator communication |

**Nmap cannot detect these at all.** Use:
- **Wireshark** with appropriate capture filters (e.g., `eth.type == 0x88A4`)
- **Scapy** for raw socket capture
- **Dedicated OT network analyzers** (Hilscher netANALYZER, PROFICHK)

---

## Emerging / Growing Protocols

These protocols are relatively new in OT but gaining traction:

| Protocol | Port | Growing In | NSE Status |
|----------|------|-----------|-----------|
| **OPC UA PubSub** | Variable | Edge-to-cloud OT/IT integration | ❌ No script |
| **MQTT Sparkplug** | 1883 / 8883 | IIoT, cloud-connected OT | ❌ No script (basic MQTT exists) |
| **TSN (Time Sensitive Networking)** | N/A (L2) | Converged OT/IT networks | ❌ Not applicable |
| **CBOR/PACE** | OPC UA | OPC UA optimization | ❌ Not applicable |
| **API-over-HTTPS** | 443 | Modern OT (e.g., Siemens SINEC NMS) | Standard HTTP scripts |
| **AMQP 1.0** | 5671/5672 | OT telemetry bus | Standard AMQP scripts |

---

## Community Script Index (Third-Party)

| Protocol | Script | Repository | Quality | Last Updated |
|----------|--------|-----------|---------|-------------|
| DNP3 | `dnp3-info.nse` | atimorin/nmap-nse-dnp3 | Production | 2023+ |
| DNP3 | `dnp3-enumerate.nse` | atimorin/nmap-nse-dnp3 | Production | 2023+ |
| DNP3 | `dnp3-brute.nse` | atimorin/nmap-nse-dnp3 | Beta | 2023+ |
| Mitsubishi MELSEC | `melsecq-info-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| GE SRTP | `gesrtp-info-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| ProConOS | `proconos-info-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| Red Lion Crimson | `redlion-cr3-info-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| OPC UA | `opcua-discovery-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| FF HSE | `ff-hse-discover-improved.nse` | This project (`improved-scripts/lesser-known/`) | ✅ Tested | 2026 |
| Mitsubishi (legacy) | `melsec-q.nse` | scadastrangelove/nse | Beta | 2022 |
| GE SRTP (legacy) | `ge-srtp.nse` | scadastrangelove/nse | Beta | 2022 |
| ProConOS (legacy) | `proconos.nse` | scadastrangelove/nse | Beta | 2022 |
| Red Lion (legacy) | `redlion.nse` | scadastrangelove/nse | Beta | 2022 |
| OPC UA | `opcua-info.nse` | Multiple forks | Alpha | 2023 |
| OPC UA | `opcua-discovery.nse` | isaacVergun/nse | Alpha | 2022 |

### Installation (Third-Party Scripts)
```bash
# Clone community OT NSE scripts
git clone https://github.com/atimorin/nmap-nse-dnp3.git
cp *.nse /usr/local/share/nmap/scripts/

# Verify
nmap --script-help dnp3-info

# Update script database
nmap --script-updatedb
```

---

## ✅ Completed: Custom NSE Development

Six custom OT NSE scripts have been developed, tested, and verified:

| Priority | Protocol | Script | Status |
|----------|----------|--------|--------|
| 1 | **DNP3** | (separate project — `atimorin/nmap-nse-dnp3`) | ❌ Not in this project |
| 2 | **OPC UA** | `opcua-discovery-improved.nse` | ✅ Complete (Tested) |
| 3 | **Mitsubishi MELSEC** | `melsecq-info-improved.nse` | ✅ Complete (Tested) |
| 4 | **GE SRTP** | `gesrtp-info-improved.nse` | ✅ Complete (Tested) |
| 5 | **ProConOS** | `proconos-info-improved.nse` | ✅ Complete (Tested) |
| 6 | **Red Lion Crimson** | `redlion-cr3-info-improved.nse` | ✅ Complete (Tested) |
| 7 | **FF HSE** | `ff-hse-discover-improved.nse` | ✅ Complete (Tested) |
| — | **ICCP** | Not yet developed | ⬜ Future |

### Still Pending (Not Covered)

- **ICCP / IEC 60870-6 TASE.2** (TCP 4000) — Control center interconnect
- **MQTT Sparkplug** (TCP 1883/8883) — IIoT telemetry
- **DNP3** — Already covered by `atimorin/nmap-nse-dnp3` (separate project)
