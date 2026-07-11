# NSE Script Catalog — Detailed Reference

> **Source:** Official nmap.org NSE documentation (17 OT/ICS-dedicated scripts)
> **Retrieved:** 2026-07-11

> **📁 NSE Script Locations by OS:**
> These scripts ship with nmap. Where they live depends on your platform:
> - **macOS (Homebrew):** `/opt/homebrew/share/nmap/scripts/`
> - **Linux (apt/dnf/pacman):** `/usr/share/nmap/scripts/`
> - **Windows (installer):** `C:\Program Files (x86)\Nmap\scripts\`
> - **Windows (Chocolatey):** `C:\ProgramData\chocolatey\lib\nmap\tools\nmap\scripts\`
> - **User scripts (any OS):** `~/.nmap/scripts/` (Linux/macOS) or `%USERPROFILE%\.nmap\scripts\` (Windows)
>
> After installing nmap, you can verify scripts are present with:
> ```bash
> nmap --script-updatedb
> ls /usr/share/nmap/scripts/ | grep -E 's7-info|modbus-discover|bacnet-info'   # Linux
> ls /opt/homebrew/share/nmap/scripts/ | grep -E 's7-info|modbus-discover|bacnet-info'  # macOS
> ```

---

## 1. BACnet Info

| Field | Value |
|-------|-------|
| **Script** | `bacnet-info` |
| **Category** | discovery |
| **Protocol** | BACnet/IP (UDP 47808 — 0xBAC0) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Enumerates BACnet devices on UDP port 47808. Discovers device instances, vendor IDs, firmware versions, and object lists via BACnet Who-Is / ReadProperty requests.

### Usage
```bash
nmap -p 47808 --script bacnet-info <target>
nmap -sU -p 47808 --script bacnet-info <target>
```

### Key Output Fields
- **Device Instance**: Unique BACnet device identifier
- **Vendor Name**: Manufacturer string
- **Firmware Version**: Application/firmware revision
- **Object Count**: Number of BACnet objects exposed
- **Protocol Version**: BACnet protocol revision (1, 14, etc.)

### Blue Team Notes
- BACnet broadcast discovery (`--script bacnet-info -p 47808 255.255.255.255`) can enumerate entire segments
- Non-intrusive read; does not write to any BACnet objects
- Useful for asset inventory of BAS/BMS systems

---

## 2. Siemens S7 Info

| Field | Value |
|-------|-------|
| **Script** | `s7-info` |
| **Category** | discovery |
| **Protocol** | Siemens S7 (TCP 102) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Connects to Siemens S7 PLCs and extracts identifying information: module type, serial number, hardware/firmware version, plant designation, and module identification.

### Usage
```bash
nmap -p 102 --script s7-info <target>
```

### Key Output Fields
- **Module**: Specific model (e.g., "6ES7 414-3EM07-0AB0")
- **Hardware**: Hardware version string
- **Firmware**: Firmware version (e.g., "V4.0.0")
- **Serial Number**: Device serial number
- **Plant Designation**: User-assigned name (if configured)

### Blue Team Notes
- One of the most useful OT discovery scripts
- S7-300/400, S7-1200, S7-1500 all respond (though newer models may require auth)
- Serial numbers enable firmware CVE correlation
- Plant designation often reveals organizational context (line/zone/area)

---

## 3. Modbus Discover

| Field | Value |
|-------|-------|
| **Script** | `modbus-discover` |
| **Category** | discovery |
| **Protocol** | Modbus/TCP (TCP 502) |
| **Risk** | Warning — reads only, but some legacy PLCs may glitch |
| **T-Level** | T1 (but use with caution) |

### Description
Scans Modbus device ID range (1-255) and reads: device identification (0x2B 0x0E), coil/descrete input status (0x01/0x02), and register ranges (0x03/0x04).

### Usage
```bash
nmap -p 502 --script modbus-discover <target>
nmap -p 502 --script modbus-discover --script-args modbus-discover.aggressive=true <target>
```

### Key Output Fields
- **Device ID**: Unit identifier (1-247)
- **Vendor / Product / Revision**: Read from 0x2B identification
- **Slave ID**: Raw slave ID response
- **Coil Status**: First 20 coils read-only (non-aggressive)
- **Register Previews**: First 20 holding/input registers

### Blue Team Notes
- Aggressive mode reads more registers — use only on isolated/test networks
- Some Schneider, Omron, and older Siemens PLCs may fault on extended reads
- Start with `--script-args modbus-discover.aggressive=false` (default)
- For read-only asset discovery, safe on most modern Modbus devices

---

## 4. EtherNet/IP Info

| Field | Value |
|-------|-------|
| **Script** | `enip-info` |
| **Category** | discovery |
| **Protocol** | EtherNet/IP (TCP/UDP 44818) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Queries EtherNet/IP devices via TCP or UDP port 44818 using the EtherNet/IP encapsulation layer. Retrieves vendor, device type, product name, serial number, revision, and status.

### Usage
```bash
nmap -p 44818 --script enip-info <target>
nmap -sU -p 44818 --script enip-info <target>
```

### Key Output Fields
- **Vendor ID**: EtherNet/IP vendor code
- **Product Name**: Human-readable product name
- **Serial Number**: Device serial (often unique per unit)
- **Device Revision**: Major.minor revision
- **State**: Device state (Standby, Operational, etc.)

### Blue Team Notes
- Rockwell/Allen-Bradley, Omron, Schneider, and many others use this protocol
- UDP broadcast discovery can find all EtherNet/IP devices on a subnet
- Completely passive read; no state changes made

---

## 5. Tridium Fox Info

| Field | Value |
|-------|-------|
| **Script** | `fox-info` |
| **Category** | discovery |
| **Protocol** | Tridium Fox (TCP 1911) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Connects to Tridium Niagara AX/N4 Fox services and extracts system information: Niagara version, station name, host ID, and brand.

### Usage
```bash
nmap -p 1911 --script fox-info <target>
```

### Key Output Fields
- **Niagara Version**: e.g., "4.8.0.89"
- **Station Name**: User-configured station name
- **Fox Brand**: Brand string (e.g., "Tridium")
- **Host ID**: Platform host identifier

### Blue Team Notes
- Niagara stations are common in building management, critical infrastructure (universities, hospitals, airports)
- Version info maps directly to known CVEs (Niagara 3.x-4.x have multiple RCEs)
- Station name + host ID enables asset tracking across sites

---

## 6. HART-IP Info

| Field | Value |
|-------|-------|
| **Script** | `hartip-info` |
| **Category** | discovery |
| **Protocol** | HART-IP (TCP/UDP 5094) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Queries HART-IP gateways and field devices for identity information: device type, manufacturer, revision level, and device ID.

### Usage
```bash
nmap -p 5094 --script hartip-info <target>
nmap -sU -p 5094 --script hartip-info <target>
```

### Key Output Fields
- **Manufacturer**: Manufacturer code and string
- **Device Type**: Device type code
- **Device ID**: Unique device identifier
- **Revision Levels**: Hardware / firmware / software revisions

### Blue Team Notes
- HART-IP gateways bridge 4-20mA analog loops to IP networks
- Often found in process control (refineries, chemical plants, pipelines)
- Device ID can be cross-referenced with HART Communication Foundation registry

---

## 7. PCWorx Info

| Field | Value |
|-------|-------|
| **Script** | `pcworx-info` |
| **Category** | discovery |
| **Protocol** | PCWorx (TCP 1962) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Connects to Phoenix Contact PCWorx PLCs and extracts device information including model, serial number, firmware version, and runtime state.

### Usage
```bash
nmap -p 1962 --script pcworx-info <target>
```

### Key Output Fields
- **CPU Module**: Specific CPU model
- **Serial Number**: Device serial number
- **Firmware Version**: Firmware version string
- **Device State**: Device operating state

---

## 8. Omron FINS Info

| Field | Value |
|-------|-------|
| **Script** | `omron-info` |
| **Category** | discovery |
| **Protocol** | Omron FINS (TCP/UDP 9600) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Queries Omron PLCs using the FINS protocol (TCP or UDP) for model information, serial number, and version data.

### Usage
```bash
nmap -p 9600 --script omron-info <target>
nmap -sU -p 9600 --script omron-info <target>
```

### Key Output Fields
- **Model**: PLC model string (e.g., "CJ2M-CPU31")
- **Serial Number**: Unit serial
- **Version**: FINS version / system version
- **Area**: Memory area info

### Blue Team Notes
- Omron PLCs widely used in packaging, automotive, semiconductor manufacturing
- FINS protocol has no authentication (all operations are authorized by default)
- Use this first, then consider — NEVER — omron-cp1r-enum (see appendix)

---

## 9. IEC 60870-5-104 Identify

| Field | Value |
|-------|-------|
| **Script** | `iec-identify` |
| **Category** | discovery |
| **Protocol** | IEC 60870-5-104 (TCP 2404) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Identifies IEC 60870-5-104 devices by sending a STARTDT (start data transfer) request and analyzing the response for station addressing and ASDU type info.

### Usage
```bash
nmap -p 2404 --script iec-identify <target>
```

### Key Output Fields
- **Station Address**: Identified RTU/station address
- **ASDU Types**: Supported ASDU types (monitoring, control, etc.)
- **Originator Address**: Originating address (if configured)

### Blue Team Notes
- IEC 104 is dominant in European power grids, water/wastewater
- STARTDT is a standard session-start message — not intrusive
- Does not issue control commands or modify data points

---

## 10. IEC 61850 MMS

| Field | Value |
|-------|-------|
| **Script** | `iec61850-mms` |
| **Category** | discovery |
| **Protocol** | IEC 61850 MMS (TCP 102) |
| **Risk** | Warning — MMS read requests may impact slow substation devices |
| **T-Level** | T1 (but use with caution on in-service devices) |

### Description
Reads IEC 61850 MMS server information and data model: server identity, logical devices, logical nodes, data objects, and data attributes.

### Usage
```bash
nmap -p 102 --script iec61850-mms <target>
```

### Key Output Fields
- **Server Identity**: Model, vendor, revision
- **Logical Devices**: List of logical devices (e.g., "PROT", "CTRL", "MEAS")
- **Logical Nodes**: Detailed node structure
- **Data Set Definitions**: Predefined data sets

### Blue Team Notes
- IEC 61850 is the standard for substation automation (digital substations)
- MMS shares port 102 with Siemens S7 — use version detection to differentiate
- On large substations, MMS read requests can cause CPU load on protection IEDs
- Use during maintenance windows on production substations
- Does NOT issue control commands

---

## 11. MQTT Subscribe

| Field | Value |
|-------|-------|
| **Script** | `mqtt-subscribe` |
| **Category** | discovery |
| **Protocol** | MQTT (TCP 1883, 8883 TLS) |
| **Risk** | Warning — subscribes to topics, which reads live data flow |
| **T-Level** | T1 (passive, but reads live data) |

### Description
Subscribes to MQTT broker topics (configurable via `mqtt-subscribe.topics`) and reports received messages. Default subscribes to `#` (all topics).

### Usage
```bash
nmap -p 1883 --script mqtt-subscribe <target>
nmap -p 1883 --script mqtt-subscribe --script-args 'mqtt-subscribe.topics={"sensors/#","status/#"}' <target>
```

### Key Output Fields
- **Broker Version**: Broker software/version banner
- **Topic**: Full topic string
- **Message Contents**: Last published message per topic
- **QoS**: Quality of Service level (0, 1, or 2)

### Blue Team Notes
- Subscribing to `#` on a live production broker reads ALL messages
- May violate data confidentiality policies (reading process data, setpoints, alarms)
- Can be intrusive if broker pushes large retained-message volumes
- Prefer targeted topic subscription over `#` on operational networks

---

## 12. CoAP Resources

| Field | Value |
|-------|-------|
| **Script** | `coap-resources` |
| **Category** | discovery |
| **Protocol** | CoAP (UDP 5683) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Discovers CoAP endpoints/resources by sending a `.well-known/core` query, which returns the resource directory of the CoAP server.

### Usage
```bash
nmap -sU -p 5683 --script coap-resources <target>
```

### Key Output Fields
- **URI**: Resource path (e.g., `/temp`, `/pressure`, `/actuator/valve1`)
- **Content Type**: Media type reported
- **Observable**: Whether resource supports observation (push updates)

### Blue Team Notes
- CoAP is the UDP counterpart to HTTP — common in constrained IoT/OT devices
- `.well-known/core` is the mandatory discovery endpoint per RFC 7252
- Non-intrusive single GET request

---

## 13. KNX Gateway Info

| Field | Value |
|-------|-------|
| **Script** | `knx-gateway-info` |
| **Category** | discovery |
| **Protocol** | KNXnet/IP (UDP 3671) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Discovers KNXnet/IP gateways by sending a DESCRIPTION_REQUEST and reading the DIB (Device Information Block) response.

### Usage
```bash
nmap -sU -p 3671 --script knx-gateway-info <target>
```

### Key Output Fields
- **Device Name**: KNX gateway name
- **Manufacturer**: Manufacturer code and string
- **Serial Number**: Device serial
- **KNX Medium**: Twisted Pair, Powerline, RF, or IP
- **Programming Mode**: Whether programming mode is active

---

## 14. KNX Gateway Discover (Broadcast)

| Field | Value |
|-------|-------|
| **Script** | `knx-gateway-discover` |
| **Category** | discovery |
| **Protocol** | KNXnet/IP (UDP 3671 broadcast) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Same as `knx-gateway-info` but sends to broadcast address to discover all KNX gateways on the subnet.

### Usage
```bash
nmap --script knx-gateway-discover
```

### Blue Team Notes
- KNX is dominant in European building automation (lighting, HVAC, blinds)
- Broadcasting discovers all gateways in one query
- Absolutely passive single-request discovery

---

## 15. PROFINET CM Lookup

| Field | Value |
|-------|-------|
| **Script** | `profinet-cm-lookup` |
| **Category** | discovery |
| **Protocol** | PROFINET CM (Context Manager) (UDP 34964) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |

### Description
Discovers PROFINET IO devices via Context Manager protocol. Retrieves device name, vendor, serial, and station name.

### Usage
```bash
nmap -sU -p 34964 --script profinet-cm-lookup <target>
```

### Key Output Fields
- **Station Name**: Configured PROFINET station name
- **Vendor ID**: Manufacturer code
- **Device ID**: Device type code
- **Serial Number**: Hardware serial
- **IP Configuration**: Assigned IP/settings

---

## 16. Multicast PROFINET Discovery

| Field | Value |
|-------|-------|
| **Script** | `multicast-profinet-discovery` |
| **Category** | discovery |
| **Protocol** | PROFINET DCP (Ethernet multicast) |
| **Risk** | Safe |
| **T-Level** | T1 (Passive Query) |
| **Layer** | L2 (Ethernet) |

### Description
Sends a PROFINET DCP Identify All request (multicast) to discover all PROFINET devices on the local Ethernet segment. This is a Layer 2 scan.

### Usage
```bash
nmap --script multicast-profinet-discovery
```

### Blue Team Notes
- PROFINET DCP operates at Layer 2 — this script sends raw Ethernet frames
- Requires root privileges on Linux (not typically available on macOS without npcap/WinPcap)
- Best for local network segment discovery
- Does NOT work across routers (Layer 2 only)

---

## 17. Stuxnet Detection

| Field | Value |
|-------|-------|
| **Script** | `stuxnet-detect` |
| **Category** | safe |
| **Protocol** | Siemens S7 (TCP 102) |
| **Risk** | Safe (detection only) |
| **T-Level** | T1 (Passive Query) |

### Description
Detects Siemens WinCC / Siemens Step 7 systems that may be infected with Stuxnet-like malware by checking for specific DLL/settings modifications.

### Usage
```bash
nmap -p 102 --script stuxnet-detect <target>
```

### Key Output Fields
- **Check Name**: Specific check performed
- **Status**: Clean / Infected / Unknown
- **Detail**: Reason for status

### Blue Team Notes
- Checks are signature-based (known Stuxnet indicators)
- Historical script — relevant for legacy installations (Step 7 v5.x, WinCC)
- Not a general malware scanner; only checks Stuxnet-specific indicators

---

## Appendix: Community / Third-Party OT Scripts

These are NOT in the official nmap distribution but found on GitHub or other sources.
To use them, copy to `~/.nmap/scripts/` (Linux/macOS) or `%USERPROFILE%\.nmap\scripts\` (Windows) and run `nmap --script-updatedb`.
Alternatively, use the full path: `--script /path/to/script.nse`.


| Script | Protocol | Repository | Notes |
|--------|----------|------------|-------|
| `dnp3-info.nse` | DNP3 (TCP 20000) | atimorin/nmap-nse-dnp3 | Reads DNP3 device attributes |
| `dnp3-enumerate.nse` | DNP3 (TCP 20000) | atimorin/nmap-nse-dnp3 | Enumerates DNP3 points/indications |
| `dnp3-brute.nse` | DNP3 (TCP 20000) | atimorin/nmap-nse-dnp3 | Brute-force DNP3 addresses |
| `melsec-q.nse` | Mitsubishi MELSEC (TCP 5007) | Community | Gets PLC model/info |
| `ge-srtp.nse` | GE SRTP (TCP 18245) | Community | GE PACSystems/90-70 info |
| `proconos.nse` | ProConOS (TCP 20547) | Community | KW-Software / Phoenix Contact info |
| `redlion.nse` | Red Lion (TCP 789) | Community | Red Lion HMI/RTU info |
| | | | |
| **Improved Scripts — This Project** | (`improved-scripts/lesser-known/`) | | |
| `melsecq-info-improved.nse` | Mitsubishi MELSEC (TCP 5007) | ✅ Tested | MC protocol 3E-frame handshake → PLC type/series/firmware |
| `gesrtp-info-improved.nse` | GE SRTP (TCP 18245) | ✅ Tested | INIT/INIT_ACK handshake + PLC_SSTAT → model/firmware/CPU |
| `proconos-info-improved.nse` | ProConOS (TCP 20547) | ✅ Tested | 0xcc probe → runtime/PLC model/project info |
| `redlion-cr3-info-improved.nse` | Red Lion Crimson (TCP 789) | ✅ Tested | STX-based query → model/firmware/part/vendor |
| `opcua-discovery-improved.nse` | OPC UA (TCP 4840) | ✅ Tested | HEL/ACK handshake + FindServers → app/endpoint info |
| `ff-hse-discover-improved.nse` | FF HSE (TCP 1089) | ✅ Tested | LREQ probe → device/vendor/tag/version/stack |
