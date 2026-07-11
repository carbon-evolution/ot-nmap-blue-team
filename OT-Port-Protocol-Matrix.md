# OT Port / Protocol / NSE Matrix

> **Source:** Official nmap.org NSE documentation, IANA registries, vendor documentation
> **Retrieved:** 2026-07-11

> **📁 NSE Script Installation Locations:**
> All official NSE scripts (`s7-info`, `modbus-discover`, `enip-info`, `fox-info`, `hartip-info`,
> `pcworx-info`, `omron-info`, `iec61850-mms`, `bacnet-info`, `mqtt-subscribe`, `knx-gateway-info`,
> `knx-gateway-discover`, `coap-resources`, `profinet-cm-lookup`, etc.) ship with nmap:
> - **macOS (Homebrew):** `/opt/homebrew/share/nmap/scripts/`
> - **Linux:** `/usr/share/nmap/scripts/`
> - **Windows:** `C:\Program Files (x86)\Nmap\scripts\`
> - **User scripts:** `~/.nmap/scripts/` (Linux/macOS) or `%USERPROFILE%\.nmap\scripts\` (Windows)
>
> Community scripts (marked *Third-party* in matrix below) must be manually downloaded to
> the user scripts directory and registered via `nmap --script-updatedb`.

---

## Complete Port-to-Protocol-to-NSE Mapping

| Port | Transport | Protocol | Official NSE Script | Risk | Layer |
|------|-----------|----------|---------------------|------|-------|
| **102** | TCP | Siemens S7, IEC 61850 MMS | `s7-info`, `iec61850-mms` | Safe / Warning | L7 |
| **502** | TCP | Modbus/TCP | `modbus-discover` | Warning | L7 |
| **789** | TCP | Red Lion | *Third-party* | Safe | L7 |
| **960** | UDP | OPC UA Discovery | — (use `opcua-discovery.nse` in community) | Safe | L7 |
| **1089** | TCP | FF HSE (Foundation Fieldbus) | — | Safe | L7 |
| **1090** | TCP | FF HSE | — | Safe | L7 |
| **1091** | TCP | FF HSE | — | Safe | L7 |
| **1541** | TCP-UDP | Fox (Tridium Niagara 2.x) | — | Safe | L7 |
| **1911** | TCP-UDP | Fox (Tridium Niagara 3.x+) | `fox-info` | Safe | L7 |
| **1962** | TCP | PCWorx (Phoenix Contact) | `pcworx-info` | Safe | L7 |
| **2222** | TCP | EtherNet/IP (EDS) | — | — | L7 |
| **2404** | TCP | IEC 60870-5-104 | `iec-identify` | Safe | L7 |
| **3671** | UDP | KNXnet/IP | `knx-gateway-info` / `knx-gateway-discover` | Safe | L7 |
| **4000** | TCP | ICCP / IEC 60870-6 TASE.2 | — | Safe | L7 |
| **44818** | TCP-UDP | EtherNet/IP | `enip-info` | Safe | L7 |
| **47808** | UDP | BACnet/IP | `bacnet-info` | Safe | L7 |
| **(0xBAC0)** | | | | | |
| **48000** | TCP | BACnet/SC | — | — | L7 |
| **4840** | TCP-UDP | OPC UA Binary | — | Safe | L7 |
| **4841** | TCP | OPC UA Discovery | — | Safe | L7 |
| **4843** | TCP | OPC UA HTTPS | — | Safe | L7 |
| **5001** | TCP | Emerson / GE (PACSystems) | — | — | L7 |
| **5007** | TCP | Mitsubishi MELSEC/Q | *Third-party* | Warning | L7 |
| **5050** | TCP | MMS (G&W / Schweitzer) | — | — | L7 |
| **5051** | TCP | MMS (SEL) | — | — | L7 |
| **5052** | TCP | MMS (SEL) | — | — | L7 |
| **5053** | TCP | MMS (SEL) | — | — | L7 |
| **5054** | TCP | MMS (SEL) | — | — | L7 |
| **5094** | TCP-UDP | HART-IP | `hartip-info` | Safe | L7 |
| **5500** | TCP | VNC (HMIs often run this) | `realvnc-auth-bypass`, etc. | — | L7 |
| **5683** | UDP | CoAP | `coap-resources` | Safe | L7 |
| **5900** | TCP | VNC (Operator HMIs) | `vnc-info` | Safe | L7 |
| **6000-6009** | TCP | X11 (HMI workstations) | — | Risk | L7 |
| **8080** | TCP | HTTP (HMI web interfaces) | `http-enum`, `http-title` | Safe | L7 |
| **8443** | TCP | HTTPS (HMI web interfaces) | `ssl-enum-ciphers` | Safe | L7 |
| **9600** | TCP-UDP | Omron FINS | `omron-info` | Safe | L7 |
| **161** | UDP | SNMP (OT devices) | `snmp-info`, `snmp-interfaces` | Safe | L7 |
| **18245** | TCP | GE SRTP (PACSystems/90-70) | *Third-party* | Warning | L7 |
| **20000** | TCP | DNP3 | *Third-party* | Safe | L7 |
| **20547** | TCP | ProConOS (KW/MultiProg) | *Third-party* | Warning | L7 |
| **34962-34964** | UDP | PROFINET | `profinet-cm-lookup`, `multicast-profinet-discovery` | Safe | L7/L2 |
| **47809** | UDP | BACnet/IPv6 | — | Safe | L7 |

---

## Layer 2 Protocols (Not Nmap-Detectable)

These protocols operate below IP and require specialized tools:

| Protocol | EtherType | Standard | Common HW | Detection Tool |
|----------|-----------|----------|-----------|----------------|
| **EtherCAT** | 0x88A4 | IEC 61158 | Beckhoff, Omron | Wireshark, ELS |
| **PROFINET RT** | 0x8892 | IEC 61158 | Siemens | Wireshark, nping |
| **PROFIsafe** | 0x8863 | IEC 61784-3 | Siemens | Wireshark |
| **POWERLINK** | 0x88AB | Ethernet POWERLINK | B&R | Wireshark |
| **SERCOS III** | 0x88CD | IEC 61158 | Bosch Rexroth | Wireshark |
| **GOOSE** | 0x88B8 | IEC 61850 | GE, Siemens, SEL | Wireshark, Scapy |
| **SV (Sampled Values)** | 0x88BA | IEC 61850-9-2 | GE, Siemens | Wireshark |
| **CIP Safety** | 0x883C | ODVA | Rockwell | Wireshark |

---

## Safe Scanning Strategy by Protocol

### T1 — Passive / Read-Only (Safe on Production)

| Protocol | NSE Script | Flag |
|----------|-----------|------|
| BACnet/IP | `bacnet-info` | `-sU -p 47808` |
| Siemens S7 | `s7-info` | `-p 102` |
| EtherNet/IP | `enip-info` | `-p 44818 -sU` |
| Fox (Niagara) | `fox-info` | `-p 1911` |
| HART-IP | `hartip-info` | `-p 5094 -sU` |
| PCWorx | `pcworx-info` | `-p 1962` |
| Omron FINS | `omron-info` | `-p 9600 -sU` |
| IEC 104 | `iec-identify` | `-p 2404` |
| CoAP | `coap-resources` | `-sU -p 5683` |
| KNX | `knx-gateway-*` | `-sU -p 3671` |
| PROFINET | `profinet-cm-lookup` | `-sU -p 34964` |
| Stuxnet | `stuxnet-detect` | `-p 102` |
| DNP3 | *Third-party* | `-p 20000` |

### T2 — Use With Caution on Production

| Protocol | NSE Script | Concern |
|----------|-----------|---------|
| Modbus/TCP | `modbus-discover` | Some legacy PLCs fault on extended register reads |
| IEC 61850 MMS | `iec61850-mms` | CPU load on protection IEDs during full model read |
| MQTT | `mqtt-subscribe` | Reads live data; `#` subscription reads everything |

### T3 — Never on Production (Lab Only)

| Protocol | Purpose | Risk |
|----------|---------|------|
| Modbus write | Writing coils/registers | Can start/stop physical processes |
| DNP3 direct operate | Control commands | Can open/close breakers, move valves |
| S7 WRITE | Writing PLC memory | Overwrites logic, can cause damage |
| FINS command write | Omron writes | No auth — fully destructive writes possible |

---

## Recommended Scan Command Cheat Sheet

### Subnet Discovery (Find Everything)
```bash
# BACnet broadcast
nmap -sU -p 47808 --script bacnet-info 255.255.255.255

# KNX broadcast
nmap -sU -p 3671 --script knx-gateway-discover

# PROFINET L2 multicast (requires raw sockets)
nmap --script multicast-profinet-discovery

# Sweep common OT ports with version detection
nmap -sT -sU -p 102,502,1911,1962,2404,44818,47808,4840,5094,9600,20000,18245,20547,789,5007 -sV --version-intensity 9 <subnet>
```

### Single Device Deep Dive
```bash
# Full OT discovery on one target
nmap -sT -sU -p U:161,3671,44818,47808,5094,5683,9600,\
T:102,502,789,1911,1962,2404,44818,4840,5094,9600,\
18245,20000,20547,5007,8080,8443,5900 \
-sV --version-intensity 9 \
--script bacnet-info,s7-info,modbus-discover,enip-info,fox-info,\
pcworx-info,omron-info,hartip-info,iec-identify,iec61850-mms,\
coap-resources,knx-gateway-info,mqtt-subscribe,stuxnet-detect \
<target>
```

### First-Contact In-Service Scan (Safe-Only)
```bash
# Only T1-safe protocols (for initial discovery on live OT network)
nmap -sT -sU -p T:102,1911,1962,2404,44818,5094,\
U:3671,44818,47808,5094,5683,9600 \
--script bacnet-info,s7-info,enip-info,fox-info,\
pcworx-info,omron-info,hartip-info,iec-identify,\
coap-resources,knx-gateway-info,stuxnet-detect \
--script-args modbus-discover.aggressive=false \
<target>
```
