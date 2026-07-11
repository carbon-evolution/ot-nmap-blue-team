# Blue Team OT/ICS Scanning Methodology — Research Report

> **Source:** NIST SP 800-82 Rev.3, SANS ICS/SCADA guidance, MITRE ATT&CK for ICS, CISA alerts
> **Retrieved:** 2026-07-11

---

## 1. Framework Alignment

### NIST SP 800-82 Rev.3 — Guide to ICS Security

The OT scanning methodology aligns with the following control families:

| Control Family | Relevant Controls | Scan Application |
|---------------|-------------------|------------------|
| RA (Risk Assessment) | RA-3, RA-5 | Vulnerability scanning via NSE |
| CM (Configuration Management) | CM-8 | Asset inventory via protocol discovery |
| CA (Security Assessment) | CA-2, CA-8 | Control assessments, penetration testing |
| IA (Identification & Auth) | IA-3 | Device identification via protocol fingerprinting |
| SI (System/Info Integrity) | SI-2, SI-7 | Firmware version detection for patch compliance |

### MITRE ATT&CK for ICS — Mapping

| ICS Tactic | Technique ID | Technique Name | NSE Coverage |
|-----------|-------------|----------------|-------------|
| **Initial Access** | T0842 | Engineering Workstation Compromise | — |
| **Discovery** | T0881 | OT Asset Discovery | All 17 OT NSE scripts |
| **Discovery** | T0886 | Remote System Information Discovery | `s7-info`, `enip-info`, `modbus-discover` |
| **Discovery** | T0887 | Network Service Scanning | Port-based OT discovery |
| **Discovery** | T0890 | I/O Module Discovery | `modbus-discover` (register/coil scanning) |
| **Collection** | T0812 | Protocol-Aware Collection | `mqtt-subscribe`, `coap-resources` |
| **Collection** | T0802 | Automated Collection | Scheduled NSE scanning |

### SANS ICS/SCADA Security Guidance

- **SANS ICS410**: Foundation-level scanning with Wireshark / tcpdump
- **SANS ICS515**: ICS Active Defense — scan methodology, network segmentation validation
- **SANS ICS456**: Passive asset discovery (which NSE aligns with — all T1 scripts are effectively passive)

---

## 2. Scan Lifecycle Methodology

### Phase 1: Passive Reconnaissance (Offline / PCAP Analysis)

**Before any active scan**, analyze existing network traffic:

```bash
# Extract OT protocol metadata from PCAPs
tshark -r capture.pcap -T fields -e bacnet.device.instance 2>/dev/null
tshark -r capture.pcap -Y "modbus.tcp" -T fields -e modbus.unit_id
tshark -r capture.pcap -Y "dnp3" -T fields -e dnp3.data_obj
```

**Goals:**
- Identify which OT protocols are in use
- Map device IPs and communications patterns
- Baseline normal traffic (traffic volume, timing, direction)
- No network impact — 100% safe

### Phase 2: Targeted Active Discovery (T1 Only)

**Run only Safe scripts on production:**

```bash
# Per-protocol gentle probes
nmap -p 102 --script s7-info,stuxnet-detect <target>
nmap -sU -p 47808 --script bacnet-info <subnet>
nmap -p 44818 --script enip-info <target>
```

**Golden Rule:** One protocol at a time. Observe device behavior between probes.

### Phase 3: Comprehensive Asset Inventory (T1 + Cautionary T2)

**Full read-only sweep with monitoring:**

```bash
# Full T1 + selected T2 with rate limiting
nmap -T2 --min-rate 50 --max-rate 200 \
  -sT -sU -p U:161,3671,44818,47808,5094,5683,9600,\
  T:102,502,1911,1962,2404,44818,4840,5094,9600,18245,20000,20547,5007 \
  --script bacnet-info,s7-info,enip-info,fox-info,pcworx-info,\
  omron-info,hartip-info,iec-identify,mqtt-subscribe,modbus-discover \
  --script-args modbus-discover.aggressive=false \
  -oA ot-inventory-$(date +%Y%m%d) <target>
```

**Key practices:**
- Use `-T2` or `-T1` timing (slow, polite)
- Rate limit with `--min-rate` / `--max-rate`
- Log everything with `-oA` (all formats)
- Run during maintenance windows if possible

### Phase 4: Vulnerability Mapping

**Correlate discovered versions with CVEs:**

| Discovered Version | Potential CVEs |
|-------------------|----------------|
| Siemens S7-1200 FW < 4.5 | CVE-2021-22619, CVE-2021-37205 |
| Niagara AX 3.8 | CVE-2022-21129 and 70+ others |
| Modicon Quantum (any) | CVE-2021-22778, CVE-2021-22779 |
| BACnet OWSVR < 3.5.0 | CVE-2020-13815 (DoS) |
| MQTT Mosquitto < 2.0.15 | CVE-2021-34433, CVE-2021-34434 |
| Omron CJ/NJ < specific | CVE-2021-22718, CVE-2021-22719 |

### Phase 5: Risk Scoring & Prioritization

**Per-asset risk = Exposure × Criticality × Exploitability**

| Factor | Scoring | Data Source |
|--------|---------|------------|
| Exposure | NSE scripts that succeeded (reachable via IT/OT boundary) | Scan output |
| Criticality | Asset function (PLC, HMI, RTU, Gateway, Historian, Engineering WS) | Protocol type + plant designation from NSE |
| Exploitability | Known CVEs for discovered versions | NVD, CISA KEV, ICS-CERT |
| Network Positioning | Segmented vs. flat, DMZ vs. cell, VPN at boundary | Network diagram + hop count |

**Priority matrix:**

```text
High Priority:
  - Engineering Workstations with direct PLC access
  - PLCs in zones accessible from IT network
  - HMIs with unauthenticated remote access (VNC, X11)
  - Firmware versions with public exploits (CISA KEV)

Medium Priority:
  - PLCs in well-segmented zones
  - Gateways with outdated firmware but no known exploit
  - IEDs/RTUs with limited attack surface

Low Priority:
  - Isolated devices (air-gapped)
  - Read-only sensors in physically secured zones
```

---

## 3. Operational Safety Guidelines

### Before Scanning

1. **Obtain written authorization** — scope, targets, contact info, escalation path
2. **Document baseline** — network topology, known devices, expected traffic
3. **Establish safety stop conditions** — if any device faults or alarms, stop immediately
4. **Schedule during maintenance windows** for anything beyond T1
5. **Set up monitoring** — watch device health, ICS alarms, operator chat during scan

### During Scanning

1. **Start slow** — `-T1` then `-T2`, never start at `-T4`
2. **Single-protocol probes first** — observe per-protocol before combining
3. **Ramp up incrementally** — increase rate after confirming device stability
4. **Watch for signs of distress** — status LED changes, console alarms, unexpected behavior
5. **Log everything** — full scan output, Wireshark capture of scan traffic

### After Scanning

1. **Verify no damage** — confirm all devices are still operating normally
2. **Cross-reference results** — compare with baseline, note discrepancies
3. **Report findings** — asset inventory, version audit, risk scoring
4. **Update inventory DB** — CMDB or specialized OT asset management tool

---

## 4. Recommended OT Scanning Tools (Beyond Nmap)

| Tool | Purpose | Layer |
|------|---------|-------|
| **Nmap + NSE** | Active discovery & fingerprinting | L3-L7 |
| **Wireshark / tshark** | PCAP analysis, L2 protocol inspection | L2-L7 |
| **GRASSMARLIN** | ICS network passive mapping (by NCCIC) | L2-L7 |
| **Shodan** | External-facing OT device discovery | L7 |
| **Zeek (Bro)** | Network monitoring + OT protocol parsing | L2-L7 |
| **nping** | Custom packet crafting for L2 probing | L2 |
| **Scapy** | Programmatic packet injection for OT protocols | L2-L7 |
| **Censys** | Internet-wide OT protocol scanning data | L7 |
| **OT-Base** | CISA's OT asset management DB | Asset Mgmt |

---

## 5. References

- NIST SP 800-82 Rev.3 — Guide to Industrial Control Systems Security
- MITRE ATT&CK for ICS v14 — https://attack.mitre.org/ics/
- CISA ICS Advisory Feeds — https://www.cisa.gov/ics-advisories
- SANS ICS515 — ICS Active Defense and Incident Response
- IEC 62443 — Industrial Communication Network Security (especially 62443-3-3 for network segmentation)
- INCONTROLLER / Pipedream analysis — Dragos / Mandiant 2022 OT threat reports
