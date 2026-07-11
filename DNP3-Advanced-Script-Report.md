# DNP3 Advanced NSE Script — Design Report

## File: `dnp3-advanced-info.nse`

---

## What It Does

Three-phase DNP3 device reconnaissance using safe, read-only operations:

### Phase 1 — Link Status (Datalink Layer)
Sends a **single** DNP3 Link Status Request (not 100 concatenated) to verify the device is DNP3-compatible and resolve its DNP3 addresses.

**Information extracted:**
| Field | Description |
|-------|-------------|
| DNP3 Destination Address | The device's DNP3 address (16-bit, IEEE 1815) |
| DNP3 Source Address | The source address from the response |
| Control Byte Decoded | Function code name + value (Link Status, ACK, NACK, etc.) |
| DNP3 Confirmation | Binary yes/no — is this a DNP3 device? |

### Phase 2 — Application Read (Class 0 Data)
Sends a DNP3 Application Layer **Read Class 0** request via User Data transport. This asks the device to return all static (Class 0) data points.

**Information extracted:**
| Field | Description |
|-------|-------------|
| IIN1, IIN2 Bytes | Full Internal Indication status (device health) |
| Device Health Summary | Parsed IIN flags with severity (CRIT/WARN/INFO) |
| Object Type Enumeration | All DNP3 object types the device exposes (e.g., Binary Input, Analog Input, Counter) |
| Point Counts per Type | Number of points per object group |
| Function Code Support | Whether device supports Application Layer reads |

**IIN flags detected:**
- `RESTART` — Device has rebooted (potential reliability issue)
- `CONFIG_CORRUPT` — Configuration may be corrupt (**critical**)
- `DEVICE_TROUBLE` — General self-test failure (**critical**)
- `EVENT_BUFFER_OVF` — Event buffer overflow (device overwhelmed)
- `NEED_TIME` — Device clock not synchronized
- `LOCAL_CONTROL` — Device in local-only mode
- `CLASS_*_EVENTS` — Pending event data

### Phase 3 — Device Attributes (Optional)
Attempts to read the DNP3 Device Attributes extension (Group 0, Variation 0). Not all devices support this — success is vendor-dependent.

**Information extracted (if supported):**
| Field | Description |
|-------|-------------|
| Vendor Name | Manufacturer identification (e.g., SEL, Schweitzer, GE) |
| Model Name | Device model (e.g., SEL-421, D200, RTAC) |
| Firmware Version | Software/firmware revision |
| Serial Number | Device serial number |

---

## Safety Features Implemented

### From the previous code review, all P0 issues are fixed:

| Issue from Review | Status in New Script |
|-------------------|---------------------|
| **🔴 P0: 100 req in one packet** | **FIXED** — sends ONE Link Status Request at a time. Uses a prioritized address discovery list (broadcast → common addresses) until a device responds. Never sends bulk requests. |
| **🔴 P0: Datalink Layer only** | **FIXED** — implements full DNP3 Application Layer (Phase 2: Read Class 0, Phase 3: Device Attributes). Reaches well beyond the datalink layer. |
| **🔴 P0: Socket leak** | **FIXED** — `sock:close()` called on ALL exit paths (success and error). |
| **🟡 P1: No CRC validation** | **FIXED** — DNP3 CRC-16 validated on every frame header before any data is parsed. Invalid CRC causes graceful error with debug log. |
| **🟡 P1: 1-byte address parsing** | **FIXED** — uses proper `(lsb | msb << 8)` for true 16-bit address resolution. |
| **🟡 P1: `sock:receive()` no buffer** | **FIXED** — uses `sock:receive_bytes(10)` for guaranteed minimum read. |
| **🟡 P1: Error path cleanup** | **FIXED** — every error return is preceded by proper socket cleanup. |
| **🟢 P2: Timeout too low** | **FIXED** — default timeout is 5000ms (configurable via `--script-args dnp3.timeout`). |
| **🟢 P2: Hardcoded address range** | **FIXED** — addresses are configurable via `--script-args dnp3.dst-addr`. Auto-address-detection tries broadcast first, then specific addresses. |
| **🟢 P2: Labeled "intrusive" incorrectly** | **FIXED** — category is `{"safe", "discovery"}`. The script never sends write, operate, select, or direct-operate commands. |

### Additional safety measures:

1. **Read-only function codes** — Only uses DNP3 Function Code 0x01 (Read). Never uses 0x02 (Write), 0x03 (Select), 0x04 (Operate), 0x05 (Direct Operate), or 0x06 (Direct Operate No Ack).

2. **Individual requests with timeout** — Each request is sent separately with a response wait. Configurable timeout (default 5 seconds) prevents flooding.

3. **Graceful degradation** — If Phase 2 (Class 0 read) fails, the script still returns Phase 1 data. If Phase 3 (Device Attributes) fails, it notes "not supported" but doesn't crash.

4. **Auto-address discovery** — Rather than sweeping 100 addresses, the script tries broadcast (0xFFFF, 0xFFFE) first, then common addresses (1, 100, 200, 10, 20, 50). This is quieter and sufficient for most deployments.

5. **Configurable behavior** — Skip Phase 2 with `dnp3.no-class0=true` or Phase 3 with `dnp3.no-attrs=true` if you want even lighter scanning.

---

## How It Compares to the Original Scripts

| Aspect | Original `dnp3-info.nse` | `dnp3-advanced-info.nse` |
|--------|------------------------|-------------------------|
| Link Status Requests | 100 at once (bulk) | 1 at a time (individual) |
| DNP3 Layer | Datalink (Layer 2) | Datalink + Transport + Application |
| Read Function Code Usage | None (link layer only) | Function 0x01 (Read) for Class 0 data |
| Device Attributes | None | Attempts Group 0 Var 0 read |
| IIN Bit Parsing | None | Full IIN1/IIN2 decode with severity |
| Object Type Enumeration | None | Full object header parsing |
| CRC Validation | None | CRC-16 on every frame |
| Socket Close | Missing on error paths | Always closed |
| Default Timeout | 1000ms | 5000ms (OT-safe) |
| Address Handling | Hardcoded 0-99 | Configurable + auto-detect |
| Category | `discovery, intrusive` | `safe, discovery` |
| Output Structure | Flat table | Phased with structured sections |

---

## DNP3 Protocol Design (For Those Studying the Script)

The script implements these DNP3 protocol layers:

### Datalink Layer (IEEE 1815 §3)
```
[0x05][0x64][len][ctrl][dst_l][dst_h][src_l][src_h][CRC_hdr] ...data... [CRC_data]
```
- Fixed 10-byte header with CRC over first 8 bytes
- Control byte encodes DIR/PRM/FCB/FCV bits and function code
- Length field = bytes after length field excluding all CRCs

### Transport Layer (§4)
```
[FIN:1][FIR:1][sequence:6]
```
- Simple pass-through layer for fragmenting app messages
- For small requests: FIN=1, FIR=1 in a single byte

### Application Layer (§5)
```
[app_ctrl:1][func_code:1][objects...]
```
- App control encodes FIR/FIN/CON/UNS + sequence
- Function 0x01 = Read, 0x81 = Response
- Object headers use Group/Variation/Qualifier format

### Object Header Format
```
[group:1][variation:1][qualifier:1][range:variable]
```
- Qualifier 0x00 = start/stop (2 bytes each, 16-bit)
- Qualifier 0x01 = start/stop (1 byte each, 8-bit)
- Qualifier 0x06 = all points (no range field)

### CRC-16 DNP3
- Polynomial: 0xA001 (reflected)
- Initial value: 0x0000
- Final XOR: 0x0000
- Same algorithm as Modbus CRC-16

---

## Usage Examples

### Basic scan:
```bash
nmap -p 20000 --script dnp3-advanced-info 192.168.1.100
```

### Specific DNP3 address (faster, no address sweep):
```bash
nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.dst-addr=10,dnp3.src-addr=100' 192.168.1.100
```

### Extended timeout for slow radio/satellite links:
```bash
nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.timeout=15000' 192.168.1.100
```

### Light scan (Class 0 only, no Device Attributes):
```bash
nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.no-attrs=true' 192.168.1.100
```

### Minimal scan (link layer only, no application reads):
```bash
nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.no-class0=true,dnp3.no-attrs=true' 192.168.1.100
```

### Subnet sweep with broadcast address:
```bash
nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.dst-addr=65535' 192.168.1.0/24
```

---

## Limitations

1. **DNP3 security (DSTK)** — The script does not handle DNP3 Secure Authentication (IEC 62351-5 / DSTK). Devices requiring secure authentication will not respond to application layer requests.

2. **Unsolicited responses** — The script does not handle unsolicited response sequences (where the outstation sends data unprompted). These are rare in blue team contexts.

3. **Device Attributes optionality** — Phase 3 (Device Attributes) is NOT part of the mandatory DNP3 standard. Many production devices (especially older ones) will not respond. This is handled gracefully (noted as "not supported").

4. **Large device enumeration** — For substations with thousands of points, the Class 0 read response can be large (multiple fragments). The current implementation reads the first response only. A production version could add multi-fragment reassembly.

5. **Multiple device instances** — If a single IP serves multiple DNP3 devices (rare), the script only detects the first one that responds.

---

## Files

| File | Location |
|------|----------|
| Script | `improved-scripts/dnp3-advanced-info.nse` |
| Code review | `NSE-Script-Code-Review.md` |
| Deep dive | `DNP3-NSE-Deep-Dive.md` |
| Full reference | `OT-Nmap-Blue-Team-Reference.md` |
| Original script (for diff) | `Redpoint/dnp3-info.nse` |
| Original enum (for diff) | `ICS-Discovery-Tools/dnp3-enumerate.nse` |
