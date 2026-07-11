# DNP3 NSE Scripts — Deep Dive & Improvement Roadmap

> **Date:** 2026-07-11
> **Sources Found:**
> - `digitalbond/Redpoint/dnp3-info.nse` (⭐467, by Stephen J. Hilt, Digital Bond)
> - `Z-0ne/ICS-Discovery-Tools/dnp3-enumerate.nse` (⭐40, by Z-0ne/plcscan.org)
> - Original `atimorin/nmap-nse-dnp3` → **404** (deleted), no Wayback archive
> - `dnp3-brute.nse` → **Extinct** — no surviving copies found anywhere

---

## 1. The DNP3 Repo Situation

### Timeline
1. **Original:** `github.com/atimorin/nmap-nse-dnp3` — contained `dnp3-info.nse`, `dnp3-enumerate.nse`, `dnp3-brute.nse`
2. **Current:** Returns HTTP 404. User `atimorin` (Aleksandr Timorin) still exists with 286 repos, but the DNP3 repo is gone.
3. **Wayback Machine:** No snapshots archived.
4. **Surviving copies** found across 15+ GitHub repos (see below)

### Surviving Repositories

| Script | Repositories (with live copies) |
|--------|-------------------------------|
| **`dnp3-info.nse`** | `digitalbond/Redpoint`, `w3h/icsmaster`, `xl7dev/ICSecurity`, `euphrat1ca/ICSwiki`, `automayt/ICS-pcap`, `pierre94/icstools`, `ControlThings-io/ct-samples`, `cldrn/external-nse-script-library`, `thainnos/ICSscannerDiode`, `r3dxpl0it/TheXFramework`, and more |
| **`dnp3-enumerate.nse`** | `Z-0ne/ICS-Discovery-Tools`, `w3h/icsmaster`, `euphrat1ca/ICSwiki`, and several derivative forks |
| **`dnp3-brute.nse`** | **No surviving copies found** — vanished from all repositories |

### What Was Cloned to Project Folder

```
ot-nmap-blue-team/
├── Redpoint/                  ← digitalbond/Redpoint (full repo, 13 NSE scripts)
│   └── dnp3-info.nse          ← DNP3 identification script
├── ICS-Discovery-Tools/       ← Z-0ne/ICS-Discovery-Tools (5 NSE scripts)
│   ├── dnp3-enumerate.nse     ← DNP3 enumeration script
│   └── melsecq-discover*.nse, s7-enumerate.nse, s71200-enumerate-old.nse
└── scada-tools/               ← atimorin/scada-tools (2 NSE scripts + Python tools)
```

---

## 2. Script Analysis: `dnp3-info.nse` (Digital Bond / Redpoint)

### Metadata
| Field | Value |
|-------|-------|
| **Author** | Stephen J. Hilt (Digital Bond) |
| **Date** | ~2014 (unversioned, undated) |
| **Categories** | `discovery`, `intrusive` |
| **Port** | TCP 20000 (`shortport.port_or_service(20000, "dnp", "tcp")`) |
| **Lines** | 207 |
| **DNP3 Layer** | Datalink Layer only |

### What It Does

1. Connects to TCP 20000
2. Sends a **single massive packet** containing **100 concatenated DNP3 Link Status requests** for addresses 0x00 through 0x63
3. Reads response, validates first 2 bytes are `0x05 0x64` (DNP3 sync + link header)
4. Parses 3 fields: Source Address (2 bytes), Destination Address (2 bytes), Control byte (1 byte)
5. Decodes Control byte using a function code lookup table
6. Sets `port.version.name = "DNP3"` for nmap version detection

### Code Flow

```lua
action(host, port)
  ├── sock = nmap.new_socket()
  ├── sock:set_timeout(1000)              -- 1 second timeout
  ├── first100 = bin.pack("H", "...")     -- ~1.5KB hex blob of 100 requests
  ├── sock:connect(host, port)
  ├── sock:send(first100)                 -- send ALL 100 requests at once
  ├── sock:receive()                      -- read first response
  ├── validate 0x05 0x64 sync
  ├── parse src_addr, dst_addr, control
  ├── sock:close()
  └── return output table
```

### DNP3 Protocol Knowledge in the Script

The `funct_lookup()` function (lines 46-69) implements the DNP3 Datalink Function Code decoding:

| PRM Bit | Function Codes Implemented |
|---------|--------------------------|
| PRM=0 (Response) | ACK (0), NACK (1), Link Status (11), User Data (15) |
| PRM=1 (Request) | RESET Link (0), Reset User Process (1), TEST Link (2), User Data (3,4), Request Link Status (9) |

This mapping is **correct per IEEE 1815-2012**.

---

## 3. Script Analysis: `dnp3-enumerate.nse` (Z-0ne / ICS-Discovery-Tools)

### Metadata
| Field | Value |
|-------|-------|
| **Author** | Z-0ne (plcscan.org) |
| **Date** | Derived from http://plcscan.org/blog/2014/12/dnp3-protocol-overview/ |
| **Categories** | `discovery`, `intrusive` |
| **Port** | TCP 20000 (`shortport.port_or_service(20000, "dnp3", "tcp")`) |
| **Lines** | 167 |

### What It Does

Uses the **identical 100-request hex blob** as `dnp3-info.nse`, but:
- Uses `comm.exchange()` instead of manual socket (cleaner)
- Simpler parsing — reads source/destination/control as single bytes
- No function code lookup table
- Same protocol validation (`0x05 0x64`)
- Sets version info to `"dnp3"` / `"dnp3devices"`

---

## 4. Critical Issues (Both Scripts)

### 🔴 P0 — Safety: Sending 100 Requests in One TCP Segment

This is the single biggest concern.

```lua
-- Structure of a single DNP3 Link Status Request (18 bytes):
-- 05 64 [len] [ctrl] [dst_l] [dst_h] [src_l] [src_h] [crc_1] [crc_2]
-- Then the script concatenates 100 of these into ONE TCP segment:
local first100 = bin.pack("H", "056405C900000000364C" ..   -- addr 0x00
                                  "056405C901000000DE8E" ..   -- addr 0x01
                                  "056405C[REDACTED]F840" ..  -- addr 0x02
                                  ... )                       -- addr 0x03 - 0x63
```

**Problem:** A DNP3 Link Status request is a simple query — but sending 100 at once is not standard behavior. DNP3 devices typically expect one request at a time. This approach can:
- **Overwhelm slow RTUs** — many embedded DNP3 devices (e.g., old GE D20, SEL RTUs) process requests sequentially. Flooding 100 Link Status requests can fill their receive buffer.
- **Cause denial of service** — some real-world RTUs have crashed when receiving unexpected bulk traffic
- **Produce unreliable results** — the device may only respond to the first valid address and ignore the rest, or mix responses

**Better approach:** Send one Link Status request, wait for response, then move to next address. Or better: just use a broadcast address or try a few common address ranges.

### 🔴 P0 — Datalink Layer Only: Missing Application Layer

Both scripts **never go above the DNP3 Datalink Layer**. A DNP3 Application Layer request opens up:

| Request | Function | What We'd Learn |
|---------|----------|----------------|
| Read Class 0 (0x01, var 0) | 0xC0 0x01 0x3C 0x02 0x06 | All static point values — I/O status |
| Get Device Attributes (0x6401) | Vendor-specific | Manufacturer, model, firmware version |
| Read IIN bits | Embedded in any response | Device status (restart, config corrupt, etc.) |
| Get Application Response Info | 0xC0 0x00 | Supported function codes |

Without Application Layer access, the scripts can only identify "there's a DNP3 device at this IP" but NOT:
- What vendor/make/model
- What firmware version (can't map to CVEs)
- How many points/indicators/controls exist
- Device health status (IIN bits)

### 🟡 P1 — No CRC Validation

DNP3 uses a **2-byte CRC every 16 bytes** of the frame:
```
[start] [length] [ctrl] [dst] [src] [CRC_1-2] [payload...] [CRC_3-4] ...
```

Neither script validates CRCs before parsing. This means:
- Corrupted responses are parsed as valid data
- A single-bit error in the response produces garbage output
- On noisy substation environments (common), this is a practical concern

### 🟡 P1 — Fragile Address Parsing in `dnp3-enumerate.nse`

```lua
local d, dstcode = bin.unpack("C", respone, 7)  -- reads 1 byte at offset 7
local d, srccode = bin.unpack("C", respone, 5)  -- reads 1 byte at offset 5
```

DNP3 addresses are **16-bit (2 bytes)**, not 8-bit:
- Offset 7 reads the low byte of destination address correctly (byte offset from start: 0x05=start, 0x64=link, length=byte3, ctrl=byte4, dst_l=byte5, dst_h=byte6, src_l=byte7)
- Wait, let me re-check the DNP3 frame structure...

DNP3 Link Header (fixed 10 bytes):
```
Byte 0: 0x05 (start byte 1)
Byte 1: 0x64 (start byte 2)  
Byte 2: Length (rest of frame, excluding CRCs)
Byte 3: Control byte
Byte 4-5: Destination Address (little-endian, LSB first)
Byte 6-7: Source Address (little-endian, LSB first)
Byte 8-9: CRC (header CRC)
```

So `dnp3-enumerate.nse`:
- `byte 5` = Destination Address LOW byte — correct
- `byte 7` = Source Address LOW byte — correct

BUT the high bytes are NOT being read. It only extracts the low byte of each. For addresses < 256 this works, but DNP3 addresses are 0-65519. For addresses > 255, the high byte is silently dropped.

Actually, let me re-read the code more carefully. For `dnp3-enumerate.nse`, it has:
```lua
local d, dstcode = bin.unpack("C", respone, 7)
-- This reads byte at index 7, which is src_addr_low (offset 6 in 0-based)
-- Wait, bin.unpack uses 1-based indexing
```

Hmm, actually this is slightly wrong. Let me recalculate:
- Byte 1 (index 1): 0x05 - start
- Byte 2 (index 2): 0x64 - start
- Byte 3 (index 3): length
- Byte 4 (index 4): control byte
- Byte 5 (index 5): dest addr LSB
- Byte 6 (index 6): dest addr MSB
- Byte 7 (index 7): src addr LSB
- Byte 8 (index 8): src addr MSB

In `dnp3-enumerate.nse`:
```lua
local d, dstcode = bin.unpack("C", respone, 7)  -- reads byte 7 = src addr LSB
output["Source address"] = dstcode                -- labeled as Source (correct field)
local d, srccode = bin.unpack("C", respone, 5)   -- reads byte 5 = dest addr LSB
output["Destination address"] = srccode            -- labeled as Destination (correct field)
```

Wait, the labels are swapped! Let me re-read:
```lua
output["Source address"] = dstcode      -- dstcode came from byte 7 = src addr LSB
output["Destination address"] = srccode  -- srccode came from byte 5 = dest addr LSB
```

OK so the code reads:
- byte 7 → `dstcode` → labeled "Source address" — actually byte 7 IS the source address LSB, so the VALUE is correct but the VARIABLE NAME `dstcode` is misleading. The LABEL "Source address" is correct.
- byte 5 → `srccode` → labeled "Destination address" — byte 5 IS the destination address LSB, so the VALUE is correct but the variable name `srccode` is misleading. The LABEL is correct.

So the parsing is actually correct in terms of values, just the variable names are swapped (cosmetic). But the bigger issue remains: **only the low byte** is read — for addresses > 255, the high byte is dropped. Use `"<S"` (little-endian 16-bit) instead of `"C"`.

In `dnp3-info.nse` (Redpoint), the address parsing correctly uses 16-bit:
```lua
local pos, dstadd = bin.unpack("S", response, 5)   -- 16-bit LE at offset 5
local pos, srceadd = bin.unpack("S", response, pos) -- 16-bit LE at current pos
```
This is correct. The Redpoint version is more accurate.

### 🟡 P1 — No Socket Close on Error Paths in `dnp3-info.nse`

Lines 150-171: If `sock:connect()`, `sock:send()`, or `sock:receive()` fails, the function returns nil WITHOUT closing the socket. Socket leak.

### 🟡 P1 — `sock:receive()` with No Buffer Size

Line 167:
```lua
local rcvstatus, response = sock:receive()
```
Without a buffer size, this reads one "line" (or default chunk). For DNP3 binary responses, this should use `sock:receive_bytes(min_count)` or a specific buffer size. It may only read partial responses.

### 🟢 P2 — Timeout Too Low for OT

Both scripts use `1000ms` or `4000ms` timeout. For remote RTUs over satellite links or radio, 5-10 seconds is more appropriate for edge cases.

### 🟢 P2 — Hardcoded Address Range

Both scripts hardcode addresses 0-99 (0x00-0x63). DNP3 supports up to 65519 addresses. For large substations, this range may miss devices. A `--script-args` parameter for address range would be better.

---

## 5. Deficiency Comparison: DNP3 vs Other OT NSE Scripts

Compare what DNP3 scripts can tell us vs what official NSE scripts tell us for other protocols:

| Protocol | Script | Info Extracted |
|----------|--------|---------------|
| **Siemens S7** | `s7-info` (official) | Module name, serial, firmware, plant designation |
| **BACnet** | `bacnet-info` (official) | Instance, vendor, firmware, objects |
| **EtherNet/IP** | `enip-info` (official) | Vendor, product name, serial, revision |
| **IEC 61850 MMS** | `mms-identify.nse` | Vendor name, model, revision |
| **IEC 104** | `iec-identify.nse` | ASDU address |
| **DNP3** | `dnp3-info.nse` ⚠️ | Source addr, dest addr, control byte |
| **DNP3** | `dnp3-enumerate.nse` ⚠️ | Source addr, dest addr, control byte |

**DNP3 is the least informative** — it only returns addresses. Every other protocol script returns device identity, version, or configuration.

---

## 6. Improvement Roadmap

### Phase 1: Fix Immediate Issues (Estimated: 2-3 hours)

1. **Fix socket leak** — add `socket:close()` to ALL exit paths
2. **Fix `dnp3-enumerate.nse` address parsing** — use `bin.unpack("<S")` instead of `"C"` for 16-bit address
3. **Fix `sock:receive()` buffer** — use `receive_bytes(min_count)` with proper min
4. **Increase default timeout** — 5000ms for OT environments
5. **Make address range configurable** — `--script-args dnp3.addr-range=0-100`
6. **Add CRC validation** — skip corrupted responses
7. **Fix category** — change from `intrusive` to `discovery` (with note that individual requests are safe; the bulk-100 approach is the actual risk)

### Phase 2: Add Application Layer (Estimated: 1-2 days)

8. **Add DNP3 transport layer parsing** — FIN/FIR/sequence tracking
9. **Implement Application Layer Read Class 0** — get static point data
10. **Implement Get Device Attributes (0x6401)** — manufacturer, model, firmware version
11. **Parse IIN bits** — device health flags (restart, configuration corrupt, etc.)
12. **Send individual Link Status requests** — not the 100-at-once approach

### Phase 3: Advanced Features (Estimated: 3-5 days)

13. **Implement DNP3 object header parsing** — understand point types (Binary Input, Analog, Counter, Control, etc.)
14. **Add support for unsolicited responses** — some devices push data
15. **Multi-session support** — some RTUs support only one connection at a time
16. **Secure DNP3 (DSTK) detection** — newer devices with authentication
17. **`--script-args dnp3.application-layer=true`** — optional deep enumeration

---

## 7. DNP3 Protocol Reference (for script development)

### DNP3 Frame Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNP3 Link Layer Header                        │
│  (10 bytes fixed, CRC-protected every 16 bytes)                  │
├─────────┬─────────┬──────────┬─────────┬───────────┬───────────┤
│  Start  │  Start  │  Length  │ Control │  Dest Addr│  Src Addr │
│  0x05   │  0x64   │ (1 byte) │ (1 byte)│ (2 bytes) │ (2 bytes) │
├─────────┴─────────┴──────────┴─────────┴───────────┴───────────┤
│                        Header CRC (2 bytes)                     │
├─────────────────────────────────────────────────────────────────┤
│                   Transport Layer (1 byte)                       │
│  FIN:1 | FIR:1 | Sequence:6                                     │
├─────────────────────────────────────────────────────────────────┤
│                   Application Layer (variable)                   │
│  App Control | Function Code | Object Headers...                │
│  CRC-protected every 16 bytes                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key DNP3 Function Codes (for Application Layer)

| Code | Function | Use for Discovery |
|------|----------|------------------|
| 0x00 | Confirm | — |
| 0x01 | Read | **Primary** — read Class 0 (all static data) |
| 0x02 | Write | Never on production |
| 0x03 | Select | Never on production |
| 0x04 | Operate | Never on production |
| 0x05 | Direct Operate | Never on production |
| 0x06 | Direct Operate No Ack | Never on production |
| 0x07 | Immediate Freeze | Never on production |
| 0x0A | Read Class 0 | **Discovery** — reads all static data |
| 0x0B | Read Class 1 | Event data |
| 0x0C | Read Class 2 | Event data |
| 0x0D | Read Class 3 | Event data |
| 0x11 | Delay Measurement | Passive — can test response |

### DNP3 Object Groups for Discovery

| Group | Variation | Name | Use |
|-------|-----------|------|-----|
| 60 | 1-4 | Class Data | Request Class 0,1,2,3 |
| 0 | (none) | Device Attributes | **Manufacturer, model, firmware** — 0x6401 |
| 1 | 1-2 | Binary Input | Status of digital inputs |
| 10 | 0-2 | Binary Output Status | Status of control outputs |
| 30 | 1-6 | Analog Input | Measured values |
| 40 | 0-4 | Analog Output Status | Setpoint readback |
| 50 | 1 | Time/Date | Device time |
| 80 | 1 | Internal Indications | **Device health flags** |

### IIN Bits (Key diagnostic flags from any response)

| Bit | Meaning | Blue Team Value |
|-----|---------|-----------------|
| IIN1.0 | RESTART | Device has restarted — potential reliability concern |
| IIN1.1 | TIME_SYNCHRONIZED | If not set, device clock is wrong |
| IIN1.2 | CONFIGURATION_CORRUPT | **CRITICAL** — device may have lost config |
| IIN1.4 | EVENT_BUFFER_OVERFLOW | Device is logging too many events |
| IIN1.7 | CLASS_1_EVENTS | Pending events to be collected |
| IIN2.0 | DEVICE_TROUBLE | **CRITICAL** — general device fault |
| IIN2.4 | NEED_TIME | Device needs time sync |

---

## 8. Surviving Copies Reference

For reference, here are all the repositories that still contain DNP3 NSE scripts:

| Repository | Stars | Contains | Notes |
|-----------|-------|----------|-------|
| [digitalbond/Redpoint](https://github.com/digitalbond/Redpoint) | ⭐467 | `dnp3-info.nse` | Original source (Digital Bond) |
| [Z-0ne/ICS-Discovery-Tools](https://github.com/Z-0ne/ICS-Discovery-Tools) | ⭐40 | `dnp3-enumerate.nse` | Has the enumeration variant |
| [w3h/icsmaster](https://github.com/w3h/icsmaster) | ⭐959 | Both `dnp3-info` + `dnp3-enumerate` | Largest ICS resource collection |
| [euphrat1ca/ICSwiki](https://github.com/euphrat1ca/ICSwiki) | — | Both | Chinese-language ICS resource |
| [xl7dev/ICSecurity](https://github.com/xl7dev/ICSecurity) | — | `dnp3-info.nse` | Mirror |
| [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) | — | `dnp3-info.nse` | PCAP-focused |
| [ControlThings-io/ct-samples](https://github.com/ControlThings-io/ct-samples) | ⭐43 | `dnp3-info.nse` | Industrial IoT platform |
