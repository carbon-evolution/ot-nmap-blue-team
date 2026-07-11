# Code Review: atimorin/scada-tools NSE Scripts

> **Review Date:** 2026-07-11
> **Source:** https://github.com/atimorin/scada-tools
> **Scripts Reviewed:** `iec-identify.nse` (v0.1), `mms-identify.nse` (v0.3)
> **Repo Status:** Last updated 2014 for Confidence conference — 12+ years old, unmaintained

---

## ⚠️ Finding: `nmap-nse-dnp3` Repo is Gone

The DNP3 NSE scripts (`dnp3-info.nse`, `dnp3-enumerate.nse`, `dnp3-brute.nse`) were previously hosted at `github.com/atimorin/nmap-nse-dnp3`. That repo now returns **HTTP 404** — it has been deleted or made private.

The user `atimorin` (Aleksandr Timorin) still exists (286 public repos), but the DNP3-specific repo is gone. The old scripts may exist in:
- Local copies held by individuals who forked/cloned it
- Internet Archive / Wayback Machine snapshots
- Private backups

**If you want DNP3 NSE scripts today**, see alternatives in the Recommendations section below.

---

## Script 1: `iec-identify.nse` — IEC 60870-5-104 (TCP 2404)

### What it Does Well
- Clean 3-step handshake: TESTFR → STARTDT → C_IC_NA_1
- Implements correct APCI (Application Protocol Control Information) framing
- Extracts ASDU address from response
- Sets `port.version.name` and `port.version` for nmap service detection integration
- Proper error return (`nil`) on failure — won't pollute output

### Code Quality Assessment

| Aspect | Score | Notes |
|--------|-------|-------|
| Correctness | 7/10 | Functional but edge-case handling is weak |
| Robustness | 4/10 | Fragile length checks, no socket cleanup |
| Safety | 8/10 | Actually safe (not intrusive despite the category tag) |
| Parsing | 3/10 | Magic-number offset parsing |
| Maintainability | 5/10 | No comments, minimal structure |
| NSE Best Practices | 3/10 | Outdated NSE idioms, missing prereqs |

### Issues Found

#### Critical
1. **Socket leak** — `socket:close()` is never called. The socket stays open until garbage collected. In a large scan scan (subnet sweep), this leaks file descriptors.
   ```lua
   -- present at line 60-65, no close anywhere
   local socket = nmap.new_socket()
   socket:set_timeout(timeout)
   status, result = socket:connect(host, port, "tcp")
   -- ... never calls socket:close()
   ```

#### High
2. **Category incorrectly labeled "intrusive"** — None of the commands sent (TESTFR, STARTDT, C_IC_NA_1) modify device state. TESTFR is a keep-alive ping, STARTDT starts data transfer (not control), C_IC_NA_1 is a general interrogation (read-only). This should be `{"safe", "discovery"}`. Labeling it "intrusive" discourages blue teams from using it on production, when it's actually perfectly safe.

3. **Fragile response parsing** — Uses `#recv == 22` (magic number) to determine if a combined INIT + EI response was received. This breaks if:
   - Device sends responses in separate TCP segments
   - Device includes additional I-format frames
   - APDU segmentation occurs
   - Different IEC 104 device profile (e.g., multiple ASDU in one APDU)

#### Medium
4. **No socket:close() on error paths** — If `socket:send()` fails at lines 76, 88, or 106, the function returns `nil` without closing the socket. The socket object becomes orphaned.

5. **Missing `prerule`** — Doesn't verify port state before connecting. Should include:
   ```lua
   prerule = function() return true end
   ```
   Or better, use `nmap.set_port_state` check.

6. **Default timeout too low for OT** — 500ms is fine for low-latency IT networks, but IEC 104 devices in substations can take 1-3 seconds to respond, especially under load. Should default to 2000ms with a more descriptive arg name.

7. **C_IC_NA_1 uses broadcast ASDU address (0xFFFF)** — This triggers all stations in the control unit to respond. For a single-device identification, using a directed interrogation or simply parsing the STARTDT_CON + INIT response would suffice. Sending broadcast is more intrusive than necessary.

#### Low
8. **`hex2str` function defined but output uses `stdnse.tohex`** — The function is defined (lines 37-49) but the output format strings use `stdnse.tohex(TESTFR)` instead of `hex2str(stdnse.tohex(TESTFR))` — the `hex2str` calls are commented out. Either use it or remove it.

9. **No ASDU content parsing beyond address** — A full IEC 104 parser could extract:
   - Cause of Transmission (COT) — single/cyclic/spontaneous/activated
   - Type ID — process monitoring, control, parameter, etc.
   - IOA (Information Object Address) — actual point addresses
   - Quality descriptors

10. **No support for IEC 104 redundancy** — IEC 104 allows redundant connections on different ports/IPs. No handling for this.

11. **Version mismatch** — Script says v0.1 but it's been 12+ years with no updates.

---

## Script 2: `mms-identify.nse` — IEC 61850 MMS (TCP 102)

### What it Does Well
- Correct 3-layer protocol handshake: TPKT → ISO 8073 (COTP) → MMS
- Proper MMS Initiate Request PDU structure with calling/presentation selectors
- Extracts vendor name, model name, and revision from Identify response
- Sets port version name for nmap service detection
- Includes Python reference implementation in comments (useful for debugging)

### Code Quality Assessment

| Aspect | Score | Notes |
|--------|-------|-------|
| Correctness | 6/10 | Works on lab devices, fragile on real gear |
| Robustness | 3/10 | String-offset parsing of ASN.1 is very fragile |
| Safety | 8/10 | Read-only protocol operations |
| Parsing | 2/10 | Acknowledged as broken with `"damn! rewrite with bin.unpack!"` |
| Maintainability | 4/10 | Hardcoded byte arrays, no structure |
| NSE Best Practices | 3/10 | Outdated, fragile parsing |

### Issues Found

#### Critical
1. **Socket leak** — Same as `iec-identify.nse`. `nmap.new_socket()` is called but `socket:close()` is never called.

2. **ASN.1/BER parsing via raw hex string offsets** — The comment at line 136 (`"damn! rewrite with bin.unpack!"`) acknowledges this. The code extracts vendor/model/revision by doing:
   ```lua
   local invokeID_size = tonumber(string.sub(tmp_recv, 47, 48), 16)
   local mms_identify_info = string.sub(tmp_recv, 52 + 2*invokeID_size +1)
   ```
   Fixed byte offsets like `47, 48` and `52` assume:
   - Fixed TPKT header size (4 bytes)
   - Fixed COTP header size (3 bytes)
   - Fixed session/presentation layer sizes
   - Fixed MMS PDU header structure
   
   Any variation in session/presentation layer options will break parsing completely. This should use proper BER-TLV parsing with tag-length-value iteration.

#### High
3. **No S7 vs MMS differentiation on port 102** — Both Siemens S7 and IEC 61850 MMS use TCP port 102. The script doesn't attempt S7 detection first or add logic to differentiate. If a S7-1200 responds first, the MMS CR_TPDU will likely fail or produce garbage.

4. **`comm.exchange` is commented out** (line 69) — The standard nmap library function `comm.exchange()` is safer and more idiomatic than manual `socket:send()` + `socket:receive_bytes()`. Being commented out suggests this was written before the author was comfortable with the NSE library.

#### Medium
5. **Blocking receive with no multi-packet handling** — `socket:receive_bytes(1024)` waits for up to 1024 bytes. But MMS responses can be fragmented across multiple TPKT segments. A complete MMS response requires reassembling multiple 4+ byte TPKT frames. If the response is >1024 bytes or segmented, this will miss data.

6. **Hardcoded maximum PDU sizes** — The MMS Initiate Request specifies `maxServOutstandingCalling=1`, `maxServOutstandingCalled=1`, `dataStructureNesting=2`. Real devices may require different negotiation parameters.

7. **No error recovery** — If any step fails (CR_TPDU, MMS_INITIATE, MMS_IDENTIFY), it returns nil immediately. A more robust approach would retry or try alternative session parameters.

8. **No TLS support** — IEC 61850 can operate over TLS (IEC 62351). No support for secure MMS.

#### Low
9. **Magic numbers everywhere** — Key protocol constants are embedded as raw byte arrays with no named constants or documentation about their structure.

10. **No support for MMS detailed enumeration** — Only calls `identify`. MMS supports: `GetCapabilities`, `GetNameList` (logical devices, logical nodes, files), `Read` (data values). A comprehensive script would enumerate:
    - All logical devices (XCBR, XSWI, MMXU, etc.)
    - Logical node data objects
    - Data set definitions
    - Report control blocks (BRCB, URCB)
    - File directory

11. **Hardcoded presentation layer OIDs** — OIDs like `1.0.851.1` (MMS) are correct but should be documented with their meaning for maintainability.

---

## Recommendations by Priority

### 🔴 P0 — Must Fix (Safety/Correctness)

#### 1. Add `socket:close()` to both scripts
```lua
-- Pattern to fix:
local socket = nmap.new_socket()
-- ... use socket ...
socket:close()  -- Add this in both success AND error paths
```
Or use the `nmap.new_socket()` in a protected call with `nmap.new_try()`.

#### 2. Fix `mms-identify.nse` ASN.1 parsing with `bin.unpack`
Replace hex-string offset parsing with proper BER-TLV iteration using nmap's `bin` library:
```lua
local pos, tag, length, value
pos = 1
while pos <= #response do
    pos, tag = bin.unpack("C", response, pos)
    -- Parse length (short/long form per BER)
    pos, length = bin.unpack("C", response, pos)
    if length > 127 then
        -- Long form: first byte indicates # of length bytes
        local len_bytes = length & 0x7F
        pos, length = bin.unpack("I" .. len_bytes, response, pos)
    end
    pos, value = bin.unpack("A" .. length, response, pos)
    -- Process tag/value...
end
```

#### 3. Fix `iec-identify.nse` `intrusive` → `safe`
Change category from `{"discovery", "intrusive"}` to `{"safe", "discovery"}`. None of the commands issued modify device state.

### 🟡 P1 — Should Fix (Robustness)

#### 4. Add prerule + port state check to both scripts
```lua
-- Ensure we only run on open ports
if port.state ~= "open" then
    return nil
end
```

#### 5. Increase default timeouts for OT environments
- `iec-identify.timeout`: 500ms → 2000ms (or 5s)
- `mms-identify.timeout`: 500ms → 3000ms (MMS negotiation is multi-step)

#### 6. Replace magic-number length checks with APCI structure parsing
```lua
-- Instead of:
if #recv == 22 then

-- Use:
local apci_length = #recv
if apci_length >= 6 then
    local start_byte = bin.unpack("C", recv, 1)  -- Should be 0x68
    local len_field = bin.unpack("C", recv, 2)    -- APDU length (excl. start+len)
    -- Validate structure...
end
```

### 🟢 P2 — Nice to Have (Features)

#### 7. Add MMS logical device/node enumeration to `mms-identify.nse`
```lua
-- After identify, request GetNameList for logical devices
-- MMS GetNameList (ObjectClass=LD, continueAfter=none)
```

#### 8. Add station name/description extraction to `iec-identify.nse`
IEC 104 supports a station interrogation (C_IC_NA_1 with specific ASDU) that can extract the station name as an alphanumeric string.

#### 9. Handle S7 vs MMS differentiation on port 102
```lua
-- Try S7 detection first, fall back to MMS
-- Or detect based on first response byte
local first_byte = recv:byte(1)
if first_byte == 0x03 then
    -- Likely MMS (TPKT starts with 0x03)
else
    -- Likely S7
end
```

#### 10. Add TLS/SSL support for MMS via `tls-nbns` or similar
IEC 62351 specifies TLS for MMS. Support `--script-args mms-identify.tls=true`.

#### 11. Add retry logic for transient failures
```
-- On first failure, retry with different session parameters
-- On receive timeout, try reconnecting
```

### 🟣 Quick Wins (Low Effort)

| # | Fix | File | Lines | Effort |
|---|-----|------|-------|--------|
| 12 | Remove unused `hex2str` or uncomment its usage | iec-identify.nse | 37-49, 83, 97 | 2 min |
| 13 | Add descriptive args help (nmap --script-help) | Both | All | 5 min |
| 14 | Document magic byte arrays (which OIDs, which parameters) | mms-identify.nse | 67-104 | 10 min |
| 15 | Clean up commented-out `comm.exchange` | mms-identify.nse | 69 | 1 min |
| 16 | Add `@usage` example for subnet broadcast scan | iec-identify.nse | 7 | 2 min |

---

## Big Picture: What's Missing from `scada-tools`

This repo was created for a **2014 conference talk** — it's a proof-of-concept, not a maintained tool. To make it production-grade for OT blue team use:

1. **DNP3 NSE script** (see alternatives below)
2. **Unified OT discovery script** that auto-detects protocol (tries each on its standard port)
3. **Modbus read improvements** (currently no Modbus NSE in this repo)
4. **S7 block enumeration** (currently only Python brute-force tools, no NSE)
5. **OPC UA discovery** (no script at all)

---

## Path Forward for DNP3 NSE

Since `atimorin/nmap-nse-dnp3` is gone, here are alternatives ranked by effort:

### Option 1: Use `plcscan` (Easiest)
`plcscan` is a Python-based OT scanner with DNP3 support.
```bash
pip install plcscan
plcscan --dnp3 --target <ip>
```

### Option 2: Custom NSE from opendnp3 (Best Long-Term)
Use the `opendnp3` library (333 stars, maintained by the DNP3 Users Group) to build a proper NSE script:
```lua
-- DNP3 NSE pseudo-design:
-- 1. Connect to TCP 20000
-- 2. Send DNP3 Link Status (0x05 0x64 ...)
-- 3. Send DNP3 Application Layer: Read Class 0 (0xC0 0x01 0x3C 0x02 0x06 0x3C 0x03 0x06 0x3C 0x04 0x06)
-- 4. Parse response for device attributes, point values
-- 5. Extract: Device address, software version, point counts, IIN bits
```
The DNP3 protocol is well-documented (IEEE 1815) and the frame format is simpler than MMS:
- Fixed link header (10 bytes): 0x05 + 0x64 + length + control + dest_addr (2) + src_addr (2) + CRC (2)
- Transport header (1 byte): FIN/FIR/sequence
- Application header: application control (1) + function code (1) + optional object headers

### Option 3: Search forks on GitHub
```bash
# Look for remaining forks of the deleted repo
gh api search/repositories?q=dnp3+nse+nmap+fork:true
```

### Option 4: Wayback Machine
```bash
# Check if the Internet Archive has the old repo
# https://web.archive.org/web/*/https://github.com/atimorin/nmap-nse-dnp3
```
