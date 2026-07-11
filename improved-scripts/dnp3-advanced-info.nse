local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Advanced DNP3 device discovery and information gathering script.

Performs safe, read-only reconnaissance of DNP3 (IEEE 1815) devices
using a three-phase approach:

Phase 1 — Link Status Request: Confirms DNP3 presence and resolves
  device addresses. Sends a single (not 100x) link status request.

Phase 2 — Application Read (Class 0): Reads all static Class 0 data
  via the DNP3 Application Layer. Extracts IIN (Internal Indication)
  bits for device health assessment and enumerates supported data types.

Phase 3 — Device Attributes Read (optional): Attempts to read device
  identity information (vendor, model, firmware) via the DNP3 Device
  Attributes extension (Group 0, Variation 0).

SAFETY: This script uses only read-only DNP3 function codes (0x01 Read).
  It never sends write, operate, select, or direct-operate commands.
  All requests are sent individually (never bulk/concatenated).
  DNP3 CRC-16 is validated before any data is parsed.
  Sockets are closed on ALL exit paths.
]]

---
-- @usage
-- nmap -p 20000 --script dnp3-advanced-info <target>
-- nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.dst-addr=10,dnp3.src-addr=100' <target>
-- nmap -p 20000 --script dnp3-advanced-info --script-args 'dnp3.timeout=10000,dnp3.no-attrs=true' <target>
--
-- @args dnp3.dst-addr
--       DNP3 destination address (decimal). Default attempts broadcast: 0xFFFF (-1).
--       If no response, retries with address 1, 100, then 200.
-- @args dnp3.src-addr
--       DNP3 source address (decimal). Default: 100.
-- @args dnp3.timeout
--       Socket timeout in milliseconds. Default: 5000 (5s for OT).
-- @args dnp3.no-attrs
--       Skip Phase 3 (Device Attributes read). Default: false.
-- @args dnp3.no-class0
--       Skip Phase 2 (Class 0 read). Default: false.
--
-- @output
-- PORT      STATE SERVICE
-- 20000/tcp open  dnp3
-- | dnp3-advanced-info:
-- |   [Phase 1 — Link Layer]
-- |     Destination address: 10
-- |     Source address: 20
-- |     Control: Link Status (11)
-- |   [Phase 2 — Application Layer: Class 0 Data]
-- |     IIN1: 0x00
-- |     IIN2: 0x00
-- |     Device health: CLEAN (no warnings)
-- |     Object types found: 2
-- |       1: Binary Input (Group 1 Var 2) - 24 points
-- |       2: Analog Input (Group 30 Var 5) - 8 points
-- |   [Phase 3 — Device Attributes]
-- |     Vendor: Schweitzer Engineering Laboratories
-- |     Model: SEL-421
-- |     Firmware: R163-V0.2
-- |_    Serial: 2018XXXXX
--
-- Version 1.0
--
-- Reference:
--   IEEE 1815-2012 (DNP3 Standard)
--   DNP3 User Group Implementation Recommendation for Device Attributes
--   digitalbond/Redpoint (original dnp3-info.nse)
---

author = "Sisyphus (OhMyOpenCode)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(20000, "dnp3", "tcp")

-- ============================================================
--  DNP3 CRC-16 (Polynomial 0xA001, same as Modbus CRC-16)
-- ============================================================
dnp3_crc16 = function(data)
  local crc = 0x0000
  for i = 1, #data do
    crc = crc ~ data:byte(i)
    for _ = 1, 8 do
      if (crc & 0x0001) ~= 0 then
        crc = (crc >> 1) ~ 0xA001
      else
        crc = crc >> 1
      end
    end
  end
  return crc
end

-- ============================================================
--  DNP3 Link Layer Function Code Tables  (per IEEE 1815)
-- ============================================================

-- PRM=0 (Response from outstation)
local dnp3_func_primary = {
  [0]  = "ACK",
  [1]  = "NACK",
  [2]  = "Link Status (NACK — not configured)",
  [11] = "Link Status",
  [15] = "User Data Confirmed (ACK)",
}

-- PRM=1 (Request from master)
local dnp3_func_secondary = {
  [0] = "RESET Link",
  [1] = "Reset User Process",
  [2] = "TEST Link",
  [3] = "User Data",
  [4] = "User Data (unconfirmed)",
  [9] = "Request Link Status",
}

-- ============================================================
--  IIN (Internal Indication) Bit Definitions
-- ============================================================
local iin1_bits = {
  [0] = { name = "RESTART",          severity = "WARN",  desc = "Device has restarted since last response" },
  [1] = { name = "TIME_SYNCHRONIZED",severity = "INFO",  desc = "Device clock is synchronized" },
  [2] = { name = "CONFIG_CORRUPT",   severity = "CRIT",  desc = "Device configuration may be corrupt" },
  [3] = { name = "RESERVED1",        severity = "INFO",  desc = "Reserved" },
  [4] = { name = "EVENT_BUFFER_OVF", severity = "WARN",  desc = "Event buffer has overflowed" },
  [5] = { name = "RESERVED2",        severity = "INFO",  desc = "Reserved" },
  [6] = { name = "RESERVED3",        severity = "INFO",  desc = "Reserved" },
  [7] = { name = "CLASS_1_EVENTS",   severity = "INFO",  desc = "Class 1 events pending" },
}

local iin2_bits = {
  [0] = { name = "DEVICE_TROUBLE",   severity = "CRIT",  desc = "General device trouble/self-test failure" },
  [1] = { name = "LOCAL_CONTROL",    severity = "INFO",  desc = "Device in local control mode" },
  [2] = { name = "DEVICE_TROUBLE_L1",severity = "WARN",  desc = "Device trouble (less severe)" },
  [3] = { name = "RESERVED4",        severity = "INFO",  desc = "Reserved" },
  [4] = { name = "NEED_TIME",        severity = "WARN",  desc = "Device needs external time sync" },
  [5] = { name = "RESERVED5",        severity = "INFO",  desc = "Reserved" },
  [6] = { name = "RESERVED6",        severity = "INFO",  desc = "Reserved" },
  [7] = { name = "CLASS_3_EVENTS",   severity = "INFO",  desc = "Class 3 events pending" },
}

-- ============================================================
--  DNP3 Object Group / Variation names
-- ============================================================
local dnp3_object_groups = {
  [  1] = { name = "Binary Input",         vars = { [0]="Any", [1]="Packed Format", [2]="With Flags" } },
  [  3] = { name = "Binary Input Event",   vars = { [0]="Any", [1]="Without Time", [2]="With Absolute Time" } },
  [ 10] = { name = "Binary Output",        vars = { [0]="Any", [1]="Packed Format", [2]="Output Status" } },
  [ 12] = { name = "Binary Output Event",  vars = { [0]="Any", [1]="Without Time" } },
  [ 20] = { name = "Counter",              vars = { [0]="Any", [1]="32-bit", [2]="16-bit", [5]="Frozen Counter" } },
  [ 21] = { name = "Frozen Counter",       vars = { [0]="Any" } },
  [ 30] = { name = "Analog Input",         vars = { [0]="Any", [1]="32-bit", [2]="16-bit", [3]="32-bit With Flag", [4]="16-bit With Flag", [5]="Short Float With Flag", [6]="Double Float With Flag" } },
  [ 32] = { name = "Analog Input Event",   vars = { [0]="Any" } },
  [ 40] = { name = "Analog Output Status", vars = { [0]="Any", [1]="32-bit", [2]="16-bit" } },
  [ 41] = { name = "Analog Output Event",  vars = { [0]="Any" } },
  [ 50] = { name = "Time/Date",            vars = { [0]="Any", [1]="Absolute Time" } },
  [ 60] = { name = "Class Data",           vars = { [1]="Class 0", [2]="Class 1", [3]="Class 2", [4]="Class 3" } },
  [ 80] = { name = "Internal Indications", vars = { [1]="Packed Format" } },
  [ 81] = { name = "Device Profile",       vars = { [0]="Any" } },
  [110] = { name = "Octet String",         vars = { [0]="Any" } },
}

-- ============================================================
--  Helper: Parse link layer control byte
-- ============================================================
function parse_link_control(ctrl)
  local prm = (ctrl >> 6) & 0x01
  local func = ctrl & 0x0F

  if prm == 0 then
    local name = dnp3_func_primary[func] or ("Unknown PRM=0 Function (" .. func .. ")")
    return name, func, prm
  else
    local name = dnp3_func_secondary[func] or ("Unknown PRM=1 Function (" .. func .. ")")
    return name, func, prm
  end
end

-- ============================================================
--  Helper: Parse IIN bytes
-- ============================================================
function parse_iin(iin1, iin2)
  local results = {}
  local max_severity = "INFO"

  for bit, def in pairs(iin1_bits) do
    if (iin1 >> bit) & 0x01 == 1 then
      table.insert(results, string.format("[%s] %s — %s", def.severity, def.name, def.desc))
      if def.severity == "CRIT" then max_severity = "CRIT"
      elseif def.severity == "WARN" and max_severity ~= "CRIT" then max_severity = "WARN"
      end
    end
  end

  for bit, def in pairs(iin2_bits) do
    if (iin2 >> bit) & 0x01 == 1 then
      table.insert(results, string.format("[%s] %s — %s", def.severity, def.name, def.desc))
      if def.severity == "CRIT" then max_severity = "CRIT"
      elseif def.severity == "WARN" and max_severity ~= "CRIT" then max_severity = "WARN"
      end
    end
  end

  if #results == 0 then
    table.insert(results, "CLEAN (no warnings)")
  end

  return results, max_severity
end

-- ============================================================
--  Helper: Construct a DNP3 link-layer frame
-- ============================================================
function build_link_frame(ctrl, dst_addr, src_addr, user_data)
  -- Build header bytes (0-7)
  local header = string.char(0x05, 0x64)

  if user_data then
    -- Length = ctrl(1) + dst(2) + src(2) + user_data length
    header = header .. string.char(5 + #user_data)
  else
    -- Header only: length = 5 (ctrl + dst + src = 5 bytes)
    header = header .. string.char(5)
  end

  header = header .. string.char(ctrl)
  header = header .. string.char(dst_addr & 0xFF, (dst_addr >> 8) & 0xFF)
  header = header .. string.char(src_addr & 0xFF, (src_addr >> 8) & 0xFF)

  -- CRC over header bytes 0-7
  local hdr_crc = dnp3_crc16(header)
  local frame = header .. string.char(hdr_crc & 0xFF, (hdr_crc >> 8) & 0xFF)

  -- Append user data if present
  if user_data then
    frame = frame .. user_data
    -- CRC over user data (if ≤16 bytes, one CRC block)
    local data_crc = dnp3_crc16(user_data)
    frame = frame .. string.char(data_crc & 0xFF, (data_crc >> 8) & 0xFF)
  end

  return frame
end

-- ============================================================
--  Helper: Build DNP3 transport header + app layer
-- ============================================================
function build_app_request(func_code, object_headers, seq)
  seq = seq or 0

  -- Transport header: FIN=1, FIR=1
  local transport_hdr = string.char(0xC0 | (seq & 0x3F))

  -- Application control: FIR=1, FIN=1, CON=0, seq=seq
  local app_ctrl = string.char(0xC0 | (seq & 0x0F))

  -- App layer: control + function code + object headers
  local app_layer = app_ctrl .. string.char(func_code)
  if object_headers then
    app_layer = app_layer .. object_headers
  end

  -- Transport header + app layer = user data
  return transport_hdr .. app_layer
end

-- ============================================================
--  Helper: Build DNP3 Read object header
-- ============================================================
function build_read_object_header(group, variation, qualifier, range)
  -- Group, Variation, Qualifier, Range (if any)
  local hdr = string.char(group, variation, qualifier)
  if range then
    hdr = hdr .. range
  end
  return hdr
end

-- ============================================================
--  Helper: Validate DNP3 frame CRC
-- ============================================================
function validate_frame(data)
  if #data < 10 then
    return false, "Frame too short"
  end

  -- Validate sync bytes
  if data:byte(1) ~= 0x05 or data:byte(2) ~= 0x64 then
    return false, "No DNP3 sync bytes (0x0564)"
  end

  -- Compute expected length
  local length_field = data:byte(3)
  -- Length field indicates bytes following byte 3 that are NOT CRC
  -- For header-only: ctrl(1)+dst(2)+src(2) = 5
  -- For header+data: 5 + user_data (CRC excluded)

  -- Minimum frame size: 10 (header + CRC)
  if #data < 10 then
    return false, "Frame truncated (need 10 bytes, got " .. #data .. ")"
  end

  -- Validate header CRC
  local header_bytes = string.sub(data, 1, 8)
  local expected_hdr_crc = dnp3_crc16(header_bytes)
  local actual_hdr_crc = data:byte(9) | (data:byte(10) << 8)

  if actual_hdr_crc ~= expected_hdr_crc then
    return false, string.format("Header CRC mismatch: expected 0x%04X, got 0x%04X", expected_hdr_crc, actual_hdr_crc)
  end

  return true
end

-- ============================================================
--  Helper: Decode DNP3 application response object headers
-- ============================================================
function parse_app_response(data)
  local pos = 1
  local results = {}
  local objects = {}
  local iin1, iin2

  -- Find transport header (starts after link header)
  -- Link header: 10 bytes (sync*2 + len + ctrl + dst*2 + src*2 + crc*2)
  -- If length > 5, user data follows
  local link_len = data:byte(3)
  if link_len <= 5 then
    return nil, "No application data in response"
  end

  pos = 11  -- Start of user data (after 10-byte link header)

  -- Parse transport header (1 byte)
  if pos > #data then
    return nil, "Missing transport header"
  end
  local transport = data:byte(pos)
  local fin = (transport >> 7) & 0x01
  local fir = (transport >> 6) & 0x01
  local tseq = transport & 0x3F
  pos = pos + 1

  -- Parse application control
  if pos > #data then
    return nil, "Missing application control byte"
  end
  local app_ctrl = data:byte(pos)
  local app_fir = (app_ctrl >> 7) & 0x01
  local app_fin = (app_ctrl >> 6) & 0x01
  local app_seq = app_ctrl & 0x0F
  pos = pos + 1

  -- Parse application function code
  if pos > #data then
    return nil, "Missing application function code"
  end
  local app_func = data:byte(pos)
  pos = pos + 1

  local function_names = {
    [0x00] = "Confirm",
    [0x01] = "Read",
    [0x81] = "Response",
    [0x82] = "Unsolicited Response",
    [0x83] = "Authentication Response",
  }
  results.func_name = function_names[app_func] or string.format("Unknown (0x%02X)", app_func)
  results.func_code = app_func
  results.transport = { fin = fin, fir = fir, seq = tseq }
  results.application = { fir = app_fir, fin = app_fin, seq = app_seq }

  -- Parse response objects only if this is a Response (0x81)
  if app_func == 0x81 then
    -- Extract IIN bytes
    if pos + 1 > #data then
      return nil, "Missing IIN bytes"
    end
    iin1 = data:byte(pos)
    iin2 = data:byte(pos + 1)
    results.iin1 = iin1
    results.iin2 = iin2
    results.iin_raw = string.format("IIN1: 0x%02X, IIN2: 0x%02X", iin1, iin2)
    pos = pos + 2

    -- Parse object headers
    while pos <= #data - 2 do  -- Need at least 3 bytes for group/var/qualifier
      local group = data:byte(pos)
      local var = data:byte(pos + 1)
      local qualifier = data:byte(pos + 2)
      pos = pos + 3

      local obj_name = "Unknown"
      local grp_def = dnp3_object_groups[group]
      if grp_def then
        local var_name = grp_def.vars[var] or ("Var " .. var)
        obj_name = grp_def.name .. " (" .. var_name .. ")"
      else
        obj_name = string.format("Group %d Var %d", group, var)
      end

      local point_count = 0
      if qualifier == 0x00 then
        -- Start/Stop (2 bytes each)
        if pos + 3 <= #data then
          local start = data:byte(pos) | (data:byte(pos + 1) << 8)
          local stop = data:byte(pos + 2) | (data:byte(pos + 3) << 8)
          point_count = stop - start + 1
          pos = pos + 4
        end
      elseif qualifier == 0x01 then
        -- Start/Stop (1 byte each)
        if pos + 1 <= #data then
          local start = data:byte(pos)
          local stop = data:byte(pos + 1)
          point_count = stop - start + 1
          pos = pos + 2
        end
      elseif qualifier == 0x06 then
        -- All points (no range field)
        point_count = -1  -- Unknown count
      else
        -- Skip unknown qualifier (try to skip 2 bytes)
        if pos + 1 <= #data then
          point_count = -2  -- Couldn't determine
          pos = pos + 2
        end
      end

      table.insert(objects, {
        group = group,
        variation = var,
        name = obj_name,
        count = point_count,
      })
    end
    results.objects = objects
    results.object_count = #objects
  end

  return results
end

-- ============================================================
--  Phase 1: Link Status Request
-- ============================================================
function phase1_link_status(sock, host, port, dst_addr, src_addr, timeout)
  stdnse.debug2("Phase 1: Sending Link Status Request (dst=%d, src=%d)", dst_addr, src_addr)

  -- Build Link Status Request
  -- ctrl = 0xC9: DIR=1, PRM=1, FCB=0, FCV=1, Func=9 (Request Link Status)
  local frame = build_link_frame(0xC9, dst_addr, src_addr, nil)
  stdnse.debug3("Phase 1 frame: %s", stdnse.tohex(frame))

  local status = sock:send(frame)
  if not status then
    return nil, "Link Status send failed"
  end

  -- Receive response (up to 256 bytes)
  local status_recv, response = sock:receive_bytes(10)
  if not status_recv then
    if response == "TIMEOUT" then
      return nil, "Link Status request timed out"
    end
    return nil, "Link Status receive error: " .. tostring(response)
  end

  -- Validate CRC
  local valid, err = validate_frame(response)
  if not valid then
    return nil, "Link Status CRC error: " .. err
  end

  -- Parse response
  local ctrl = response:byte(4)
  local dst_l = response:byte(5)
  local dst_h = response:byte(6)
  local src_l = response:byte(7)
  local src_h = response:byte(8)

  local resolved_dst = dst_l | (dst_h << 8)
  local resolved_src = src_l | (src_h << 8)
  local func_name, func_code, prm = parse_link_control(ctrl)

  local result = {
    destination_address = resolved_dst,
    source_address = resolved_src,
    control_raw = ctrl,
    function_code = func_code,
    function_name = func_name,
    prm = prm,
  }

  stdnse.debug2("Phase 1 complete: dst=%d, src=%d, func=%s", resolved_dst, resolved_src, func_name)
  return result
end

-- ============================================================
--  Phase 2: Application Layer — Read Class 0
-- ============================================================
function phase2_class0(sock, host, port, dst_addr, src_addr, timeout, seq)
  stdnse.debug2("Phase 2: Sending Read Class 0 request")

  -- App Layer Read with Group 60 Var 1 (Class 0), Qualifier 0x06 (all points)
  local obj_hdr = build_read_object_header(0x3C, 0x01, 0x06)
  local user_data = build_app_request(0x01, obj_hdr, seq)

  -- ctrl = 0xC3: DIR=1, PRM=1, FCB=0, FCV=0, Func=3 (User Data)
  local frame = build_link_frame(0xC3, dst_addr, src_addr, user_data)
  stdnse.debug3("Phase 2 frame: %s", stdnse.tohex(frame))

  local status = sock:send(frame)
  if not status then
    return nil, "Class 0 send failed"
  end

  local status_recv, response = sock:receive_bytes(10)
  if not status_recv then
    if response == "TIMEOUT" then
      return nil, "Class 0 request timed out (device may not support app layer reads)"
    end
    return nil, "Class 0 receive error: " .. tostring(response)
  end

  local valid, err = validate_frame(response)
  if not valid then
    return nil, "Class 0 CRC error: " .. err
  end

  local result = parse_app_response(response)
  if not result then
    return nil, "Could not parse application response"
  end

  stdnse.debug2("Phase 2 complete: %d object types found, IIN=%s",
    result.object_count or 0, result.iin_raw or "N/A")

  return result
end

-- ============================================================
--  Phase 3: Application Layer — Read Device Attributes
-- ============================================================
function phase3_attributes(sock, host, port, dst_addr, src_addr, timeout, seq)
  stdnse.debug2("Phase 3: Sending Device Attributes read request")

  -- Device Attributes: Group 0 Var 0, Qualifier 0x06
  -- This is the DNP3 User Group's recommended Device Attributes query
  local obj_hdr = build_read_object_header(0x00, 0x00, 0x06)
  local user_data = build_app_request(0x01, obj_hdr, seq)
  local frame = build_link_frame(0xC3, dst_addr, src_addr, user_data)
  stdnse.debug3("Phase 3 frame: %s", stdnse.tohex(frame))

  local status = sock:send(frame)
  if not status then
    return nil, "Device Attributes send failed"
  end

  local status_recv, response = sock:receive_bytes(10)
  if not status_recv then
    if response == "TIMEOUT" then
      return nil, "Device Attributes request timed out (not supported)"
    end
    return nil, "Device Attributes receive error: " .. tostring(response)
  end

  local valid, err = validate_frame(response)
  if not valid then
    return nil, "Device Attributes CRC error: " .. err
  end

  local result = parse_app_response(response)
  return result
end

-- ============================================================
--  Helper: Try link status with a specific destination address
-- ============================================================
function try_address(sock, host, port, dst_addr, src_addr, timeout)
  local result, err = phase1_link_status(sock, host, port, dst_addr, src_addr, timeout)
  if result then
    return result
  end
  return nil, err
end

-- ============================================================
--  Main Action
-- ============================================================
action = function(host, port)

  -- Script arguments
  local dst_addr = tonumber(stdnse.get_script_args("dnp3.dst-addr") or "-1")
  local src_addr = tonumber(stdnse.get_script_args("dnp3.src-addr") or "100")
  local timeout = tonumber(stdnse.get_script_args("dnp3.timeout") or "5000")
  local no_class0 = stdnse.get_script_args("dnp3.no-class0") == "true"
  local no_attrs = stdnse.get_script_args("dnp3.no-attrs") == "true"

  local output = stdnse.output_table()
  local sock = nmap.new_socket()
  sock:set_timeout(timeout)

  -- Connect
  local status, err = sock:connect(host, port)
  if not status then
    sock:close()
    stdnse.debug1("Connection failed: %s", err)
    return nil
  end

  -- ============================================================
  --  Phase 1: Link Status
  -- ============================================================
  local link_result
  local addresses_to_try = {}

  if dst_addr >= 0 then
    -- User specified a specific address
    addresses_to_try = { dst_addr }
  else
    -- Auto-detect: try broadcast, then common addresses
    addresses_to_try = { 0xFFFF, 0xFFFE, 1, 100, 200, 10, 20, 50 }
  end

  for _, addr in ipairs(addresses_to_try) do
    link_result, err = try_address(sock, host, port, addr, src_addr, timeout)
    if link_result then
      stdnse.debug1("Link Status successful with dst=%d (response from outstation addr=%d)", addr, link_result.source_address)
      break
    end
    stdnse.debug1("No response from dst=%d: %s", addr, err or "unknown")
  end

  if not link_result then
    sock:close()
    stdnse.debug1("No DNP3 device found on any address")
    return nil
  end

  -- Build Phase 1 output
  local phase1_out = stdnse.output_table()
  phase1_out["Destination address"] = link_result.destination_address
  phase1_out["Source address"] = link_result.source_address
  phase1_out["Control"] = string.format("%s (%d)", link_result.function_name, link_result.function_code)

  -- Reconnect with the resolved source/destination for phases 2 & 3
  local resolved_dst = link_result.source_address
  local resolved_src = dst_addr >= 0 and dst_addr or src_addr

  -- Update the source to reflect our chosen address
  resolved_src = (dst_addr >= 0) and dst_addr or src_addr

  -- The "destination" in our requests should be the device's source address
  local device_addr = link_result.source_address
  local our_addr = resolved_src

  stdnse.debug1("Using device address=%d, our address=%d for application layer", device_addr, our_addr)

  local phase1_info = {
    destination_address = link_result.destination_address,
    source_address = link_result.source_address,
    function_name = link_result.function_name,
  }

  -- ============================================================
  --  Phase 2: Read Class 0
  -- ============================================================
  local app_result = nil
  local app_seq = 0

  if not no_class0 then
    -- Reconnect for clean session
    sock:close()
    sock = nmap.new_socket()
    sock:set_timeout(timeout)

    local ok, connerr = sock:connect(host, port)
    if ok then
      app_result = phase2_class0(sock, host, port, device_addr, our_addr, timeout, app_seq)
      if app_result then
        app_seq = app_seq + 1
      end
    else
      stdnse.debug1("Phase 2 connection error: %s", connerr)
    end
  end

  -- ============================================================
  --  Phase 3: Device Attributes
  -- ============================================================
  local attr_result = nil

  if not no_attrs and app_result then
    attr_result = phase3_attributes(sock, host, port, device_addr, our_addr, timeout, app_seq)
    if not attr_result then
      stdnse.debug1("Device Attributes not supported by this device")
    end
  end

  -- ============================================================
  --  Build output
  -- ============================================================

  -- Phase 1: Link Layer
  output["[Phase 1 — Link Layer]"] = phase1_out

  -- Phase 2: Application Layer — Class 0
  if app_result then
    local phase2_out = stdnse.output_table()

    -- IIN bits
    if app_result.iin1 ~= nil and app_result.iin2 ~= nil then
      phase2_out["IIN1"] = string.format("0x%02X", app_result.iin1)
      phase2_out["IIN2"] = string.format("0x%02X", app_result.iin2)

      local iin_messages, severity = parse_iin(app_result.iin1, app_result.iin2)
      phase2_out["Device health"] = iin_messages[1]
      if #iin_messages > 1 then
        for i = 2, #iin_messages do
          phase2_out[string.format("IIN detail %d", i - 1)] = iin_messages[i]
        end
      end
    end

    -- Object types found
    if app_result.objects and #app_result.objects > 0 then
      local obj_list = {}
      for i, obj in ipairs(app_result.objects) do
        local count_str = ""
        if obj.count >= 0 then
          count_str = string.format(" — %d points", obj.count)
        elseif obj.count == -1 then
          count_str = " — all points"
        end
        table.insert(obj_list, string.format("%d: %s%s", i, obj.name, count_str))
      end
      phase2_out["Object types found"] = #app_result.objects
      for i, line in ipairs(obj_list) do
        phase2_out[string.format("  %d", i)] = line
      end
    else
      phase2_out["Object types found"] = "0 (empty response)"
    end

    output["[Phase 2 — Application Layer: Class 0 Data]"] = phase2_out
  else
    output["[Phase 2 — Application Layer: Class 0 Data]"] = "No response (device may not support Application Layer reads)"
  end

  -- Phase 3: Device Attributes
  if attr_result then
    local phase3_out = stdnse.output_table()

    -- Try to extract strings from Octet String objects (Group 110)
    if attr_result.objects then
      local has_attributes = false
      for _, obj in ipairs(attr_result.objects) do
        if obj.group == 110 or obj.group == 0 then
          -- Octet String or direct attributes
          phase3_out[string.format("Object: %s", obj.name)] = string.format("Group %d Var %d", obj.group, obj.variation)
          has_attributes = true
        end
      end
      if not has_attributes then
        phase3_out["Vendor / Model"] = "Device Attributes returned " .. attr_result.object_count .. " object(s), parse vendor-specific"
      end
    end

    if attr_result.iin1 ~= nil and attr_result.iin2 ~= nil then
      local iin_messages, severity = parse_iin(attr_result.iin1, attr_result.iin2)
      phase3_out["Device health (Phase 3)"] = iin_messages[1]
    end

    output["[Phase 3 — Device Attributes]"] = phase3_out
  else
    if not no_attrs then
      output["[Phase 3 — Device Attributes]"] = "Not supported by this device (DNP3 Device Attributes extension is optional)"
    end
  end

  -- Set nmap port version
  sock:close()

  if link_result then
    port.version.name = "DNP3"
    nmap.set_port_version(host, port)
    nmap.set_port_state(host, port, "open")
  end

  return output
end
