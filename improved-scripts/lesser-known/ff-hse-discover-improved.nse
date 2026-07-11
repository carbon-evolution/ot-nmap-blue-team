local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Improved Foundation Fieldbus HSE (High Speed Ethernet) device discovery script.

Foundation Fieldbus HSE is an Ethernet-based process automation protocol that
uses TCP/UDP ports 1089-1091. HSE devices use the Fieldbus Foundation's
System Management (SM) and Management Agent (MA) protocols for device
discovery and management.

This script probes all three HSE ports:
- Port 1089 (TCP): HSE Management Agent (MA) — device management interface
- Port 1090 (TCP): HSE System Management (SM) — device identification
- Port 1091 (TCP): HSE System Management (SM) — secondary/alternate SM

For each port it sends the appropriate protocol probe and extracts device
identification information from the response.

References:
* https://fieldcommgroup.org/technologies/foundation-fieldbus
* https://www.fieldbus.org/
* IEC 61158-5 (Fieldbus Message Specification)
* IEC 61158-6 (Fieldbus Protocol Specification)
]]

---
-- @usage
-- nmap --script ff-hse-discover-improved -p 1089-1091 <host>
-- nmap --script ff-hse-discover-improved -p 1089 <host>
--
-- @output
-- 1089/tcp open  ff-hse-ma
-- | ff-hse-discover-improved:
-- |   Port: 1089
-- |   Service: HSE Management Agent
-- |   State: responding
-- |   Device Info:
-- |     Device ID: ACME-FF-HSE-12345
-- |     Vendor: Fieldbus Foundation
-- |     HSE Version: 1.2
-- |     Device Type: FF_HSE_Device
-- |_    Stack: FF_HSE_Stack_v2.1
--
-- 1090/tcp open  ff-hse-sm
-- | ff-hse-discover-improved:
-- |   Port: 1090
-- |   Service: HSE System Management
-- |   State: responding
-- |   Device Info:
-- |     Device ID: ACME-FF-HSE-12345
-- |     Vendor: Fieldbus Foundation
-- |     HSE Version: 1.2
-- |     Device Tag: FIC-101
-- |_    Software Rev: 3.0.1
--
-- @xmloutput
-- <table>
--   <elem key="port">1089</elem>
--   <elem key="service">HSE Management Agent</elem>
--   <elem key="state">responding</elem>
--   <table key="device_info">
--     <elem key="device_id">ACME-FF-HSE-12345</elem>
--     <elem key="vendor">Fieldbus Foundation</elem>
--     <elem key="hse_version">1.2</elem>
--     <elem key="device_type">FF_HSE_Device</elem>
--     <elem key="stack">FF_HSE_Stack_v2.1</elem>
--   </table>
-- </table>

author = "Sisyphus (OhMyOpenCode)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Port specification: FF HSE uses TCP/UDP 1089-1091
local HSE_PORTS = {1089, 1090, 1091}
local HSE_MA_PORT = 1089
local HSE_SM_PORTS = {1090, 1091}

-- ============================================================
-- PROBE DEFINITIONS
-- ============================================================

--- HSE SM_Identify request (System Management on ports 1090/1091).
-- Structure:
--   Byte 0: Protocol version (0x01 = HSE SM v1)
--   Byte 1: Service code (0x01 = SM_Identify)
--   Bytes 2-3: Reserved (0x0000)
local SM_IDENTIFY_REQ = string.char(
  0x01,       -- SM Protocol version
  0x01,       -- Service code: SM_Identify
  0x00, 0x00  -- Reserved
)

--- HSE Management Agent query (port 1089).
-- The HSE Management Agent uses a simple request/response protocol.
-- Structure:
--   Byte 0: Protocol discriminator (0x90 = HSE MA)
--   Byte 1: Message type (0x01 = GetIdentification)
--   Bytes 2-3: Transaction ID (0x0001)
--   Bytes 4-7: Reserved (0x00000000)
local MA_IDENTIFY_REQ = string.char(
  0x90,             -- Protocol discriminator: HSE MA
  0x01,             -- Message type: GetIdentification
  0x00, 0x01,       -- Transaction ID
  0x00, 0x00,       -- Reserved (message body length)
  0x00, 0x00        -- Reserved
)

-- ============================================================
-- HSE PROTOCOL SIGNATURES
-- ============================================================

--- HSE response signature patterns (hex strings to search for).
-- These are byte sequences that identify a response as FF HSE protocol.
local HSE_SIGNATURES = {
  -- HSE SM_Identify response prefix (version + service code = 0x01 0x01)
  { pattern = string.char(0x01, 0x01), label = "HSE SM_Identify Response" },
  -- HSE SM_IdentifyResponse with success (0x01 0x01 0x00)
  { pattern = string.char(0x01, 0x01, 0x00), label = "HSE SM_Identify Positive" },
  -- HSE MA response prefix (discriminator 0x90 + message type)
  { pattern = string.char(0x90, 0x01), label = "HSE MA Identification Response" },
  -- HSE MA response variant
  { pattern = string.char(0x90, 0x81), label = "HSE MA Response (bit 7 set)" },
  -- HSE protocol version indicator
  { pattern = string.char(0x01, 0x04), label = "HSE SM Status Response" },
}

--- Known text strings that identify FF HSE implementations in binary responses.
local HSE_TEXT_SIGNATURES = {
  "FF_HSE",
  "FF HSE",
  "Fieldbus",
  "Foundation",
  "FOUNDATION",
  "fieldbus",
  "HSE Stack",
  "HSE SM",
  "HSE-MA",
  "HSE-MA",
  "FF_HSE_Device",
  "HSE_Stack",
  "Fieldbus Foundation",
  "FOUNDATION fieldbus",
  "fieldbus.org",
  "FieldComm",
}

-- ============================================================
-- UTILITY FUNCTIONS
-- ============================================================

--- Check if data contains any HSE protocol byte signatures.
-- @param data string: raw response data
-- @return string|nil: label of the first matching signature, or nil
local function has_hse_signature(data)
  if not data or #data < 2 then
    return nil
  end
  for _, sig in ipairs(HSE_SIGNATURES) do
    if data:find(sig.pattern, 1, true) then
      return sig.label
    end
  end
  return nil
end

--- Extract printable ASCII strings from binary response data.
-- Looks for sequences of printable ASCII characters (0x20-0x7e)
-- that are at least 3 characters long.
-- @param data string: raw response data
-- @return table: array of extracted ASCII strings
local function extract_ascii_strings(data)
  if not data or #data == 0 then
    return {}
  end
  local strings = {}
  local current = {}
  for i = 1, #data do
    local byte = data:byte(i)
    if byte >= 0x20 and byte <= 0x7e then
      table.insert(current, string.char(byte))
    else
      if #current >= 3 then
        table.insert(strings, table.concat(current))
      end
      current = {}
    end
  end
  if #current >= 3 then
    table.insert(strings, table.concat(current))
  end
  return strings
end

--- Filter ASCII strings to find those that match HSE-related keywords.
-- @param strings table: array of ASCII strings
-- @return table: array of HSE-relevant strings (deduplicated)
local function filter_hse_strings(strings)
  local seen = {}
  local result = {}
  for _, s in ipairs(strings) do
    local s_trimmed = s:match("^%s*(.-)%s*$") or s
    if #s_trimmed > 0 then
      for _, keyword in ipairs(HSE_TEXT_SIGNATURES) do
        if s_trimmed:find(keyword, 1, true) and not seen[s_trimmed] then
          seen[s_trimmed] = true
          table.insert(result, s_trimmed)
          break
        end
      end
    end
  end
  return result
end

--- Extract meaningful device identification strings from the response.
-- Attempts to parse structured fields from an HSE SM_Identify response.
-- The SM_Identify response contains null-terminated strings at known
-- positions after the header.
-- @param data string: raw response data
-- @return table: key-value pairs of device info
local function parse_sm_identify_response(data)
  local info = {}

  if #data < 4 then
    return info
  end

  -- SM_Identify response structure (speculative, based on fieldbus specs):
  -- Bytes 0-1: Version + Service code (0x01 0x01)
  -- Byte 2: Status (0x00 = success)
  -- Byte 3: Reserved/Flags
  -- Then null-terminated strings for device info

  local pos = 4

  -- Try to extract null-terminated strings from the response
  local fields = {
    "device_id",
    "vendor_name",
    "device_tag",
    "hse_version",
    "software_rev",
    "device_type",
    "stack_version",
  }

  for _, field_name in ipairs(fields) do
    if pos and pos <= #data then
      local val
      pos, val = string.unpack("z", data, pos)
      if val and #val > 0 then
        info[field_name] = val
      end
    end
  end

  return info
end

--- Parse HSE Management Agent response (port 1089).
-- @param data string: raw response data
-- @return table: key-value pairs of device info
local function parse_ma_response(data)
  local info = {}

  if #data < 4 then
    return info
  end

  -- MA response structure:
  -- Byte 0: Protocol discriminator (0x90 = HSE MA response)
  -- Byte 1: Response type (0x81 = response with bit 7 set)
  -- Bytes 2-3: Transaction ID (echoed from request)
  -- Then variable-length payload with device info strings

  local pos = 4

  local fields = {
    "device_id",
    "vendor_name",
    "device_type",
    "hse_version",
    "stack",
  }

  for _, field_name in ipairs(fields) do
    if pos and pos <= #data then
      local val
      pos, val = string.unpack("z", data, pos)
      if val and #val > 0 then
        info[field_name] = val
      end
    end
  end

  return info
end

--- Generate a summary of extracted device information for structured output.
-- @param info table: key-value pairs of device info
-- @return string: formatted summary or nil
local function summarize_device_info(info)
  if not info or next(info) == nil then
    return nil
  end
  local parts = {}
  for k, v in pairs(info) do
    local key_label = k:gsub("_", " "):gsub("^%l", string.upper)
    table.insert(parts, key_label .. ": " .. v)
  end
  return table.concat(parts, ", ")
end

-- ============================================================
-- NMAP VERSION SETTING
-- ============================================================

--- Set nmap port version information for FF HSE services.
-- @param host table: nmap host table
-- @param port table: nmap port table
-- @param port_num number: the port number
--- @param service_name string: service name to report
local function set_nmap_version(host, port, port_num, service_name)
  port.version.name = "ff-hse"
  port.version.product = "Foundation Fieldbus HSE (" .. service_name .. ")"
  if port_num == 1089 then
    port.version.name = "ff-hse-ma"
    port.version.extrainfo = "HSE Management Agent (device management)"
  elseif port_num == 1090 then
    port.version.name = "ff-hse-sm"
    port.version.extrainfo = "HSE System Management"
  elseif port_num == 1091 then
    port.version.name = "ff-hse-sm-alt"
    port.version.extrainfo = "HSE System Management (alternate)"
  end
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")
end

-- ============================================================
-- PORT RULE
-- ============================================================

portrule = shortport.portnumber(HSE_PORTS, "tcp")

-- ============================================================
-- ACTION
-- ============================================================

action = function(host, port)
  local port_num = port.number
  local service_name
  local probe_data

  -- Select probe based on port
  if port_num == HSE_MA_PORT then
    service_name = "HSE Management Agent"
    probe_data = MA_IDENTIFY_REQ
  elseif port_num == 1090 or port_num == 1091 then
    service_name = "HSE System Management"
    probe_data = SM_IDENTIFY_REQ
  else
    return nil
  end

  stdnse.debug1("Probing FF HSE port %d (%s) on %s", port_num, service_name, host.ip)

  -- Create socket
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local result = stdnse.output_table()
  result["port"] = port_num
  result["service"] = service_name

  -- Connect
  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("Connection to %s:%d failed: %s", host.ip, port_num, err)
    socket:close()
    result["state"] = "connection refused"
    return result
  end

  -- Small delay to allow device to send banner (some HSE devices
  -- send identification info immediately on connect)
  stdnse.sleep(0.5)

  -- Try to receive any banner data first
  local banner_status, banner_data = socket:receive_bytes(1)

  if banner_status then
    stdnse.debug1("Received banner (%d bytes) from %s:%d", #banner_data, host.ip, port_num)
    stdnse.debug2("Banner hex: %s", stdnse.tohex(banner_data))

    result["state"] = "responding"
    set_nmap_version(host, port, port_num, service_name)

    -- Check for HSE-specific signatures in banner
    local sig_match = has_hse_signature(banner_data)
    if sig_match then
      stdnse.debug1("HSE signature matched: %s", sig_match)
      result["signature"] = sig_match
    end

    -- Extract and filter ASCII strings
    local ascii_strings = extract_ascii_strings(banner_data)
    local hse_strings = filter_hse_strings(ascii_strings)
    if #hse_strings > 0 then
      result["raw_strings"] = hse_strings
      stdnse.debug1("Found HSE-related strings: %s", table.concat(hse_strings, ", "))
    end

    -- Parse structured device info
    local device_info
    if port_num == HSE_MA_PORT then
      device_info = parse_ma_response(banner_data)
    else
      device_info = parse_sm_identify_response(banner_data)
    end

    if device_info and next(device_info) then
      result["device_info"] = device_info
      local summary = summarize_device_info(device_info)
      if summary then
        stdnse.debug1("Device info: %s", summary)
      end
    elseif #hse_strings > 0 then
      -- Fall back to raw strings as device info if structured parse failed
      -- but we found HSE-relevant text
      local fallback_info = {}
      for i, s in ipairs(hse_strings) do
        fallback_info["field_" .. i] = s
      end
      result["device_info"] = fallback_info
    end

    socket:close()
    return result
  end

  -- No banner received, send probe
  stdnse.debug1("No banner, sending %d-byte probe to %s:%d", #probe_data, host.ip, port_num)

  local send_ok, send_err = socket:send(probe_data)
  if not send_ok then
    stdnse.debug1("Send error on %s:%d: %s", host.ip, port_num, send_err)
    -- Even if send fails, the port is open (we connected)
    result["state"] = "open (no response)"
    socket:close()
    return result
  end

  -- Wait for response to probe
  stdnse.sleep(1.0)

  local recv_ok, recv_data = socket:receive_bytes(1)

  if recv_ok then
    stdnse.debug1("Received probe response (%d bytes) from %s:%d", #recv_data, host.ip, port_num)
    stdnse.debug2("Response hex: %s", stdnse.tohex(recv_data))

    result["state"] = "responding"
    set_nmap_version(host, port, port_num, service_name)

    -- Check for HSE-specific signatures
    local sig_match = has_hse_signature(recv_data)
    if sig_match then
      result["signature"] = sig_match
      stdnse.debug1("HSE signature matched: %s", sig_match)
    end

    -- Extract and filter ASCII strings
    local ascii_strings = extract_ascii_strings(recv_data)
    local hse_strings = filter_hse_strings(ascii_strings)
    if #hse_strings > 0 then
      result["raw_strings"] = hse_strings
    end

    -- Parse structured device info
    local device_info
    if port_num == HSE_MA_PORT then
      device_info = parse_ma_response(recv_data)
    else
      device_info = parse_sm_identify_response(recv_data)
    end

    if device_info and next(device_info) then
      result["device_info"] = device_info
    elseif #hse_strings > 0 then
      local fallback_info = {}
      for i, s in ipairs(hse_strings) do
        fallback_info["field_" .. i] = s
      end
      result["device_info"] = fallback_info
    end

    socket:close()
    return result
  end

  -- Connected but no response to probe
  stdnse.debug1("No response from %s:%d after probe", host.ip, port_num)
  result["state"] = "open (no response)"

-- Mark port as open with HSE service even without response
  set_nmap_version(host, port, port_num, service_name)

  socket:close()
  return result
end
