local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
GE SRTP (Service Request Transport Protocol) is a protocol used by GE Fanuc and GE
Intelligent Platforms PLCs (PACSystems, Rx3i, 90-30, 90-70 series) for programming
and data exchange over TCP port 18245.

This script performs a two-phase handshake (INIT/INIT_ACK) then sends a PLC_SSTAT
service request to retrieve PLC identification information including the model name,
firmware version, and CPU type.
]]

---
-- @usage
-- nmap --script gesrtp-info-improved.nse -p 18245 <host>
--
-- @output
-- 18245/tcp open  ge-srtp
-- | gesrtp-info:
-- |   PLC Model: GE PACSystems RX3i
-- |   Firmware Version: V9.50
-- |   CPU Type: IC695CPE302
-- |_  PLC Status: Running
--
-- @xmloutput
-- <elem key="plc_model">GE PACSystems RX3i</elem>
-- <elem key="firmware_version">V9.50</elem>
-- <elem key="cpu_type">IC695CPE302</elem>
-- <elem key="plc_status">Running</elem>
--

author = "Sisyphus (OhMyOpenCode)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

-- SRTP protocol constants
local SRTP_PORT = 18245
local PKT_INIT    = 0x0000
local PKT_INIT_ACK = 0x0001
local PKT_REQ     = 0x0002
local PKT_REQ_ACK = 0x0003
local SRTP_HEADER_LEN = 6
local SRTP_PACKET_LEN = 56
local SRTP_DATA_LEN   = 50

-- Service codes
local SERVICE_PLC_SSTAT = 0
local SERVICE_PLC_LSTAT = 1
local SERVICE_RET_CONFIG_INFO = 67

-- PLC status values
local PLC_STATUS = {
  [0x0000] = "Running",
  [0x0001] = "Stopped",
  [0x0002] = "Faulted",
  [0x0003] = "Halted",
  [0x0004] = "Debug",
}

portrule = shortport.portnumber(SRTP_PORT, "tcp")

---
-- Extract a null-terminated ASCII string from a binary buffer starting at
-- the given 1-indexed offset. Returns the string without the null terminator.
-- If no null terminator is found within the remaining buffer, returns the
-- substring from offset to end.
--
-- @param data  Binary buffer (string)
-- @param off   1-indexed offset into the buffer
-- @return      Extracted string (without null terminator)
local function extract_string(data, off)
  local null_pos = data:find("\x00", off)
  if not null_pos then
    return data:sub(off)
  end
  return data:sub(off, null_pos - 1)
end

---
-- Build an SRTP INIT packet (56 bytes).
-- Packet type 0x0000, index 0x0001, data length 0x0000, rest zero-filled.
--
-- @return  56-byte INIT packet
local function build_init()
  return string.pack(">I2I2I2", PKT_INIT, 0x0001, 0x0000)
         .. string.rep("\x00", SRTP_DATA_LEN)
end

---
-- Build an SRTP REQ packet targeting a given service code (56 bytes).
-- Packet type 0x0002, index 0x0002, data length 0x0004 (4-byte service code).
--
-- @param service  Service code (uint32) e.g. 0 = PLC_SSTAT
-- @return         56-byte REQ packet
local function build_req(service)
  local pkt = string.pack(">I2I2I2", PKT_REQ, 0x0002, 0x0004)
              .. string.pack(">I4", service)
  pkt = pkt .. string.rep("\x00", SRTP_PACKET_LEN - #pkt)
  return pkt
end

---
-- Parse an SRTP REQ_ACK response for PLC_SSTAT and extract identification
-- information from the 50-byte data payload.
--
-- Layout of data payload (bytes 7..56, 1-indexed):
--   Bytes  7-8:   Status code (uint16)
--   Bytes  9-10:  Reserved (uint16)
--   Bytes 11-30:  PLC model string (20 bytes, null-terminated)
--   Bytes 31-40:  Firmware version string (10 bytes, null-terminated)
--   Bytes 41-56:  CPU type string (16 bytes, null-terminated)
--
-- @param data  Full 56-byte REQ_ACK response
-- @return      Table with plc_model, firmware_version, cpu_type and raw_status,
--              or nil if parsing fails
local function parse_sstat_response(data)
  if #data < SRTP_PACKET_LEN then
    stdnse.debug1("REQ_ACK too short: %d bytes", #data)
    return nil
  end

  local status_code = string.unpack(">I2", data, 7)
  if status_code ~= 0x0000 then
    stdnse.debug1("PLC returned non-zero status 0x%04x", status_code)
    return nil
  end

  local result = {
    raw_status = status_code,
    plc_status_word = PLC_STATUS[status_code] or ("Unknown (0x%04x)"):format(status_code),
  }

  -- Extract null-terminated strings from fixed offsets
  local model   = extract_string(data, 11)  -- byte 11 = after status + reserved
  local fw_ver  = extract_string(data, 31)  -- byte 31 = after model field (20 bytes)
  local cpu     = extract_string(data, 41)  -- byte 41 = after firmware field (10 bytes)

  if model ~= "" then
    result.plc_model = model
  end
  if fw_ver ~= "" then
    result.firmware_version = fw_ver
  end
  if cpu ~= "" then
    result.cpu_type = cpu
  end

  return result
end

-- ########################################
-- Action
-- ########################################
action = function(host, port)
  local socket = nmap.new_socket()
  local timeout = stdnse.get_timeout(host)
  socket:set_timeout(timeout)

  -- Connect
  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("Connection to %s:%d failed: %s", host.ip, port.number, err)
    return nil
  end

  -- ========================================
  -- Phase 1: INIT / INIT_ACK
  -- ========================================
  local init_pkt = build_init()
  status, err = socket:send(init_pkt)
  if not status then
    stdnse.debug1("Failed to send INIT: %s", err)
    socket:close()
    return nil
  end
  stdnse.debug2("Sent INIT packet (%d bytes)", #init_pkt)

  -- Receive INIT_ACK (expect at least 56 bytes)
  local resp
  status, resp = socket:receive_bytes(SRTP_PACKET_LEN)
  if not status then
    stdnse.debug1("Failed to receive INIT_ACK: %s", resp or err)
    socket:close()
    return nil
  end

  if #resp < SRTP_PACKET_LEN then
    stdnse.debug1("INIT_ACK too short: got %d bytes, expected %d", #resp, SRTP_PACKET_LEN)
    socket:close()
    return nil
  end

  -- Validate INIT_ACK packet type
  local pkt_type = string.unpack(">I2", resp)
  if pkt_type ~= PKT_INIT_ACK then
    stdnse.debug1("Expected INIT_ACK (0x%04x), got packet type 0x%04x", PKT_INIT_ACK, pkt_type)
    socket:close()
    return nil
  end
  stdnse.debug2("Received valid INIT_ACK")

  -- ========================================
  -- Phase 2: REQ (PLC_SSTAT) / REQ_ACK
  -- ========================================
  local req_pkt = build_req(SERVICE_PLC_SSTAT)
  status, err = socket:send(req_pkt)
  if not status then
    stdnse.debug1("Failed to send PLC_SSTAT REQ: %s", err)
    socket:close()
    return nil
  end
  stdnse.debug2("Sent PLC_SSTAT REQ (service=%d)", SERVICE_PLC_SSTAT)

  -- Receive REQ_ACK
  status, resp = socket:receive_bytes(SRTP_PACKET_LEN)
  if not status then
    stdnse.debug1("Failed to receive REQ_ACK: %s", resp or err)
    socket:close()
    return nil
  end

  if #resp < SRTP_PACKET_LEN then
    stdnse.debug1("REQ_ACK too short: got %d bytes", #resp)
    socket:close()
    return nil
  end

  -- Validate REQ_ACK packet type
  pkt_type = string.unpack(">I2", resp)
  if pkt_type ~= PKT_REQ_ACK then
    stdnse.debug1("Expected REQ_ACK (0x%04x), got packet type 0x%04x", PKT_REQ_ACK, pkt_type)
    socket:close()
    return nil
  end
  stdnse.debug2("Received valid REQ_ACK")

  -- ========================================
  -- Parse Results
  -- ========================================
  socket:close()

  local info = parse_sstat_response(resp)
  if not info then
    stdnse.debug1("Failed to parse PLC_SSTAT response")
    return nil
  end

  -- Build output table
  local result = stdnse.output_table()
  if info.plc_model then
    result["PLC Model"] = info.plc_model
  end
  if info.firmware_version then
    result["Firmware Version"] = info.firmware_version
  end
  if info.cpu_type then
    result["CPU Type"] = info.cpu_type
  end
  if info.plc_status_word then
    result["PLC Status"] = info.plc_status_word
  end

  -- Set port version info for nmap service/version detection
  port.version.name = "ge-srtp"
  port.version.product = info.plc_model or "GE SRTP PLC"
  port.version.version = info.firmware_version
  nmap.set_port_version(host, port)

  -- Return nil if nothing useful was extracted
  if #result <= 0 then
    return nil
  end

  return result
end
