local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Improved MELSEC-Q (MELSOFT) PLC information discovery script.

MELSEC-Q is Mitsubishi Electric's series of programmable logic controllers.
They use the proprietary MC (MELSEC Communication) protocol over TCP port 5007,
typically referred to as "MelsoftTCP" or "MelsecQ" in the OT community.

This script uses the MC protocol 3E frame format (binary mode) to probe the PLC
with three sequential requests:

1. CPU type read (command 0x0101)  — returns the CPU model string
2. Model name read (command 0x0100) — returns the PLC series / model name
3. Version read (command 0x0113)    — returns the firmware / version info

Each request is sent over the same TCP connection, and responses are parsed
for the 3E response subheader (0xD000), success response code (0x0000),
and the response payload strings. CPU-type strings are space-padded to
16 bytes per the MC protocol specification.

The 3E binary frame format:
  Subheader (2) + Network(1) + PC(1) + I/O(2) + Station(1) +
  DataLen(3,LE) + Timer(3) + Command(2) + Subcmd(2) + [Data]

References:
  - MELSEC Communication Protocol Reference Manual (SH-080008)
  - MELSEC-Q/L Programming Manual (Mitsubishi Electric)
  - Digital Bond's original melsecq-discover.nse
  - https://github.com/Z-0ne/ICS-Discovery-Tools
]]

---
-- @usage
-- nmap --script melsecq-info-improved.nse -p 5007 <host>
--
-- @output
-- 5007/tcp open  MelsoftTCP
-- | melsecq-info-improved:
-- |   CPU Type: Q03UDECPU
-- |   Model Name: MELSEC-Q
-- |_  Firmware Version: V1.20
--
-- @xmloutput
-- <elem key="CPU Type">Q03UDECPU</elem>
-- <elem key="Model Name">MELSEC-Q</elem>
-- <elem key="Firmware Version">V1.20</elem>
--

author = "Sisyphus (OhMyOpenCode)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

-- 3E frame subheader constants (binary mode)
local SUBHDR_REQUEST    = "\x50\x00"
local SUBHDR_SUCCESS    = "\xD0\x00"

-- MC protocol commands
local CMD_CPU_TYPE_READ = 0x0101   -- CPU type read
local CMD_MODEL_READ    = 0x0100   -- model name read
local CMD_VERSION_READ  = 0x0113   -- version / firmware info read

-- Frame geometry
local FRAME_HDR_SZ      = 7        -- subhdr(2)+net(1)+pc(1)+io(2)+station(1)
local RESP_CODE_SZ      = 2        -- response code (2 bytes)
local MIN_RESPONSE_SZ   = 12       -- subhdr(2)+net(1)+pc(1)+io(2)+station(1)+len(3)+respcode(2)

-- Expected payload sizes per command (response string in bytes)
local CPU_TYPE_DATA_SZ  = 16       -- CPU type string length
local MODEL_DATA_SZ     = 16       -- model name string length
local VERSION_DATA_SZ   = 16       -- version string length


-- ==============================
-- 3-byte LE field helpers
-- ==============================

--- Pack an integer into 3 bytes (little-endian).
-- Supports values up to 0xFFFFFF.
-- @param val  Integer (0 .. 16777215)
-- @return     3-character string
local function pack_u24_le(val)
  return string.char(
    bit32.band(val, 0xFF),
    bit32.band(bit32.rshift(val, 8), 0xFF),
    bit32.band(bit32.rshift(val, 16), 0xFF)
  )
end

--- Unpack a 3-byte little-endian integer.
-- @param data  Source string
-- @param off   1-based offset
-- @return      Unpacked integer
local function unpack_u24_le(data, off)
  local b1 = string.byte(data, off)
  local b2 = string.byte(data, off + 1)
  local b3 = string.byte(data, off + 2)
  return b1 + b2 * 256 + b3 * 65536
end


-- ==============================
-- 3E Frame Builder
-- ==============================

--- Build a complete 3E frame (binary mode) request.
--
-- Frame layout:
--   Off 0:   Subheader (2 bytes, 0x5000 = binary request)
--   Off 2:   Network No (1 byte, 0x00)
--   Off 3:   PC No (1 byte, 0xFF)
--   Off 4:   Request Dest Module I/O No (2 bytes, 0x03FF)
--   Off 6:   Request Dest Module Station No (1 byte, 0x00)
--   Off 7:   Request Data Length (3 bytes LE = timer+cmd+subcmd+data)
--   Off 10:  Timer (3 bytes, 0x001000 = 1000ms)
--   Off 13:  Command (2 bytes)
--   Off 15:  Subcommand (2 bytes)
--   Off 17:  Command-specific data (variable)
--
-- @param cmd     MC protocol command (uint16)
-- @param subcmd  MC protocol subcommand (uint16)
-- @param data    Optional command-specific payload (default empty)
-- @return        Complete 3E request frame as a string
local function build_3e_request(cmd, subcmd, data)
  data = data or ""

  -- Payload = timer(3) + cmd(2) + subcmd(2) + data
  local payload = "\x00\x00\x10"          -- timer: 1000ms in 3 bytes
               .. string.pack("<I2", cmd)
               .. string.pack("<I2", subcmd)
               .. data

  local frame = SUBHDR_REQUEST            -- subheader (2)
             .. "\x00"                    -- network no (1)
             .. "\xFF"                    -- PC no (1)
             .. "\xFF\x03"                -- I/O no (2)
             .. "\x00"                    -- station no (1)
             .. pack_u24_le(#payload)     -- data length (3)
             .. payload

  return frame
end


-- ==============================
-- Response Parser
-- ==============================

--- Parse a 3E frame response.
--
-- Response layout:
--   Off 0:    Subheader (2 bytes, 0xD000 = success)
--   Off 2-6:  Routing fields (5 bytes, echoed from request)
--   Off 7-9:  Data Length (3 bytes LE)
--   Off 10-11: Response Code (2 bytes, 0x0000 = success)
--   Off 12+:  Response data (command-specific)
--
-- @param resp  Raw response buffer
-- @return      (response_data, nil) on success,
--              (nil, error_message) on failure
local function parse_response(resp)
  if #resp < MIN_RESPONSE_SZ then
    return nil, string.format("response too short: %d bytes", #resp)
  end

  -- Verify response subheader (0xD000)
  if string.byte(resp, 1) ~= 0xD0 or string.byte(resp, 2) ~= 0x00 then
    return nil, string.format("bad response subheader: 0x%02x 0x%02x",
                              string.byte(resp, 1), string.byte(resp, 2))
  end

  -- Parse data length (3 bytes at offset 8, 1-indexed)
  local dlen = unpack_u24_le(resp, 8)
  if dlen < RESP_CODE_SZ then
    return nil, string.format("data length too small: %d", dlen)
  end

  -- Read response code (2 bytes at offset 11, 1-indexed)
  local res_code = string.byte(resp, 11) + string.byte(resp, 12) * 256
  if res_code ~= 0 then
    return nil, string.format("PLC error code 0x%04x", res_code)
  end

  -- Extract payload data after response code (starts at offset 13)
  local data_end = 12 + dlen
  if data_end > #resp then
    data_end = #resp
  end
  local data = resp:sub(13, data_end)

  return data, nil
end


--- Extract a printable ASCII string from binary data, stopping at the
-- first null byte (0x00) and trimming trailing spaces.
--
-- CPU type strings in the MC protocol are typically fixed-size (16 bytes)
-- and padded with spaces (0x20) or nulls.
--
-- @param data  Binary buffer
-- @return      Trimmed printable string, or nil if empty
local function extract_string(data)
  if not data or #data == 0 then
    return nil
  end

  -- Scan until we hit a null or non-printable character
  local pos = 1
  while pos <= #data do
    local b = string.byte(data, pos)
    if b == 0 then
      break
    elseif b < 0x20 or b > 0x7E then
      if b == 0x09 or b == 0x0A or b == 0x0D then
        pos = pos + 1   -- allow tabs/newlines
      else
        break
      end
    else
      pos = pos + 1
    end
  end

  if pos == 1 then
    return nil
  end

  local s = data:sub(1, pos - 1)
  -- Trim trailing whitespace and nulls
  s = s:match("^%s*(.-)%s*$") or s
  if s == "" then
    return nil
  end
  return s
end


--- Send a single 3E request, receive the response, and parse it.
--
-- @param socket  An already-connected nmap socket
-- @param cmd     MC protocol command (uint16)
-- @param subcmd  MC protocol subcommand (uint16)
-- @param data    Optional request payload
-- @return        (response_data, nil) or (nil, error_msg)
local function request_command(socket, cmd, subcmd, data)
  local frame = build_3e_request(cmd, subcmd, data)
  stdnse.debug2("Sending cmd=0x%04x frame (%d bytes)", cmd, #frame)

  local status, err = socket:send(frame)
  if not status then
    return nil, string.format("send error: %s", err)
  end

  -- MC protocol 3E responses are typically < 64 bytes
  local resp
  status, resp = socket:receive_bytes(32)
  if not status then
    return nil, string.format("receive error: %s", resp or err)
  end

  stdnse.debug2("Received %d bytes for cmd=0x%04x", #resp, cmd)
  return parse_response(resp)
end


-- ==============================
-- Port Rule
-- ==============================

portrule = function(host, port)
  return shortport.port_or_service(5007, "MelsoftTCP", "tcp")(host, port)
end


-- ==============================
-- Action
-- ==============================

action = function(host, port)
  local socket = nmap.new_socket()
  local timeout = stdnse.get_timeout(host)
  socket:set_timeout(timeout)

  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("Connection to %s:%d failed: %s", host.ip, port.number, err)
    return nil
  end

  local result = stdnse.output_table()

  -- ==========================================
  -- Request 1: CPU Type Read (command 0x0101)
  -- ==========================================
  local data, err_msg = request_command(socket, CMD_CPU_TYPE_READ, 0x0000)
  if data then
    local cpu_type = extract_string(data)
    if cpu_type then
      result["CPU Type"] = cpu_type
      stdnse.debug1("CPU Type: %s", cpu_type)
    else
      stdnse.debug1("CPU type data unprintable, hex: %s", stdnse.tohex(data))
    end
  else
    stdnse.debug1("CPU type read: %s", err_msg)
  end

  -- ==========================================
  -- Request 2: Model Read (command 0x0100)
  -- ==========================================
  data, err_msg = request_command(socket, CMD_MODEL_READ, 0x0000)
  if data then
    local model = extract_string(data)
    if model then
      result["Model Name"] = model
      stdnse.debug1("Model Name: %s", model)
    else
      stdnse.debug1("Model name data unprintable")
    end
  else
    stdnse.debug1("Model read: %s", err_msg)
  end

  -- ==========================================
  -- Request 3: Version Read (command 0x0113)
  -- ==========================================
  data, err_msg = request_command(socket, CMD_VERSION_READ, 0x0000)
  if data then
    local version = extract_string(data)
    if version then
      result["Firmware Version"] = version
      stdnse.debug1("Firmware Version: %s", version)
    else
      stdnse.debug1("Version data unprintable")
    end
  else
    stdnse.debug1("Version read: %s", err_msg)
  end

  socket:close()

  -- ==========================================
  -- Set nmap port version info
  -- ==========================================
  if result["CPU Type"] or result["Model Name"] then
    port.version.name = "MelsoftTCP"
    port.version.product = "Mitsubishi Q PLC"
    if result["Firmware Version"] then
      port.version.version = result["Firmware Version"]
    end
    nmap.set_port_version(host, port)
  end

  -- Return nil if nothing was extracted
  if #result <= 0 then
    return nil
  end

  return result
end
