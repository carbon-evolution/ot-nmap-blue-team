local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Identifies a Siemens S7 PLC (S7-1200/1500, S7comm-plus era) on TCP 102 by
performing the read-only S7comm identification exchange: a COTP connection,
S7comm setup-communication, then SZL reads of SZL-ID 0x0011 (module
identification) and 0x001C (component identification). Reports Module
(order/MLFB number), firmware Version, Module Type, Serial Number, and
System Name.

This targets S7-1200/1500 devices, which answer the classic SZL
identification used here in addition to their S7comm-plus session protocol.
It is a T1-safe read: identification SZL reads only, no configuration reads
and no writes.

Improved over the upstream Redpoint s7-enumerate.nse: the fixed-offset
string parsing is ported from the removed Nmap `bin.unpack` API to
`string.unpack`, and each parse is guarded so a malformed or short response
degrades gracefully instead of raising.
]]

---
-- @usage nmap --script s7comm-plus-info-improved -p 102 <host>
--
-- @output
-- 102/tcp open  iso-tsap
-- | s7comm-plus-info-improved:
-- |   Module Type: CPU 1212C DC/DC/DC
-- |   Module: 6ES7 212-1AE40-0XB0
-- |   Version: 4.4.0
-- |   Serial Number: S C-K1U450132020
-- |_  System Name: PLC_1200

author = "OT Nmap Blue Team (improved from Redpoint by Digital Bond)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(102, "iso-tsap", "tcp")

-- Fixed identification frames (COTP + S7comm), reused from the upstream script.
local REQ_COTP     = "0300001611e00000001400c1020100c2020102c0010a"
local REQ_SETUP    = "0300001902f08032010000000000080000f0000001000101e0"
local REQ_SZL_11   = "0300002102f080320700000000000800080001120411440100ff09000400110001"
local REQ_SZL_1C   = "0300002102f080320700000000000800080001120411440100ff090004001c0001"

--- Read a null-terminated ASCII string at a 1-based offset, guarded.
-- @return string|nil the value (nil if empty or on error)
local function read_z(resp, offset)
  if not resp or offset > #resp then return nil end
  local ok, value = pcall(string.unpack, "z", resp, offset)
  if not ok or not value or value == "" then return nil end
  return value
end

--- Parse the SZL 0x11 response: Module (@44) and Version (3 bytes @123).
local function parse_szl_11(resp, out)
  if not resp or resp:byte(8) ~= 0x32 then return end
  local module = read_z(resp, 44)
  if module then out["Module"] = module end
  if #resp >= 125 then
    local ok, b1, b2, b3 = pcall(string.unpack, "BBB", resp, 123)
    if ok then
      out["Version"] = string.format("%d.%d.%d", b1, b2, b3)
    end
  end
end

--- Parse the SZL 0x1C response: System Name (@40), Module Type (@74),
--- Serial Number (@176). For a valid 0x1C reply the offset base is 0.
local function parse_szl_1c(resp, out)
  if not resp or resp:byte(8) ~= 0x32 then return end
  local system_name = read_z(resp, 40)
  local module_type = read_z(resp, 74)
  local serial      = read_z(resp, 176)
  if system_name then out["System Name"] = system_name end
  if module_type then out["Module Type"] = module_type end
  if serial then out["Serial Number"] = serial end
end

local function send_receive(sock, hexframe)
  local ok = sock:send(stdnse.fromhex(hexframe))
  if not ok then return nil end
  local status, resp = sock:receive()
  if not status then return nil end
  return resp
end

action = function(host, port)
  local out = stdnse.output_table()
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok = sock:connect(host, port)
  if not ok then return nil end

  -- 1. COTP connection request -> expect Connection Confirm (byte 6 = 0xD0).
  local resp = send_receive(sock, REQ_COTP)
  if not resp or resp:byte(6) ~= 0xD0 then sock:close(); return nil end

  -- 2. S7comm setup-communication -> expect S7 protocol id (byte 8 = 0x32).
  resp = send_receive(sock, REQ_SETUP)
  if not resp or resp:byte(8) ~= 0x32 then sock:close(); return nil end

  -- 3. SZL 0x11 (module identification): Module + Version.
  resp = send_receive(sock, REQ_SZL_11)
  parse_szl_11(resp, out)

  -- 4. SZL 0x1C (component identification): System Name, Module Type, Serial.
  resp = send_receive(sock, REQ_SZL_1C)
  parse_szl_1c(resp, out)

  sock:close()
  if #out == 0 then return nil end

  nmap.set_port_state(host, port, "open")
  return out
end
