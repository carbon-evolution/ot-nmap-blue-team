local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Sends an EtherNet/IP CIP ListIdentity request (encapsulation command 0x0063)
to a device with TCP 44818 open, then parses the ListIdentity response to
extract device identity: Vendor, Product Name, Serial Number, Device Type,
Product Code, Revision, and Device State.

This is a passive, T1-safe discovery probe. It issues a single ListIdentity
request only -- no CIP object reads and no writes are performed, so it is
safe to run against live OT/ICS assets.

This is an improved, hardened port of Digital Bond's Redpoint
enip-enumerate.nse. The original relied on the removed bin.pack/bin.unpack
API, which crashes at runtime on Nmap 7.9x (Lua 5.4). This version uses
string.pack/string.unpack and pcall-guards the response parser.
]]

---
-- @usage
-- nmap --script enip-identity-improved -p 44818 <host>
--
-- @output
-- 44818/tcp open  EtherNet/IP
-- | enip-identity-improved:
-- |   Vendor: Rockwell Automation/Allen-Bradley (1)
-- |   Product Name: 1756-L61/B LOGIX5561
-- |   Serial Number: 0x00C0FFEE
-- |   Device Type: Programmable Logic Controller (14)
-- |   Product Code: 54
-- |   Revision: 20.11
-- |_  Device State: Operational (3)
--
-- @xmloutput
-- <elem key="Vendor">Rockwell Automation/Allen-Bradley (1)</elem>
-- <elem key="Product Name">1756-L61/B LOGIX5561</elem>
-- <elem key="Serial Number">0x00C0FFEE</elem>
-- <elem key="Device Type">Programmable Logic Controller (14)</elem>
-- <elem key="Product Code">54</elem>
-- <elem key="Revision">20.11</elem>
-- <elem key="Device State">Operational (3)</elem>

author = "Improved port for Nmap 7.9x (based on Stephen Hilt, Digital Bond)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(44818, "EtherNet/IP-2", "tcp")

-- Trimmed vendor lookup (full ODVA table is >1200 entries). Falls back to
-- "Unknown Vendor" for IDs not listed here.
local vendor_id = {
  [0] = "Reserved",
  [1] = "Rockwell Automation/Allen-Bradley",
  [40] = "Wago Corporation",
  [47] = "OMRON Corporation",
  [90] = "HMS Industrial Networks AB",
  [108] = "Beckhoff Automation GmbH",
  [161] = "Mitsubishi Electric Corporation",
  [243] = "Schneider Automation Inc.",
  [283] = "Hilscher GmbH",
  [562] = "Phoenix Contact",
}

local function vendor_lookup(vennum)
  return vendor_id[vennum] or "Unknown Vendor"
end

-- CIP device type lookup (trimmed).
local device_type = {
  [0] = "Generic Device (deprecated)",
  [2] = "AC Drive",
  [7] = "General Purpose Discrete I/O",
  [12] = "Communications Adapter",
  [14] = "Programmable Logic Controller",
  [16] = "Position Controller",
  [24] = "Human-Machine Interface",
  [37] = "CIP Motion Drive",
  [44] = "Managed Switch",
}

local function device_type_lookup(devtype)
  return device_type[devtype] or "Unknown Device Type"
end

-- CIP Identity object device state (attribute 8).
local device_state = {
  [0] = "Nonexistent",
  [1] = "Device Self Testing",
  [2] = "Standby",
  [3] = "Operational",
  [4] = "Major Recoverable Fault",
  [5] = "Major Unrecoverable Fault",
}

local function device_state_lookup(state)
  return device_state[state] or "Unknown"
end

--- Parse a ListIdentity response into an output table.
-- Byte offsets are 1-based, matching the on-wire layout:
--   1  command (uint16 LE)          -- expect 0x0063
--   27 CPF item type (uint16 LE)    -- expect 0x000C (Identity)
--   49 vendor_id (uint16 LE)
--   51 device_type (uint16 LE)
--   53 product_code (uint16 LE)
--   55 revision_major (uint8), 56 revision_minor (uint8)
--   59 serial_number (uint32 LE)
--   63 product_name (uint8 length prefix + ASCII)
--   ..  device state (uint8) immediately after the product name
local function parse_identity(response)
  local output = stdnse.output_table()

  local command = string.unpack("<I2", response, 1)
  if command ~= 0x0063 then
    return nil
  end

  local typeid = string.unpack("<I2", response, 27)
  if typeid ~= 0x000C then
    return nil
  end

  local vennum = string.unpack("<I2", response, 49)
  output["Vendor"] = string.format("%s (%d)", vendor_lookup(vennum), vennum)

  local devnum = string.unpack("<I2", response, 51)
  local pcode = string.unpack("<I2", response, 53)
  local rmaj, rmin = string.unpack("BB", response, 55)
  local serial = string.unpack("<I4", response, 59)

  local pname, npos = string.unpack("s1", response, 63)
  local state = string.unpack("B", response, npos)

  output["Product Name"] = pname
  output["Serial Number"] = string.format("0x%08X", serial)
  output["Device Type"] = string.format("%s (%d)",
    device_type_lookup(devnum), devnum)
  output["Product Code"] = pcode
  output["Revision"] = string.format("%d.%d", rmaj, rmin)
  output["Device State"] = string.format("%s (%d)",
    device_state_lookup(state), state)

  return output
end

local function set_nmap(host, port)
  port.state = "open"
  port.version.name = "EtherNet/IP"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")
end

action = function(host, port)
  -- ListIdentity request: 24-byte encapsulation header, command 0x0063.
  local enip_req_ident = stdnse.fromhex(
    "63000000000000000000000000000000c1debed100000000")

  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)

  try(socket:connect(host, port))
  try(socket:send(enip_req_ident))

  local rcvstatus, response = socket:receive()
  socket:close()
  if not rcvstatus then
    return nil
  end

  local ok, output = pcall(parse_identity, response)
  if not ok or not output then
    return nil
  end

  set_nmap(host, port)
  return output
end
