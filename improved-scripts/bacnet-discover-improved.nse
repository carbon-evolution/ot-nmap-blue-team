local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers a BACnet/IP device (UDP 47808) and reads the Device object's
standard identity properties via Confirmed-Request ReadProperty: Vendor
(name + identifier), Model Name, Firmware Revision, Application Software
Version, Object Name, Location, and Description.

This is a read-only (T1-safe) discovery probe: it issues ReadProperty for
the Device object's identity properties only. It performs no writes and no
broader object enumeration.

Improved over the upstream Redpoint BACnet-discover-enumerate.nse: the
character-string decoder is ported from the removed Nmap `bin` API to
`string.unpack`/`string.byte`, and the parse is guarded so a malformed or
truncated response degrades gracefully instead of raising.
]]

---
-- @usage nmap --script bacnet-discover-improved -sU -p 47808 <host>
--
-- @output
-- 47808/udp open  bacnet
-- | bacnet-discover-improved:
-- |   Vendor: Automated Logic Corporation (24)
-- |   Model Name: LGR1000
-- |   Firmware: 6.02
-- |   Application Software: OS-6.02b
-- |   Object Name: ALC-VAV-101
-- |   Location: Bldg-A/Fl-3
-- |_  Description: VAV Controller

author = "OT Nmap Blue Team (improved from Redpoint by Digital Bond)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(47808, "bacnet", "udp")

-- BACnet property identifiers (ASHRAE 135).
local PROP_OBJECT_NAME  = 0x4D  -- 77
local PROP_VENDOR_NAME  = 0x79  -- 121
local PROP_VENDOR_ID    = 0x78  -- 120 (unsigned)
local PROP_MODEL_NAME   = 0x46  -- 70
local PROP_FIRMWARE_REV = 0x2C  -- 44
local PROP_APP_SOFTWARE = 0x0C  -- 12
local PROP_LOCATION     = 0x3A  -- 58
local PROP_DESCRIPTION  = 0x1C  -- 28

--- Build a Confirmed-Request ReadProperty for the Device object (any-instance).
-- @param prop integer property identifier
-- @return string raw request bytes
local function read_property_request(prop)
  return stdnse.fromhex(string.format(
    "810a001101040005010c0c023fffff19%02x", prop))
end

--- Decode the character-string value out of a ReadProperty ComplexACK.
-- Mirrors the upstream field-size logic (the string tag sits at byte 18):
-- byte 18 is the application tag/length; low nibble < 5 means the length is
-- inline, otherwise the real length is in byte 19. The value is preceded by a
-- one-byte character set (0 = UTF-8), which we skip.
-- @param resp string raw response bytes
-- @return string|nil the decoded value, or nil on a malformed packet
local function decode_string_value(resp)
  if not resp or #resp < 20 then return nil end
  local b18 = resp:byte(18)
  local length, offset
  if b18 % 0x10 < 5 then
    length = (b18 % 0x10) - 1
    offset = 19
  else
    length = resp:byte(19) - 1
    offset = 20
  end
  if length < 0 or offset + length > #resp then return nil end
  -- offset points at the character-set byte; the string follows it.
  return resp:sub(offset + 1, offset + length)
end

--- Decode an unsigned integer value (application tag 2) from a ReadProperty ACK.
-- The tag byte sits at byte 18; its low nibble is the length in bytes.
-- @param resp string raw response bytes
-- @return integer|nil the decoded number, or nil on a malformed packet
local function decode_unsigned_value(resp)
  if not resp or #resp < 19 then return nil end
  local tag = resp:byte(18)
  local length = tag % 0x10
  if length < 1 or 18 + length > #resp then return nil end
  local value = 0
  for i = 19, 18 + length do
    value = value * 256 + resp:byte(i)
  end
  return value
end

--- Validate a BACnet reply: BVLC type 0x81 and not an Error PDU (byte 7 0x50).
local function is_valid_ack(resp)
  return resp and #resp >= 7 and resp:byte(1) == 0x81 and resp:byte(7) ~= 0x50
end

--- Send one ReadProperty and return the decoded value (string or number).
local function query(host, port, prop, decoder)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(3000)
  local ok = socket:connect(host, port, "udp")
  if not ok then socket:close(); return nil end
  local sent = socket:send(read_property_request(prop))
  if not sent then socket:close(); return nil end
  local status, resp = socket:receive()
  socket:close()
  if not status or not is_valid_ack(resp) then return nil end
  local ok2, value = pcall(decoder, resp)
  if not ok2 then return nil end
  return value
end

action = function(host, port)
  local out = stdnse.output_table()

  local vendor_name = query(host, port, PROP_VENDOR_NAME, decode_string_value)
  local vendor_id   = query(host, port, PROP_VENDOR_ID, decode_unsigned_value)
  if vendor_name and vendor_id then
    out["Vendor"] = string.format("%s (%d)", vendor_name, vendor_id)
  elseif vendor_name then
    out["Vendor"] = vendor_name
  end

  local fields = {
    {"Model Name",           PROP_MODEL_NAME},
    {"Firmware",             PROP_FIRMWARE_REV},
    {"Application Software", PROP_APP_SOFTWARE},
    {"Object Name",          PROP_OBJECT_NAME},
    {"Location",             PROP_LOCATION},
    {"Description",          PROP_DESCRIPTION},
  }
  for _, f in ipairs(fields) do
    local v = query(host, port, f[2], decode_string_value)
    if v then out[f[1]] = v end
  end

  if #out == 0 then return nil end

  -- Mark the port so nmap reports it open rather than open|filtered.
  nmap.set_port_state(host, port, "open")
  return out
end
