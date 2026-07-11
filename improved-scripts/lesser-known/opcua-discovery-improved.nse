local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects OPC UA (Open Platform Communications Unified Architecture) servers on TCP
port 4840 by performing the initial handshake sequence: sending a HEL (Hello)
message and verifying the server responds with an ACK (Acknowledge) message.

OPC UA is the successor to OPC Classic (OPC DA/OPC HDA/OPC A&E) and is widely
used in industrial automation, SCADA systems, and Industry 4.0 environments.
Unlike the older OPC Classic which relies on DCOM (RPC), OPC UA uses a binary
or SOAP/HTTP-based protocol on TCP 4840.

The script performs a minimal OPC UA Binary handshake:
1. Connects to TCP 4840
2. Sends a HEL message with default buffer parameters
3. Reads and validates the ACK response
4. Extracts protocol version, buffer sizes, and max message/chunk counts

Reference:
  - OPC UA Part 6: Mappings - https://opcfoundation.org/UA/Part6/
  - OPC 10000-6: Unified Architecture, Part 6: Mappings
]]

---
-- @usage
-- nmap -p 4840 --script opcua-discovery <target>
-- nmap -sV --script opcua-discovery <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4840/tcp open  opcua
-- | opcua-discovery:
-- |   Protocol version: 0
-- |   Receive buffer size: 65535
-- |   Send buffer size: 65535
-- |   Max message length: 65536
-- |   Max chunk count: 0
-- |_  Server: OPC UA Server detected
--
-- @xmloutput
-- <elem key="protocol_version">0</elem>
-- <elem key="receive_buffer_size">65535</elem>
-- <elem key="send_buffer_size">65535</elem>
-- <elem key="max_message_length">65536</elem>
-- <elem key="max_chunk_count">0</elem>
-- <elem key="status">OPC UA Server detected</elem>
--

author = "OT-NMAP-Blue-Team"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

portrule = shortport.portnumber(4840, "tcp", {"open", "open|filtered"})

-- Build the OPC UA Binary HEL (Hello) message.
-- All multi-byte fields are little-endian (uint32).
-- Total message size is 32 bytes with no endpoint URL.
--
-- Structure:
--   byte  0-2: 'HEL'           ASCII message type tag
--   byte    3: 0x00            Reserved / final byte of message type
--   byte  4-7: message_length  Total message size in bytes (uint32 LE)
--   byte  8-11: protocol_version Protocol version (uint32 LE) = 0
--   byte 12-15: receive_buffer_size (uint32 LE) = 65535
--   byte 16-19: send_buffer_size (uint32 LE) = 65535
--   byte 20-23: max_message_length (uint32 LE) = 65536
--   byte 24-27: max_chunk_count (uint32 LE) = 0
--   byte 28-31: endpoint_url_length (uint32 LE) = 0
--
-- @return string containing the raw 32-byte HEL message
local function build_hello_message()
  -- "HEL" + reserved 0x00, then 7 little-endian uint32 fields (28 bytes),
  -- for a total message length of 32 bytes.
  local hel = "HEL\0"
      .. string.pack("<I4", 32)         -- message length
      .. string.pack("<I4", 0)          -- protocol version
      .. string.pack("<I4", 65535)      -- receive buffer size
      .. string.pack("<I4", 65535)      -- send buffer size
      .. string.pack("<I4", 65536)      -- max message length
      .. string.pack("<I4", 0)          -- max chunk count
      .. string.pack("<I4", 0)          -- endpoint URL length (none)
  return hel
end

-- Parse the OPC UA Binary ACK (Acknowledge) response.
-- Returns a table with parsed fields on success, or nil + error message.
--
-- ACK structure:
--   byte  0-2: 'ACK'           ASCII message type tag
--   byte    3: 0x00            Reserved / final byte of message type
--   byte  4-7: message_length  Total message size in bytes (uint32 LE)
--   byte  8-11: protocol_version (uint32 LE)
--   byte 12-15: receive_buffer_size (uint32 LE)
--   byte 16-19: send_buffer_size (uint32 LE)
--   byte 20-23: max_message_length (uint32 LE)
--   byte 24-27: max_chunk_count (uint32 LE)
--
-- @param data string raw response data from server
-- @return table|nil parsed ACK fields, or nil + error message
local function parse_ack_response(data)
  if #data < 28 then
    return nil, string.format("Response too short for ACK: %d bytes (expected >= 28)", #data)
  end

  local ack_tag = data:sub(1, 3)
  if ack_tag ~= "ACK" then
    return nil, string.format("Not an ACK response: got '%.3s' (0x%s)", ack_tag, stdnse.tohex(data:sub(1, 3)))
  end

  -- Six little-endian uint32 fields starting just past "ACK\0" (offset 5).
  -- string.unpack returns the values followed by the next position.
  local message_length, protocol_version, recv_buffer_size,
        send_buffer_size, max_message_length, max_chunk_count =
    string.unpack("<I4I4I4I4I4I4", data, 5)

  return {
    message_length    = message_length,
    protocol_version  = protocol_version,
    recv_buffer_size  = recv_buffer_size,
    send_buffer_size  = send_buffer_size,
    max_message_length = max_message_length,
    max_chunk_count   = max_chunk_count,
  }
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)  -- 5 second timeout

  -- Attempt connection
  local status, err = socket:connect(host, port)
  if not status then
    return stdnse.format_output(false, "Connection failed: %s", err)
  end

  -- Build and send HEL message
  local hello = build_hello_message()
  stdnse.debug2("Sending OPC UA HEL message (%d bytes)", #hello)
  stdnse.debug3("HEL hex: %s", stdnse.tohex(hello))

  status, err = socket:send(hello)
  if not status then
    socket:close()
    return stdnse.format_output(false, "Failed to send HEL: %s", err)
  end

  -- Receive ACK response. The ACK is a small fixed-size message (28 bytes),
  -- so a single receive is sufficient; receive() returns (status, data|err).
  local response
  status, response = socket:receive()
  socket:close()

  if not status then
    return stdnse.format_output(false, "Failed to receive ACK: %s", response)
  end

  if #response == 0 then
    return stdnse.format_output(false, "Empty response received (server closed connection)")
  end

  stdnse.debug2("Received %d bytes from server", #response)
  stdnse.debug3("Response hex: %s", stdnse.tohex(response))

  -- Parse the ACK response
  local ack, err_msg = parse_ack_response(response)
  if not ack then
    -- Check if it's a recognizable non-OPC UA response
    local resp_tag = response:sub(1, 3):match("^%w%w%w$") and response:sub(1, 3) or
                     string.format("0x%s", stdnse.tohex(response:sub(1, 4)))
    return stdnse.format_output(false, "Not an OPC UA server: %s (received: %s)", err_msg, resp_tag)
  end

  -- Set version information for nmap service detection
  port.version.name = "opcua"
  port.version.product = "OPC UA Server"
  port.version.protocol = "tcp"

  if ack.protocol_version then
    port.version.version = tostring(ack.protocol_version)
  end

  -- Extract additional version info from buffer sizes if they differ from defaults
  local extrainfo_parts = {}
  if ack.recv_buffer_size ~= 65535 then
    table.insert(extrainfo_parts, string.format("recv_buf=%d", ack.recv_buffer_size))
  end
  if ack.send_buffer_size ~= 65535 then
    table.insert(extrainfo_parts, string.format("send_buf=%d", ack.send_buffer_size))
  end
  if #extrainfo_parts > 0 then
    port.version.extrainfo = table.concat(extrainfo_parts, "; ")
  end

  nmap.set_port_version(host, port)

  -- Build structured output
  local output = stdnse.output_table()

  output["protocol_version"]    = ack.protocol_version or "N/A"
  output["receive_buffer_size"] = ack.recv_buffer_size or "N/A"
  output["send_buffer_size"]    = ack.send_buffer_size or "N/A"
  output["max_message_length"]  = ack.max_message_length or "N/A"
  output["max_chunk_count"]     = ack.max_chunk_count or "N/A"
  output["status"]              = "OPC UA Server detected"

  return output
end
