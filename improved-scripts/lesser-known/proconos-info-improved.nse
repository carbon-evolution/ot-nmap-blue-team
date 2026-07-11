local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Improved ProConOS PLC information discovery script.

ProConOS is a high-performance PLC runtime engine designed for both embedded
and PC-based control applications, commonly found on TCP port 20547.

This script sends a query packet to the PLC and parses the response to extract:
- Ladder Logic Runtime version
- PLC Type / hardware model
- Project Name (running project)
- Boot Project (startup project)
- Project Source Code status

Based on the original proconos-info.nse by Stephen Hilt (Digital Bond).
]]

---
-- @usage
-- nmap --script proconos-info-improved -p 20547 <host>
--
-- @output
-- 20547/tcp open  ProConOS
-- | proconos-info-improved:
-- |   Ladder Logic Runtime: ProConOS V3.0.1040 Oct 29 2002
-- |   PLC Type: ADAM5510KW 1.24 Build 005
-- |   Project Name: 510-projec
-- |   Boot Project: 510-projec
-- |_  Project Source Code: Exist
--
-- @xmloutput
-- <elem key="Ladder Logic Runtime">ProConOS V3.0.1040 Oct 29 2002</elem>
-- <elem key="PLC Type">ADAM5510KW 1.24 Build 005</elem>
-- <elem key="Project Name">510-projec</elem>
-- <elem key="Boot Project">510-projec</elem>
-- <elem key="Project Source Code">Exist</elem>

author = "DINA-community (based on Stephen Hilt)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

portrule = shortport.portnumber(20547, "tcp")

local function set_nmap(host, port)
  port.state = "open"
  port.version.name = "ProConOS"
  port.version.product = "ProConOS PLC Runtime"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")
end

action = function(host, port)
  -- ProConOS query packet: 0xcc header + request data
  -- This is the standard probe that requests PLC identification
  local req_info = stdnse.fromhex(
    "cc01000b0000000000000000000000000000" ..
    "0000000000000000000000000000000000000000" ..
    "0000000000000000000000000000000000000000" ..
    "0000000000000000000000000000000000000000" ..
    "0000000000000000000000000000000000000000" ..
    "00ee"
  )

  local output = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local constatus, conerr = socket:connect(host, port)
  if not constatus then
    stdnse.debug1("Error connecting to %s:%d - %s", host.ip, port.number, conerr)
    return nil
  end

  local sendstatus, senderr = socket:send(req_info)
  if not sendstatus then
    stdnse.debug1("Error sending ProConOS request: %s", senderr)
    socket:close()
    return nil
  end

  local rcvstatus, response = socket:receive_bytes(1024)
  if rcvstatus == false then
    stdnse.debug1("Receive error: %s", response)
    socket:close()
    return nil
  end

  if #response < 10 then
    stdnse.debug1("Response too short (%d bytes)", #response)
    socket:close()
    return nil
  end

  local check1 = string.byte(response, 1)

  -- Read a null-terminated string at the given 1-based offset.
  -- string.unpack("z", ...) returns (value, next_pos) and throws if the
  -- remaining bytes contain no null terminator, so guard with pcall.
  local function read_z(off)
    if not off or off > #response then
      return nil, off
    end
    local ok, val, newpos = pcall(string.unpack, "z", response, off)
    if not ok then
      return nil, off
    end
    return val, newpos
  end

  if check1 == 0xcc then
    set_nmap(host, port)

    local pos

    -- Parse null-terminated strings at known offsets. The wire format places
    -- these fields at 0-based byte offsets 13, 45 and 78; Lua string positions
    -- are 1-based, so they live at positions 14, 46 and 79.
    -- Position 14: Ladder Logic Runtime string
    if #response >= 14 then
      output["Ladder Logic Runtime"], pos = read_z(14)
    end

    -- Position 46: PLC Type string
    if #response >= 46 then
      output["PLC Type"], pos = read_z(46)
    end

    -- Position 79: Project Name
    if #response >= 79 then
      output["Project Name"], pos = read_z(79)
    end

    -- Remaining offset: Boot Project
    if pos and pos <= #response then
      output["Boot Project"], pos = read_z(pos)
    end

    -- Remaining offset: Project Source Code status
    if pos and pos <= #response then
      output["Project Source Code"], pos = read_z(pos)
    end

    socket:close()
    return output
  end

  -- Unexpected response format
  stdnse.debug1("Unexpected response first byte: 0x%02x (expected 0xcc)", check1)
  socket:close()
  return nil
end
