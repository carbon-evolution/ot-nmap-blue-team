local bin = require "bin"
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
  local req_info = bin.pack("H",
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

  local catch = function()
    socket:close()
  end
  local try = nmap.new_try(catch)

  local constatus, conerr = try(socket:connect(host, port))
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

  local pos, check1 = bin.unpack("C", response, 1)

  if check1 == 0xcc then
    set_nmap(host, port)

    -- Parse null-terminated strings at known offsets
    -- Offset 13: Ladder Logic Runtime string
    if #response >= 13 then
      pos, output["Ladder Logic Runtime"] = bin.unpack("z", response, 13)
    end

    -- Offset 45: PLC Type string
    if #response >= 45 then
      pos, output["PLC Type"] = bin.unpack("z", response, 45)
    end

    -- Offset 78: Project Name
    if #response >= 78 then
      pos, output["Project Name"] = bin.unpack("z", response, 78)
    end

    -- Remaining offset: Boot Project
    if pos and pos <= #response then
      pos, output["Boot Project"] = bin.unpack("z", response, pos)
    end

    -- Remaining offset: Project Source Code status
    if pos and pos <= #response then
      pos, output["Project Source Code"] = bin.unpack("z", response, pos)
    end

    socket:close()
    return output
  end

  -- Unexpected response format
  stdnse.debug1("Unexpected response first byte: 0x%02x (expected 0xcc)", check1)
  socket:close()
  return nil
end
