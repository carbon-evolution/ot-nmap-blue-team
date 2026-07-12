local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local nsedebug = require "nsedebug"

description = [[
This NSE script is used to send a HART-IP packet to a HART device that has TCP 5094 open.
The script will establish Session with HART device, then Read Unique Identifier and
Read Long Tag packets are sent to parse the required HART device information.
Read Sub-Device Identity Summary packet with Sub-Device index 00 01 is sent
to request information on Sub-Device, if any available. If the response code
differs from 0 (success), the error code is passed as Sub-Device Information.
Otherwise, the required Sub-Device information is parsed from response packet.

Device/Sub-Device Information that is parsed includes Long Tag (user assigned device name),
Expanded Device Type, Manufacturer ID, Device ID, Device Revision, Software Revision,
HART Protocol Major Revision and Private Label Distributor.

This script was written based of HART Specifications available at
https://www.fieldcommgroup.org/hart-specifications.
]]
---
-- @usage
-- nmap <host> -p 5094 --script hartip-info
--
-- @args hartip-info.timeout  Sets the socket timeout in milliseconds (default: uses --host-timeout or 5000ms)
--
-- @output
--PORT     STATE SERVICE
--5094/tcp open  hart-ip
--| hartip-info:
--|   Device Information:
--|     IP Address: 172.16.10.90
--|     Long Tag: ????????????????????????????????
--|     Expanded Device Type: GW PL ETH/UNI-BUS
--|     Manufacturer ID: Phoenix Contact
--|     Device ID: dd4ee3
--|     Device Revision: 1
--|     Software Revision: 1
--|     HART Protocol Major Revision: 7
--|     Private Label Distributor: Phoenix Contact
--|   Sub-Device Information:
--|_    Error Code: 2
-- @xmloutput
--<elem key="IP Address">172.16.10.90</elem>
--<elem>Long Tag: ????????????????????????????????</elem>
--<elem>Expanded Device Type: GW PL ETH/UNI-BUS</elem>
--<elem>Manufacturer ID: Phoenix Contact</elem>
--<elem>Device ID: dd4ee3</elem>
--<elem>Device Revision: 1</elem>
--<elem>Software Revision: 1</elem>
--<elem>HART Protocol Major Revision: 7</elem>
--<elem>Private Label Distributor: Phoenix Contact</elem>

author = "DINA-community"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

-- Function to define the portrule as per nmap standards
portrule = shortport.port_or_service(5094, "hart-ip", "tcp")

--  Table to look up the Product Name based on number-represented Expanded Device Type Code
--    Returns "Unknown Device Type" if Expanded Device Type not recognized
--  Table data from Common Tables Specification, HCF_SPEC-183, FCG TS20183, Revision 26.0
--  5.1 Table 1. Expanded Device Type Codes
-- key is number-represented Device Type Code parsed out of the HART-IP packet
local productName = {
  [520] = "3051S Pressure Transmitter",
  [1450] = "Rosemount 3144P Temperature Transmitter",
  [2490] = "Micropilot FMR60",
  [3005] = "Promag 53 Electromagnetic Flowmeter",
  [4440] = "E+H TMT162 Temperature Transmitter",
  [4560] = "iTEMP TMT72",
  [5500] = "SITRANS P300 Pressure Transmitter",
  [7500] = "Yokogawa EJA-E Series Pressure Transmitter",
  [10000] = "VEGAPULS 69 Radar Sensor",
  [12750] = "SMAR LD302 Pressure Transmitter",
  [20000] = "ABB 266 Pressure Transmitter",
  [30000] = "Honeywell ST 800 Pressure Transmitter",
  [45075] = "GW PL ETH/UNI-BUS",
}

--return device type information
local function expdevtyp_lookup(expdevtypnum)
  return productName[expdevtypnum] or "Unknown Device Type"
end

--  Table to look up the Manufacturer Name based on Manufacturer ID
--    Returns "Unknown Manufacturer" if Manufacturer ID not recognized
--  Table data from Common Tables Specification, HCF_SPEC-183, FCG TS20183, Revision 26.0
--  5.8 Table 8. Manufacturer Identification Codes
-- key is number-represented Manufacturer ID parsed out of the HART-IP packet
local manufacturerName = {
  [17] = "Yokogawa Electric Corporation",
  [38] = "Siemens AG",
  [64] = "Krohne",
  [69] = "Emerson Process Management/Rosemount",
  [70] = "ABB Automation Products GmbH",
  [73] = "Magnetrol International",
  [76] = "Endress+Hauser",
  [77] = "MTS Sensors",
  [88] = "Vega Grieshaber KG",
  [94] = "Honeywell Industrial Automation and Control",
  [109] = "Fisher Controls International LLC",
  [127] = "SMAR Equipamentos Industriais Ltda",
  [132] = "Metso Automation",
  [152] = "E+E Elektronik Ges.m.b.H.",
  [153] = "Druck Limited",
  [158] = "Rittmeyer AG",
  [176] = "Phoenix Contact",
  [177] = "M-System Co., Ltd.",
  [180] = "Sensotec",
  [198] = "Moore Industries-International Inc.",
  [204] = "K-TEK Corp.",
  [220] = "Burkert Contromatic Corp.",
  [223] = "Yamatake Corporation",
  [227] = "Flowserve Corporation",
  [230] = "Samson AG",
  [234] = "SOR Inc.",
  [245] = "Knebel Elektronik A/S",
  [250] = "Applied System Technologies, Inc.",
  [252] = "Flow Technology, Inc.",
  [255] = "Pepperl+Fuchs GmbH",
  [259] = "Wika Alexander Wiegand GmbH & Co. KG",
  [263] = "Ifm Electronic GmbH",
  [267] = "Micro Motion, Inc.",
  [268] = "Knick Elektronische Messgeraete GmbH & Co. KG",
  [277] = "Yokogawa Process Analyzers (Europe) B.V.",
  [288] = "Deltalab S.L.",
  [295] = "Oval Corporation",
  [305] = "Nivus GmbH",
  [307] = "Azbil Corporation (formerly Yamatake)",
  [310] = "Beijing Sincerity Automatic Equipment Co., Ltd.",
}

--return manufacturer information
local function manid_lookup(manidnum)
  return manufacturerName[manidnum] or "Unknown Manufacturer"
end

--  Action Function that is used to run the NSE. This function will send
--  the initial query to the host and port that were passed in via nmap.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  -- create local vars for socket handling
  local socket, try, catch, status, err

  -- create new socket
  socket = nmap.new_socket()

  -- resolve script arg timeout (in ms), fall back to stdnse.get_timeout which handles --host-timeout
  local timeout = stdnse.get_script_args("hartip-info.timeout")
  if timeout then
    timeout = tonumber(timeout)
  end
  if not timeout then
    timeout = stdnse.get_timeout(host)
  end
  socket:set_timeout(timeout)

  -- define the catch of the try statement
  catch = function()
    socket:close()
  end

  -- create new try
  try = nmap.new_try(catch)

  -- connect to port on host
  try(socket:connect(host, port))
  stdnse.debug(1, "#- socket connection established.")

  -- send the initiate session packet
  -- receive response
  -- abort if no response
  local sessInitQuery = stdnse.fromhex("010000000001000D0100004E20")
  local send_ok, send_err = socket:send(sessInitQuery)
  if not send_ok then
    stdnse.debug(1, "#- session initiation send - FAIL: %s", send_err)
    socket:close()
    return nil
  end

  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    stdnse.debug(1, "#- session initiation with HART device - FAIL.")
    socket:close()
    return nil
  end
  stdnse.debug(1, "#- session initiation with HART device - SUCCESS.")

  -- Command 0 BEGIN  --

  -- send the Command 0 Read Unique Idenifier packet
  -- receive response, abort if no response
  local cmd0Req = stdnse.fromhex("010003000002000D[REDACTED]")
  try(socket:send(cmd0Req))

  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    stdnse.debug(1, "#- command 0 Read Unique Identifier request - FAIL.")
    socket:close()
    return nil
  end
  stdnse.debug(1, "#- command 0 Read Unique Identifier request - SUCCESS.")

  -- get hart-ip version, message type, message id, response status and sequence number
  -- abort if no response
  local _, _, _, res_status, _ = string.unpack(">BBBBI2", response, 1)
  if (res_status ~= 0) then
    stdnse.debug(1, "#- command 0 Read Unique Identifier response - FAIL.")
    socket:close()
    return nil
  end
  stdnse.debug(1, "#- command 0 Read Unique Identifier response - SUCCESS.")

  --- unpack device information from Command 0

  -- create table for output and device information
  local output = stdnse.output_table()
  local deviceInfo = stdnse.output_table()

  deviceInfo["IP Address"] = host.ip

  -- get expanded device type
  -- lookup device type number
  local expDevTypeNum, Index = string.unpack(">I2", response, 16)
  local expandedDeviceType = expdevtyp_lookup(expDevTypeNum)
  deviceInfo["Expanded Device Type"] = expandedDeviceType

  -- get master-to-slave minimum preambles
  local minPreMasterToSlave, Index = string.unpack("B", response, Index)

  -- get HART protocol major revision number
  local hartProtocolMajorRevision, Index = string.unpack("B", response, Index)
  deviceInfo["HART Protocol Major Revision"] = hartProtocolMajorRevision

  -- get device revision number
  local deviceRevision, Index = string.unpack("B",response, Index)
  deviceInfo["Device Revision"] = deviceRevision

  -- get software revision number
  local softwareRevision, Index = string.unpack("B",response, Index)
  deviceInfo["Software Revision"] = softwareRevision

  -- get hardware revision level with physical signaling code and flags
  local _,flags, Index = string.unpack("BB", response, Index)

  -- get device ID in hex format
  local deviceID, Index = string.unpack("c3", response, Index)
  deviceID = stdnse.tohex(deviceID)
  deviceInfo["Device ID"] = deviceID

  -- get slave-to-master minimum preambles, last device variable code,
  -- configuration change counter, extended field device status
  _,_,_,_, Index = string.unpack("BBI2B", response, Index)

  -- get manufacturer ID
  -- lookup manufacturer id
  local manufacturerID, Index = string.unpack(">I2", response, Index)
  manufacturerID = manid_lookup(manufacturerID)
  deviceInfo["Manufacturer ID"] = manufacturerID

  -- get private label distributor
  -- lookup manufacturer id
  local privateLabelDistributor, Index = string.unpack(">I2", response, Index)
  privateLabelDistributor = manid_lookup(privateLabelDistributor)
  deviceInfo["Private Label Distributor"] = privateLabelDistributor

  -- get device profile
  local deviceProfile = string.unpack("B", response, Index)

  -- Command 0 END    --

  -- Command 20 BEGIN --

  local longAddress = stdnse.tohex(expDevTypeNum) .. deviceID

  -- send the Command 20 Read Long Tag packet
  -- receive response, abort if no response
  local cmd20Req = stdnse.fromhex("010003000003001182" .. longAddress .. "140045")
  try(socket:send(cmd20Req))

  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    stdnse.debug(1, "#- command 20 Read Long Tag request - FAIL.")
    socket:close()
    output['Device Information'] = deviceInfo
    return output
  end
  stdnse.debug(1, "#- command 20 Read Long Tag request - SUCCESS.")

  -- get hart-ip version, message type, message id, response status and sequence number
  -- abort if no response
  local _, _, _, res_status, _ = string.unpack(">BBBBI2", response, 1)
  if (res_status ~= 0) then
    stdnse.debug(1, "#- command 20 Read Long Tag response - FAIL.")
    socket:close()
    output['Device Information'] = deviceInfo
    return output
  end
  stdnse.debug(1, "#- command 20 Read Long Tag response - SUCCESS.")

  --- unpack device information from Command 20

  -- get device long tag
  local longTag = string.unpack("c32", response, 19)
  stdnse.debug(1, "#--- Long Tag = " .. longTag)
  deviceInfo["Long Tag"] = longTag

  -- Command 20 END   --

  --- Command 84 BEGIN

  -- send the Command 84 Read Sub-Device Identity Summary packet for Sub-Device at index 0001
  -- receive response, abort if no response
  local subDeviceIndex = "0001"
  local cmd84Req = stdnse.fromhex("010003000004001382" .. longAddress .. "5402" .. subDeviceIndex .. "06")
  try(socket:send(cmd84Req))

  local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    stdnse.debug(1, "#- command 84 Read Sub-Device Identity Summary request - FAIL.")
    socket:close()
    output['Device Information'] = deviceInfo
    return output
  end
  stdnse.debug(1, "#- command 84 Read Sub-Device Identity Summary request - SUCCESS.")

  -- get hart-ip version, message type, message id, response status and sequence number
  -- abort if no response
  local _, _, _, res_status, _ = string.unpack(">BBBBI2", response, 1)
  if (res_status ~= 0) then
    stdnse.debug(1, "#- command 84 Read Sub-Device Identity Summary response - FAIL.")
    socket:close()
    output['Device Information'] = deviceInfo
    return output
  end
  stdnse.debug(1, "#- command 84 Read Sub-Device Identity Summary response - SUCCESS.")

  --- get sub-device information from Command 84
  local subDeviceInfo = stdnse.output_table()

  -- get response code
  -- abort if no success
  local responseCode = string.unpack("B", response, 17)
  if (responseCode ~= 0) then
    stdnse.debug(1, "#- command 84 Read Sub-Device Identity Summary response code %d - FAIL.", responseCode)
    subDeviceInfo["Error Code"] = responseCode
    socket:close()
    output['Device Information'] = deviceInfo
    output['Sub-Device Information'] = subDeviceInfo
    return output
  end

  --- Command 84 END

  -- close socket
  socket:close()
  stdnse.debug(1, "#- socket connection terminated.")

  -- populate output table
  output['Device Information'] = deviceInfo
  output['Sub-Device Information'] = subDeviceInfo

  -- return output table to Nmap
  return output
end
