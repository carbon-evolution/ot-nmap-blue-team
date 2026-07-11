# OT NSE Script Test Results

## GE SRTP (gesrtp-info-improved.nse) — TCP 18245 ✅

```
PORT      STATE  SERVICE
18245/tcp open  ge-srtp
| gesrtp-info-improved:
|   PLC Model: GE PACSystems RX3i
|   Firmware Version: V9.50
|   CPU Type: IC695CPE302
|_  PLC Status: Running
```

## OPC UA Discovery (opcua-discovery-improved.nse) — TCP 4840 ✅

```
PORT      STATE   SERVICE
4840/tcp  open    opcua-tcp
| opcua-discovery-improved:
|   Application Name: OPC UA Mock Server
|   Application URI: urn:OPCUA:MockServer
|   Product URI: urn:OPCUA:MockServer:product
|   Gateway Server URI: urn:OPCUA:MockServer:gateway
|   Discovery Profile: http://opcfoundation.org/UA-Profile/Discovery/Register
|_  Endpoints available: 2
```

## MELSEC-Q (melsecq-info-improved.nse) — TCP 5007 ✅

```
PORT      STATE  SERVICE
5007/tcp  open   melsec-q
| melsecq-info-improved:
|   PLC Type: Q03UDVCPU
|   Series: MELSEC-Q Series
|_  Firmware: 1.20
```

## ProConOS (proconos-info-improved.nse) — TCP 20547 ✅

```
PORT      STATE   SERVICE
20547/tcp open    proconos
| proconos-info-improved:
|   Runtime: ProConOS V3.0.1040 Oct 29 2002
|   PLC Model: ADAM5510KW 1.24 Build 005
|   Project: 510-projec
|_  Project Source: Exist
```

## FF HSE (ff-hse-discover-improved.nse) — TCP 1089 ✅

```
PORT      STATE  SERVICE
1089/tcp  open   ff-hse
| ff-hse-discover-improved:
|   Device Name: ACME-FF-HSE-24601
|   Vendor Name: Fieldbus Foundation
|   Device Tag: FIC-101
|   HSE Version: 1.2
|   Software Revision: 3.0.1
|   Stack: FF_HSE_Stack_v2.1
|_  MAC: B7:...

## Red Lion Crimson (redlion-cr3-info-improved.nse) — TCP 789 ✅

```
PORT    STATE  SERVICE
789/tcp open   redlion-crimson
| redlion-cr3-info-improved:
|   Model: G310C2
|   Firmware: Crimson 3.2
|   Part Number: MNGR-BASE
|_  Vendor: Red Lion Controls
```
