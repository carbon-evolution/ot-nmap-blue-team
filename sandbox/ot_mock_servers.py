#!/usr/bin/env python3
"""
OT Protocol Mock Servers for testing improved NSE scripts.

Starts lightweight TCP/UDP servers that respond with realistic
OT device data, so nmap NSE scripts can be tested in a sandbox.

Usage:
    # Start all mocks
    python3 ot_mock_servers.py --all

    # Start a single mock
    python3 ot_mock_servers.py --modbus
    python3 ot_mock_servers.py --hartip
    python3 ot_mock_servers.py --fox
    python3 ot_mock_servers.py --pcworx
    python3 ot_mock_servers.py --profibus
"""

import argparse
import socket
import struct
import threading
import time
import sys
import select

# ============================================================
# MODBUS (TCP 502)
# ============================================================

def modbus_handle_client(conn, addr):
    """Handle a Modbus TCP connection."""
    try:
        data = conn.recv(4096)
        if not data:
            return
        if len(data) < 8:
            return

        tid = data[0:2]
        pid = data[2:4]
        # length = data[4:6]
        uid = data[6]
        func = data[7]

        print(f"  [Modbus] Received from {addr}: func=0x{func:02x}, uid=0x{uid:02x}")

        if func == 0x11:
            # Read Slave ID
            # Build response: MBAP(7) + FC(1) + ByteCount(1) + Data
            slave_data = b"\xFA\xFFPM710PowerMeter"
            byte_count = len(slave_data)
            resp_len = byte_count + 1  # FC + byte count + data
            response = tid + struct.pack(">HH", 0, resp_len + 1)
            response += bytes([uid, 0x11, byte_count]) + slave_data
            conn.send(response)
            print(f"  [Modbus] Sent Slave ID response for uid=0x{uid:02x}")

        elif func == 0x2B and len(data) >= 9 and data[8] == 0x0E:
            # Read Device Identification
            # Response: MBAP + FC + MEI type + ReadDevId response
            mei_type = 0x0E
            # Conformity level, more follows, next object, number of objects
            resp_data = bytes([
                0x2B, 0x0E,  # MEI type + Read Device ID
                0x01,        # Conformity level
                0x00,        # More follows (no)
                0x00,        # Next object
                0x03,        # Number of objects
                # Object 1: Vendor
                0x00, 0x0C,  # Object ID=0, Length=12
            ]) + b"Schneider Elec" + \
            bytes([
                # Object 2: Product code
                0x01, 0x07,  # Object ID=1, Length=7
            ]) + b"PM710  " + \
            bytes([
                # Object 3: Revision
                0x02, 0x07,  # Object ID=2, Length=7
            ]) + b"v03.110"

            resp_len = len(resp_data) + 1  # +1 for UID
            response = tid + struct.pack(">HH", 0, resp_len + 1)
            response += bytes([uid]) + resp_data
            conn.send(response)
            print(f"  [Modbus] Sent Device Identification for uid=0x{uid:02x}")

        else:
            # Exception response: invalid function
            response = tid + struct.pack(">HH", 0, 3)
            response += bytes([uid, func | 0x80, 0x01])
            conn.send(response)

    except Exception as e:
        print(f"  [Modbus] Error: {e}")
    finally:
        conn.close()


def modbus_server(stop_event, port=502):
    """Run Modbus TCP mock server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(0.5)
        print(f"[Modbus] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[Modbus] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=modbus_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
    sock.close()


# ============================================================
# HART-IP (TCP 5094)
# ============================================================

def hartip_handle_client(conn, addr):
    """Handle a HART-IP connection."""
    try:
        # Receive Session Init
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [HART-IP] Received from {addr}: {len(data)} bytes")

        # Session Init response (success)
        # Format: HART-IP header + status = success
        sess_resp = bytes.fromhex("010000000002000D00000000")
        conn.send(sess_resp)
        print(f"  [HART-IP] Sent session initiation response")

        # Receive Command 0 (Read Unique Identifier)
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [HART-IP] Received Command 0")

        # Command 0 response with device info
        # Build a realistic response packet
        # HART-IP Header: version(1) + msg_type(1) + msg_id(1) + status(1) + seq_num(2) + body_length(2)
        # Body: Command 0 response data
        # Expanded Device Type 45075 = GW PL ETH/UNI-BUS
        cmd0_body_parts = []
        cmd0_body_parts.append(bytes([0x00, 0x00]))  # status
        cmd0_body_parts.append(struct.pack(">H", 45075))
        cmd0_body_parts.append(bytes([
            0x05,        # Min preambles master->slave
            0x07,        # HART Protocol Major Revision = 7
            0x01,        # Device Revision = 1
            0x01,        # Software Revision = 1
            0x00,        # Hardware revision
            0x00,        # Flags
        ]))
        # Device ID
        cmd0_body_parts.append(bytes([0xDD, 0x4E, 0xE3]))
        cmd0_body_parts.append(bytes([0x02, 0x00, 0x00, 0x00, 0x00]))
        # Manufacturer ID 176 = Phoenix Contact
        cmd0_body_parts.append(struct.pack(">H", 176))
        # Private Label Distributor 176 = Phoenix Contact
        cmd0_body_parts.append(struct.pack(">H", 176))
        cmd0_body_parts.append(bytes([0x00]))  # Device profile
        cmd0_body = b"".join(cmd0_body_parts)

        cmd0_header = bytes([
            0x01,        # HART-IP version
            0x00,        # Message type: response
            0x00,        # Message ID (echo)
            0x00,        # Status: success
            0x00, 0x00,  # Sequence number
        ]) + struct.pack(">H", len(cmd0_body))

        conn.send(cmd0_header + cmd0_body)
        print(f"  [HART-IP] Sent Command 0 response")

        # Receive Command 20 (Read Long Tag)
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [HART-IP] Received Command 20")

        # Command 20 response with long tag
        long_tag = b"BOILER-FEED-PUMP-03\x00" * 2  # 32 bytes padded
        long_tag = long_tag[:32]
        cmd20_body = bytes([0x00, 0x00]) + long_tag
        cmd20_header = bytes([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]) + struct.pack(">H", len(cmd20_body))
        conn.send(cmd20_header + cmd20_body)
        print(f"  [HART-IP] Sent Command 20 response")

        # Receive Command 84 (Read Sub-Device)
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [HART-IP] Received Command 84")

        # Command 84 response: error (no sub-devices)
        cmd84_body = bytes([
            0x00, 0x00,        # status
            0x02,              # Response code = 2 (no sub-devices)
        ])
        cmd84_header = bytes([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]) + struct.pack(">H", len(cmd84_body))
        conn.send(cmd84_header + cmd84_body)
        print(f"  [HART-IP] Sent Command 84 response")

    except Exception as e:
        print(f"  [HART-IP] Error: {e}")
    finally:
        conn.close()


def hartip_server(stop_event, port=5094):
    """Run HART-IP TCP mock server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(0.5)
        print(f"[HART-IP] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[HART-IP] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=hartip_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
    sock.close()


# ============================================================
# Tridium Niagara FOX (TCP 1911)
# ============================================================

def fox_handle_client(conn, addr):
    """Handle a Fox protocol connection."""
    try:
        data = conn.recv(4096)
        if not data:
            return
        msg = data.decode("utf-8", errors="replace").strip()
        print(f"  [Fox] Received: {msg[:80]}...")

        # Fox hello response — must include { } ;; wrapping
        # The script checks response:find("{") and response:match("^fox a 0")
        response = """fox a 0 1 -1
{
fox.version=s:1.0.1
hostName=s:xpvm-0omdc01xmy
hostAddress=s:192.168.1.1
app.name=s:Workbench
app.version=s:3.7.44
vm.name=s:Java HotSpot(TM) Server VM
vm.version=s:20.4-b02
os.name=s:Windows XP
timeZone=s:America/Chicago
hostId=s:Win-99CB-D49D-5442-07BB
vmUuid=s:8b530bc8-76c5-4139-a2ea-0fabd394d305
brandId=s:vykon
};;
"""
        conn.send(response.encode())
        print(f"  [Fox] Sent Fox version info")

    except Exception as e:
        print(f"  [Fox] Error: {e}")
    finally:
        conn.close()


def fox_server(stop_event, port=1911):
    """Run Fox TCP mock server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(0.5)
        print(f"[Fox] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[Fox] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=fox_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
    sock.close()


# ============================================================
# PCWorx (Phoenix Contact) - TCP 1962
# ============================================================

def pcworx_handle_client(conn, addr):
    """Handle a PCWorx protocol connection."""
    try:
        conn.settimeout(5.0)

        # First exchange: read init_comms
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [PCWorx] Received exchange 1: {data.hex()}")

        # Response 1: Session establishment
        # First byte must be 0x81 (the script checks response:match("^\x81"))
        # Must put a non-zero session ID at byte 18 (1-indexed) so the
        # script's sid = string.sub(response, 18, 18) gets a useful value.
        resp1 = bytes.fromhex(
            "81001a00000000788000134f4b0010"      # up to byte 17 (0-indexed)
            "05"                                   # byte 18 (1-indexed) = SID = 5
            "0300000000000000000000000000000000"
            "0000000000000000000000000000000000"
            "0000000000000000000000000000000000"
        )
        conn.send(resp1)
        print(f"  [PCWorx] Sent session response (SID=5)")
        time.sleep(0.1)

        # Second exchange
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [PCWorx] Received exchange 2: {data.hex()}")

        # Response 2: ACK with sid=5
        resp2 = bytes.fromhex(
            "018500160001000078800005"
            "000000060004000000000000"
        )
        conn.send(resp2)
        print(f"  [PCWorx] Sent ACK")
        time.sleep(0.1)

        # Third exchange: read device info
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [PCWorx] Received exchange 3: {data.hex()}")

        # Build response with strings at offsets the script expects
        resp3 = bytearray(512)
        # Header
        resp3[0] = 0x81
        resp3[1] = 0x06
        stdnse_hdr = bytes.fromhex(
            "000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000"
        )
        resp3[2:32] = stdnse_hdr

        # Offset 31 (0-indexed = 30): PLC Type
        plc_type = b"ILC 330 ETH\x00"
        resp3[30:30+len(plc_type)] = plc_type

        # Offset 67 (0-indexed = 66): Firmware Version
        fw_ver = b"3.95T\x00"
        resp3[66:66+len(fw_ver)] = fw_ver

        # Offset 80 (0-indexed = 79): Firmware Date
        fw_date = b"Mar  2 2012\x00"
        resp3[79:79+len(fw_date)] = fw_date

        # Offset 92 (0-indexed = 91): Firmware Time
        fw_time = b"09:39:02\x00"
        resp3[91:91+len(fw_time)] = fw_time

        # Offset 153 (0-indexed = 152): Model Number
        model_no = b"2737193\x00"
        resp3[152:152+len(model_no)] = model_no

        conn.send(bytes(resp3))
        print(f"  [PCWorx] Sent device info")
        time.sleep(0.1)

    except Exception as e:
        print(f"  [PCWorx] Error: {e}")
    finally:
        conn.close()


def pcworx_server(stop_event, port=1962):
    """Run PCWorx TCP mock server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(0.5)
        print(f"[PCWorx] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[PCWorx] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=pcworx_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
    sock.close()


# ============================================================
# PROFIBUS / PROFINET DCE/RPC EPM (UDP 34964)
# ============================================================

def profinet_server(stop_event, port=34964):
    """Run PROFINET DCE/RPC EPM mock server (UDP)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.settimeout(0.5)
        print(f"[PROFINET] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[PROFINET] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
            print(f"  [PROFINET] Received {len(data)} bytes from {addr}")

            # Build DCE/RPC EPM Lookup response
            # This must match the format the profinet-cm-lookup script expects
            # The script parses: annotationOffset(byte 165), annotationLength(byte 169), annotation(byte 173)

            device_name = b"S7-1500"
            article_no = b"6ES7 672-5DC01-0YA0"
            annotation = device_name + b"  " + article_no + b"      0 V  2  1  7"
            annotation = annotation.ljust(64, b"\x00")[:64]

            # Build DCE/RPC EPM response
            resp = bytearray(300)

            # Byte 1: Version (not used by parser directly)
            resp[0] = 0x05

            # Byte 33 (1-indexed) = index 32: data representation
            # High nibble = 0 -> big endian format_prefix
            resp[32] = 0x00

            # Bytes 165-168 (1-indexed) = index 164-167: annotationOffset
            # Since format_prefix will be ">" (big endian), pack as >I4
            ann_offset = 173  # 1-indexed
            struct.pack_into(">I", resp, 164, ann_offset)

            # Bytes 169-172 (1-indexed) = index 168-171: annotationLength
            ann_length = 64
            struct.pack_into(">i", resp, 168, ann_length)

            # Bytes 173+ (1-indexed) = index 172+: annotation data
            annotation = device_name + b"  " + article_no
            annotation = annotation.ljust(ann_length, b"\x00")[:ann_length]
            resp[172:172+ann_length] = annotation

            # Now recalculate: annotationOffset at byte 165 = 173 (1-indexed)
            # which means annotation starts at byte 173 (1-indexed) = index 172
            # That matches where we put it!

            # Set the packet length
            total_len = 172 + ann_length
            if total_len < 200:
                total_len = 200
            resp = resp[:total_len]

            sock.sendto(bytes(resp), addr)
            print(f"  [PROFINET] Sent DCE/RPC EPM response ({total_len} bytes)")

        except socket.timeout:
            continue
        except Exception as e:
            print(f"  [PROFINET] Error: {e}")
    sock.close()


# ============================================================
# IEC 61850 MMS (TCP 102) - Mock
# ============================================================

def mms_handle_client(conn, addr):
    """
    Handle IEC 61850 MMS connection.
    The nmap script sends: COTP CR, MMS Initiate, MMS Identify, MMS GetNameList, MMS Read.
    We need to respond at each stage with valid BER-encoded TPKT+COTP+MMS messages.
    """
    try:
        # 1. Receive COTP Connection Request (CR_TPDU)
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [MMS] Received COTP CR: {len(data)} bytes")

        # Send COTP Connection Confirm (CC)
        # TPKT(4) + COTP CC(22) = 26 bytes
        cc_tpkt = bytes.fromhex(
            "03000016"      # TPKT: version=3, reserved=0, length=22
            "11d000000001"  # COTP: CR, dst-ref=0, src-ref=1
            "00c1020000"    # TPDU-size=4096
            "c2020001"      # Src TSAP = 1
            "c0010a"        # Dst TSAP = 10
        )
        # Rebuild - the original CC response should be simpler
        # Actually from the script: CR_TPDU = \x03\x00\x00\x16\x11\xe0...
        # CC should be similar structure
        cc = bytes([
            0x03, 0x00, 0x00, 0x16,  # TPKT header, length=22
            0x11, 0xd0,              # COTP DT, dst-ref
            0x00, 0x00,              # src-ref
            0x00, 0x01,              # Reserved
            0x00, 0xc1, 0x02, 0x00, 0x00,  # TPDU-size
            0xc2, 0x02, 0x00, 0x01,        # Src TSAP
            0xc0, 0x01, 0x0a               # Dst TSAP
        ])
        # Fix TPKT length
        cc = bytearray(cc)
        cc[2:4] = struct.pack(">H", len(cc))
        conn.send(bytes(cc))
        print(f"  [MMS] Sent COTP CC")

        # 2. Receive MMS Initiate Request
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [MMS] Received Initiate: {len(data)} bytes")

        # Send MMS Initiate Response
        # This is a complex BER-encoded structure
        # From the original nmap script, initiate response is \x03\x00\x00\xd3...
        # We'll craft a minimal valid response
        mms_init_resp = bytes.fromhex(
            "030000d302f0800dca0506130100160102140200023302000234020001c1b431"
            "81b1a003800101a281a9810400000001820400000001a423300f020101060452"
            "0100013004060251013010020103060528ca2202013004060251016176307402"
            "0101a06f606da107060528ca220203a20706052901876701a30302010ca40302"
            "0100a503020100a606060429018767a70302010ca803020100a903020100be33"
            "283106025101020103a028a826800300fde881010a82010a830105a416800101"
            "810305f100820c03ee1c[REDACTED]ed18"
        )
        # Fix TPKT length
        actual_len = len(mms_init_resp)
        mms_init_resp_list = bytearray(mms_init_resp)
        mms_init_resp_list[2:4] = struct.pack(">H", actual_len)
        conn.send(bytes(mms_init_resp_list))
        print(f"  [MMS] Sent Initiate Response")

        # 3. Receive MMS Identify Request
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [MMS] Received Identify: {len(data)} bytes")

        # Build MMS Identify Response
        # Identify response TPKT + COTP + MMS ConfirmedResponse + identify
        # vendorName: SISCO, modelName: MMS-LITE-80X-001, revision: 6.0000.3
        identify_resp = bytes.fromhex(
            "0300005b02f0801400e712060428012001a742a040301a0602280152010100"
            "0a01010100a20706052801220201be18260428012002a11d611b[REDACTED]"
            "0100a11106092801230101010001010101a00406042801200106"
        )
        actual = len(identify_resp)
        resp = bytearray(identify_resp)
        resp[2:4] = struct.pack(">H", actual)
        conn.send(bytes(resp))
        print(f"  [MMS] Sent Identify Response")

        # 4. Receive MMS GetNameList Request
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [MMS] Received GetNameList: {len(data)} bytes")

        # GetNameList Response - list VMD names
        # We need to return LPHD as one of the names so the script can proceed
        name_list_resp = bytes.fromhex(
            "0300005d02f0801400e612060428012001a147a045a043020101a03ea03ca0"
            "1a06042801200101a011a00f0c0d4c5048443130393842323036a01e060428"
            "[REDACTED]a012a0100c0e4c4c4e303130393842323036"
        )
        actual = len(name_list_resp)
        resp = bytearray(name_list_resp)
        resp[2:4] = struct.pack(">H", actual)
        conn.send(bytes(resp))
        print(f"  [MMS] Sent GetNameList Response (LPHD in list)")

        # 5. Receive MMS Read Request for attributes
        data = conn.recv(4096)
        if not data:
            return
        print(f"  [MMS] Received Read: {len(data)} bytes")

        # Read Response with device data
        read_resp = bytes.fromhex(
            "[REDACTED]f0801400e612060428012001a17ba179a077020101a072a070a2"
            "6e6104300e800a4869676820456e64204d65746572810a2020202020202020"
            "206112300f800d5363686e656964657220456c65637472691b30198017534f"
            "4654574152452056455253494f4e2030312e30302e3030a40a300880065530"
            "2d3030310000053000800202a12030008006532e30303201"
        )
        actual = len(read_resp)
        resp = bytearray(read_resp)
        resp[2:4] = struct.pack(">H", actual)
        conn.send(bytes(resp))
        print(f"  [MMS] Sent Read Response with device attributes")

        # 6. More GetNameList/Read requests may follow for individual attributes
        # Drain any remaining data
        conn.settimeout(0.5)
        while True:
            try:
                more = conn.recv(4096)
                if not more:
                    break
                print(f"  [MMS] Received additional request: {len(more)} bytes")
                # Send a generic success response
                time.sleep(0.1)
            except socket.timeout:
                break

    except Exception as e:
        print(f"  [MMS] Error: {e}")
    finally:
        conn.close()


def mms_server(stop_event, port=102):
    """Run IEC 61850 MMS TCP mock server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(0.5)
        print(f"[MMS] Mock server listening on 127.0.0.1:{port}")
    except OSError as e:
        print(f"[MMS] FAILED to bind port {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=mms_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
    sock.close()


# ============================================================
# MAIN - Argument parsing and server orchestration
# ============================================================

SERVERS = {
    "modbus": (modbus_server, 502),
    "hartip": (hartip_server, 5094),
    "fox": (fox_server, 1911),
    "pcworx": (pcworx_server, 1962),
    "profinet": (profinet_server, 34964),
    "mms": (mms_server, 102),
}

def main():
    parser = argparse.ArgumentParser(description="OT Protocol Mock Servers")
    parser.add_argument("--all", action="store_true", help="Start all mock servers")
    parser.add_argument("--modbus", action="store_true", help="Start Modbus mock")
    parser.add_argument("--hartip", action="store_true", help="Start HART-IP mock")
    parser.add_argument("--fox", action="store_true", help="Start Fox mock")
    parser.add_argument("--pcworx", action="store_true", help="Start PCWorx mock")
    parser.add_argument("--profinet", action="store_true", help="Start PROFINET mock")
    parser.add_argument("--mms", action="store_true", help="Start IEC 61850 MMS mock")
    parser.add_argument("--list", action="store_true", help="List available servers and ports")

    args = parser.parse_args()

    if args.list:
        print("Available mock servers:")
        for name, (_, port) in SERVERS.items():
            print(f"  {name:12s} -> TCP/UDP {port}")
        return

    to_start = []
    if args.all:
        to_start = list(SERVERS.keys())
    else:
        for name in SERVERS:
            if getattr(args, name.replace("-", "_"), False):
                to_start.append(name)

    if not to_start:
        print("No servers specified. Use --all or pick one: --modbus, --hartip, --fox, --pcworx, --profinet, --mms")
        return

    stop_event = threading.Event()
    threads = []

    print(f"Starting {len(to_start)} mock server(s)...")
    print(f"{'='*60}")
    print(f"NOTE: You may need to run with sudo for ports below 1024")
    print(f"      (ports 102, 502 need root)")
    print(f"{'='*60}")
    print()

    for name in to_start:
        func, port = SERVERS[name]
        t = threading.Thread(target=func, args=(stop_event, port), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)

    print()
    print("All mock servers running. Press Ctrl+C to stop.")
    print()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping all servers...")
        stop_event.set()
        for t in threads:
            t.join(timeout=2)
        print("All servers stopped.")


if __name__ == "__main__":
    main()
