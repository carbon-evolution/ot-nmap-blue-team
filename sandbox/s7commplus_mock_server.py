#!/usr/bin/env python3
"""
S7comm / S7comm-plus (S7-1200/1500) Identity Honeypot-Grade Emulator.

Listens on TCP 102 (ISO-TSAP) and emulates a Siemens S7 PLC's identification
exchange: COTP connection setup, S7comm setup-communication, then SZL reads
of SZL-ID 0x0011 (module identification) and 0x001C (component
identification). Returns per-profile identity — Module (order/MLFB number),
firmware Version, Module Type, Serial Number, and System Name — placed at the
exact byte offsets the discovery script parses.

Port 102 is privileged (<1024); run as root. Port is configurable via --port
so the test harness can bind it without colliding with the IEC 61850 MMS mock
(also port 102) in ot_mock_servers.py.

Usage:
    sudo python3 s7commplus_mock_server.py                      # s7_1200 @ 102
    python3 s7commplus_mock_server.py --profile s7_1500 --port 10102
    python3 s7commplus_mock_server.py --self-test

Handshake (each over one TCP connection):
    1. COTP Connection Request (req byte 6 = 0xE0)  -> Connection Confirm (0xD0)
    2. S7comm setup-communication (req byte 9 ROSCTR = 0x01) -> setup ack
    3. SZL read, SZL-ID at req byte 31:
         0x11 -> module-identification response (Module @44, Version @123)
         0x1C -> component-identification response (System Name @40,
                 Module Type @74, Serial Number @176)
    (The upstream Redpoint parser reads these fixed 1-based offsets; the mock
    writes strings there in an otherwise zero-filled buffer.)
"""

import argparse
import logging
import signal
import socket
import sys
import threading

S7_DEFAULT_PORT = 102
DEFAULT_PROFILE = "s7_1200"

PROFILES = {
    "s7_1200": {
        "system_name": "PLC_1200",
        "module_type": "CPU 1212C DC/DC/DC",
        "module": "6ES7 212-1AE40-0XB0",
        "serial": "S C-K1U450132020",
        "version": (4, 4, 0),
    },
    "s7_1500": {
        "system_name": "PLC_1500",
        "module_type": "CPU 1515-2 PN",
        "module": "6ES7 515-2AM01-0AB0",
        "serial": "S C-L2X920551024",
        "version": (2, 9, 2),
    },
}

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [DETECT] %(message)s",
    datefmt="%H:%M:%S",
)
_detection_log = logging.getLogger("s7commplus")


# ======================================================================
# Packet building
# ======================================================================
def _place(buf: bytearray, pos1: int, data: bytes):
    """Write bytes at a 1-based offset into a zero-filled buffer."""
    idx = pos1 - 1
    buf[idx:idx + len(data)] = data


def _tpkt_cotp_header(buf: bytearray):
    """Fill the TPKT + COTP-DT header and the total length field."""
    total = len(buf)
    buf[0] = 0x03            # TPKT version
    buf[1] = 0x00
    buf[2] = (total >> 8) & 0xFF
    buf[3] = total & 0xFF
    buf[4] = 0x02            # COTP length
    buf[5] = 0xF0            # COTP PDU type: DT Data
    buf[6] = 0x80            # COTP TPDU number / EOT


def build_connection_confirm() -> bytes:
    """COTP Connection Confirm (PDU type 0xD0 at byte 6)."""
    return bytes([
        0x03, 0x00, 0x00, 0x16,                    # TPKT, len 22
        0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00,  # COTP CC (0xD0)
        0xC0, 0x01, 0x0A,                          # tpdu-size
        0xC1, 0x02, 0x01, 0x00,                    # src-tsap
        0xC2, 0x02, 0x01, 0x02,                    # dst-tsap
    ])


def build_setup_ack() -> bytes:
    """S7comm setup-communication Ack_Data (protocol id 0x32 at byte 8)."""
    buf = bytearray(27)
    _tpkt_cotp_header(buf)
    _place(buf, 8, bytes([0x32, 0x03]))            # S7 proto id, ROSCTR Ack_Data
    _place(buf, 14, bytes([0x00, 0x08, 0x00, 0x00]))  # param/data len placeholders
    _place(buf, 20, bytes([0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0]))
    return bytes(buf)


def build_szl_11(prof: dict) -> bytes:
    """SZL-ID 0x0011 response: Module @44, Basic Hardware @72, Version @123."""
    buf = bytearray(130)
    _tpkt_cotp_header(buf)
    _place(buf, 8, bytes([0x32, 0x07]))            # S7 proto id, ROSCTR Userdata
    buf[30] = 0x11                                 # byte 31: SZL-ID low byte
    _place(buf, 44, prof["module"].encode("ascii") + b"\x00")
    _place(buf, 72, prof["module"].encode("ascii") + b"\x00")   # basic hardware
    _place(buf, 123, bytes(prof["version"]))       # 3 version bytes (numbers)
    return bytes(buf)


def build_szl_1c(prof: dict) -> bytes:
    """SZL-ID 0x001C response: System Name @40, Module Type @74, Serial @176."""
    buf = bytearray(200)
    _tpkt_cotp_header(buf)
    _place(buf, 8, bytes([0x32, 0x07]))
    buf[30] = 0x1C                                 # byte 31: SZL-ID low byte
    _place(buf, 40, prof["system_name"].encode("ascii") + b"\x00")
    _place(buf, 74, prof["module_type"].encode("ascii") + b"\x00")
    _place(buf, 176, prof["serial"].encode("ascii") + b"\x00")
    return bytes(buf)


def build_szl_0424(prof: dict) -> bytes:
    """SZL-ID 0x0424 response: CPU operating-state byte at the last data byte.

    The probe reads the CPU state from the final byte of the frame and maps it
    via faultcodes.s7_cpu_state_name (0x08=RUN, 0x04=STOP, ...).
    """
    buf = bytearray(60)
    _tpkt_cotp_header(buf)
    _place(buf, 8, bytes([0x32, 0x07]))            # S7 proto id, ROSCTR Userdata
    buf[29] = 0x04                                 # byte 30: SZL-ID high (echo)
    buf[30] = 0x24                                 # byte 31: SZL-ID low
    buf[-1] = prof.get("cpu_state", 0x08) & 0xFF   # CPU state at last byte
    return bytes(buf)


def build_szl_00a0(prof: dict) -> bytes:
    """SZL-ID 0x00A0 response: diagnostic buffer.

    Zero events by default; when a diag event id is configured it is written as
    a big-endian u16 at the start of the trailing 12-byte window the probe reads
    (frame bytes 49-50, 1-based). Zero => the probe records no fault.
    """
    buf = bytearray(60)
    _tpkt_cotp_header(buf)
    _place(buf, 8, bytes([0x32, 0x07]))            # S7 proto id, ROSCTR Userdata
    buf[29] = 0x00                                 # byte 30: SZL-ID high (echo)
    buf[30] = 0xA0                                 # byte 31: SZL-ID low
    event = prof.get("diag_event")
    if event:
        _place(buf, len(buf) - 12 + 1, bytes([(event >> 8) & 0xFF, event & 0xFF]))
    return bytes(buf)


def response_for(prof: dict, req: bytes):
    """Return the reply bytes for a received request, or None to ignore."""
    if len(req) < 8:
        return None
    if req[5] == 0xE0:                             # byte 6: COTP Connection Request
        return build_connection_confirm()
    if req[7] != 0x32:                             # byte 8: not S7comm
        return None
    rosctr = req[8] if len(req) > 8 else 0         # byte 9
    if rosctr == 0x01:                             # setup-communication
        return build_setup_ack()
    if rosctr == 0x07:                             # userdata (SZL read)
        # 2-byte SZL-ID (big-endian) at bytes 30-31 (1-based). The real script
        # sends 00 11 / 00 1C, so single-byte 0x11/0x1C dispatch is preserved.
        szl_id = ((req[29] << 8) | req[30]) if len(req) > 30 else 0
        if szl_id == 0x001C:
            return build_szl_1c(prof)
        if szl_id == 0x0424:
            return build_szl_0424(prof)
        if szl_id == 0x00A0:
            return build_szl_00a0(prof)
        return build_szl_11(prof)                  # default / 0x0011
    return None


# ======================================================================
# Server
# ======================================================================
_shutdown = threading.Event()


def handle_client(conn, addr, prof, verbose):
    addr_str = f"{addr[0]}:{addr[1]}"
    try:
        conn.settimeout(5.0)
        while not _shutdown.is_set():
            data = conn.recv(1024)
            if not data:
                break
            resp = response_for(prof, data)
            if resp is None:
                _detection_log.info("%s -> unrecognized S7 frame (%dB, ignored)",
                                    addr_str, len(data))
                continue
            conn.sendall(resp)
            if verbose:
                _detection_log.info("%s -> S7 frame %dB -> %dB reply",
                                    addr_str, len(data), len(resp))
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
        pass
    except Exception as e:  # noqa: BLE001 - keep the honeypot alive
        print(f"  [{addr_str}] Error: {type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def run_server(port: int = S7_DEFAULT_PORT, profile: str = DEFAULT_PROFILE,
               verbose: bool = False, cpu_state: int = 0x08,
               diag_event=None):
    prof = dict(PROFILES.get(profile, PROFILES[DEFAULT_PROFILE]))
    prof["cpu_state"] = cpu_state
    prof["diag_event"] = diag_event
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(1.0)
    except OSError as e:
        print(f"[FATAL] Cannot bind 127.0.0.1:{port}: {e}")
        sys.exit(1)

    print(f"{'=' * 60}")
    print("  S7comm / S7comm-plus Identity Honeypot Emulator")
    print(f"  Listening on:  127.0.0.1:{port}/tcp")
    print(f"  Profile:       {profile}")
    print(f"  Module:        {prof['module']}  ({prof['module_type']})")
    print(f"  Version:       {'.'.join(map(str, prof['version']))}")
    print(f"{'=' * 60}", flush=True)

    client_id = 0
    try:
        while not _shutdown.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client_id += 1
            threading.Thread(
                target=handle_client, args=(conn, addr, prof, verbose),
                daemon=True, name=f"s7-client-{client_id}",
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def _handle_sigterm(signum, frame):
    _shutdown.set()


# ======================================================================
# Self-Test
# ======================================================================
def _read_z(buf: bytes, pos1: int) -> str:
    """Read a null-terminated ASCII string at a 1-based offset (test helper)."""
    idx = pos1 - 1
    end = buf.index(0, idx)
    return buf[idx:end].decode("ascii")


def self_test():
    print("[SELF-TEST] S7comm SZL identity round-trip...\n")
    for name, prof in PROFILES.items():
        r11 = build_szl_11(prof)
        assert r11[7] == 0x32, name
        assert _read_z(r11, 44) == prof["module"], (name, _read_z(r11, 44))
        ver = "%d.%d.%d" % (r11[122], r11[123], r11[124])
        assert ver == "%d.%d.%d" % prof["version"], (name, ver)

        r1c = build_szl_1c(prof)
        assert r1c[30] == 0x1C, name
        assert _read_z(r1c, 40) == prof["system_name"], name
        assert _read_z(r1c, 74) == prof["module_type"], name
        assert _read_z(r1c, 176) == prof["serial"], name

        cc = build_connection_confirm()
        assert cc[5] == 0xD0, name
        print(f"  [PASS] {name:9s} module='{prof['module']}' "
              f"type='{prof['module_type']}' ver={ver} serial='{prof['serial']}'")
    print("\n[SELF-TEST] All profiles passed.")


# ======================================================================
# Main
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="S7comm / S7comm-plus Identity Honeypot-Grade Emulator",
    )
    parser.add_argument("--port", "-p", type=int, default=S7_DEFAULT_PORT,
                        help=f"TCP port (default: {S7_DEFAULT_PORT})")
    parser.add_argument("--profile", type=str, default=DEFAULT_PROFILE,
                        choices=sorted(PROFILES.keys()),
                        help=f"Device profile (default: {DEFAULT_PROFILE})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable per-response logging")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in packet self-test and exit")
    parser.add_argument("--cpu-state", type=lambda x: int(x, 0), default=0x08,
                        help="CPU state byte for SZL 0x0424 (0x08=RUN,0x04=STOP)")
    parser.add_argument("--diag-event", type=lambda x: int(x, 0), default=None,
                        help="one diag-buffer event id for SZL 0x00A0 (e.g. 0x4300)")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    signal.signal(signal.SIGTERM, _handle_sigterm)
    run_server(port=args.port, profile=args.profile, verbose=args.verbose,
               cpu_state=args.cpu_state, diag_event=args.diag_event)


if __name__ == "__main__":
    main()
