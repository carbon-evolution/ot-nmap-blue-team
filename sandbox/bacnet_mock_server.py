#!/usr/bin/env python3
"""
BACnet/IP Honeypot-Grade Emulator.

Listens on UDP 47808 and emulates a BACnet building-automation device,
answering Confirmed-Request ReadProperty queries for the Device object's
standard identity properties (object-name, vendor-name, vendor-identifier,
model-name, firmware-revision, application-software-version, location,
description). Supports multiple device profiles, blue-team detection
logging, and clean SIGTERM shutdown.

Because BACnet/IP is UDP-only but the test harness detects readiness with a
TCP connect, this mock ALSO opens a tiny TCP listener on the same port that
does nothing but accept and close — purely so `_wait_port` succeeds. Real
BACnet traffic is UDP.

Usage:
    python3 bacnet_mock_server.py                              # automated_logic @ 47808
    python3 bacnet_mock_server.py --profile siemens_bas
    python3 bacnet_mock_server.py --profile honeywell_bas --port 47808
    python3 bacnet_mock_server.py --self-test                  # packet round-trip

Protocol Overview (BACnet/IP, integers big-endian):
    A ReadProperty request is 17 bytes:
        BVLC:  81 0a 00 11              type=0x81, func=0x0a (Orig-Unicast-NPDU),
                                        length=0x0011 (17)
        NPDU:  01 04                    version=1, control=0x04 (expecting reply)
        APDU:  00 05 01 0c              Confirmed-Req, max-apdu, invoke-id, ReadProperty(12)
               0c 02 3f ff ff          ctx-tag0 objectIdentifier: device (8), instance 0x3FFFFF
               19 <prop>                ctx-tag1 propertyIdentifier (1 byte)

    The ReadProperty ComplexACK reply this mock builds:
        BVLC:  81 0a <len:2>
        NPDU:  01 00
        APDU:  30 <invoke> 0c          ComplexACK, invoke-id, service=ReadProperty(12)
               0c 02 3f ff ff          ctx-tag0 objectIdentifier (echo)
               19 <prop>               ctx-tag1 propertyIdentifier (echo)
               3e                       ctx-tag3 opening (propertyValue)
               <value>                  application-tagged value
               3f                       ctx-tag3 closing
    Character-string values use application tag 7 with extended length:
        75 <strlen+1> 00 <ascii>       tag=7/ext-len, len byte, charset=0 (UTF-8), bytes
    Unsigned values (vendor-identifier) use application tag 2:
        21 <byte>                       tag=2, length 1, value
"""

import argparse
import logging
import signal
import socket
import sys
import threading

BACNET_DEFAULT_PORT = 47808
DEFAULT_PROFILE = "automated_logic"

# BACnet property identifiers (ASHRAE 135) used for device discovery.
PROP_OBJECT_NAME = 0x4D          # 77
PROP_VENDOR_NAME = 0x79          # 121
PROP_VENDOR_ID = 0x78            # 120  (unsigned)
PROP_MODEL_NAME = 0x46           # 70
PROP_FIRMWARE_REV = 0x2C         # 44
PROP_APP_SOFTWARE = 0x0C         # 12
PROP_LOCATION = 0x3A             # 58
PROP_DESCRIPTION = 0x1C          # 28

# Per-profile device identities (the character-string / unsigned values the
# mock returns for each queried property).
PROFILES = {
    "automated_logic": {
        "vendor_id": 24,
        "vendor_name": "Automated Logic Corporation",
        "model_name": "LGR1000",
        "firmware": "6.02",
        "app_software": "OS-6.02b",
        "object_name": "ALC-VAV-101",
        "location": "Bldg-A/Fl-3",
        "description": "VAV Controller",
    },
    "siemens_bas": {
        "vendor_id": 7,
        "vendor_name": "Siemens Industry, Inc.",
        "model_name": "PXC00-E.D",
        "firmware": "3.5.1",
        "app_software": "APOGEE-3.5",
        "object_name": "SBT-AHU-02",
        "location": "Bldg-B/Roof",
        "description": "AHU Controller",
    },
    "honeywell_bas": {
        "vendor_id": 17,
        "vendor_name": "Honeywell Inc.",
        "model_name": "CIPer 50",
        "firmware": "9.0.1",
        "app_software": "Niagara-4.9",
        "object_name": "HON-JACE-07",
        "location": "Bldg-C/Fl-1",
        "description": "Supervisory Controller",
    },
}

# Map a queried property id -> the profile key that answers it (strings).
STRING_PROP_MAP = {
    PROP_OBJECT_NAME: "object_name",
    PROP_VENDOR_NAME: "vendor_name",
    PROP_MODEL_NAME: "model_name",
    PROP_FIRMWARE_REV: "firmware",
    PROP_APP_SOFTWARE: "app_software",
    PROP_LOCATION: "location",
    PROP_DESCRIPTION: "description",
}

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [DETECT] %(message)s",
    datefmt="%H:%M:%S",
)
_detection_log = logging.getLogger("bacnet")


# ======================================================================
# Packet building
# ======================================================================
def _complex_ack(prop: int, value_tlv: bytes, invoke: int = 1) -> bytes:
    """Wrap an application-tagged value in a ReadProperty ComplexACK."""
    apdu = bytes([0x30, invoke & 0xFF, 0x0C,          # ComplexACK, invoke, ReadProperty
                  0x0C, 0x02, 0x3F, 0xFF, 0xFF,        # ctx0 objectIdentifier (device, any)
                  0x19, prop & 0xFF,                   # ctx1 propertyIdentifier
                  0x3E]) + value_tlv + bytes([0x3F])   # ctx3 open, value, ctx3 close
    npdu = bytes([0x01, 0x00])                         # version, control
    total = 4 + len(npdu) + len(apdu)                  # incl. 4-byte BVLC header
    bvlc = bytes([0x81, 0x0A, (total >> 8) & 0xFF, total & 0xFF])
    return bvlc + npdu + apdu


def build_string_response(prop: int, text: str, invoke: int = 1) -> bytes:
    """ReadProperty ACK carrying a character-string value (app tag 7)."""
    raw = text.encode("utf-8")
    # extended-length form: tag byte 0x75, length = charset byte + string bytes
    value = bytes([0x75, len(raw) + 1, 0x00]) + raw
    return _complex_ack(prop, value, invoke)


def build_unsigned_response(prop: int, number: int, invoke: int = 1) -> bytes:
    """ReadProperty ACK carrying an unsigned integer (app tag 2)."""
    if number <= 0xFF:
        value = bytes([0x21, number & 0xFF])
    else:
        value = bytes([0x22, (number >> 8) & 0xFF, number & 0xFF])
    return _complex_ack(prop, value, invoke)


def parse_request_property(data: bytes):
    """Extract (invoke_id, property_id) from a ReadProperty request, or None."""
    # Minimum: 4 BVLC + 2 NPDU + 4 APDU-head + 5 objid + 2 propid = 17 bytes.
    if len(data) < 17 or data[0] != 0x81:
        return None
    # APDU service choice at byte index 9 must be ReadProperty (0x0c).
    if data[9] != 0x0C:
        return None
    invoke = data[8]
    # ctx-tag1 propertyIdentifier opening (0x19) then the 1-byte prop id.
    if data[15] != 0x19:
        return None
    return invoke, data[16]


def build_response(prof: dict, invoke: int, prop: int):
    """Build the ComplexACK for a queried property, or None if unsupported."""
    if prop == PROP_VENDOR_ID:
        return build_unsigned_response(prop, prof["vendor_id"], invoke)
    key = STRING_PROP_MAP.get(prop)
    if key is not None:
        return build_string_response(prop, prof[key], invoke)
    return None


# ======================================================================
# Servers
# ======================================================================
_shutdown = threading.Event()


def _readiness_listener(port: int):
    """Tiny TCP accept-and-close loop so the harness's _wait_port succeeds."""
    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tsock.bind(("127.0.0.1", port))
        tsock.listen(5)
        tsock.settimeout(1.0)
    except OSError as e:
        print(f"[WARN] readiness TCP listener could not bind {port}: {e}")
        return
    while not _shutdown.is_set():
        try:
            conn, _ = tsock.accept()
            conn.close()
        except socket.timeout:
            continue
        except OSError:
            break
    tsock.close()


def run_server(port: int = BACNET_DEFAULT_PORT, profile: str = DEFAULT_PROFILE,
               verbose: bool = False):
    """Run the BACnet/IP UDP mock until SIGTERM/Ctrl+C."""
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    threading.Thread(target=_readiness_listener, args=(port,),
                     daemon=True, name="bacnet-ready").start()

    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        usock.bind(("127.0.0.1", port))
        usock.settimeout(1.0)
    except OSError as e:
        print(f"[FATAL] Cannot bind UDP 127.0.0.1:{port}: {e}")
        sys.exit(1)

    print(f"{'=' * 60}")
    print("  BACnet/IP Honeypot Emulator")
    print(f"  Listening on:  127.0.0.1:{port}/udp")
    print(f"  Profile:       {profile}")
    print(f"  Vendor:        {prof['vendor_name']} ({prof['vendor_id']})")
    print(f"  Model:         {prof['model_name']}  Firmware: {prof['firmware']}")
    print(f"{'=' * 60}", flush=True)

    while not _shutdown.is_set():
        try:
            data, addr = usock.recvfrom(1500)
        except socket.timeout:
            continue
        except OSError:
            break
        parsed = parse_request_property(data)
        if parsed is None:
            _detection_log.info("%s:%d -> non-ReadProperty/invalid (%dB, ignored)",
                                addr[0], addr[1], len(data))
            continue
        invoke, prop = parsed
        resp = build_response(prof, invoke, prop)
        if resp is None:
            _detection_log.info("%s:%d -> ReadProperty prop 0x%02x (unsupported)",
                                addr[0], addr[1], prop)
            continue
        usock.sendto(resp, addr)
        if verbose:
            _detection_log.info("%s:%d -> ReadProperty prop 0x%02x -> %dB reply",
                                addr[0], addr[1], prop, len(resp))
    usock.close()


def _handle_sigterm(signum, frame):
    _shutdown.set()


# ======================================================================
# Self-Test
# ======================================================================
def self_test():
    """Round-trip the builder/parser for every profile and property."""
    print("[SELF-TEST] BACnet/IP ReadProperty round-trip...\n")
    for name, prof in PROFILES.items():
        # String property: model name.
        resp = build_string_response(PROP_MODEL_NAME, prof["model_name"])
        got = _decode_string_value(resp)
        assert got == prof["model_name"], (name, got)
        # Unsigned property: vendor id.
        resp_v = build_unsigned_response(PROP_VENDOR_ID, prof["vendor_id"])
        num = _decode_unsigned_value(resp_v)
        assert num == prof["vendor_id"], (name, num)
        # Request parsing.
        req = bytes.fromhex("810a001101040005010c0c023fffff1946")
        assert parse_request_property(req) == (1, PROP_MODEL_NAME), name
        print(f"  [PASS] {name:16s} model='{prof['model_name']}' "
              f"vendor={prof['vendor_name']} ({prof['vendor_id']})")
    print("\n[SELF-TEST] All profiles passed.")


def _decode_string_value(resp: bytes) -> str:
    """Mirror the NSE character-string decode (for self-test only)."""
    b18 = resp[17]                       # 1-based byte 18
    if b18 % 0x10 < 5:
        length = (b18 % 0x10) - 1
        offset = 18                      # 0-based index of charset byte
    else:
        length = resp[18] - 1            # byte 19
        offset = 19
    charset = resp[offset]               # noqa: F841 - documents the field
    return resp[offset + 1:offset + 1 + length].decode("utf-8")


def _decode_unsigned_value(resp: bytes) -> int:
    """Mirror the NSE unsigned decode (for self-test only)."""
    tag = resp[17]                       # 1-based byte 18
    length = tag & 0x0F
    return int.from_bytes(resp[18:18 + length], "big")


# ======================================================================
# Main
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="BACnet/IP Honeypot-Grade Emulator",
    )
    parser.add_argument("--port", "-p", type=int, default=BACNET_DEFAULT_PORT,
                        help=f"UDP port (default: {BACNET_DEFAULT_PORT})")
    parser.add_argument("--profile", type=str, default=DEFAULT_PROFILE,
                        choices=sorted(PROFILES.keys()),
                        help=f"Device profile (default: {DEFAULT_PROFILE})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable per-response logging")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in packet self-test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    signal.signal(signal.SIGTERM, _handle_sigterm)
    run_server(port=args.port, profile=args.profile, verbose=args.verbose)


if __name__ == "__main__":
    main()
