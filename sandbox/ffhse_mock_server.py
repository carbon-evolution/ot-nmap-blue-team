#!/usr/bin/env python3
"""
FF HSE (Foundation Fieldbus High Speed Ethernet) Honeypot Device Emulator.

Upgraded from simple mock server to honeypot-grade device emulator with:
- LREQ/LRES (Local Request/Response) handshake protocol
- FMS (Fieldbus Message Specification) read services — typed variable reads
- Configurable device profiles: temperature, pressure, flow, valve
- Simulated process variables with realistic drift
- Device Description (DD) parameter simulation (VERE_ID, ST_REV, DEV_STATUS, etc.)
- Alarm simulation with periodic background notifications
- Blue-team detection logging on every connection
- Thread-per-connection concurrent handling
- Full backward compatibility with ff-hse-discover-improved.nse

Ports (standard FF HSE):
  1089 — HSE Management Agent (MA)
  1090 — HSE System Management (SM) primary
  1091 — HSE System Management (SM) alternate

Wire format note: All multi-byte fields are little-endian (per FF HSE spec).

Usage:
  python3 ffhse_mock_server.py                              # default ports 1089-1091
  python3 ffhse_mock_server.py --profile temperature         # RTD temp transmitter
  python3 ffhse_mock_server.py --profile pressure            # pressure transmitter
  python3 ffhse_mock_server.py --profile flow                # Coriolis flow meter
  python3 ffhse_mock_server.py --profile valve               # valve positioner
  python3 ffhse_mock_server.py --port 1089                   # single port only
  python3 ffhse_mock_server.py --verbose                     # hex dump all traffic
  python3 ffhse_mock_server.py --enable-alarms               # periodic alarm simulation
  python3 ffhse_mock_server.py --profile flow --enable-alarms --verbose

Press Ctrl+C to stop.
"""

import argparse
import logging
import socket
import struct
import sys
import time
import threading
import random
from collections import deque

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ffhse-honeypot")

# ─── Protocol Constants ─────────────────────────────────────────────────────

# SM (System Management) protocol
SM_PROTO_VER = 0x01
SM_SERVICE_IDENTIFY = 0x01
SM_SERVICE_STATUS = 0x04
SM_STATUS_SUCCESS = 0x00

# MA (Management Agent) protocol
MA_PROTO_DISCRIMINATOR = 0x90
MA_MSG_GET_IDENTIFICATION = 0x01
MA_MSG_IDENTIFICATION_RESP = 0x81

# LREQ/LRES protocol — layered on top of existing SM/MA ports
# Tag chosen to NOT conflict with SM (starts 0x01) or MA (starts 0x90)
LREQ_TAG = 0xF1E1   # bytes on wire (LE): 0xE1, 0xF1
LREQ_TYPE = 0x0001
LRES_TYPE = 0x8001   # response flag (bit 15 set)

# FMS Read service
FMS_READ_TAG = 0xF1E2       # bytes on wire (LE): 0xE2, 0xF1
FMS_READ_TYPE = 0x0010
FMS_READ_RESP_TYPE = 0x8010  # response flag (bit 15 set)

# Variable indices
PV_INDEX      = 0x0001  # Primary Value (process variable)
SV_INDEX      = 0x0002  # Secondary Value
DEV_STATUS    = 0x0003  # Device status word

# DD (Device Description) parameter indices
DD_VERE_ID    = 0x0100
DD_ST_REV     = 0x0101
DD_DEV_STATUS = 0x0102
DD_TAG_DESC   = 0x0103
DD_MANUFAC_ID = 0x0104

# ─── Device Profiles ───────────────────────────────────────────────────────

PROFILES = {
    "temperature": {
        "device_id": "E+H-RTD-TIC101-0001",
        "vendor": "Endress+Hauser",
        "device_tag": "TIC-101",
        "device_type": "RTD_Temp_Transmitter",
        "hse_version": "1.2",
        "software_rev": "3.0.1",
        "stack_version": "FF_HSE_Stack_v2.1",
        "mac_address": "00:1B:44:11:3A:B7",
        "manufac_id": 0x00001B44,
        # Process simulation
        "pv_range": (20.0, 150.0),
        "pv_unit": "degC",
        "pv_noise": 0.5,
        "sv_range": (18.0, 148.0),
        "sv_unit": "degC",
        "alarm_triggers": ["HH_TEMP", "HI_TEMP", "SENSOR_FAIL"],
        "tag_desc": "RTD Temp Transmitter TIC-101",
        # DD defaults
        "dd_vere_id": 0x0101,
        "dd_st_rev": 0x0003,
    },
    "pressure": {
        "device_id": "ROS-PTX-PIC201-0001",
        "vendor": "Rosemount",
        "device_tag": "PIC-201",
        "device_type": "Pressure_Transmitter",
        "hse_version": "1.1",
        "software_rev": "4.2.0",
        "stack_version": "FF_HSE_Stack_v2.2",
        "mac_address": "00:0B:5B:2A:C4:19",
        "manufac_id": 0x00000B5B,
        "pv_range": (0.0, 100.0),
        "pv_unit": "bar",
        "pv_noise": 0.3,
        "sv_range": (20.0, 30.0),
        "sv_unit": "degC",
        "alarm_triggers": ["HI_PRESS", "LO_PRESS", "SENSOR_FAIL"],
        "tag_desc": "Pressure Transmitter PIC-201",
        "dd_vere_id": 0x0100,
        "dd_st_rev": 0x0002,
    },
    "flow": {
        "device_id": "MMI-CFM-FIC301-0001",
        "vendor": "Micro Motion",
        "device_tag": "FIC-301",
        "device_type": "Coriolis_Flowmeter",
        "hse_version": "1.3",
        "software_rev": "5.0.1",
        "stack_version": "FF_HSE_Stack_v2.3",
        "mac_address": "00:0E:B5:44:92:F0",
        "manufac_id": 0x00000EB5,
        "pv_range": (0.0, 500.0),
        "pv_unit": "kg/h",
        "pv_noise": 1.0,
        "sv_range": (20.0, 50.0),
        "sv_unit": "degC",
        "alarm_triggers": ["HI_FLOW", "LO_FLOW", "EMPTY_PIPE", "SENSOR_FAIL"],
        "tag_desc": "Coriolis Flow Meter FIC-301",
        "dd_vere_id": 0x0102,
        "dd_st_rev": 0x0004,
    },
    "valve": {
        "device_id": "FIS-VP-PV401-0001",
        "vendor": "Fisher",
        "device_tag": "PV-401",
        "device_type": "Valve_Positioner",
        "hse_version": "1.0",
        "software_rev": "2.1.0",
        "stack_version": "FF_HSE_Stack_v1.9",
        "mac_address": "00:1E:8C:77:32:5D",
        "manufac_id": 0x00001E8C,
        "pv_range": (0.0, 100.0),
        "pv_unit": "%",
        "pv_noise": 0.2,
        "sv_range": (0.0, 100.0),
        "sv_unit": "%",
        "alarm_triggers": ["VALVE_STUCK", "POS_LIMIT", "AIR_LOSS"],
        "tag_desc": "Valve Positioner PV-401",
        "dd_vere_id": 0x0100,
        "dd_st_rev": 0x0001,
    },
}

# ─── Variable Table per Profile ─────────────────────────────────────────────
# Each entry: (index, name, type_str, description)
# type_str one of: "float", "uint16", "uint32", "string"

VARIABLE_TABLES = {
    "temperature": [
        (PV_INDEX, "PRIMARY_VALUE", "float", "Process temperature"),
        (SV_INDEX, "SENSOR_TEMP", "float", "Sensor internal temperature"),
        (DEV_STATUS, "DEVICE_STATUS", "uint16", "Device status word"),
        (DD_VERE_ID, "VERE_ID", "uint16", "DD Version ID"),
        (DD_ST_REV, "ST_REV", "uint16", "Standard Revision"),
        (DD_DEV_STATUS, "DEV_STATUS", "uint16", "Device Status (DD)"),
        (DD_TAG_DESC, "TAG_DESC", "string", "Tag description"),
        (DD_MANUFAC_ID, "MANUFAC_ID", "uint32", "Manufacturer ID"),
    ],
    "pressure": [
        (PV_INDEX, "PRIMARY_VALUE", "float", "Process pressure"),
        (SV_INDEX, "SENSOR_TEMP", "float", "Sensor internal temperature"),
        (DEV_STATUS, "DEVICE_STATUS", "uint16", "Device status word"),
        (DD_VERE_ID, "VERE_ID", "uint16", "DD Version ID"),
        (DD_ST_REV, "ST_REV", "uint16", "Standard Revision"),
        (DD_DEV_STATUS, "DEV_STATUS", "uint16", "Device Status (DD)"),
        (DD_TAG_DESC, "TAG_DESC", "string", "Tag description"),
        (DD_MANUFAC_ID, "MANUFAC_ID", "uint32", "Manufacturer ID"),
    ],
    "flow": [
        (PV_INDEX, "PRIMARY_VALUE", "float", "Mass flow rate"),
        (SV_INDEX, "DENSITY", "float", "Process density"),
        (DEV_STATUS, "DEVICE_STATUS", "uint16", "Device status word"),
        (DD_VERE_ID, "VERE_ID", "uint16", "DD Version ID"),
        (DD_ST_REV, "ST_REV", "uint16", "Standard Revision"),
        (DD_DEV_STATUS, "DEV_STATUS", "uint16", "Device Status (DD)"),
        (DD_TAG_DESC, "TAG_DESC", "string", "Tag description"),
        (DD_MANUFAC_ID, "MANUFAC_ID", "uint32", "Manufacturer ID"),
    ],
    "valve": [
        (PV_INDEX, "PRIMARY_VALUE", "float", "Valve position"),
        (SV_INDEX, "SETPOINT", "float", "Position setpoint"),
        (DEV_STATUS, "DEVICE_STATUS", "uint16", "Device status word"),
        (DD_VERE_ID, "VERE_ID", "uint16", "DD Version ID"),
        (DD_ST_REV, "ST_REV", "uint16", "Standard Revision"),
        (DD_DEV_STATUS, "DEV_STATUS", "uint16", "Device Status (DD)"),
        (DD_TAG_DESC, "TAG_DESC", "string", "Tag description"),
        (DD_MANUFAC_ID, "MANUFAC_ID", "uint32", "Manufacturer ID"),
    ],
}

# Quick lookup from index to variable entry
VAR_LOOKUP = {}
for pname, vtable in VARIABLE_TABLES.items():
    VAR_LOOKUP[pname] = {idx: (name, typ, desc) for idx, name, typ, desc in vtable}

# ─── Global Shared State ────────────────────────────────────────────────────

_state_lock = threading.Lock()
_alarm_queue = deque()         # pending alarm events
_pv_drift = {}                 # current drift offset per profile
_connection_counter = 0        # global connection counter for tracking


def _init_pv_drift(profile_name: str):
    """Seed initial drift for a profile's process variable."""
    p = PROFILES[profile_name]
    lo, hi = p["pv_range"]
    with _state_lock:
        if profile_name not in _pv_drift:
            _pv_drift[profile_name] = random.uniform(lo * 0.1, hi * 0.15)


def _get_pv(profile_name: str) -> float:
    """Get the current simulated process variable value with drift."""
    p = PROFILES[profile_name]
    lo, hi = p["pv_range"]
    with _state_lock:
        drift = _pv_drift.get(profile_name, 0.0)
        # Apply random walk drift
        step = random.uniform(-0.5, 0.5) * (hi - lo) * 0.005
        drift += step
        drift = max(-(hi - lo) * 0.2, min((hi - lo) * 0.2, drift))
        _pv_drift[profile_name] = drift
    mid = (lo + hi) / 2.0
    noise = random.uniform(-p["pv_noise"], p["pv_noise"])
    val = mid + drift + noise
    return round(max(lo, min(hi, val)), 2)


def _get_sv(profile_name: str) -> float:
    """Get the current simulated secondary variable value."""
    p = PROFILES[profile_name]
    lo, hi = p["sv_range"]
    mid = (lo + hi) / 2.0
    noise = random.uniform(-p["pv_noise"] * 0.5, p["pv_noise"] * 0.5)
    val = mid + noise
    return round(max(lo, min(hi, val)), 2)


# ─── Hex Dump Utility ──────────────────────────────────────────────────────

def hex_dump(data: bytes, label: str = "") -> str:
    """Return a formatted hex dump of data (hex + ASCII)."""
    output = []
    output.append(f"─── {label} ({len(data)} bytes) ───" if label
                  else f"─── Data ({len(data)} bytes) ───")
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_part += "   " * (16 - len(chunk))
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        output.append(f"  {offset:04x}: {hex_part}  |{ascii_part}|")
    return "\n".join(output)


# ─── Detection Logger ──────────────────────────────────────────────────────

def log_detection(client_ip: str, client_port: int, tcp_port: int,
                  req_type: str, detail: str, data: bytes = b""):
    """Structured detection log for blue-team analysis.

    Format:
      [DETECTION] <ISO timestamp> | client=<ip>:<port> | port=<tcp_port> |
                   type=<req_type> | <detail>
      [hex dump of data follows]
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    base = (f"[DETECTION] {ts} | client={client_ip}:{client_port} | "
            f"port={tcp_port} | type={req_type} | {detail}")
    log.warning("%s", base)
    if data:
        for line in hex_dump(data, label=f"DETECT {req_type}").split("\n"):
            log.warning("  %s", line)


# ─── Alarm Simulation Engine ───────────────────────────────────────────────

_alarm_shutdown = threading.Event()


def _alarm_generator(profile_name: str, interval: float = 12.0):
    """Background thread that generates periodic alarm events.

    Uses a base interval with ±40% jitter to avoid predictable patterns.
    Alarms are placed on a shared deque for consumption by connection handlers.
    """
    p = PROFILES[profile_name]
    while not _alarm_shutdown.is_set():
        jitter = interval * random.uniform(-0.4, 0.4)
        _alarm_shutdown.wait(interval + jitter)
        if _alarm_shutdown.is_set():
            break
        alarm_type = random.choice(p["alarm_triggers"])
        pv = _get_pv(profile_name)
        severity = random.choices(
            ["LOW", "HIGH", "HIGH_HIGH"],
            weights=[0.5, 0.35, 0.15],
            k=1,
        )[0]
        event = {
            "ts": time.time(),
            "alarm_type": alarm_type,
            "severity": severity,
            "value": pv,
            "profile": profile_name,
            "description": f"[{severity}] {alarm_type} @ {pv} {p['pv_unit']}",
        }
        with _state_lock:
            _alarm_queue.append(event)
            # Keep at most 50 pending alarms
            while len(_alarm_queue) > 50:
                _alarm_queue.popleft()
        log.info("[ALARM] %s | pv=%.2f %s",
                 event["description"], pv, p["pv_unit"])


def _get_pending_alarms() -> list:
    """Consume and return all pending alarm events."""
    with _state_lock:
        alarms = list(_alarm_queue)
        _alarm_queue.clear()
    return alarms


# ─── Response Builders ─────────────────────────────────────────────────────

# 1. Text banner (NSE backward compatibility)

def build_banner(profile: dict) -> bytes:
    """Build a human-readable device banner.

    Sent immediately on TCP connect. The NSE script's banner grab
    picks this up and extracts ASCII strings from it.
    """
    lines = [
        f"FF_HSE Device: {profile['device_id']}",
        f"Vendor: {profile['vendor']}",
        f"Device Tag: {profile['device_tag']}",
        f"Device Type: {profile['device_type']}",
        f"HSE Version: {profile['hse_version']}",
        f"Software Rev: {profile['software_rev']}",
        f"Stack: {profile['stack_version']}",
        f"MAC: {profile['mac_address']}",
    ]
    return "\r\n".join(lines).encode() + b"\r\n"


# 2. SM_Identify response (binary, for NSE on ports 1090/1091)

def build_sm_identify_response(profile: dict) -> bytes:
    """Build a binary SM_Identify response.

    Structure (per FF HSE spec):
      Byte 0:  Protocol version (0x01)
      Byte 1:  Service code (0x01 = SM_Identify)
      Byte 2:  Status (0x00 = success)
      Byte 3:  Reserved (0x00)
      Then null-terminated ASCII strings for device info fields.
    """
    header = struct.pack("<BBBB",
        SM_PROTO_VER,
        SM_SERVICE_IDENTIFY,
        SM_STATUS_SUCCESS,
        0x00,
    )
    fields = [
        profile["device_id"].encode(),
        profile["vendor"].encode(),
        profile["device_tag"].encode(),
        profile["hse_version"].encode(),
        profile["software_rev"].encode(),
        profile["device_type"].encode(),
        profile["stack_version"].encode(),
    ]
    body = b"\x00".join(fields) + b"\x00"
    return header + body


# 3. MA identification response (binary, for NSE on port 1089)

def build_ma_identification_response(profile: dict, txn_id: int = 1) -> bytes:
    """Build a binary MA identification response.

    Structure:
      Byte 0:     Protocol discriminator (0x90 = HSE MA)
      Byte 1:     Response type (0x81)
      Bytes 2-3:  Transaction ID (echoed from request, LE)
      Bytes 4-7:  Reserved (0x00000000)
      Then null-terminated ASCII strings for device info.
    """
    header = struct.pack("<BBH",
        MA_PROTO_DISCRIMINATOR,
        MA_MSG_IDENTIFICATION_RESP,
        txn_id & 0xFFFF,
    )
    fields = [
        profile["device_id"].encode(),
        profile["vendor"].encode(),
        profile["device_type"].encode(),
        profile["hse_version"].encode(),
        profile["stack_version"].encode(),
    ]
    body = b"\x00".join(fields) + b"\x00"
    return header + body


# 4. LRES (Local Response) for LREQ handshake

def build_lres(profile: dict, device_id: int) -> bytes:
    """Build an LRES response to an LREQ handshake.

    Structure (all LE):
      tag (uint16):     echoed from LREQ (0xF1E1)
      type (uint16):    0x8001 (response)
      DeviceID (uint32): echoed from request
      payload:          null-terminated device description strings
    """
    fields = [
        profile["device_id"].encode(),
        profile["vendor"].encode(),
        profile["device_tag"].encode(),
        profile["device_type"].encode(),
        profile["hse_version"].encode(),
        profile["software_rev"].encode(),
        profile["stack_version"].encode(),
        profile["mac_address"].encode(),
    ]
    payload = b"\x00".join(fields) + b"\x00"
    header = struct.pack("<HHI", LREQ_TAG, LRES_TYPE, device_id)
    return header + payload


# 5. FMS Read response — typed variable value

def _encode_variable_value(typ: str, val) -> bytes:
    """Encode a typed value into wire bytes (all LE)."""
    if typ == "float":
        return struct.pack("<f", float(val))
    elif typ == "uint16":
        return struct.pack("<H", int(val) & 0xFFFF)
    elif typ == "uint32":
        return struct.pack("<I", int(val) & 0xFFFFFFFF)
    elif typ == "string":
        enc = str(val).encode("ascii", errors="replace")
        return enc + b"\x00"
    return struct.pack("<f", float(val))


def build_fms_read_response(profile: dict, tag: int,
                            index: int, length: int) -> bytes:
    """Build an FMS Read response with the requested variable's value.

    Structure (all LE):
      tag (uint16):     echoed from request
      type (uint16):    0x8010 (FMS read response)
      reserved (4B):    0x00000000
      index (uint16):   echoed from request
      length (uint16):  byte length of response data
      data (variable):  encoded variable value

    Returns the complete response bytes. If the variable index is not
    recognised, returns a zero-length data response.
    """
    # Look up variable by index
    pname = profile.get("_name", "")
    var_entry = VAR_LOOKUP.get(pname, {}).get(index)
    if var_entry is None:
        # Unknown index — return zero-length response
        header = struct.pack("<HHIHH", tag, FMS_READ_RESP_TYPE,
                             0x00000000, index, 0x0000)
        return header

    var_name, var_type, var_desc = var_entry
    val = _get_variable_value(profile, index, var_name, var_type)
    payload = _encode_variable_value(var_type, val)

    # Clamp to requested length
    if length > 0 and len(payload) > length:
        payload = payload[:length]

    header = struct.pack("<HHIHH", tag, FMS_READ_RESP_TYPE,
                         0x00000000, index, len(payload))
    return header + payload


def _get_variable_value(profile: dict, index: int,
                        var_name: str, var_type: str):
    """Determine the current value for a variable index, handling PV/SV/DD."""
    if index == PV_INDEX:
        return _get_pv(profile.get("_name", ""))
    elif index == SV_INDEX:
        return _get_sv(profile.get("_name", ""))
    elif index == DEV_STATUS:
        return 0x0000  # OK
    elif index == DD_VERE_ID:
        return profile.get("dd_vere_id", 0x0100)
    elif index == DD_ST_REV:
        return profile.get("dd_st_rev", 0x0001)
    elif index == DD_DEV_STATUS:
        return 0x0000  # operational
    elif index == DD_TAG_DESC:
        return profile.get("tag_desc", "")
    elif index == DD_MANUFAC_ID:
        return profile.get("manufac_id", 0)
    return 0.0


# 6. DD parameter descriptor response

def build_dd_descriptor_response(profile: dict, tag: int,
                                 index: int) -> bytes:
    """Build a DD parameter descriptor response.

    The DD descriptor provides metadata about a parameter (name, data type,
    length, engineering units reference). This is what a real FF device
    returns when a client enumerates the Device Description.

    Structure (all LE):
      tag (uint16):     echoed from request
      type (uint16):    0x8010 (read response)
      reserved (4B):    0x00000000
      index (uint16):   parameter index echoed
      length (uint16):  descriptor byte length
      data:             descriptor structure
        param_name (32B ASCII, space-padded)
        data_type (uint16): 1=float, 2=uint16, 3=uint32, 4=string
        data_len  (uint16): byte length of param value
        param_class (uint16): 0=Input, 1=Output, 2=Configuration
        label (16B ASCII, space-padded)
    """
    # Build descriptor payload
    var_entry = VAR_LOOKUP.get(profile.get("_name", ""), {}).get(index)
    if var_entry is None:
        header = struct.pack("<HHIHH", tag, FMS_READ_RESP_TYPE,
                             0x00000000, index, 0x0000)
        return header

    var_name, var_type, var_desc = var_entry

    type_map = {"float": 1, "uint16": 2, "uint32": 3, "string": 4}
    dtype = type_map.get(var_type, 1)
    dlen = {"float": 4, "uint16": 2, "uint32": 4, "string": 16}.get(var_type, 4)

    # Parameter class
    if index == PV_INDEX:
        pclass = 0  # Input
    elif index == SV_INDEX:
        pclass = 0  # Input
    elif index >= 0x0100:
        pclass = 2  # Configuration
    else:
        pclass = 1  # Output

    name_enc = var_name.ljust(32, " ")[:32].encode("ascii", errors="replace")
    label_enc = var_desc.ljust(16, " ")[:16].encode("ascii", errors="replace")

    desc_body = struct.pack("<32sHHH16s", name_enc, dtype, dlen, pclass, label_enc)
    header = struct.pack("<HHIHH", tag, FMS_READ_RESP_TYPE,
                         0x00000000, index, len(desc_body))
    return header + desc_body


# ─── Request Classification ────────────────────────────────────────────────

def classify_request(data: bytes):
    """Classify an incoming request by its leading bytes.

    Returns a tuple (req_type, parsed_fields, matched) where:
      req_type:  "SM_IDENTIFY", "MA_IDENTIFY", "LREQ", "FMS_READ", or "UNKNOWN"
      parsed:    dict of parsed fields (type-specific)
      matched:   bool — True if we recognised the format
    """
    if len(data) < 2:
        return "UNKNOWN", {}, False

    # Check LREQ first (distinguishable tag)
    if len(data) >= 8:
        tag = struct.unpack_from("<H", data, 0)[0]
        rtype = struct.unpack_from("<H", data, 2)[0]

        if tag == LREQ_TAG and rtype == LREQ_TYPE:
            device_id = struct.unpack_from("<I", data, 4)[0]
            return "LREQ", {"tag": tag, "type": rtype, "device_id": device_id}, True

        if tag == FMS_READ_TAG and rtype == FMS_READ_TYPE and len(data) >= 12:
            index = struct.unpack_from("<H", data, 8)[0]
            length = struct.unpack_from("<H", data, 10)[0]
            return ("FMS_READ", {
                "tag": tag, "type": rtype,
                "index": index, "length": length,
            }, True)

    # Check MA protocol (starts with 0x90)
    if data[0] == MA_PROTO_DISCRIMINATOR:
        txn_id = 1
        if len(data) >= 4:
            txn_id = struct.unpack_from("<H", data, 2)[0]
        return "MA_IDENTIFY", {"txn_id": txn_id}, True

    # Check SM protocol (first byte 0x01)
    if len(data) >= 2 and data[0] == SM_PROTO_VER and data[1] == SM_SERVICE_IDENTIFY:
        return "SM_IDENTIFY", {}, True

    return "UNKNOWN", {}, False


# ─── Connection Handler (runs in a thread) ─────────────────────────────────

def handle_connection(conn: socket.socket, addr: tuple, tcp_port: int,
                      profile: dict, verbose: bool):
    """Handle a single client connection.

    Protocol flow:
      1. Send ASCII banner (backward compat with NSE banner grab)
      2. Receive and classify client request
      3. Dispatch to appropriate response builder
      4. If alarms enabled, inject pending alarm notifications
      5. Log everything for blue-team detection

    Thread-per-connection: each caller gets a fresh handler thread.
    """
    global _connection_counter
    client_ip, client_port = addr
    pname = profile.get("_name", "unknown")

    service = {
        1089: "HSE Management Agent",
        1090: "HSE System Management (primary)",
        1091: "HSE System Management (alternate)",
    }.get(tcp_port, f"port {tcp_port}")

    with _state_lock:
        _connection_counter += 1
        conn_id = _connection_counter

    log.info("Conn[%d] from %s:%d on %s [%d] (profile=%s)",
             conn_id, client_ip, client_port, service, tcp_port, pname)

    try:
        with conn:
            # ── Step 1: Send banner (backward compat with NSE) ──────
            banner = build_banner(profile)
            conn.sendall(banner)
            log_detection(
                client_ip, client_port, tcp_port,
                "BANNER", f"Sent {len(banner)}B banner to {client_ip}:{client_port}",
                banner if verbose else b"",
            )

            # ── Step 2: Wait for client request ─────────────────────
            conn.settimeout(10.0)
            buf = b""
            # Receive first chunk with long timeout
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                log.info("Conn[%d] timeout — no request received", conn_id)
                return
            if not chunk:
                log.info("Conn[%d] client closed connection", conn_id)
                return
            buf += chunk

            # Brief pause to aggregate any additional data that follows
            try:
                conn.settimeout(0.3)
                while True:
                    more = conn.recv(4096)
                    if not more:
                        break
                    buf += more
            except socket.timeout:
                pass

            if verbose:
                for line in hex_dump(buf, "RX Raw").split("\n"):
                    log.info("  %s", line)

            # ── Step 3: Classify and build response ─────────────────
            req_type, parsed, matched = classify_request(buf)
            response = None

            if req_type == "SM_IDENTIFY":
                response = build_sm_identify_response(profile)
                log_detection(client_ip, client_port, tcp_port,
                              "SM_IDENTIFY",
                              f"SM_Identify from {client_ip}:{client_port}",
                              buf if verbose else b"")

            elif req_type == "MA_IDENTIFY":
                txn_id = parsed.get("txn_id", 1)
                response = build_ma_identification_response(profile, txn_id)
                log_detection(client_ip, client_port, tcp_port,
                              "MA_IDENTIFY",
                              f"MA_Identify (txn_id={txn_id})",
                              buf if verbose else b"")

            elif req_type == "LREQ":
                device_id = parsed.get("device_id", 0)
                response = build_lres(profile, device_id)
                log_detection(client_ip, client_port, tcp_port,
                              "LREQ",
                              f"LREQ handshake device_id=0x{device_id:08X}",
                              buf if verbose else b"")

            elif req_type == "FMS_READ":
                index = parsed.get("index", 0)
                length = parsed.get("length", 0)
                tag = parsed.get("tag", FMS_READ_TAG)

                if index >= 0x0100 and index <= 0x0104:
                    # DD parameter descriptor request
                    response = build_dd_descriptor_response(
                        profile, tag, index)
                    dtype = "DD_PARAM"
                else:
                    # Regular process variable read
                    response = build_fms_read_response(
                        profile, tag, index, length)
                    dtype = "PV"

                # Look up variable name for logging
                var_entry = VAR_LOOKUP.get(pname, {}).get(index, (f"idx=0x{index:04X}", "", ""))
                var_name = var_entry[0]
                log_detection(client_ip, client_port, tcp_port,
                              "FMS_READ",
                              f"{dtype} index=0x{index:04X} ({var_name}) "
                              f"len={length}",
                              buf if verbose else b"")

            else:
                # Unknown — try SM_Identify as generic fallback
                log_detection(client_ip, client_port, tcp_port,
                              "UNKNOWN",
                              f"Unrecognised request ({len(buf)}B) — "
                              f"sending generic SM_Identify",
                              buf)
                response = build_sm_identify_response(profile)

            # ── Step 4: Send response ──────────────────────────────
            if response:
                conn.sendall(response)
                if verbose:
                    for line in hex_dump(response, "TX Response").split("\n"):
                        log.info("  %s", line)
                else:
                    log.info("Conn[%d] sent %d-byte %s response",
                             conn_id, len(response), req_type)

            # ── Step 5: Check for pending alarms ────────────────────
            pending = _get_pending_alarms()
            if pending:
                alarm_msgs = [a["description"] for a in pending]
                log.warning(
                    "Conn[%d] pending alarms for %s:%d: %s",
                    conn_id, client_ip, client_port,
                    "; ".join(alarm_msgs))
                # Optional: inject alarm notification into connection
                for alarm in pending:
                    try:
                        notif = build_alarm_notification(profile, alarm)
                        conn.sendall(notif)
                    except OSError:
                        break

    except Exception as e:
        log.error("Conn[%d] error from %s:%d: %s",
                  conn_id, client_ip, client_port, e)
    finally:
        log.info("Conn[%d] closed from %s:%d", conn_id, client_ip, client_port)


def build_alarm_notification(profile: dict, alarm: dict) -> bytes:
    """Build an asynchronous alarm notification.

    Format (similar to FMS response but with alarm flag):
      tag (uint16 LE):   0xF1E3 (alarm notification tag)
      type (uint16 LE):  0x9001 (async notification)
      severity (uint16): 0=LO,1=HI,2=HIHI
      alarm_type (16B ASCII): alarm code
      value (float LE):  PV at time of alarm
    """
    severity_map = {"LOW": 0, "HIGH": 1, "HIGH_HIGH": 2}
    sev_code = severity_map.get(alarm["severity"], 0)
    atype_enc = alarm["alarm_type"].ljust(16, " ")[:16].encode("ascii")
    header = struct.pack("<HHHH", 0xF1E3, 0x9001, sev_code, 0x0000)
    body = atype_enc + struct.pack("<f", alarm["value"])
    return header + body


# ─── Server ────────────────────────────────────────────────────────────────

def start_server(ports: list, verbose: bool,
                 profile: dict, enable_alarms: bool):
    """Start the FF HSE honeypot server.

    Creates a listening socket per port and accepts connections in a loop,
    dispatching each to a handler thread.  Thread-per-connection means
    concurrent scanners see all ports as responsive.
    """
    # Tag the profile dict with its name for lookup
    profile["_name"] = profile.get("_name", "unknown")

    sockets = []
    alarm_threads = []

    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sock.settimeout(1.0)
            sockets.append((port, sock))
            log.info("Listening on 0.0.0.0:%d [%s] (profile=%s)",
                     port,
                     {1089: "HSE MA", 1090: "HSE SM", 1091: "HSE SM-alt"}
                     .get(port, "HSE"),
                     profile.get("_name", "?"))

        # Start alarm generator if requested
        if enable_alarms:
            pname = profile.get("_name", "temperature")
            _init_pv_drift(pname)
            t = threading.Thread(
                target=_alarm_generator,
                args=(pname,),
                daemon=True,
                name="alarm-gen",
            )
            t.start()
            alarm_threads.append(t)
            log.info("Alarm simulation enabled (profile=%s, interval=~12s)", pname)

        port_list = ", ".join(str(p) for p in ports)
        log.info("FF HSE honeypot running on port(s): %s", port_list)
        log.info("Profile: %s — %s %s",
                 profile.get("_name", "?"), profile.get("vendor", "?"),
                 profile.get("device_type", "?"))
        if enable_alarms:
            log.info("Alarms: ENABLED")
        log.info("Press Ctrl+C to stop.")
        log.info("")

        while True:
            for port_num, sock in sockets:
                try:
                    conn, addr = sock.accept()
                    # Thread-per-connection for concurrent handling
                    t = threading.Thread(
                        target=handle_connection,
                        args=(conn, addr, port_num, profile, verbose),
                        daemon=True,
                        name=f"conn-{addr[0]}:{addr[1]}",
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    log.debug("Accept error on port %d: %s", port_num, e)
                    continue

    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl+C)...")
    finally:
        _alarm_shutdown.set()
        for t in alarm_threads:
            t.join(timeout=2.0)
        for port_num, sock in sockets:
            sock.close()
        log.info("All ports closed.")


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FF HSE Honeypot Device Emulator — Foundation Fieldbus HSE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                                 # default ports\n"
            "  %(prog)s --profile temperature            # RTD temp transmitter\n"
            "  %(prog)s --profile pressure               # pressure transmitter\n"
            "  %(prog)s --profile flow                   # Coriolis flow meter\n"
            "  %(prog)s --profile valve                  # valve positioner\n"
            "  %(prog)s --port 1090 --port 1091          # SM ports only\n"
            "  %(prog)s --verbose                        # hex dump all traffic\n"
            "  %(prog)s --enable-alarms                  # periodic alarm sim\n"
        ),
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        action="append",
        choices=[1089, 1090, 1091],
        help="TCP port to listen on (default: 1089 1090 1091)",
    )
    parser.add_argument(
        "--profile", "-P",
        type=str,
        default="temperature",
        choices=list(PROFILES.keys()),
        help="Device profile to emulate (default: temperature)",
    )
    parser.add_argument(
        "--enable-alarms", "-a",
        action="store_true",
        help="Enable periodic alarm simulation on background thread",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose hex dump logging",
    )
    args = parser.parse_args()

    ports = args.port if args.port else [1089, 1090, 1091]
    ports = sorted(set(ports))
    if not ports:
        log.error("No valid ports specified.")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Deep-copy the selected profile so modifications don't affect master
    profile_name = args.profile
    profile = dict(PROFILES[profile_name])
    profile["_name"] = profile_name

    _init_pv_drift(profile_name)

    start_server(ports, args.verbose, profile, args.enable_alarms)


if __name__ == "__main__":
    main()
