#!/usr/bin/env python3
"""
OPC UA Honeypot Server — TCP 4840

Realistic OPC UA Binary protocol emulator for blue-team testing.
Supports full handshake, discovery services, read operations,
configurable PLC profiles, and detection logging.

All standard library — zero external dependencies.

Usage:
    python3 opcua_mock_server.py [--port 4840] [--host 0.0.0.0]
        [--profile siemens_s7|rockwell_logix|generic]
        [--endpoints 3] [--session-timeout 300]
"""

import socket
import struct
import sys
import threading
import argparse
import logging
import time
import os
import hashlib
import random
from datetime import datetime, timezone

# ── Constants ────────────────────────────────────────────────────────────────

# Message type tags
MSG_HEL = b'HEL'
MSG_ACK = b'ACK'
MSG_OPN = b'OPN'
MSG_CLO = b'CLO'
MSG_MSG = b'MSG'

# Chunk type byte
CHUNK_FINAL = ord('F')
CHUNK_ABORT = ord('A')

# Default ACK parameters
DEF_PROTOCOL_VER = 0
DEF_RECV_BUF = 65535
DEF_SEND_BUF = 65535
DEF_MAX_MSG_LEN = 65536
DEF_MAX_CHUNK = 0

# Service type IDs
SVC_OPN_REQ = 446
SVC_OPN_RESP = 447
SVC_CLO_REQ = 448
SVC_CLO_RESP = 449
SVC_FIND_SERVERS_REQ = 422
SVC_FIND_SERVERS_RESP = 423
SVC_GET_ENDPOINTS_REQ = 428
SVC_GET_ENDPOINTS_RESP = 429
SVC_READ_REQ = 631
SVC_READ_RESP = 632
SVC_BROWSE_REQ = 525
SVC_BROWSE_RESP = 526
SVC_WRITE_REQ = 634
SVC_WRITE_RESP = 635

# Attribute IDs
ATTR_NODE_CLASS = 1
ATTR_BROWSE_NAME = 2
ATTR_DISPLAY_NAME = 3
ATTR_DESCRIPTION = 4
ATTR_VALUE = 13
ATTR_DATA_TYPE = 14

# Status codes
STATUS_GOOD = 0
STATUS_BAD_NODE_ID_UNKNOWN = 0x80340000
STATUS_BAD_ATTR_ID_INVALID = 0x80350000
STATUS_BAD_SECURE_CHANNEL_ID = 0x803D0000

# Built-in OPC UA type codes for Variant
BT_NULL = 0
BT_BOOLEAN = 1
BT_INT32 = 6
BT_UINT32 = 7
BT_DOUBLE = 11
BT_STRING = 12
BT_DATETIME = 13
BT_BYTESTRING = 15
BT_NODE_ID = 17
BT_LOCALIZED_TEXT = 21

SESSION_TIMEOUT_DEFAULT = 300  # seconds

# ── Profile Definitions ──────────────────────────────────────────────────────

PROFILES = {
    'generic': {
        'name': 'Generic OPC UA Server',
        'app_uri': 'urn:localhost:opcua:server',
        'prod_uri': 'http://localhost/opcua',
        'manufacturer': 'Generic Manufacturer',
        'device_name': 'OPC UA Server',
        'serial': '00000000',
        'discovery_urls': ['opc.tcp://localhost:4840'],
    },
    'siemens_s7': {
        'name': 'SIMATIC S7-1500 OPC UA Server',
        'app_uri': 'urn:siemens:opcua:s7-1500',
        'prod_uri': 'http://siemens.com/automation/s7-1500',
        'manufacturer': 'Siemens AG',
        'device_name': 'SIMATIC S7-1500',
        'serial': 'S7-OPC-2024-001',
        'discovery_urls': ['opc.tcp://192.168.1.10:4840'],
    },
    'rockwell_logix': {
        'name': 'ControlLogix 5580 OPC UA Server',
        'app_uri': 'urn:rockwellautomation:opcua:controllogix',
        'prod_uri': 'http://rockwellautomation.com/products/controllogix',
        'manufacturer': 'Rockwell Automation Inc.',
        'device_name': 'ControlLogix 5580',
        'serial': 'CLX-OPC-2024-002',
        'discovery_urls': ['opc.tcp://192.168.1.20:4840'],
    },
}


# ── Encoding Primitives ──────────────────────────────────────────────────────
# ponytail: only the encodings needed for OPC UA Binary responses

def u8(v):
    return struct.pack("<B", v)

def u16(v):
    return struct.pack("<H", v)

def u32(v):
    return struct.pack("<I", v)

def i32(v):
    return struct.pack("<i", v)

def u64(v):
    return struct.pack("<Q", v)

def dbl(v):
    return struct.pack("<d", v)


def enc_string(s):
    """OPC UA Binary String: length-prefixed UTF-8. -1 = null."""
    if s is None:
        return b'\xff\xff\xff\xff'
    data = s.encode('utf-8')
    return u32(len(data)) + data


def enc_bytearray(data):
    """OPC UA ByteString."""
    if data is None:
        return b'\xff\xff\xff\xff'
    return u32(len(data)) + data


def enc_array(items, item_enc):
    """OPC UA array: length-prefixed sequence of encoded items. -1 = null."""
    if items is None:
        return i32(-1)
    buf = i32(len(items))
    for item in items:
        buf += item_enc(item)
    return buf


def enc_datetime(dt=None):
    """OPC UA DateTime = 100ns intervals since 1601-01-01 UTC."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return u64(int(delta.total_seconds() * 10000000))


def enc_node_id(namespace, identifier, id_type='numeric'):
    """NodeId encoding: TwoByte/FourByte (ns=0) or Numeric/String with optional ns."""
    if id_type == 'numeric':
        if namespace == 0:
            if 0 <= identifier <= 255:
                return u8(0x00) + u8(identifier)      # TwoByte
            return u8(0x01) + u16(identifier)          # FourByte
        # Numeric with namespace: bit7 + type2, then ns uint16, then id uint32
        return u8(0x82) + u16(namespace) + u32(identifier)
    # String NodeId
    data = identifier.encode('utf-8')
    if namespace == 0:
        return u8(0x03) + u32(len(data)) + data
    # String with namespace: bit7 + type3, then ns uint16, then string
    return u8(0x83) + u16(namespace) + u32(len(data)) + data


def enc_expanded_node_id(namespace, identifier, id_type='numeric'):
    """ExpandedNodeId — same as NodeId when no NamespaceUri/ServerIndex."""
    return enc_node_id(namespace, identifier, id_type)


def enc_qualified_name(ns_idx, name):
    return u16(ns_idx) + enc_string(name)


def enc_localized_text(text, locale=None):
    """LocalizedText: encoding mask + optional locale + optional text."""
    mask = 0
    buf = bytearray()
    if locale is not None:
        mask |= 0x01
    if text is not None:
        mask |= 0x02
    buf.append(mask)
    if locale is not None:
        buf += enc_string(locale)
    if text is not None:
        buf += enc_string(text)
    return bytes(buf)


# ── Variant & DataValue ──────────────────────────────────────────────────────

def enc_variant(value, btype=None):
    """Encode a Python value as an OPC UA Variant."""
    if btype is None:
        if isinstance(value, bool):
            btype = BT_BOOLEAN
        elif isinstance(value, int):
            btype = BT_INT32
        elif isinstance(value, float):
            btype = BT_DOUBLE
        elif isinstance(value, str):
            btype = BT_STRING
        elif value is None:
            btype = BT_NULL
        else:
            btype = BT_NULL

    buf = u8(btype)
    if btype == BT_NULL:
        pass
    elif btype == BT_BOOLEAN:
        buf += u8(1 if value else 0)
    elif btype == BT_INT32:
        buf += i32(value)
    elif btype == BT_UINT32:
        buf += u32(value)
    elif btype == BT_DOUBLE:
        buf += dbl(value)
    elif btype == BT_STRING:
        buf += enc_string(value)
    elif btype == BT_BYTESTRING:
        buf += enc_bytearray(value)
    elif btype == BT_DATETIME:
        buf += enc_datetime(value)
    elif btype == BT_LOCALIZED_TEXT:
        buf += enc_localized_text(value)
    elif btype == BT_NODE_ID:
        buf += enc_node_id(*value)
    return bytes(buf)


def enc_data_value(value, btype=None, status=STATUS_GOOD):
    """DataValue: encoding mask + value + status + timestamp."""
    mask = 0x07  # Value + StatusCode + SourceTimestamp
    if value is None:
        mask = 0x06  # just StatusCode + SourceTimestamp
    buf = u8(mask)
    if value is not None:
        buf += enc_variant(value, btype)
    buf += u32(status)
    buf += enc_datetime_now()
    return buf


def enc_datetime_now():
    return enc_datetime(datetime.now(timezone.utc))


# ── Variant/DataValue Parsing ────────────────────────────────────────────────

def parse_variant_value(data, offset):
    """Parse a Variant at offset, return (value, btype, new_offset)."""
    if offset >= len(data):
        return None, BT_NULL, offset
    enc_byte = data[offset]
    btype = enc_byte & 0x3F
    is_array = (enc_byte & 0x40) != 0
    off = offset + 1

    if is_array or btype == BT_NULL:
        return None, btype, off

    value = None
    if btype == BT_BOOLEAN and off < len(data):
        value = bool(data[off]); off += 1
    elif btype == BT_INT32 and off + 4 <= len(data):
        value = struct.unpack_from("<i", data, off)[0]; off += 4
    elif btype == BT_UINT32 and off + 4 <= len(data):
        value = struct.unpack_from("<I", data, off)[0]; off += 4
    elif btype == BT_DOUBLE and off + 8 <= len(data):
        value = struct.unpack_from("<d", data, off)[0]; off += 8
    elif btype == BT_STRING and off + 4 <= len(data):
        slen = struct.unpack_from("<I", data, off)[0]; off += 4
        if slen != 0xFFFFFFFF and slen > 0 and off + slen <= len(data):
            value = data[off:off+slen].decode('utf-8', errors='replace'); off += slen
    elif btype == BT_DATETIME:
        off += 8
    elif btype == BT_BYTESTRING and off + 4 <= len(data):
        blen = struct.unpack_from("<I", data, off)[0]; off += 4
        if blen != 0xFFFFFFFF and blen > 0:
            off += blen
    return value, btype, off


def parse_data_value(data, offset):
    """Parse a DataValue at offset, return (value, btype, new_offset)."""
    if offset >= len(data):
        return None, BT_NULL, offset
    mask = data[offset]
    off = offset + 1
    value = None
    btype = BT_NULL
    if mask & 0x01:
        value, btype, off = parse_variant_value(data, off)
    if mask & 0x02:
        off += 4  # StatusCode
    if mask & 0x04:
        off += 8  # SourceTimestamp
    if mask & 0x08:
        off += 8  # ServerTimestamp
    if mask & 0x10:
        off += 2  # SourcePicoseconds
    if mask & 0x20:
        off += 2  # ServerPicoseconds
    return value, btype, off


# ── Message Body Encoding Helpers ────────────────────────────────────────────

def enc_response_header(req_handle, status=STATUS_GOOD):
    """OPC UA ResponseHeader: timestamp + requestHandle + result + diag + table + addl."""
    buf = enc_datetime_now()       # Timestamp
    buf += u32(req_handle)         # RequestHandle
    buf += u32(status)             # ServiceResult
    buf += u8(0)                   # ServiceDiagnostics (no diag info)
    buf += i32(-1)                 # StringTable (null array)
    buf += u8(0) + u8(0) + u8(0)  # AdditionalHeader: TwoByteNodeId(0) + no body
    return buf


def enc_chunk(msg_type, chunk_type, body, channel_id=0):
    """Wrap a body in an OPC UA Binary chunk header."""
    header_size = 8 + 4 if msg_type in (MSG_OPN, MSG_CLO, MSG_MSG) else 8
    total = header_size + len(body)
    hdr = msg_type + bytes([chunk_type]) + u32(total)
    if msg_type in (MSG_OPN, MSG_CLO, MSG_MSG):
        hdr += u32(channel_id)
    return hdr + body


def enc_opn_asym_security_header():
    """AsymmetricSecurityHeader for SecurityPolicy None."""
    return enc_string("") + enc_bytearray(None) + enc_bytearray(None)


def enc_sym_security_header(token_id):
    """SymmetricSecurityHeader: just TokenId for None policy."""
    return u32(token_id)


def enc_seq_header(seq_num, req_id):
    return u32(seq_num) + u32(req_id)


# ── Message Handlers ─────────────────────────────────────────────────────────

def build_ack():
    """Build ACK message (fixed 28 bytes, no chunk framing)."""
    msg = MSG_ACK + b'\x00'
    msg += u32(28)
    msg += u32(DEF_PROTOCOL_VER)
    msg += u32(DEF_RECV_BUF)
    msg += u32(DEF_SEND_BUF)
    msg += u32(DEF_MAX_MSG_LEN)
    msg += u32(DEF_MAX_CHUNK)
    return msg


def build_opn_response(channel_id, token_id, req_id, seq_num):
    """OpenSecureChannel response body."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_OPN_RESP)
    body += enc_response_header(0)     # request handle = 0 for OPN
    body += u32(0)                     # ServerProtocolVersion
    # SecurityToken
    now = enc_datetime_now()
    body += u32(channel_id)            # ChannelId
    body += u32(token_id)              # TokenId
    body += now                        # CreatedAt
    body += u32(3600000)               # RevisedLifetime (1 hour in ms)
    body += enc_bytearray(os.urandom(32))  # ServerNonce
    return enc_chunk(MSG_OPN, CHUNK_FINAL, bytes(body), channel_id)


def build_find_servers_response(profile, req_handle, req_id, seq_num, channel_id, token_id):
    """FindServers response body with ApplicationDescription."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_FIND_SERVERS_RESP)
    body += enc_response_header(req_handle)

    def enc_app_desc():
        buf = bytearray()
        buf += enc_string(profile['app_uri'])
        buf += enc_string(profile['prod_uri'])
        buf += enc_localized_text(profile['name'])
        buf += u32(0)  # ApplicationType: Server
        buf += enc_string(None)  # GatewayServerUri
        buf += enc_string(None)  # DiscoveryProfileUri
        buf += enc_array(profile['discovery_urls'], enc_string)
        return bytes(buf)

    body += enc_array([profile], lambda p: enc_app_desc())
    return enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)


def build_get_endpoints_response(profile, num_endpoints, req_handle, req_id, seq_num, channel_id, token_id):
    """GetEndpoints response with EndpointDescription list."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_GET_ENDPOINTS_RESP)
    body += enc_response_header(req_handle)

    base_urls = profile['discovery_urls']
    # Build requested number of endpoint URLs
    ep_urls = []
    for i in range(num_endpoints):
        if i < len(base_urls):
            ep_urls.append(base_urls[i])
        else:
            ep_urls.append(f"opc.tcp://localhost:{4840 + i}")

    def enc_endpoint_desc(url):
        buf = bytearray()
        buf += enc_string(url)
        # Server ApplicationDescription (inline)
        buf += enc_string(profile['app_uri'])
        buf += enc_string(profile['prod_uri'])
        buf += enc_localized_text(profile['name'])
        buf += u32(0)  # ApplicationType: Server
        buf += enc_string(None)  # GatewayServerUri
        buf += enc_string(None)  # DiscoveryProfileUri
        buf += enc_array(profile['discovery_urls'], enc_string)
        # Continue endpoint description
        buf += enc_bytearray(None)  # ServerCertificate
        buf += u32(1)  # SecurityMode: None
        policy_uri = "http://opcfoundation.org/UA/SecurityPolicy#None"
        buf += enc_string(policy_uri)  # SecurityPolicyUri
        # UserIdentityTokens
        def enc_token():
            t = bytearray()
            t += enc_string("anonymous")
            t += u32(0)  # Anonymous
            t += enc_string(None)
            t += enc_string(None)
            t += enc_string(None)
            return bytes(t)
        buf += enc_array([None], lambda _: enc_token())
        buf += enc_string("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
        buf += u8(0)  # SecurityLevel
        return bytes(buf)

    body += enc_array(ep_urls, enc_endpoint_desc)
    return enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)


def build_read_response(nodes_to_read, addr_space, req_handle, req_id, seq_num, channel_id, token_id):
    """Read response with DataValue array."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_READ_RESP)
    body += enc_response_header(req_handle)

    results = []
    for node_id, attr_id in nodes_to_read:
        key = (node_id, attr_id)
        if key in addr_space:
            val, btype = addr_space[key]
            results.append(enc_data_value(val, btype))
        else:
            # Try matching just the node with generic Value attribute
            alt_key = (node_id, ATTR_VALUE)
            if alt_key in addr_space and attr_id not in (ATTR_VALUE, ATTR_DISPLAY_NAME, ATTR_NODE_CLASS):
                val, btype = addr_space[alt_key]
                results.append(enc_data_value(val, btype))
            elif attr_id == ATTR_DISPLAY_NAME:
                results.append(enc_data_value(f"Node {node_id}", BT_LOCALIZED_TEXT))
            elif attr_id == ATTR_NODE_CLASS:
                results.append(enc_data_value(1, BT_UINT32))  # Object
            elif attr_id == ATTR_BROWSE_NAME:
                results.append(enc_data_value(f"Node{node_id}", BT_STRING))
            elif attr_id == ATTR_DESCRIPTION:
                results.append(enc_data_value(None, status=STATUS_BAD_NODE_ID_UNKNOWN))
            else:
                results.append(enc_data_value(None, status=STATUS_BAD_NODE_ID_UNKNOWN))

    body += enc_array(results, lambda r: r)
    body += i32(-1)  # DiagnosticInfos (null array)
    return enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)


def build_browse_response(starting_node, profile, addr_space, req_handle, req_id, seq_num, channel_id, token_id):
    """Browse response with child references for the requested node."""
    children = _get_browse_children(starting_node, profile, addr_space)

    body = bytearray()
    body += enc_expanded_node_id(0, SVC_BROWSE_RESP)
    body += enc_response_header(req_handle)

    # Encode individual reference descriptions
    ref_enc_list = []
    for ref_type_id, is_fwd, node_id, bn, dn, nc, td in children:
        ref = bytearray()
        ref += enc_node_id(*ref_type_id)
        ref += u8(1 if is_fwd else 0)
        ref += enc_expanded_node_id(*node_id)
        ref += enc_qualified_name(0, bn)
        ref += enc_localized_text(dn)
        ref += u32(nc)
        ref += enc_expanded_node_id(*td)
        ref_enc_list.append(bytes(ref))

    # Single BrowseResult: StatusCode + ContinuationPoint + References
    result = bytearray()
    result += u32(STATUS_GOOD)
    result += enc_bytearray(None)  # ContinuationPoint (null = no more)
    result += enc_array(ref_enc_list, lambda r: r)  # References array
    body += enc_array([bytes(result)], lambda r: r)  # Results array (one BrowseResult)
    body += i32(-1)  # DiagnosticInfos (null)
    return enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)


def build_write_response(status_codes, req_handle, channel_id):
    """Write response with array of status codes."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_WRITE_RESP)
    body += enc_response_header(req_handle)
    body += enc_array(status_codes, lambda sc: u32(sc))
    body += i32(-1)  # DiagnosticInfos (null)
    return enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)


def build_clo_response(req_handle, channel_id):
    """CloseSecureChannel response."""
    body = bytearray()
    body += enc_expanded_node_id(0, SVC_CLO_RESP)
    body += enc_response_header(req_handle)
    return enc_chunk(MSG_CLO, CHUNK_FINAL, bytes(body), channel_id)


# ── Message Parsing ──────────────────────────────────────────────────────────

def parse_hello(data):
    """Parse HEL message, return dict of fields or None."""
    if len(data) < 32 or data[0:3] != MSG_HEL:
        return None
    pos = 4
    message_length = struct.unpack_from("<I", data, pos)[0]; pos += 4
    protocol_version = struct.unpack_from("<I", data, pos)[0]; pos += 4
    receive_buffer_size = struct.unpack_from("<I", data, pos)[0]; pos += 4
    send_buffer_size = struct.unpack_from("<I", data, pos)[0]; pos += 4
    max_message_length = struct.unpack_from("<I", data, pos)[0]; pos += 4
    max_chunk_count = struct.unpack_from("<I", data, pos)[0]; pos += 4
    endpoint_url_length = struct.unpack_from("<I", data, pos)[0]; pos += 4

    endpoint_url = ''
    if endpoint_url_length > 0 and pos + endpoint_url_length <= len(data):
        endpoint_url = data[pos:pos + endpoint_url_length].decode('utf-8', errors='replace')

    return {
        'message_length': message_length,
        'protocol_version': protocol_version,
        'receive_buffer_size': receive_buffer_size,
        'send_buffer_size': send_buffer_size,
        'max_message_length': max_message_length,
        'max_chunk_count': max_chunk_count,
        'endpoint_url_length': endpoint_url_length,
        'endpoint_url': endpoint_url,
    }


def skip_node_id(data, offset):
    """Skip past a NodeId at offset, return new offset. Returns -1 on error."""
    if offset >= len(data):
        return -1
    enc_byte = data[offset]
    has_ns = (enc_byte & 0x80) != 0
    vtype = enc_byte & 0x0F
    off = offset + 1

    if has_ns:
        off += 2  # uint16 namespace

    if vtype == 0x00:  # TwoByte
        off += 1
    elif vtype == 0x01:  # FourByte
        off += 2
    elif vtype == 0x02:  # Numeric
        off += 4
    elif vtype == 0x03:  # String
        if off + 4 > len(data):
            return -1
        slen = struct.unpack_from("<I", data, off)[0]
        off += 4
        if slen == 0xFFFFFFFF:
            pass  # null string
        else:
            off += slen
    elif vtype == 0x04:  # ByteString
        if off + 4 > len(data):
            return -1
        blen = struct.unpack_from("<I", data, off)[0]
        off += 4
        if blen != 0xFFFFFFFF:
            off += blen
    else:
        return -1  # unsupported
    return off


def parse_node_id_value(data, offset):
    """Parse a NodeId at offset and return (namespace, identifier, id_type, new_offset)."""
    if offset >= len(data):
        return None, offset
    enc_byte = data[offset]
    has_ns = (enc_byte & 0x80) != 0
    vtype = enc_byte & 0x0F
    off = offset + 1
    ns = 0

    if has_ns:
        ns = struct.unpack_from("<H", data, off)[0]
        off += 2

    if vtype == 0x00:  # TwoByte
        return (ns, data[off], 'numeric'), off + 1
    elif vtype == 0x01:  # FourByte
        return (ns, struct.unpack_from("<H", data, off)[0], 'numeric'), off + 2
    elif vtype == 0x02:  # Numeric
        return (ns, struct.unpack_from("<I", data, off)[0], 'numeric'), off + 4
    elif vtype == 0x03:  # String
        slen = struct.unpack_from("<I", data, off)[0]
        off += 4
        if slen == 0xFFFFFFFF:
            return (ns, None, 'string'), off
        return (ns, data[off:off+slen].decode('utf-8', errors='replace'), 'string'), off + slen
    return None, offset


def parse_service_request(data, offset):
    """Parse a service request from a MSG body at offset.
    Returns (service_id, request_handle, nodes_to_read, new_offset)
    where service_id is the numeric NodeId identifier of the request TypeId.
    nodes_to_read is only set for Read requests.
    """
    if offset >= len(data):
        return None, 0, [], offset

    # Parse ExpandedNodeId (like NodeId but with optional NamespaceUri and ServerIndex)
    enc_byte = data[offset]
    has_ns = (enc_byte & 0x80) != 0
    has_ns_uri = (enc_byte & 0x20) != 0
    has_srv_idx = (enc_byte & 0x40) != 0
    vtype = enc_byte & 0x0F
    off = offset + 1
    ns = 0
    service_id = None

    if has_ns:
        if off + 2 > len(data):
            return None, 0, [], off
        ns = struct.unpack_from("<H", data, off)[0]
        off += 2

    if vtype == 0x00:
        service_id = data[off]
        off += 1
    elif vtype == 0x01:
        if off + 2 > len(data):
            return None, 0, [], off
        service_id = struct.unpack_from("<H", data, off)[0]
        off += 2
    elif vtype == 0x02:
        if off + 4 > len(data):
            return None, 0, [], off
        service_id = struct.unpack_from("<I", data, off)[0]
        off += 4
    else:
        return None, 0, [], off

    # Skip NamespaceUri and ServerIndex if present
    if has_ns_uri:
        if off + 4 > len(data):
            return None, 0, [], off
        ns_len = struct.unpack_from("<I", data, off)[0]
        off += 4
        if ns_len != 0xFFFFFFFF and ns_len > 0:
            off += ns_len
    if has_srv_idx:
        off += 4

    # Now parse RequestHeader
    # AuthenticationToken: NodeId
    node_id, off = parse_node_id_value(data, off)
    if node_id is None:
        return None, 0, [], off

    # Timestamp: 8 bytes
    off += 8
    # RequestHandle: uint32
    if off + 4 > len(data):
        return None, 0, [], off
    req_handle = struct.unpack_from("<I", data, off)[0]
    off += 4

    # Skip ReturnDiagnostics (4), AuditEntryId (string), TimeoutHint (4)
    off += 4  # ReturnDiagnostics
    if off + 4 > len(data):
        return None, 0, [], off
    ae_len = struct.unpack_from("<I", data, off)[0]
    off += 4
    if ae_len != 0xFFFFFFFF and ae_len > 0:
        off += ae_len
    off += 4  # TimeoutHint

    # AdditionalHeader: ExtensionObject - skip it
    # It's a NodeId + encoding byte, simplest: try to skip
    nid, off = parse_node_id_value(data, off)
    if nid is None:
        return None, 0, [], off
    if off < len(data):
        ext_enc = data[off]
        off += 1
        if ext_enc == 0x01:
            if off + 4 <= len(data):
                blen = struct.unpack_from("<I", data, off)[0]
                off += 4
                if blen != 0xFFFFFFFF:
                    off += blen

    # --- Service-specific parsing ---
    nodes_to_read = []

    if service_id == SVC_GET_ENDPOINTS_REQ:
        # EndpointUrl: String
        if off + 4 <= len(data):
            url_len = struct.unpack_from("<I", data, off)[0]
            off += 4
            if url_len != 0xFFFFFFFF and url_len > 0:
                off += url_len
        # LocaleIds: array
        if off + 4 <= len(data):
            n_locales = struct.unpack_from("<i", data, off)[0]
            off += 4
            if n_locales > 0 and n_locales < 100:
                for _ in range(n_locales):
                    if off + 4 <= len(data):
                        loc_len = struct.unpack_from("<I", data, off)[0]
                        off += 4
                        if loc_len != 0xFFFFFFFF and loc_len > 0:
                            off += loc_len
        # ProfileUris: array
        if off + 4 <= len(data):
            n_profs = struct.unpack_from("<i", data, off)[0]
            off += 4

    elif service_id == SVC_FIND_SERVERS_REQ:
        # EndpointUrl: String
        if off + 4 <= len(data):
            url_len = struct.unpack_from("<I", data, off)[0]
            off += 4
            if url_len != 0xFFFFFFFF and url_len > 0:
                off += url_len
        # LocaleIds: array
        if off + 4 <= len(data):
            n_loc = struct.unpack_from("<i", data, off)[0]
            off += 4
            if n_loc > 0 and n_loc < 100:
                for _ in range(n_loc):
                    if off + 4 <= len(data):
                        ll = struct.unpack_from("<I", data, off)[0]
                        off += 4
                        if ll != 0xFFFFFFFF and ll > 0:
                            off += ll
        # ServerUris: array
        if off + 4 <= len(data):
            n_srv = struct.unpack_from("<i", data, off)[0]
            off += 4

    elif service_id == SVC_READ_REQ:
        # MaxAge: double
        off += 8
        # TimestampsToReturn: uint32
        off += 4
        # NodesToRead array
        if off + 4 <= len(data):
            n_nodes = struct.unpack_from("<i", data, off)[0]
            off += 4
            if n_nodes > 0 and n_nodes < 1000:
                for _ in range(n_nodes):
                    nid, off = parse_node_id_value(data, off)
                    if nid is None:
                        break
                    if off + 4 > len(data):
                        break
                    attr_id = struct.unpack_from("<I", data, off)[0]
                    off += 4
                    # IndexRange: String
                    if off + 4 <= len(data):
                        ir_len = struct.unpack_from("<I", data, off)[0]
                        off += 4
                        if ir_len != 0xFFFFFFFF and ir_len > 0:
                            off += ir_len
                    # DataEncoding: QualifiedName
                    if off + 2 <= len(data):
                        off += 2  # namespace index
                        if off + 4 <= len(data):
                            dn_len = struct.unpack_from("<I", data, off)[0]
                            off += 4
                            if dn_len != 0xFFFFFFFF and dn_len > 0:
                                off += dn_len
                    nodes_to_read.append((nid, attr_id))

    elif service_id == SVC_BROWSE_REQ:
        # ViewDescription: ViewId (NodeId) + Timestamp + ViewVersion
        _, off = parse_node_id_value(data, off)
        off += 8  # Timestamp
        off += 4  # ViewVersion
        off += 4  # MaxReferencesToReturn
        # ContinuationPoint (ByteString)
        if off + 4 <= len(data):
            cp_len = struct.unpack_from("<I", data, off)[0]; off += 4
            if cp_len != 0xFFFFFFFF and cp_len > 0:
                off += cp_len
        # StartingNode (NodeId) -- the key field for Browse
        starting_node, off = parse_node_id_value(data, off)
        if starting_node:
            nodes_to_read.append(starting_node)
        off += 4   # BrowseDirection
        off += 1   # IncludeSubtypes
        off += 4   # NodeClassMask
        off += 4   # ResultMask

    elif service_id == SVC_WRITE_REQ:
        # NodesToWrite array
        if off + 4 <= len(data):
            n_nodes = struct.unpack_from("<i", data, off)[0]; off += 4
            if n_nodes > 0 and n_nodes < 1000:
                for _ in range(n_nodes):
                    nid, off = parse_node_id_value(data, off)
                    if nid is None:
                        break
                    if off + 4 > len(data):
                        break
                    attr_id = struct.unpack_from("<I", data, off)[0]; off += 4
                    # IndexRange: String
                    if off + 4 <= len(data):
                        ir_len = struct.unpack_from("<I", data, off)[0]; off += 4
                        if ir_len != 0xFFFFFFFF and ir_len > 0:
                            off += ir_len
                    # Value: DataValue
                    val, btype, off = parse_data_value(data, off)
                    nodes_to_read.append((nid, attr_id, val, btype))

    return service_id, req_handle, nodes_to_read, off


# ── Hex Dump ─────────────────────────────────────────────────────────────────

def hex_dump(data, label=""):
    lines = []
    lines.append(f"─── {label} ({len(data)} bytes) ───")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_p = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_p = hex_p.ljust(47)
        ascii_p = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_p}  |{ascii_p}|")
    return "\n".join(lines)


# ── Detection Logging ────────────────────────────────────────────────────────

class DetectionLogger:
    """Structured detection logging for blue-team analysis."""

    def __init__(self):
        self.logger = logging.getLogger("opcua.honeypot")
        self._setup()

    def _setup(self):
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            fmt = logging.Formatter(
                "%(asctime)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(fmt)
            self.logger.addHandler(handler)

    def connection(self, remote):
        self.logger.info("CONNECT | %s", remote)

    def disconnect(self, remote):
        self.logger.info("DISCONNECT | %s", remote)

    def message(self, remote, msg_type, extra=""):
        self.logger.info("MSG | %s | %s %s", remote, msg_type, extra)

    def event(self, remote, event_type, detail=""):
        self.logger.info("EVENT | %s | %s %s", remote, event_type, detail)

    def error(self, remote, err_desc):
        self.logger.info("ERROR | %s | %s", remote, err_desc)


detect_log = DetectionLogger()


# ── Address Space ────────────────────────────────────────────────────────────

def make_address_space(profile):
    """Build address space dict {(node_id_tuple, attr_id): (value, builtin_type)}."""
    space = {}

    # ServerStatus.State (Running)
    space[((0, 2256, 'numeric'), ATTR_VALUE)] = (0, BT_INT32)
    space[((0, 2256, 'numeric'), ATTR_DISPLAY_NAME)] = ("Server State", BT_LOCALIZED_TEXT)
    space[((0, 2256, 'numeric'), ATTR_NODE_CLASS)] = (1, BT_UINT32)  # Object

    # CurrentTime
    space[((0, 2267, 'numeric'), ATTR_VALUE)] = (datetime.now(timezone.utc), BT_DATETIME)
    space[((0, 2267, 'numeric'), ATTR_DISPLAY_NAME)] = ("Current Time", BT_LOCALIZED_TEXT)

    # StartTime
    space[((0, 2268, 'numeric'), ATTR_VALUE)] = (datetime.now(timezone.utc), BT_DATETIME)
    space[((0, 2268, 'numeric'), ATTR_DISPLAY_NAME)] = ("Start Time", BT_LOCALIZED_TEXT)

    # ManufacturerName
    space[((0, 2266, 'numeric'), ATTR_VALUE)] = (profile['manufacturer'], BT_STRING)
    space[((0, 2266, 'numeric'), ATTR_DISPLAY_NAME)] = ("ManufacturerName", BT_LOCALIZED_TEXT)

    # ProductName
    space[((0, 2261, 'numeric'), ATTR_VALUE)] = (profile['name'], BT_STRING)
    space[((0, 2261, 'numeric'), ATTR_DISPLAY_NAME)] = ("ProductName", BT_LOCALIZED_TEXT)

    # ProductUri
    space[((0, 2262, 'numeric'), ATTR_VALUE)] = (profile['prod_uri'], BT_STRING)

    # Standard address space hierarchy nodes (for Browse)
    space[((0, 84, 'numeric'), ATTR_DISPLAY_NAME)] = ("Root", BT_LOCALIZED_TEXT)
    space[((0, 84, 'numeric'), ATTR_NODE_CLASS)] = (1, BT_UINT32)
    space[((0, 85, 'numeric'), ATTR_DISPLAY_NAME)] = ("Objects", BT_LOCALIZED_TEXT)
    space[((0, 85, 'numeric'), ATTR_NODE_CLASS)] = (1, BT_UINT32)
    space[((0, 86, 'numeric'), ATTR_DISPLAY_NAME)] = ("Types", BT_LOCALIZED_TEXT)
    space[((0, 86, 'numeric'), ATTR_NODE_CLASS)] = (1, BT_UINT32)
    space[((0, 87, 'numeric'), ATTR_DISPLAY_NAME)] = ("Views", BT_LOCALIZED_TEXT)
    space[((0, 87, 'numeric'), ATTR_NODE_CLASS)] = (1, BT_UINT32)

    # Vendor-specific namespace (ns=2) — device info
    space[((2, 'DeviceName', 'string'), ATTR_VALUE)] = (profile['device_name'], BT_STRING)
    space[((2, 'DeviceName', 'string'), ATTR_DISPLAY_NAME)] = ("DeviceName", BT_LOCALIZED_TEXT)

    space[((2, 'Manufacturer', 'string'), ATTR_VALUE)] = (profile['manufacturer'], BT_STRING)
    space[((2, 'Manufacturer', 'string'), ATTR_DISPLAY_NAME)] = ("Manufacturer", BT_LOCALIZED_TEXT)

    space[((2, 'SerialNumber', 'string'), ATTR_VALUE)] = (profile['serial'], BT_STRING)
    space[((2, 'SerialNumber', 'string'), ATTR_DISPLAY_NAME)] = ("SerialNumber", BT_LOCALIZED_TEXT)

    return space


# ── Browse Address Space Hierarchy ───────────────────────────────────────────

def _get_browse_children(starting_node, profile, addr_space):
    """Get child references for a given starting node.

    Returns list of (ref_type_id, is_forward, node_id, browse_name,
                     display_name, node_class, type_def) tuples.
    """
    ORG = (0, 35, 'numeric')          # Organizes reference type
    FOLDER_T = (0, 61, 'numeric')     # FolderType
    OBJ_T = (0, 58, 'numeric')        # BaseObjectType
    VAR_T = (0, 63, 'numeric')        # BaseDataVariableType

    CACHE = {
        (0, 84, 'numeric'): [  # RootFolder
            (ORG, True, (0, 85, 'numeric'), "Objects", "Objects", 1, FOLDER_T),
            (ORG, True, (0, 86, 'numeric'), "Types", "Types", 1, FOLDER_T),
            (ORG, True, (0, 87, 'numeric'), "Views", "Views", 1, FOLDER_T),
        ],
        (0, 85, 'numeric'): [  # Objects
            (ORG, True, (0, 2253, 'numeric'), "Server", "Server", 1, OBJ_T),
            (ORG, True, (2, 'DeviceName', 'string'), "DeviceName", "DeviceName", 2, VAR_T),
            (ORG, True, (2, 'Manufacturer', 'string'), "Manufacturer", "Manufacturer", 2, VAR_T),
            (ORG, True, (2, 'SerialNumber', 'string'), "SerialNumber", "SerialNumber", 2, VAR_T),
        ],
        (0, 2253, 'numeric'): [  # Server
            (ORG, True, (0, 2256, 'numeric'), "ServerState", "Server State", 2, VAR_T),
            (ORG, True, (0, 2267, 'numeric'), "CurrentTime", "Current Time", 2, VAR_T),
            (ORG, True, (0, 2268, 'numeric'), "StartTime", "Start Time", 2, VAR_T),
            (ORG, True, (0, 2266, 'numeric'), "ManufacturerName", "Manufacturer Name", 2, VAR_T),
            (ORG, True, (0, 2261, 'numeric'), "ProductName", "Product Name", 2, VAR_T),
            (ORG, True, (0, 2262, 'numeric'), "ProductUri", "Product URI", 2, VAR_T),
        ],
        (0, 86, 'numeric'): [  # Types
            (ORG, True, (0, 88, 'numeric'), "ObjectTypes", "Object Types", 1, FOLDER_T),
            (ORG, True, (0, 89, 'numeric'), "VariableTypes", "Variable Types", 1, FOLDER_T),
        ],
    }
    return CACHE.get(starting_node, [])


# ── Client Handler ───────────────────────────────────────────────────────────

def handle_client(client_sock, addr, profile_name, num_endpoints, session_timeout):
    """Handle a full OPC UA session for one client connection."""
    remote = f"{addr[0]}:{addr[1]}"
    detect_log.connection(remote)
    client_sock.settimeout(60.0)
    buf = b""

    # Session state
    profile = PROFILES.get(profile_name, PROFILES['generic'])
    addr_space = make_address_space(profile)
    channel_id = 0
    token_id = 0
    seq_num = 0
    handshake_done = False
    token_created = 0
    token_lifetime = 3600000
    session_active = False

    try:
        while True:
            if not buf:
                try:
                    chunk = client_sock.recv(4096)
                except socket.timeout:
                    detect_log.event(remote, "TIMEOUT", "idle")
                    break
                if not chunk:
                    break
                buf += chunk

            # Peek at message type
            if len(buf) < 8:
                try:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    continue
                except socket.timeout:
                    break

            msg_type = buf[0:3]
            msg_type_str = msg_type.decode('ascii', errors='replace')

            if msg_type == MSG_HEL:
                # HEL: no secureChannelId field, fixed format
                if len(buf) < 4:
                    buf_peek = buf[0:4]
                else:
                    buf_peek = buf[0:4]

                if len(buf) < 8:
                    need = 8
                else:
                    msg_len = struct.unpack_from("<I", buf, 4)[0]
                    need = msg_len

                if len(buf) < need:
                    try:
                        chunk = client_sock.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                        continue
                    except socket.timeout:
                        break

                packet = buf[:need]
                buf = buf[need:]

                detect_log.message(remote, "HEL")
                print(hex_dump(packet, label=f"RECV HEL from {remote}"))

                fields = parse_hello(packet)
                if fields:
                    print(f"  >>> PARSED HEL <<<")
                    print(f"    Protocol version:    {fields['protocol_version']}")
                    print(f"    Receive buffer size: {fields['receive_buffer_size']}")
                    print(f"    Send buffer size:    {fields['send_buffer_size']}")
                    print(f"    Max message length:  {fields['max_message_length']}")
                    print(f"    Max chunk count:     {fields['max_chunk_count']}")
                    if fields['endpoint_url']:
                        print(f"    Endpoint URL:        {fields['endpoint_url']}")

                ack = build_ack()
                print(hex_dump(ack, label=f"SEND ACK to {remote}"))
                client_sock.sendall(ack)
                detect_log.message(remote, "ACK")

            elif msg_type in (MSG_OPN, MSG_CLO, MSG_MSG):
                # These have 8-byte header + 4-byte secureChannelId
                if len(buf) < 8:
                    continue
                msg_len = struct.unpack_from("<I", buf, 4)[0]
                # Validate: msg_len must be at least 12 (8 header + 4 channelId)
                if msg_len < 12 or msg_len > 65536:
                    detect_log.error(remote, f"Invalid message size: {msg_len}")
                    buf = b""
                    continue

                if len(buf) < msg_len:
                    try:
                        chunk = client_sock.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                        continue
                    except socket.timeout:
                        break

                packet = buf[:msg_len]
                buf = buf[msg_len:]

                pkt_channel_id = struct.unpack_from("<I", packet, 8)[0]

                if msg_type == MSG_OPN:
                    detect_log.message(remote, "OPN", f"channel={pkt_channel_id}")
                    print(hex_dump(packet, label=f"RECV OPN from {remote}"))

                    if not handshake_done:
                        channel_id = random.randint(1, 0x7FFFFFFF)
                        token_id = random.randint(1, 0x7FFFFFFF)
                        seq_num = 1
                        token_created = time.time()
                        handshake_done = True

                    resp = build_opn_response(channel_id, token_id, 0, seq_num)
                    seq_num += 1
                    print(hex_dump(resp, label=f"SEND OPN to {remote}"))
                    client_sock.sendall(resp)
                    detect_log.message(remote, "OPN_RESP", f"channel={channel_id} token=[REDACTED]")

                elif msg_type == MSG_CLO:
                    detect_log.message(remote, "CLO")
                    resp = build_clo_response(0, channel_id)
                    print(hex_dump(resp, label=f"SEND CLO to {remote}"))
                    try:
                        client_sock.sendall(resp)
                    except OSError:
                        pass
                    detect_log.message(remote, "CLO_RESP")
                    break

                elif msg_type == MSG_MSG:
                    if len(packet) < 16:
                        continue
                    pkt_token_id = struct.unpack_from("<I", packet, 12)[0]
                    # SequenceHeader starts at offset 16
                    if len(packet) < 24:
                        continue
                    pkt_seq_num = struct.unpack_from("<I", packet, 16)[0]
                    pkt_req_id = struct.unpack_from("<I", packet, 20)[0]
                    body_offset = 24

                    detect_log.message(remote, "MSG",
                        f"channel={pkt_channel_id} token=[REDACTED] seq={pkt_seq_num}")

                    print(hex_dump(packet, label=f"RECV MSG from {remote}"))

                    # Validate secure channel
                    if pkt_channel_id != channel_id:
                        detect_log.error(remote, f"Invalid channel: {pkt_channel_id}")
                        break

                    # Parse service request
                    service_id, req_handle, nodes_to_read, _ = parse_service_request(packet, body_offset)

                    if service_id is None:
                        detect_log.error(remote, "Failed to parse service request")
                        continue

                    detect_log.event(remote, "SERVICE", f"id={service_id} handle={req_handle}")

                    if service_id == SVC_GET_ENDPOINTS_REQ:
                        resp = build_get_endpoints_response(
                            profile, num_endpoints, req_handle,
                            pkt_req_id, seq_num, channel_id, pkt_token_id)
                        seq_num += 1
                        print(hex_dump(resp, label=f"SEND GetEndpoints RESP to {remote}"))
                        client_sock.sendall(resp)
                        detect_log.message(remote, "GET_ENDPOINTS_RESP")

                    elif service_id == SVC_FIND_SERVERS_REQ:
                        resp = build_find_servers_response(
                            profile, req_handle,
                            pkt_req_id, seq_num, channel_id, pkt_token_id)
                        seq_num += 1
                        print(hex_dump(resp, label=f"SEND FindServers RESP to {remote}"))
                        client_sock.sendall(resp)
                        detect_log.message(remote, "FIND_SERVERS_RESP")

                    elif service_id == SVC_READ_REQ:
                        resp = build_read_response(
                            nodes_to_read, addr_space, req_handle,
                            pkt_req_id, seq_num, channel_id, pkt_token_id)
                        seq_num += 1
                        print(hex_dump(resp, label=f"SEND Read RESP to {remote}"))
                        client_sock.sendall(resp)
                        detect_log.message(remote, "READ_RESP",
                            f"nodes={len(nodes_to_read)}")

                    elif service_id == SVC_BROWSE_REQ:
                        starting_node = nodes_to_read[0] if nodes_to_read else None
                        if starting_node:
                            resp = build_browse_response(
                                starting_node, profile, addr_space, req_handle,
                                pkt_req_id, seq_num, channel_id, pkt_token_id)
                            seq_num += 1
                            print(hex_dump(resp, label=f"SEND Browse RESP to {remote}"))
                            client_sock.sendall(resp)
                            detect_log.message(remote, "BROWSE_RESP",
                                f"node={starting_node}")
                        else:
                            detect_log.error(remote, "Browse with no starting node")
                            body = bytearray()
                            body += enc_expanded_node_id(0, SVC_BROWSE_RESP)
                            body += enc_response_header(req_handle, STATUS_GOOD)
                            body += i32(0)  # empty results
                            body += i32(-1)  # null DiagnosticInfos
                            resp = enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)
                            try:
                                client_sock.sendall(resp)
                            except OSError:
                                pass

                    elif service_id == SVC_WRITE_REQ:
                        num_writes = len(nodes_to_read)
                        for entry in nodes_to_read:
                            if len(entry) >= 2:
                                nid_w = entry[0]; attr_w = entry[1]
                                val_w = entry[2] if len(entry) >= 3 else None
                                detect_log.event(remote, "WRITE",
                                    f"node={nid_w} attr={attr_w} value={val_w}")
                        status_codes = [STATUS_GOOD] * num_writes if num_writes else [STATUS_GOOD]
                        resp = build_write_response(status_codes, req_handle, channel_id)
                        seq_num += 1
                        print(hex_dump(resp, label=f"SEND Write RESP to {remote}"))
                        client_sock.sendall(resp)
                        detect_log.message(remote, "WRITE_RESP",
                            f"nodes={num_writes}")

                    else:
                        # Unknown service — respond with generic OK or error
                        # Build a minimal empty response for unknown service
                        detect_log.event(remote, "UNKNOWN_SERVICE", f"id={service_id}")
                        # Send service-specific empty response
                        body = bytearray()
                        body += enc_expanded_node_id(0, service_id + 1)
                        body += enc_response_header(req_handle, STATUS_GOOD)
                        if service_id in (SVC_READ_REQ + 1,):
                            pass  # Read response needs no extra fields after header
                        resp = enc_chunk(MSG_MSG, CHUNK_FINAL, bytes(body), channel_id)
                        try:
                            client_sock.sendall(resp)
                        except OSError:
                            pass

            else:
                detect_log.error(remote, f"Unknown message type: {msg_type_str}")
                buf = b""
                continue

    except socket.timeout:
        detect_log.event(remote, "TIMEOUT", "connection idle")
    except ConnectionResetError:
        detect_log.event(remote, "RST", "connection reset")
    except ConnectionAbortedError:
        detect_log.event(remote, "ABORT", "connection aborted")
    except OSError as e:
        detect_log.error(remote, f"Socket error: {e}")
    except Exception as e:
        detect_log.error(remote, f"Unhandled: {type(e).__name__}: {e}")
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        detect_log.disconnect(remote)
        print(f"[*] {remote}: Connection closed\n")


# ── Main Server ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OPC UA Honeypot Server — blue-team detection testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Profiles:\n"
            "  generic       Generic OPC UA Server (default)\n"
            "  siemens_s7    SIMATIC S7-1500\n"
            "  rockwell_logix  ControlLogix 5580\n"
            "\n"
            "Examples:\n"
            "  %(prog)s --port 4840\n"
            "  %(prog)s --profile siemens_s7 --endpoints 5\n"
            "  %(prog)s --port 4840 --host 0.0.0.0 --profile rockwell_logix\n"
        )
    )
    parser.add_argument('--port', '-p', type=int, default=4840,
                        help='Port to listen on (default: 4840)')
    parser.add_argument('--host', '-H', type=str, default='0.0.0.0',
                        help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--profile', type=str, default='generic',
                        choices=list(PROFILES.keys()),
                        help='PLC profile to emulate (default: generic)')
    parser.add_argument('--endpoints', '-e', type=int, default=3,
                        help='Number of endpoints in GetEndpoints response (default: 3)')
    parser.add_argument('--session-timeout', type=int, default=SESSION_TIMEOUT_DEFAULT,
                        help=f'Session timeout in seconds (default: {SESSION_TIMEOUT_DEFAULT})')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose debug logging')

    args = parser.parse_args()
    profile = PROFILES[args.profile]

    if args.verbose:
        logging.getLogger("opcua.honeypot").setLevel(logging.DEBUG)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.host, args.port))
        server.listen(10)
    except PermissionError:
        print(
            f"ERROR: Binding to {args.host}:{args.port} requires root.\n"
            f"  Try: sudo {sys.argv[0]} --port {args.port}\n"
            f"  Or: {sys.argv[0]} --port 14840  (non-privileged port)"
        )
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: Failed to bind: {e}")
        sys.exit(1)

    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║              OPC UA Honeypot Server                         ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on  {args.host}:{args.port:<5}                               ║
║  Profile:      {args.profile:<39}║
║  Endpoints:    {args.endpoints:<39}║
║  PID:          {os.getpid():<39}║
║  Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<25}║
║                                                              ║
║  Profiles supported: generic, siemens_s7, rockwell_logix     ║
║  Services: FindServers, GetEndpoints, Read, Browse, Write    ║
║                                                              ║
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

    try:
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, args.profile, args.endpoints, args.session_timeout),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print(f"\n[*] Shutting down (received Ctrl+C)...")
    finally:
        server.close()
        print("[*] Server stopped.")


if __name__ == "__main__":
    main()
