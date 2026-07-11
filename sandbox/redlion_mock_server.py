#!/usr/bin/env python3
"""
Red Lion Controls Crimson v3 Honeypot Emulator

Honeypot-grade emulator of a Red Lion Controls HMI/PLC device running
Crimson v3 firmware. Listens on TCP port 789 (default) and responds to
the proprietary Crimson v3 protocol with realistic device behavior,
configurable models, simulated HMI tags, and security detection logging.

Supports two protocol modes:
  1. Legacy identification probe (16-byte zero-filled) — backward compatible
     with NSE scripts like redlion-cr3-info-improved.nse
  2. STX-framed command/response protocol (0x02/0x03 framing) with multiple
     command handlers, password challenge-response, and tag database

Usage:
    python3 redlion_mock_server.py
    python3 redlion_mock_server.py --port 789 --model G310C2 --num-tags 10
    python3 redlion_mock_server.py --port 789 --verbose
    sudo python3 redlion_mock_server.py --port 789

NOTE: Port 789 is below 1024 and requires root on Unix. Use sudo or
      choose a higher port with --port.
"""

import argparse
import logging
import random
import socket
import struct
import sys
import threading
import time

# ── Protocol constants ────────────────────────────────────────────────

STX = 0x02
ETX = 0x03

CMD_READ_DEVICE_INFO = 0x01
CMD_READ_TAG_VALUE = 0x02
CMD_READ_CONFIG = 0x03
CMD_PROTOCOL_VERSION = 0x04
CMD_READ_STATUS = 0x05
CMD_LOGIN_CHALLENGE = 0x10
CMD_LOGIN_RESPONSE = 0x11

PROTOCOL_VERSION_STRING = "Crimson v3.0"

# ── Device model configurations ──────────────────────────────────────

DEVICE_MODELS = {
    "G307C2": {
        "firmware": "Crimson 3.0",
        "part_number": "MNGR-BASE",
        "memory": "16MB",
        "vendor": "Red Lion Controls",
        "hw_rev": "1.2A",
    },
    "G308C2": {
        "firmware": "Crimson 3.1",
        "part_number": "MNGR-BASE",
        "memory": "32MB",
        "vendor": "Red Lion Controls",
        "hw_rev": "1.3B",
    },
    "G310C2": {
        "firmware": "Crimson 3.2",
        "part_number": "MNGR-BASE",
        "memory": "32MB",
        "vendor": "Red Lion Controls",
        "hw_rev": "2.0A",
    },
    "G315C2": {
        "firmware": "Crimson 3.3",
        "part_number": "MNGR-PLUS",
        "memory": "64MB",
        "vendor": "Red Lion Controls",
        "hw_rev": "2.1B",
    },
}

# ── Tag name pool for simulated HMI tags ─────────────────────────────

TAG_NAME_POOL = [
    "TankLevel", "PumpSpeed", "ValvePosition", "Temperature", "Pressure",
    "FlowRate", "MotorCurrent", "PowerUsage", "Frequency", "Humidity",
    "LevelSensor", "RPM", "TorqueOutput", "VoltageInput", "CurrentOutput",
    "PressureSetpoint", "TemperatureSP", "FlowSetpoint", "PumpStatus",
    "AlarmCode", "MotorSpeed", "OutputPower", "WaterLevel", "LinePressure",
    "EncoderPosition", "PIDOutput", "CycleCount", "BatchTotal",
]

# ── Global server state (thread-safe via lock) ───────────────────────

_global_lock = threading.Lock()
_connection_count = 0
_active_sessions = 0
_error_count = 0
_server_start = time.time()

# Unique per-run serial number
_serial_number = "RL-{}-{:04X}".format(
    time.strftime("%Y%m%d"), random.randint(0, 0xFFFF)
)


# ══════════════════════════════════════════════════════════════════════
#  Tag Database
# ══════════════════════════════════════════════════════════════════════

class TagDatabase:
    """In-memory simulated HMI tag database with value jitter."""

    def __init__(self, num_tags=10):
        self._tags = {}
        names = random.sample(
            TAG_NAME_POOL, min(num_tags, len(TAG_NAME_POOL))
        )
        # If we need more tags than the pool, generate numbered extras
        if len(names) < num_tags:
            for i in range(num_tags - len(names)):
                names.append(f"UserTag_{i + 1}")
        for name in names:
            self._tags[name] = self._generate_base(name)

    @staticmethod
    def _generate_base(name):
        """Return a realistic base value for a tag based on its name."""
        nl = name.lower()
        if "level" in nl or "tank" in nl or "water" in nl:
            return round(random.uniform(0, 100), 1)
        if "pump" in nl or "speed" in nl or "rpm" in nl:
            return round(random.uniform(0, 3600), 0)
        if "valve" in nl or "position" in nl or "encoder" in nl:
            return round(random.uniform(0, 100), 1)
        if "temp" in nl:
            return round(random.uniform(20, 150), 1)
        if "pressure" in nl or "linepressure" in nl:
            return round(random.uniform(0, 300), 1)
        if "flow" in nl:
            return round(random.uniform(0, 500), 1)
        if "motor" in nl or "current" in nl:
            return round(random.uniform(0, 100), 1)
        if "power" in nl or "outputpower" in nl:
            return round(random.uniform(0, 50000), 0)
        if "freq" in nl:
            return round(random.uniform(0, 60), 1)
        if "humid" in nl:
            return round(random.uniform(0, 100), 1)
        if "voltage" in nl or "volt" in nl:
            return round(random.uniform(0, 480), 1)
        if "torque" in nl:
            return round(random.uniform(0, 2000), 1)
        if "alarm" in nl:
            return random.choice([0, 0, 0, 0, 1, 2, 3])
        if "status" in nl or "cycle" in nl or "batch" in nl:
            return random.choice([0, 1, 1, 1, 2])
        if "setpoint" in nl or "sp" in nl or "pid" in nl:
            return round(random.uniform(0, 100), 1)
        return round(random.uniform(0, 1000), 2)

    def read(self, name):
        """Read a tag value with slight jitter to simulate real-world drift."""
        if name not in self._tags:
            return None
        base = self._tags[name]
        jitter = base * random.uniform(-0.03, 0.03)
        if isinstance(base, int):
            return int(round(base + jitter))
        return round(base + jitter, 2)

    @property
    def names(self):
        return list(self._tags.keys())


# ══════════════════════════════════════════════════════════════════════
#  Protocol helpers
# ══════════════════════════════════════════════════════════════════════

def build_legacy_device_info(model_key):
    """Build the legacy binary blob for a 16-byte zero-filled probe.

    This preserves backward compatibility with NSE scripts that send
    a 16-byte zero-filled identification probe and expect a fixed-offset
    binary response containing manufacturer, model, and firmware strings.
    """
    cfg = DEVICE_MODELS[model_key]
    buf = bytearray()

    # Header: fixed signature bytes
    buf.extend(b'\x06\x00\x01\x00')
    # Payload length placeholder (4 bytes) — filled at the end
    buf.extend(b'\x00\x00\x00\x00')
    # Reserved / zero padding
    buf.extend(b'\x00' * 8)

    # --- ASCII identity block at offset 16 ---

    # Manufacturer (16..35)
    buf.extend(b'Red Lion Controls\x00')
    while len(buf) < 36:
        buf.append(0x00)

    # Model (36..55)
    buf.extend(model_key.encode())
    buf.append(0x00)
    while len(buf) < 56:
        buf.append(0x00)

    # Firmware version (56..79)
    buf.extend(cfg["firmware"].encode())
    buf.append(0x00)
    while len(buf) < 80:
        buf.append(0x00)

    # Serial number (80..103)
    buf.extend(_serial_number.encode())
    buf.append(0x00)
    while len(buf) < 104:
        buf.append(0x00)

    # Part number (104..127)
    buf.extend(cfg["part_number"].encode())
    buf.append(0x00)
    while len(buf) < 128:
        buf.append(0x00)

    # Write payload length at bytes 4-7 (total minus 8-byte prefix)
    struct.pack_into('>I', buf, 4, len(buf) - 8)
    return bytes(buf)


def build_stx_response(cmd, data):
    """Wrap response data in an STX-framed envelope.

    Format: STX + length_byte + command + data + ETX
    Length = 1 (command) + len(data)
    """
    length = 1 + len(data)
    return bytes([STX, length, cmd]) + data + bytes([ETX])


def parse_stx_request(data):
    """Parse an STX-framed request.

    Returns (command, payload_bytes) or None if the data doesn't look
    like a valid STX-framed message.

    Format: STX + length_byte + command + payload + [ETX]
    Length includes the command byte (1) plus payload length.
    ETX is treated as optional — some clients may omit it.
    """
    if len(data) < 4 or data[0] != STX:
        return None

    declared_len = data[1]
    cmd = data[2]
    # Payload = declared length - 1 (for the command byte itself)
    payload_len = declared_len - 1
    if payload_len < 0:
        return None

    # Make sure we have enough bytes
    if len(data) < 3 + payload_len:
        return None

    payload = data[3:3 + payload_len]
    return cmd, payload


# ══════════════════════════════════════════════════════════════════════
#  Honeypot server
# ══════════════════════════════════════════════════════════════════════

class RedLionHoneypot:
    """Red Lion Crimson v3 honeypot — thread-per-connection server."""

    def __init__(self, host, port, model_key, num_tags, verbose):
        self.host = host
        self.port = port
        self.model_key = model_key
        self.cfg = DEVICE_MODELS[model_key]
        self.tags = TagDatabase(num_tags)
        self.legacy_resp = build_legacy_device_info(model_key)
        self.verbose = verbose
        self.log = logging.getLogger("redlion")

    # ── Command handlers ──────────────────────────────────────────

    def _cmd_device_info(self):
        """CMD 0x01 — Read Device Info.

        Returns model, firmware, part number, vendor, serial number as
        null-terminated strings concatenated in the payload.
        """
        data = b''
        for field in [self.model_key, self.cfg["firmware"],
                      self.cfg["part_number"], self.cfg["vendor"],
                      self.cfg["hw_rev"], _serial_number]:
            data += field.encode() + b'\x00'
        return build_stx_response(CMD_READ_DEVICE_INFO, data)

    def _cmd_tag_value(self, payload):
        """CMD 0x02 — Read Tag Value.

        Payload is the tag name (null-terminated). Returns the tag's
        current value packed as a 32-bit IEEE-754 float, or -1.0 if
        the tag doesn't exist.
        """
        raw_name = payload.split(b'\x00')[0] if b'\x00' in payload else payload
        tag_name = raw_name.decode("utf-8", errors="replace")

        value = self.tags.read(tag_name)
        if value is None:
            value = -1.0
        data = struct.pack("<f", float(value))
        return build_stx_response(CMD_READ_TAG_VALUE, data), tag_name

    def _cmd_config(self):
        """CMD 0x03 — Read Configuration.

        Returns a semicolon-delimited key=value config string.
        """
        uptime = int(time.time() - _server_start)
        config = (
            f"Model={self.model_key};"
            f"Firmware={self.cfg['firmware']};"
            f"PartNumber={self.cfg['part_number']};"
            f"Memory={self.cfg['memory']};"
            f"HWRev={self.cfg['hw_rev']};"
            f"Serial={_serial_number};"
            f"Uptime={uptime}s;"
            f"Connections={_connection_count}"
        )
        return build_stx_response(CMD_READ_CONFIG, config.encode())

    def _cmd_protocol_version(self):
        """CMD 0x04 — Protocol Version."""
        return build_stx_response(
            CMD_PROTOCOL_VERSION, PROTOCOL_VERSION_STRING.encode()
        )

    def _cmd_status(self):
        """CMD 0x05 — Read Status.

        Returns uptime, connection stats, and model info.
        """
        uptime = int(time.time() - _server_start)
        status = (
            f"Uptime={uptime}s;"
            f"Connections={_connection_count};"
            f"ActiveSessions={_active_sessions};"
            f"Errors={_error_count};"
            f"Model={self.model_key};"
            f"Serial={_serial_number}"
        )
        return build_stx_response(CMD_READ_STATUS, status.encode())

    def _cmd_login_challenge(self):
        """CMD 0x10 — Login Challenge.

        Returns 8 random bytes as a challenge token. The honeypot
        accepts any non-empty response in _cmd_login_response.
        """
        challenge = bytes(random.randint(0, 255) for _ in range(8))
        return build_stx_response(CMD_LOGIN_CHALLENGE, challenge)

    def _cmd_login_response(self, payload):
        """CMD 0x11 — Login Response.

        Accepts any non-empty payload as valid (honeypot behavior).
        Returns 0x00000000 (success) for non-empty, 0x00000001 (fail)
        for empty.
        """
        if len(payload) > 0:
            result = b'\x00\x00\x00\x00'
        else:
            result = b'\x00\x00\x00\x01'
        return build_stx_response(CMD_LOGIN_RESPONSE, result)

    # ── Client handler ────────────────────────────────────────────

    def handle_client(self, conn, addr):
        """Handle one client connection. Reads commands in a loop."""
        global _connection_count, _active_sessions, _error_count

        with _global_lock:
            _connection_count += 1
            _active_sessions += 1
            cid = _connection_count

        client = f"{addr[0]}:{addr[1]}"
        self.log.info("[%s] #%d — connection established", client, cid)

        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break  # clean disconnect

                self.log.info(
                    "[%s] RX (%d bytes): %s",
                    client, len(data), data.hex()
                )
                if self.verbose:
                    self.log.debug(
                        "[%s] HEX DUMP:\n%s", client, _hexdump(data)
                    )

                # ── Legacy 16-byte zero probe ────────────────
                if len(data) >= 16 and all(b == 0 for b in data[:16]):
                    self.log.info(
                        "[%s] Legacy identification probe → device info",
                        client
                    )
                    conn.sendall(self.legacy_resp)
                    self.log.info(
                        "[%s] TX (%d bytes): %s",
                        client, len(self.legacy_resp), self.legacy_resp.hex()
                    )
                    continue

                # ── STX-framed command dispatch ──────────────
                parsed = parse_stx_request(data)
                if parsed is None:
                    self.log.warning(
                        "[%s] Unparseable data | DETECTION: "
                        "BadProtocol:%s",
                        client, data.hex()
                    )
                    with _global_lock:
                        _error_count += 1
                    continue

                cmd, payload = parsed
                self.log.info(
                    "[%s] STX command 0x%02X, payload=%s | "
                    "DETECTION: Command:0x%02X",
                    client, cmd, payload.hex(), cmd
                )

                if cmd == CMD_READ_DEVICE_INFO:
                    resp = self._cmd_device_info()
                    conn.sendall(resp)
                    self.log.info("[%s] → device info (%d bytes)", client, len(resp))

                elif cmd == CMD_READ_TAG_VALUE:
                    resp, tag_name = self._cmd_tag_value(payload)
                    conn.sendall(resp)
                    self.log.info(
                        "[%s] → tag '%s' value (%d bytes) | "
                        "DETECTION: TagRead:%s",
                        client, tag_name, len(resp), tag_name
                    )

                elif cmd == CMD_READ_CONFIG:
                    resp = self._cmd_config()
                    conn.sendall(resp)
                    self.log.info("[%s] → configuration (%d bytes)", client, len(resp))

                elif cmd == CMD_PROTOCOL_VERSION:
                    resp = self._cmd_protocol_version()
                    conn.sendall(resp)
                    self.log.info("[%s] → protocol version (%d bytes)", client, len(resp))

                elif cmd == CMD_READ_STATUS:
                    resp = self._cmd_status()
                    conn.sendall(resp)
                    self.log.info("[%s] → status (%d bytes)", client, len(resp))

                elif cmd == CMD_LOGIN_CHALLENGE:
                    challenge = self._cmd_login_challenge()
                    conn.sendall(challenge)
                    self.log.info(
                        "[%s] → login challenge (%d bytes) | "
                        "DETECTION: LoginAttempt",
                        client, len(challenge)
                    )

                elif cmd == CMD_LOGIN_RESPONSE:
                    resp = self._cmd_login_response(payload)
                    conn.sendall(resp)
                    self.log.info(
                        "[%s] → login response (%d bytes, payload=%s) | "
                        "DETECTION: LoginResponse:%s",
                        client, len(resp), payload.hex(), payload.hex()
                    )

                else:
                    self.log.warning(
                        "[%s] Unknown command 0x%02X | "
                        "DETECTION: UnknownCommand:0x%02X",
                        client, cmd, cmd
                    )
                    conn.sendall(build_stx_response(cmd, b'\x00\x00'))
                    with _global_lock:
                        _error_count += 1

        except ConnectionResetError:
            self.log.warning("[%s] Connection reset", client)
        except ConnectionAbortedError:
            self.log.warning("[%s] Connection aborted", client)
        except TimeoutError:
            self.log.warning("[%s] Connection timed out", client)
        except Exception as exc:
            self.log.error("[%s] Handler error: %s", client, exc)
            with _global_lock:
                _error_count += 1
        finally:
            with _global_lock:
                _active_sessions -= 1
            conn.close()
            self.log.info("[%s] #%d — connection closed", client, cid)


# ── Utility ──────────────────────────────────────────────────────────

def _hexdump(data, width=16):
    """Produce a compact hexdump for debug logging."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:04x}  {hex_part:<{width * 3}}{ascii_part}")
    return "\n".join(lines)


# ── Entry point ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Red Lion Controls Crimson v3 Honeypot Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --port 789 --verbose
  %(prog)s --port 789 --model G315C2 --num-tags 20
  sudo %(prog)s --port 789

Port 789 (default) is below 1024 and requires root on Unix.
Use a higher port (e.g. --port 1789) to run without privileges.
        """,
    )
    parser.add_argument(
        "--port", type=int, default=789,
        help="TCP listen port (default: 789; requires root if < 1024)",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Bind address (default: 127.0.0.1; use 0.0.0.0 for all interfaces)",
    )
    parser.add_argument(
        "--model", type=str, default="G310C2",
        choices=sorted(DEVICE_MODELS.keys()),
        help="Device model (default: G310C2)",
    )
    parser.add_argument(
        "--num-tags", type=int, default=10, metavar="N",
        help="Number of simulated HMI tags (default: 10)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging with hex dumps",
    )

    args = parser.parse_args()

    # ── Logger setup ───────────────────────────────────────────
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("redlion")

    # ── Banner ─────────────────────────────────────────────────
    cfg = DEVICE_MODELS[args.model]
    log.info("=" * 60)
    log.info("Red Lion Crimson v3 Honeypot")
    log.info("=" * 60)
    log.info("Model:      %s", args.model)
    log.info("Firmware:   %s", cfg["firmware"])
    log.info("Part #:     %s", cfg["part_number"])
    log.info("HW Rev:     %s", cfg["hw_rev"])
    log.info("Memory:     %s", cfg["memory"])
    log.info("Serial:     %s", _serial_number)
    log.info("Tags:       %d simulated", args.num_tags)
    log.info("Bind:       %s:%d", args.host, args.port)
    log.info("Verbose:    %s", args.verbose)
    log.info("=" * 60)

    # ── Create honeypot ────────────────────────────────────────
    honeypot = RedLionHoneypot(
        args.host, args.port, args.model, args.num_tags, args.verbose
    )

    # ── Server socket ──────────────────────────────────────────
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.host, args.port))
    except PermissionError:
        log.error("Cannot bind to port %d — need root on Unix for ports < 1024", args.port)
        log.info("Try: sudo %s %s", sys.argv[0], " ".join(sys.argv[1:]))
        log.info("Or:  %s --port 1789 %s", sys.argv[0], " ".join(
            a for a in sys.argv[1:] if not a.startswith("--port")
        ))
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to bind: %s", exc)
        sys.exit(1)

    server.listen(5)
    log.info("Listening on %s:%d — Ctrl+C to stop", args.host, args.port)

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=honeypot.handle_client,
                args=(conn, addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl+C)...")
    finally:
        server.close()
        log.info("Server stopped.")


if __name__ == "__main__":
    main()
