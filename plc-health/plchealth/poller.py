"""Select a protocol (or auto-detect) and run the matching probe."""
import socket

from plchealth.model import PLCHealth, State
from plchealth.probes import modbus, s7, enip

_PROBES = {"modbus": modbus, "s7": s7, "enip": enip}
_DEFAULT_PORTS = {"modbus": 502, "s7": 102, "enip": 44818}
_AUTO_ORDER = ["modbus", "s7", "enip"]


def _port_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def poll(host, proto="auto", port=None, timeout=3.0, ports=None):
    ports = ports or dict(_DEFAULT_PORTS)
    if proto == "auto":
        for name in _AUTO_ORDER:
            p = ports.get(name, _DEFAULT_PORTS[name])
            if _port_open(host, p, min(timeout, 1.0)):
                return _PROBES[name].probe(host, p, timeout=timeout)
        return PLCHealth(host=host, port=0, proto="auto",
                         reachable=False, state=State.UNREACHABLE)
    p = port if port is not None else ports.get(proto, _DEFAULT_PORTS[proto])
    return _PROBES[proto].probe(host, p, timeout=timeout)
