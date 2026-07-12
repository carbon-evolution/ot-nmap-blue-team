import os
import re
import socket
import subprocess
import sys
import time

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS_DIR))
SANDBOX = os.path.join(REPO, "sandbox")
SCRIPTS = os.path.join(REPO, "improved-scripts")
LESSER = os.path.join(SCRIPTS, "lesser-known")


def _wait_port(port, host="127.0.0.1", timeout=10.0):
    """Poll-connect until the port accepts a TCP connection or timeout."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _wait_udp_port(port, host="127.0.0.1", timeout=10.0):
    """Best-effort readiness for a UDP mock.

    A connected UDP socket to a port with no listener triggers an ICMP
    port-unreachable, surfaced as ECONNREFUSED on the probe. Once the mock is
    bound the probe either draws a reply or simply times out (the mock ignores
    the junk probe) — both mean "listening". Poll until that happens.
    """
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(0.3)
            s.connect((host, port))
            s.send(b"\x00")
            try:
                s.recv(64)      # a reply => definitely listening
                return True
            except socket.timeout:
                return True     # no reply, but no refusal => bound and ignoring
            except ConnectionRefusedError:
                pass            # nothing bound yet; retry
        except (ConnectionRefusedError, OSError):
            pass
        finally:
            s.close()
        time.sleep(0.15)
    return False


class _Mock:
    def __init__(self, script, port, *args, inject_port=True, udp=False):
        self.script = script
        cmd = [sys.executable, os.path.join(SANDBOX, script)]
        if inject_port:
            cmd += ["--port", str(port)]
        cmd += list(args)
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ready = _wait_udp_port(port) if udp else _wait_port(port)
        if not ready:
            self.stop()
            raise RuntimeError(f"{script} never opened port {port}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def mock_server():
    """Factory fixture: mock_server(script, port, *args) -> running mock.

    All started mocks are torn down at test teardown, even on failure.
    """
    started = []

    def _start(script, port, *args, inject_port=True, udp=False):
        m = _Mock(script, port, *args, inject_port=inject_port, udp=udp)
        started.append(m)
        return m

    yield _start
    for m in started:
        try:
            m.stop()
        except Exception:
            pass


def parse_fields(out):
    """Flatten an nmap NSE output block into {lowercased label: value}."""
    fields = {}
    for line in out.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        content = line.lstrip()[1:].lstrip("_").strip()
        m = re.match(r"^(.+?):\s+(.+)$", content)
        if m:
            fields[m.group(1).strip().lower()] = m.group(2).strip()
    return fields


def nmap_scan(port, script_path, script_args=None, udp=False):
    """Run nmap against 127.0.0.1:port with one NSE script.

    udp=True issues a UDP scan (nmap -sU), which requires root. Returns
    (fields_dict, raw_stdout).
    """
    proto_flag = "-sU" if udp else "-sT"
    cmd = ["nmap", "-Pn", proto_flag, "-p", str(port),
           "--script", script_path, "127.0.0.1"]
    if script_args:
        cmd += ["--script-args", script_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = proc.stdout
    if proc.returncode != 0:
        out += f"\n[nmap exited {proc.returncode}]\n{proc.stderr}"
    return parse_fields(out), out
