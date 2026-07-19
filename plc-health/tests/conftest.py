import os
import socket
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX = os.path.join(REPO, "sandbox")


def _wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _spawn(script, port, *extra):
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SANDBOX, script), "--port", str(port), *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_port(port):
        proc.terminate()
        raise RuntimeError(f"{script} never opened {port}")
    return proc


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def modbus_healthy():
    proc = _spawn("modbus_mock_server.py", 15020, "--fault-reg-value", "0")
    yield 15020
    _stop(proc)


@pytest.fixture
def modbus_faulted():
    proc = _spawn("modbus_mock_server.py", 15021, "--fault-reg-value", "1")
    yield 15021
    _stop(proc)


@pytest.fixture
def modbus_exception():
    proc = _spawn("modbus_mock_server.py", 15022, "--exception", "4")
    yield 15022
    _stop(proc)


@pytest.fixture
def enip_healthy():
    proc = _spawn("enip_mock_server.py", 44818, "--profile", "controllogix",
                  "--state", "4", "--status", "0x0000")
    yield 44818
    _stop(proc)


@pytest.fixture
def enip_faulted():
    proc = _spawn("enip_mock_server.py", 44819, "--profile", "controllogix",
                  "--state", "2", "--status", "0x0090")  # major unrecoverable
    yield 44819
    _stop(proc)
