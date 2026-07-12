import os
import socket
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX = os.path.join(REPO, "sandbox")
SCRIPTS = os.path.join(REPO, "improved-scripts")


def _wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


@pytest.fixture
def enip_mock():
    """Start the EtherNet/IP mock on TCP 44818 (unprivileged) for the run."""
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SANDBOX, "enip_mock_server.py"),
         "--port", "44818", "--profile", "controllogix"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_port(44818):
        proc.terminate()
        raise RuntimeError("enip mock never opened 44818")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
