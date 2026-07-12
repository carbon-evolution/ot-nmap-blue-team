"""Produce nmap -oX XML, either by running nmap or reading a saved file."""
import subprocess


def run_scan(target, ports, script_path, udp=False, timeout=180):
    """Run nmap with one or more NSE scripts and return the -oX XML string.

    script_path is passed straight to --script (a path, a comma-separated list,
    or a category). udp=True issues a UDP scan (needs root).
    """
    proto = "-sU" if udp else "-sT"
    cmd = ["nmap", "-Pn", proto, "-p", str(ports), "--script", script_path,
           "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout


def load_xml(path):
    """Read a previously captured nmap -oX file."""
    with open(path) as f:
        return f.read()
