# OT Protocol Mock Server Sandbox

A **self-contained test environment** for developing and validating Nmap NSE scripts against 12 industrial OT/ICS protocols — without touching real hardware.

```
        nmap NSE script  ──TCP/UDP──>  Mock server  ──>  Realistic OT response
                                            │
                                     Detection logging
                                     (blue-team audit trail)
```

---

## Table of Contents

- [Architecture & Design](#architecture--design)
  - [Two Server Patterns](#two-server-patterns)
  - [The All-in-One Launcher](#the-all-in-one-launcher)
  - [Cleanup & Lifecycle](#cleanup--lifecycle)
  - [Detection Logging](#detection-logging)
  - [Profiles & Realism](#profiles--realism)
  - [Graceful Degradation](#graceful-degradation)
- [Quick Start](#quick-start)
- [Server Catalog](#server-catalog)
  - [Protocol Groups](#protocol-groups)
  - [Port Reference](#port-reference)
- [Usage Guide](#usage-guide)
  - [All-in-One Launcher](#all-in-one-launcher)
  - [Standalone Servers](#standalone-servers)
  - [Running NSE Scripts Against Mocks](#running-nse-scripts-against-mocks)
  - [Automated Test Suite](#automated-test-suite)
- [Design Details](#design-details)
  - [Threaded Servers (Legacy)](#threaded-servers-legacy)
  - [Subprocess Servers (Lesser-Known)](#subprocess-servers-lesser-known)
  - [How the Launcher Wires It Together](#how-the-launcher-wires-it-together)
- [Privileged Ports](#privileged-ports)
- [Extending the Sandbox](#extending-the-sandbox)
- [Troubleshooting](#troubleshooting)

---

## Architecture & Design

The sandbox serves one purpose: **give each NSE script a real TCP/UDP endpoint that speaks its protocol**, so you can iterate on script logic without needing a PLC on your desk.

### Two Server Patterns

The 12 protocol servers use two different patterns depending on complexity:

| Pattern | How It Works | Protocol Count | Examples |
|---------|-------------|----------------|---------|
| **Inline threaded** | Server function runs as a daemon thread inside `ot_mock_servers.py`. A single process hosts all of them. | 6 | modbus, hartip, fox, pcworx, profinet, mms |
| **Standalone subprocess** | Each server is its own Python file with a `main()` entry point. The launcher spawns them via `subprocess.Popen`. | 6 | melsecq, opcua, proconos, gesrtp, redlion, ffhse |

**Why two patterns?** The 6 lesser-known protocols require richer protocol emulation — packet-level parsing, cyclic data push, profiles, scan delay simulation, detection logging. They earn their own files with dedicated `main()` functions, `argparse`, and optional flags like `--profile`, `--scan-delay`, `--verbose`.

The 6 legacy protocols are simple enough to inline: they accept a connection, send a canned response, and close.

### The All-in-One Launcher

```
ot_mock_servers.py  (single entry point)
│
├── [threading] Daemon threads for legacy servers
│   ├── modbus_server(stop_event, port=502)
│   ├── hartip_server(stop_event, port=5094)
│   ├── fox_server(stop_event, port=1911)
│   ├── pcworx_server(stop_event, port=1962)
│   ├── mms_server(stop_event, port=102)
│   └── profinet_server(stop_event, port=34964)  (UDP)
│
├── [subprocess] Standalone server wrappers
│   ├── _launch_standalone("melsecq_mock_server.py", port=5007)
│   ├── _launch_standalone("opcua_mock_server.py", port=4840)
│   ├── _launch_standalone("proconos_mock_server.py", port=20547)
│   ├── _launch_standalone("gesrtp_mock_server.py", port=18245)
│   ├── _launch_standalone("redlion_mock_server.py", port=44818)
│   └── _launch_standalone("ffhse_mock_server.py", port=1089)
│
└── _stop_subprocesses()  — clean shutdown on Ctrl+C
```

### Cleanup & Lifecycle

```
Start:  python3 ot_mock_servers.py --all-lesser-known
           │
           ▼
        Threaded daemons start (background)
        Subprocess servers spawn (background)
           │
           ▼
        Main thread sleeps until Ctrl+C
           │
           ▼
  Ctrl+C → stop_event.set() → threads join → _stop_subprocesses()
                                            → terminate() each subprocess
                                            → wait(3s) → kill() fallback
                                            → all ports released
```

Subprocesses are tracked by PID and receive `SIGTERM` first. If they don't exit within 3 seconds, `SIGKILL` is sent. The list is cleared after all are stopped.

### Detection Logging

The 6 upgraded standalone servers include structured **blue-team detection logging** — every connection, probe, and operation is timestamped and logged:

```
2026-07-11 10:06:18 [DETECT] 127.0.0.1:55387 -> CONNECT (profile=rx3i)
2026-07-11 10:06:18 [DETECT] 127.0.0.1:55387 -> READ var idx=0 name=Temperature_1 type=0x04 value=25.3
```

These logs serve two purposes:
1. **Validate NSE script behavior** — confirm the script sends the expected probes
2. **Audit trail** — demonstrate what detection events a real device would generate

Enable verbose mode with `--verbose` (or `-v`) on standalone servers for full hex dumps.

### Profiles & Realism

The 6 upgraded servers ship with multiple **device profiles** selectable via `--profile`:

| Server | Default Profile | Other Profiles |
|--------|----------------|----------------|
| MELSEC-Q | `q03udvcpu` | `q06udvcpu`, `q13udvcpu`, `q26udvcpu` |
| ProConOS | `adam5510kw` | `adam5510e`, `adam5510m`, `generic` |
| OPC UA | `siemens_s7` | `rockwell_logix`, `schneider_m340`, `generic` |
| GE SRTP | `rx3i` | `ge90_30`, `ge90_70` |
| Red Lion | `g310c2` | `g308c2`, `g312c2`, `dsp1h` |
| FF HSE | `tic101` | `pic201`, `fic301`, `fse_generic` |

Each profile changes:
- Device identity strings (model, vendor, firmware, serial)
- Simulated process variables (temperatures, pressures, speeds with jitter)
- Protocol-specific behavior (command support, response timing)

### Graceful Degradation

All servers handle:
- **TCP fragmentation** — `recv_exactly()` loops ensure partial reads assemble correctly
- **Connection resets** — `ConnectionResetError` and `ConnectionAbortedError` caught per-client
- **Port conflicts** — `SO_REUSEADDR` set on all sockets
- **KeyboardInterrupt** — clean shutdown via `stop_event` and subprocess `terminate()`
- **Missing files** — launcher prints `[WARN]` and skips if a standalone script is absent

---

## Quick Start

```bash
# 1. Start ALL mock servers (12 protocols, 1 command)
python3 ot_mock_servers.py --all

# 2. In another terminal, run NSE tests
nmap -p 5007 --script ../improved-scripts/lesser-known/melsecq-info-improved.nse 127.0.0.1
nmap -p 4840 --script ../improved-scripts/lesser-known/opcua-discovery-improved.nse 127.0.0.1
nmap -p 18245 --script ../improved-scripts/lesser-known/gesrtp-info-improved.nse 127.0.0.1
nmap -p 1089 --script ../improved-scripts/lesser-known/ff-hse-discover-improved.nse 127.0.0.1

# 3. Or run the full automated test suite
./test_runner.sh all
```

No dependencies beyond Python 3 stdlib. No `pip install`. No configuration files.

---

## Server Catalog

### Protocol Groups

| Group | Flag | Protocols | Purpose |
|-------|------|-----------|---------|
| **All** | `--all` | 12 servers | Everything |
| **Legacy** | `--all-legacy` | modbus, hartip, fox, pcworx, profinet, mms | Original 6, inline/thin |
| **Lesser-Known** | `--all-lesser-known` | melsecq, opcua, proconos, gesrtp, redlion, ffhse | New 6, standalone/rich |

### Port Reference

| Server | Launcher Port | Standalone Default | Protocol | Transport | Needs Root |
|--------|--------------|-------------------|----------|-----------|-----------|
| modbus | 502 | 502 | Modbus TCP | TCP | ✅ |
| hartip | 5094 | 5094 | HART-IP | TCP | ❌ |
| fox | 1911 | 1911 | Fox (Tridium) | TCP | ❌ |
| pcworx | 1962 | 1962 | PCWorx (Phoenix Contact) | TCP | ❌ |
| profinet | 34964 | 34964 | PROFINET DCP | UDP | ❌ |
| mms | 102 | 102 | IEC 61850 MMS | TCP | ✅ |
| **melsecq** | **5007** | 5007 | MELSEC-Q (Mitsubishi) | TCP | ❌ |
| **opcua** | **4840** | 4840 | OPC UA Binary | TCP | ❌ |
| **proconos** | **20547** | 20547 | ProConOS (KW-Software) | TCP | ❌ |
| **gesrtp** | **18245** | 18245 | GE SRTP (GE/Emerson) | TCP | ❌ |
| **redlion** | **44818** | 789 | Red Lion Crimson v3 | TCP | ❌* |
| **ffhse** | **1089** | 1089 | Foundation Fieldbus HSE | TCP | ❌ |

> \* Red Lion defaults to port 789 in standalone, which requires root. The launcher uses port **44818** to avoid privilege escalation.

---

## Usage Guide

### All-in-One Launcher

```bash
# Start a group
python3 ot_mock_servers.py --all-lesser-known

# Start a single server
python3 ot_mock_servers.py --melsecq

# Start specific combination
python3 ot_mock_servers.py --melsecq --opcua --gesrtp

# List all available servers and their ports
python3 ot_mock_servers.py --list

# Start everything (needs sudo for ports 102, 502)
sudo python3 ot_mock_servers.py --all
```

### Standalone Servers

Each standalone server can run independently with its own flags:

```bash
# Default profile
python3 melsecq_mock_server.py

# Custom profile + port + verbose logging
python3 melsecq_mock_server.py --profile q06udvcpu --port 5007 --verbose

# Available profiles
python3 opcua_mock_server.py --profile rockwell_logix
python3 proconos_mock_server.py --profile adam5510e
python3 gesrtp_mock_server.py --profile ge90_70 --scan-delay 50
python3 redlion_mock_server.py --profile g308c2
python3 ffhse_mock_server.py --profile pic201 --enable-alarms
```

### Running NSE Scripts Against Mocks

```bash
# Terminal 1: Start the sandbox
python3 ot_mock_servers.py --melsecq --opcua --gesrtp

# Terminal 2: Run NSE scripts
nmap -p 5007 --script ../improved-scripts/lesser-known/melsecq-info-improved.nse 127.0.0.1
nmap -p 4840 --script ../improved-scripts/lesser-known/opcua-discovery-improved.nse 127.0.0.1
nmap -p 18245 --script ../improved-scripts/lesser-known/gesrtp-info-improved.nse 127.0.0.1
nmap -p 1089 --script ../improved-scripts/lesser-known/ff-hse-discover-improved.nse 127.0.0.1
nmap -p 20547 --script ../improved-scripts/lesser-known/proconos-info-improved.nse 127.0.0.1
```

Expected output for a working script:
```
PORT      STATE    SERVICE
5007/tcp  open     melsecq
| melsecq-info-improved:
|   CPU Type: Q03UDVCPU
|   Model Name: MELSEC-Q Series
|_  Status: Mitsubishi PLC detected
```

### Automated Test Suite

The `test_runner.sh` script performs a complete lifecycle:

```bash
# Test all lesser-known protocol servers
./test_runner.sh all

# Test a single protocol
./test_runner.sh melsecq
./test_runner.sh opcua
./test_runner.sh gesrtp
./test_runner.sh proconos
./test_runner.sh ffhse

# Start servers and keep them running
./test_runner.sh start

# Stop all running mock servers
./test_runner.sh stop
```

The test runner:
1. Starts each mock server as a background process
2. Waits for initialization
3. Sends protocol-specific probes (raw socket, not nmap)
4. Captures and displays responses
5. Saves results to `test-results/*.txt`
6. Stops all servers

Run `./test_runner.sh all` before committing changes to confirm nothing is broken.

---

## Design Details

### Threaded Servers (Legacy)

The 6 legacy servers follow a uniform pattern inside `ot_mock_servers.py`:

```python
def modbus_server(stop_event, port=502):
    """Thread target — runs until stop_event is set."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    sock.settimeout(0.5)  # so accept() doesn't block shutdown

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=modbus_handle_client,
                                 args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue

    sock.close()
```

Key design points:
- **`stop_event`** — a `threading.Event` shared across all servers. When set, every server's `accept()` loop exits.
- **`socket.timeout`** — `settimeout(0.5)` ensures `accept()` checks `stop_event` at least twice per second.
- **Daemon threads** — per-connection handlers are daemon threads so they don't block shutdown.
- **`SO_REUSEADDR`** — allows immediate rebind after a crash.

### Subprocess Servers (Lesser-Known)

The 6 upgraded servers follow a richer pattern:

```
main()
  ├── argparse → --port, --host, --profile, --verbose, --scan-delay
  ├── socket setup → SO_REUSEADDR, bind, listen
  ├── accept loop → thread per client
  │
  └── handle_client()
       ├── recv_exactly() loop (handles TCP fragmentation)
       ├── protocol parser (MC protocol, OPC UA binary, ProConOS, ...)
       ├── handler dispatch (0xCC ident, 0x01 read, 0x02 write, ...)
       ├── detection logging (DETECT level)
       └── cyclic data push (background thread per client)

  on Ctrl+C:
    └── cleanup: wait for threads, close socket
```

Each server is self-contained and testable in isolation:

```bash
python3 melsecq_mock_server.py --profile q03udvcpu --port 5007 --verbose
```

### How the Launcher Wires It Together

The launcher's subprocess mechanism is simple and robust:

```python
_subprocesses = []

def _launch_standalone(script_name, port):
    script_path = os.path.join(SCRIPT_DIR, script_name)
    cmd = [sys.executable, script_path, "--port", str(port)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _subprocesses.append(proc)
    return proc

def _make_standalone_wrapper(script_name):
    """Factory: creates a function compatible with (stop_event, port) signature."""
    def wrapper(stop_event, port):
        _launch_standalone(script_name, port)
        while not stop_event.is_set():
            try:
                proc.wait(timeout=0.5)
                break  # process died
            except subprocess.TimeoutExpired:
                continue
    return wrapper
```

`_stop_subprocesses()` sends `SIGTERM`, waits up to 3 seconds, then escalates to `SIGKILL`:

```python
def _stop_subprocesses():
    for proc in _subprocesses:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
    _subprocesses.clear()
```

---

## Privileged Ports

Ports below 1024 require root on Unix systems:

| Port | Protocol | Workaround |
|------|----------|-----------|
| 102 | MMS | Use `sudo` or run on a port above 1024 and redirect |
| 502 | Modbus | Use `sudo` or run on a port above 1024 and redirect |
| 789 | Red Lion (standalone) | Launcher uses port 44818; standalone accepts `--port` |

For the launcher with privileged ports:
```bash
sudo python3 ot_mock_servers.py --mms --modbus
```

For standalone servers:
```bash
sudo python3 redlion_mock_server.py
# or use a non-privileged port:
python3 redlion_mock_server.py --port 44818
```

---

## Extending the Sandbox

### Adding a New Mock Server

1. **Create a standalone file** following the pattern of `melsecq_mock_server.py`:
   - `main()` with argparse (`--port`, `--host`, `--profile`, `--verbose`)
   - Thread-per-client accept loop
   - `SO_REUSEADDR`, graceful shutdown on Ctrl+C
   - Detection logging

2. **Wire it into the launcher** by adding two lines to `ot_mock_servers.py`:
   ```python
   # In SERVERS dict:
   "myprotocol": (_make_standalone_wrapper("myprotocol_mock_server.py"), MY_PORT),
   
   # In SERVERS_LESSER_KNOWN or a new group:
   SERVERS_LESSER_KNOWN.append("myprotocol")
   ```

3. **Add a test function** to `test_runner.sh`:
   ```bash
   test_myprotocol() {
       echo -e "${YELLOW}[*] Testing MyProtocol...${NC}"
       python3 -c "
   import socket, time
   s = socket.socket(...)
   # ... send probe, check response ...
   s.close()
   "
   }
   ```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `Address already in use` | Stale process from previous run | `pkill -f mock_server` |
| `Connection refused` | Server not started yet | Wait for startup, or increase `sleep` in scripts |
| NSE script returns no output | Wrong port or server not running | Check `--list` for correct ports |
| NSE script returns `socket time` | Firewall or server bound to wrong interface | Server should bind to `0.0.0.0` or `127.0.0.1` |
| `[WARN] script not found` | Standalone file moved or deleted | Check file exists in sandbox directory |
| Port 102/502/789 fail | Need root on Unix | Use `sudo` or `--port` with a value > 1024 |
| Responses truncated | TCP fragmentation | Server uses `recv_exactly()`, check client-side handling |
| Cyclic data not arriving | Client disconnected or thread crashed | Check server logs for errors; reconnect |

### Diagnostic Commands

```bash
# Check which mock server processes are running
ps aux | grep mock_server

# Check which ports are in use
lsof -iTCP -sTCP:LISTEN -P -n | grep -E "Python|nmap"

# Kill all mock servers
pkill -f mock_server

# Test if a port is open
python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 5007)); print('open'); s.close()"
```
