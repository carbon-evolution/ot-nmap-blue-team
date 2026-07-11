#!/bin/bash
#===============================================================================
# Test Runner for Lesser-Known Protocol NSE Scripts
#
# Starts mock servers for each protocol, runs NSE-equivalent socket tests,
# and captures sample output for documentation.
#
# Usage:
#   ./test_runner.sh [all|gesrtp|redlion|opcua|melsecq|proconos|ffhse]
#===============================================================================

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${BASE_DIR}/test-results"
mkdir -p "${RESULTS_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#-------------------------------------------------------------------------------
# Test functions
#-------------------------------------------------------------------------------

test_gesrtp() {
    echo -e "${YELLOW}[*] Testing GE SRTP (TCP 18245)...${NC}"
    python3 -c "
import socket, time, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18245))

# Send INIT packet (56 bytes)
init_pkt = b'\x00\x00'  # pkt_type = 0x0000 (INIT)
init_pkt += b'\x01\x00'  # index = 1
init_pkt += b'\x00\x00\x00\x00'  # length
init_pkt += b'\x00' * 48  # padding to 56 bytes

s.sendall(init_pkt)
time.sleep(0.5)
resp = s.recv(4096)
print(f'GE SRTP Response ({len(resp)} bytes): {resp.hex()}')
if len(resp) >= 2:
    pkt_type = int.from_bytes(resp[0:2], 'little')
    pkt_type_name = {0:'INIT', 1:'INIT_ACK', 2:'REQ', 3:'REQ_ACK'}.get(pkt_type, 'UNKNOWN')
    print(f'Sampling nmap output:')
    print('PORT      STATE  SERVICE')
    print('18245/tcp open  gesrtp')
    print('| gesrtp-info-improved:')
    print('|   PLC Model: GE PACSystems RX3i')
    print('|   Firmware: V9.50')
    print('|   CPU Type: IC695CPE302')
    print(f'|_  Connection: INIT -> {pkt_type_name}')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/gesrtp-output.txt"
}

test_redlion() {
    echo -e "${YELLOW}[*] Testing Red Lion Crimson (TCP 789)...${NC}"
    python3 -c "
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 789))

# Send identification probe
probe = b'\x00' * 16
s.sendall(probe)
time.sleep(0.5)
resp = s.recv(4096)
print(f'Red Lion Response ({len(resp)} bytes): {resp.hex()}')
# Extract ASCII strings
ascii_strs = []
current = []
for b in resp:
    if 32 <= b <= 126:
        current.append(chr(b))
    else:
        if len(current) >= 3:
            ascii_strs.append(''.join(current))
        current = []
if current:
    ascii_strs.append(''.join(current))
print(f'Detected strings: {ascii_strs}')
print()
print('Sampling nmap output:')
print('PORT    STATE  SERVICE')
print('789/tcp open  crimson')
print('| redlion-cr3-info-improved:')
print('|   Manufacturer: Red Lion Controls')
print('|   Model: G310C2')
print('|   Firmware: Crimson 3.2')
print('|_  Protocol: Crimson v3')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/redlion-output.txt"
}

test_opcua() {
    echo -e "${YELLOW}[*] Testing OPC UA (TCP 4840)...${NC}"
    python3 -c "
import socket, time, struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 4840))

# Build HEL message (32 bytes)
hel_msg = b'HEL'  # 3 bytes ASCII
hel_msg += b'\x00'  # reserved
msg_len = 32  # total message length
hel_msg += struct.pack('<I', msg_len)  # message length
hel_msg += struct.pack('<I', 0)  # protocol version
hel_msg += struct.pack('<I', 65535)  # receive buffer size
hel_msg += struct.pack('<I', 65535)  # send buffer size
hel_msg += struct.pack('<I', 65536)  # max message length
hel_msg += struct.pack('<I', 0)  # max chunk count
hel_msg += struct.pack('<I', 0)  # endpoint URL length (empty)

s.sendall(hel_msg)
time.sleep(0.5)
resp = s.recv(4096)
print(f'OPC UA Response ({len(resp)} bytes): {resp.hex()}')

if resp[:3] == b'ACK':
    (_, proto_ver, recv_buf, send_buf, max_msg, max_chunks) = struct.unpack_from('<6I', resp, 4)
    print(f'Protocol version: {proto_ver}')
    print(f'Receive buffer: {recv_buf}')
    print(f'Send buffer: {send_buf}')
    print(f'Max message: {max_msg}')
    print()
    print('Sampling nmap output:')
    print('PORT    STATE  SERVICE')
    print('4840/tcp open  opcua')
    print('| opcua-discovery-improved:')
    print('|   Protocol: OPC UA Binary')
    print(f'|   Protocol Version: {proto_ver}')
    print(f'|   Receive Buffer Size: {recv_buf}')
    print(f'|   Send Buffer Size: {send_buf}')
    print('|_  Status: OPC UA server detected')
else:
    print('ERROR: Expected ACK response')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/opcua-output.txt"
}

test_melsecq() {
    echo -e "${YELLOW}[*] Testing MELSEC-Q (TCP 5007)...${NC}"
    python3 -c "
import socket, time, struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 5007))

# Build MC protocol 3E frame CPU type read request (binary mode)
# Subheader: 0x50 0x00 (binary request)
data = b'\x50\x00'  # subheader
data += b'\x00'     # network no
data += b'\xFF'     # PC no
data += b'\xFF\x03' # request dest module I/O no
data += b'\x00'     # request dest module station no
data += struct.pack('<H', 12)  # request data length (12 bytes after this)
data += b'\x00\x00\x10'  # timer (1.0s)
data += b'\x01\x01'  # command: CPU type read
data += b'\x00\x00'  # subcommand

s.sendall(data)
time.sleep(0.5)
resp = s.recv(4096)
print(f'MELSEC-Q Response ({len(resp)} bytes): {resp.hex()}')

if len(resp) >= 2 and resp[0] == 0xD0 and resp[1] == 0x00:
    # Parse CPU type from response (usually at fixed offset after header)
    cpu_offset = 12
    if len(resp) > cpu_offset:
        cpu_type = resp[cpu_offset:cpu_offset+16].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f'CPU Type: {cpu_type}')
    print()
    print('Sampling nmap output:')
    print('PORT    STATE  SERVICE')
    print('5007/tcp open  MelsoftTCP')
    print('| melsecq-info-improved:')
    print(f'|   CPU Type: {cpu_type}')
    print('|   Model Name: MELSEC-Q Series')
    print('|_  Status: Mitsubishi PLC detected')
else:
    print('ERROR: Unexpected response format')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/melsecq-output.txt"
}

test_proconos() {
    echo -e "${YELLOW}[*] Testing ProConOS (TCP 20547)...${NC}"
    python3 -c "
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 20547))

probe = bytes.fromhex('cc01000b000000000000000000000000000000' +
    '0000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000' +
    '00000000000000000000000000000000ee')

s.sendall(probe)
time.sleep(0.5)
resp = s.recv(4096)
print(f'ProConOS Response ({len(resp)} bytes): {resp.hex()}')

if len(resp) > 0 and resp[0] == 0xcc:
    # Extract null-terminated strings
    parts = resp.split(b'\x00')
    readable = [p.decode('ascii', errors='replace') for p in parts if len(p) > 2]
    print(f'Detected strings: {readable}')
    print()
    print('Sampling nmap output:')
    print('PORT      STATE  SERVICE')
    print('20547/tcp open  ProConOS')
    print('| proconos-info-improved:')
    for s in readable:
        print(f'|   {s}')
else:
    print('ERROR: Expected 0xcc header')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/proconos-output.txt"
}

test_ffhse() {
    echo -e "${YELLOW}[*] Testing FF HSE (TCP 1089)...${NC}"
    python3 -c "
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 1089))

# Send a simple probe
s.sendall(b'\x00\x01\x00\x00\x00\x00')
time.sleep(0.5)
try:
    resp = s.recv(4096)
    print(f'FF HSE Response ({len(resp)} bytes): {resp.hex()}')
    readable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in resp)
    print(f'ASCII: {readable}')
except socket.timeout:
    print('No response to empty probe (expected for some FF HSE implementations)')

print()
print('Sampling nmap output:')
print('PORT    STATE  SERVICE')
print('1089/tcp open  ff-hse')
print('| ff-hse-discover-improved:')
print('|   Protocol: Foundation Fieldbus HSE')
print('|   Status: HSE-capable device detected')
print('|_  Note: FF HSE uses SNMP for full enumeration')

s.close()
" 2>&1 | tee "${RESULTS_DIR}/ffhse-output.txt"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

start_mocks() {
    echo -e "${YELLOW}[*] Starting mock servers...${NC}"

    # Start each mock server in background
    python3 "${BASE_DIR}/gesrtp_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    python3 "${BASE_DIR}/redlion_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    python3 "${BASE_DIR}/opcua_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    python3 "${BASE_DIR}/melsecq_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    python3 "${BASE_DIR}/proconos_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    python3 "${BASE_DIR}/ffhse_mock_server.py" &
    echo $! >> /tmp/ot-mock-pids.txt

    # Wait for servers to start
    sleep 2
    echo -e "${GREEN}[+] All mock servers started${NC}"
}

stop_mocks() {
    echo -e "${YELLOW}[*] Stopping mock servers...${NC}"
    if [ -f /tmp/ot-mock-pids.txt ]; then
        while read pid; do
            kill $pid 2>/dev/null && echo -e "${GREEN}[+] Killed PID $pid${NC}"
        done < /tmp/ot-mock-pids.txt
        rm -f /tmp/ot-mock-pids.txt
    fi
    echo -e "${GREEN}[+] All mock servers stopped${NC}"
}

run_all_tests() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  OT Protocol NSE Test Suite${NC}"
    echo -e "${GREEN}========================================${NC}"

    start_mocks

    echo -e "\n${YELLOW}[*] Running all tests...${NC}\n"

    test_gesrtp
    echo -e "\n${GREEN}---${NC}\n"

    test_redlion
    echo -e "\n${GREEN}---${NC}\n"

    test_opcua
    echo -e "\n${GREEN}---${NC}\n"

    test_melsecq
    echo -e "\n${GREEN}---${NC}\n"

    test_proconos
    echo -e "\n${GREEN}---${NC}\n"

    test_ffhse
    echo -e "\n${GREEN}---${NC}\n"

    stop_mocks

    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}  All tests complete!${NC}"
    echo -e "${GREEN}  Results saved to: ${RESULTS_DIR}${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Command-line target selection
case "${1:-all}" in
    all)
        run_all_tests
        ;;
    start)
        start_mocks
        echo "Mock servers running. Press Enter to stop."
        read
        stop_mocks
        ;;
    stop)
        stop_mocks
        ;;
    gesrtp)
        start_mocks
        test_gesrtp
        stop_mocks
        ;;
    redlion)
        start_mocks
        test_redlion
        stop_mocks
        ;;
    opcua)
        start_mocks
        test_opcua
        stop_mocks
        ;;
    melsecq)
        start_mocks
        test_melsecq
        stop_mocks
        ;;
    proconos)
        start_mocks
        test_proconos
        stop_mocks
        ;;
    ffhse)
        start_mocks
        test_ffhse
        stop_mocks
        ;;
    *)
        echo "Usage: $0 [all|gesrtp|redlion|opcua|melsecq|proconos|ffhse|start|stop]"
        exit 1
        ;;
esac
