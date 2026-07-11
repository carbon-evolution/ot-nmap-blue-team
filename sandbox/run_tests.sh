#!/bin/bash
# Run all improved OT NSE scripts against mock servers and capture output
# Usage: ./run_tests.sh [--sudo]

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX_DIR="$PROJECT_DIR/sandbox"
IMPROVED_DIR="$PROJECT_DIR/improved-scripts"
OUTPUT_DIR="$SANDBOX_DIR/output"
MOCK_LOG="$SANDBOX_DIR/mock_servers.log"

# Parse args
NEED_SUDO=false
if [[ "$1" == "--sudo" ]]; then
    NEED_SUDO=true
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "OT NSE Script Test Runner"
echo "============================================"
echo "Project:  $PROJECT_DIR"
echo "Scripts:  $IMPROVED_DIR"
echo "Output:   $OUTPUT_DIR"
echo "============================================"
echo ""

# Check for root if needed (ports 102, 502)
if [[ "$NEED_SUDO" == "true" ]] || [[ $EUID -eq 0 ]]; then
    echo "[*] Running with elevated privileges"
else
    echo "[!] Note: Tests for port 102 (MMS) and 502 (Modbus) may fail without root"
    echo "    Run with --sudo to retry with privilege escalation"
fi
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    # Stop mock servers
    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    # Kill any remaining python processes from our script
    pkill -f "ot_mock_servers.py --all" 2>/dev/null || true
    echo "[✓] Cleanup done"
}
trap cleanup EXIT INT TERM

# Start mock servers
echo "[*] Starting mock OT servers..."
python3 "$SANDBOX_DIR/ot_mock_servers.py" --all &
MOCK_PID=$!
sleep 2

# Check if mocks started
if kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "[✓] Mock servers running (PID: $MOCK_PID)"
else
    echo "[✗] Failed to start mock servers"
    exit 1
fi

# Verify ports
echo ""
echo "[*] Verifying mock servers..."
for port in 502 1911 1962 5094; do
    if lsof -i :$port -P 2>/dev/null | grep -q LISTEN; then
        echo "  ✓ Port $port — listening"
    else
        echo "  ✗ Port $port — NOT listening"
    fi
done
# UDP port
if lsof -i :34964 -P 2>/dev/null | grep -q LISTEN; then
    echo "  ✓ Port 34964/UDP — listening"
else
    echo "  ✗ Port 34964/UDP — NOT listening"
fi
echo ""

# =============================================
# Run tests
# =============================================

run_test() {
    local script="$1"
    local port="$2"
    local proto="${3:-tcp}"
    local args="${4:-}"
    local name="$(basename "$script" .nse)"
    local output_file="$OUTPUT_DIR/${name}.txt"

    echo "--------------------------------------------"
    echo "Testing: $name"
    echo "Script:  $script"
    echo "Port:    $port/$proto"
    [[ -n "$args" ]] && echo "Args:    $args"
    echo "--------------------------------------------"

    NMAP_CMD="nmap -sT -p $port --script \"$script\""
    [[ "$proto" == "udp" ]] && NMAP_CMD="nmap -sU -p $port --script \"$script\""
    [[ -n "$args" ]] && NMAP_CMD="$NMAP_CMD --script-args \"$args\""
    NMAP_CMD="$NMAP_CMD 127.0.0.1 -T2 2>&1"

    echo "Running: nmap -p $port ..."
    eval "$NMAP_CMD" > "$output_file" 2>&1 || true

    if grep -q "|_" "$output_file" 2>/dev/null || grep -q "|" "$output_file" 2>/dev/null; then
        echo "[✓] Script produced output"
    else
        echo "[ ] Minimal or no output — may need root or the server didn't respond"
    fi
    
    # Print output summary
    grep -E "^\|" "$output_file" 2>/dev/null | head -20
    echo ""
}

# Test scripts one by one, capturing output
# (will show partial results even if some fail due to permissions)

run_test "$IMPROVED_DIR/modbus-discover-improved.nse" "502"
run_test "$IMPROVED_DIR/fox-info-improved.nse" "1911"
run_test "$IMPROVED_DIR/pcworx-info-improved.nse" "1962"
run_test "$IMPROVED_DIR/hartip-info-improved.nse" "5094"
# PROFINET is UDP and may need root
run_test "$IMPROVED_DIR/profinet-cm-lookup-improved.nse" "34964" "udp"
# MMS on port 102 (needs root)
run_test "$IMPROVED_DIR/iec61850-mms-improved.nse" "102"

echo "============================================"
echo "Test results saved to: $OUTPUT_DIR"
echo "============================================"
ls -la "$OUTPUT_DIR/"
