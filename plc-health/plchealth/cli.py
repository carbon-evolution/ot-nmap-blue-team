"""plchealth CLI: poll a PLC's live health over Modbus/S7comm/EtherNet-IP."""
import argparse
import csv
import json
import sys

from plchealth import poller
from plchealth.model import PLCHealth


def _emit(health, args):
    if args.json:
        with open(args.json, "w") as f:
            json.dump(health.to_dict(), f, indent=2)
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "proto", "reachable", "state", "fault_count"])
            w.writerow([health.host, health.proto, health.reachable,
                        health.state.value, len(health.faults)])
    sys.stdout.write(
        f"{health.host} [{health.proto}] state={health.state.value} "
        f"faults={len(health.faults)}\n")
    for fault in health.faults:
        sys.stdout.write(f"  - {fault.source} {fault.code}: {fault.description}\n")


def _exit_code(health):
    if not health.reachable:
        return 2
    if health.healthy():
        return 0
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="plchealth", description="Read live PLC fault/diagnostic state")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("poll", help="poll a PLC's health")
    pp.add_argument("host")
    pp.add_argument("--proto", choices=["auto", "modbus", "s7", "enip"],
                    default="auto")
    pp.add_argument("--port", type=int, default=None)
    pp.add_argument("--timeout", type=float, default=3.0)
    pp.add_argument("--modbus-status-reg", type=int, default=0)
    pp.add_argument("--modbus-fault-bit", type=int, default=None)
    pp.add_argument("--json", help="write full record to FILE")
    pp.add_argument("--csv", help="write summary row to FILE")
    args = ap.parse_args(argv)

    if args.proto == "modbus":
        from plchealth.probes import modbus
        port = args.port if args.port is not None else 502
        health = modbus.probe(args.host, port, timeout=args.timeout,
                              status_reg=args.modbus_status_reg,
                              fault_bit=args.modbus_fault_bit)
    else:
        health = poller.poll(args.host, proto=args.proto, port=args.port,
                             timeout=args.timeout)
    _emit(health, args)
    return _exit_code(health)
