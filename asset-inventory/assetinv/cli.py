"""assetinv CLI: build an OT asset inventory from NSE scan results."""
import argparse
import sys

from assetinv import runner, parser as xmlparser, normalizer, cve, export


def _build(records, want_cve):
    bundle = cve.load_bundle() if want_cve else None
    assets = []
    for rec in records:
        asset = normalizer.normalize(rec)
        if bundle is not None:
            asset.cve_hints = cve.correlate(asset, bundle)
        assets.append(asset)
    return assets


def _emit(assets, fmt, out):
    text = export.to_json(assets) if fmt == "json" else export.to_csv(assets)
    if out:
        with open(out, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="assetinv",
        description="OT asset inventory from NSE scan results")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="run nmap and build an inventory")
    ps.add_argument("target")
    ps.add_argument("--ports", default="44818")
    ps.add_argument("--script", required=True,
                    help="path(s)/category for nmap --script")
    ps.add_argument("--udp", action="store_true", help="UDP scan (needs root)")

    pp = sub.add_parser("parse", help="build an inventory from saved nmap XML")
    pp.add_argument("xml")

    for p in (ps, pp):
        p.add_argument("--cve", action="store_true",
                       help="annotate assets with offline CVE hints")
        p.add_argument("--format", choices=["json", "csv"], default="json")
        p.add_argument("-o", "--out", help="write to FILE instead of stdout")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        xml = runner.run_scan(args.target, args.ports, args.script, args.udp)
    else:
        xml = runner.load_xml(args.xml)
    records = xmlparser.parse_xml(xml)
    assets = _build(records, args.cve)
    _emit(assets, args.format, args.out)
    return 0
