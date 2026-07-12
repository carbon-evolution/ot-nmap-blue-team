"""Map raw parser records into the canonical Asset schema."""
from dataclasses import dataclass, field


@dataclass
class Asset:
    host: str
    port: int
    protocol: str
    script: str
    device: str = ""
    vendor: str = None
    product: str = None
    firmware: str = None
    serial: str = None
    device_type: str = None
    raw: dict = field(default_factory=dict)
    cve_hints: list = field(default_factory=list)


# Per-script: (human device label, {canonical field: source NSE label}).
# Source labels are the exact labels each improved script emits (parse_fields
# in the mock harness lowercases them, but nmap XML preserves original case).
SCRIPT_MAP = {
    "enip-identity-improved": ("EtherNet/IP CIP", {
        "vendor": "Vendor", "product": "Product Name",
        "firmware": "Revision", "serial": "Serial Number",
        "device_type": "Device Type"}),
    "bacnet-discover-improved": ("BACnet/IP", {
        "vendor": "Vendor", "product": "Model Name", "firmware": "Firmware"}),
    "s7comm-plus-info-improved": ("S7comm-plus", {
        "product": "Module", "device_type": "Module Type",
        "firmware": "Version", "serial": "Serial Number"}),
    "modbus-discover-improved": ("Modbus", {"product": "Slave ID data"}),
    "fox-info-improved": ("Fox", {"firmware": "fox.version"}),
    "pcworx-info-improved": ("PCWorx", {
        "product": "PLC Type", "firmware": "Firmware Version"}),
    "hartip-info-improved": ("HART-IP", {"vendor": "Manufacturer Id"}),
    "iec61850-mms-improved": ("IEC 61850 MMS", {"vendor": "VendorName"}),
    "profinet-cm-lookup-improved": ("PROFINET CM", {"product": "deviceName"}),
    "dnp3-advanced-info": ("DNP3", {}),
    "gesrtp-info-improved": ("GE SRTP", {
        "product": "PLC Model", "firmware": "Firmware Version",
        "device_type": "CPU Type"}),
    "opcua-discovery-improved": ("OPC UA", {"product": "Application Name"}),
    "melsecq-info-improved": ("MELSEC-Q", {
        "product": "PLC Type", "firmware": "Firmware"}),
    "proconos-info-improved": ("ProConOS", {
        "product": "PLC Model", "firmware": "Runtime"}),
    "ff-hse-discover-improved": ("FF HSE", {
        "vendor": "Vendor", "product": "Device Name",
        "firmware": "Software Revision"}),
    "redlion-cr3-info-improved": ("Red Lion", {
        "vendor": "Manufacturer", "product": "Model",
        "firmware": "Firmware Version"}),
}


def normalize(record):
    """Map a raw parser record to a canonical Asset (lossless via .raw).

    Every original label is preserved in .raw; the mapping only lifts known
    labels into canonical fields. An unknown script still yields an Asset with
    its data under .raw and empty canonical fields.
    """
    device, mapping = SCRIPT_MAP.get(record["script"], ("", {}))
    fields = dict(record["fields"])
    asset = Asset(host=record["host"], port=record["port"],
                  protocol=record["protocol"], script=record["script"],
                  device=device, raw=fields)
    for canon, label in mapping.items():
        if label in fields:
            setattr(asset, canon, fields[label])
    return asset
