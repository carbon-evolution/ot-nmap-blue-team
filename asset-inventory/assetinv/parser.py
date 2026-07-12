"""Parse nmap -oX output into raw per-(host, port, script) records."""
import xml.etree.ElementTree as ET


def _script_fields(script_el):
    """Collect {label: value} from a <script>'s <elem key> children.

    Handles both flat <elem key="..."> directly under <script> and children
    nested one level in <table>. Keyless <elem> and empty values are skipped.
    """
    fields = {}
    for elem in script_el.iter("elem"):
        key = elem.get("key")
        if key and elem.text is not None:
            fields[key] = elem.text.strip()
    return fields


def parse_xml(xml_str):
    """Parse nmap -oX output into a list of raw records.

    Each record: {host, port, protocol, script, fields{label: value}}.
    Only ports whose script produced at least one keyed field are included.
    """
    root = ET.fromstring(xml_str)
    records = []
    for host in root.iter("host"):
        addr = None
        for a in host.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        for port in host.iter("port"):
            portid = int(port.get("portid"))
            proto = port.get("protocol")
            for script in port.findall("script"):
                fields = _script_fields(script)
                if fields:
                    records.append({
                        "host": addr, "port": portid, "protocol": proto,
                        "script": script.get("id"), "fields": fields,
                    })
    return records
