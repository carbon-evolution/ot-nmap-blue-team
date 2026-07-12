from assetinv.normalizer import normalize


def test_normalize_enip():
    rec = {"host": "127.0.0.1", "port": 44818, "protocol": "tcp",
           "script": "enip-identity-improved",
           "fields": {"Vendor": "Rockwell Automation/Allen-Bradley (1)",
                      "Product Name": "1756-L61/B LOGIX5561",
                      "Serial Number": "0x00C0FFEE", "Revision": "20.11",
                      "Device Type": "Programmable Logic Controller (14)"}}
    a = normalize(rec)
    assert a.vendor == "Rockwell Automation/Allen-Bradley (1)"
    assert a.product == "1756-L61/B LOGIX5561"
    assert a.firmware == "20.11"
    assert a.serial == "0x00C0FFEE"
    assert a.device == "EtherNet/IP CIP"
    assert a.raw["Device Type"] == "Programmable Logic Controller (14)"


def test_normalize_s7():
    rec = {"host": "10.0.0.9", "port": 102, "protocol": "tcp",
           "script": "s7comm-plus-info-improved",
           "fields": {"Module": "6ES7 515-2AM01-0AB0", "Version": "2.9.2",
                      "Module Type": "CPU 1515-2 PN", "System Name": "PLC_1500",
                      "Serial Number": "S C-L2X920551024"}}
    a = normalize(rec)
    assert a.product == "6ES7 515-2AM01-0AB0"
    assert a.firmware == "2.9.2"
    assert a.device_type == "CPU 1515-2 PN"
    assert a.raw["System Name"] == "PLC_1500"


def test_normalize_unknown_script_is_lossless():
    rec = {"host": "x", "port": 1, "protocol": "tcp", "script": "future-proto",
           "fields": {"Weird Label": "v"}}
    a = normalize(rec)
    assert a.raw["Weird Label"] == "v"
    assert a.vendor is None and a.product is None
