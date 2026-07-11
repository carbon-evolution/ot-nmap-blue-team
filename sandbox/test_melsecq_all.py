#!/usr/bin/env python3
"""Comprehensive smoke test for melsecq_mock_server.py."""

import argparse, socket, struct, sys, time

P = "\033[92m\u2713\033[0m"
E = "\033[91m\u2717\033[0m"

def p16b(v): return struct.pack(">H", v)
def up16b(d,o): return struct.unpack_from(">H", d, o)[0]
def up16(d,o): return struct.unpack_from("<H", d, o)[0]

ERR_OK = 0x0000; ERR_CMD = 0xC051; ERR_DEV = 0xC054
PROFS = {"q03":("Q03UDVCPU","1.20"),"q06":("Q06UDVCPU","2.10"),
         "q13":("Q13UDVCPU","1.50"),"q26":("Q26UDVCPU","3.00")}
MDL = "MELSEC-Q Series"

_run=0; _pass=0; _fail=0
def t(n,o,d=""):
    global _run,_pass,_fail; _run+=1
    if o: _pass+=1; print(f"  {P} {n}")
    else: _fail+=1; print(f"  {E} {n} -- {d}")

def conn(h,p):
    s=socket.socket(); s.settimeout(5); s.connect((h,p)); return s
def xfer(s,d):
    s.sendall(d); time.sleep(0.2); return s.recv(4096)

# --- 0x5000 frame builder ---
def mk5000(cmd):
    """Build 17B 0x5000 frame: subhdr(2)+net(1)+pc(1)+io(2)+station(1)+dlen(3)+timer(3)+cmd(2)+subcmd(2)"""
    return (p16b(0x5000) + b'\x00\xff\xff\x03\x00' + bytes([7,0,0]) +
            b'\x00\x00\x00' + struct.pack("<H", cmd) + b'\x00\x00')

# Pre-built frames
F_CPU = mk5000(0x0101)
F_MOD = mk5000(0x0100)
F_VER = mk5000(0x0113)
F_UNK = mk5000(0xFFFF)

def chk5000(r):
    if not t("resp>=12B", len(r)>=12, f"{len(r)}B"): return None
    t("subhdr=0xD000", up16b(r,0)==0xD000, f"0x{up16b(r,0):04x}")
    e = up16(r,10)
    t("err=0x0000", e==ERR_OK, f"0x{e:04x}")
    return r[12:28].rstrip(b"\x00").decode() if len(r)>=28 else None

def test_cpu():
    s=conn(*HOST); r=xfer(s,F_CPU); s.close()
    c=chk5000(r)
    if c is not None: t(f"CPU='{c}'", any(c==p[0] for p in PROFS.values()))

def test_model():
    s=conn(*HOST); r=xfer(s,F_MOD); s.close()
    c=chk5000(r)
    if c is not None: t(f"Model='{c}'", c==MDL)

def test_version():
    s=conn(*HOST); r=xfer(s,F_VER); s.close()
    c=chk5000(r)
    if c is not None: t(f"Ver='{c}'", any(c==p[1] for p in PROFS.values()))

def test_unk_cmd():
    s=conn(*HOST); r=xfer(s,F_UNK); s.close()
    if t("unk cmd: resp>=12B", len(r)>=12, f"{len(r)}B"):
        t("err=0xC051", up16(r,10)==ERR_CMD, f"0x{up16(r,10):04x}")

# --- Extended frame helpers ---
def ext(sh, src, pl):
    net=struct.pack("<H",0); ub=b'\xff'; de=struct.pack("<H",0)
    sb=struct.pack("<H",src); tm=struct.pack("<H",0x1000)
    dl=struct.pack("<H",len(pl)); ef=b'\x00'
    return p16b(sh)+net+ub+de+sb+tm+dl+ef+pl

def chk_ext(r, nm, esh):
    if not t(f"{nm}: >=16B", len(r)>=16, f"{len(r)}B"): return False
    sh=up16b(r,0)
    t(f"{nm}: subhdr=0x{esh:04x}", sh==esh, f"0x{sh:04x}")
    e=up16(r,14)
    t(f"{nm}: err=0x0000", e==ERR_OK, f"0x{e:04x}")
    return True

def test_drd():
    pl=b'\x44'+struct.pack("<I",100)[:3]+struct.pack("<H",3)
    s=conn(*HOST); r=xfer(s,ext(0x0401,100,pl)); s.close()
    if not chk_ext(r,"Dev rd",0x8401): return
    d=r[16:22]
    t("6B data", len(d)==6, f"{len(d)}B")
    if len(d)>=2: t(f"D100={up16(d,0)}", 240<=up16(d,0)<=260)

def test_dunk():
    pl=b'\x99'+struct.pack("<I",0)[:3]+struct.pack("<H",1)
    s=conn(*HOST); r=xfer(s,ext(0x0401,200,pl)); s.close()
    if t(">=16B", len(r)>=16, f"{len(r)}B"):
        t("err=0xC054", up16(r,14)==ERR_DEV, f"0x{up16(r,14):04x}")

def test_dwr():
    pl=b'\x44'+struct.pack("<I",200)[:3]+struct.pack("<H",1234)
    s=conn(*HOST); r=xfer(s,ext(0x1401,300,pl)); s.close()
    chk_ext(r,"Dev wr",0x9401)

def test_loop():
    pl=struct.pack("<H",0x1234)
    s=conn(*HOST); r=xfer(s,ext(0x0500,400,pl)); s.close()
    if chk_ext(r,"Loop",0x8500):
        e=up16(r,16); t("0x1234->0x1235", e==0x1235, f"0x{e:04x}")

def test_ush():
    s=conn(*HOST); r=xfer(s,ext(0x6000,500,b"")); s.close()
    if t(">=16B", len(r)>=16, f"{len(r)}B"):
        t("err=0xC051", up16(r,14)==ERR_CMD, f"0x{up16(r,14):04x}")

HOST = ("127.0.0.1", 5007)

def main():
    print("MELSEC-Q Honeypot Test")
    print("--- 0x5000 subheader ---")
    test_cpu(); test_model(); test_version(); test_unk_cmd()
    print("--- Extended subheader ---")
    test_drd(); test_dunk(); test_dwr(); test_loop(); test_ush()
    print(f"\n{_pass}/{_run} passed, {_fail} failed")
    return 0 if _fail==0 else 1

if __name__=="__main__":
    sys.exit(main())
