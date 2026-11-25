#!/usr/bin/env python3
"""Testet das lokale DNSSEC-Lab (up.sh muss laufen). Nutzt dieselbe Logik wie dg_send."""
import os, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import dgcommon as g

R = "127.0.0.1:5302"
here = os.path.dirname(os.path.abspath(__file__))
lab = os.path.dirname(here)
ok = bad = 0
def check(n, c):
    global ok, bad
    ok, bad = (ok + 1, bad) if c else (ok, bad + 1)
    print(("  ok   " if c else "  FAIL ") + n)
def fc(dom, req=True):
    try:
        g.lookup_pubkey(dom, R, req); return False
    except g.FailClosed:
        return True

pa = g.age_pub_from_keyfile(os.path.join(lab, "keys/a.key"))
pb = g.age_pub_from_keyfile(os.path.join(lab, "keys/b.key"))
print("Positiv")
check("docguard.lab: Key + AD", g.lookup_pubkey("docguard.lab", R) == pa)
check("keyleash.lab: Key + AD", g.lookup_pubkey("keyleash.lab", R) == pb)
print("Negativ")
check("unsigned.lab: fail-closed (kein AD)", fc("unsigned.lab"))
check("unsigned.lab mit REQUIRE=0: Key wird akzeptiert", g.lookup_pubkey("unsigned.lab", R, False) == pb)
check("nicht existierende Zone: fail-closed", fc("gibtsnicht.lab"))
print("Manipulation")
subprocess.run([os.path.join(here, "tamper.sh")], check=True, capture_output=True)
check("manipulierte Zone (ungültige Signatur): fail-closed", fc("docguard.lab"))
check("manipulierte Zone auch mit REQUIRE=0: fail-closed (Resolver liefert SERVFAIL)", fc("docguard.lab", False))
check("keyleash.lab bleibt gültig", g.lookup_pubkey("keyleash.lab", R) == pb)
print(f"\n{ok} bestanden, {bad} fehlgeschlagen")
sys.exit(1 if bad else 0)
