#!/usr/bin/env python3
"""Rundlauf A->B und B->A mit zufälliger 64-KB-Nutzlast, SHA-256-Vergleich, plus Negativtest."""
import hashlib
import os
import sys
import dgcommon as g


def one(env, frm, to, timeout):
    s, r = g.account(env, frm), g.account(env, to)
    dom = r["key_domain"]
    pub = g.lookup_pubkey(dom, env.get("DG_DNS_RESOLVER", "9.9.9.9"),
                          env.get("DG_REQUIRE_DNSSEC", "1") == "1")
    payload = os.urandom(65536)
    tok = g.new_token()
    msg = g.build_message(s["address"], r["address"], f"docguard-lab {tok}",
                          "Rundlauftest", [("payload.bin", payload)], pub)
    g.smtp_send(s, msg)
    print(f"  gesendet {frm}->{to} ({tok}), warte auf Zustellung ...")
    got, folder = g.wait_for_message(r, tok, timeout=timeout)
    if not got:
        print("  FEHLER: nicht angekommen (Spam-Ordner? Greylisting? Timeout)")
        return False
    if folder != "INBOX":
        print(f"  Hinweis: Nachricht lag in '{folder}'")
    files = g.decrypt_message(got, r["key_file"])
    ok = len(files) == 1 and hashlib.sha256(files[0][1]).digest() == hashlib.sha256(payload).digest()
    print("  " + ("OK: SHA-256 identisch" if ok else "FEHLER: Inhalt abweichend"))
    return ok


def negative(env):
    try:
        g.lookup_pubkey("nonexistent-docguard-test.invalid", env.get("DG_DNS_RESOLVER", "9.9.9.9"), True)
    except g.FailClosed as e:
        print(f"  OK: fail-closed ({e})")
        return True
    print("  FEHLER: hätte fail-closed sein müssen")
    return False


def main():
    env = g.load_env()
    timeout = int(env.get("DG_WAIT", "120"))
    res = []
    print("A -> B"); res.append(one(env, "A", "B", timeout))
    print("B -> A"); res.append(one(env, "B", "A", timeout))
    print("Negativtest (kein Schlüssel im DNS)"); res.append(negative(env))
    print("\nGESAMT:", "BESTANDEN" if all(res) else "FEHLGESCHLAGEN")
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    try:
        main()
    except g.ConfigError as e:
        print(f"Konfigurationsfehler: {e}", file=sys.stderr); sys.exit(g.EXIT_CONFIG)
    except g.FailClosed as e:
        print(f"FAIL-CLOSED: {e}", file=sys.stderr); sys.exit(g.EXIT_FAILCLOSED)
