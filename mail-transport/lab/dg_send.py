#!/usr/bin/env python3
"""Versand: dg_send.py A B datei [datei...] [--subject S] [--body T]
Schlüssel kommt aus DNS (_docguard.<Empfängerdomain>); ohne gültigen Key wird NICHT gesendet."""
import argparse
import os
import sys
import dgcommon as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sender", choices=["A", "B", "a", "b"])
    ap.add_argument("empfaenger", choices=["A", "B", "a", "b"])
    ap.add_argument("dateien", nargs="+")
    ap.add_argument("--subject", default=None)
    ap.add_argument("--body", default="docguard-lab Testnachricht")
    a = ap.parse_args()
    env = g.load_env()
    s, r = g.account(env, a.sender), g.account(env, a.empfaenger)
    dom = r["key_domain"]
    pub = g.lookup_pubkey(dom, env.get("DG_DNS_RESOLVER", "9.9.9.9"),
                          env.get("DG_REQUIRE_DNSSEC", "1") == "1")
    atts = [(os.path.basename(p), open(p, "rb").read()) for p in a.dateien]
    subj = a.subject or ("docguard-lab " + g.new_token())
    msg = g.build_message(s["address"], r["address"], subj, a.body, atts, pub)
    g.smtp_send(s, msg)
    print(f"gesendet: {s['address']} -> {r['address']}  Betreff: {subj}")


if __name__ == "__main__":
    try:
        main()
    except g.ConfigError as e:
        print(f"Konfigurationsfehler: {e}", file=sys.stderr); sys.exit(g.EXIT_CONFIG)
    except g.FailClosed as e:
        print(f"FAIL-CLOSED, nichts gesendet: {e}", file=sys.stderr); sys.exit(g.EXIT_FAILCLOSED)
    except g.AgeError as e:
        print(f"age-Fehler: {e}", file=sys.stderr); sys.exit(g.EXIT_AGE)
