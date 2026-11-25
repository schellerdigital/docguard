#!/usr/bin/env python3
"""Prüft _docguard.<domain>: Key vorhanden? DNSSEC (AD)? passt zum lokalen Key?"""
import sys
import dgcommon as g


def main():
    env = g.load_env()
    resolver = env.get("DG_DNS_RESOLVER", "9.9.9.9")
    req = env.get("DG_REQUIRE_DNSSEC", "1") == "1"
    rc = 0
    for w in ("A", "B"):
        acc = g.account(env, w)
        dom = acc["key_domain"]
        print(f"[{w}] {acc['address']}  -> {g.TXT_PREFIX}{dom}")
        try:
            pub = g.lookup_pubkey(dom, resolver, req)
            print(f"    Key im DNS: {pub[:20]}...  DNSSEC: {'ok' if req else 'nicht erzwungen'}")
            try:
                local = g.age_pub_from_keyfile(acc["key_file"])
                print("    passt zum lokalen Schlüssel: " + ("JA" if local == pub else "NEIN"))
                if local != pub:
                    rc = g.EXIT_FAILCLOSED
            except Exception as e:
                print(f"    lokaler Schlüssel nicht lesbar: {e}")
                rc = g.EXIT_AGE
        except g.FailClosed as e:
            print(f"    FAIL-CLOSED: {e}")
            rc = g.EXIT_FAILCLOSED
    sys.exit(rc)


if __name__ == "__main__":
    try:
        main()
    except g.ConfigError as e:
        print(f"Konfigurationsfehler: {e}", file=sys.stderr)
        sys.exit(g.EXIT_CONFIG)
