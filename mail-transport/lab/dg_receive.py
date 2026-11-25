#!/usr/bin/env python3
"""Empfang: dg_receive.py A|B [--token T] [--limit N]  (IMAP read-only, entschlüsselt nach received/)"""
import argparse
import os
import sys
import dgcommon as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("konto", choices=["A", "B", "a", "b"])
    ap.add_argument("--token", default=None)
    ap.add_argument("--limit", type=int, default=10)
    a = ap.parse_args()
    env = g.load_env()
    acc = g.account(env, a.konto)
    msgs = g.imap_recent(acc, subject_token=a.token, limit=a.limit)
    os.makedirs("received", exist_ok=True)
    n = 0
    for m in msgs:
        try:
            files = g.decrypt_message(m, acc["key_file"])
        except g.AgeError as e:
            print(f"- '{m['Subject']}': Entschlüsselung fehlgeschlagen ({e})")
            continue
        for name, data in files:
            out = os.path.join("received", name)
            open(out, "wb").write(data)
            print(f"- '{m['Subject']}': {name} ({len(data)} Byte) -> {out}")
            n += 1
    print(f"{n} Anhang/Anhänge entschlüsselt")


if __name__ == "__main__":
    try:
        main()
    except g.ConfigError as e:
        print(f"Konfigurationsfehler: {e}", file=sys.stderr); sys.exit(g.EXIT_CONFIG)
