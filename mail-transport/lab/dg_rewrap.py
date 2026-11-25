#!/usr/bin/env python3
"""Gateway-Schritt Stufe 2 (Lab): dg_rewrap.py IN.eml OUT.eml --domain-key KEY --directory DIR.json
Entschlüsselt den Anhang mit dem Domänenschlüssel (nur im Speicher), prüft ihn (Platzhalter-Scanner)
und verschlüsselt ihn für die Nutzerschlüssel (Badge-Ersatz) aus dem Verzeichnis. Fail-closed.
Exit: 0 ok, 3 fail-closed (kein Schlüssel), 4 age-Fehler, 5 Scan-Treffer (Quarantäne)."""
import argparse
import email
import email.policy
import sys
import dgcommon as g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inp"); ap.add_argument("out")
    ap.add_argument("--domain-key", required=True)
    ap.add_argument("--directory", required=True)
    a = ap.parse_args()
    msg = email.message_from_binary_file(open(a.inp, "rb"), policy=email.policy.default)
    try:
        out = g.rewrap_message(msg, a.domain_key, g.load_directory(a.directory))
    except g.FailClosed as e:
        print(f"FAIL-CLOSED: {e}", file=sys.stderr); sys.exit(g.EXIT_FAILCLOSED)
    except g.ScanBlocked as e:
        print(f"QUARANTÄNE: {e}", file=sys.stderr); sys.exit(5)
    except g.AgeError as e:
        print(f"age-Fehler: {e}", file=sys.stderr); sys.exit(4)
    open(a.out, "wb").write(out.as_bytes())
    print(f"umgeschlüsselt -> {a.out}")


if __name__ == "__main__":
    main()
