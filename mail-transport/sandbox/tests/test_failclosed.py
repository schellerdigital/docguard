#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prüft die beiden behobenen Fail-open-Stellen ohne laufende Sandbox.

DNS und age werden ersetzt; geprüft wird allein die Entscheidungslogik.
"""
import base64
import email
import email.policy
import importlib
import os
import subprocess
import sys
from email.message import EmailMessage

# Die Filter liegen eine Ebene höher in filters/; das eigene Verzeichnis
# kommt dazu, falls die Datei einmal neben den Filtern liegt.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_here), "filters"))
sys.path.insert(0, _here)

FAILS = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FEHL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def build(with_attachment=True):
    m = EmailMessage()
    m["From"] = "anwalt@kanzlei.test"
    m["To"] = "a@alpha.test, b@beta.test"
    m["Subject"] = "Unterlagen"
    m.set_content("Siehe Anhang.")
    if with_attachment:
        m.add_attachment(b"GEHEIM" * 100, maintype="application",
                         subtype="pdf", filename="akte.pdf")
    return m.as_bytes(policy=email.policy.default)


def load_filter_raw(shadow=False):
    """Lädt den Filter unverändert — für die Prüfung des Eintragsformats."""
    os.environ["DOCGUARD_SHADOW_MODE"] = "1" if shadow else "0"
    sys.modules.pop("docguard_filter", None)
    return importlib.import_module("docguard_filter")


def load_filter(shadow):
    """Lädt den Filter mit Attrappen für DNS und age."""
    mod = load_filter_raw(shadow)
    mod.lookup_pubkey = lambda d: ["age1ALPHAKEY"] if d == "alpha.test" else []
    mod.encrypt_bytes_with_age = (
        lambda pks, data: b"AGE[" + b",".join(k.encode() for k in pks) + b"]" + data)
    mod.reinject = lambda *a, **k: None
    return mod


def attachments_of(raw):
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return list(msg.iter_attachments())


print("docguard_filter — Nachricht an zwei Domains, nur alpha.test hat einen Schlüssel")

print("\nEnforce-Modus:")
f = load_filter(shadow=False)
zu, bl = f.process(build(), "anwalt@kanzlei.test", ["a@alpha.test", "b@beta.test"])
check("eine Zustellung", len(zu) == 1, f"{len(zu)}")
check("eine Blockade", len(bl) == 1, f"{len(bl)}")
if zu:
    rcpts, data = zu[0]
    check("Zustellung geht nur an alpha.test", rcpts == ["a@alpha.test"], str(rcpts))
    parts = attachments_of(data)
    ct = parts[0].get_content_type() if parts else ""
    check("Anhang ist verschlüsselt", ct == "application/docguard+age", ct)
    body = base64.b64decode(parts[0].get_payload()) if parts else b""
    # Verschlüsselt wird hier durch eine Attrappe, echte Vertraulichkeit ist
    # damit nicht prüfbar. Prüfbar ist, dass der richtige Domain-Schlüssel
    # verwendet und der Anhang überhaupt ersetzt wurde.
    check("Chiffrat entstand mit dem Schlüssel von alpha.test", b"age1ALPHAKEY" in body)
    check("Anhang ist nicht mehr der Originalinhalt", body != b"GEHEIM" * 100)
    name = parts[0].get_filename() if parts else ""
    check("Dateiname endet auf .age", name.endswith(".age"), name)
if bl:
    dom, rcpts = bl[0]
    check("blockiert wird beta.test", dom == "beta.test", dom)
    check("blockiert sind nur deren Empfänger", rcpts == ["b@beta.test"], str(rcpts))

print("\nAlte Fassung hätte hier unverschlüsselt an beide zugestellt.")

print("\nShadow-Modus:")
f = load_filter(shadow=True)
raw_in = build()
zu, bl = f.process(raw_in, "anwalt@kanzlei.test", ["a@alpha.test", "b@beta.test"])
check("nichts wird blockiert", bl == [])
check("beide Domains werden zugestellt", len(zu) == 2, f"{len(zu)}")
check("Nachrichten bleiben Byte für Byte unverändert",
      all(d == raw_in for _, d in zu))

print("\nOhne Anhang:")
f = load_filter(shadow=False)
zu, bl = f.process(build(with_attachment=False), "anwalt@kanzlei.test",
                   ["a@alpha.test", "b@beta.test"])
check("eine Zustellung an alle Empfänger",
      len(zu) == 1 and zu[0][0] == ["a@alpha.test", "b@beta.test"], str(zu[0][0] if zu else None))
check("kein DNS-Lookup nötig, nichts blockiert", bl == [])

print("\nDrei Empfänger, zwei davon in derselben Domain:")
zu, bl = f.process(build(), "anwalt@kanzlei.test",
                   ["a@alpha.test", "a2@alpha.test", "b@beta.test"])
check("alpha.test wird einmal zugestellt, an beide",
      len(zu) == 1 and zu[0][0] == ["a@alpha.test", "a2@alpha.test"], str(zu[0][0] if zu else None))
check("beta.test bleibt blockiert", len(bl) == 1 and bl[0][0] == "beta.test")

print("\ndocguard_filter — Eintragsformat v=DG1; k=age-x25519; p=age1…")
f = load_filter_raw()
K1 = "age1" + "a" * 55
K2 = "age1" + "b" * 55

check("gültiger Eintrag liefert den Schlüssel",
      f.key_from_record(f"v=DG1; k=age-x25519; p={K1}", "t") == K1)
check("Leerzeichen und Groß/Klein sind egal",
      f.key_from_record(f"V=DG1;K=age-x25519;  p={K1}", "t") == K1)
check("unbekanntes Zusatzfeld stört nicht",
      f.key_from_record(f"v=DG1; k=age-x25519; p={K1}; n=42", "t") == K1)
check("alte Schreibweise wird übersprungen",
      f.key_from_record(f"agepubkey={K1}", "t") is None)
check("andere Version wird übersprungen",
      f.key_from_record(f"v=docguard1; agepubkey={K1}", "t") is None)
check("unbekannter Algorithmus wird übersprungen",
      f.key_from_record(f"v=DG1; k=kyber-1024; p={K1}", "t") is None)
check("Eintrag ohne p= ist unbrauchbar",
      f.key_from_record("v=DG1; k=age-x25519", "t") is None)


def fake_dns(records, ad=True):
    """Ersetzt den Resolver, damit die Pool-Logik ohne DNS prüfbar ist."""
    import dns.flags

    class Rdata:
        def __init__(self, txt):
            self.strings = [txt.encode()]

    class Answers(list):
        pass

    class Response:
        flags = dns.flags.AD if ad else 0

    class Resolver:
        nameservers: list = []
        port = 53
        lifetime = 0

        def __init__(self, configure=True):
            pass

        def use_edns(self, *a, **k):
            pass

        def resolve(self, qname, rdtype):
            a = Answers(Rdata(r) for r in records)
            a.response = Response()
            return a

    f.dns.resolver.Resolver = Resolver


fake_dns([f"v=DG1; k=age-x25519; p={K1}"])
check("ein Schlüssel im Pool", f.lookup_pubkey("alpha.test") == [K1])

fake_dns([f"v=DG1; k=age-x25519; p={K1}", f"v=DG1; k=age-x25519; p={K2}"])
check("zwei Schlüssel im Pool", f.lookup_pubkey("alpha.test") == [K1, K2])

fake_dns([f"v=DG1; k=age-x25519; p={K1}", f"v=docguard1; agepubkey={K2}"])
check("alter Eintrag neben neuem wird ignoriert", f.lookup_pubkey("alpha.test") == [K1])

fake_dns([f"v=DG1; k=age-x25519; p=age1{c*55}" for c in "abcd"])
check("zu großer Pool wird verworfen (fail-closed)", f.lookup_pubkey("alpha.test") == [])

fake_dns([f"v=DG1; k=age-x25519; p={K1}"], ad=False)
check("ohne AD-Flag kein Schlüssel", f.lookup_pubkey("alpha.test") == [])

befehle = []
f.subprocess.run = lambda cmd, **kw: befehle.append(cmd)
f.encrypt_bytes_with_age([K1, K2], b"x")
check("age bekommt beide Schlüssel als -r",
      befehle and befehle[0].count("-r") == 2, str(befehle[:1]))

print("\ndocguard_unwrap — fehlgeschlagene Entschlüsselung")
os.environ["DOCGUARD_DIRECTORY"] = ""
sys.modules.pop("docguard_unwrap", None)
u = importlib.import_module("docguard_unwrap")


def boom(ciphertext):
    raise subprocess.CalledProcessError(1, ["age"], stderr=b"no identity matched")


u.decrypt_bytes_with_age = boom

m = EmailMessage()
m["From"] = "gw@alpha.test"
m["To"] = "a@alpha.test"
m["Subject"] = "Unterlagen"
m.set_content("Siehe Anhang.")
m.add_attachment(base64.b64encode(b"KAPUTT"), maintype="application",
                 subtype="age-encrypted", filename="akte.pdf.age")
raw = m.as_bytes(policy=email.policy.default)

try:
    u.process(raw)
    check("Reject wird ausgelöst", False, "process() lief durch")
except u.Reject as exc:
    check("Reject wird ausgelöst", True)
    check("Meldung nennt den Anhang", "akte.pdf.age" in str(exc), str(exc))

print("\nAlte Fassung hätte das Chiffrat kommentarlos zugestellt.")

print()
if FAILS:
    print(f"FEHLGESCHLAGEN: {len(FAILS)} — " + "; ".join(FAILS))
    sys.exit(1)
print("Alle Prüfungen bestanden.")
