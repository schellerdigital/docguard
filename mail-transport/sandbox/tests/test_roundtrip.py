#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Echter Durchlauf Sender-Filter -> Empfänger-Filter mit richtigem age.

Braucht age und age-keygen im Pfad, sonst nichts: kein Postfix, kein DNS,
keine Container. Geprüft wird, dass der Anhang Byte für Byte ankommt und
dass Typ und Dateiname den Weg durch den Ciphertext überstehen — und dass
sie unterwegs nirgends im Klartext stehen.
"""
import base64
import email
import email.policy
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
from email.message import EmailMessage

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_here), "filters"))
sys.path.insert(0, _here)

FAILS = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FEHL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


if not (shutil.which("age") and shutil.which("age-keygen")):
    print("age oder age-keygen fehlt - Test übersprungen")
    sys.exit(0)

tmp = tempfile.mkdtemp(prefix="docguard-roundtrip-")
keyfile = os.path.join(tmp, "empfang.key")
with open(keyfile, "wb") as fh:
    fh.write(subprocess.run(["age-keygen"], capture_output=True, check=True).stdout)
os.chmod(keyfile, 0o600)
pubkey = subprocess.run(["age-keygen", "-y", keyfile],
                        capture_output=True, check=True).stdout.decode().strip()

GEHEIM = bytes(range(256)) * 40                      # auch nicht-druckbare Bytes
NAME = "Kündigung Müller.pdf"                        # Umlaute im Dateinamen

os.environ["DOCGUARD_SHADOW_MODE"] = "0"
sys.modules.pop("docguard_filter", None)
f = importlib.import_module("docguard_filter")
f.lookup_pubkey = lambda d: [pubkey] if d == "empfang.test" else []
f.reinject = lambda *a, **k: None

os.environ["DOCGUARD_PRIVATE_KEY"] = keyfile
os.environ["DOCGUARD_DIRECTORY"] = ""
sys.modules.pop("docguard_unwrap", None)
u = importlib.import_module("docguard_unwrap")

m = EmailMessage()
m["From"] = "anwalt@kanzlei.test"
m["To"] = "mandant@empfang.test"
m["Subject"] = "Unterlagen"
m.set_content("Siehe Anhang.")
m.add_attachment(GEHEIM, maintype="application", subtype="pdf", filename=NAME)
m.add_attachment(b"zweiter Anhang", maintype="text", subtype="plain", filename="Notiz.txt")
raw = m.as_bytes(policy=email.policy.default)

print("Sender-Filter (echtes age):")
zu, bl = f.process(raw, "anwalt@kanzlei.test", ["mandant@empfang.test"])
check("eine Zustellung, nichts blockiert", len(zu) == 1 and bl == [])
unterwegs = zu[0][1]
teile = list(email.message_from_bytes(unterwegs, policy=email.policy.default).iter_attachments())
check("zwei Anhänge", len(teile) == 2, str(len(teile)))
check("Content-Type außen ist docguard+age",
      all(p.get_content_type() == "application/docguard+age" for p in teile))
check("Namen außen sind durchnummeriert",
      [p.get_filename() for p in teile] == ["docguard-1.age", "docguard-2.age"],
      str([p.get_filename() for p in teile]))
check("Originalname steht nirgends in der Nachricht",
      b"ndigung" not in unterwegs and "Kündigung".encode() not in unterwegs)
check("Originaltyp steht nicht mehr außen", b"application/pdf" not in unterwegs)
check("Klartext ist weg", GEHEIM[:64] not in unterwegs)

print("\nEmpfänger-Filter (echtes age):")
zurueck = u.process(unterwegs)
zteile = list(email.message_from_bytes(zurueck, policy=email.policy.default).iter_attachments())
check("zwei Anhänge zurück", len(zteile) == 2, str(len(zteile)))
if len(zteile) == 2:
    a, b = zteile
    check("Dateiname wiederhergestellt", a.get_filename() == NAME, a.get_filename())
    check("Content-Type wiederhergestellt",
          a.get_content_type() == "application/pdf", a.get_content_type())
    check("Inhalt Byte für Byte identisch", a.get_payload(decode=True) == GEHEIM)
    check("zweiter Anhang: Name", b.get_filename() == "Notiz.txt", b.get_filename())
    check("zweiter Anhang: Typ", b.get_content_type() == "text/plain", b.get_content_type())
    check("zweiter Anhang: Inhalt", b.get_payload(decode=True) == b"zweiter Anhang")

print("\nAnhang aus der Zeit vor DGP1 (alte Schreibweise):")
alt = EmailMessage()
alt["From"] = "gw@alpha.test"
alt["To"] = "mandant@empfang.test"
alt["Subject"] = "Alt"
alt.set_content("x")
roh = subprocess.run(["age", "-e", "-r", pubkey], input=b"alter Inhalt",
                     capture_output=True, check=True).stdout
alt.add_attachment(roh, maintype="application", subtype="age-encrypted",
                   filename="bericht.pdf.age")
out = u.process(alt.as_bytes(policy=email.policy.default))
t = list(email.message_from_bytes(out, policy=email.policy.default).iter_attachments())[0]
check("wird weiterhin entschlüsselt", t.get_payload(decode=True) == b"alter Inhalt")
check("Name kommt dann von außen", t.get_filename() == "bericht.pdf", t.get_filename())

print("\nBeschädigter Ciphertext:")
kaputt = EmailMessage()
kaputt["From"] = "gw@alpha.test"
kaputt["To"] = "mandant@empfang.test"
kaputt["Subject"] = "Kaputt"
kaputt.set_content("x")
kaputt.add_attachment(roh[:-20] + b"X" * 20, maintype="application",
                      subtype="docguard+age", filename="docguard-1.age")
try:
    u.process(kaputt.as_bytes(policy=email.policy.default))
    check("wird abgelehnt statt zugestellt", False, "lief durch")
except u.Reject:
    check("wird abgelehnt statt zugestellt", True)

shutil.rmtree(tmp, ignore_errors=True)

print()
if FAILS:
    print(f"FEHLGESCHLAGEN: {len(FAILS)} — " + "; ".join(FAILS))
    sys.exit(1)
print("Durchlauf vollständig, alle Prüfungen bestanden.")
