#!/usr/bin/env python3
"""Offline-Test Stufe 2: Umschlüsseln auf den Nutzerschlüssel (Badge-Ersatz = Software-Schlüssel)."""
import email, email.policy, json, os, subprocess, sys, tempfile
import dgcommon as g

passed = failed = 0
def check(n, c):
    global passed, failed
    if c: passed += 1; print(f"  ok   {n}")
    else: failed += 1; print(f"  FAIL {n}")
def raises(exc, fn):
    try: fn()
    except exc: return True
    except Exception: return False
    return False

tmp = tempfile.mkdtemp()
def mkkey(n):
    f = os.path.join(tmp, n + ".key")
    subprocess.run(["age-keygen", "-o", f], capture_output=True, check=True)
    return f, g.age_pub_from_keyfile(f)

kdom, pdom = mkkey("domain")      # Domänenschlüssel (Transport)
kb1, pb1 = mkkey("badge1")        # Badge Empfänger 1
kb2, pb2 = mkkey("badge2")        # Badge Empfänger 2
kx, px = mkkey("fremd")
dirp = os.path.join(tmp, "dir.json")
json.dump({"anna@ziel.test": [pb1], "ben@ziel.test": pb2}, open(dirp, "w"))
D = g.load_directory(dirp)
data = os.urandom(50000)

def incoming(rcpt, payload=data):
    m = g.build_message("x@sender.test", rcpt, "t", "text bleibt lesbar", [("a.bin", payload)], pdom)
    return email.message_from_bytes(m.as_bytes(), policy=email.policy.default)

print("Umschlüsseln")
out = g.rewrap_message(incoming("anna@ziel.test"), kdom, D)
raw = out.as_bytes()
parsed = email.message_from_bytes(raw, policy=email.policy.default)
check("Nutzer-Badge öffnet den Anhang", g.decrypt_message(parsed, kb1)[0][1] == data)
check("Domänenschlüssel öffnet ihn nicht mehr", raises(g.AgeError, lambda: g.decrypt_message(parsed, kdom)))
check("fremder Schlüssel scheitert", raises(g.AgeError, lambda: g.decrypt_message(parsed, kx)))
check("Klartext nicht in Rohnachricht", data[:64] not in raw)
check("Nachrichtentext bleibt lesbar", "text bleibt lesbar" in parsed.get_body(("plain",)).get_content())
check("Header markiert Modus", "recipient-key" in parsed["X-Docguard"])

print("Mehrere Empfänger")
m2 = g.build_message("x@sender.test", "anna@ziel.test, ben@ziel.test", "t", "x", [("a.bin", data)], pdom)
o2 = email.message_from_bytes(g.rewrap_message(
    email.message_from_bytes(m2.as_bytes(), policy=email.policy.default), kdom, D).as_bytes(), policy=email.policy.default)
check("beide Badges öffnen", g.decrypt_message(o2, kb1)[0][1] == data and g.decrypt_message(o2, kb2)[0][1] == data)

print("Fail-closed")
check("Empfänger ohne Schlüssel -> FailClosed", raises(g.FailClosed, lambda: g.rewrap_message(incoming("niemand@ziel.test"), kdom, D)))
m3 = g.build_message("x@sender.test", "anna@ziel.test, niemand@ziel.test", "t", "x", [("a.bin", data)], pdom)
check("ein Empfänger ohne Schlüssel blockiert alle", raises(g.FailClosed, lambda: g.rewrap_message(
    email.message_from_bytes(m3.as_bytes(), policy=email.policy.default), kdom, D)))
check("falscher Domänenschlüssel -> AgeError", raises(g.AgeError, lambda: g.rewrap_message(incoming("anna@ziel.test"), kx, D)))
plain = email.message_from_string("From: a@x.test\nTo: anna@ziel.test\nSubject: s\n\nohne Anhang\n", policy=email.policy.default)
check("Nachricht ohne docguard-Anhang -> FailClosed", raises(g.FailClosed, lambda: g.rewrap_message(plain, kdom, D)))

print("Prüfung vor dem Umschlüsseln")
bad = incoming("anna@ziel.test", g.EICAR)
check("EICAR -> ScanBlocked (Quarantäne)", raises(g.ScanBlocked, lambda: g.rewrap_message(bad, kdom, D)))
seen = []
def spy(n, d): seen.append(d); return True, ""
g.rewrap_message(incoming("anna@ziel.test"), kdom, D, scanner=spy)
check("Scanner sieht den Klartext", seen and seen[0] == data)

print("Kommandozeile")
src = os.path.join(tmp, "in.eml"); dst = os.path.join(tmp, "out.eml")
open(src, "wb").write(incoming("anna@ziel.test").as_bytes())
r = subprocess.run([sys.executable, "dg_rewrap.py", src, dst, "--domain-key", kdom, "--directory", dirp], capture_output=True)
check("CLI Exit 0", r.returncode == 0)
check("CLI-Ergebnis mit Badge lesbar", g.decrypt_message(email.message_from_bytes(open(dst, "rb").read(), policy=email.policy.default), kb1)[0][1] == data)
open(src, "wb").write(incoming("niemand@ziel.test").as_bytes())
check("CLI Exit 3 ohne Schlüssel", subprocess.run([sys.executable, "dg_rewrap.py", src, dst, "--domain-key", kdom, "--directory", dirp], capture_output=True).returncode == 3)
open(src, "wb").write(bad.as_bytes() if hasattr(bad, "as_bytes") else b"")
check("CLI Exit 5 bei Fund", subprocess.run([sys.executable, "dg_rewrap.py", src, dst, "--domain-key", kdom, "--directory", dirp], capture_output=True).returncode == 5)

print(f"\n{passed} bestanden, {failed} fehlgeschlagen")
sys.exit(1 if failed else 0)
