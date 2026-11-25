#!/usr/bin/env python3
"""Offline-Selbsttest: Krypto, MIME, fail-closed, DNS-Parsing, SMTP (lokal), IMAP (Fake)."""
import email
import email.policy
import os
import subprocess
import sys
import tempfile
import threading
import time

import dgcommon as g

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ok   {name}")
    else:
        failed += 1; print(f"  FAIL {name}")


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


tmp = tempfile.mkdtemp()
def mkkey(n):
    f = os.path.join(tmp, n + ".key")
    subprocess.run(["age-keygen", "-o", f], capture_output=True, check=True)
    return f, g.age_pub_from_keyfile(f)

ka, pa = mkkey("a"); kb, pb = mkkey("b")
payload = os.urandom(65536)

print("Krypto / MIME")
enc = g.age_encrypt(payload, pb)
check("Ciphertext != Klartext", enc != payload and payload[:32] not in enc)
check("Entschlüsselung mit richtigem Key", g.age_decrypt(enc, kb) == payload)
check("falscher Key scheitert", raises(g.AgeError, lambda: g.age_decrypt(enc, ka)))
m = g.build_message("a@x.test", "b@y.test", "t", "body", [("../../etc/passwd", payload)], pb)
raw = m.as_bytes()
check("Klartext nicht in Rohnachricht", payload[:64] not in raw)
check("äußerer Name ist neutral", b"docguard-1.age" in raw)
check("Originalname steht nicht außen", b"passwd" not in raw and b"../" not in raw)
check("Name kommt aus dem Ciphertext zurück",
      g.decrypt_parts(g.email.message_from_bytes(raw, policy=g.email.policy.default), kb)[0][1] == "passwd")
parsed = email.message_from_bytes(raw, policy=email.policy.default)
files = g.decrypt_message(parsed, kb)
check("Empfänger entschlüsselt", len(files) == 1 and files[0][1] == payload)
# umgeschriebener Content-Type
for p in parsed.walk():
    if p.get_filename():
        p.replace_header("Content-Type", f'application/x-weird; name="{p.get_filename()}"')
check("umgeschriebener Content-Type akzeptiert", g.decrypt_message(parsed, kb)[0][1] == payload)
check("safe_name", g.safe_name("..\\..\\a b.txt") == "a_b.txt")

print("DNS-Logik (gemockt)")
orig = g._dns_txt
def mock(txts, ad):
    g._dns_txt = lambda n, r: (txts, ad)
good = [f"v=DG1; k=age-x25519; p={pb}"]
mock(good, True);  check("gültiger Key + AD", g.lookup_pubkey("y.test", "x") == pb)
mock(good, False); check("ohne AD -> fail-closed", raises(g.FailClosed, lambda: g.lookup_pubkey("y.test", "x")))
mock(good, False); check("ohne AD, require=0 -> ok", g.lookup_pubkey("y.test", "x", False) == pb)
mock([], True);    check("leer -> fail-closed", raises(g.FailClosed, lambda: g.lookup_pubkey("y.test", "x")))
mock(["v=spf1 -all"], True); check("fremder TXT -> fail-closed", raises(g.FailClosed, lambda: g.lookup_pubkey("y.test", "x")))
mock(good + [f"v=DG1; k=age-x25519; p={pa}"], True); check("zwei Keys -> fail-closed", raises(g.FailClosed, lambda: g.lookup_pubkey("y.test", "x")))
mock(good + good, True); check("identischer Key doppelt -> ok", g.lookup_pubkey("y.test", "x") == pb)
mock([f"v=docguard1; agepubkey={pb}"], True); check("alte Schreibweise -> fail-closed", raises(g.FailClosed, lambda: g.lookup_pubkey("y.test", "x")))
g._dns_txt = orig

print("SMTP (lokaler aiosmtpd)")
try:
    from aiosmtpd.controller import Controller
    box = []
    class H:
        async def handle_DATA(self, server, session, envelope):
            box.append(envelope.content); return "250 OK"
    import socket
    _s = socket.socket(); _s.bind(("127.0.0.1", 0)); port = _s.getsockname()[1]; _s.close()
    ctl = Controller(H(), hostname="127.0.0.1", port=port); ctl.start()
    acc = {"smtp_host": "127.0.0.1", "smtp_port": port,
           "smtp_security": "none", "user": "", "pass": ""}
    g.smtp_send(acc, m)
    check("Nachricht zugestellt", len(box) == 1)
    got = email.message_from_bytes(box[0], policy=email.policy.default)
    check("Anhang nach SMTP entschlüsselbar", g.decrypt_message(got, kb)[0][1] == payload)
    acc2 = dict(acc, smtp_host="mail.example.com")
    check("security=none nur localhost", raises(g.ConfigError, lambda: g.smtp_send(acc2, m)))
    ctl.stop()
except ImportError:
    print("  übersprungen (aiosmtpd fehlt)")

print("IMAP (Fake, read-only)")
class FakeIMAP:
    log = []
    def __init__(self, h, p): pass
    def login(self, u, p): return "OK", []
    def select(self, f, readonly=False): FakeIMAP.log.append(("select", readonly)); return "OK", [b"1"]
    def search(self, c, q): return "OK", [b"1"]
    def fetch(self, i, what): FakeIMAP.log.append(("fetch", what)); return "OK", [(b"1", raw)]
    def logout(self): return "BYE", []
acc = {"imap_host": "x", "imap_port": 993, "user": "u", "pass": "p"}
r = g.imap_recent(acc, imap_cls=FakeIMAP)
check("Nachricht gelesen", len(r) == 1 and g.decrypt_message(r[0], kb)[0][1] == payload)
check("readonly + BODY.PEEK", ("select", True) in FakeIMAP.log and ("fetch", "(BODY.PEEK[])") in FakeIMAP.log)
check("Token-Filter", g.imap_recent(acc, imap_cls=FakeIMAP, subject_token="nein") == [])

print("Konfiguration")
p = os.path.join(tmp, "e.env")
open(p, "w").write("A_ADDRESS=a@x # kommentar\n# B_X=1\n"); os.chmod(p, 0o600)
check("env-Parser", g.load_env(p) == {"A_ADDRESS": "a@x"})
check("fehlender Eintrag -> ConfigError", raises(g.ConfigError, lambda: g.account({"A_ADDRESS": "a@x"}, "A")))

print(f"\n{passed} bestanden, {failed} fehlgeschlagen")
sys.exit(1 if failed else 0)
