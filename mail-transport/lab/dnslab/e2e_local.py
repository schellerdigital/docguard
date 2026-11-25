#!/usr/bin/env python3
"""Komplett lokal: DNSSEC-Lab (up.sh) + lokaler SMTP-Sink. A -> B und B -> A ohne echte Postfächer."""
import email, email.policy, hashlib, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import dgcommon as g
from aiosmtpd.controller import Controller

R = "127.0.0.1:5302"
lab = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
box = []
class H:
    async def handle_DATA(self, s, sess, env):
        box.append(env.content); return "250 OK"
sk = socket.socket(); sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]; sk.close()
ctl = Controller(H(), hostname="127.0.0.1", port=port); ctl.start()
sink = {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_security": "none", "user": "", "pass": ""}
acc = {"A": ("lab@docguard.lab", "docguard.lab", "keys/a.key"), "B": ("lab@keyleash.lab", "keyleash.lab", "keys/b.key")}
ok = True
for frm, to in (("A", "B"), ("B", "A")):
    pub = g.lookup_pubkey(acc[to][1], R)
    data = os.urandom(65536)
    box.clear()
    g.smtp_send(sink, g.build_message(acc[frm][0], acc[to][0], "e2e", "x", [("p.bin", data)], pub))
    got = email.message_from_bytes(box[0], policy=email.policy.default)
    out = g.decrypt_message(got, os.path.join(lab, acc[to][2]))
    good = len(out) == 1 and out[0][1] == data
    # falscher Empfänger darf nicht entschlüsseln können
    wrong = os.path.join(lab, acc[frm][2])
    try: g.decrypt_message(got, wrong); leak = True
    except g.AgeError: leak = False
    print(f"{frm}->{to}: {'OK' if good else 'FEHLER'}; fremder Schlüssel scheitert: {'ja' if not leak else 'NEIN'}")
    ok = ok and good and not leak
ctl.stop(); print("GESAMT:", "BESTANDEN" if ok else "FEHLGESCHLAGEN"); sys.exit(0 if ok else 1)
