#!/usr/bin/env python3
"""Gateway-Test OHNE Docker: zwei echte Postfix-Instanzen (sender/empfang), signierende+validierende DNS-Zonen,
Mitlese-Proxy zwischen den Gateways und ein 'Mailpit'-Ersatz. Nutzt die ausgelieferten main.cf/master.cf/Filter.
Voraussetzung: root (sudo), apt: postfix bind9 bind9utils unbound age swaks python3-dnspython python3-aiosmtpd
Aufruf: sudo python3 tests/native_gateway_test.py            (Stufe 1: Klartext-Zustellung, 13 Prüfungen)
        sudo python3 tests/native_gateway_test.py --stufe2   (Stufe 2: Umschlüsseln auf den Nutzerschlüssel)
"""
import os, re, shutil, signal, smtplib, subprocess, sys, time, email, email.policy, hashlib, threading, socket

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
T = "/tmp/dgtest"; os.environ["PATH"] += ":/usr/sbin:/sbin"
ok = bad = 0
def check(n, c):
    global ok, bad
    ok, bad = (ok + 1, bad) if c else (ok, bad + 1); print(("  ok   " if c else "  FAIL ") + n)
def sh(*a, **k): return subprocess.run(a, capture_output=True, text=True, **k)

def dgp1_payload(blob):
    """Trennt den DGP1-Kopf ab (Magic-Zeile, JSON-Zeile, dann die Daten)."""
    if blob is None or not blob.startswith(b"DGP1\n"):
        return blob
    return blob.split(b"\n", 2)[2]


if os.geteuid() != 0: sys.exit("bitte mit sudo starten")
if not os.path.isdir("/etc/postfix") or not shutil.which("postfix", path=os.environ["PATH"]):
    sys.exit("Postfix fehlt: sudo apt install postfix  (Rückfrage: 'No configuration')")
for tool in ("named", "unbound", "dnssec-keygen", "dnssec-signzone", "age", "swaks", "dig"):
    if not shutil.which(tool, path=os.environ["PATH"]): sys.exit(f"Programm fehlt: {tool} (siehe Voraussetzungen im Kopf dieser Datei)")
def busy(p):
    try: socket.create_connection(("127.0.0.1", p), 1).close(); return True
    except OSError: return False
for p_ in (2525, 2526, 2530, 1025, 5301, 5302, 10025, 10026):
    if busy(p_): sys.exit(f"Port {p_} ist belegt (Reste eines früheren Laufs? Prozesse master/named/unbound prüfen)")
import atexit
def cleanup():
    for q in (f"{T}/q-sender", f"{T}/q-empfang"):          # nur die Postfix-Master dieses Tests (Pidfile)
        try: os.kill(int(open(f"{q}/pid/master.pid").read().strip()), signal.SIGTERM)
        except Exception: pass
    for pf in ("named.pid", "unbound.pid", "unbound.shell.pid"):
        try: os.kill(int(open(f"{T}/dns/run/{pf}").read().strip()), signal.SIGTERM)
        except Exception: pass
atexit.register(cleanup)
cleanup(); time.sleep(1); shutil.rmtree(T, ignore_errors=True)
for d in ("bin", "log", "dns", "mail"): os.makedirs(f"{T}/{d}")
os.chmod(T, 0o755); os.chmod(f"{T}/log", 0o777)
for f in ("docguard_filter.py", "docguard_unwrap.py"):
    shutil.copy(f"{ROOT}/filters/{f}", f"{T}/bin/{f}"); os.chmod(f"{T}/bin/{f}", 0o755)
if not os.path.exists(f"{ROOT}/keys/empfang-private.key"):   # frisches Repo: Schlüssel erzeugen
    r = sh("sh", f"{ROOT}/setup-keys.sh")
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode: sys.exit("setup-keys.sh fehlgeschlagen: " + r.stderr)
shutil.copy(f"{ROOT}/keys/empfang-private.key", f"{T}/empfang.key"); os.chmod(f"{T}/empfang.key", 0o644)

# ---- DNS (signierend + validierend) ----
env = dict(os.environ, ZONES_SRC=f"{ROOT}/dns/zones", WORK=f"{T}/dns", RES_ADDR="127.0.0.1", RES_PORT="5302", DG_BACKGROUND="1")
r = subprocess.run(["bash", f"{ROOT}/dns/start.sh"], env=env, stdin=subprocess.DEVNULL, stdout=open(f"{T}/dns.out", "w"), stderr=subprocess.STDOUT)
if r.returncode: sys.exit("DNS-Start fehlgeschlagen: " + open(f"{T}/dns.out").read())
def dnsq():
    return sh("dig", "+dnssec", "-p", "5302", "@127.0.0.1", "_docguard.empfang.docguard.test", "TXT")
for _ in range(30):
    d = dnsq()
    if "v=DG1" in d.stdout: break
    time.sleep(1)
check("DNS-Lab liefert Schlüssel mit AD-Flag (validiert)", "v=DG1" in d.stdout and re.search(r"flags:[^;]*\bad\b", d.stdout) is not None)

# ---- Mailpit-Ersatz, Mitlese-Proxy ----
from aiosmtpd.controller import Controller
sink, tapped = [], []
class Sink:
    async def handle_DATA(self, s, ss, e): sink.append((e.mail_from, e.rcpt_tos, e.content)); return "250 OK"
class Tap:
    async def handle_DATA(self, s, ss, e):
        tapped.append(e.content)
        with smtplib.SMTP("127.0.0.1", 2526, timeout=30) as c: c.sendmail(e.mail_from, e.rcpt_tos, e.content)
        return "250 OK"
c1 = Controller(Sink(), hostname="127.0.0.1", port=1025); c1.start()
c2 = Controller(Tap(), hostname="127.0.0.1", port=2530); c2.start()

# ---- Postfix-Instanzen aus den ausgelieferten Dateien ----
def mkinst(name, smtp_port, reinj_port, extra_transport, pipe_script):
    cd = f"{T}/pf-{name}"; shutil.copytree("/etc/postfix", cd, symlinks=True, ignore=shutil.ignore_patterns("main.cf", "master.cf", "dynamicmaps.cf.d"))
    shutil.copy("/etc/postfix/dynamicmaps.cf", cd)
    mc = open(f"{ROOT}/postfix-{name}/main.cf").read()
    if "--no-env" in sys.argv:   # Diagnose: ohne import/export_environment (zeigt, warum die Zeilen nötig sind)
        mc = re.sub(r"^(import|export)_environment.*\n", "", mc, flags=re.M)
    mc = re.sub(r"^(maillog_file|inet_interfaces|mynetworks|myhostname)\b.*\n", "", mc, flags=re.M)
    mc += f"\nqueue_directory = {T}/q-{name}\ndata_directory = {T}/d-{name}\nmaillog_file = {T}/log/mail-{name}.log\nmaillog_file_prefixes = /var, /dev/stdout, /tmp\nmulti_instance_enable = yes\nmulti_instance_name = pf{name}\ninet_interfaces = 127.0.0.1\nmynetworks = 127.0.0.0/8\nmyhostname = mail.{name if name=='empfang' else 'sender'}.docguard.test\n"
    mc = re.sub(r"^transport_maps.*$", f"transport_maps = regexp:{cd}/transport.regexp", mc, flags=re.M)
    open(f"{cd}/main.cf", "w").write(mc)
    tr = open(f"{ROOT}/postfix-{name}/transport.regexp").read().replace("[10.10.0.30]:1025", "[127.0.0.1]:1025")
    open(f"{cd}/transport.regexp", "w").write(extra_transport + tr)
    ms = open(f"{ROOT}/postfix-{name}/master.cf").read()
    ms = ms.replace("smtp      inet  n", f"127.0.0.1:{smtp_port} inet  n", 1)
    ms = ms.replace("127.0.0.1:10025 inet", f"127.0.0.1:{reinj_port} inet")
    ms = ms.replace(f"/usr/local/bin/{pipe_script}", f"{T}/bin/{pipe_script}")
    open(f"{cd}/master.cf", "w").write(ms)
    os.makedirs(f"{T}/d-{name}", exist_ok=True); os.makedirs(f"{T}/q-{name}", exist_ok=True)
    sh("chown", "postfix", f"{T}/d-{name}")
    sh("postfix", "-c", cd, "check")   # legt Queue-Unterverzeichnisse an
    return cd
def start(cd, extra_env):
    e = dict(os.environ, DOCGUARD_DNS_SERVER="127.0.0.1:5302", DOCGUARD_SHADOW_MODE="0", DOCGUARD_REQUIRE_DNSSEC="1", **extra_env)
    log = f"{cd}/start.out"
    with open(log, "w") as fh:     # Datei statt Pipe: der Daemon erbt sonst die Pipe und subprocess.run hängt
        r = subprocess.run(["postfix", "-c", cd, "start"], env=e, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT)
    r.stdout, r.stderr = open(log).read(), ""
    return r
cd_s = mkinst("sender", 2525, 10025, "/@empfang\\.docguard\\.test$/ smtp:[127.0.0.1]:2530\n", "docguard_filter.py")
cd_e = mkinst("empfang", 2526, 10026, "", "docguard_unwrap.py")
rs = start(cd_s, {"DOCGUARD_LOG": f"{T}/log/filter.log", "DOCGUARD_REINJECT_PORT": "10025"})
S2 = "--stufe2" in sys.argv
e_env = {"DOCGUARD_LOG": f"{T}/log/unwrap.log", "DOCGUARD_PRIVATE_KEY": f"{T}/empfang.key", "DOCGUARD_REINJECT_PORT": "10026"}
if S2:   # Badge-Ersatz: Software-Schlüssel für bob; carol hat keinen Eintrag im Verzeichnis
    import json
    subprocess.run(["age-keygen", "-o", f"{T}/bob.key"], capture_output=True, check=True)
    bobpub = sh("age-keygen", "-y", f"{T}/bob.key").stdout.strip()
    json.dump({"bob@empfang.docguard.test": [bobpub]}, open(f"{T}/directory.json", "w"))
    os.makedirs(f"{T}/quarantine", exist_ok=True); os.chmod(f"{T}/quarantine", 0o777)
    e_env.update({"DOCGUARD_DIRECTORY": f"{T}/directory.json", "DOCGUARD_QUARANTINE": f"{T}/quarantine"})
re_ = start(cd_e, e_env)
time.sleep(3)
if rs.returncode or re_.returncode:
    print(rs.stdout, rs.stderr, re_.stdout, re_.stderr); sys.exit("Postfix-Start fehlgeschlagen")
def up(p):
    try: socket.create_connection(("127.0.0.1", p), 2).close(); return True
    except OSError: return False
check("Postfix sender/empfang lauschen", up(2525) and up(2526))

def send(rcpt, attach=None, subject="t"):
    a = ["swaks", "--to", rcpt, "--from", "alice@sender.docguard.test", "--server", "127.0.0.1:2525",
         "--header", f"Subject: {subject}", "--body", "hallo", "--suppress-data"]
    if attach: a += ["--attach", f"@{attach}"]
    return sh(*a)
def wait(cond, t=25):
    e = time.time() + t
    while time.time() < e:
        if cond(): return True
        time.sleep(0.5)
    return False
def parse(raw): return email.message_from_bytes(raw, policy=email.policy.default)


def age_open(raw_att, keyfile):
    p = subprocess.run(["age", "-d", "-i", keyfile], input=raw_att, capture_output=True)
    return p.stdout if p.returncode == 0 else None

if S2:
    payload = os.urandom(50000); open(f"{T}/mail/secret.bin", "wb").write(payload)
    EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    open(f"{T}/mail/eicar.bin", "wb").write(EICAR)
    print("S1: Anhang an Nutzer mit Badge-Schlüssel")
    send("bob@empfang.docguard.test", f"{T}/mail/secret.bin", "s1")
    got = wait(lambda: any(b"Subject: s1" in c for _, _, c in sink))
    check("Mail kam am Ziel an", got)
    if got:
        raw = [c for _, _, c in sink if b"Subject: s1" in c][0]
        m = parse(raw)
        atts = [p.get_payload(decode=True) for p in m.iter_attachments()]
        check("im Postfach nur Ciphertext (Klartext nirgends in der Nachricht)", len(atts) == 1 and payload[:64] not in raw and atts[0] != payload)
        check("Badge-Schlüssel öffnet den Anhang, byte-identisch", len(atts) == 1 and dgp1_payload(age_open(atts[0], f"{T}/bob.key")) == payload)
        check("Domänenschlüssel öffnet ihn nicht mehr", len(atts) == 1 and age_open(atts[0], f"{T}/empfang.key") is None)
        check("Nachrichtentext bleibt lesbar", "hallo" in m.get_body(("plain",)).get_content())
        check("Header markiert Modus recipient-key", "recipient-key" in (m["X-Docguard"] or ""))
    w = [c for c in tapped if b"Subject: s1" in c]
    check("zwischen den Gateways weiterhin Ciphertext (Stufe 1 unverändert)", len(w) == 1 and payload[:64] not in w[0])
    print("S2: Empfänger ohne Schlüssel im Verzeichnis (fail-closed)")
    n = len(sink)
    send("carol@empfang.docguard.test", f"{T}/mail/secret.bin", "s2")
    # Der Bounce selbst ist im Testaufbau nicht zustellbar (das Empfänger-Gateway kennt die Absenderdomain nicht),
    # daher wird die Ablehnung im Postfix-Log des Empfänger-Gateways geprüft.
    mlog = lambda: open(f"{T}/log/mail-empfang.log").read()
    check("Postfix lehnt ab (status=bounced, kein Nutzerschlüssel)", wait(lambda: "status=bounced (data format error. Command output: docguard fail-closed: kein Nutzerschluessel" in mlog()))
    check("nichts mit Anhang an Carol zugestellt", not any(b"Subject: s2" in c and b"docguard+age" in c for _, _, c in sink[n:]) and not any(payload[:64] in c for _, _, c in sink[n:]))
    print("S3: Prüfung schlägt an (EICAR) -> Quarantäne")
    n = len(sink)
    send("bob@empfang.docguard.test", f"{T}/mail/eicar.bin", "s3")
    check("Postfix lehnt ab (status=bounced, Anhang blockiert)", wait(lambda: "status=bounced (data format error. Command output: docguard: Anhang" in mlog()))
    check("EICAR-Anhang nicht zugestellt", not any(b"Subject: s3" in c and b"docguard+age" in c for _, _, c in sink[n:]))
    q = os.listdir(f"{T}/quarantine")
    check("Quarantäne hält nur Domänenschlüssel-Ciphertext, keinen Klartext", len(q) >= 1 and all(EICAR not in open(f"{T}/quarantine/{x}", "rb").read() for x in q))
    print("S4: Mail ohne Anhang")
    send("bob@empfang.docguard.test", None, "s4")
    check("ohne Anhang unverändert zugestellt", wait(lambda: any(b"Subject: s4" in c for _, _, c in sink)))
    ul = open(f"{T}/log/unwrap.log").read() if os.path.exists(f"{T}/log/unwrap.log") else ""
    check("Empfänger-Filter hat umgeschlüsselt (Log)", "umgeschluesselt" in ul and "ABGELEHNT" in ul)
else:
    payload = os.urandom(50000); open(f"{T}/mail/secret.bin", "wb").write(payload)
    print("T1: Anhang an signierte Empfängerdomain")
    send("bob@empfang.docguard.test", f"{T}/mail/secret.bin", "t1")
    got = wait(lambda: any(b"Subject: t1" in c for _, _, c in sink))
    check("Mail kam am Ziel an", got)
    if got:
        m = parse([c for _, _, c in sink if b"Subject: t1" in c][0])
        atts = [p.get_payload(decode=True) for p in m.iter_attachments()]
        check("Anhang beim Empfänger wieder im Klartext, byte-identisch", len(atts) == 1 and atts[0] == payload)
    w = [c for c in tapped if b"Subject: t1" in c]
    check("zwischen den Gateways: Anhang verschlüsselt (age)", len(w) == 1 and payload[:64] not in w[0] and b"application/docguard+age" in w[0])
    if w:
        check("zwischen den Gateways: neutraler Dateiname", b"docguard-1.age" in w[0])
        leck = b"secret.bin" in w[0]
        check("zwischen den Gateways: Originalname nicht sichtbar", not leck)
        if leck:        # zeigen, wo genau er steht, statt raten zu lassen
            i = w[0].find(b"secret.bin")
            umfeld = w[0][max(0, i - 200):i + 60].decode("utf-8", "replace")
            print("       Fundstelle: ..." + umfeld.replace("\r\n", " ⏎ ") + "...")
    print("T2: Anhang an unsignierte Domain (fail-closed)")
    n_tap = len(tapped); n_sink = len(sink)
    send("bob@unsigned.docguard.test", f"{T}/mail/secret.bin", "t2")
    b = wait(lambda: any(b"docguard fail-closed" in c for _, _, c in sink))
    check("Bounce an Absender zugestellt", b)
    check("nichts an den Empfänger-Gateway weitergeleitet", len(tapped) == n_tap and not any(b"Subject: t2" in c for c in tapped[n_tap:]))
    check("Klartext-Anhang nirgends zugestellt", not any(payload[:64] in c for _, _, c in sink[n_sink:]))
    print("T3: Mail ohne Anhang")
    send("bob@empfang.docguard.test", None, "t3")
    check("ohne Anhang unverändert zugestellt", wait(lambda: any(b"Subject: t3" in c for _, _, c in sink)))
    print("T4: Filter-Logs")
    fl = open(f"{T}/log/filter.log").read() if os.path.exists(f"{T}/log/filter.log") else ""
    ul = open(f"{T}/log/unwrap.log").read() if os.path.exists(f"{T}/log/unwrap.log") else ""
    check("Sender-Filter: ENFORCE statt SHADOW (Umgebung kommt an)", "[ENFORCE]" in fl and "[SHADOW]" not in fl)
    check("Empfänger-Filter hat entschlüsselt", "entschluesselt (" in ul)
    check("unsignierter Key wurde wegen fehlendem AD verworfen", "kein AD-Flag" in fl)


c1.stop(); c2.stop()
print(f"\n{ok} bestanden, {bad} fehlgeschlagen"); sys.exit(1 if bad else 0)
