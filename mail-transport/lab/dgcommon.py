"""Gemeinsame Funktionen des docguard-lab (Client-seitige Simulation)."""
import email
import email.policy
import imaplib
import json
import os
import re
import smtplib
import ssl
import stat
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

EXIT_CONFIG, EXIT_FAILCLOSED, EXIT_AGE = 2, 3, 4
TXT_PREFIX = "_docguard."


class ConfigError(Exception):
    pass


class FailClosed(Exception):
    """Kein gültiger/validierter Schlüssel -> NICHT senden."""


class AgeError(Exception):
    pass


# ---------- Konfiguration ----------
def load_env(path="lab.env"):
    if not os.path.exists(path):
        raise ConfigError(f"{path} fehlt (lab.env.example kopieren und ausfüllen)")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        print(f"WARNUNG: {path} ist für andere lesbar (chmod 600 {path})", file=sys.stderr)
    env = {}
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def account(env, which):
    which = which.upper()
    keys = ["ADDRESS", "SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "IMAP_HOST",
            "IMAP_PORT", "USER", "PASS", "KEY_FILE"]
    acc = {}
    for k in keys:
        v = env.get(f"{which}_{k}")
        if v is None or v == "":
            raise ConfigError(f"{which}_{k} fehlt in lab.env")
        acc[k.lower()] = v
    acc["key_domain"] = env.get(f"{which}_KEY_DOMAIN") or acc["address"].split("@")[-1]
    acc["smtp_port"] = int(acc["smtp_port"])
    acc["imap_port"] = int(acc["imap_port"])
    if acc["smtp_security"] not in ("starttls", "ssl", "none"):
        raise ConfigError("SMTP_SECURITY muss starttls|ssl|none sein")
    return acc


# ---------- DNS ----------
def _dns_txt(name, resolver_ip):
    """Gibt (liste_von_txt_strings, ad_flag) zurück. Wird im Selbsttest ersetzt."""
    import dns.flags
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    ip, _, port = resolver_ip.partition(":") if resolver_ip.count(":") == 1 else (resolver_ip, "", "")
    r.nameservers = [ip]
    if port:
        r.port = int(port)
    r.use_edns(0, dns.flags.DO, 1232)
    r.lifetime = 8
    try:
        ans = r.resolve(name, "TXT", raise_on_no_answer=True)
    except Exception as e:
        raise FailClosed(f"DNS-Abfrage {name} fehlgeschlagen: {type(e).__name__}")
    ad = bool(ans.response.flags & dns.flags.AD)
    out = []
    for rd in ans:
        out.append(b"".join(rd.strings).decode("utf-8", "replace"))
    return out, ad


# Eintragsformat, Schreibweise wie bei DKIM:  v=DG1; k=age-x25519; p=age1...
# Dieselbe Auswertung steckt in sandbox/filters/docguard_filter.py. Die
# Dopplung ist gewollt: Der Filter wird als einzelne Datei in den Container
# eingehängt und kann dieses Modul dort nicht importieren. Wer hier etwas
# ändert, ändert es dort mit.
RECORD_VERSION = "DG1"
SUPPORTED_ALGORITHMS = {"age-x25519"}


def parse_record(txt):
    """Zerlegt einen TXT-Eintrag in seine Felder; unbekannte werden überlesen."""
    fields = {}
    for token in txt.split(";"):
        name, sep, value = token.strip().partition("=")
        if sep:
            fields[name.strip().lower()] = value.strip()
    return fields


def parse_txt_keys(txts):
    """
    Die Schlüssel aller Einträge, die zu dieser Fassung gehören.

    Eine unbekannte Version oder ein unbekannter Algorithmus ist kein Fehler,
    sondern wird übersprungen — nur so kann eine Domain ein neues Verfahren
    einführen, ohne ältere Sender zu brechen.
    """
    keys = []
    for t in txts:
        f = parse_record(t)
        if f.get("v") != RECORD_VERSION:
            continue
        if f.get("k") not in SUPPORTED_ALGORITHMS:
            continue
        p = f.get("p")
        if p and p not in keys:
            keys.append(p)
    return keys


def lookup_pubkey(domain, resolver_ip, require_dnssec=True):
    """
    Gibt genau einen Schlüssel zurück. Das Pooling mehrerer Schlüssel
    (Konzeptpapier 3.2) ist bisher nur im Sandbox-Filter umgesetzt; die
    nativen Werkzeuge bleiben bewusst bei einem Schlüssel, solange die
    aufrufenden Skripte einen einzelnen erwarten.
    """
    name = TXT_PREFIX + domain.strip(".").lower()
    txts, ad = _dns_txt(name, resolver_ip)
    if require_dnssec and not ad:
        raise FailClosed(f"{name}: Antwort nicht DNSSEC-validiert (kein AD-Flag) -> fail-closed")
    if not require_dnssec and not ad:
        print(f"WARNUNG: {name} ohne DNSSEC-Validierung akzeptiert (nur Lab!)", file=sys.stderr)
    keys = parse_txt_keys(txts)
    if len(keys) == 0:
        raise FailClosed(f"{name}: kein gültiger Eintrag (v={RECORD_VERSION}) gefunden")
    if len(keys) > 1:
        raise FailClosed(f"{name}: mehrere verschiedene Schlüssel (hier: genau einer erlaubt)")
    return keys[0]


# ---------- Nutzlastformat DGP1 ----------
# Der urspruengliche Content-Type und der Dateiname gehoeren in den
# verschluesselten Teil, nicht in die MIME-Huelle: Ein Dateiname wie
# "kuendigung_mueller.pdf" verraet den Inhalt auch dann, wenn die Datei
# selbst unlesbar ist. Aussen steht nur ein durchnummerierter Name.
#
#   DGP1\n
#   {"ct":"application/pdf","fn":"Kündigung.pdf","len":483201}\n
#   <Originalbytes>
#
# Der Kopf ist eine Zeile JSON zwischen zwei Zeilenumbruechen, damit er
# ohne MIME-Bibliothek zu lesen ist. "len" dient der Vollstaendigkeitspruefung.
DGP1_MAGIC = b"DGP1"
DGP1_CONTENT_TYPE = "application/docguard+age"
# Von der Fassung vor dem 25.11.2026 erzeugte Anhaenge; werden beim
# Entschluesseln weiterhin erkannt, aber nicht mehr erzeugt.
LEGACY_CONTENT_TYPE = "application/age-encrypted"


def dgp1_pack(content_type: str, filename: str, data: bytes) -> bytes:
    head = json.dumps({"ct": content_type, "fn": filename, "len": len(data)},
                      ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return DGP1_MAGIC + b"\n" + head + b"\n" + data


def dgp1_unpack(blob: bytes):
    """Gibt (content_type, dateiname, daten) zurueck. ValueError, wenn der
    Kopf fehlt oder die angekuendigte Laenge nicht stimmt."""
    magic, _, rest = blob.partition(b"\n")
    if magic != DGP1_MAGIC:
        raise ValueError("kein DGP1-Kopf")
    head, sep, data = rest.partition(b"\n")
    if not sep:
        raise ValueError("DGP1-Kopf unvollstaendig")
    try:
        meta = json.loads(head.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"DGP1-Kopf nicht lesbar: {exc}") from exc
    if meta.get("len") != len(data):
        raise ValueError(f"DGP1: {meta.get('len')} Byte angekuendigt, {len(data)} erhalten")
    return (meta.get("ct") or "application/octet-stream",
            meta.get("fn") or "anhang", data)


def set_header(part, name: str, value: str):
    """replace_header wirft KeyError, wenn der Header fehlt - das hier nicht."""
    if name in part:
        part.replace_header(name, value)
    else:
        part.add_header(name, value)


# ---------- age ----------
def age_encrypt(data: bytes, pubkey: str) -> bytes:
    p = subprocess.run(["age", "-r", pubkey], input=data, capture_output=True)
    if p.returncode != 0:
        raise AgeError(p.stderr.decode(errors="replace").strip())
    return p.stdout


def age_decrypt(data: bytes, key_file: str) -> bytes:
    p = subprocess.run(["age", "-d", "-i", key_file], input=data, capture_output=True)
    if p.returncode != 0:
        raise AgeError(p.stderr.decode(errors="replace").strip())
    return p.stdout


def age_pub_from_keyfile(key_file: str) -> str:
    p = subprocess.run(["age-keygen", "-y", key_file], capture_output=True)
    if p.returncode != 0:
        raise AgeError(p.stderr.decode(errors="replace").strip())
    return p.stdout.decode().strip()


# ---------- Nachricht ----------
def safe_name(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name or "anhang"


def build_message(sender, rcpt, subject, body, attachments, pubkey):
    """attachments: Liste (dateiname, bytes). Anhänge werden einzeln verschlüsselt."""
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, rcpt, subject
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
    m["X-Docguard"] = "1; mode=envelope-attachment"
    m.set_content(body)
    import mimetypes
    for i, (fname, data) in enumerate(attachments, start=1):
        ct = mimetypes.guess_type(fname)[0] or "application/octet-stream"
        # Im Ciphertext steht der Name so, wie er ist — safe_name() greift
        # erst dort, wo wirklich eine Datei geschrieben wird (decrypt_parts).
        base = os.path.basename(fname.replace("\\", "/")) or "anhang"
        enc = age_encrypt(dgp1_pack(ct, base, data), pubkey)
        maintype, _, subtype = DGP1_CONTENT_TYPE.partition("/")
        m.add_attachment(enc, maintype=maintype, subtype=subtype,
                         filename=f"docguard-{i}.age")
    return m


def decrypt_parts(msg, key_file):
    """Gibt Liste (content_type, originalname, klartext) zurück. Erkennt den
    Anhang am Content-Type oder, wie bisher, an der Endung .age."""
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename() or ""
        if (part.get_content_type() not in (DGP1_CONTENT_TYPE, LEGACY_CONTENT_TYPE)
                and not fn.lower().endswith(".age")):
            continue
        raw = part.get_payload(decode=True)
        if raw is None:
            continue
        blob = age_decrypt(raw, key_file)
        try:
            ct, name, data = dgp1_unpack(blob)
        except ValueError:
            # Anhang aus der Zeit vor DGP1
            ct = "application/octet-stream"
            name = fn[:-4] if fn.lower().endswith(".age") else (fn or "anhang")
            data = blob
        out.append((ct, safe_name(name), data))
    return out


def decrypt_message(msg, key_file):
    """Wie decrypt_parts, aber ohne Content-Type — Schnittstelle für dg_receive.py."""
    return [(name, data) for _ct, name, data in decrypt_parts(msg, key_file)]


# ---------- SMTP / IMAP ----------
def smtp_send(acc, msg):
    sec = acc["smtp_security"]
    host, port = acc["smtp_host"], acc["smtp_port"]
    if sec == "none" and host not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("SMTP_SECURITY=none nur für localhost erlaubt")
    ctx = ssl.create_default_context()
    if sec == "ssl":
        s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
        s.ehlo()
        if sec == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
    try:
        if acc["user"] and acc["pass"] and acc["pass"] != "-":
            s.login(acc["user"], acc["pass"])
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:
            pass


def imap_recent(acc, imap_cls=None, subject_token=None, limit=20, folder="INBOX"):
    """Liest Nachrichten read-only (BODY.PEEK[]). Optional Filter auf Betreff-Token."""
    cls = imap_cls or imaplib.IMAP4_SSL
    c = cls(acc["imap_host"], acc["imap_port"])
    msgs = []
    try:
        c.login(acc["user"], acc["pass"])
        c.select(folder, readonly=True)
        typ, data = c.search(None, "ALL")
        ids = data[0].split()[-limit:]
        for i in reversed(ids):
            typ, d = c.fetch(i, "(BODY.PEEK[])")
            raw = d[0][1]
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            if subject_token and subject_token not in (msg["Subject"] or ""):
                continue
            msgs.append(msg)
    finally:
        try:
            c.logout()
        except Exception:
            pass
    return msgs


def wait_for_message(acc, token, timeout=120, interval=5, folder_list=("INBOX", "Junk", "Spam")):
    end = time.time() + timeout
    while time.time() < end:
        for f in folder_list:
            try:
                r = imap_recent(acc, subject_token=token, folder=f)
            except Exception:
                continue
            if r:
                return r[0], f
        time.sleep(interval)
    return None, None


def new_token():
    return "DG-" + uuid.uuid4().hex[:12]


# ---------- Stufe 2: Umschlüsseln auf den Nutzerschlüssel (Badge) ----------
class ScanBlocked(Exception):
    pass


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def scan_stub(name: str, data: bytes):
    """Platzhalter für AV/DLP am Vertrauenspunkt. Erkennt nur den EICAR-Teststring.
    Gibt (ok, grund) zurück. In echt: ICAP/Milter/Hook (siehe Konzept)."""
    if EICAR in data:
        return False, "EICAR-Testsignatur"
    return True, ""


def load_directory(path):
    """Verzeichnis-Ersatz (Lab): JSON {"adresse": ["age1...", ...]}. In echt: LDAP/AD."""
    import json
    with open(path) as f:
        d = json.load(f)
    return {k.lower(): ([v] if isinstance(v, str) else list(v)) for k, v in d.items()}


def age_encrypt_multi(data: bytes, pubkeys) -> bytes:
    cmd = ["age"]
    for k in pubkeys:
        cmd += ["-r", k]
    p = subprocess.run(cmd, input=data, capture_output=True)
    if p.returncode != 0:
        raise AgeError(p.stderr.decode(errors="replace").strip())
    return p.stdout


def resolve_recipient_keys(msg, directory):
    """Alle Empfänger (To, Cc) müssen einen Schlüssel haben, sonst fail-closed."""
    from email.utils import getaddresses
    addrs = [a.lower() for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", [])) if a]
    if not addrs:
        raise FailClosed("keine Empfänger")
    keys = []
    for a in addrs:
        ks = directory.get(a)
        if not ks:
            raise FailClosed(f"kein Nutzerschlüssel im Verzeichnis für {a}")
        for k in ks:
            if k not in keys:
                keys.append(k)
    return keys


def rewrap_message(msg, domain_key_file, directory, scanner=scan_stub):
    """Domänenschlüssel -> prüfen (nur im Speicher) -> Nutzerschlüssel.
    Reihenfolge: erst Schlüssel auflösen (fail-closed), dann entschlüsseln, dann alles
    prüfen, erst danach wird neu verschlüsselt. Ein Fund blockiert die ganze Nachricht."""
    keys = resolve_recipient_keys(msg, directory)
    plain = decrypt_parts(msg, domain_key_file)
    if not plain:
        raise FailClosed("kein docguard-Anhang zum Umschlüsseln")
    for _ct, name, data in plain:
        ok, why = scanner(name, data)
        if not ok:
            raise ScanBlocked(f"{name}: {why}")
    out = EmailMessage()
    for h in ("From", "To", "Cc", "Subject", "Date", "Message-ID"):
        if msg[h]:
            out[h] = msg[h]
    out["X-Docguard"] = "1; mode=recipient-key"
    body = msg.get_body(preferencelist=("plain",))
    out.set_content(body.get_content() if body else "")
    maintype, _, subtype = DGP1_CONTENT_TYPE.partition("/")
    for i, (ct, name, data) in enumerate(plain, start=1):
        out.add_attachment(age_encrypt_multi(dgp1_pack(ct, name, data), keys),
                           maintype=maintype, subtype=subtype,
                           filename=f"docguard-{i}.age")
    return out
