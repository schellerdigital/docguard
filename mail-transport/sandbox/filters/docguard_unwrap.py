#!/usr/bin/env python3
"""
docguard_unwrap.py — Empfaenger-seitiger Postfix Content-Filter (Stufe 0 / Sandbox).

Gegenstueck zu docguard_filter.py: entschluesselt Anhaenge mit
Content-Type 'application/age-encrypted' mithilfe des privaten
Schluessels dieser Domain und liefert den Klartext-Anhang normal aus.

Der private Schluessel verlaesst diesen Container nie (siehe
Konzeptpapier, Abschnitt 2) - er liegt lokal unter DOCGUARD_PRIVATE_KEY.
"""
import base64
import email
import json
import time
import email.policy
import logging
import os
import smtplib
import subprocess
import sys
import tempfile

REINJECT_HOST = os.environ.get("DOCGUARD_REINJECT_HOST", "127.0.0.1")
REINJECT_PORT = int(os.environ.get("DOCGUARD_REINJECT_PORT", "10025"))
PRIVATE_KEY_PATH = os.environ.get("DOCGUARD_PRIVATE_KEY", "/etc/docguard/private.key")
LOG_PATH = os.environ.get("DOCGUARD_LOG", "/var/log/docguard/unwrap.log")
# Stufe 2 (optional): Wenn gesetzt, wird nicht im Klartext zugestellt, sondern auf die
# Nutzerschluessel (Badge) aus diesem Verzeichnis (JSON {"adresse": ["age1..."]}) umgeschluesselt.
DIRECTORY_PATH = os.environ.get("DOCGUARD_DIRECTORY", "")
QUARANTINE_DIR = os.environ.get("DOCGUARD_QUARANTINE", "")
EX_DATAERR = 65   # Postfix pipe: Exit 65 = endgueltig ablehnen (Bounce), nichts wird zugestellt
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

_fmt = "%(asctime)s recipient-filter %(levelname)s %(message)s"
try:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format=_fmt)
except OSError:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=_fmt)


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


def reinject(envelope_from: str, envelope_rcpts: list[str], data: bytes):
    """Siehe docguard_filter.py: SMTP an den lokalen 10025-Listener statt
    den `sendmail`-Befehl, um eine Content-Filter-Endlosschleife zu vermeiden."""
    with smtplib.SMTP(REINJECT_HOST, REINJECT_PORT, timeout=30) as smtp:
        smtp.sendmail(envelope_from, envelope_rcpts, data)


def decrypt_bytes_with_age(ciphertext: bytes) -> bytes:
    with tempfile.NamedTemporaryFile() as src, tempfile.NamedTemporaryFile() as dst:
        src.write(ciphertext)
        src.flush()
        subprocess.run(
            ["age", "-d", "-i", PRIVATE_KEY_PATH, "-o", dst.name, src.name],
            check=True, capture_output=True,
        )
        return open(dst.name, "rb").read()


class Reject(Exception):
    pass


def scan_stub(name: str, data: bytes):
    """Platzhalter fuer AV/DLP am Vertrauenspunkt (hier nur EICAR-Testsignatur)."""
    return (False, "EICAR-Testsignatur") if EICAR in data else (True, "")


def load_directory(path: str) -> dict:
    with open(path) as fh:
        d = json.load(fh)
    return {k.lower(): ([v] if isinstance(v, str) else list(v)) for k, v in d.items()}


def encrypt_for(plaintext: bytes, pubkeys: list) -> bytes:
    cmd = ["age"]
    for k in pubkeys:
        cmd += ["-r", k]
    return subprocess.run(cmd, input=plaintext, check=True, capture_output=True).stdout


def rewrap(raw_message: bytes, envelope_rcpts: list) -> bytes:
    """Stufe 2: Domaenenschluessel -> pruefen (nur im Speicher) -> Nutzerschluessel.
    Alles oder nichts: fehlt fuer einen Empfaenger der Schluessel, oder schlaegt die Pruefung an,
    wird die ganze Nachricht abgelehnt (Reject). Es wird nie Klartext zugestellt."""
    msg = email.message_from_bytes(raw_message, policy=email.policy.default)
    parts = [p for p in msg.walk()
             if p.get_content_type() in (DGP1_CONTENT_TYPE, LEGACY_CONTENT_TYPE)]
    if not parts:
        return raw_message          # kein docguard-Anhang: unveraendert
    directory = load_directory(DIRECTORY_PATH)
    keys = []
    for r in envelope_rcpts:
        ks = directory.get(r.lower())
        if not ks:
            raise Reject(f"docguard fail-closed: kein Nutzerschluessel im Verzeichnis fuer {r}")
        keys += [k for k in ks if k not in keys]
    plain = []
    for part in parts:
        outer = part.get_filename() or "anhang.age"
        try:
            blob = decrypt_bytes_with_age(base64.b64decode(part.get_payload()))
        except subprocess.CalledProcessError as exc:
            raise Reject(f"docguard: Entschluesselung mit Domaenenschluessel fehlgeschlagen ({outer})") from exc
        try:
            content_type, name, data = dgp1_unpack(blob)
        except ValueError:
            content_type = "application/octet-stream"
            name = outer[:-4] if outer.endswith(".age") else outer
            data = blob
        ok, why = scan_stub(name, data)
        if not ok:
            raise Reject(f"docguard: Anhang '{name}' blockiert (Pruefung: {why})")
        plain.append((part, content_type, name, data))
    for part, content_type, name, data in plain:   # erst nach bestandener Pruefung
        # Der DGP1-Kopf bleibt erhalten: Auch der Nutzerschluessel-Anhang
        # soll Typ und Namen im verschluesselten Teil tragen, nicht aussen.
        enc = encrypt_for(dgp1_pack(content_type, name, data), keys)
        del part["Content-Transfer-Encoding"]
        part.add_header("Content-Transfer-Encoding", "base64")
        part.set_payload(base64.b64encode(enc).decode("ascii"))
        set_header(part, "Content-Type", DGP1_CONTENT_TYPE)
        logging.info("Anhang '%s' umgeschluesselt auf %d Nutzerschluessel (%d Byte)",
                     name, len(keys), len(data))
    if "X-Docguard" in msg:
        del msg["X-Docguard"]
    msg["X-Docguard"] = "1; mode=recipient-key"
    return msg.as_bytes(policy=email.policy.default)


def quarantine(raw: bytes, reason: str):
    """Legt die (noch Domaenenschluessel-verschluesselte) Originalnachricht ab, nie Klartext."""
    if not QUARANTINE_DIR:
        return
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        with open(os.path.join(QUARANTINE_DIR, f"{int(time.time()*1000)}.eml"), "wb") as fh:
            fh.write(raw)
    except OSError as exc:
        logging.error("Quarantaene nicht schreibbar: %s", exc)


def process(raw_message: bytes) -> bytes:
    """
    Entschluesselt alle docguard-Anhaenge. Schlaegt das bei einem Anhang
    fehl, wird die ganze Nachricht abgelehnt (Reject) und landet in der
    Quarantaene.

    Frueher wurde ein fehlgeschlagener Anhang uebersprungen und das Chiffrat
    stillschweigend zugestellt. Fuer den Empfaenger sah das aus wie eine
    kaputte Datei, waehrend in Wirklichkeit entweder der falsche Schluessel
    im Gateway lag oder jemand an der Nachricht manipuliert hatte — beides
    Vorfaelle, die auffallen muessen.
    """
    msg = email.message_from_bytes(raw_message, policy=email.policy.default)
    decrypted_count = 0

    for part in msg.walk():
        if part.get_content_type() not in (DGP1_CONTENT_TYPE, LEGACY_CONTENT_TYPE):
            continue
        filename = part.get_filename() or "anhang.age"
        ciphertext = base64.b64decode(part.get_payload())
        try:
            plaintext = decrypt_bytes_with_age(ciphertext)
        except subprocess.CalledProcessError as exc:
            logging.error("ALARM: Entschluesselung fehlgeschlagen fuer '%s': %s",
                          filename, exc.stderr)
            raise Reject(
                f"docguard: Entschluesselung des Anhangs '{filename}' fehlgeschlagen "
                f"- Nachricht nicht zugestellt"
            ) from exc

        try:
            content_type, original_name, data = dgp1_unpack(plaintext)
        except ValueError as exc:
            # Anhang aus der Zeit vor DGP1: Typ ist nicht ueberliefert, der
            # Name steckt noch aussen. Beides nur noch als Rueckfall.
            logging.info("'%s' ohne DGP1-Kopf (%s) - alte Schreibweise angenommen",
                         filename, exc)
            content_type = "application/octet-stream"
            original_name = filename[:-4] if filename.endswith(".age") else filename
            data = plaintext

        del part["Content-Transfer-Encoding"]
        part.add_header("Content-Transfer-Encoding", "base64")
        part.set_payload(base64.b64encode(data).decode("ascii"))
        set_header(part, "Content-Type", content_type)
        set_header(part, "Content-Disposition", f'attachment; filename="{original_name}"')
        decrypted_count += 1
        logging.info("Anhang '%s' entschluesselt (%s, %d Byte)",
                     original_name, content_type, len(data))

    if decrypted_count == 0:
        logging.info("Keine docguard-verschluesselten Anhaenge gefunden, Nachricht unveraendert")

    return msg.as_bytes(policy=email.policy.default)


def main():
    envelope_from = sys.argv[1]
    envelope_rcpts = sys.argv[2:]
    raw = sys.stdin.buffer.read()
    try:
        out = rewrap(raw, envelope_rcpts) if DIRECTORY_PATH else process(raw)
    except Reject as exc:
        # Gilt jetzt fuer beide Betriebsarten: nichts wird zugestellt, was
        # nicht vollstaendig geprueft bzw. entschluesselt werden konnte.
        logging.error("ABGELEHNT: %s", exc)
        quarantine(raw, str(exc))
        print(exc)
        sys.exit(EX_DATAERR)
    reinject(envelope_from, envelope_rcpts, out)


if __name__ == "__main__":
    main()
