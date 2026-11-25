#!/usr/bin/env python3
"""
docguard_filter.py — Sender-seitiger Postfix Content-Filter (Stufe 0 / Sandbox).

Vertragskonvention (Postfix "simple content filter", after-queue):
  - Die Nachricht kommt komplett als RFC822 auf stdin.
  - Das Skript darf sie verändern und muss sie über `sendmail -G -i`
    zurück in die Queue einspeisen, sonst geht sie verloren.
  - Exit-Code 0 = "ich habe die Nachricht übernommen" (auch bei Fail-Closed-
    Bounce, den erzeugt dann das Skript selbst über eine Bounce-Mail).

Kryptografie: nutzt bewusst das etablierte `age`-Tool für die Envelope-
Encryption (asymmetrisch, ECIES-artig) statt eine eigene Implementierung —
das ist exakt der Baustein, den das docguard-Konzeptpapier als Referenz
nennt. Der eigentliche docguard-Kern (Argon2id + AES-256-GCM) bleibt für
die passphrasenbasierte Variante reserviert; hier geht es um den
transparenten Mail-Transport-Anwendungsfall.

Umgebungsvariablen:
  DOCGUARD_SHADOW_MODE=1   (Default) Nur protokollieren, nicht wirklich
                           verschlüsseln/blockieren — sicherer erster Schritt,
                           bevor echte Nachrichten verändert werden.
  DOCGUARD_SHADOW_MODE=0   Scharf schalten: tatsächlich verschlüsseln bzw.
                           bei fehlendem Schlüssel per Fail-Closed blockieren.
  DOCGUARD_DNS_SERVER      IP[:Port] des validierenden Resolvers (Sandbox-Unbound), z.B. 10.10.0.53
  DOCGUARD_REQUIRE_DNSSEC  1 (Default) = Schluessel nur akzeptieren, wenn der Resolver die
                           Antwort DNSSEC-validiert hat (AD-Flag). 0 = nur zum Debuggen.
  DOCGUARD_LOG             Pfad zur Logdatei (Default: /var/log/docguard/filter.log)
"""
import base64
import email
import json
import email.policy
import logging
import os
import smtplib
import subprocess
import sys
import tempfile
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import dns.flags
import dns.resolver  # dnspython

REINJECT_HOST = os.environ.get("DOCGUARD_REINJECT_HOST", "127.0.0.1")
REINJECT_PORT = int(os.environ.get("DOCGUARD_REINJECT_PORT", "10025"))
SHADOW_MODE = os.environ.get("DOCGUARD_SHADOW_MODE", "1") != "0"
DNS_SERVER = os.environ.get("DOCGUARD_DNS_SERVER")
REQUIRE_DNSSEC = os.environ.get("DOCGUARD_REQUIRE_DNSSEC", "1") != "0"
LOG_PATH = os.environ.get("DOCGUARD_LOG", "/var/log/docguard/filter.log")

_fmt = "%(asctime)s sender-filter %(levelname)s %(message)s"
try:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format=_fmt)
except OSError:  # z.B. keine Schreibrechte fuer den Pipe-User -> nicht abstuerzen
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=_fmt)


def reinject(envelope_from: str, envelope_rcpts: list[str], data: bytes):
    """
    Speist die (ggf. veraenderte) Nachricht per SMTP auf dem lokalen
    Reinjection-Listener (127.0.0.1:10025, siehe master.cf) wieder ein.

    WICHTIG: Re-Injection ueber den lokalen `sendmail`-Befehl wuerde
    erneut durch main.cf's content_filter laufen -> Endlosschleife. Der
    10025-Listener hat content_filter bewusst geleert (siehe master.cf-
    Kommentar), deshalb SMTP direkt an diesen Port statt den
    Kommandozeilen-Sendmail zu nutzen.
    """
    with smtplib.SMTP(REINJECT_HOST, REINJECT_PORT, timeout=30) as smtp:
        smtp.sendmail(envelope_from, envelope_rcpts, data)


RECORD_VERSION = "DG1"
SUPPORTED_ALGORITHMS = {"age-x25519"}
MAX_POOL = 3


def parse_record(txt: str) -> dict[str, str]:
    """
    Zerlegt einen TXT-Eintrag in seine Felder, Schreibweise wie bei DKIM:

        v=DG1; k=age-x25519; p=age1...

    Unbekannte Felder werden ueberlesen, damit spaetere Erweiterungen
    aeltere Sender nicht brechen.
    """
    fields: dict[str, str] = {}
    for token in txt.split(";"):
        name, sep, value = token.strip().partition("=")
        if sep:
            fields[name.strip().lower()] = value.strip()
    return fields


def key_from_record(txt: str, qname: str) -> str | None:
    """
    Gibt den Schluessel eines Eintrags zurueck, oder None, wenn der Eintrag
    nicht zu dieser Fassung gehoert.

    Unbekannte Version und unbekannter Algorithmus sind ausdruecklich KEIN
    Fehler, sondern werden uebersprungen: Nur so kann eine Domain ein neues
    Verfahren einfuehren, waehrend aeltere Sender den alten Eintrag
    weiterbenutzen.
    """
    fields = parse_record(txt)
    version = fields.get("v")
    if version != RECORD_VERSION:
        logging.info("%s: Eintrag mit Version %r uebersprungen (erwartet %s)",
                     qname, version, RECORD_VERSION)
        return None
    algorithm = fields.get("k")
    if algorithm not in SUPPORTED_ALGORITHMS:
        logging.info("%s: Algorithmus %r nicht unterstuetzt, Eintrag uebersprungen",
                     qname, algorithm)
        return None
    pubkey = fields.get("p")
    if not pubkey:
        logging.warning("%s: Eintrag ohne p= - unbrauchbar", qname)
        return None
    return pubkey


def lookup_pubkey(domain: str) -> list[str]:
    """
    DNS-TXT-Lookup unter _docguard.<domain>. Gibt die Liste der verwertbaren
    oeffentlichen Schluessel zurueck (Pool, siehe Konzeptpapier 3.2) oder
    eine leere Liste.

    Mit REQUIRE_DNSSEC wird das Ergebnis nur akzeptiert, wenn der
    (validierende) Resolver die Antwort als authentisch markiert hat
    (AD-Flag). Fail-closed: kein Eintrag, kein AD, zu grosser Pool -> [].
    """
    resolver = dns.resolver.Resolver(configure=DNS_SERVER is None)
    if DNS_SERVER:
        host, _, port = DNS_SERVER.partition(":") if DNS_SERVER.count(":") == 1 else (DNS_SERVER, "", "")
        resolver.nameservers = [host]
        if port:
            resolver.port = int(port)
    resolver.use_edns(0, dns.flags.DO, 1232)
    resolver.lifetime = 8
    qname = f"_docguard.{domain}"
    try:
        answers = resolver.resolve(qname, "TXT")
    except Exception as exc:
        logging.info("DNS-Lookup fehlgeschlagen fuer %s: %s", qname, type(exc).__name__)
        return []
    if REQUIRE_DNSSEC and not (answers.response.flags & dns.flags.AD):
        logging.warning("%s: Antwort nicht DNSSEC-validiert (kein AD-Flag) - Schluessel verworfen", qname)
        return []

    keys: list[str] = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", "ignore")
        key = key_from_record(txt, qname)
        if key and key not in keys:
            keys.append(key)

    if not keys:
        logging.warning("%s: kein verwertbarer docguard-Eintrag gefunden", qname)
        return []
    if len(keys) > MAX_POOL:
        # Lieber nichts zustellen als an eine willkuerliche Teilmenge wrappen:
        # haelt das Empfaenger-Gateway den weggelassenen Schluessel, kaeme die
        # Nachricht unlesbar an. Mehr als MAX_POOL ist eine Fehlkonfiguration.
        logging.warning("%s: %d Schluessel im Pool, hoechstens %d erlaubt - verworfen",
                        qname, len(keys), MAX_POOL)
        return []
    return keys


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


def recipient_domain(rcpt: str) -> str:
    return rcpt.rsplit("@", 1)[-1].strip().rstrip(">").lower()


def group_by_domain(rcpts: list[str]) -> dict[str, list[str]]:
    """
    Gruppiert die Envelope-Empfaenger nach Zieldomain.

    Der Schluessel wird je Domain veroeffentlicht, also faellt auch die
    Entscheidung je Domain. Eine Nachricht an zwei Domains ergibt zwei
    Zustellungen mit je eigenem Chiffrat — sonst muesste der symmetrische
    Schluessel an beide Domains gewrappt werden, und jede koennte die
    Anhaenge der jeweils anderen Empfaenger lesen.
    """
    groups: dict[str, list[str]] = {}
    for rcpt in rcpts:
        groups.setdefault(recipient_domain(rcpt), []).append(rcpt)
    return groups


def encrypt_bytes_with_age(pubkeys: list[str], data: bytes) -> bytes:
    """
    Verschluesselt fuer einen oder mehrere Empfaengerschluessel. Mehrere
    Schluessel sind der Pool-Fall aus Abschnitt 3.2 des Konzeptpapiers:
    age wrappt den Nachrichtenschluessel an jeden davon, entschluesseln kann
    jeder einzelne.
    """
    recipients: list[str] = []
    for key in pubkeys:
        recipients += ["-r", key]
    with tempfile.NamedTemporaryFile() as src, tempfile.NamedTemporaryFile() as dst:
        src.write(data)
        src.flush()
        subprocess.run(
            ["age", "-e", *recipients, "-o", dst.name, src.name],
            check=True, capture_output=True,
        )
        return open(dst.name, "rb").read()


def encrypt_for_domain(raw_message: bytes, pubkeys: list[str], domain: str) -> tuple[bytes, int]:
    """
    Verschluesselt alle Anhaenge einer frischen Kopie der Nachricht fuer
    genau eine Zieldomain. Die Kopie ist noetig, weil jede Domain ihr
    eigenes Chiffrat bekommt.
    """
    msg = email.message_from_bytes(raw_message, policy=email.policy.default)
    count = 0
    for part in msg.iter_attachments():
        filename = part.get_filename() or "anhang.bin"
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)

        # Typ und Name wandern in den Ciphertext; aussen bleibt ein
        # durchnummerierter Name ohne Aussagekraft.
        blob = dgp1_pack(content_type, filename, payload)
        ciphertext = encrypt_bytes_with_age(pubkeys, blob)

        count += 1
        del part["Content-Transfer-Encoding"]
        part.add_header("Content-Transfer-Encoding", "base64")
        part.set_payload(base64.b64encode(ciphertext).decode("ascii"))
        set_header(part, "Content-Type", DGP1_CONTENT_TYPE)
        set_header(part, "Content-Disposition",
                   f'attachment; filename="docguard-{count}.age"')
        # Content-Description traegt bei manchen Versendern (u.a. swaks) noch
        # einmal den Dateinamen. Content-Type und Content-Disposition werden
        # oben ersetzt, dieser Header bliebe sonst als Klartext stehen.
        del part["Content-Description"]
        logging.info("[ENFORCE] Anhang %d (%s, %d Byte) verschluesselt fuer %s "
                     "(%d Schluessel, erster %s...)",
                     count, content_type, len(payload), domain,
                     len(pubkeys), pubkeys[0][:12])
    return msg.as_bytes(policy=email.policy.default), count


def process(raw_message: bytes, envelope_from: str,
            envelope_rcpts: list[str]) -> tuple[list[tuple[list[str], bytes]],
                                                list[tuple[str, list[str]]]]:
    """
    Entscheidet je Zieldomain und gibt zurueck:
      zustellungen — Liste von (Empfaenger dieser Domain, Nachricht)
      blockiert    — Liste von (Domain, Empfaenger), fuer die Fail-Closed greift

    Frueher wurde eine Nachricht mit mehr als einem Empfaenger unveraendert
    durchgelassen, auch im scharfen Modus. Das hob den Schutz still auf,
    sobald jemand einen zweiten Empfaenger ins Feld schrieb. Jetzt faellt die
    Entscheidung je Domain, so wie der Schluessel je Domain veroeffentlicht
    wird (Konzeptpapier, Abschnitt 4.2).
    """
    msg = email.message_from_bytes(raw_message, policy=email.policy.default)
    if not list(msg.iter_attachments()):
        return [(envelope_rcpts, raw_message)], []
    if not envelope_rcpts:
        logging.warning("Kein Empfaenger im Envelope - nichts zuzustellen")
        return [], []

    zustellungen: list[tuple[list[str], bytes]] = []
    blockiert: list[tuple[str, list[str]]] = []

    for domain, rcpts in group_by_domain(envelope_rcpts).items():
        pubkeys = lookup_pubkey(domain)

        if not pubkeys:
            txt = f"Kein docguard-Schluessel fuer Domain {domain} ({', '.join(rcpts)})"
            if SHADOW_MODE:
                logging.info("[SHADOW] %s -> wuerde blockieren, sende unveraendert weiter", txt)
                zustellungen.append((rcpts, raw_message))
            else:
                logging.warning("[ENFORCE] %s -> FAIL-CLOSED, Zustellung blockiert", txt)
                blockiert.append((domain, rcpts))
            continue

        if SHADOW_MODE:
            logging.info("[SHADOW] wuerde Anhaenge fuer %s verschluesseln (%s, %d Schluessel)",
                         domain, ", ".join(rcpts), len(pubkeys))
            zustellungen.append((rcpts, raw_message))
            continue

        out, count = encrypt_for_domain(raw_message, pubkeys, domain)
        logging.info("[ENFORCE] %d Anhang/Anhaenge fuer %s verschluesselt, %d Empfaenger",
                     count, domain, len(rcpts))
        zustellungen.append((rcpts, out))

    return zustellungen, blockiert


def bounce(envelope_from: str, domain: str, rcpts: list[str]):
    """Sehr einfacher Bounce - in Produktion: richtige Bounce-Mail mit Diagnose."""
    logging.warning("Bounce an %s: kein docguard-Schluessel fuer %s (%s)",
                    envelope_from, domain, ", ".join(rcpts))
    body = (
        f"From: MAILER-DAEMON\r\nTo: {envelope_from}\r\n"
        f"Date: {formatdate(localtime=True)}\r\nMessage-ID: {make_msgid(domain='docguard.test')}\r\n"
        f"Subject: Zustellung blockiert (docguard fail-closed)\r\n\r\n"
        f"Die Nachricht enthielt einen Anhang, der laut Policy verschluesselt "
        f"werden muss, aber fuer die Zieldomain '{domain}' wurde kein "
        f"gueltiger docguard-Schluessel gefunden. Aus Sicherheitsgruenden "
        f"wurde NICHT unverschluesselt zugestellt (Fail-Closed).\r\n\r\n"
        f"Betroffene Empfaenger: {', '.join(rcpts)}\r\n"
        f"Empfaenger in anderen Domains wurden davon nicht beruehrt.\r\n"
    ).encode()
    reinject("<>", [envelope_from], body)


def main():
    envelope_from = sys.argv[1]
    envelope_rcpts = sys.argv[2:]
    raw = sys.stdin.buffer.read()

    zustellungen, blockiert = process(raw, envelope_from, envelope_rcpts)

    for domain, rcpts in blockiert:
        bounce(envelope_from, domain, rcpts)

    for rcpts, data in zustellungen:
        reinject(envelope_from, rcpts, data)


if __name__ == "__main__":
    main()
