# docguard Sandbox — Stufe 0 (Dogfooding)

Diese Sandbox bildet den kompletten Ablauf aus dem Secure-Mail-Transport-
Konzeptpapier zwischen zwei Domains nach, die beide dir gehören:

```
Du (Testmail) --> sender.docguard.test --[docguard-Filter: verschlüsselt]-->
                   empfang.docguard.test --[docguard-Filter: entschlüsselt]--> Mailpit
```

**Kryptografie:** Envelope Encryption via `age` (asymmetrisch, ECIES-artig) —
bewusst kein Eigenbau, siehe Konzeptpapier Abschnitt 2.
**Fail-Closed:** Fehlt für die Zieldomain ein `_docguard`-TXT-Record mit
gültigem Public Key, wird die Zustellung blockiert statt unverschlüsselt
zugestellt (außer im Shadow-Mode, siehe unten).
**DNSSEC:** Die Zonen `sender.docguard.test` und `empfang.docguard.test` werden beim Start des
`dns`-Containers mit frischen Schlüsseln signiert (BIND); ein validierender Unbound beantwortet die
Abfragen der Filter, sein Trust-Anchor ist der lokal erzeugte DS-Record. Der Sender-Filter akzeptiert einen
Schlüssel nur, wenn die Antwort das AD-Flag trägt (`DOCGUARD_REQUIRE_DNSSEC=1`, Standard). `unsigned.docguard.test`
ist absichtlich unsigniert und dient dem Fail-Closed-Test. Das ist eine **lokale** Root-of-Trust: sie belegt
Mechanik und Fehlerverhalten, nicht eine Kette bis zur echten Root.

## Voraussetzungen

- Docker + Docker Compose (getestet mit Compose v2)
- Ports 2525 und 8025 frei auf deinem Host

## Zwei Wege zum Testen

**A) Ohne Docker, mit echtem Postfix (getestet):**
```bash
sudo apt install postfix bind9 bind9utils unbound age swaks python3-dnspython python3-aiosmtpd
sudo python3 tests/native_gateway_test.py
```
Startet zwei Postfix-Instanzen aus den ausgelieferten `main.cf`/`master.cf` im Verzeichnis `/tmp/dgtest`
(eigene Ports 2525/2526, eigene Queues), dazu das signierende DNS, einen Mitlese-Proxy zwischen den Gateways
und einen Mailpit-Ersatz. Geprüft werden 13 Punkte, u. a.: Anhang beim Empfänger byte-identisch, zwischen den
Gateways als `age`-Ciphertext sichtbar, unsignierte Zieldomain wird mit Bounce blockiert und nichts weitergeleitet.
Das System-Postfix wird nicht angefasst; bricht der Test ab, die Prozesse `master`, `named`, `unbound` prüfen.

**B) Mit Docker (`docker compose up`)** – siehe unten. Die Container-Konfiguration ist aus den gleichen Dateien
gebaut, wurde von mir aber nicht in Docker gestartet (dort lief kein Docker-Daemon).

## Start

```bash
cd docguard-sandbox
docker compose up --build
```

Kurz warten, bis alle vier Container stehen (`dns`, `postfix-sender`,
`postfix-empfang`, `mailpit`).

## Testlauf

In einem zweiten Terminal, während `docker compose up` läuft:

```bash
# Testmail mit Anhang direkt per SMTP an den Sender-Postfix schicken
swaks --to bob@empfang.docguard.test \
      --from alice@sender.docguard.test \
      --server localhost:2525 \
      --header "Subject: Testmail" \
      --body "Hallo Bob, siehe Anhang." \
      --attach @/etc/hostname
```

(`swaks` ist ein gängiges SMTP-Testtool: `apt install swaks` /
`brew install swaks`. Alternativ tut es auch ein Python-Skript mit
`smtplib`, falls du swaks nicht installieren willst.)

**Ergebnis ansehen:** http://localhost:8025 (Mailpit-Weboberfläche) —
dort sollte die Mail mit dem **entschlüsselten, lesbaren** Anhang
ankommen, obwohl sie zwischen den beiden Postfix-Instanzen verschlüsselt
transportiert wurde.

**Den Verschlüsselungs-Beweis führen:** Während die Mail unterwegs ist
(oder danach in den Logs), zeig dir den Zwischenzustand:

```bash
docker exec docguard-postfix-sender cat /var/log/docguard/filter.log
```

Dort siehst du die Log-Zeile `Anhang '...' verschluesselt fuer
empfang.docguard.test (Ziel-Pubkey age15lf6...)`. Der Anhang liegt in der
Postfix-Queue zwischen den beiden Containern nur noch als `age`-Ciphertext
vor.

## Shadow-Mode (empfohlener erster Schritt)

Per Default ist die Sandbox **scharf geschaltet** (`DOCGUARD_SHADOW_MODE=0`
in `docker-compose.yml`). Für den allerersten Testlauf würde ich empfehlen,
das auf `"1"` zu setzen — dann wird nur geloggt, was passiert wäre, ohne
tatsächlich zu verschlüsseln oder zu blockieren. Das ist die in unserem
Gespräch besprochene Vorstufe, bevor du dem System vertraust.

## Fail-Closed testen

Schick eine Mail an eine Domain ohne `_docguard`-Record, z.B.
`bob@irgendwas.test` (nicht in der Sandbox-DNS-Zone). Im scharfen Modus
solltest du einen Bounce an den Absender sehen (Mailpit zeigt auch
Bounce-Mails an); im Shadow-Mode nur einen entsprechenden Log-Eintrag.

## Änderungen gegenüber der ersten Version

Beim Durchtesten mit echtem Postfix aufgefallen und behoben:
- `import_environment`/`export_environment` fehlten: Postfix reicht Umgebungsvariablen nicht an Pipe-Filter durch,
  der Filter lief unbemerkt mit Standardwerten (Shadow-Mode, kein Verschlüsseln).
- Postfix-Logging (`maillog_file`) braucht den `postlogd`-Dienst in `master.cf`; ohne ihn blockiert `smtpd` beim Loggen.
- Log-Verzeichnis war für den Pipe-User `nobody` nicht beschreibbar.
- Bounce an den Absender der eigenen Domain wäre per MX an sich selbst gegangen (Mail-Loop); jetzt per
  `transport_maps` an Mailpit.
- `virtual_alias_domains` und `mydestination` listeten dieselbe Domain (Konflikt); Empfänger nutzt jetzt `relay_domains`.
- Der private Testschlüssel muss für `nobody` lesbar sein (`chmod 644`, nur Testschlüssel!).
- Neu: DNSSEC-Signierung und -Validierung, Filter prüft das AD-Flag, genau ein Schlüssel erlaubt.

## Struktur

```
docguard-sandbox/
├── docker-compose.yml
├── dns/                    BIND (signiert) + Unbound (validiert), start.sh
│   └── zones/                  sender/empfang (signiert), unsigned (unsigniert)
├── tests/native_gateway_test.py   Gateway-Test ohne Docker
├── postfix-sender/         Postfix + Filter-Pipe (verschlüsselt ausgehend)
├── postfix-empfang/        Postfix + Filter-Pipe (entschlüsselt eingehend)
├── filters/
│   ├── docguard_filter.py      Sender-seitiger Content-Filter
│   └── docguard_unwrap.py      Empfänger-seitiger Content-Filter
└── keys/
    └── empfang-private.key     Testschlüssel (NICHT für echten Einsatz!)
```

## Bekannte Grenzen dieser Sandbox (bewusste Vereinfachungen für Stufe 0)

- **Lokale Root-of-Trust** statt echter DNSSEC-Kette (siehe oben).
- **Ein Schlüssel pro Domain**, kein Multi-MX-Pooling (Konzeptpapier
  Abschnitt 3.2) — für Stufe 0 nicht nötig.
- **Kein HSM**, der private Schlüssel liegt als Klartextdatei im
  Container — für einen echten Piloten (Stufe 2) nachrüsten.
- **MIME-Typ des Original-Anhangs wird nicht mitverschlüsselt/-signiert**
  (`docguard_unwrap.py` setzt beim Entschlüsseln pauschal
  `application/octet-stream`) — für Produktivbetrieb sollte der originale
  Content-Type Teil der verschlüsselten Nutzlast sein, nicht geraten werden.
- **Multi-Recipient-Mails** (mehr als ein Empfänger) werden vom
  Sender-Filter aktuell übersprungen (unverändert durchgelassen, mit
  Log-Hinweis) statt pro Empfänger einzeln behandelt zu werden.

Das sind genau die Punkte, die eine Portierung von diesem Python-
Prototyp auf eine gehärtete Rust-Implementierung (analog zum
docguard-Kern) sinnvoll machen, sobald der Ablauf hier zuverlässig läuft.
