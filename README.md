# docguard

Automatische Verschlüsselung von E-Mail-Anhängen auf dem Transportweg zwischen
Mailservern, mit Schlüsseln aus DNSSEC-gesichertem DNS.

Ein Anhang passiert auf dem Weg zum Empfänger mehrere Stationen, die ihn heute im
Klartext sehen: Provider, Weiterleitungen, Cloud-Filter. docguard verschlüsselt ihn
zwischen dem sendenden und dem empfangenden Gateway, ohne dass ein Endnutzer etwas
tun muss. Die Empfängerdomain veröffentlicht einen öffentlichen Schlüssel im DNS,
das sendende Gateway holt ihn, prüft die DNSSEC-Signatur und verschlüsselt. Findet
es keinen gültigen Schlüssel, wird **nicht** im Klartext zugestellt, sondern
blockiert.

Was docguard **nicht** leistet, steht genauso deutlich im Konzeptpapier: Nach der
Entschlüsselung am Empfänger-Gateway greift der Schutz nicht mehr. Wo echte
Ende-zu-Ende-Verschlüsselung eingerichtet ist, hat sie Vorrang.

## Stand

Konzeptstadium mit lauffähiger Erprobung. Das Verfahren ist gegen echtes Postfix,
echtes BIND mit DNSSEC und einen mitlesenden Proxy nachgewiesen; es ist kein
Produkt, kein Internet-Draft und nicht für den Produktivbetrieb gedacht.

## Verzeichnisse

| Pfad | Inhalt |
|---|---|
| `docs/` | Konzeptpapier, Formatentscheidungen, Laborprotokoll, Glossar |
| `mail-transport/sandbox/` | Die Gateway-Filter, Postfix- und DNS-Konfiguration, Tests |
| `mail-transport/lab/` | Werkzeuge für den Weg ohne Container, dazu ein lokales DNSSEC-Labor |
| `mail-transport/lauf.sh` | Führt alle Prüfungen aus und schreibt ein Protokoll |

Der Passphrase-Kern (Argon2id, AES-256-GCM, Rust) und der Deniable-Container
gehören zum Gesamtkonzept, liegen aber noch nicht in diesem Repository.

## Ausprobieren

Ohne root, ohne Container, ohne DNS — braucht nur Python und
[age](https://age-encryption.org):

```bash
cd mail-transport
bash lauf.sh --ohne-root
```

Der vollständige Lauf startet zusätzlich zwei echte Postfix-Instanzen, ein
signierendes BIND und einen validierenden Unbound:

```bash
sudo apt install postfix bind9 bind9utils unbound age swaks python3-dnspython python3-aiosmtpd
cd mail-transport
bash lauf.sh
```

Das System-Postfix wird dabei nicht angefasst; der Test arbeitet unter `/tmp/dgtest`
mit eigenen Ports und eigenen Queues.

### Schlüssel

Im Repository liegt **kein** privater Schlüssel. Der Schlüssel der Empfängerdomain
wird beim ersten Lauf erzeugt und der passende öffentliche Schlüssel gleich in die
Zonendateien eingetragen:

```bash
sh mail-transport/sandbox/setup-keys.sh
```

## Die beiden Formate

Der DNS-Eintrag führt Version und Verfahren mit, in der Schreibweise von DKIM:

```
_docguard.example.com.  IN TXT  "v=DG1; k=age-x25519; p=age1…"
```

Ein Eintrag mit unbekannter Version oder unbekanntem Verfahren wird übersprungen,
nicht als Fehler behandelt — sonst könnte keine Domain je etwas Neues einführen.

Der verschlüsselte Anhang trägt Typ und Dateinamen **innen**, nicht in der
MIME-Hülle. Außen steht nur ein durchnummerierter Name, denn ein Dateiname wie
`kuendigung_mueller.pdf` verrät den Inhalt auch dann, wenn die Datei unlesbar ist.

Beides ist in `docs/formatentscheidungen.md` begründet und in Abschnitt 2.2 und 2.3
des Konzeptpapiers spezifiziert.

## Lizenz

Code: MIT (`LICENSE-MIT`). Konzept und Dokumentation: CC BY 4.0
(`LICENSE-CC-BY-4.0`).

## Kontakt

Christian Scheller · <christian@scheller.me> · <https://docguard.de>
