# docguard-lab

Lab-Kit, das zwei echte Postfächer (A = docguard, B = keyleash) als Sender und
Empfänger verschlüsselter Anhänge nutzt. Schlüsselveröffentlichung per DNS-TXT
mit DNSSEC, Versand, Empfang, Rundlauf-Test.

## Ehrlicher Rahmen

- Das ist eine **client-seitige Simulation** des Konzepts, **kein MTA-Gateway**.
  Verschlüsselt wird im Sendeskript, entschlüsselt im Empfangsskript. Es zeigt:
  DNS-Schlüsselabruf, Fail-closed-Verhalten, Verschlüsselung/Entschlüsselung,
  Zustellung über echte Provider. Es zeigt **nicht** das Verhalten zweier
  Gateways im Transportpfad. Dafür: `docguard-sandbox` (Postfix) bzw. der Hetzner-Pfad.
- DNSSEC wird über das **AD-Flag** eines validierenden Resolvers (Standard 9.9.9.9)
  geprüft. Das vertraut dem Resolver und dem Pfad dorthin. Für ein Lab okay,
  für Produktion sollte der Gateway selbst validieren (lokaler Resolver, z. B. Unbound).
- Der **Selbsttest** (`dg_selftest.py`) läuft offline und ist bestanden (23 Prüfungen).
  Die Online-Teile (echtes DNS, SMTP, IMAP bei deinem Provider) konnte ich nicht testen.

## Voraussetzungen

- `age` und `age-keygen` (Ubuntu: `sudo apt install age`)
- Python 3.9+, `pip install -r requirements.txt`
- Zwei Postfächer mit SMTP und IMAP. Verwende **App-Passwörter**, keine Hauptpasswörter.
- DNS-Zugriff auf beide Domains, idealerweise mit aktiviertem DNSSEC

## Ablauf

1. **Selbsttest:** `python3 dg_selftest.py`
2. **Konfiguration:** `cp lab.env.example lab.env && chmod 600 lab.env`, dann ausfüllen.
   Kommentare mit `#` hinter Werten sind erlaubt; Passwörter dürfen daher kein `#` enthalten.
3. **Schlüssel erzeugen:** `./dg_keygen.sh a` und `./dg_keygen.sh b`
4. **DNS setzen:** Die ausgegebene TXT-Zeile als `_docguard.<domain>` bei der jeweiligen
   Domain eintragen (A: docguard-Domain, B: keyleash-Domain). Etwas warten (TTL).
5. **Prüfen:** `python3 dg_dnscheck.py` – zeigt Key, DNSSEC-Status, Übereinstimmung mit lokalem Schlüssel.
   - Ist DNSSEC noch nicht aktiv: in `lab.env` `DG_REQUIRE_DNSSEC=0` setzen (nur fürs Bootstrapping, laute Warnung).
6. **Einzeln testen:**
   - `python3 dg_send.py A B datei.pdf`
   - `python3 dg_receive.py B` (entschlüsselt nach `received/`)
7. **Rundlauf:** `python3 run_roundtrip.py` – A→B, B→A mit 64-KB-Zufallsdaten,
   SHA-256-Vergleich, plus Negativtest (Domain ohne Schlüssel muss fail-closed enden).

## Lokales DNSSEC-Lab (`dnslab/`) – ohne externen DNS-Anbieter

Wenn deine Domains (z. B. bei Hetzner) kein DNSSEC-Signing bieten, bringt das Lab seinen eigenen
DNSSEC-Stack mit: BIND signiert die Zonen (`docguard.lab`, `keyleash.lab`, plus `unsigned.lab` ohne Signatur),
Unbound validiert gegen die lokalen Trust-Anchors. Alles läuft auf localhost (Ports 5301/5302).

```
sudo apt install bind9 unbound bind9-dnsutils age
dnslab/up.sh                 # Zonen erzeugen, signieren, Server starten
python3 dnslab/dnslab_test.py  # 8 Prüfungen inkl. Manipulations-Szenario
python3 dnslab/e2e_local.py    # A->B und B->A komplett lokal (SMTP-Sink, keine echten Postfächer)
dnslab/down.sh
```

Für die **echten Postfächer** mit lokalem DNS in `lab.env` setzen:
`DG_DNS_RESOLVER=127.0.0.1:5302`, `A_KEY_DOMAIN=docguard.lab`, `B_KEY_DOMAIN=keyleash.lab`.
Die Schlüsselabfrage geht dann gegen die Lab-Zonen, die Mails laufen weiter über die echten Adressen.

Was das Lab zeigt: gültige Signatur -> Key akzeptiert; unsignierte Zone -> fail-closed; manipulierte Zone
(Signatur passt nicht mehr) -> Resolver liefert SERVFAIL -> fail-closed; nicht existierender Name -> fail-closed.

Grenzen: Der Trust-Anchor ist ein lokal erzeugter DS-Record, keine Kette bis zur Root. Das beweist die
Mechanik und das Fehlerverhalten, ersetzt aber nicht den Test mit einer echten, in der Root-Kette
verankerten Domain. Das Verzeichnis `dnslab/work/` enthält private Zonenschlüssel (Lab-Müll, nicht weitergeben).

## Stufe 2: Umschlüsseln auf den Nutzerschlüssel (Badge-Ersatz)

Simuliert den Schritt am Ziel-Gateway: Domänenschlüssel entschlüsseln (nur im Speicher), prüfen,
für die Nutzerschlüssel aus einem Verzeichnis neu verschlüsseln. Als „Badge“ dient ein **Software-Schlüssel**;
das ist kein Hardware-Nachweis (Smartcard/YubiKey/TPM via age-Plugins sind separat zu prüfen).

```
python3 dg_rewrap_test.py                       # 17 Prüfungen, offline
python3 dg_rewrap.py in.eml out.eml --domain-key keys/b.key --directory directory.json
```

`directory.json` (Verzeichnis-Ersatz): `{"anna@ziel.test": ["age1..."], "ben@ziel.test": "age1..."}`

| Situation | Ergebnis |
|---|---|
| Empfänger ohne Schlüssel im Verzeichnis (auch nur einer von mehreren) | Exit 3, nichts umgeschlüsselt |
| Scanner-Treffer (hier nur EICAR-Test, Platzhalter) | Exit 5, Quarantäne, nichts umgeschlüsselt |
| Mehrere Empfänger | Anhang für alle Badges lesbar |
| Nach dem Umschlüsseln | Domänenschlüssel öffnet den Anhang nicht mehr; Text bleibt lesbar |

Grenzen: Der Scanner ist ein Platzhalter für AV/DLP; das Verzeichnis ist eine JSON-Datei statt LDAP/AD;
Recovery, Rotation, Verteilerlisten und der Client zum Öffnen sind nicht abgebildet.
Siehe `docguard_stufe2_badge.pdf`.

## Verhalten

| Situation | Ergebnis |
|---|---|
| Kein gültiger `v=DG1`-Eintrag im DNS | Exit 3, **nichts gesendet** |
| Antwort ohne DNSSEC-Validierung | Exit 3 (außer `DG_REQUIRE_DNSSEC=0`) |
| Mehrere verschiedene Schlüssel | Exit 3 (v1: genau einer) |
| SMTP ohne TLS | nur für localhost erlaubt |
| IMAP | read-only, `BODY.PEEK[]`, Nachrichten bleiben ungelesen |

Exit-Codes: 2 Konfiguration, 3 fail-closed, 4 age-Fehler.

## Stolpersteine

- **Port 25/465 bei Hetzner** gesperrt; 587 (STARTTLS) nutzen. Sonst `SMTP_SECURITY=ssl` mit 465.
- Provider können Anhänge mit unbekanntem Typ in den **Spam-Ordner** legen; der Rundlauf prüft Junk/Spam mit.
- Manche Provider schreiben Content-Types um; der Empfänger erkennt Anhänge am Namen `*.age`.
- Der Betreff enthält ein Token, Metadaten (Absender, Betreff, Größe) bleiben unverschlüsselt.
- `lab.env`, `keys/` und `received/` nie einchecken oder weitergeben (`.gitignore` ist gesetzt).
- Private Schlüssel gehören nur auf die Maschine, die das jeweilige Postfach liest.

## Dateien

`dgcommon.py` Kernfunktionen · `dg_dnscheck.py` · `dg_send.py` · `dg_receive.py` ·
`run_roundtrip.py` · `dg_selftest.py` · `dg_rewrap.py` · `dg_rewrap_test.py` · 
