# Formatentscheidungen vor Phase 1

Stand: 25. November 2026 · Entwurf zur Entscheidung

## Warum diese drei Entscheidungen vor Phase 1 fallen müssen

Der Phasenplan sieht vor, erst die Sandbox zu reparieren und zu testen (Phase 1) und
danach das Record- und Payload-Format zu spezifizieren (Phase 2). Beide Filter lesen
aber genau diese Formate: `docguard_filter.py` wertet den TXT-Eintrag aus und baut den
verschlüsselten MIME-Teil, `docguard_unwrap.py` liest ihn wieder. Wird das Format
nachträglich festgelegt, werden Filter, Tests und Sandbox-Zonen ein zweites Mal
angefasst.

Die drei Festlegungen kosten eine Sitzung am Schreibtisch, kein Entwicklungsbudget.
Alles Übrige aus Phase 2 — Fail-Closed-Semantik, DSN-Format, Abgrenzungskapitel — kann
bleiben, wo es ist.

Unabhängig davon und vor allem anderen: die beiden Fail-open-Stellen aus der
Bestandsaufnahme (Nachrichten an mehrere Empfänger, stille Zustellung bei
fehlgeschlagener Entschlüsselung). Die hängen an keiner Formatfrage.

---

## E1 — Envelope-Format

**Entscheidung: age bleibt für v1.**

Das Konzeptpapier sagte bisher „AES-256-GCM, unverändert aus dem docguard-Kern", die
Sandbox benutzt age, also X25519 zum Schlüsselaustausch, HKDF zur Ableitung und
ChaCha20-Poly1305 zur Verschlüsselung. Das ist kein Implementierungsfehler, sondern eine
nie getroffene Entscheidung. Abschnitt 2.1 des Papiers hält jetzt beides getrennt fest.

Für age spricht, dass das Format geprüft, schlank und spezifiziert ist, dass es
Mehrfachempfänger nativ kann — was Pooling und Rotation aus Abschnitt 3.2 ohne eigene
Arbeit abdeckt — und dass es Implementierungen in Rust und Go gibt. Gegen age spricht
nur, dass Kern und Transport dann unterschiedliche Primitive verwenden.

Das ist ein ästhetischer Einwand, kein sicherheitstechnischer. Ein eigenes Format auf
Basis des Kerns hieße, Schlüsselaustausch, Header und Mehrfachempfänger selbst zu
spezifizieren und zu implementieren — die klassische Stelle, an der eigene Kryptografie
schiefgeht.

**Wann die Entscheidung neu zu prüfen ist:** wenn eine Zertifizierung oder eine
BSI-Vorgabe AES-GCM verlangt, oder wenn der Transport ohne externe Abhängigkeit
auskommen muss. Beides ist heute nicht der Fall.

**Folge für das Papier:** Der Begriff „ECIES-Prinzip" bleibt als Beschreibung des
Musters richtig, darf aber nicht mehr neben „AES-256-GCM" stehen, wenn vom Transport die
Rede ist.

---

## E2 — Record-Format

**Entscheidung: getaggtes Format mit Version und Algorithmus, wie bei DKIM und
MTA-STS.**

```
_docguard.example.com.  IN TXT  "v=DG1; k=age-x25519; p=age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
```

Der bisherige Entwurf (`agepubkey=age1…`) nennt weder Version noch Algorithmus. Damit
ist jeder spätere Wechsel ein Bruch: Ein Empfänger kann einen neuen Eintrag nicht
veröffentlichen, ohne dass alte Sender ihn missverstehen.

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `v` | ja, zuerst | Version des Eintragsformats. `DG1` für diese Fassung. |
| `k` | ja | Algorithmus-Kennung, hier `age-x25519`. |
| `p` | ja | Öffentlicher Schlüssel in der Textform des Algorithmus. |

**Regeln für die Auswertung:**

1. Ein Eintrag, dessen `v` der Sender nicht kennt, wird ignoriert — nicht als Fehler
   behandelt. Dasselbe gilt für ein unbekanntes `k`. So kann eine Domain einen neuen
   Algorithmus einführen, während alte Sender den alten Eintrag weiterbenutzen.
2. Mehrere TXT-Einträge unter demselben Namen bilden den Pool aus Abschnitt 3.2. Der
   Sender wrappt den Nachrichtenschlüssel an alle Einträge, die er versteht. Obergrenze:
   drei gleichzeitig gültige Schlüssel.
3. Bleibt nach dem Aussortieren kein verwertbarer Eintrag übrig, gilt dasselbe wie bei
   gar keinem Eintrag: Der Geltungsbereich aus Abschnitt 4.1 entscheidet, ob blockiert
   oder normal zugestellt wird.
4. EDNS0 wird vorausgesetzt. Jeder Eintrag muss in eine einzelne Zeichenkette von 255
   Byte passen; mit einem age-Schlüssel von 62 Zeichen ist das eingehalten.
5. Unbekannte weitere Felder werden überlesen, damit spätere Erweiterungen keine alten
   Sender brechen.

---

## E3 — Payload-Format

**Entscheidung: Ursprünglicher Content-Type und Dateiname gehören in den
verschlüsselten Teil, nicht in die MIME-Hülle.**

Die Sandbox verliert beim Entschlüsseln den MIME-Typ (alles wird `octet-stream`) und
trägt den Original-Dateinamen im Klartext in der Hülle. Beides ist falsch herum: Der
Dateiname ist oft der verräterischste Teil einer Nachricht (`kuendigung_mueller.pdf`),
und der Typ ist genau die Information, die nach dem Entschlüsseln fehlt.

**Äußerer Teil**, sichtbar für jede Zwischenstation:

```
Content-Type: application/docguard+age
Content-Disposition: attachment; filename="docguard-1.age"
```

Der äußere Name ist durchnummeriert und sagt nichts über den Inhalt.

**Innerer Teil**, erst nach dem Entschlüsseln lesbar: ein kurzer Kopf vor den
Originaldaten.

```
DGP1\n
{"ct":"application/pdf","fn":"Kündigung Müller.pdf","len":483201}\n
<Originalbytes>
```

Der Kopf ist eine Zeile JSON zwischen zwei Zeilenumbrüchen, damit er ohne
MIME-Bibliothek zu lesen ist. `len` erlaubt dem entschlüsselnden Gateway zu prüfen, dass
es vollständig entpackt hat.

**Nachrichtenkopf als Marker:**

```
X-Docguard: v=DG1
```

Damit erkennt das Empfänger-Gateway eine docguard-Nachricht, ohne jeden Teil auf
Verdacht zu entschlüsseln. Der Marker ist ein Hinweis, keine Zusicherung — er wird nicht
signiert und darf keine Entscheidung tragen, die Sicherheit betrifft.

---

## Was daraus für Phase 1 folgt

1. Der Filter liest `v`, `k` und `p` statt `agepubkey=` und sortiert aus, was er nicht
   versteht.
2. Der Filter gruppiert Empfänger nach Zieldomain und entscheidet je Gruppe — das ist
   zugleich die Behebung des Fail-open bei mehreren Empfängern und die Umsetzung von
   Abschnitt 4.2 des Konzeptpapiers.
3. Der Filter schreibt den DGP1-Kopf in den Ciphertext und setzt außen einen neutralen
   Namen.
4. `docguard_unwrap.py` stellt Content-Type und Dateiname aus dem DGP1-Kopf wieder her.
5. Schlägt das Entschlüsseln fehl, geht die Nachricht in Quarantäne und löst einen Alarm
   aus; der Ciphertext wird nicht stillschweigend zugestellt.
6. Die pytest-Fälle aus dem Phasenplan kommen um drei Fälle dazu: unbekannte Version,
   unbekannter Algorithmus, Empfänger in zwei Domains mit unterschiedlichem Status.

---

## Was offen bleibt

- Die Kennung `application/docguard+age` ist nicht registriert. Für die Sandbox
  unerheblich, für ein Internet-Draft zu klären.
- Ob der DGP1-Kopf zusätzlich den ursprünglichen `Content-ID` tragen soll, damit Inline-
  Bilder nach dem Entschlüsseln wieder im Text sitzen. Betrifft nur Nachrichten mit
  eingebetteten Teilen und kann in v2 nachkommen.
- Verhalten bei einem Anhang, der bereits verschlüsselt ankommt (OpenPGP, oder ein
  zweites docguard-Gateway davor): durchreichen, nicht doppelt verpacken. Regel ist
  klar, Erkennungslogik noch nicht geschrieben.
