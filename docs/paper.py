#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Erzeugt docguard_secure_mail_transport.pdf."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from style import (S, MARGIN, WIDTH, Rule, Flow, Decision, callout, deftable,
                   comptable, h1, h2, para, bullets)

OUT = "docguard_secure_mail_transport.pdf"
story = []
A = story.append


def AA(items):
    story.extend(items)


# ------------------------------------------------------------------ Kopf
A(Paragraph("DOCGUARD — ERGÄNZUNG ZUM HAUPTKONZEPT", S["eyebrow"]))
A(Paragraph("Secure Mail Transport: Automatisierte,<br/>transparente "
            "Anhang-Verschlüsselung", S["title"]))
A(Paragraph("Konzeptpapier zur Diskussion mit dem BSI — Architektur, Bedrohungsmodell "
            "und Abgrenzung zu bestehenden Standards", S["subtitle"]))
A(Spacer(1, 10))
A(Rule())

# ------------------------------------------------------------------ 1
A(h1("1. Zusammenfassung"))
A(para("Dieses Papier ergänzt das docguard-Hauptkonzept (Passphrase-basierte "
       "Dokumentenverschlüsselung, inkl. Deniable-Encryption-Variante) um einen "
       "Automatisierungsmechanismus für den Business-Anwendungsfall: die transparente, "
       "für Endbenutzer unsichtbare Verschlüsselung von E-Mail-Anhängen zwischen "
       "Mailservern. Ziel ist, den in docguard Business beschriebenen Schutz vor "
       "Postfach-Kompromittierung und automatisierter KI-Analyse (z.B. Copilot, Gemini) "
       "ohne manuelle Passphrasen-Verwaltung nutzbar zu machen."))

# ------------------------------------------------------------------ 2
A(h1("2. Architektur: Envelope Encryption"))
A(para("Die Empfänger-Domain veröffentlicht ausschließlich einen öffentlichen Schlüssel "
       "(z.B. X25519) über einen DNS-TXT-Eintrag — analog zu etablierten Mustern bei "
       "DKIM, DANE (RFC 7672) oder OpenPGP Web Key Directory. Der private Schlüssel "
       "verlässt die Empfänger-Domain nie. Das Sender-Gateway erzeugt pro Nachricht "
       "einen zufälligen symmetrischen Schlüssel, verschlüsselt den Anhang damit und "
       "verschlüsselt anschließend nur den kleinen symmetrischen Schlüssel mit dem "
       "öffentlichen Schlüssel des Empfängers (Envelope Encryption / ECIES-Prinzip, wie "
       "es z.B. <font face='DJ'>age -r &lt;empfänger-pubkey&gt;</font> bereits nativ "
       "umsetzt)."))
A(Spacer(1, 6))
A(Flow([
    ("User sendet E-Mail", "Anhang: vertrauliches Dokument", "grau"),
    ("Sender-Gateway erkennt Anhang", "Content-Filter nach SMTP DATA", "orange"),
    ("DNS TXT + DNSSEC-Prüfung", "Public Key kryptographisch verifiziert", "gruen"),
    ("Envelope Encryption", "Zufallsschlüssel, gewrappt an den Domain-Schlüssel", "lila"),
    ("SMTP-Zustellung", "an Empfänger-Domain", "grau"),
    ("Empfänger-Gateway entschlüsselt", "Privater Schlüssel, nie veröffentlicht", "lila"),
    ("Zustellung an Endbenutzer", "Anhang wie gewohnt lesbar", "grau"),
]))
A(Paragraph("Abbildung 1: Ende-zu-Ende-Ablauf von Absender bis Empfänger",
            ParagraphStyle("cap1", parent=S["caption"], alignment=1)))

A(h2("2.1 Kryptografische Festlegung"))
A(para("Der docguard-Kern und der hier beschriebene Transportweg verwenden "
       "unterschiedliche Verfahren. Das ist beabsichtigt, wurde in früheren Fassungen "
       "dieses Papiers aber nicht sauber getrennt und soll hier ausdrücklich "
       "festgehalten werden."))
A(Spacer(1, 2))
A(deftable([
 ("Kern (Passphrase)", "Argon2id zur Schlüsselableitung aus der Passphrase, "
  "AES-256-GCM zur Verschlüsselung des Dokuments. Dateiformat DGRD1. Dieses Verfahren "
  "gilt unverändert für den Passphrase-Weg aus Abschnitt 5."),
 ("Transport (Envelope)", "Festgelegt auf age: X25519 zum Schlüsselaustausch, HKDF zur "
  "Ableitung und ChaCha20-Poly1305 zur Verschlüsselung des Anhangs. Begründung siehe "
  "unten; Eintrags- und Nutzlastformat in 2.2 und 2.3."),
], keyw=150))
A(Spacer(1, 8))
A(callout("Entscheidung",
          "Der Transportweg bleibt bei age. Dafür sprechen ein geprüftes, schlankes "
          "Format, vorhandene Implementierungen in Rust und Go und native "
          "Mehrfachempfänger, die das Pooling aus Abschnitt 3.2 ohne eigene Arbeit "
          "abdecken. Dagegen spricht allein, dass Kern und Transport dann "
          "unterschiedliche Primitive verwenden — ein ästhetischer Einwand, kein "
          "sicherheitstechnischer. Ein eigenes Format hieße, Schlüsselaustausch, Header "
          "und Mehrfachempfänger selbst zu spezifizieren und zu implementieren. Neu zu "
          "prüfen wäre die Entscheidung, wenn eine Zertifizierung AES-GCM verlangt oder "
          "der Transport ohne externe Abhängigkeit auskommen muss."))

A(h2("2.2 Eintragsformat"))
A(para("Der DNS-Eintrag führt Version und Algorithmus mit, in der Schreibweise von "
       "DKIM und MTA-STS. Ohne diese beiden Felder wäre jeder spätere Wechsel des "
       "Verfahrens ein Bruch: Eine Domain könnte einen neuen Eintrag nicht "
       "veröffentlichen, ohne dass ältere Sender ihn missverstehen."))
A(Spacer(1, 2))
A(deftable([
 ("Form", "<font face='DJ'>_docguard.&lt;domain&gt; IN TXT \"v=DG1; k=age-x25519; "
  "p=age1…\"</font>"),
 ("v", "Version des Eintragsformats, als erstes Feld. Pflicht."),
 ("k", "Kennung des Verfahrens, hier age-x25519. Pflicht."),
 ("p", "Öffentlicher Schlüssel in der Textform des Verfahrens. Pflicht."),
], keyw=150))
A(Spacer(1, 8))
A(para("Für die Auswertung gilt: Ein Eintrag mit unbekannter Version oder unbekanntem "
       "Algorithmus wird <b>übersprungen, nicht als Fehler behandelt</b> — nur so kann "
       "eine Domain ein neues Verfahren einführen, während ältere Sender den bisherigen "
       "Eintrag weiter verwenden. Unbekannte weitere Felder werden überlesen. Mehrere "
       "Einträge bilden den Pool aus Abschnitt 3.2; über drei gleichzeitig gültigen "
       "Schlüsseln wird der ganze Satz verworfen und es bleibt beim Fail-Closed, denn "
       "an eine willkürliche Teilmenge zu verschlüsseln hieße, eine unlesbare Nachricht "
       "zuzustellen, falls das Empfänger-Gateway gerade den ausgelassenen Schlüssel "
       "hält. Bleibt nach dem Aussortieren kein verwertbarer Eintrag, gilt dasselbe wie "
       "bei gar keinem Eintrag: Der Geltungsbereich aus Abschnitt 4.1 entscheidet."))

A(h2("2.3 Nutzlastformat"))
A(para("Der ursprüngliche Content-Type und der Dateiname gehören in den verschlüsselten "
       "Teil, nicht in die MIME-Hülle. Ein Dateiname wie "
       "<font face='DJ'>kuendigung_mueller.pdf</font> verrät den Inhalt auch dann, wenn "
       "die Datei selbst unlesbar ist; der Content-Type wiederum ist genau die "
       "Information, die dem Empfänger-Gateway nach dem Entschlüsseln fehlt, wenn sie "
       "nicht mitgeführt wird."))
A(Spacer(1, 2))
A(deftable([
 ("Außen, für jede Zwischenstation sichtbar",
  "<font face='DJ'>Content-Type: application/docguard+age</font><br/>"
  "<font face='DJ'>Content-Disposition: attachment; filename=\"docguard-1.age\"</font>"
  "<br/>Der äußere Name ist durchnummeriert und sagt nichts über den Inhalt."),
 ("Innen, erst nach dem Entschlüsseln lesbar",
  "<font face='DJ'>DGP1</font> als Kennzeile, darunter eine Zeile JSON mit "
  "<font face='DJ'>ct</font> (Content-Type), <font face='DJ'>fn</font> (Dateiname) und "
  "<font face='DJ'>len</font> (Länge), danach die Originalbytes. Der Kopf ist ohne "
  "MIME-Bibliothek zu lesen; <font face='DJ'>len</font> belegt, dass vollständig "
  "entpackt wurde."),
 ("Markierung der Nachricht",
  "<font face='DJ'>X-Docguard: v=DG1</font> als Hinweis für das Empfänger-Gateway, "
  "damit es nicht jeden Teil auf Verdacht zu entschlüsseln versucht. Der Header ist "
  "nicht signiert und darf keine Entscheidung tragen, die Sicherheit betrifft."),
], keyw=150))
A(Spacer(1, 8))
A(callout("Metadaten vollständig entfernen",
          "Das sendende Gateway muss jeden Header des Anhangs beseitigen, der den "
          "ursprünglichen Namen trägt, nicht nur Content-Type und "
          "Content-Disposition. In der Erprobung setzte ein verbreitetes Testwerkzeug "
          "den Dateinamen zusätzlich in Content-Description; dieser Header blieb "
          "zunächst stehen, sodass der Name zwischen den Gateways weiterhin lesbar war, "
          "obwohl der Inhalt verschlüsselt war. Eine Spezifikation sollte die "
          "erlaubten Header des umgehüllten Teils abschließend aufzählen, statt "
          "einzelne zu verbieten."))

# ------------------------------------------------------------------ 3
A(h1("3. Multi-MX-Umgebungen: Minimallösung und Erweiterung"))
A(para("Die Bündelung der Schlüsselverwaltung auf Domain-Ebene statt pro MX-Hostname "
       "(analog zu DKIM-Selectors und MTA-STS-Policies) ist der richtige Ansatz — der "
       "Sender muss dann nicht wissen, welcher konkrete MX-Host die Nachricht am Ende "
       "annimmt, bevor er verschlüsselt. Offen bleibt dabei, wie viele unabhängige "
       "Schlüssel ein solcher Domain-Block enthalten darf und wie der Sender bei "
       "mehreren MX-Einträgen vorgeht."))

A(h2("3.1 Minimallösung (v1)"))
A(para("Für eine erste, implementierbare Version wird empfohlen, ausschließlich den "
       "MX-Record mit der niedrigsten Preference-Zahl (höchste Priorität) als "
       "kanonischen Schlüsselträger zu definieren. Der Sender sortiert alle MX-Records "
       "der Zieldomain aufsteigend nach Preference und fragt den öffentlichen "
       "docguard-Schlüssel ausschließlich für den resultierenden primären MX ab, "
       "veröffentlicht weiterhin als domain-weiter DNS-TXT-Eintrag (siehe Abschnitt 2), "
       "nicht als separater Eintrag pro Hostname. Existiert dort kein gültiger, "
       "DNSSEC-verifizierter Schlüssel, greift unverändert das Fail-Closed-Prinzip "
       "(Abschnitt 4) — es wird nicht auf einen sekundären MX ausgewichen, um keine "
       "Unklarheit über den tatsächlich adressierten Schlüssel entstehen zu lassen. "
       "Diese Minimallösung deckt den in der Praxis häufigsten Fall ab (mehrere "
       "MX-Einträge für Redundanz, aber ein zentral verwaltetes Mailsystem dahinter) "
       "und verschiebt die Komplexität unabhängiger Schlüssel je Gateway auf eine "
       "spätere Erweiterung."))

A(h2("3.2 Erweiterung: Pooling mehrerer Schlüssel"))
A(para("Für Umgebungen mit mehreren unabhängigen Gateways sind zwei Fälle zu "
       "unterscheiden. Bei zentral verwaltetem Schlüsselmaterial (z.B. "
       "synchronisierter Key-Store oder HSM-Cluster) reicht weiterhin ein öffentlicher "
       "Schlüssel im Pool, da jeder Host denselben privaten Schlüssel nutzt. Bei "
       "unabhängigen Gateways mit eigenen Schlüsselpaaren müsste der Sender den "
       "symmetrischen Nachrichtenschlüssel für jeden gepoolten öffentlichen Schlüssel "
       "separat wrappen (Multi-Recipient Envelope Encryption) — ein etabliertes Muster, "
       "wie es z.B. age mit mehreren Empfänger-Flags bereits nativ umsetzt."))
A(Spacer(1, 4))
A(callout("Sicherheits-Resilienz-Trade-off",
          "Pooling mehrerer unabhängiger Schlüssel erhöht die Angriffsfläche linear mit "
          "der Anzahl der Schlüssel im Pool: Die Kompromittierung irgendeines der N "
          "privaten Schlüssel genügt, um jede Nachricht an die Domain zu entschlüsseln. "
          "Für produktive Umgebungen wird daher zentral verwaltetes Schlüsselmaterial "
          "(ein Schlüssel, mehrere Hosts) gegenüber unabhängigen Schlüsselpaaren je "
          "Gateway empfohlen."))
A(Spacer(1, 8))
A(para("Derselbe Pooling-Mechanismus lässt sich für die Schlüsselrotation "
       "wiederverwenden: Während einer Übergangsfrist stehen alter und neuer Schlüssel "
       "gleichzeitig im Pool, Sender verschlüsseln an beide, der Empfänger entschlüsselt "
       "mit dem noch vorhandenen. Zu beachten ist die begrenzte Größe von "
       "DNS-TXT-Antworten (klassisch 512 Byte ohne EDNS0, je Zeichenkette max. 255 "
       "Byte); mit DNSSEC-Signaturen und mehreren gepoolten Schlüsseln wächst die "
       "Antwortgröße schnell — DANE hat mit vergleichbarer UDP-Truncation bereits "
       "dokumentierte operative Schwierigkeiten. Für eine Spezifikation: EDNS0 "
       "voraussetzen und die Poolgröße auf maximal 2–3 gleichzeitig gültige Schlüssel "
       "begrenzen."))

# ------------------------------------------------------------------ 4
A(h1("4. DNSSEC-Absicherung und Fail-Closed-Prinzip"))
A(para("Zwei Ergänzungen adressieren die zentralen Restrisiken der DNS-basierten "
       "Schlüsselverteilung:"))
AA(bullets([
    "<b>DNSSEC-Validierung:</b> Der abgerufene öffentliche Schlüssel wird ausschließlich "
    "verwendet, wenn seine DNSSEC-Signaturkette bis zur Root-Zone gültig ist. Ohne "
    "DNSSEC wäre der Schlüssel per DNS-Cache-Poisoning gegen einen vom Angreifer "
    "kontrollierten Schlüssel austauschbar (Key-Substitution-Angriff) — strukturell "
    "dieselbe Schwäche, die DANE ohne DNSSEC hätte.",
    "<b>Fail-Closed:</b> Existiert kein DNS-TXT-Eintrag oder schlägt die "
    "DNSSEC-Validierung fehl, wird die Zustellung blockiert, nicht auf Klartext "
    "zurückgefallen. Der Absender erhält einen Bounce, das Security-Team einen Alarm. "
    "Dies verhindert einen STARTTLS-Stripping-artigen Downgrade-Angriff, bei dem ein "
    "aktiver Angreifer die DNS-Auflösung stört, um eine unverschlüsselte Zustellung zu "
    "erzwingen.",
]))
A(Spacer(1, 8))
A(Decision("DNS TXT + DNSSEC gültig?",
           ("Fail-Closed", "Blockiert, Bounce + SOC-Alarm", "orange"),
           ("Envelope Encryption", "Zustellung geschützt", "gruen")))
A(Paragraph("Abbildung 2: Entscheidungslogik bei fehlender oder ungültiger "
            "Schlüsselvalidierung",
            ParagraphStyle("cap2", parent=S["caption"], alignment=1)))

A(h2("4.1 Geltungsbereich der Richtlinie"))
A(para("Fail-Closed beantwortet, was bei einer fehlgeschlagenen Prüfung geschieht, "
       "nicht, für welchen Mailverkehr die Prüfung überhaupt gilt. Ohne diese zweite "
       "Festlegung läge nahe, die Richtlinie auf den gesamten ausgehenden Verkehr "
       "anzuwenden. Für eine Organisation mit Publikumsverkehr wäre das untragbar, weil "
       "jede Nachricht an eine Domain ohne Schlüssel unzustellbar würde. Der "
       "Geltungsbereich wird deshalb ausdrücklich in drei Stufen festgelegt:"))
A(Spacer(1, 4))
A(deftable([
 ("Konfiguriert", "Die Gegenstelle ist auf dem Sender-Gateway eingetragen — als Domain "
  "mit eigenem Gateway oder als Empfänger des Passphrase-Wegs aus Abschnitt 5. Hier "
  "gilt Fail-Closed unverändert: Eine fehlende oder ungültige Signatur führt zur "
  "Blockade, nicht zur Klartextzustellung."),
 ("Entdeckt und gemerkt", "Beim ersten erfolgreichen, DNSSEC-validierten Abruf wird die "
  "Domain für eine festgelegte Gültigkeitsdauer gemerkt (Pinning, wie bei MTA-STS). Ab "
  "dem zweiten Kontakt gilt Fail-Closed. Angreifbar bleibt allein der Erstkontakt."),
 ("Außerhalb der Richtlinie", "Besteht weder ein Eintrag noch ein gültiger Pin, fällt "
  "der Verkehr nicht unter die Richtlinie und wird zugestellt wie bisher — nicht "
  "schlechter geschützt als ohne docguard, aber auch nicht besser."),
], keyw=150))
A(Spacer(1, 8))
A(callout("Entwurfsentscheidung",
          "Der Geltungsbereich wird lokal bestimmt und nicht aus dem Vorhandensein "
          "eines DNS-Eintrags abgeleitet. Entschiede das Gateway allein anhand eines "
          "gefundenen Schlüssels, ob es schützt, könnte ein Angreifer durch Unterdrücken "
          "der DNS-Antwort den Schutz abschalten — derselbe Downgrade-Angriff, den "
          "Fail-Closed verhindern soll, eine Ebene höher. Das Pinning der zweiten Stufe "
          "begrenzt dieses Fenster auf den Erstkontakt; dessen Absicherung ist in "
          "Abschnitt 8 als offener Punkt vermerkt."))
A(Spacer(1, 6))
A(para("Für eine Behörde heißt das konkret: Korrespondenz mit eingerichteten Stellen "
       "und Empfängern ist geschützt, allgemeiner Bürgerverkehr bleibt unverändert "
       "zustellbar. Die Interoperabilität der Organisation nach außen hängt damit nicht "
       "am Verbreitungsgrad des Verfahrens."))

A(h2("4.2 Nachrichten an mehrere Empfänger"))
A(para("Eine Nachricht kann Empfänger in mehreren Domains haben, die unterschiedlich "
       "eingestuft sind: eine mit gültigem Schlüssel, eine ohne. Dieser Fall ist "
       "festzulegen, weil die naheliegende Implementierung — eine Nachricht, eine "
       "Entscheidung — den Schutz still aufhebt, sobald ein einziger Empfänger "
       "außerhalb der Richtlinie liegt. Empfohlen wird, die Nachricht vor der "
       "Entscheidung nach Zieldomain aufzuteilen und je Teilzustellung getrennt zu "
       "bewerten. Das Wrappen des Nachrichtenschlüssels an alle beteiligten "
       "Domain-Schlüssel ist technisch einfacher, hat aber die Folge, dass jede "
       "beteiligte Domain jeden Anhang entschlüsseln kann; es kommt daher nur in "
       "Betracht, wenn alle Empfänger ohnehin denselben Vertraulichkeitskreis bilden."))

# ------------------------------------------------------------------ 5
A(h1("5. Empfänger ohne eigenes Gateway"))
A(para("Das Fail-Closed-Prinzip aus Abschnitt 4 setzt voraus, dass die "
       "Empfänger-Domain einen Schlüssel veröffentlicht und ein Gateway betreibt. Für "
       "einen erheblichen Teil der Empfänger trifft das nicht zu und wird es absehbar "
       "nicht tun: Privatpersonen mit Webmail-Konto, Einzelkanzleien, Kleinstbetriebe. "
       "Ohne eine Antwort für diese Gruppe ist die Architektur auf Kommunikation "
       "zwischen Organisationen beschränkt."))
A(para("Für diese Fälle greift der docguard-Kern in seiner ursprünglichen Form: "
       "Passphrase-basierte Verschlüsselung des Anhangs (Argon2id, AES-256-GCM), "
       "entschlüsselbar mit einem kleinen Werkzeug ohne eigene Infrastruktur."))

A(h2("5.1 Kein automatischer Rückfall"))
A(para("Der Passphrase-Weg wird je Empfänger vorab konfiguriert und ist an einen "
       "Eintrag in der Empfängerliste des Sender-Gateways gebunden. Er wird nicht "
       "ausgelöst, wenn die DNSSEC-Prüfung fehlschlägt."))
A(Spacer(1, 4))
A(callout("Entwurfsentscheidung",
          "Ein automatischer Rückfall vom Envelope- auf den Passphrase-Weg wäre ein "
          "Downgrade-Pfad: Ein aktiver Angreifer, der die DNS-Auflösung stört, könnte "
          "damit den schwächeren Weg erzwingen — strukturell derselbe Angriff, den "
          "Fail-Closed in Abschnitt 4 ausschließt. Für einen Empfänger, der weder in "
          "der Passphrase-Liste steht noch einen gültigen DNS-Schlüssel hat, bleibt es "
          "unverändert beim Fail-Closed."))

A(h2("5.2 Übergabe der Passphrase"))
A(para("Die Passphrase erreicht den Empfänger außerhalb des Mailwegs. Welcher Weg dafür "
       "gewählt wird, legt dieses Konzept bewusst nicht fest, weil der angemessene Weg "
       "vom Schutzbedarf und von der Beziehung zwischen den Beteiligten abhängt, nicht "
       "von der Technik. In Frage kommen unter anderem die persönliche Übergabe bei "
       "Beginn der Geschäftsbeziehung, Brief oder Einschreiben, das Telefon oder ein "
       "bereits bestehender, beidseitig bestätigter Kanal."))
A(para("Es gilt dabei der Grundsatz aus dem Hauptkonzept: Ein Kanal, der ein "
       "Vertraulichkeitsgeheimnis trägt, darf weder öffentlich abfragbar sein noch "
       "einen Dritten einschließen, der das Geheimnis im Klartext sieht. Persönliche "
       "Übergabe und Postweg erfüllen das; ein Dienstleister im Weg, etwa ein "
       "SMS-Gateway, erfüllt es nicht. Maßgeblich ist nicht, welcher Weg gewählt wird, "
       "sondern dass die Wahl bewusst getroffen und dokumentiert wird: Die Sicherheit "
       "dieses Wegs begrenzt die Sicherheit des gesamten Verfahrens für diesen "
       "Empfänger nach oben."))

A(h2("5.3 Eine Passphrase je Beziehung, ein Schlüssel je Nachricht"))
A(para("Die Passphrase wird einmal zu Beginn übergeben und bleibt gültig. Je Nachricht "
       "leitet das Sender-Gateway daraus mit einem zufälligen, im Container "
       "mitgeführten Salt einen eigenen Nachrichtenschlüssel ab. Eine aufgedeckte "
       "Nachricht öffnet dadurch nicht die übrigen."))
A(para("Die Passphrase wird vom Gateway erzeugt, nicht vom Nutzer gewählt. Vorschlag "
       "für die Spezifikation: sechs Wörter aus einer geprüften Wortliste, Ableitung "
       "mit Argon2id nach OWASP-Parametern. Nutzergewählte Passphrasen sind für dieses "
       "Verfahren ungeeignet, weil das Chiffrat beim Empfänger liegt und damit ohne "
       "Begrenzung angegriffen werden kann."))

A(h2("5.4 Einordnung"))
A(comptable(["Envelope-Weg (Abschnitt 2)", "Passphrase-Weg"], [
    ("Voraussetzung beim Empfänger", "DNSSEC-Schlüssel und Gateway",
     "nur ein Entschlüsselungswerkzeug"),
    ("Geheimnis auf einem Übertragungsweg", "nein", "ja, einmalig"),
    ("Sichtbar für den Endbenutzer", "nein", "ja, bei der Ersteinrichtung"),
    ("Obergrenze der Sicherheit", "kryptografisch", "durch den Übergabeweg bestimmt"),
], keyw=150))
A(Spacer(1, 8))
A(para("Wo der Envelope-Weg möglich ist, hat er Vorrang. Der Passphrase-Weg deckt die "
       "Fälle ab, in denen er es nicht ist, und ersetzt ihn nicht."))

# ------------------------------------------------------------------ 6
A(h1("6. Abgrenzung zu bestehenden Standards"))
A(para("Die Architektur überschneidet sich konzeptionell mit etablierten "
       "BSI-Empfehlungen, adressiert aber eine andere Schutzebene:"))
A(Spacer(1, 4))
A(deftable([
 ("BSI TR-03108", "Empfiehlt DANE (RFC 7672, TLSA-Records mit DNSSEC) bzw. MTA-STS für "
  "die Absicherung des Transportwegs (TLS-Verbindung zwischen Mailservern). Schützt "
  "nicht den Anhang selbst nach Zustellung ins Postfach."),
 ("DANE / DNSSEC", "Gleiches Grundprinzip (DNSSEC-abgesicherte "
  "Schlüssel-/Zertifikatsverteilung), hier wiederverwendet — aber für einen "
  "öffentlichen Envelope-Encryption-Schlüssel statt für ein TLS-Zertifikat."),
 ("docguard Secure Mail", "Ergänzt DANE/MTA-STS um eine Verschlüsselung des Anhangs "
  "selbst zwischen sendendem und empfangendem Gateway — wirksam gegen jede "
  "Zwischenstation auf dem Weg, auch gegen automatisierte Auswertung. Nach der "
  "Entschlüsselung am Empfänger-Gateway greift der Schutz nicht mehr (siehe "
  "Abschnitt 7)."),
], keyw=150))
A(Spacer(1, 8))
A(para("Diese Lösung ist als Ergänzung, nicht als Ersatz von DANE/MTA-STS zu verstehen "
       "— beide Schutzebenen sollten parallel betrieben werden."))

A(h2("6.1 OpenPGP, S/MIME und Web Key Directory"))
A(para("Die nächstverwandte Technik ist nicht DANE, sondern die klassische "
       "Ende-zu-Ende-Verschlüsselung per OpenPGP oder S/MIME — und, für die "
       "Schlüsselverteilung, das Web Key Directory (WKD). Letzteres wurde im Auftrag "
       "des BSI im Projekt EasyGPG entwickelt. Die Abgrenzung gehört deshalb "
       "ausdrücklich in dieses Papier."))
A(para("<b>Was WKD tut.</b> Die Domain des Empfängers veröffentlicht dessen "
       "öffentlichen Schlüssel an einer festgelegten Adresse, das sendende Programm "
       "holt ihn automatisch, der Nutzer bemerkt davon nichts. Das Grundmuster ist "
       "dasselbe wie hier: Die Empfängerseite veröffentlicht einen Schlüssel, die "
       "Absenderseite holt ihn ohne Zutun eines Menschen. Die Unterschiede liegen im "
       "Trägerkanal (HTTPS an einer wohlbekannten Adresse statt DNSSEC-gesichertem DNS) "
       "und im Geltungsbereich des Schlüssels (je Adresse statt je Domain)."))
A(para("<b>Was OpenPGP und S/MIME besser können.</b> Sie verschlüsseln die gesamte "
       "Nachricht, nicht nur den Anhang; der private Schlüssel liegt beim Nutzer, nicht "
       "auf einem Gateway; und der Schutz reicht bis ins Postfach und darüber hinaus. "
       "In allen drei Punkten ist echte Ende-zu-Ende-Verschlüsselung stärker als das "
       "hier beschriebene Verfahren. Dieses Papier will das nicht relativieren."))
A(para("<b>Warum es dennoch einen Platz gibt.</b> Das BSI stellt auf seiner "
       "Verbraucherseite zur E-Mail-Verschlüsselung selbst fest, dass "
       "Ende-zu-Ende-Verschlüsselung bisher nur sehr selten eingesetzt wird, und nennt "
       "als Grund, dass Nutzer sich selbst um Programme und Erweiterungen kümmern "
       "müssen — und zwar auf beiden Seiten. Genau dort setzt docguard an: Es verlangt "
       "von keinem Endnutzer eine Handlung, weil der Betreiber des Gateways die Arbeit "
       "übernimmt. Der Preis dafür steht in der Tabelle."))
A(Spacer(1, 4))
A(comptable(["OpenPGP / S/MIME", "docguard Secure Mail"], [
    ("Was wird geschützt", "die ganze Nachricht", "nur der Anhang"),
    ("Wer hält den privaten Schlüssel", "der Nutzer", "das Empfänger-Gateway"),
    ("Schutz reicht bis", "ins Postfach und darüber hinaus", "zum Empfänger-Gateway"),
    ("Aufwand beim Endnutzer", "Einrichtung auf beiden Seiten", "keiner"),
    ("Aufwand beim Betreiber", "keiner", "Gateway und Schlüsselverwaltung"),
], keyw=150))
A(Spacer(1, 8))
A(para("<b>Beide Verfahren schließen sich nicht aus.</b> Ein mit OpenPGP "
       "verschlüsselter Anhang passiert ein docguard-Gateway unverändert; die Verfahren "
       "greifen auf verschiedenen Schichten. Wo Ende-zu-Ende-Verschlüsselung zwischen "
       "den Beteiligten eingerichtet ist, hat sie Vorrang. docguard ist die Antwort für "
       "den Normalfall, in dem sie es nicht ist."))
A(para("<b>Für den Passphrase-Weg aus Abschnitt 5 gilt dieselbe Frage.</b> Ein "
       "Empfänger, der bereit ist, ein Entschlüsselungswerkzeug zu installieren, könnte "
       "stattdessen auch ein Mailprogramm mit OpenPGP einrichten — und bräuchte dann "
       "kein Geheimnis auf einem Übergabeweg. Der Unterschied liegt im Aufwand bis zur "
       "ersten geschützten Nachricht: Beim Passphrase-Weg entfallen Schlüsselerzeugung, "
       "Veröffentlichung und Fingerabdruckprüfung, und der Absender bestimmt den "
       "Zeitpunkt, statt auf die Einrichtung beim Empfänger zu warten. Wo der Empfänger "
       "ohnehin bereit und in der Lage ist, OpenPGP einzurichten, ist dieser Weg "
       "vorzuziehen."))

A(h2("6.2 SMIMEA (RFC 8162) und OPENPGPKEY (RFC 7929)"))
A(para("Zwei bestehende RFCs lösen dasselbe Teilproblem über denselben Trägerkanal: die "
       "Veröffentlichung eines öffentlichen Schlüssels im DNSSEC-gesicherten DNS. "
       "OPENPGPKEY (RFC 7929, Experimental) veröffentlicht einen OpenPGP-Schlüssel, "
       "SMIMEA (RFC 8162, Experimental) ein X.509-Zertifikat für S/MIME, beide unter "
       "einem aus dem lokalen Teil der Adresse abgeleiteten Namen. Für ein künftiges "
       "Internet-Draft ist die Nähe zu diesen beiden Dokumenten die erste Frage, die "
       "gestellt werden wird; sie gehört deshalb hierher."))
A(Spacer(1, 4))
A(comptable(["SMIMEA / OPENPGPKEY", "docguard Secure Mail"], [
    ("Schlüsselgranularität", "je Nutzer, unter einem aus der Adresse abgeleiteten Namen",
     "je Domain, unter _docguard.&lt;domain&gt;"),
    ("Wer hält den privaten Schlüssel", "der Endnutzer, im Client",
     "das Gateway der Domain"),
    ("Endpunkte der Verschlüsselung", "Client zu Client, echtes Ende-zu-Ende",
     "Gateway zu Gateway, Domain zu Domain"),
    ("Was wird verschlüsselt", "die gesamte Nachricht als S/MIME- bzw. "
     "PGP/MIME-Struktur", "nur der Anhang; Body, Betreff und Dateiname bleiben Klartext"),
    ("Nutzerinteraktion", "Client-Unterstützung nötig, Nutzer verwalten Schlüssel",
     "keine, vollständig transparent"),
    ("Policy-Semantik", "reine Schlüsselveröffentlichung, keine Pflicht zu verschlüsseln",
     "der Eintrag ist eine Zusage, Fail-Closed wird erzwungen"),
    ("Eintragstyp", "eigene Resource-Record-Typen (61 bzw. 53)",
     "generischer TXT-Eintrag"),
    ("Stand", "RFC, Experimental", "Konzept, beim BSI eingereicht, kein Internet-Draft"),
], keyw=150))
A(Spacer(1, 8))
A(para("Der Unterschied, auf den es ankommt, ist nicht der Eintragstyp, sondern die "
       "Semantik. SMIMEA und OPENPGPKEY sind reine Schlüsselveröffentlichung: Ein "
       "Eintrag sagt „hier ist ein Schlüssel“ und verpflichtet niemanden, ihn zu "
       "benutzen. Ein docguard-Eintrag sagt „Anhänge an diese Domain sind zu "
       "verschlüsseln“ und wird durch Fail-Closed durchgesetzt — näher an der Logik von "
       "MTA-STS und DANE, aber angewandt auf die Nutzlast statt auf die Verbindung. Den "
       "Preis dafür nennt dieselbe Tabelle: Die Ende-zu-Ende-Eigenschaft auf "
       "Nutzerebene wird aufgegeben, derselbe Tausch wie in Abschnitt 6.1."))
A(para("Daraus folgt auch, dass die Verfahren nebeneinander bestehen können. Eine "
       "Domain, die OPENPGPKEY-Einträge für ihre Nutzer veröffentlicht, kann zusätzlich "
       "einen docguard-Eintrag führen; sendende Systeme, die Ende-zu-Ende "
       "unterstützen, nutzen den stärkeren Weg, alle übrigen den transparenten."))

# ------------------------------------------------------------------ 7
A(h1("7. Bedrohungsmodell (Auszug)"))
A(deftable([
 ("Passive Interception", "Wirkungslos gegen den Anhang: Ciphertext bleibt ohne privaten "
  "Schlüssel unlesbar, unabhängig davon, ob der Angreifer Mensch oder automatisiertes "
  "System (KI-Mailbox-Agent) ist."),
 ("DNS-Cache-Poisoning", "Durch verpflichtende DNSSEC-Validierung des öffentlichen "
  "Schlüssels adressiert."),
 ("Downgrade-Angriff", "Durch Fail-Closed-Prinzip adressiert — kein stiller Rückfall auf "
  "Klartext."),
 ("Erzwungener Downgrade auf den Passphrase-Weg", "Durch die Festlegung in Abschnitt 5.1 "
  "adressiert: Der Passphrase-Weg ist vorab konfiguriert und wird nicht durch einen "
  "fehlgeschlagenen DNS-Abruf ausgelöst."),
 ("Stiller Verlust des Schutzes bei mehreren Empfängern", "Durch die Festlegung in "
  "Abschnitt 4.2 adressiert: Die Entscheidung fällt je Zieldomain, nicht je Nachricht."),
 ("Kompromittierter Übergabeweg der Passphrase", "Nicht durch die Architektur "
  "adressierbar. Wer den gewählten Übergabeweg kontrolliert, kann alle Anhänge dieser "
  "Beziehung entschlüsseln. Die Wahl des Wegs ist damit eine Sicherheitsentscheidung, "
  "keine Komfortentscheidung."),
 ("Kompromittiertes Sender-/Empfänger-Gateway", "Nicht durch diese Architektur "
  "adressierbar — der private Schlüssel liegt auf dem Empfänger-Gateway; dessen "
  "Kompromittierung ist ein eigenständiges Bedrohungsszenario (Schlüsselverwahrung, "
  "HSM-Einsatz empfohlen)."),
 ("Kompromittierter Endpunkt nach Entschlüsselung", "Nicht adressierbar — sobald der "
  "Anhang beim Endbenutzer entschlüsselt vorliegt, greift kein Transportschutz mehr "
  "(siehe docguard-Business-Papier, Abschnitt „Bewusste Abgrenzung“)."),
], keyw=150))

# ------------------------------------------------------------------ 8
A(h1("8. Offene Punkte für die weitere Ausarbeitung"))
AA(bullets([
    "<b>Zuordnung von Schlüssel und MX:</b> Abschnitt 3.1 verlangt, den Schlüssel für "
    "den primären MX abzufragen, hält im selben Satz aber fest, dass er domainweit "
    "veröffentlicht wird. Beides zusammen ergibt keine eindeutige Handlungsanweisung. "
    "Die Erprobung fragt den Eintrag unter der Empfängerdomain ab; die Reihenfolge der "
    "MX-Einträge wird erst dann bedeutsam, wenn Schlüssel je Hostname zugelassen "
    "werden. Zu entscheiden ist, ob es dabei bleibt.",
    "<b>Werkzeug beim Endnutzer:</b> Wird ein Anhang auf einen Nutzerschlüssel "
    "umgeschlüsselt, trägt auch dieser den Nutzlastkopf aus Abschnitt 2.3. Das "
    "Entschlüsselungswerkzeug beim Endnutzer muss ihn deshalb kennen, sonst sieht der "
    "Nutzer den Kopf als Datenmüll vor seiner Datei.",
    "<b>Schlüsselrotation:</b> Grundmechanismus über denselben Pooling-Ansatz wie in "
    "Abschnitt 3.2 beschrieben (alter und neuer Schlüssel parallel im Pool während der "
    "Übergangsfrist); konkrete Fristen und Ablaufprozess sind noch zu definieren.",
    "<b>Mehrere MX-Einträge:</b> Minimallösung spezifiziert (siehe Abschnitt 3.1 — "
    "primärer MX nach Preference); Pooling mehrerer unabhängiger Schlüssel bleibt als "
    "Erweiterung zu evaluieren (siehe Abschnitt 3.2, insbesondere "
    "Sicherheits-Resilienz-Trade-off und DNS-Antwortgrößen).",
    "<b>Trust-on-First-Use / Erstverteilung:</b> Prozess für die initiale, "
    "vertrauenswürdige Veröffentlichung eines Schlüssels für eine Domain, die noch "
    "keinen DNSSEC-verifizierten Eintrag hat. Dazu gehört die Absicherung des "
    "Erstkontakts in der zweiten Stufe des Geltungsbereichs (Abschnitt 4.1), die als "
    "einzige nicht durch Fail-Closed gedeckt ist.",
    "<b>Fehlerhafte Zuordnung:</b> Schutz davor, dass ein veralteter oder falsch "
    "zugeordneter DNS-Eintrag fälschlich als docguard-Unterstützung interpretiert wird, "
    "obwohl kein aktives, korrekt betriebenes Empfänger-Gateway dahintersteht.",
    "<b>Schlüsselverwahrung:</b> Empfehlung für HSM- oder vergleichbaren Schutz des "
    "privaten Schlüssels auf Empfängerseite.",
    "<b>Rückruf und Wechsel einer Passphrase (Abschnitt 5):</b> Verfahren für den Fall, "
    "dass eine Passphrase kompromittiert ist oder die Beziehung endet, einschließlich "
    "der Frage, ob bereits zugestellte Anhänge dadurch unbrauchbar werden sollen oder "
    "nicht.",
]))

# ------------------------------------------------------------------ 9
A(h1("9. Empfehlung für das weitere Vorgehen"))
A(para("Vorschlag: Abstimmung mit der zuständigen Aufsichts- bzw. "
       "Standardisierungsstelle zur Einordnung dieser Architektur relativ zu TR-03108, "
       "Klärung, ob eine Erweiterung bestehender Empfehlungen (statt eines neuen "
       "Standards) der sinnvollere Weg ist, sowie Pilotierung in einer kontrollierten "
       "Umgebung mit einer begrenzten Anzahl kooperierender Domains vor einer breiteren "
       "Betrachtung."))

A(Spacer(1, 18))
A(Rule())
A(Paragraph("Konzeptpapier, Stand November 2026 — Ergänzung zum docguard-Hauptkonzept "
            "(Passphrase-Verschlüsselung, Deniable Encryption, docguard Business). "
            "Kontakt: Christian Scheller · christian@scheller.me", S["footer"]))

SimpleDocTemplate(OUT, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                  topMargin=MARGIN, bottomMargin=MARGIN,
                  title="docguard — Secure Mail Transport",
                  author="Christian Scheller").build(story)
print("geschrieben:", OUT)
