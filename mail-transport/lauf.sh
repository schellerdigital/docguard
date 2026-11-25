#!/usr/bin/env bash
# Führt alle Prüfungen des docguard-Lab aus und schreibt das vollständige
# Protokoll in lauf-<zeitstempel>.log, damit es ohne Kopieren lesbar ist.
#
#   ./lauf.sh              offline-Prüfungen + echter Gateway-Test (braucht sudo)
#   ./lauf.sh --ohne-root  nur die beiden offline-Prüfungen
#   ./lauf.sh --stufe2     zusätzlich das Umschlüsseln auf den Nutzerschlüssel
#
# Der Rückgabewert ist 0, wenn alles bestanden hat.

set -uo pipefail                      # kein -e: Jeder Schritt soll laufen,
                                      # auch wenn der vorige fehlschlug.
cd "$(dirname "$(readlink -f "$0")")"

MIT_ROOT=1
STUFE2=""
for arg in "$@"; do
  case "$arg" in
    --ohne-root) MIT_ROOT=0 ;;
    --stufe2)    STUFE2="--stufe2" ;;
    *) echo "unbekannte Option: $arg"; exit 2 ;;
  esac
done

LOG="lauf-$(date +%Y%m%d-%H%M%S).log"

# Das Passwort vor der Umleitung abfragen, damit die Eingabe sauber läuft.
if [ "$MIT_ROOT" = 1 ] && [ "$(id -u)" != 0 ]; then
  echo "Der Gateway-Test braucht root. Bitte einmal das sudo-Passwort eingeben."
  sudo -v || { echo "ohne sudo nur die offline-Prüfungen"; MIT_ROOT=0; }
fi

exec > >(tee "$LOG") 2>&1

echo "docguard-Lab — Protokoll vom $(date '+%d.%m.%Y %H:%M:%S')"
echo "Rechner: $(hostname)  |  Verzeichnis: $PWD"
echo "python3: $(python3 --version 2>&1)  |  age: $(age --version 2>&1 || echo fehlt)"
echo "================================================================"

FEHLER=0

schritt() {                           # schritt "Name" befehl...
  local name="$1"; shift
  echo
  echo "---- $name"
  "$@"
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo "---- $name: bestanden"
  else
    echo "---- $name: FEHLGESCHLAGEN (Rückgabewert $rc)"
    FEHLER=$((FEHLER + 1))
  fi
  return 0
}

schritt "Entscheidungslogik (ohne DNS, ohne age)" \
        python3 sandbox/tests/test_failclosed.py

schritt "Durchlauf beider Filter mit echtem age" \
        python3 sandbox/tests/test_roundtrip.py

if [ "$MIT_ROOT" = 1 ]; then
  FEHLT=""
  for t in postfix named unbound dnssec-keygen dnssec-signzone age swaks dig; do
    command -v "$t" >/dev/null 2>&1 || PATH="$PATH:/usr/sbin:/sbin" command -v "$t" >/dev/null 2>&1 || FEHLT="$FEHLT $t"
  done
  # Das dnslab belegt 5301/5302 — dieselben Ports, die der Gateway-Test
  # für sein eigenes BIND und Unbound braucht. Das ist der häufigste Grund
  # für einen Abbruch, also vorher nachsehen und es beim Namen nennen.
  BELEGT=""
  for p in 2525 2526 2530 1025 5301 5302 10025 10026; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then BELEGT="$BELEGT $p"; fi
  done
  if [ -n "$BELEGT" ]; then
    echo
    echo "---- Echter Gateway-Test: übersprungen, belegte Ports:$BELEGT"
    case "$BELEGT" in
      *530*) echo "     5301/5302 gehören dem dnslab. Beenden mit:  bash lab/dnslab/down.sh" ;;
    esac
    echo "     Danach noch einmal: bash lauf.sh"
    FEHLER=$((FEHLER + 1))
  elif [ -n "$FEHLT" ]; then
    echo
    echo "---- Echter Gateway-Test: übersprungen, es fehlt:$FEHLT"
    echo "     sudo apt install postfix bind9 bind9utils unbound age swaks python3-dnspython python3-aiosmtpd"
    FEHLER=$((FEHLER + 1))
  else
    schritt "Echter Gateway-Test (Postfix, BIND, DNSSEC)" \
            sudo python3 sandbox/tests/native_gateway_test.py $STUFE2
  fi
else
  echo
  echo "---- Echter Gateway-Test: nicht angefordert (--ohne-root)"
fi

echo
echo "================================================================"
if [ "$FEHLER" -eq 0 ]; then
  echo "ERGEBNIS: alles bestanden"
else
  echo "ERGEBNIS: $FEHLER Schritt(e) fehlgeschlagen"
fi
echo "Protokoll: $PWD/$LOG"
exit "$FEHLER"
