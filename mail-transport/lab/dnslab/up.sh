#!/bin/bash
# Lokales DNSSEC-Lab: signierende Autoritative (BIND, :5301) + validierender Resolver (Unbound, :5302)
# Zonen: docguard.lab, keyleash.lab (signiert), unsigned.lab (unsigniert)
# Voraussetzung: apt install bind9 unbound bind9-dnsutils age
set -euo pipefail
cd "$(dirname "$0")"; ROOT=$(pwd); LAB=$(cd .. && pwd)
W="$ROOT/work"; ./down.sh >/dev/null 2>&1 || true
rm -rf "$W"; mkdir -p "$W"/{keys,zones,run,bin}
# AppArmor (Ubuntu) sperrt named/unbound unter /usr/sbin im Home -> Kopien ohne Profil verwenden
cp "$(command -v named)" "$W/bin/named-lab"; cp "$(command -v unbound)" "$W/bin/unbound-lab"
mkdir -p "$LAB/keys"
for n in a b; do [ -f "$LAB/keys/$n.key" ] || (cd "$LAB" && ./dg_keygen.sh $n >/dev/null); done
PUBA=$(age-keygen -y "$LAB/keys/a.key"); PUBB=$(age-keygen -y "$LAB/keys/b.key")

mkzone() { # name txtkey
  local z=$1 pub=${2:-}
  local f="$W/zones/$z.db"
  { echo '$TTL 60'
    echo "@ IN SOA ns.$z. admin.$z. 1 3600 600 86400 60"
    echo "@ IN NS ns.$z."; echo "ns IN A 127.0.0.1"
    echo "@ IN MX 10 mail.$z."; echo "mail IN A 127.0.0.1"
    [ -n "$pub" ] && echo "_docguard IN TXT \"v=DG1; k=age-x25519; p=$pub\""
    true; } > "$f"
}
mkzone docguard.lab "$PUBA"; mkzone keyleash.lab "$PUBB"; mkzone unsigned.lab "$PUBB"

: > "$W/anchors.conf"
for z in docguard.lab keyleash.lab; do
  (cd "$W/keys" && dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE -f KSK $z >/dev/null && dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE $z >/dev/null)
  dnssec-signzone -q -S -K "$W/keys" -d "$W/keys" -o $z -N unixtime -f "$W/zones/$z.db.signed" "$W/zones/$z.db" >/dev/null
  awk '{d=""; for(i=7;i<=NF;i++) d=d $i; print "trust-anchor: \"" $1 " DS " $4 " " $5 " " $6 " " d "\""}' "$W/keys/dsset-$z." >> "$W/anchors.conf"
done

cat > "$W/named.conf" <<N
options { directory "$W"; listen-on port 5301 { 127.0.0.1; }; listen-on-v6 { none; };
  recursion no; dnssec-validation no; pid-file "$W/run/named.pid"; session-keyfile "$W/run/session.key"; };
controls { };
zone "docguard.lab" { type primary; file "$W/zones/docguard.lab.db.signed"; };
zone "keyleash.lab" { type primary; file "$W/zones/keyleash.lab.db.signed"; };
zone "unsigned.lab" { type primary; file "$W/zones/unsigned.lab.db"; };
N
cat > "$W/unbound.conf" <<U
server:
  interface: 127.0.0.1@5302
  access-control: 127.0.0.0/8 allow
  do-not-query-localhost: no
  directory: "$W"
  pidfile: "$W/run/unbound.pid"
  use-syslog: no
  logfile: ""
  module-config: "validator iterator"
  val-log-level: 1
  username: ""
  chroot: ""
  include: "$W/anchors.conf"
stub-zone: name: "docguard.lab" stub-addr: 127.0.0.1@5301
U
# stub-zone braucht eigene Zeilen
python3 - "$W/unbound.conf" <<'P'
import sys
p=sys.argv[1]; s=open(p).read().split("stub-zone:")[0]
for z in ("docguard.lab","keyleash.lab","unsigned.lab"):
    s+=f'stub-zone:\n  name: "{z}"\n  stub-addr: 127.0.0.1@5301\n'
open(p,"w").write(s)
P
"$W/bin/named-lab" -c "$W/named.conf" 2>"$W/named.err" || { cat "$W/named.err"; exit 1; }
"$W/bin/unbound-lab" -c "$W/unbound.conf" -d >"$W/unbound.log" 2>&1 &
echo $! > "$W/run/unbound.shell.pid"
for i in $(seq 20); do dig +short -p 5302 @127.0.0.1 docguard.lab SOA >/dev/null 2>&1 && break; sleep 0.5; done
echo "DNSSEC-Lab läuft. In lab.env eintragen:"
echo "  DG_DNS_RESOLVER=127.0.0.1:5302"
echo "  A_KEY_DOMAIN=docguard.lab"; echo "  B_KEY_DOMAIN=keyleash.lab"
echo "Test: python3 dnslab/dnslab_test.py   |  Stoppen: dnslab/down.sh"
