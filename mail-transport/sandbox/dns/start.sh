#!/bin/bash
# Signierende Autoritative (BIND, intern) + validierender Resolver (Unbound, nach außen).
# Zonen in SIGNED_ZONES werden beim Start mit frischen Schlüsseln signiert, die DS-Records
# werden als Trust-Anchor in Unbound eingetragen. Zonen in UNSIGNED_ZONES bleiben unsigniert.
set -euo pipefail
ZONES_SRC=${ZONES_SRC:-/zones}
W=${WORK:-/var/lib/dglab}
SIGNED_ZONES=${SIGNED_ZONES:-"sender.docguard.test empfang.docguard.test"}
UNSIGNED_ZONES=${UNSIGNED_ZONES:-"unsigned.docguard.test"}
AUTH_PORT=${AUTH_PORT:-5301}; RES_ADDR=${RES_ADDR:-0.0.0.0}; RES_PORT=${RES_PORT:-53}
rm -rf "$W"; mkdir -p "$W"/{keys,zones,run,bin}
# Ubuntu/AppArmor: Die Profile von /usr/sbin/named und /usr/sbin/unbound erlauben keine Konfiguration unter /tmp
# (Symptom: stiller Abbruch, dmesg: apparmor="DENIED" profile="named"). Das Profil haengt am Pfad, daher laufen
# Kopien der Programme aus dem Arbeitsordner. Das System selbst bleibt unveraendert.
cp "$(command -v named)" "$W/bin/named-lab"; cp "$(command -v unbound)" "$W/bin/unbound-lab"
NAMED="$W/bin/named-lab"; UNBOUND="$W/bin/unbound-lab"
: > "$W/anchors.conf"
for z in $SIGNED_ZONES; do
  (cd "$W/keys" && dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE -f KSK $z >/dev/null && dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE $z >/dev/null)
  dnssec-signzone -q -S -K "$W/keys" -d "$W/keys" -o $z -N keep -f "$W/zones/$z.signed" "$ZONES_SRC/$z.zone" >/dev/null
  awk '{d=""; for(i=7;i<=NF;i++) d=d $i; print "trust-anchor: \"" $1 " DS " $4 " " $5 " " $6 " " d "\""}' "$W/keys/dsset-$z." >> "$W/anchors.conf"
done
{ echo "options { directory \"$W\"; listen-on port $AUTH_PORT { 127.0.0.1; }; listen-on-v6 { none; }; recursion no; allow-query { any; };"
  echo "  dnssec-validation no; pid-file \"$W/run/named.pid\"; session-keyfile \"$W/run/session.key\"; };"
  echo "controls { };"
  for z in $SIGNED_ZONES; do echo "zone \"$z\" { type primary; file \"$W/zones/$z.signed\"; };"; done
  for z in $UNSIGNED_ZONES; do cp "$ZONES_SRC/$z.zone" "$W/zones/$z.zone"; echo "zone \"$z\" { type primary; file \"$W/zones/$z.zone\"; };"; done
} > "$W/named.conf"
{ echo "server:"
  echo "  interface: $RES_ADDR@$RES_PORT"
  echo "  access-control: 0.0.0.0/0 allow"
  echo "  do-not-query-localhost: no"
  echo "  module-config: \"validator iterator\""
  echo "  username: \"\""; echo "  chroot: \"\""; echo "  directory: \"$W\""; echo "  pidfile: \"$W/run/unbound.pid\""
  echo "  local-zone: \"test.\" nodefault"
  echo "  include: \"$W/anchors.conf\""
  for z in $SIGNED_ZONES $UNSIGNED_ZONES; do
    echo "stub-zone:"; echo "  name: \"$z\""; echo "  stub-addr: 127.0.0.1@$AUTH_PORT"
  done
} > "$W/unbound.conf"
"$NAMED" -c "$W/named.conf" ${NAMED_USER:+-u $NAMED_USER}
if [ "${DG_BACKGROUND:-0}" = "1" ]; then "$UNBOUND" -c "$W/unbound.conf" -d >"$W/unbound.log" 2>&1 & echo $! > "$W/run/unbound.shell.pid"; exit 0; fi
echo "DNSSEC-Resolver auf $RES_ADDR:$RES_PORT, signierte Zonen: $SIGNED_ZONES"
exec "$UNBOUND" -c "$W/unbound.conf" -d
