#!/bin/bash
# Simuliert Manipulation: ersetzt den Schlüssel in docguard.lab OHNE neu zu signieren -> bogus -> fail-closed
cd "$(dirname "$0")"; W="$(pwd)/work"; f="$W/zones/docguard.lab.db.signed"
T=$(mktemp); age-keygen -o "$T" 2>/dev/null; FAKE=$(age-keygen -y "$T"); rm -f "$T"
python3 - "$f" "$FAKE" <<'P'
import re,sys
p,fake=sys.argv[1:]; s=open(p).read()
n=0
s,n=re.subn(r'p=age1[a-z0-9]+','p='+fake,s,count=1)
if n==0: sys.exit('kein Schluessel in der Zone gefunden - Format geaendert?')
open(p,'w').write(s)
P
kill -HUP "$(cat "$W/run/named.pid")"
# Unbound neu starten (Cache leeren)
kill "$(cat "$W/run/unbound.pid")" 2>/dev/null; sleep 1
"$W/bin/unbound-lab" -c "$W/unbound.conf" -d >"$W/unbound.log" 2>&1 &
sleep 1.5; echo "Zone manipuliert (Signatur ungültig), Resolver neu gestartet."
