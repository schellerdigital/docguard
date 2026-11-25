#!/bin/sh
# Usage: ./dg_keygen.sh a   -> keys/a.key (600) und TXT-Zeile für DNS
set -eu
name="${1:?Name (a|b)}"
mkdir -p keys
umask 077
f="keys/$name.key"
[ -e "$f" ] && { echo "$f existiert bereits - abgebrochen" >&2; exit 1; }
age-keygen -o "$f" 2>/dev/null
pub=$(age-keygen -y "$f")
echo "Privater Schlüssel: $f (nicht weitergeben, nicht einchecken)"
echo
echo "DNS TXT-Eintrag (Name: _docguard.<deine-domain>):"
echo "  \"v=DG1; k=age-x25519; p=$pub\""
