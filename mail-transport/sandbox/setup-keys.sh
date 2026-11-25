#!/bin/sh
# Erzeugt den privaten Schlüssel der Empfängerdomain und trägt den passenden
# öffentlichen Schlüssel in die Zonendateien ein.
#
# Der private Schlüssel liegt bewusst nicht im Repository: Ein eingecheckter
# privater Schlüssel ist auch in einem Labor ein schlechtes Vorbild, und weil
# der öffentliche Schlüssel in der Zone dazu passen muss, wird er hier gleich
# mitgeschrieben.
set -eu
cd "$(dirname "$0")"
KEY=keys/empfang-private.key
mkdir -p keys
if [ ! -e "$KEY" ]; then
  (umask 077; age-keygen -o "$KEY" 2>/dev/null)
  echo "erzeugt:    $KEY"
else
  echo "vorhanden:  $KEY"
fi
PUB=$(age-keygen -y "$KEY")
for z in dns/zones/empfang.docguard.test.zone dns/zones/unsigned.docguard.test.zone; do
  sed "s#^_docguard IN TXT .*#_docguard IN TXT \"v=DG1; k=age-x25519; p=$PUB\"#" "$z" > "$z.neu"
  mv "$z.neu" "$z"
  echo "eingetragen: $z"
done
echo "öffentlicher Schlüssel: $PUB"
