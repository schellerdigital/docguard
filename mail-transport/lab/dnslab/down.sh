#!/bin/bash
cd "$(dirname "$0")"; W="$(pwd)/work/run"
for p in named.pid unbound.pid unbound.shell.pid; do [ -f "$W/$p" ] && kill "$(cat "$W/$p")" 2>/dev/null; done
pkill -f "named-lab -c $(pwd)/work" 2>/dev/null; pkill -f "unbound-lab -c $(pwd)/work" 2>/dev/null
echo "gestoppt"
