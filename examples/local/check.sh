#!/usr/bin/env sh
# Runs on the host: reads /etc/shadow, which Falco's default rules flag,
# and the canary file the example's own rule watches, then checks Falco
# logged an alert for each. CI pipes it in with podman exec. With "released"
# as its argument, it checks the package hold is gone rather than in place.
set -eu
# The hold: an apt pin on Debian and Ubuntu, a dnf versionlock elsewhere.
if [ "${1:-held}" = held ]; then
  if command -v apt-get >/dev/null; then
    grep -qx 'Package: falco' /etc/apt/preferences.d/falco
  else
    dnf -q versionlock list 2>/dev/null | grep -q falco
  fi
elif [ -e /etc/apt/preferences.d/falco ] || dnf -q versionlock list 2>/dev/null | grep -q falco; then
  echo "falco is still held." >&2
  exit 1
fi
unit=falco-modern-bpf.service
systemctl is-enabled "$unit"
systemctl is-active "$unit"
[ "$(systemctl is-enabled falcoctl-artifact-follow.service)" = masked ]

# The probe can take a few seconds to attach after a start.
for _ in $(seq 60); do
  journalctl -u "$unit" -b --no-pager | grep -q 'Opening .syscall. source with modern BPF probe' && break
  sleep 1
done
# The health webserver, on port 8765 (223D in hex), listens on loopback only.
awk '$4 == "0A" { print $2 }' /proc/net/tcp /proc/net/tcp6 | grep -qx '0100007F:223D'
if awk '$4 == "0A" { print $2 }' /proc/net/tcp /proc/net/tcp6 | grep -v '^0100007F:' | grep -q ':223D$'; then
  echo "Falco's webserver listens beyond loopback." >&2
  exit 1
fi
sleep 5

echo canary > /etc/conn3x-falco-canary
since=$(date +%s)
cat /etc/shadow > /dev/null
cat /etc/conn3x-falco-canary > /dev/null

found() { journalctl -u "$unit" --since "@$since" --no-pager | grep -q "$1"; }
for _ in $(seq 30); do
  if found 'Sensitive file opened for reading by non-trusted program.*file=/etc/shadow' &&
    found 'Canary file read | file=/etc/conn3x-falco-canary process=cat'; then
    journalctl -u "$unit" --since "@$since" --no-pager | grep -E 'file=/etc/(shadow|conn3x-falco-canary)'
    rm -f /etc/conn3x-falco-canary
    exit 0
  fi
  sleep 1
done
echo "Falco didn't log both alerts. Its log since the reads:" >&2
journalctl -u "$unit" --since "@$since" --no-pager | tail -n 20 >&2
exit 1
