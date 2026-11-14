#!/bin/sh
# Only disposable, network-disabled containers. Never source this on a real host.
set -eu
[ "${CTFIR_DISPOSABLE_LAB:-}" = 1 ] && [ -f /.dockerenv ] || { echo 'disposable container required'; exit 2; }
BIN=$1
OUT=/ctfir-out
MARK=/usr/local/bin/.ctfir-marker-worker
PIDS=''
cleanup() {
  for pid in $PIDS; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  rm -f /var/tmp/.ctfir-marker-cache /var/tmp/.ctfir-marker-script /etc/cron.d/ctfir-marker-hidden /etc/cron.d/ctfir-marker-clean /etc/systemd/system/ctfir-marker-hidden.service /etc/systemd/system/ctfir-marker-clean.service /etc/ld.so.conf.d/ctfir-marker-multilib.conf "$MARK"
  chmod 700 /var/tmp/.ctfir-marker-denied 2>/dev/null || true
  rmdir /var/tmp/.ctfir-marker-denied 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
for path in /var/tmp/.ctfir-marker-cache "$MARK"; do [ ! -e "$path" ] || exit 3; done
mkdir -p /etc/cron.d /etc/systemd/system /etc/ld.so.conf.d /usr/local/bin /var/tmp/.ctfir-marker-denied
cp /bin/true /var/tmp/.ctfir-marker-cache
chmod 4755 /var/tmp/.ctfir-marker-cache
printf '#!/bin/sh\nexit 0\n' > /var/tmp/.ctfir-marker-script
chmod 4755 /var/tmp/.ctfir-marker-script
# Harmless resident script. No listener, reverse shell or network execution.
printf '#!/bin/sh\nwhile :; do sleep 1; done\n' > "$MARK"
chmod 755 "$MARK"
/bin/sh "$MARK" & PIDS="$PIDS $!"
if [ -x /bin/bash ]; then
  /bin/bash -c 'exec -a "[kworker/ctfir-marker]" /bin/sleep 60' & PIDS="$PIDS $!"
else
  /bin/busybox ash -c 'exec -a "[kworker/ctfir-marker]" /bin/sleep 60' & PIDS="$PIDS $!"
fi
printf '* * * * * root /bin/sh %s\n' "$MARK" > /etc/cron.d/ctfir-marker-hidden
printf '[Service]\nExecStart=/bin/sh %s\n' "$MARK" > /etc/systemd/system/ctfir-marker-hidden.service
printf '* * * * * root /usr/bin/curl https://example.org/health\n' > /etc/cron.d/ctfir-marker-clean
printf '[Service]\nExecStart=/usr/bin/python3 /usr/local/bin/backup.py\n' > /etc/systemd/system/ctfir-marker-clean.service
printf '/lib32\n/usr/lib32\n/libx32\n' > /etc/ld.so.conf.d/ctfir-marker-multilib.conf
chmod 000 /var/tmp/.ctfir-marker-denied
"$BIN" scan --out "$OUT/positive" > "$OUT/positive.log" 2>&1
# A distinct unprivileged scan must account for unreadable scope, not call it clean.
chmod 777 "$OUT"
if [ -x /bin/su ]; then SU=/bin/su; else SU=/usr/bin/su; fi
"$SU" -s /bin/sh nobody -c "$BIN scan --out $OUT/unprivileged" > "$OUT/unprivileged.log" 2>&1
cleanup
PIDS=''
"$BIN" scan --out "$OUT/clean" > "$OUT/clean.log" 2>&1
