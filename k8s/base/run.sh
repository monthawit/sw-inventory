#!/bin/sh
# Runs inside the DaemonSet container (busybox). Executes sw-inventory.sh with the
# HOST's own tools (dpkg/rpm/apt/dnf) via chroot into the read-only host root.
# Files are re-read every loop, so ConfigMap edits apply without a restart.
set -u

INTERVAL_SECONDS="${INTERVAL_SECONDS:-3600}"
JITTER_SECONDS="${JITTER_SECONDS:-600}"
HOST_ROOT="${HOST_ROOT:-/host}"
OSV_ENRICH="${OSV_ENRICH:-0}"
OSV_ECOSYSTEM="${OSV_ECOSYSTEM:-}"
OSV_TIMEOUT="${OSV_TIMEOUT:-10}"

build_regex() {
  grep -vE '^[[:space:]]*(#|$)' /config/allowlist.conf | sed 's/[[:space:]]*$//' | tr '\n' '|' | sed 's/|$//'
}

# spread first run across nodes
J=$(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % (JITTER_SECONDS + 1) ))
echo "sw-inventory: node=${NODE_NAME:-?} first run in ${J}s, then every ${INTERVAL_SECONDS}s"
sleep "$J"

while true; do
  SCRIPT=$(cat /config/sw-inventory.sh)
  ALLOWLIST_REGEX=$(build_regex)
  if chroot "$HOST_ROOT" /usr/bin/env \
        ALLOWLIST_REGEX="$ALLOWLIST_REGEX" \
        TEXTFILE_DIR=/var/lib/node_exporter/textfile \
        INVENTORY_DIR=/var/lib/sw-inventory \
        TMPDIR=/var/lib/sw-inventory \
        REFRESH_CACHE=0 \
        OSV_ENRICH="$OSV_ENRICH" \
        OSV_ECOSYSTEM="$OSV_ECOSYSTEM" \
        OSV_TIMEOUT="$OSV_TIMEOUT" \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        /bin/bash -c "$SCRIPT"; then
    echo "sw-inventory: $(date -u +%FT%TZ) ok"
  else
    echo "sw-inventory: $(date -u +%FT%TZ) FAILED rc=$?" >&2
  fi
  sleep "$INTERVAL_SECONDS"
done
