#!/usr/bin/env bash
# install.sh — install sw-inventory Phase 1 on a host (run as root from this folder)
set -euo pipefail
cd "$(dirname "$0")"

TEXTFILE_DIR=/var/lib/node_exporter/textfile

install -d -m 0755 "$TEXTFILE_DIR" /var/lib/sw-inventory /etc/sw-inventory
install -m 0755 sw-inventory.sh /usr/local/bin/sw-inventory.sh
[[ -f /etc/sw-inventory/allowlist.conf ]] || install -m 0644 allowlist.conf /etc/sw-inventory/allowlist.conf
[[ -f /etc/default/sw-inventory ]] || cat > /etc/default/sw-inventory <<EOF
TEXTFILE_DIR=$TEXTFILE_DIR
INVENTORY_DIR=/var/lib/sw-inventory
ALLOWLIST_FILE=/etc/sw-inventory/allowlist.conf
# 1 = refresh apt/dnf cache before checking updates (needs repo access)
REFRESH_CACHE=0
EOF

install -m 0644 systemd/sw-inventory.service /etc/systemd/system/
install -m 0644 systemd/sw-inventory.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sw-inventory.timer
systemctl start sw-inventory.service

echo "--- result ---"
head -20 "$TEXTFILE_DIR/sw_inventory.prom"
echo
echo "Next: make sure node_exporter runs with --collector.textfile.directory=$TEXTFILE_DIR"
