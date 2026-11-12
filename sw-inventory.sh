#!/usr/bin/env bash
# sw-inventory.sh — Phase 1: Software inventory metrics for node_exporter textfile collector
# Supports: Debian/Ubuntu (dpkg/apt) and RHEL/Rocky/Alma/CentOS Stream/Fedora (rpm/dnf/yum)
#
# Output : $TEXTFILE_DIR/sw_inventory.prom   (read by node_exporter --collector.textfile.directory)
#          $INVENTORY_DIR/packages.tsv        (full inventory, NOT sent to Prometheus — for Phase 3)
#
# Env vars (override in /etc/default/sw-inventory):
#   TEXTFILE_DIR   default /var/lib/node_exporter/textfile
#   INVENTORY_DIR  default /var/lib/sw-inventory
#   ALLOWLIST_FILE default /etc/sw-inventory/allowlist.conf
#   REFRESH_CACHE  default 0  (1 = run apt-get update / dnf makecache before checking upgrades; needs repo access)
#   ALLOWLIST_REGEX optional  (overrides ALLOWLIST_FILE; used by the K8s DaemonSet)
#   TMPDIR         optional  (K8s mode points this at a writable host dir because host / is mounted read-only)

set -uo pipefail

TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}"
INVENTORY_DIR="${INVENTORY_DIR:-/var/lib/sw-inventory}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-/etc/sw-inventory/allowlist.conf}"
REFRESH_CACHE="${REFRESH_CACHE:-0}"
OUT="${TEXTFILE_DIR}/sw_inventory.prom"

START=$(date +%s.%N)
SUCCESS=1

mkdir -p "$TEXTFILE_DIR" "$INVENTORY_DIR"
TMP=$(mktemp "${OUT}.XXXXXX") || exit 1
PKGTMP=$(mktemp)
trap 'rm -f "$TMP" "$PKGTMP"' EXIT

# ---------- helpers ----------
esc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "${s//$'\n'/}"; }

if command -v dpkg-query >/dev/null 2>&1; then
  PKG_FAMILY=deb
elif command -v rpm >/dev/null 2>&1; then
  PKG_FAMILY=rpm
else
  echo "sw-inventory: no dpkg or rpm found" >&2
  exit 1
fi

# ---------- build allowlist regex ----------
ALLOW_RE="${ALLOWLIST_REGEX:-}"          # K8s mode passes the regex via env (allowlist comes from a ConfigMap)
if [[ -z "$ALLOW_RE" && -r "$ALLOWLIST_FILE" ]]; then
  ALLOW_RE=$(grep -vE '^\s*(#|$)' "$ALLOWLIST_FILE" | sed 's/[[:space:]]*$//' | paste -sd'|' -)
fi
[[ -z "$ALLOW_RE" ]] && ALLOW_RE='^(openssl|openssh-server|sudo)$'

# ---------- full package list: name<TAB>version ----------
if [[ $PKG_FAMILY == deb ]]; then
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 2>/dev/null \
    | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3}' | sort -u > "$PKGTMP" || SUCCESS=0
else
  rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null \
    | grep -v '^gpg-pubkey' | sort -u > "$PKGTMP" || SUCCESS=0
fi
PKG_TOTAL=$(wc -l < "$PKGTMP")
cp "$PKGTMP" "${INVENTORY_DIR}/packages.tsv.tmp" && mv "${INVENTORY_DIR}/packages.tsv.tmp" "${INVENTORY_DIR}/packages.tsv"

# ---------- upgradable packages: name<TAB>candidate<TAB>security(0/1)<TAB>severity ----------
# severity is one of: critical, high, medium, low, unknown (security update, no mapped severity), "" (not a security update)
UPG=$(mktemp); trap 'rm -f "$TMP" "$PKGTMP" "$UPG"' EXIT
if [[ $PKG_FAMILY == deb ]]; then
  [[ $REFRESH_CACHE == 1 ]] && { apt-get update -qq >/dev/null 2>&1 || SUCCESS=0; }
  # apt list line: name/suite1,suite2 newver arch [upgradable from: oldver]
  # Debian/Ubuntu's apt does not expose a per-CVE severity, only "is this from the -security pocket".
  apt list --upgradable 2>/dev/null | awk '/upgradable from/ {
      split($1,a,"/"); sec=(a[2] ~ /-security/)?1:0; sev=(sec==1)?"unknown":"";
      print a[1]"\t"$2"\t"sec"\t"sev }' > "$UPG"
else
  DNF=$(command -v dnf || command -v yum)
  if [[ -n "$DNF" ]]; then
    CACHEOPT="-C"; [[ $REFRESH_CACHE == 1 ]] && CACHEOPT=""
    # "<advisory> <Severity>/Sec. <name>-<ver>-<rel>.<arch>" -> name<TAB>severity (critical/high/medium/low)
    SECSEVMAP=$(mktemp)
    $DNF $CACHEOPT -q updateinfo list --security 2>/dev/null | awk 'NF>=3 {
        sev=tolower($2); sub(/\/.*/,"",sev); gsub(/important/,"high",sev); gsub(/moderate/,"medium",sev);
        n=$3; sub(/-[^-]+-[^-]+$/,"",n); print n"\t"sev }' | sort -u > "$SECSEVMAP"
    SECPKGS=$(cut -f1 "$SECSEVMAP" | sort -u)
    # check-update exits 100 when updates exist
    $DNF $CACHEOPT -q check-update 2>/dev/null | awk 'NF==3 && $1 ~ /\./ {
        n=$1; sub(/\.[^.]+$/,"",n); print n"\t"$2 }' \
      | while IFS=$'\t' read -r n v; do
          s=0; sev=""
          if grep -qxF "$n" <<<"$SECPKGS"; then
            s=1
            sev=$(awk -F'\t' -v n="$n" '$1==n{print $2; exit}' "$SECSEVMAP")
            case "$sev" in critical|high|medium|low) ;; *) sev=unknown ;; esac
          fi
          printf '%s\t%s\t%s\t%s\n' "$n" "$v" "$s" "$sev"
        done > "$UPG"
    rm -f "$SECSEVMAP"
  fi
fi
UPG_ALL=$(wc -l < "$UPG")
UPG_SEC=$(awk -F'\t' '$3==1' "$UPG" | wc -l)

# ---------- kernel: running vs newest installed ----------
RUNNING_KERNEL=$(uname -r)
if [[ $PKG_FAMILY == deb ]]; then
  LATEST_KERNEL=$(awk -F'\t' '$1 ~ /^linux-image-[0-9]/ {sub(/^linux-image-/,"",$1); print $1}' "$PKGTMP" | sort -V | tail -1)
else
  LATEST_KERNEL=$(rpm -q kernel kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null \
                  | grep -v 'not installed' | sort -Vu | tail -1)
fi
[[ -z "$LATEST_KERNEL" ]] && LATEST_KERNEL="$RUNNING_KERNEL"
KERNEL_PENDING=0; [[ "$RUNNING_KERNEL" != "$LATEST_KERNEL" ]] && KERNEL_PENDING=1

# ---------- reboot required (any reason) ----------
REBOOT_REQUIRED=$KERNEL_PENDING
if [[ -f /var/run/reboot-required ]]; then
  REBOOT_REQUIRED=1
elif command -v needs-restarting >/dev/null 2>&1; then
  needs-restarting -r >/dev/null 2>&1; [[ $? -eq 1 ]] && REBOOT_REQUIRED=1
fi

# ---------- write metrics ----------
{
  echo "# HELP node_software_info Installed version of allowlisted software (value always 1)."
  echo "# TYPE node_software_info gauge"
  awk -F'\t' -v re="$ALLOW_RE" '$1 ~ re' "$PKGTMP" | while IFS=$'\t' read -r n v; do
    printf 'node_software_info{name="%s",version="%s",source="%s"} 1\n' "$(esc "$n")" "$(esc "$v")" "$PKG_FAMILY"
  done

  echo "# HELP node_software_upgradable Allowlisted package has a newer version available (security=1 if from security advisory; severity is critical/high/medium/low/unknown for security updates, empty otherwise)."
  echo "# TYPE node_software_upgradable gauge"
  awk -F'\t' -v re="$ALLOW_RE" '$1 ~ re' "$UPG" | while IFS=$'\t' read -r n v s sev; do
    printf 'node_software_upgradable{name="%s",candidate="%s",security="%s",severity="%s"} 1\n' "$(esc "$n")" "$(esc "$v")" "$s" "$(esc "$sev")"
  done

  echo "# HELP node_packages_total Number of installed OS packages."
  echo "# TYPE node_packages_total gauge"
  echo "node_packages_total{source=\"$PKG_FAMILY\"} $PKG_TOTAL"

  echo "# HELP node_packages_upgradable Number of OS packages with pending updates."
  echo "# TYPE node_packages_upgradable gauge"
  echo "node_packages_upgradable{type=\"all\"} $UPG_ALL"
  echo "node_packages_upgradable{type=\"security\"} $UPG_SEC"

  echo "# HELP node_kernel_latest_installed_info Newest installed kernel package (compare with node_uname_info release)."
  echo "# TYPE node_kernel_latest_installed_info gauge"
  echo "node_kernel_latest_installed_info{version=\"$(esc "$LATEST_KERNEL")\",running=\"$(esc "$RUNNING_KERNEL")\"} 1"

  echo "# HELP node_kernel_update_pending 1 if a newer kernel is installed but not running."
  echo "# TYPE node_kernel_update_pending gauge"
  echo "node_kernel_update_pending $KERNEL_PENDING"

  echo "# HELP node_reboot_required 1 if the OS reports a reboot is required."
  echo "# TYPE node_reboot_required gauge"
  echo "node_reboot_required $REBOOT_REQUIRED"

  END=$(date +%s.%N)
  echo "# HELP node_sw_inventory_scan_success 1 if the last inventory run succeeded."
  echo "# TYPE node_sw_inventory_scan_success gauge"
  echo "node_sw_inventory_scan_success $SUCCESS"
  echo "# HELP node_sw_inventory_scan_duration_seconds Duration of the last inventory run."
  echo "# TYPE node_sw_inventory_scan_duration_seconds gauge"
  awk -v s="$START" -v e="$END" 'BEGIN{printf "node_sw_inventory_scan_duration_seconds %.3f\n", e-s}'
  echo "# HELP node_sw_inventory_scan_timestamp_seconds Unix time of the last inventory run."
  echo "# TYPE node_sw_inventory_scan_timestamp_seconds gauge"
  echo "node_sw_inventory_scan_timestamp_seconds $(date +%s)"
} > "$TMP"

chmod 0644 "$TMP"
mv "$TMP" "$OUT"     # atomic replace
