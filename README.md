# sw-inventory — Phase 1

Software inventory and patch status metrics through the **node_exporter textfile collector**.
node_exporter itself is not modified.

```
systemd timer (hourly) → sw-inventory.sh → /var/lib/node_exporter/textfile/sw_inventory.prom
                                         → /var/lib/sw-inventory/packages.tsv  (full list, not sent to Prometheus)
node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile → Prometheus
```

Supports Debian/Ubuntu (dpkg/apt) and RHEL/Rocky/Alma (rpm/dnf/yum).

## Files

| File | Purpose |
|---|---|
| `sw-inventory.sh` | Collector script → `/usr/local/bin/` |
| `allowlist.conf` | Regex list of packages exported as `node_software_info` → `/etc/sw-inventory/` |
| `systemd/sw-inventory.{service,timer}` | Runs hourly (+ random 0–10 min delay) |
| `install.sh` | Installs everything on one host |
| `prometheus/sw-inventory-rules.yml` | Alert + recording rules (plain Prometheus, VM hosts) |
| `kustomization.yaml` | **K8s entry point** (`kubectl apply -k .`). Builds the ConfigMap from the same `sw-inventory.sh` + `allowlist.conf` |
| `k8s/base/` | DaemonSet, ServiceAccount, PrometheusRule, `run.sh` loop |
| `k8s/components/podmonitor/` | Mode B: httpd sidecar + PodMonitor |
| `k8s/node-exporter-values.yaml` | Mode A: kube-prometheus-stack (Helm) values to turn on the textfile collector |
| `k8s/node-exporter-patch.yaml` | Mode A: same, as a `kubectl patch` for non-Helm (plain manifest) installs |

## Install (per host)

```bash
sudo ./install.sh
```

Then make sure node_exporter runs with:

```
--collector.textfile.directory=/var/lib/node_exporter/textfile
```

* **systemd node_exporter:** add the flag to `ExecStart` (or `/etc/default/prometheus-node-exporter` / `/etc/sysconfig/node_exporter`), then restart.
* **K8s nodes:** do not use `install.sh`. Use the DaemonSet below.

## Install on Kubernetes (Prometheus Operator)

The DaemonSet runs on every node and mounts the host root **read-only**. It `chroot`s into the host so the
**host's own** `dpkg`/`rpm`/`apt`/`dnf` do the work (one image works for Ubuntu and RHEL nodes).
The only writable host paths are `/var/lib/node_exporter/textfile` and `/var/lib/sw-inventory`.
The container drops all capabilities except `SYS_CHROOT`, uses a read-only root filesystem, and gets no SA token.

### Mode A (default): node-exporter reads the textfile

```
DaemonSet sw-inventory ─(hostPath)─► /var/lib/node_exporter/textfile/sw_inventory.prom
node-exporter DaemonSet ─(hostPath, ro)─┘  → existing ServiceMonitor → Prometheus
```

```bash
# 1. turn on the textfile collector in kube-prometheus-stack
helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring \
  --reuse-values -f k8s/node-exporter-values.yaml
# 2. deploy collector + PrometheusRule
kubectl apply -k .
```

If Prometheus Operator / node-exporter was installed from plain manifests (no Helm, e.g. `kubectl apply` of
prometheus-operator/kube-prometheus), patch the node-exporter DaemonSet directly instead of step 1:

```bash
# 1. turn on the textfile collector by patching the node-exporter DaemonSet
kubectl patch daemonset <node-exporter-ds-name> -n monitoring \
  --type=json --patch-file k8s/node-exporter-patch.yaml
# 2. deploy collector + PrometheusRule
kubectl apply -k .
```

See `k8s/node-exporter-patch.yaml` for the patch and how to confirm the container index first.

Metrics then carry the same `job`/`instance` labels as all other node-exporter metrics, so dashboards can join on them directly.

### Mode B: DaemonSet serves metrics + PodMonitor (no node-exporter change)

Use for **OpenShift/OKD**, where cluster-monitoring's node-exporter is operator-managed, or any cluster where you cannot change node-exporter flags.
Uncomment `components:` in `kustomization.yaml`, then `kubectl apply -k .`
A busybox `httpd` sidecar (non-root, port 9102) serves `/sw_inventory.prom`. The PodMonitor scrapes it every 2 min and relabels `instance` and `node` to the node name.
Do not run Mode A and Mode B together, or every metric is duplicated.

### Before you apply

| Item | Check |
|---|---|
| Namespace | default `monitoring` (change `namespace:` in `kustomization.yaml`) |
| Selector labels | `release: kube-prometheus-stack` on PrometheusRule/PodMonitor must match Prometheus `ruleSelector` / `podMonitorSelector` |
| Pod Security Admission | hostPath needs the namespace at `pod-security.kubernetes.io/enforce=privileged` (the kube-prometheus-stack namespace usually already is, because node-exporter needs it too) |
| OpenShift SCC | `oc adm policy add-scc-to-user privileged -z sw-inventory -n <ns>` (or a custom SCC allowing hostPath + `SYS_CHROOT` + runAsUser 0) |
| Image | `busybox:1.37.0`. Mirror it to Harbor and set `images:` in `kustomization.yaml` (and the sidecar image in Mode B) |
| priorityClass | `system-node-critical`. Remove it if your policy restricts it to kube-system |
| Interval | `INTERVAL_SECONDS=3600`, `JITTER_SECONDS=600` env on the DaemonSet |

`REFRESH_CACHE` is forced to `0` in K8s mode because host `/` is read-only. Upgrade counts come from the node's existing apt/dnf cache.
Editing `allowlist.conf` or `sw-inventory.sh` and re-applying rolls the DaemonSet (ConfigMap hash suffix).

Verify:

```bash
kubectl -n monitoring rollout status ds/sw-inventory
kubectl -n monitoring logs ds/sw-inventory -c collector --tail=5     # "... ok"
# Mode A
kubectl -n monitoring exec ds/kube-prometheus-stack-prometheus-node-exporter -- \
  wget -qO- localhost:9100/metrics | grep node_sw_inventory_scan_success
```

In PromQL: `count(node_sw_inventory_scan_timestamp_seconds)` should equal `count(kube_node_info)`.

**OpenShift/OKD (RHCOS/FCOS) nodes** use rpm-ostree, with no dnf. `node_software_info` and the kernel metrics still work (rpm DB), but upgradable counts stay 0. Node OS updates are managed by the Machine Config Operator.

Check:

```bash
curl -s localhost:9100/metrics | grep -E '^node_(software|packages|kernel_update|reboot|sw_inventory)'
```

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `node_software_info` | name, version, source | Allowlisted package installed (=1) |
| `node_software_upgradable` | name, candidate, security | Allowlisted package has an update |
| `node_packages_total` | source | Number of installed packages |
| `node_packages_upgradable` | type=all/security | Pending updates |
| `node_kernel_latest_installed_info` | version, running | Newest installed kernel |
| `node_kernel_update_pending` | – | 1 = newer kernel installed but not booted |
| `node_reboot_required` | – | 1 = OS says reboot needed |
| `node_sw_inventory_scan_{success,duration_seconds,timestamp_seconds}` | – | Pipeline health |

Expected cardinality: about 15–40 series per node.

## Useful queries

```promql
# Which version of openssl runs where
node_software_info{name=~"openssl|openssl-libs|libssl.*"}

# Fleet version spread per package
count by (name, version) (node_software_info)

# Nodes with the most pending security updates
topk(10, node_packages_upgradable{type="security"})

# Nodes waiting for a reboot to load the new kernel
node_kernel_update_pending == 1
```

## Settings (`/etc/default/sw-inventory`)

* `REFRESH_CACHE=0` (default): read the existing apt/dnf cache. Fast, no network. The upgrade count is only as fresh as the last `apt update` / `dnf makecache` (unattended-upgrades or dnf-automatic usually refresh it).
* `REFRESH_CACHE=1`: refresh the cache on every run. Needs access to the repo or mirror. Takes about 5 s on Ubuntu.

To track a new package, add a regex line to `/etc/sw-inventory/allowlist.conf`. It is picked up on the next run.

## Notes

* Software running inside containers is not visible here (use Trivy Operator / Harbor scan for images).
* "Installed" is not the same as "running": a DB upgraded on disk still runs the old binary until it restarts.
* K8s mode was tested by simulating the DaemonSet (read-only recursive bind of host `/` + chroot + writable textfile dir) and the Mode B httpd content type. It has not yet been deployed on a live cluster.
* Tested on Ubuntu 24.04. The RHEL code path (rpm/dnf, `needs-restarting`) has not been run yet, so pilot it on 1 node first. `needs-restarting` comes from `dnf-utils` / `yum-utils`.
