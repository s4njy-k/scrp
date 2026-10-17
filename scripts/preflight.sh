#!/usr/bin/env bash
# Phase A preflight (blueprint §2, §18): inventory the REAL remote VM and write a
# compatibility record. Read-only: it changes nothing on the host, stops no
# daemon and touches no other project.
#
#   scripts/preflight.sh [--context rootless] [--data-dir /srv/cyber-web-collector] [--check-public-ip] > compatibility-record.md
#
# --check-public-ip contacts https://api.ipify.org to learn the current public
# egress IP (opt-in: it sends a request to an external service).
set -uo pipefail
CTX=rootless
DATA_DIR="${COLLECTOR_DATA_DIR:-/srv/cyber-web-collector}"
CHECK_IP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --context) CTX="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --check-public-ip) CHECK_IP=1; shift ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac
done
blockers=()
warnings=()
section() { printf '\n## %s\n\n```\n' "$1"; }
endsection() { printf '```\n'; }
run() { "$@" 2>&1 || true; }

printf '# Compatibility record — cyber-web-collector\n\nGenerated: %s on host `%s` by `%s`\n' "$(date -u +%FT%TZ)" "$(hostname)" "$(id -un)"

section "Operating system"; run cat /etc/os-release; run uname -a; endsection
section "CPU"; run nproc; run lscpu | grep -Ei 'model name|socket|thread|core|virtuali|hypervisor|flags' | cut -c1-200; endsection
section "Load, I/O wait and steal (vmstat 1 5)"; run cat /proc/loadavg; run vmstat 1 5; endsection
section "Memory and swap"; run free -h; endsection
section "Filesystems"; run df -hT; run findmnt -no SOURCE,FSTYPE,OPTIONS -T "$DATA_DIR"; endsection
section "GPU"; if command -v nvidia-smi >/dev/null; then run nvidia-smi -L; else echo "nvidia-smi not present (no usable NVIDIA GPU expected)"; fi; run lspci 2>/dev/null | grep -Ei 'vga|display|3d'; endsection

section "cgroups and delegation"
fs=$(stat -fc %T /sys/fs/cgroup 2>/dev/null); echo "cgroup fs: $fs"
uid=$(id -u)
deleg="/sys/fs/cgroup/user.slice/user-${uid}.slice/user@${uid}.service/cgroup.controllers"
if [ -r "$deleg" ]; then echo "delegated controllers: $(cat "$deleg")"; else echo "delegation file not readable: $deleg"; fi
endsection
[ "$fs" = "cgroup2fs" ] || blockers+=("cgroup v2 not mounted: rootless resource caps will not be enforced")
if [ -r "$deleg" ]; then
  for c in cpu memory pids; do grep -qw "$c" "$deleg" || blockers+=("cgroup controller '$c' not delegated to user $uid: compose cpus/mem_limit/pids_limit ineffective (see docs/runbook.md#cgroup-delegation)"); done
fi

section "User namespaces (Chromium sandbox)"
for k in kernel.unprivileged_userns_clone user.max_user_namespaces kernel.apparmor_restrict_unprivileged_userns; do
  printf '%s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo n/a)"
done
endsection
[ "$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)" = "0" ] && blockers+=("unprivileged user namespaces disabled: Chromium sandbox cannot start (deployment blocker; do not disable the sandbox)")
[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ] && warnings+=("AppArmor restricts unprivileged userns: verify Chromium sandbox inside the rootless engine (docs/security.md#sandbox-verification)")

section "Docker contexts and daemons"
run docker context ls
run docker --context "$CTX" info --format 'Server {{.ServerVersion}} | rootless={{range .SecurityOptions}}{{.}} {{end}} | cgroup={{.CgroupDriver}} v{{.CgroupVersion}} | storage={{.Driver}} | root={{.DockerRootDir}}'
run docker --context "$CTX" compose version
run docker --context "$CTX" compose ls
run docker --context "$CTX" ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'
endsection
docker --context "$CTX" info >/dev/null 2>&1 || blockers+=("docker context '$CTX' not reachable")
docker --context "$CTX" compose ls 2>/dev/null | grep -q '^cyber-web-collector ' && warnings+=("a compose project named cyber-web-collector already exists: inspect before 'up'")

section "Listening ports (existing services must stay bound unchanged)"; run ss -ltnp; endsection
section "Clock synchronisation (evidence timestamps)"; run timedatectl show -p NTPSynchronized -p Timezone; run chronyc tracking 2>/dev/null | head -5; endsection
[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ] || warnings+=("clock not confirmed NTP-synchronised: artifact timestamps depend on the host clock")

section "systemd user lingering (rootless daemon after logout)"; run loginctl show-user "$(id -un)" -p Linger; run systemctl --user is-enabled docker; endsection
[ "$(loginctl show-user "$(id -un)" -p Linger 2>/dev/null)" = "Linger=yes" ] || warnings+=("user lingering disabled: the rootless daemon may stop at logout (docs/runbook.md#start-on-boot)")

section "Data directory"
if [ -d "$DATA_DIR" ]; then run ls -la "$DATA_DIR"; run df -h "$DATA_DIR"; else echo "$DATA_DIR does not exist yet"; fi
endsection
if [ -d "$DATA_DIR" ]; then
  free_gb=$(df -BG --output=avail "$DATA_DIR" | tail -1 | tr -dc 0-9)
  [ "${free_gb:-0}" -lt 40 ] && blockers+=("only ${free_gb} GB free at $DATA_DIR: below the 40 GB resume threshold")
  fstype=$(findmnt -no FSTYPE -T "$DATA_DIR")
  [ "$fstype" = "ext4" ] || warnings+=("$DATA_DIR is on $fstype, blueprint assumed ext4")
fi

section "Backup destination"
if [ -n "${BACKUP_DEST:-}" ]; then
  run findmnt -no SOURCE,FSTYPE -T "$BACKUP_DEST"
  if [ "$(stat -c %d "$BACKUP_DEST" 2>/dev/null)" = "$(stat -c %d "$DATA_DIR" 2>/dev/null)" ]; then echo "SAME DEVICE as data dir"; fi
else
  echo "BACKUP_DEST not set: no independent backup destination identified"
fi
endsection
if [ -z "${BACKUP_DEST:-}" ] || [ "$(stat -c %d "${BACKUP_DEST:-/nonexistent}" 2>/dev/null)" = "$(stat -c %d "$DATA_DIR" 2>/dev/null)" ]; then
  warnings+=("no independent backup storage: single-disk risk remains and must be reported")
fi

section "Outbound vantage"
if [ "$CHECK_IP" = 1 ]; then printf 'public egress IP: %s\n' "$(curl -fsS -m 10 https://api.ipify.org || echo unknown)"; else echo "not checked (pass --check-public-ip to contact api.ipify.org)"; fi
echo "Note: the local egress gateway does not change this public IP or its country."
endsection

printf '\n## Blockers\n\n'
if [ ${#blockers[@]} -eq 0 ]; then echo "- none detected by this script (manual review still required)"; else printf -- '- %s\n' "${blockers[@]}"; fi
printf '\n## Warnings\n\n'
if [ ${#warnings[@]} -eq 0 ]; then echo "- none"; else printf -- '- %s\n' "${warnings[@]}"; fi
printf '\nRecord the resource allocation actually granted to this project (CPU/memory/disk) and any services that must be preserved.\n'
[ ${#blockers[@]} -eq 0 ]
