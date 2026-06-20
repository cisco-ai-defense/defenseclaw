#!/usr/bin/env bash
# Host-wide cleanup for the self-hosted E2E runner.
#
# Idempotent. Logs each section so we can correlate disk-fill regressions to
# specific consumers when CI fails the FREE_GB headroom check below.
#
# Why a script instead of inlining in e2e.yml: the disk-fill bug surfaced as
# "the self-hosted runner lost communication with the server" (looks like an
# OOM but is actually exhausted root fs). The runner died mid-job before its
# inline cleanup could run, so the next run inherited the same full disk.
# Calling this script BEFORE the heavy E2E steps (and again unconditionally
# in post-run cleanup) means a single run's worth of leaks can never wedge
# the host across runs.
#
# Set RUNNER_CLEANUP_VERBOSE=1 to trace every command. Otherwise we just emit
# section headers and leave individual rm/prune output on stdout.
set -u
[ "${RUNNER_CLEANUP_VERBOSE:-0}" = "1" ] && set -x

log() { printf '[runner-cleanup] %s\n' "$*"; }

repair_state_path() {
  local state_path="$1"
  [ -e "$state_path" ] || return 0
  if sudo -n chown -R -- "$runner_uid:$runner_gid" "$state_path" 2>/dev/null; then
    chmod -R u+rwX -- "$state_path" 2>/dev/null || true
    return 0
  fi
  if sudo -n setfacl -R -m "u:${runner_uid}:rwX" -- "$state_path" 2>/dev/null; then
    return 0
  fi
  if sudo -n chmod -R a+rwX -- "$state_path" 2>/dev/null; then
    log "Relaxed permissions on $state_path after ownership repair failed"
    return 0
  fi
  return 1
}

repair_persistent_state_permissions() {
  local runner_uid runner_gid state_dir repaired resolved_state_dir
  runner_uid="$(id -u)"
  runner_gid="$(id -g)"
  for state_dir in "$HOME/.defenseclaw" "$HOME/.openclaw"; do
    [ -e "$state_dir" ] || continue
    repaired=0

    # Sandbox setup can leave ~/.openclaw as a symlink to a root-owned target.
    # Repair the resolved target first; chown -R on the symlink path itself may
    # only affect the link and leave openclaw.json unreadable.
    if [ -L "$state_dir" ]; then
      resolved_state_dir="$(realpath "$state_dir" 2>/dev/null || true)"
      if [ -n "$resolved_state_dir" ] && [ "$resolved_state_dir" != "$state_dir" ]; then
        if repair_state_path "$resolved_state_dir"; then
          repaired=1
        else
          log "WARNING: unable to repair permissions on $resolved_state_dir"
        fi
      fi
    fi

    if repair_state_path "$state_dir"; then
      repaired=1
    fi
    if [ "$repaired" -ne 1 ]; then
      log "WARNING: unable to repair permissions on $state_dir"
    fi
  done
}

normalize_openclaw_ci_config() {
  local cfg_path="$HOME/.openclaw/openclaw.json"
  [ -f "$cfg_path" ] || return 0
  python3 - "$cfg_path" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])

try:
    with cfg_path.open() as f:
        cfg = json.load(f)
except PermissionError as exc:
    print(f"[runner-cleanup] WARNING: OpenClaw config unreadable during normalization: {exc}")
    raise SystemExit(0)
except json.JSONDecodeError as exc:
    print(f"[runner-cleanup] WARNING: OpenClaw config invalid during normalization: {exc}")
    raise SystemExit(0)

if not isinstance(cfg, dict):
    raise SystemExit(0)

changed = False


def is_defenseclaw_load_path(value):
    if isinstance(value, str):
        return Path(value.rstrip("/")).name == "defenseclaw"
    if isinstance(value, dict):
        return any(is_defenseclaw_load_path(item) for item in value.values())
    if isinstance(value, list):
        return any(is_defenseclaw_load_path(item) for item in value)
    return False


plugins = cfg.get("plugins")
if isinstance(plugins, dict):
    for section in ("entries", "installs", "allow", "enabled"):
        bucket = plugins.get(section)
        if isinstance(bucket, dict):
            next_bucket = {name: meta for name, meta in bucket.items() if str(name) != "defenseclaw"}
            if next_bucket != bucket:
                plugins[section] = next_bucket
                changed = True
        elif isinstance(bucket, list):
            next_bucket = [item for item in bucket if str(item) != "defenseclaw"]
            if next_bucket != bucket:
                plugins[section] = next_bucket
                changed = True

    load = plugins.get("load")
    if isinstance(load, dict):
        paths = load.get("paths")
        if isinstance(paths, list):
            next_paths = [path for path in paths if not is_defenseclaw_load_path(path)]
            if next_paths != paths:
                load["paths"] = next_paths
                changed = True

gateway = cfg.get("gateway")
if not isinstance(gateway, dict):
    gateway = {}
    cfg["gateway"] = gateway
    changed = True
if not gateway.get("mode"):
    gateway["mode"] = "local"
    changed = True

channels = cfg.get("channels")
if isinstance(channels, dict):
    for channel in channels.values():
        if not isinstance(channel, dict):
            continue
        if "nativeStreaming" in channel:
            channel.pop("nativeStreaming", None)
            changed = True
        if "streaming" in channel and not isinstance(channel.get("streaming"), dict):
            channel.pop("streaming", None)
            changed = True

if changed:
    with cfg_path.open("w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print("[runner-cleanup] OpenClaw config normalized for CI")
else:
    print("[runner-cleanup] OpenClaw config already clean")
PY
}

if [ "${RUNNER_CLEANUP_STATE_ONLY:-0}" = "1" ]; then
  log "Repairing persistent product state permissions and config only"
  repair_persistent_state_permissions
  normalize_openclaw_ci_config
  exit 0
fi

log "Disk before cleanup: $(df -h / | tail -1)"

# 1. Stop stranded sidecar processes from earlier crashed runs. The runner
# dying mid-job leaves these around (see PID 2462199 / 2461276 incident).
defenseclaw-gateway stop 2>/dev/null || true
openclaw gateway stop 2>/dev/null || true
pkill -TERM -f 'openclaw-gateway' 2>/dev/null || true
pkill -TERM -f 'defenseclaw-gateway' 2>/dev/null || true
pkill -TERM -f 'splunk_hec_mock.py' 2>/dev/null || true
sleep 1
pkill -KILL -f 'openclaw-gateway' 2>/dev/null || true
pkill -KILL -f 'defenseclaw-gateway' 2>/dev/null || true

# 2. Aggressive docker reclaim. Splunk's image is ~4 GB and a dangling-only
# prune would never reclaim it across runs.
docker container prune -f 2>/dev/null || true
docker volume prune -f 2>/dev/null || true
docker image prune -a -f 2>/dev/null || true
docker builder prune -a -f 2>/dev/null || true

# 2b. Persistent product state can be left owned by root after sandboxed or
# service-backed E2E paths. Repair it before workflow cleanup parses or prunes
# these directories on the next run.
repair_persistent_state_permissions
normalize_openclaw_ci_config

# 3. Runner-level caches. _work/_actions and _tool accumulate from every job
# that ever ran on this host; without TTL pruning they grow unbounded.
RUNNER_ROOT="$(dirname "$(dirname "${RUNNER_WORKSPACE:-/home/ubuntu/actions-runner/_work/defenseclaw}")")"
find "$RUNNER_ROOT/_work/_actions" -mindepth 2 -maxdepth 3 \
     -type d -mtime +1 -exec rm -rf {} + 2>/dev/null || true
find "$RUNNER_ROOT/_work/_tool" -mindepth 2 -maxdepth 3 \
     -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
find "$RUNNER_ROOT/_diag" -type f -mtime +1 -delete 2>/dev/null || true

# 3b. Old runner binaries from in-place upgrades (./bin is symlinked to
# ./bin.<active-version>; everything else is dead weight). On the bedrock
# runner this saved ~1.4 GB.
RUNNER_HOME="$(dirname "$RUNNER_ROOT")"
if [ -L "$RUNNER_HOME/bin" ]; then
  ACTIVE_BIN="$(basename "$(readlink "$RUNNER_HOME/bin")")"
  ACTIVE_EXT="${ACTIVE_BIN/bin/externals}"
  for d in "$RUNNER_HOME"/bin.* "$RUNNER_HOME"/externals.*; do
    [ -d "$d" ] || continue
    base="$(basename "$d")"
    if [ "$base" != "$ACTIVE_BIN" ] && [ "$base" != "$ACTIVE_EXT" ]; then
      rm -rf "$d" 2>/dev/null || true
    fi
  done
fi

# 4. Language / package caches filled by `make install`. /tmp/go-build* is
# the single biggest disk leak we've seen: a single failed E2E job leaves
# ~700 MB behind, and `go clean -cache` does NOT touch them (it only flushes
# ~/.cache/go-build).
go clean -cache 2>/dev/null || true
rm -rf "$HOME/.cache/go-build" 2>/dev/null || true
rm -rf "$HOME/.cache/uv"/* "$HOME/.cache/pip"/* 2>/dev/null || true
# `npm cache clean --force` is a no-op on hosts where npm isn't installed
# globally; the explicit rm covers nvm-managed installs too.
npm cache clean --force 2>/dev/null || true
rm -rf "$HOME/.npm/_cacache" 2>/dev/null || true

# 5. /tmp leaks from prior runs. Every entry here has been observed in a
# disk-fill incident on the self-hosted runner.
rm -rf /tmp/go-build* /tmp/go-link-* /tmp/go-* 2>/dev/null || true
rm -rf /tmp/buildah* 2>/dev/null || true
rm -rf /tmp/dclaw-test-* 2>/dev/null || true
rm -rf /tmp/openclaw 2>/dev/null || true
rm -rf /tmp/defenseclaw-logs-* 2>/dev/null || true
rm -rf /tmp/splunk-mock-*.log /tmp/splunk-mock.stdout 2>/dev/null || true
rm -f /tmp/opa 2>/dev/null || true

# 6. Journals grow unbounded on long-running runners.
journalctl --user --vacuum-time=1h 2>/dev/null || true
sudo -n journalctl --vacuum-size=200M 2>/dev/null || true

log "Disk after cleanup: $(df -h / | tail -1)"
