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
