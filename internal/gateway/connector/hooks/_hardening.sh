#!/bin/bash
# defenseclaw-managed-hook v1
# Plan B4 / S0.4: shell-side hook hardening helpers.
#
# Sourced at the top of every hook in this directory (claude-code-hook.sh,
# codex-hook.sh, inspect-*.sh) BEFORE any agent-supplied data is touched.
# The Go side already strips dangerous git env (sanitizeHookCWD +
# safeGitEnv); this file gives the shell-side scripts the matching
# defense surface so a rogue agent can't influence the hook by exporting
# GIT_*, HOME, PATH, etc. before invoking it.
#
# Usage:
#   . "$(dirname "${BASH_SOURCE[0]}")/_hardening.sh"
#   defenseclaw_harden_env
#   defenseclaw_harden_resources
#
# All helpers are idempotent and pure — no side effects beyond setting
# env / ulimit. They MUST NOT call out to the agent or the gateway.

# Resource limits — bound the hook so a stuck regex / hostile input
# can't wedge the agent. Plan F16 ask: CPU 5s, virt mem 512MiB, fds 32.
# Use ulimit -S (soft) so the hook doesn't try to exceed kernel maxima
# on platforms where defaults differ; soft limits still cause SIGXCPU
# / mmap failure when crossed, which is what we want.
defenseclaw_harden_resources() {
  ulimit -S -t 5     2>/dev/null || true
  ulimit -S -v 524288 2>/dev/null || true
  ulimit -S -n 32    2>/dev/null || true
}

# Sanitize PATH and git environment. Goal: any subprocess this hook
# spawns sees a known-good search path (no $HOME/bin first, no agent-
# injected entries) and a git that ignores user / system config.
defenseclaw_harden_env() {
  # Per-hook ephemeral HOME so any tool that stores state under $HOME
  # (gh, gcloud, openssl rand state, etc.) writes to a sandbox the
  # hook tears down on exit. Fall back to the gateway data dir if
  # mktemp is unavailable.
  if command -v mktemp >/dev/null 2>&1; then
    DEFENSECLAW_HOOK_HOME="$(mktemp -d -t defenseclaw-hook.XXXXXXXX 2>/dev/null || true)"
  fi
  if [ -z "${DEFENSECLAW_HOOK_HOME:-}" ]; then
    DEFENSECLAW_HOOK_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/hook-tmp.$$"
    mkdir -p "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
  fi
  export HOME="$DEFENSECLAW_HOOK_HOME"
  trap '_defenseclaw_hook_cleanup' EXIT

  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
        GIT_CONFIG GIT_NAMESPACE GIT_OPTIONAL_LOCKS \
        GIT_TRACE GIT_TRACE_PACKET GIT_TRACE_PACK_ACCESS \
        GIT_SSH GIT_SSH_COMMAND

  # Lock down PATH — keep only the standard system bins where curl /
  # jq / sed / tail / cat / mktemp must live. Operators (and tests)
  # that need a custom path must set DEFENSECLAW_HOOK_PATH explicitly;
  # the variable is sticky across the script so any subsequent
  # subprocess inherits it. Setting it to an empty string disables
  # the override and falls back to the locked-down default.
  if [ -n "${DEFENSECLAW_HOOK_PATH:-}" ]; then
    export PATH="$DEFENSECLAW_HOOK_PATH"
  else
    export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  fi

  # Keep the locale predictable so jq output / sed regex behavior
  # don't shift under the agent's locale.
  export LC_ALL=C
  export LANG=C
}

_defenseclaw_hook_cleanup() {
  if [ -n "${DEFENSECLAW_HOOK_HOME:-}" ] && [ -d "${DEFENSECLAW_HOOK_HOME}" ]; then
    case "$DEFENSECLAW_HOOK_HOME" in
      /tmp/*|/var/folders/*|"${DEFENSECLAW_HOME:-/dev/null}"/hook-tmp.*)
        rm -rf -- "$DEFENSECLAW_HOOK_HOME" 2>/dev/null || true
        ;;
    esac
  fi
}

# defenseclaw_validate_path checks that $1 matches the allow-list
# regex for path-like values pulled from agent payloads. Returns 0
# when safe, 1 when rejected. Use for any payload-derived string the
# hook subsequently passes to a subprocess.
defenseclaw_validate_path() {
  local val="$1"
  case "$val" in
    *$'\n'*|*$'\r'*|*$'\0'*) return 1 ;;
  esac
  # Allow-list: alphanumeric, underscore, dot, dash, slash. Reject
  # everything else (including spaces) so a payload can't smuggle
  # shell metacharacters into a downstream command.
  case "$val" in
    *[!A-Za-z0-9_./-]*) return 1 ;;
  esac
  return 0
}

# defenseclaw_resolve_cwd walks $PWD through realpath and refuses if
# the resolved path doesn't exist. Sets DEFENSECLAW_HOOK_CWD on
# success. The Go side enforces that the resolved path lives under
# the gateway data dir for git-touching hooks; the shell side mirrors
# this for hooks that don't go through the Go API.
defenseclaw_resolve_cwd() {
  local resolved
  if command -v realpath >/dev/null 2>&1; then
    resolved="$(realpath -e -- "${PWD:-/}" 2>/dev/null || true)"
  else
    resolved="${PWD:-/}"
  fi
  if [ -z "$resolved" ] || [ ! -d "$resolved" ]; then
    return 1
  fi
  DEFENSECLAW_HOOK_CWD="$resolved"
  export DEFENSECLAW_HOOK_CWD
  return 0
}
