// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"runtime"
	"text/template"
)

// managedShellGuardGOOS selects the hosts whose managed shell hooks carry the
// prologue below. macOS runs the managed hooks as per-user bash scripts; other
// hosts keep their existing scripts unchanged.
var managedShellGuardGOOS = runtime.GOOS

func managedShellGuardEnabled(managed bool) bool {
	return managed && managedShellGuardGOOS == "darwin"
}

// managedHookBlockSentence is the only text a managed shell hook writes to the
// agent's stderr when it fails closed without a policy reason. Claude Code and
// Codex need a non-empty stderr on exit 2 to treat the exit as a block.
const managedHookBlockSentence = "DefenseClaw blocked this action because its hook failed closed."

// managedHookPrologueTemplate is rendered into every managed macOS connector
// shell hook right after DEFENSECLAW_HOME is fixed, before _hardening.sh is
// sourced:
//
//   - Tuning variables from the agent's environment never apply to a managed
//     hook.
//   - An unexpected shell failure (a failed command under set -e, a missing or
//     unreadable helper, an unbound variable, any exit status other than 0 or
//     2) follows the configured fail mode: an explicit exit code, or Cursor's
//     JSON. Bash's own exit status 1 is a non-blocking error for the agents, so
//     it must never decide the outcome. Bash 3.2 reports status 0 to the EXIT
//     trap after a fatal shell error, so every deliberate exit goes through an
//     exit function that marks it; any other way out is unexpected.
//   - The agent's stderr is saved on descriptor 6 and the shell's stderr goes
//     to the per-user log, so diagnostics never reach the agent. The only text
//     the agent sees on stderr is the one block reason the protocol requires
//     on exit 2.
//
// Every command here is a builtin or an absolute path: the agent controls
// PATH until _hardening.sh locks it down.
const managedHookPrologueTemplate = `{{define "managed-prologue"}}
unset DEFENSECLAW_HOOK_MAX_BODY DEFENSECLAW_HOOK_HOME DEFENSECLAW_FAIL_MODE \
  DEFENSECLAW_CONNECTOR DEFENSECLAW_HOOK_PATH DEFENSECLAW_HOOK_PATH_TRUSTED
_DC_MANAGED_FAIL_MODE="{{.FailMode}}"
_DC_BLOCK_REASON_SENT=0
_DC_EXIT_INTENDED=0
exec 6>&2
exit() {
  local _dc_status=$?
  _DC_EXIT_INTENDED=1
  builtin exit "${1:-$_dc_status}"
}
_dc_managed_block_reason() {
  if [ "$_DC_BLOCK_REASON_SENT" != "1" ]; then
    _DC_BLOCK_REASON_SENT=1
    printf '%s\n' "$1" >&6 2>/dev/null || true
  fi
}
_dc_managed_cleanup() {
  if declare -F _defenseclaw_hook_cleanup >/dev/null 2>&1; then
    _defenseclaw_hook_cleanup >/dev/null 2>&1 || true
  fi
}
_dc_managed_fail() {
  set +e
  trap - ERR EXIT
  local outcome=fail_open
  [ "$_DC_MANAGED_FAIL_MODE" = "closed" ] && outcome=fail_closed
  printf 'defenseclaw: {{.ConnectorName}} hook unexpected failure (%s); fail mode %s\n' \
    "$1" "$_DC_MANAGED_FAIL_MODE" >&2 2>/dev/null
  if declare -F defenseclaw_log_hook_failure >/dev/null 2>&1; then
    defenseclaw_log_hook_failure "{{.ConnectorName}}" "${DEFENSECLAW_HOOK_NAME:-{{.ConnectorName}}-hook}" \
      "unexpected hook failure: $1" internal "$_DC_MANAGED_FAIL_MODE" "$outcome" >/dev/null 2>&1
  fi
  _dc_managed_cleanup
  if [ "$_DC_MANAGED_FAIL_MODE" = "closed" ]; then
{{- if eq .ConnectorName "cursor"}}
    printf '%s\n' '{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}'
{{- else}}
    _dc_managed_block_reason "` + managedHookBlockSentence + `"
{{- end}}
    exit 2
  fi
{{- if eq .ConnectorName "cursor"}}
  printf '%s\n' '{"continue":true,"permission":"allow"}'
{{- end}}
  exit 0
}
_dc_managed_on_exit() {
  local rc=$?
  set +e
  trap - ERR EXIT
  if [ "$_DC_EXIT_INTENDED" != "1" ]; then
    _dc_managed_fail "shell error, status $rc"
  fi
  case "$rc" in
    0)
      _dc_managed_cleanup
      exit 0
      ;;
    2)
{{- if ne .ConnectorName "cursor"}}
      _dc_managed_block_reason "` + managedHookBlockSentence + `"
{{- end}}
      _dc_managed_cleanup
      exit 2
      ;;
  esac
  _dc_managed_fail "exit status $rc"
}
trap '_dc_managed_fail "status $? at line $LINENO"' ERR
trap '_dc_managed_on_exit' EXIT
_dc_diag_dir="${DEFENSECLAW_HOME}/logs"
_dc_diag_log="${_dc_diag_dir}/hook-diagnostics.log"
if [ -d "$_dc_diag_dir" ] || /bin/mkdir -p -m 700 "$_dc_diag_dir" 2>/dev/null; then
  if [ -f "$_dc_diag_log" ] && [ -x /usr/bin/wc ]; then
    _dc_diag_size="$(/usr/bin/wc -c < "$_dc_diag_log" 2>/dev/null || true)"
    _dc_diag_size="${_dc_diag_size//[!0-9]/}"
    if [ "${_dc_diag_size:-0}" -gt 1048576 ]; then
      /bin/mv -f "$_dc_diag_log" "${_dc_diag_log}.1" 2>/dev/null || true
    fi
  fi
fi
if { : >>"$_dc_diag_log"; } 2>/dev/null; then
  exec 2>>"$_dc_diag_log"
else
  exec 2>/dev/null
fi
unset _dc_diag_dir _dc_diag_log _dc_diag_size
{{- end}}`

// shellExitGuardTemplate is the fail-mode exit guard of the Claude Code, Codex
// and Cursor shell hooks that are not Secure Client renders: the per-user
// hooks, where it replaces the boot trap, and the standalone managed hooks:
// right after DEFENSECLAW_HOME is fixed (GAP-1734), and for Codex from the
// first line of the hook (GAP-1755); and of the OpenShell sandbox Codex hook
// (GAP-1769). defenseclaw_harden_env
// keeps _dc_hook_on_exit as the EXIT trap, so the guard holds to the end.
//
//   - Every deliberate exit goes through the exit function, which marks it.
//     Bash 3.2 (macOS /bin/bash) ends a script with status 0 after an unbound
//     variable or a "." of a missing file, so an unmarked exit is a failure
//     whatever its status.
//   - A deliberate exit 0 or 2 keeps its outcome. Codex reads a non-zero
//     UserPromptSubmit status as a hook failure and submits the prompt, so
//     a Codex block (exit 2) is answered as Codex reads one, on stdout with
//     exit 0 (codex_closed_answer), in the per-user, the standalone managed
//     and the OpenShell sandbox Codex hooks alike (GAP-0949, GAP-1755,
//     GAP-1769). A sandbox hook's guard is closed, as its FAIL_MODE is.
//   - Any other status, or an unmarked exit, is an unexpected failure: exit
//     status 1 is a non-blocking error for the agents, so it never decides
//     the outcome. It writes one hook-failures.jsonl record, as the Secure
//     Client macOS prologue does (GAP-1757). In fail mode closed (per-user:
//     defenseclaw_boot_fails_closed) the hook blocks the call. Fail mode open
//     keeps the exit status, as the boot trap did, except an unmarked exit
//     2, which would block: it answers 0, as the Secure Client macOS
//     prologue does (GAP-1756).
//
// The Secure Client renders keep their own bytes: macOS uses the managed
// prologue above, and the other Secure Client renders are pinned
// (TestSecureClientShellRendersKeepPrePerfBytes).
const shellExitGuardTemplate = `{{define "shell-exit-guard"}}_DC_EXIT_INTENDED=0
exit() {
  local _dc_status=$?
  _DC_EXIT_INTENDED=1
  builtin exit "${1:-$_dc_status}"
}
{{if .Managed}}_DC_HOOK_FAIL_MODE="{{if .Sandbox}}closed{{else}}{{.FailMode}}{{end}}"
{{end}}_dc_hook_on_exit() {
  local rc=$? _dc_mode=closed
  set +e
  trap - EXIT
  if [ "$_DC_EXIT_INTENDED" = "1" ]; then
    case "$rc" in
      0|2)
        if declare -F _defenseclaw_hook_cleanup >/dev/null 2>&1; then
          _defenseclaw_hook_cleanup >/dev/null 2>&1 || true
        fi
        [ "$rc" -eq 0 ] && builtin exit 0
        {{if eq .ConnectorName "codex"}}codex_closed_answer{{else}}builtin exit 2{{end}}
        ;;
    esac
  elif [ "$rc" -eq 0 ]; then
    rc=1
  fi
  {{if .Managed}}[ "$_DC_HOOK_FAIL_MODE" = "closed" ]{{else}}defenseclaw_boot_fails_closed{{end}} || _dc_mode=open
  if declare -F defenseclaw_log_hook_failure >/dev/null 2>&1; then
    defenseclaw_log_hook_failure {{.ConnectorName}} "${DEFENSECLAW_HOOK_NAME:-{{.ConnectorName}}-hook}" \
      "unexpected hook failure: exit status $rc" internal "$_dc_mode" "fail_$_dc_mode" >/dev/null 2>&1 || true
  fi
  if declare -F _defenseclaw_hook_cleanup >/dev/null 2>&1; then
    _defenseclaw_hook_cleanup >/dev/null 2>&1 || true
  fi
  if [ "$_dc_mode" = "open" ]; then
    [ "$_DC_EXIT_INTENDED" = "1" ] || [ "$rc" -ne 2 ] || rc=0
    builtin exit "$rc"
  fi
{{- if eq .ConnectorName "cursor"}}
  printf '%s\n' '{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}'
  builtin exit 2
{{- else if eq .ConnectorName "codex"}}
  codex_closed_answer
{{- else}}
  printf '%s (unexpected exit status %s)\n' "` + managedHookBlockSentence + `" "$rc" >&2
  builtin exit 2
{{- end}}
}
trap '_dc_hook_on_exit' EXIT
{{- end}}`

// parseHookTemplate parses a hook template together with the shared managed
// prologue and the shell exit guard so every connector template can include
// them by name.
func parseHookTemplate(tmpl string) (*template.Template, error) {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	if _, err := t.New("managed-prologue-definitions").Parse(managedHookPrologueTemplate); err != nil {
		return nil, err
	}
	if _, err := t.New("shell-exit-guard-definitions").Parse(shellExitGuardTemplate); err != nil {
		return nil, err
	}
	return t, nil
}
