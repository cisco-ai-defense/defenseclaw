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
	"strings"
)

// shellHookForeignGuardBlock is inserted into the standalone Hermes shell
// hook after the socket transport block and before the gateway request.
// Hermes runs every shell hook registered for an event in order and lets a
// later pre_tool_call hook rewrite the tool call, so a hook a user adds after
// DefenseClaw's could change a command DefenseClaw already checked. Before a
// tool call, and at session start (where the gateway records the hooks the
// Hermes process started with), the block asks the administrator-owned hook
// binary for the foreign-hook guard's decision (hook --foreign-hook-check,
// as the standalone Amp and OpenCode plugins do). The check runs with the
// agent's own HOME, which the hardening above replaced, and without the
// hardening's address-space limit: the check is a Go program, and the Go
// runtime cannot start under that limit (Linux enforces it, macOS does not).
// The payload goes in as a here-string, so a check that answers without
// reading it (a policy that turns the guard off) cannot fail the pipeline.
// Only an explicit {"deny":false} allows; any other answer, including none,
// blocks the tool call with the Hermes block object the check rendered, or,
// when the check gave no decision, with a fixed one that names why; that
// block is also sent to the gateway's session route, which writes the audit
// row the check would have. A session-start event cannot be blocked and
// continues to the gateway.
const shellHookForeignGuardBlock = `# Standalone foreign-hook guard. Hermes runs every shell hook registered for
# an event, and a hook that runs after this one can rewrite the tool call
# DefenseClaw checked. Before a tool call, and at session start, the
# administrator-owned hook binary checks this account's Hermes hooks against
# the organization's policy; while an unapproved hook is present, and for
# the rest of a Hermes process that started with one, tool calls are
# blocked. Anything but an explicit allow blocks. The check is a Go program,
# which cannot start under the address-space limit set above.
DEFENSECLAW_FOREIGN_GUARD=@GUARD@
DEFENSECLAW_GUARD_EVENT="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.hook_event_name // empty' 2>/dev/null)" || DEFENSECLAW_GUARD_EVENT=""
case "$DEFENSECLAW_GUARD_EVENT" in
  pre_tool_call|on_session_start|"")
    DEFENSECLAW_GUARD_STATUS=0
    DEFENSECLAW_GUARD_RESULT="$(ulimit -S -v "$(ulimit -H -v)" 2>/dev/null || :; HOME="${DEFENSECLAW_GUARD_AGENT_HOME:-}" "$DEFENSECLAW_FOREIGN_GUARD" hook --connector hermes --foreign-hook-check 2>/dev/null <<<"$PAYLOAD")" || { DEFENSECLAW_GUARD_STATUS=$?; DEFENSECLAW_GUARD_RESULT=""; }
    case "$DEFENSECLAW_GUARD_RESULT" in
      '{"deny":false}') ;;
      '{"deny":false,"warnings":'*)
        echo "defenseclaw: warning: an unapproved Hermes hook is configured for this account; your organization reports it but allows it to run" >&2
        ;;
      *)
        if [ "$DEFENSECLAW_GUARD_EVENT" != "on_session_start" ]; then
          DEFENSECLAW_GUARD_REASON="$(printf '%s' "$DEFENSECLAW_GUARD_RESULT" | _dc_jq -r '.reason // empty' 2>/dev/null)" || DEFENSECLAW_GUARD_REASON=""
          DEFENSECLAW_GUARD_OUTPUT="$(printf '%s' "$DEFENSECLAW_GUARD_RESULT" | _dc_jq -c '.hook_output // empty' 2>/dev/null)" || DEFENSECLAW_GUARD_OUTPUT=""
          case "$DEFENSECLAW_GUARD_OUTPUT" in
            '{"action":"block","message":"'*'"}') ;;
            *)
              if [ "$DEFENSECLAW_GUARD_STATUS" != 0 ]; then
                DEFENSECLAW_GUARD_CAUSE="the check exited with status $DEFENSECLAW_GUARD_STATUS without an answer"
              elif [ -z "$DEFENSECLAW_GUARD_RESULT" ]; then
                DEFENSECLAW_GUARD_CAUSE="the check gave no answer"
              else
                DEFENSECLAW_GUARD_CAUSE="the check gave an answer DefenseClaw could not read"
              fi
              DEFENSECLAW_GUARD_OUTPUT='{"action":"block","message":"DefenseClaw blocked this tool call: it could not check the Hermes hooks of this account ('"$DEFENSECLAW_GUARD_CAUSE"'). Try again; if this continues, contact your administrator. (enterprise_foreign_hook_check_failed)"}'
              if [ -z "$DEFENSECLAW_GUARD_REASON" ]; then
                # The check never reached the gateway, so this block has no
                # audit row yet: send it to the session route, which writes one.
                DEFENSECLAW_GUARD_REASON="enterprise_foreign_hook_check_failed: DefenseClaw could not check the Hermes hooks of this account: $DEFENSECLAW_GUARD_CAUSE"
                DEFENSECLAW_GUARD_SESSION="$(printf '%s' "$PAYLOAD" | _dc_jq -r '.session_id // empty' 2>/dev/null)" || DEFENSECLAW_GUARD_SESSION=""
                curl -s -o /dev/null -X POST "http://${API_ADDR}/api/v1/foreign-hook-session/hermes" \
                  -H "Content-Type: application/json" \
                  -H "X-DefenseClaw-Client: hermes-hook/1.0" \
                  --connect-timeout 2 --max-time 5 --unix-socket "${DEFENSECLAW_HOOK_SOCKET}" \
                  -d '{"key":{"Connector":"hermes","Session":"'"$(defenseclaw_json_escape "$DEFENSECLAW_GUARD_SESSION")"'"},"session_start":false,"decision":{"deny":true,"reason":"'"$(defenseclaw_json_escape "$DEFENSECLAW_GUARD_REASON")"'"}}' \
                  2>/dev/null || :
              fi
              ;;
          esac
          DEFENSECLAW_GUARD_REASON="${DEFENSECLAW_GUARD_REASON:-enterprise_foreign_hook_check_failed}"
          defenseclaw_log_hook_failure hermes hermes-hook "$DEFENSECLAW_GUARD_REASON" policy closed
          echo "defenseclaw: blocking hermes tool: $DEFENSECLAW_GUARD_REASON" >&2
          printf '%s\n' "$DEFENSECLAW_GUARD_OUTPUT"
          exit 0
        fi
        ;;
    esac
    ;;
esac

`

// shellHookForeignGuard renders shellHookForeignGuardBlock for the
// administrator-owned hook binary, emitted as one single-quoted shell word.
func shellHookForeignGuard(binary string) string {
	return strings.Replace(shellHookForeignGuardBlock, "@GUARD@", shellSingleQuote(binary), 1)
}

// shellHookForeignGuardBinary is the administrator-owned hook binary a
// connector's shell hook runs for the standalone foreign-hook guard, or ""
// when the hook runs none. Only the Hermes hook of a Linux or macOS
// standalone install with a hook socket runs it (Hermes has no managed
// hook source, so its hook stays the per-user hermes-hook.sh); every other
// hook and install, including Windows, per-user and Secure Client, renders
// unchanged.
func shellHookForeignGuardBinary(opts SetupOpts, connectorName string) string {
	if runtime.GOOS == "windows" || normalizeConnectorName(connectorName) != "hermes" {
		return ""
	}
	if socket, _ := managedPluginHookSocket(opts); socket == "" {
		return ""
	}
	binary := managedPluginForeignHookGuard(opts)
	if binary == "" || strings.ContainsAny(binary, "\x00\r\n") {
		return ""
	}
	return binary
}

// HookForeignGuardDrifted reports whether the hooks recorded by lock were
// rendered with a different foreign-hook guard than opts now selects: a
// Hermes hook installed before its standalone hook ran the guard, or for
// another hook binary. Unix verification does not compare hook bytes, so,
// like HookTransportDrifted, this is the repair signal that makes the
// guardian re-render such a hook.
func HookForeignGuardDrifted(lock HookContractLockEntry, opts SetupOpts) bool {
	have := ""
	if posture := lock.RegistrationPosture; posture != nil {
		have = posture.ForeignHookGuard
	}
	return have != shellHookForeignGuardBinary(opts, lock.Connector)
}

// ReplaceTopLevelYAMLField returns original with its top-level field set to
// value and every byte outside that field kept, the way Setup rewrites the
// hooks mapping of a Hermes config.yaml. label names the document in errors.
// The standalone foreign-hook cleanup uses it to remove a user's unapproved
// Hermes hooks without reformatting the rest of the file.
func ReplaceTopLevelYAMLField(label string, original []byte, field string, value any) ([]byte, error) {
	return replaceTopLevelYAMLFieldPreservingOtherBytes(label, original, field, value)
}
