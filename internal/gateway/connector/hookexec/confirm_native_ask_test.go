// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"testing"
)

// GAP-0983: a 2xx answer with action confirm and no native object reached
// Claude Code and Codex as no decision at all (exit 0, empty stdout), so the
// call ran as if the gateway had allowed it, during an install too. A
// confirmation is the gateway's ask, and those agents ask only through the
// object: the native hook now refuses such an answer closed in every fail
// mode. Every other native tool hook form answers it during an install as
// it does in fail mode closed (the class), and a confirmation that carries
// its ask is still forwarded (control).
func TestNativeHookRefusesAConfirmWithoutItsNativeAsk(t *testing.T) {
	answer := func(t *testing.T, form nativeHookForm, body, failMode string, install bool) runResult {
		rt := &stubRT{status: http.StatusOK, body: body}
		payload := `{"hook_event_name":"` + form.event + `","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
		return run(t, form.connector, rt, func(opts *Options) {
			if install {
				mkdirInstallLock(t, opts.Home)
			}
			opts.Event = form.event
			opts.HookSurface = form.surface
			opts.FailMode = failMode
			opts.Stdin = strings.NewReader(payload)
		})
	}
	for _, body := range []string{
		`{"action":"confirm","reason":"sure?"}`,
		`{"action":"confirm","reason":"sure?","claude_code_output":null,"codex_output":null,"hook_output":null}`,
	} {
		for _, form := range nativeToolHookForms {
			t.Run(form.String()+"/"+body, func(t *testing.T) {
				closed := answer(t, form, body, "closed", false)
				installing := answer(t, form, body, "open", true)
				if got, want := nativeAnswerBlocks(installing.code, installing.stdout), nativeAnswerBlocks(closed.code, closed.stdout); got != want {
					t.Fatalf("during an install: exit %d stdout %q stderr %q blocks=%v, want blocks=%v as in fail mode closed",
						installing.code, installing.stdout, installing.stderr, got, want)
				}
				if form.connector != "claudecode" && form.connector != "codex" {
					return
				}
				for _, result := range []runResult{closed, installing, answer(t, form, body, "open", false)} {
					if !nativeAnswerBlocks(result.code, result.stdout) || !strings.Contains(result.stderr, missingNativeAskReason) {
						t.Fatalf("exit %d stdout %q stderr %q, want the confirmation refused closed (%s)",
							result.code, result.stdout, result.stderr, missingNativeAskReason)
					}
				}
			})
		}
	}
	for _, form := range []nativeHookForm{{"claudecode", "PreToolUse", ""}, {"codex", "PreToolUse", ""}} {
		t.Run(form.String()+"/confirm with its ask", func(t *testing.T) {
			ask := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"sure?"}}`
			result := answer(t, form, `{"action":"confirm","claude_code_output":`+ask+`,"codex_output":`+ask+`}`, "open", false)
			if result.code != 0 || strings.TrimSpace(result.stdout) != ask {
				t.Fatalf("exit %d stdout %q stderr %q, want the ask forwarded", result.code, result.stdout, result.stderr)
			}
		})
	}
}
