// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"testing"
)

func TestMalformedGatewayHookRefusalIsClosedEvenInPerUserOpenMode(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge} {
		result := run(t, "claudecode", &stubRT{
			status: status,
			body:   `{"error":"malformed hook event","reason":"` + MalformedHookPayloadReason + `"}`,
		}, func(o *Options) {
			o.FailMode = "open"
			o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
		})
		if !blocked(result) {
			t.Errorf("HTTP %d malformed payload was allowed in open mode: code=%d stdout=%q stderr=%q",
				status, result.code, result.stdout, result.stderr)
		}
	}
}

func TestPerUserOpenCannotAllowCompletedGatewayErrorStatus(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict, http.StatusInternalServerError} {
		result := run(t, "codex", &stubRT{status: status, body: `{"error":"gateway refused request"}`},
			func(o *Options) { o.FailMode = "open" })
		if !blocked(result) {
			t.Errorf("HTTP %d was allowed in per-user open mode: code=%d stdout=%q stderr=%q",
				status, result.code, result.stdout, result.stderr)
		}
	}
}

// A duplicated event key can make the hook's local JSON decoder see only the
// later PostToolUse spelling. A gateway parse rejection must still be a native
// failure, never the empty allow that the original driven hook produced.
func TestAmbiguousClaudeEventRefusalStaysClosedWhenLastKeyIsPostToolUse(t *testing.T) {
	payload := `{"hook_event_name":"PreToolUse","hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys"}}`
	result := run(t, "claudecode", &stubRT{
		status: http.StatusBadRequest,
		body:   `{"error":"malformed hook event: ambiguous_json","reason":"` + MalformedHookPayloadReason + `"}`,
	}, func(o *Options) {
		o.Event = "" // Claude Code's command has no out-of-band event binding.
		o.FailMode = "open"
		o.Stdin = strings.NewReader(payload)
	})
	if result.code != blockExit || string(result.rt.gotBody) != payload {
		t.Fatalf("ambiguous event was not refused: code=%d stdout=%q stderr=%q body=%q",
			result.code, result.stdout, result.stderr, result.rt.gotBody)
	}
}
