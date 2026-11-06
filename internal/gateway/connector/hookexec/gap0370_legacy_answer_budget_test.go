// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An earlier gateway needs the body to finish before it can deliver its
// ordinary answer. The receipt probe must preserve that answer's budget.
func TestGAP0370LegacyAnswerNearBudget(t *testing.T) {
	shortAnswerBudget(t, 3*time.Second)
	for _, row := range []struct {
		name        string
		healthDelay time.Duration
	}{
		{"prompt health", 0},
		{"delayed health", 400 * time.Millisecond},
	} {
		t.Run(row.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					time.Sleep(row.healthDelay)
					w.WriteHeader(http.StatusOK)
					return
				}
				if _, err := io.ReadAll(r.Body); err != nil {
					return
				}
				time.Sleep(2690 * time.Millisecond)
				_, _ = io.WriteString(w, `{"action":"allow","codex_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}`+"\n")
			}))
			defer server.Close()
			result, elapsed := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
				opts.FailMode = "open"
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"echo ok"}}`)
			})
			if blocked(result) {
				t.Fatalf("ordinary gateway allow became block after %s: code=%d stdout=%q stderr=%q", elapsed, result.code, result.stdout, result.stderr)
			}
		})
	}
}
