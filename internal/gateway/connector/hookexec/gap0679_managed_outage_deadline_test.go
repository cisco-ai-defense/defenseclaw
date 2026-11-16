// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A stopped-service proof can arrive before a host holds the hook inside its
// restart window. The answer at the deadline keeps the administrator's
// outage choice; a different transport failure, strict mode, and a live
// gateway retain their respective answers.
func TestGAP0679ProvenManagedOutageRetainsAdminModeAtDeadline(t *testing.T) {
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	for _, row := range []struct {
		name, mode, command                           string
		strict, stopped, connected, live, wantBlocked bool
	}{
		{"proven stopped, admin open", "open", "echo ready", false, true, false, false, false},
		{"proven stopped, admin closed", "closed", "echo ready", false, true, false, false, true},
		{"proven stopped, strict", "open", "echo ready", true, true, false, false, true},
		{"proven stopped, named target", "open", "cat ~/.ssh/authorized_keys", false, true, false, false, true},
		{"connected retry, admin open", "open", "echo ready", false, true, true, false, true},
		{"unproven transport, admin open", "open", "echo ready", false, false, false, false, true},
		{"live gateway, admin open", "open", "echo ready", false, false, false, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
				if row.live {
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
				}
				if rt.requests == 1 {
					if row.stopped {
						return nil, fakeStoppedSCM()
					}
					return nil, io.EOF
				}
				if row.connected {
					if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
						trace.GotConn(httptrace.GotConnInfo{})
					}
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}}
			result := run(t, "codex", rt, func(opts *Options) {
				managedCodex(opts)
				opts.FailMode = row.mode
				opts.StrictAvailability = row.strict
				opts.ExplainUnenrolledAccount = true
				opts.StartedAt = time.Now()
				opts.FailureLogHome = userLogHome(opts.Home)
				cwd := filepath.Join(opts.Home, "project")
				if err := os.MkdirAll(cwd, 0o700); err != nil {
					t.Fatal(err)
				}
				opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, cwd, row.command))
			})
			if got := blocked(result); got != row.wantBlocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.wantBlocked, result.code, result.stdout, result.stderr)
			}
			if row.stopped && !row.wantBlocked &&
				(!strings.Contains(result.stdout+result.stderr, managedGatewayNotRunningReason) ||
					!strings.Contains(result.stdout+result.stderr, "WARNING hook fail-open")) {
				t.Fatalf("missing stopped-service warning: stdout=%q stderr=%q", result.stdout, result.stderr)
			}
			if row.live && strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
				t.Fatalf("live gateway got no-answer text: stdout=%q stderr=%q", result.stdout, result.stderr)
			}
		})
	}
}
