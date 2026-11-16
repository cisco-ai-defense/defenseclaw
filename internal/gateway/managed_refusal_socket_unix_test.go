//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0411, GAP-0470: the managed CLI's refusal reports travel the real hook
// socket stack (kernel peer credentials, peer authorization, CSRF gate) and
// land as one attributed audit row each. The earlier tests posted to a bare
// server, or set the CSRF header themselves, so a reporter without the
// header passed them while every live report was refused with 403.
func TestManagedCommandRefusalReachesTheAuditStoreThroughTheHookSocket(t *testing.T) {
	socket, _, store := startTestHookSocketServer(t, hookSocketTestServer{})

	// The CSRF gate is what refused the live reports: a POST without the
	// client header never reaches the handler.
	status, _, err := hookSocketPost(hookSocketClient(socket, 10*time.Second), managed.CommandRefusalPath,
		[]byte(`{"action":"action","target":"uninstall","details":"command=uninstall"}`))
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("report without the client header: status %d err %v, want 403", status, err)
	}

	commands := []struct{ command, reason string }{
		{"guardrail disable", ""},
		{"uninstall", ""},
		{"enterprise linux ensure", "not_root"},
		{"enterprise linux tetragon pause", "not_root"},
	}
	for _, tc := range commands {
		status, err := managed.ReportCommandRefusal(t.Context(), socket, tc.command, tc.reason)
		if err != nil || status != http.StatusNoContent {
			t.Fatalf("report %q: status %d err %v, want 204", tc.command, status, err)
		}
	}
	events, err := store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	actor := fmt.Sprintf("actor=uid:%d", os.Getuid())
	for _, tc := range commands {
		reason := tc.reason
		if reason == "" {
			reason = "managed_device"
		}
		var rows []string
		for _, event := range events {
			if event.Action == "action" && event.Target == tc.command {
				rows = append(rows, event.Details)
			}
		}
		if len(rows) != 1 || !strings.Contains(rows[0], "outcome=refused") || !strings.Contains(rows[0], "reason="+reason) ||
			!strings.Contains(rows[0], actor) || !strings.Contains(rows[0], "command="+tc.command) {
			t.Fatalf("%q rows = %q, want one refused row by %s with reason=%s", tc.command, rows, actor, reason)
		}
	}

	// A burst from one account is limited per account; the reporter sees
	// 429, never a changed refusal.
	limited := 0
	for range managedRefusalBurst {
		status, err := managed.ReportCommandRefusal(t.Context(), socket, "uninstall", "")
		if err != nil {
			t.Fatal(err)
		}
		if status == http.StatusTooManyRequests {
			limited++
		} else if status != http.StatusNoContent {
			t.Fatalf("burst report status %d", status)
		}
	}
	if limited == 0 {
		t.Fatal("one account posted more than the burst without a 429")
	}
}
