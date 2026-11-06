// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0053: on a managed computer `defenseclaw status` shows the
// standard user their own protection state from the hook socket, instead of
// refusing; --json keeps deployment_mode managed_enterprise, which the
// quickstart's stop rule reads.
func TestLauncherStatusShowsOwnState(t *testing.T) {
	previousSocket, previousFetch := ownProfileExplainSocket, ownStatusFetch
	t.Cleanup(func() { ownProfileExplainSocket, ownStatusFetch = previousSocket, previousFetch })
	ownProfileExplainSocket = func() string { return "/run/defenseclaw/hook.sock" }
	answer := `{"own":true,"managed":true,"managed_by":"your organization","account":{"uid":"5001","name":"alice"},` +
		`"claude_code":{"protected":true},"cowork":{"protected":true,"state":"protected: Cowork runs the Claude Code hooks your organization manages","last_event_at":"2026-11-04T09:00:00Z"}}`
	fetched := 0
	ownStatusFetch = func(_ context.Context, socket string) (int, []byte, error) {
		fetched++
		if socket != "/run/defenseclaw/hook.sock" {
			t.Fatalf("socket %q", socket)
		}
		return http.StatusOK, []byte(answer), nil
	}
	run := func(args ...string) (int, string, string) {
		var ran []string
		root := launcherTestRoot(&ran)
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		code := executeLauncherInTest(t, root, args)
		if len(ran) != 0 {
			t.Fatalf("%v ran the gateway's %v", args, ran)
		}
		return code, stdout.String(), stderr.String()
	}
	code, stdout, stderr := run("status")
	if code != 0 || !strings.Contains(stdout, "This computer is managed by your organization.") ||
		!strings.Contains(stdout, "alice (uid 5001)") || !strings.Contains(stdout, "Claude Code   protected") ||
		!strings.Contains(stdout, "Cowork        protected") || strings.Contains(stdout, "none from you yet") {
		t.Fatalf("status = %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	code, stdout, _ = run("status", "--json")
	var out map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" || out["own"] != true {
		t.Fatalf("status --json = %d %s", code, stdout)
	}
	if code, _, stderr := run("status", "--user", "bob"); code == 0 || fetched != 2 {
		t.Fatalf("status --user is not a launcher flag: exit %d %s", code, stderr)
	}

	// A gateway that refuses or does not answer is an error, and the JSON
	// still says the computer is managed.
	ownStatusFetch = func(context.Context, string) (int, []byte, error) {
		return http.StatusForbidden, []byte(`{"error":"peer_unverified"}`), nil
	}
	code, stdout, _ = run("status", "--json")
	out = nil
	if code == 0 || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" || out["error"] == nil {
		t.Fatalf("refused status --json = %d %s", code, stdout)
	}
	ownProfileExplainSocket = func() string { return "" }
	if code, _, stderr := run("status"); code == 0 || !strings.Contains(stderr, "hook socket is not available") {
		t.Fatalf("status without a hook socket = %d %s", code, stderr)
	}
}
