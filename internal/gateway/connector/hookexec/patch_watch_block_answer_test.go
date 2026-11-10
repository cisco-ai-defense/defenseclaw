// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A typed Codex apply_patch whose target is a protected key file is
// attested complete, so the hook watches the target. The watch reports that
// target as changed on every reading (it resolves to a protected file), which
// used to replace the gateway's block, with its rule text, by the generic
// "answer DefenseClaw could not use" refusal. A block is final: the user
// reads the gateway's own reason. An allow for the same target, and a
// target swapped to a protected file while the gateway answers allow, are
// still refused by the hook.
func TestTypedPatchBlockAnswerKeepsGatewayRuleText(t *testing.T) {
	const ruleText = "DefenseClaw policy blocked this action (rule persistence.ssh_authorized_keys_command: SSH authorized keys mutation). Do not retry it in another form."
	block := `{"action":"block","codex_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"` +
		ruleText + `"}},"reason":"` + ruleText + `","mode":"action","raw_action":"block","severity":"CRITICAL"}`
	allow := `{"action":"allow"}`
	for _, tc := range []struct {
		name, answer, file string
		wantBlocked        bool
		wantRuleText       bool
	}{
		{"block for the keys file keeps the rule text", block, "keys", true, true},
		{"block for the ssh config keeps the rule text", block, "config", true, true},
		{"allow for the keys file is still refused", allow, "keys", true, false},
		{"allow for an ordinary file runs", allow, "ordinary", false, false},
		{"block for an ordinary file keeps the rule text", block, "ordinary", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			project := filepath.Join(home, "proj")
			for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			paths := map[string]string{
				"keys":     filepath.Join(home, ".ssh", "authorized_keys"),
				"config":   filepath.Join(home, ".ssh", "config"),
				"ordinary": filepath.Join(project, "notes.txt"),
			}
			for _, path := range paths {
				if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			target := paths[tc.file]
			patch := "*** Begin Patch\n*** Add File: " + target + "\n+ssh-ed25519 AAAA x\n*** End Patch\n"
			stdin, err := json.Marshal(map[string]any{"session_id": "s", "turn_id": "t", "hook_event_name": "PreToolUse",
				"cwd": project, "model": "m", "permission_mode": "default", "tool_name": "apply_patch",
				"tool_input": map[string]any{"command": patch}, "tool_use_id": "call_1"})
			if err != nil {
				t.Fatal(err)
			}
			rt := &stubRT{}
			attested := false
			rt.onRequest = func(s *stubRT, req *http.Request) (*http.Response, error) {
				targets, ok := hookpaths.Decode(req.Header.Get(hookpaths.Header))
				attested = ok && targets[hookpaths.PatchCompleteKey] == "1"
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.answer)), Header: make(http.Header)}, nil
			}
			result := run(t, "codex", rt, func(o *Options) {
				o.FailMode = "closed"
				o.ManagedEnterprise = true
				o.Stdin = strings.NewReader(string(stdin))
			})
			if !attested {
				t.Fatal("the hook did not attest the typed patch as complete, so the watch is not armed")
			}
			blocked := strings.Contains(result.stdout, "deny")
			if blocked != tc.wantBlocked {
				t.Fatalf("stdout = %q (code %d), blocked = %v, want %v", result.stdout, result.code, blocked, tc.wantBlocked)
			}
			if got := strings.Contains(result.stdout, "persistence.ssh_authorized_keys_command"); got != tc.wantRuleText {
				t.Fatalf("stdout = %q: names the gateway rule = %v, want %v", result.stdout, got, tc.wantRuleText)
			}
			if tc.wantRuleText && strings.Contains(result.stdout+result.stderr, "could not use") {
				t.Fatalf("the gateway block was replaced by the generic refusal: %q", result.stdout)
			}
		})
	}
}
