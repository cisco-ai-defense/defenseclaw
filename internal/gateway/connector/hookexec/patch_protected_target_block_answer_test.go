// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1007: a patch whose target is itself a protected file reads as changed
// to the hook when it checks the targets again. When the gateway has already
// blocked the call, the hook passes the block (with the rule the gateway
// named) to the agent; the target-changed refusal is the backstop for an
// answer that would let the call run.
func TestPatchOfProtectedTargetKeepsTheGatewayBlockAnswer(t *testing.T) {
	const rule = "persistence.ssh_authorized_keys_command"
	block := `{"action":"block","reason":"` + rule + `","findings":["` + rule + `: patch of the keys file"],` +
		`"hook_output":{"action":"block","message":"DefenseClaw blocked this tool call: ` + rule + `"}}`
	for _, tc := range []struct {
		name, answer, want string
		target             func(home, project string) string
	}{
		{"absolute path, gateway blocks", block, rule, func(home, _ string) string { return filepath.Join(home, ".ssh", "authorized_keys") }},
		{"hard link, gateway blocks", block, rule, func(_, project string) string { return filepath.Join(project, "keys-hard") }},
		{"symlink, gateway blocks", block, rule, func(_, project string) string { return filepath.Join(project, "keys-soft") }},
		{"absolute path, gateway allows", `{"action":"allow"}`, "a patch target changed after DefenseClaw reviewed it",
			func(home, _ string) string { return filepath.Join(home, ".ssh", "authorized_keys") }},
		{"symlink, gateway allows", `{"action":"allow"}`, "a patch target changed after DefenseClaw reviewed it",
			func(_, project string) string { return filepath.Join(project, "keys-soft") }},
		{"ordinary file, gateway blocks", block, rule, func(_, project string) string { return filepath.Join(project, "notes.txt") }},
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
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			for _, file := range []string{keys, filepath.Join(project, "notes.txt")} {
				if err := os.WriteFile(file, []byte("k\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Link(keys, filepath.Join(project, "keys-hard")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(keys, filepath.Join(project, "keys-soft")); err != nil {
				t.Fatal(err)
			}
			patch := "*** Begin Patch\n*** Update File: " + tc.target(home, project) + "\n@@\n k\n+x\n*** End Patch\n"
			stdin, err := json.Marshal(map[string]any{"hook_event_name": "pre_tool_call", "tool_name": "patch",
				"tool_input": map[string]any{"mode": "patch", "patch": patch}, "cwd": project})
			if err != nil {
				t.Fatal(err)
			}
			result := run(t, "hermes", ok(tc.answer), func(o *Options) {
				o.Event = "pre_tool_call"
				o.FailMode = "closed"
				o.ManagedEnterprise = true
				o.Stdin = strings.NewReader(string(stdin))
			})
			message := hermesBlockMessage(t, result.stdout)
			if result.code != 0 || !strings.Contains(message+result.stderr, tc.want) {
				t.Fatalf("code %d, message %q, stderr %q, want a block naming %q", result.code, message, result.stderr, tc.want)
			}
			if tc.want == rule && strings.Contains(message+result.stderr, "patch target changed") {
				t.Fatalf("message %q, stderr %q: the gateway block was replaced by the target-changed refusal", message, result.stderr)
			}
		})
	}
}
