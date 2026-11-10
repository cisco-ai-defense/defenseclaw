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

// A typed Codex apply_patch whose target steps up from a directory that does
// not exist (proj/../.ssh/authorized_keys from the project is the ordinary
// ~/proj/.ssh/authorized_keys) takes the answer of the gateway: an allow runs
// the call, with no refusal that the patch target changed, and a block keeps
// the rule the gateway named. The spellings that lead to the real keys file
// stay refused when the gateway allows, and stay blocked with their rule when
// it blocks.
func TestTypedPatchStepUpThroughMissingDirectoryTakesTheGatewayAnswer(t *testing.T) {
	const rule = "persistence.ssh_authorized_keys_command"
	block := `{"action":"block","reason":"` + rule + `","findings":["` + rule + `: patch of the keys file"],` +
		`"hook_output":{"action":"block","message":"DefenseClaw blocked this tool call: ` + rule + `"}}`
	for _, tc := range []struct {
		name, target, answer string
		blocked              bool
		want                 string
	}{
		{"ordinary keys name, gateway allows", "proj/../.ssh/authorized_keys", `{"action":"allow"}`, false, ""},
		{"ordinary config name, gateway allows", "proj/../.ssh/config", `{"action":"allow"}`, false, ""},
		{"project file, gateway allows", "proj/../notes.txt", `{"action":"allow"}`, false, ""},
		{"ordinary keys name, gateway blocks", "proj/../.ssh/authorized_keys", block, true, rule},
		{"real keys file by step up, gateway blocks", "../.ssh/authorized_keys", block, true, rule},
		{"real keys file by step up, gateway allows", "../.ssh/authorized_keys", `{"action":"allow"}`, true,
			"a patch target changed after DefenseClaw reviewed it"},
		{"real keys file by absolute path, gateway allows", "@HOME@/.ssh/authorized_keys", `{"action":"allow"}`, true,
			"a patch target changed after DefenseClaw reviewed it"},
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
			for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "notes.txt")} {
				if err := os.WriteFile(file, []byte("k\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			target := strings.Replace(tc.target, "@HOME@", home, 1)
			patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n k\n+x\n*** End Patch\n"
			stdin, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
				"tool_input": map[string]any{"command": patch}, "cwd": project})
			if err != nil {
				t.Fatal(err)
			}
			result := run(t, "codex", ok(tc.answer), func(o *Options) {
				o.FailMode = "closed"
				o.ManagedEnterprise = true
				o.Stdin = strings.NewReader(string(stdin))
			})
			text := result.stdout + result.stderr
			if tc.blocked {
				if !strings.Contains(text, tc.want) {
					t.Fatalf("code %d, stdout %q, stderr %q, want a block naming %q", result.code, result.stdout, result.stderr, tc.want)
				}
				return
			}
			for _, refusal := range []string{"deny", "could not use", "patch target changed", "blocked"} {
				if strings.Contains(text, refusal) {
					t.Fatalf("code %d, stdout %q, stderr %q: the gateway allow was refused (%q)", result.code, result.stdout, result.stderr, refusal)
				}
			}
			if result.code != 0 {
				t.Fatalf("code %d, stdout %q, stderr %q, want the call to run", result.code, result.stdout, result.stderr)
			}
		})
	}
}
