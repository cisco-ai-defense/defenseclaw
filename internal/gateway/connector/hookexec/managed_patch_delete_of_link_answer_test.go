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

// On a managed endpoint a typed Codex apply_patch Delete File of a project
// link takes the answer of the gateway: an allow runs the call, whatever the
// link reaches (an ordinary file or a credential file), as the delete removes
// the link and not its target. A name below a link into the home is the file
// itself: the protected keys file stays refused when the answer allows, and
// the gateway's block of a credential file keeps its rule.
func TestManagedTypedPatchDeleteOfLinkTakesTheGatewayAnswer(t *testing.T) {
	const refused = "a patch target changed after DefenseClaw reviewed it"
	const rule = "path.credential_file"
	block := `{"action":"block","reason":"` + rule + `","findings":["` + rule + `: delete of a credential file"],` +
		`"hook_output":{"action":"block","message":"DefenseClaw blocked this tool call: ` + rule + `"}}`
	allow := `{"action":"allow"}`
	for _, tc := range []struct {
		name, verb, target, answer string
		want                       string // "" runs the call
	}{
		{"link to an ordinary file", "Delete", "lnk-notes", allow, ""},
		{"link to the credential file", "Delete", "lnk-netrc", allow, ""},
		{"link to the credential file, absolute", "Delete", "@PROJECT@/lnk-netrc", allow, ""},
		{"ordinary file", "Delete", "notes.txt", allow, ""},
		{"keys name below a link into the home, gateway allows", "Delete", "lnk-home/.ssh/authorized_keys", allow, refused},
		{"credential name below a link into the home, gateway blocks", "Delete", "lnk-home/.netrc", block, rule},
		{"keys file itself, gateway allows", "Delete", "@HOME@/.ssh/authorized_keys", allow, refused},
		{"delete of a link to the keys file", "Delete", "lnk-ssh", allow, ""},
		{"update through a link to the keys file, gateway allows", "Update", "lnk-ssh", allow, refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			project := filepath.Join(home, "proj")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{filepath.Join(home, ".netrc"), filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "notes.txt")} {
				if err := os.WriteFile(file, []byte("k\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for name, target := range map[string]string{
				"lnk-netrc": filepath.Join(home, ".netrc"),
				"lnk-notes": filepath.Join(project, "notes.txt"),
				"lnk-home":  home,
				"lnk-ssh":   filepath.Join(home, ".ssh", "authorized_keys"),
			} {
				if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
					t.Fatal(err)
				}
			}
			target := strings.NewReplacer("@HOME@", home, "@PROJECT@", project).Replace(tc.target)
			patch := "*** Begin Patch\n*** " + tc.verb + " File: " + target + "\n"
			if tc.verb == "Update" {
				patch += "@@\n k\n+x\n"
			}
			patch += "*** End Patch\n"
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
			if tc.want != "" {
				if !strings.Contains(text, tc.want) {
					t.Fatalf("code %d, stdout %q, stderr %q, want a refusal naming %q", result.code, result.stdout, result.stderr, tc.want)
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
