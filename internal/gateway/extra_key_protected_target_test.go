// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0729 GAP-0734: a native file-write call is the write of every
// file it names in its reviewed key, whatever the file is. In a key outside
// the schema of the tool the rule is by class: DefenseClaw's own state blocks
// in every profile under any key at any depth, in every spelling of the local
// volume; any other protected file (the vendors' managed settings, an SSH
// key file) counts only under a key that names a place (path, file, target,
// destination, output, to, ...), and is text under metadata, commentary and
// the like. The same keys holding an ordinary file stay allowed.
func TestExtraKeyProtectedTargetsByClass(t *testing.T) {
	const winHome = `C:\Users\vn`
	posixHome, posixProject := dynamicWordParityProject(t)
	keys := filepath.Join(posixHome, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("# key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	type target struct {
		name, home, cwd, project, file, rule string
		self                                 bool
	}
	const state = "tamper.detector_state_write"
	win := func(name, file string, self bool) target {
		return target{name, winHome, winHome + `\proj`, winHome + `\proj\notes.txt`, file, state, self}
	}
	targets := []target{
		{"ssh-keys", posixHome, posixProject, posixProject + "/notes.txt", keys, "ssh_authorized_keys", false},
		win("state-share", `\\localhost\C$\Users\vn\.defenseclaw\config.yaml`, true),
		win("state-slashes", `//localhost/C$/Users/vn/.defenseclaw/config.yaml`, true),
		win("state-unc", `//?/UNC/localhost/C$/Users/vn/.defenseclaw/config.yaml`, true),
		win("managed-share", `\\localhost\C$\Program Files\ClaudeCode\managed-settings.json`, false),
		win("managed-slashes", `//localhost/C$/Program Files/ClaudeCode/managed-settings.json`, false),
		win("managed-loopback", `//127.0.0.1/C$/Program Files/ClaudeCode/managed-settings.json`, false),
		win("managed-unc", `//?/UNC/localhost/C$/Program Files/ClaudeCode/managed-settings.json`, false),
	}
	// shapes place the file in the call; place is true when a key that names
	// a place holds it.
	type shape struct {
		name  string
		place bool
		extra func(file string) map[string]any
	}
	shapes := []shape{
		{"f", false, func(f string) map[string]any { return map[string]any{"f": f} }},
		{"metadata", false, func(f string) map[string]any { return map[string]any{"metadata": f} }},
		{"commentary", false, func(f string) map[string]any { return map[string]any{"commentary": f} }},
		{"meta.note", false, func(f string) map[string]any { return map[string]any{"meta": map[string]any{"note": f}} }},
		{"payload[].note", false, func(f string) map[string]any {
			return map[string]any{"payload": []any{map[string]any{"note": f}}}
		}},
		{"target_alias", true, func(f string) map[string]any { return map[string]any{"target_alias": f} }},
		{"destination", true, func(f string) map[string]any { return map[string]any{"destination": f} }},
		{"meta.output", true, func(f string) map[string]any { return map[string]any{"meta": map[string]any{"output": f}} }},
		{"destinations[].note", true, func(f string) map[string]any {
			return map[string]any{"destinations": []any{map[string]any{"note": f}}}
		}},
	}
	for _, tc := range targets {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				direct := map[string]any{"file_path": tc.file, "content": "x"}
				if _, got := postFileToolCell(t, tc.home, tc.cwd, "Write", direct, managed, pack); !strings.HasPrefix(got, fileToolBlockPrefix) || !strings.Contains(got, tc.rule) {
					t.Errorf("%s direct managed=%t pack=%q: %.200s, want a %s block", tc.name, managed, pack, got, tc.rule)
				}
				for _, sh := range shapes {
					input := map[string]any{"file_path": tc.project, "content": "x"}
					for key, value := range sh.extra(tc.file) {
						input[key] = value
					}
					_, got := postFileToolCell(t, tc.home, tc.cwd, "Write", input, managed, pack)
					blocked := strings.HasPrefix(got, fileToolBlockPrefix) && strings.Contains(got, tc.rule)
					switch want := tc.self || sh.place; {
					case want && !blocked:
						t.Errorf("%s %s managed=%t pack=%q: %.200s, want a %s block", tc.name, sh.name, managed, pack, got, tc.rule)
					case !want && strings.HasPrefix(got, fileToolBlockPrefix):
						t.Errorf("%s %s managed=%t pack=%q: %.200s, want allow (text under a key that names no place)", tc.name, sh.name, managed, pack, got)
					}
					ordinary := map[string]any{"file_path": tc.project, "content": "x"}
					for key, value := range sh.extra(tc.project) {
						ordinary[key] = value
					}
					if _, got := postFileToolCell(t, tc.home, tc.cwd, "Write", ordinary, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
						t.Errorf("%s %s managed=%t pack=%q holding an ordinary file: %.200s, want allow", tc.name, sh.name, managed, pack, got)
					}
				}
			}
		}
	}
}
