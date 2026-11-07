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
// protected file it names, in its reviewed key or in a key outside the
// schema of the tool, whatever the key is called and in whatever spelling of
// the local volume. The same key holding an ordinary file stays allowed.
func TestG235bExtraKeyProtectedTargets(t *testing.T) {
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
	}
	const state = "tamper.detector_state_write"
	win := func(name, file string) target {
		return target{name, winHome, winHome + `\proj`, winHome + `\proj\notes.txt`, file, state}
	}
	targets := []target{
		{"ssh-keys", posixHome, posixProject, posixProject + "/notes.txt", keys, "ssh_authorized_keys"},
		win("state-share", `\\localhost\C$\Users\vn\.defenseclaw\config.yaml`),
		win("state-slashes", `//localhost/C$/Users/vn/.defenseclaw/config.yaml`),
		win("state-unc", `//?/UNC/localhost/C$/Users/vn/.defenseclaw/config.yaml`),
		win("managed-share", `\\localhost\C$\Program Files\ClaudeCode\managed-settings.json`),
		win("managed-slashes", `//localhost/C$/Program Files/ClaudeCode/managed-settings.json`),
		win("managed-loopback", `//127.0.0.1/C$/Program Files/ClaudeCode/managed-settings.json`),
		win("managed-unc", `//?/UNC/localhost/C$/Program Files/ClaudeCode/managed-settings.json`),
	}
	for _, tc := range targets {
		for _, key := range []string{"", "f", "target_alias", "destination"} {
			for _, managed := range []bool{false, true} {
				for _, pack := range []string{"", "strict", "permissive"} {
					input := map[string]any{"file_path": tc.file, "content": "x"}
					if key != "" {
						input["file_path"] = tc.project
						input[key] = tc.file
					}
					if _, got := postFileToolCell(t, tc.home, tc.cwd, "Write", input, managed, pack); !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, tc.rule) {
						t.Errorf("%s key=%q managed=%t pack=%q: %.200s, want a %s block", tc.name, key, managed, pack, got, tc.rule)
					}
					if key == "" {
						continue
					}
					ordinary := map[string]any{"file_path": tc.project, "content": "x", key: tc.project}
					if _, got := postFileToolCell(t, tc.home, tc.cwd, "Write", ordinary, managed, pack); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("%s key=%q managed=%t pack=%q holding an ordinary file: %.200s, want allow", tc.name, key, managed, pack, got)
					}
				}
			}
		}
	}
}
