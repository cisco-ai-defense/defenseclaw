// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0518WrappedLateAliasAndOrdinaryTwin(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(key, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(cwd, "key-alias")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "notes"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(command string) []byte {
		return []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + mustJSONString(cwd) +
			`,"tool_input":{"command":` + mustJSONString(command) + `}}`)
	}
	for _, row := range []struct {
		name, command string
		ordinary      bool
	}{
		{"direct protected", "bash -c 'cat key-alias'", false},
		{"env protected", "env -i bash -c 'cat key-alias'", false},
		{"env double dash protected", "env -- bash -c 'cat key-alias'", false},
		{"command protected", "command bash -c 'cat key-alias'", false},
		{"command double dash protected", "command -- bash -c 'cat key-alias'", false},
		{"command path protected", "command -p bash -c 'cat key-alias'", false},
		{"nested protected", "env -i command bash -c 'cat key-alias'", false},
		{"env assignment protected", "env FOO=bar bash -c 'cat key-alias'", false},
		{"env unset protected", "env -u FOO bash -c 'cat key-alias'", false},
		{"exec protected", "exec bash -c 'cat key-alias'", false},
		{"env ordinary", "env -i bash -c 'cat notes'", true},
		{"env double dash ordinary", "env -- bash -c 'cat notes'", true},
		{"command ordinary", "command bash -c 'cat notes'", true},
		{"command double dash ordinary", "command -- bash -c 'cat notes'", true},
		{"command path ordinary", "command -p bash -c 'cat notes'", true},
		{"nested ordinary", "env -i command bash -c 'cat notes'", true},
		{"env assignment ordinary", "env FOO=bar bash -c 'cat notes'", true},
		{"env unset ordinary", "env -u FOO bash -c 'cat notes'", true},
		{"exec ordinary", "exec bash -c 'cat notes'", true},
		{"env display ordinary", "env -i", true},
		{"env assignment display ordinary", "env FOO=bar", true},
		{"command empty ordinary", "command", true},
		{"exec empty ordinary", "exec", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := ordinaryNoAnswerPayloadInHome(call(row.command), home)
			t.Logf("command=%q ordinary=%v", row.command, got)
			if got != row.ordinary {
				t.Errorf("late proof=%v, want %v", got, row.ordinary)
			}
		})
	}
}
