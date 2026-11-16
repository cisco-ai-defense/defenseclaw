// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0641LateWrapperProtectedAndOrdinaryTwins(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(key, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(cwd, "key-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "notes"), []byte("notes"), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(command string) []byte {
		qcwd, _ := json.Marshal(cwd)
		qcommand, _ := json.Marshal(command)
		return []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + string(qcwd) + `,"tool_input":{"command":` + string(qcommand) + `}}`)
	}
	for _, row := range []struct {
		name, command string
		ordinary      bool
	}{
		{"env protected control", "env -i bash -c 'cat key-alias'", false},
		{"nice protected", "nice -n 5 bash -c 'cat key-alias'", false},
		{"nice direct protected", "nice -n 5 bash -c 'cat ~/.ssh/authorized_keys'", false},
		{"timeout protected", "timeout 5 bash -c 'cat key-alias'", false},
		{"timeout known home protected", "timeout 5 bash -c 'cat \"$HOME/.ssh/authorized_keys\"'", false},
		{"nohup protected", "nohup bash -c 'cat key-alias'", false},
		{"env nice protected", "env -i nice -n 5 bash -c 'cat key-alias'", false},
		{"env split string protected", `env -S 'bash -c "cat key-alias"'`, false},
		{"nice ordinary", "nice -n 5 bash -c 'cat notes'", true},
		{"command display ordinary", "command -v sh", true},
		{"compound command display ordinary", "command -v sh; echo ready", true},
		{"env split ordinary", "env -S bash -c 'cat notes'", true},
		{"env split string ordinary", `env -S 'bash -c "cat notes"'`, true},
		{"env home ordinary", "env HOME=/tmp bash -c 'cat notes'", true},
		{"env home named", "env HOME=" + ssh + ` bash -c 'cat "$HOME/authorized_keys"'`, false},
		{"exec argv ordinary", "exec -a label bash -c 'cat notes'", true},
		{"exec argv named", "exec -a " + filepath.Join(cwd, "key-alias") + " bash -c 'cat notes'", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := ordinaryNoAnswerPayloadInHome(call(row.command), home)
			if got != row.ordinary {
				t.Errorf("ordinary late proof=%v, want %v for %q", got, row.ordinary, row.command)
			}
		})
	}
}
