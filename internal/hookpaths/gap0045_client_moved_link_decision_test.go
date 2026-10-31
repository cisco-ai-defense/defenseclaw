// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestR106ClientDecisionFollowsMovedDiskLink (rel-1-0-6:GAP-0045): the hook
// client sends the decision a per-user gateway makes on the command
// (ActionDecisionKey), also when only its target scan finds the keys file:
// a project link to it moved to a new name and written through that name.
// A move of a link to an ordinary file, a plain read through the keys link
// and an ordinary write carry no decision.
func TestR106ClientDecisionFollowsMovedDiskLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	_, home, project := r106KeysHome(t)
	if err := os.Symlink("notes.txt", filepath.Join(project, "readlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for command, want := range map[string]bool{
		`mv keylink k2; echo x >> k2`:                               true,
		`ln -s notes.txt docs.md; mv keylink k2; echo x >> k2`:      true,
		`cd ~/project && mv keylink k2; echo x >> k2`:               true,
		`mv keylink k2 && printf y >> k2`:                           true,
		`echo x >> ~/.ssh/authorized_keys`:                          true,
		`mv readlink k2; echo x >> k2`:                              false,
		`mv notes.txt n2; echo x >> n2`:                             false,
		`grep x keylink`:                                            false,
		`echo hi > notes.txt`:                                       false,
		`echo done >> notes.txt # see ~/.ssh/authorized_keys later`: false,
	} {
		payload, err := json.Marshal(map[string]any{"session_id": "gap0045", "hook_event_name": "PreToolUse",
			"cwd": project, "tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatalf("%q: client header does not decode", command)
		}
		if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != want {
			t.Errorf("%q: client decision = %t, want %t", command, got, want)
		}
	}
}
