// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestClientDecisionReadsASourcedScriptOutsideTheWorkingFolder: the hook
// client, the one reader that opens the user home for a managed gateway, reads
// a script that a source, dot, bash or sh command names wherever it lies:
// .. from the project into the home, a full path or $HOME in the home, a
// full path beside the home, on Linux, macOS and Windows alike. A write it
// makes to the keys file is the client decision a managed gateway blocks on
// (ActionDecisionKey); the ordinary script carries none
// (rel-1-0-9:GAP-1038, GAP-1039).
func TestClientDecisionReadsASourcedScriptOutsideTheWorkingFolder(t *testing.T) {
	_, home, project := r106KeysHome(t)
	shared := filepath.Join(filepath.Dir(home), "shared")
	live := filepath.Join(home, "chain", "live")
	for _, folder := range []string{shared, live} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{
			"wk.sh": "echo marker >> $HOME/.ssh/authorized_keys\n",
			"ok.sh": "echo ordinary >> report.txt\n",
		} {
			if err := os.WriteFile(filepath.Join(folder, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	spellings := []string{
		"../chain/live/%s",
		"../project/../chain/live/%s",
		"../../shared/%s",
		filepath.ToSlash(live) + "/%s",
		filepath.ToSlash(shared) + "/%s",
		"$HOME/chain/live/%s",
		"~/chain/live/%s",
	}
	for _, spelling := range spellings {
		for _, command := range []string{". %s", "source %s", "bash %s", "sh %s", `bash -c ". %s"`, `sh -c "bash %s"`} {
			for script, want := range map[string]bool{"wk.sh": true, "ok.sh": false} {
				line := fmt.Sprintf(command, fmt.Sprintf(spelling, script))
				payload, err := json.Marshal(map[string]any{"session_id": "c1013", "hook_event_name": "PreToolUse",
					"cwd": project, "tool_name": "Bash", "tool_input": map[string]any{"command": line}})
				if err != nil {
					t.Fatal(err)
				}
				targets, ok := Decode(Resolve(payload))
				if !ok {
					t.Fatalf("%q: client header does not decode", line)
				}
				if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != want {
					t.Errorf("%q: client decision = %t, want %t", line, got, want)
				}
			}
		}
	}
}
