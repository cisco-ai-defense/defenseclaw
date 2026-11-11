// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestClientDecisionReadsASourcedScriptWhateverArgumentsFollowIt: the first
// word after . or source is the script and the words after it are its
// positional parameters, so the client reads the same body with or without
// them. A write the script makes to the keys file is the client decision a
// managed gateway blocks on; the ordinary script carries none
// (rel-1-0-6:GAP-1068).
func TestClientDecisionReadsASourcedScriptWhateverArgumentsFollowIt(t *testing.T) {
	_, home, project := r106KeysHome(t)
	live := filepath.Join(home, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wk.sh": "echo marker >> $HOME/.ssh/authorized_keys\n",
		"ok.sh": "echo ordinary >> report.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, spelling := range []string{filepath.ToSlash(live) + "/%s", "$HOME/live/%s", "~/live/%s", "../live/%s"} {
		for _, command := range []string{". %s", "source %s"} {
			for _, args := range []string{"", " a", " a b", " then stop"} {
				for script, want := range map[string]bool{"wk.sh": true, "ok.sh": false} {
					line := fmt.Sprintf(command, fmt.Sprintf(spelling, script)) + args
					if got := sourcedWriterReachesKeys(t, project, home, line); got != want {
						t.Errorf("%q: reaches the keys file = %t, want %t", line, got, want)
					}
				}
			}
		}
	}
}
