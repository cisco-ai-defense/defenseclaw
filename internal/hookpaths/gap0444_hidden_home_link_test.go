// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP0444HiddenHomeLinkFromAReadableFolderDefersToTheClient: a managed
// gateway behind ProtectHome cannot read the user's home but can read an
// away folder. A link there of an ordinary name to ~/.ssh/authorized_keys
// matched the write pattern, the link could not be resolved, so it was not
// protected; the walk was complete, so the client's "1" was never read and
// the write was allowed (rel-1-0-10:GAP-0444, probe H3). The match is
// unseen now: the client's answer decides. A link to an ordinary file of
// the home, which the client answers "0", stays allowed, and so does a
// pattern with only ordinary files in the away folder.
func TestGAP0444HiddenHomeLinkFromAReadableFolderDefersToTheClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission fixture")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged walk")
	}
	homes, home, cwd := globFactsFixture(t, false)
	away := t.TempDir()
	for _, dir := range []string{"keys", "plain", "files"} {
		if err := os.MkdirAll(filepath.Join(away, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	testSymlink(t, filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(away, "keys", "n.txt"))
	testSymlink(t, filepath.Join(cwd, "payload"), filepath.Join(away, "plain", "n.txt"))
	if err := os.WriteFile(filepath.Join(away, "files", "n.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		dir, want string
	}{
		{"keys", "protected-target"},
		{"plain", ""},
		{"files", ""},
	}
	for _, row := range rows {
		for _, form := range []string{"echo k >> %s/n*.txt", "cp payload %s/n*.txt", "tee %s/n*.txt < payload"} {
			command := fmt.Sprintf(form, filepath.Join(away, row.dir))
			facts := clientGlobFactsFor(t, command, cwd)
			visible := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts)
			if visible != row.want {
				t.Fatalf("%q with the home visible: %q, want %q", command, visible, row.want)
			}
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			hidden := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts)
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			if hidden != row.want {
				t.Errorf("%q behind a hidden home, away folder readable, client answers %v: %q, want %q (the visible decision)",
					command, facts, hidden, row.want)
			}
		}
	}
}
