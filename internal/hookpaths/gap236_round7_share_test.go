// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGAP236AnsweredShareIdentityGradeIsStable(t *testing.T) {
	for _, delay := range []time.Duration{40 * time.Millisecond, 700 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			project := filepath.Join(root, "project")
			for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			if err := os.WriteFile(keys, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(project, "link")
			if err := os.Link(keys, target); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			fakeNetworkShare(t, root, networkShareAnswerWait, networkShareDeadAfter, func(string) {
				time.Sleep(100 * time.Millisecond)
			})
			oldRead := readPath
			t.Cleanup(func() { readPath = oldRead })
			readPath = func(name string, kind pathReadKind) pathReadResult {
				if name == root || strings.HasPrefix(name, root+string(filepath.Separator)) {
					time.Sleep(delay)
				}
				return oldRead(name, kind)
			}
			if got := ProtectedSSHReach(target, home, NewTargetMemo()); got != GradeNamed {
				t.Fatalf("answered share with %v identity read = %s, want named", delay, got)
			}
		})
	}
}
