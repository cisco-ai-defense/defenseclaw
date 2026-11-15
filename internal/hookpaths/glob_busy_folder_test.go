// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A folder of more than actionGlobMaxNames names (/tmp, a build cache) is read
// whole: a pattern in it that names no key is an ordinary glob, a pattern that
// selects an alias of the key still decides (rel-1-0-10:GAP-0018).
func TestGlobInBusyFolderIsExpanded(t *testing.T) {
	_, home, cwd := globFactsFixture(t, false)
	busy := filepath.Join(cwd, "busy")
	if err := os.MkdirAll(busy, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < actionGlobMaxNames+904; i++ {
		if err := os.WriteFile(filepath.Join(busy, fmt.Sprintf("f%05d.dat", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		`cp payload busy/zz9*.log`,
		`rm -f busy/f0001*.dat`,
		`echo busy/x*.log; pgrep -fa go`,
		`cd busy && cp payload ./q*.txt`,
	} {
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("%s: decision = %q, want allow", command, got)
		}
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(key, filepath.Join(busy, "zzkey.lnk")); err != nil {
		t.Fatal(err)
	}
	// The alias sorts anywhere in the folder's order; the pattern finds it.
	for _, command := range []string{`cp payload busy/zz*.lnk`, `cd busy && cp payload zzkey.l*`} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: decision = %q, want protected-target", command, got)
		}
	}
}
