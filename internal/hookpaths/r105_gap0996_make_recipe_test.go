// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0996: the Makefile proof read a selected recipe as written, so a
// recipe that names the key file through make's $(HOME) variable, or runs
// make again on another file ($(MAKE) -f other.mk), hid the protected write.
// $(HOME) is the environment's home and a recursive make is read the same
// way, to a bounded depth.
func TestActionMakeRecipeVariablesAndRecursion(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"writer.mk":     "write-key:\n\techo k >> $(HOME)/.ssh/authorized_keys\n",
		"outer.mk":      "all:\n\t$(MAKE) -f ../inner.mk\n",
		"inner.mk":      "all:\n\techo k >> ~/.ssh/authorized_keys\n",
		"ordinary.mk":   "all:\n\t$(MAKE) -f ../build.mk\n",
		"build.mk":      "all:\n\techo ok >> $(HOME)/proj/build.log\n",
		"proj/Makefile": "test:\n\techo ok\n",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for command, want := range map[string]string{
		"make -f ../writer.mk write-key": "protected-target",
		"make -f ../outer.mk":            "protected-target",
		"make -f ../ordinary.mk":         "",
		"make test":                      "",
	} {
		if got := ActionCommandDecision(command, cwd, home); got != want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", command, got, want)
		}
	}
}
