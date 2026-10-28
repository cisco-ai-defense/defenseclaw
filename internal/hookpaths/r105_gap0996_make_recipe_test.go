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

// GAP-0996 (farm TST-33903): `make -f - write-key < evil.mk` and
// `cat evil.mk | make -f - write-key` ran a $(HOME)/.ssh/authorized_keys
// recipe in action mode because the makefile came on standard input. A static
// stdin file or a plain cat feeder is read like `-f evil.mk`.
func TestActionMakeStdinMakefileIsRead(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"proj/evil.mk":  "write-key:\n\t@echo marker >> $(HOME)/.ssh/authorized_keys\n",
		"proj/build.mk": "all:\n\t@echo ok > build.log\n",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for command, want := range map[string]string{
		"make -f - write-key < evil.mk":          "protected-target",
		"cat evil.mk | make -f - write-key":      "protected-target",
		"cat < evil.mk | make -f - write-key":    "protected-target",
		"make --file=- write-key < ./evil.mk":    "protected-target",
		"make -f /dev/stdin write-key < evil.mk": "protected-target",
		"cd . && cat evil.mk | make -f -":        "protected-target",
		"make -f - < build.mk":                   "",
		"cat build.mk | make -f -":               "",
		"make -f - < missing.mk":                 "",
		"make test < evil.mk":                    "",
	} {
		if got := ActionCommandDecision(command, cwd, home); got != want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", command, got, want)
		}
	}
}
