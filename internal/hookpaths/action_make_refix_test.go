// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0996VisibleStdinMakefile(t *testing.T) {
	home, cwd, _ := gap0996Fixture(t)
	safe := "safe:\n\t@true\n"
	protected := "safe:\n\tprintf ok >> ~/.ssh/authorized_keys\n"
	for _, tc := range []struct {
		name, source, command string
		block                 bool
	}{
		{"heredoc safe", safe, "make -f - safe <<'EOF'\n" + safe + "EOF", false},
		{"unquoted heredoc safe", safe, "make -f - safe <<EOF\n" + safe + "EOF", false},
		{"heredoc protected", protected, "make -f - safe <<'EOF'\n" + protected + "EOF", true},
		{"here string safe", "", "make -f - safe <<< 'safe:'", false},
		{"here string protected", "", "make -f - safe <<< 'safe: ; printf ok >> ~/.ssh/authorized_keys'", true},
		{"file input safe", safe, "make -f - safe < safe.mk", false},
		{"file input protected", protected, "make -f - safe < safe.mk", true},
		{"pipe safe", safe, "cat safe.mk | make -f - safe", false},
		{"pipe protected", protected, "cat safe.mk | make -f - safe", true},
		{"printf pipe safe", "", `printf 'safe:\n\t@true\n' | make -f - safe`, false},
		{"echo escape source unknown", "", `echo 'safe:\n\t@true\n' | make -f - safe`, true},
		{"stdin device safe", safe, "make -f /dev/stdin safe < safe.mk", false},
		{"fd zero safe", safe, "make --file=/dev/fd/0 safe < safe.mk", false},
		{"process substitution safe", safe, "make -f <(cat safe.mk) safe", false},
		{"process substitution protected", protected, "make -f <(cat safe.mk) safe", true},
		{"env wrapper safe", safe, "env make -f - safe < safe.mk", false},
		{"nice wrapper safe", safe, "nice -n 5 make -f - safe < safe.mk", false},
		{"shell wrapper safe", safe, "sh -c 'make -f - safe' < safe.mk", false},
		{"env split wrapper safe", safe, "env -S 'make -f - safe' < safe.mk", false},
		{"timeout wrapper protected", protected, "timeout 5 make -f - safe < safe.mk", true},
		{"hidden stdin", safe, "make -f - safe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.source != "" {
				if err := os.WriteFile(filepath.Join(cwd, "safe.mk"), []byte(tc.source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
}

func TestGAP0996OnlySelectedMakeEffects(t *testing.T) {
	home, cwd, _ := gap0996Fixture(t)
	for _, tc := range []struct {
		name, makefile, command string
		block                   bool
	}{
		{"inert assignment", "TARGET := ~/.ssh/authorized_keys\nsafe:\n\t@true\n", "make safe", false},
		{"inert recursive assignment", "TARGET = ~/.ssh/authorized_keys\nsafe:\n\t@true\n", "make safe", false},
		{"unused recursive shell assignment", "TARGET = $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", "make safe", false},
		{"unused conditional shell assignment", "TARGET ?= $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", "make safe", false},
		{"unused recursive append shell", "TARGET = report.txt\nTARGET += $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", "make safe", false},
		{"overridden immediate shell assignment", "TARGET := $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", "make safe TARGET=report.txt", true},
		{"unrelated pattern", "%.key:\n\tprintf ok >> ~/.ssh/authorized_keys\nsafe:\n\t@true\n", "make safe", false},
		{"explicit recipe beats pattern", "%.key:\n\tprintf ok >> ~/.ssh/authorized_keys\ntoken.key:\n\t@true\n", "make token.key", false},
		{"unselected eval rule", "safe:\n\t@true\n", "make --eval='unused: ; printf ok >> ~/.ssh/authorized_keys' safe", false},
		{"unselected eval variable", "safe:\n\t@true\n", "make --eval='TARGET := ~/.ssh/authorized_keys' safe", false},
		{"matching pattern", "%.key:\n\tprintf ok >> ~/.ssh/authorized_keys\n", "make token.key", true},
		{"two matching pattern stems", "%.key: %.prep\n\t@true\na.prep:\n\t@true\nb.prep:\n\tprintf ok >> ~/.ssh/authorized_keys\n", "make a.key b.key", true},
		{"selected variable write", "TARGET := ~/.ssh/authorized_keys\nsafe:\n\tprintf ok >> $(TARGET)\n", "make safe", true},
		{"selected variable as data", "TARGET := ~/.ssh/authorized_keys\nsafe:\n\tprintf '%s\\n' $(TARGET) > report.txt\n", "make safe", false},
		{"selected override write", "safe:\n\tprintf ok >> $(TARGET)\n", "make safe TARGET=~/.ssh/authorized_keys", true},
		{"makefile override wins", "override TARGET := ~/.ssh/authorized_keys\nsafe:\n\tprintf ok >> $(TARGET)\n", "make safe TARGET=report.txt", true},
		{"conditional assignment keeps target", "TARGET := ~/.ssh/authorized_keys\nTARGET ?= report.txt\nsafe:\n\tprintf ok >> $(TARGET)\n", "make safe", true},
		{"append keeps target", "TARGET := ~/.ssh/authorized_keys\nTARGET += extra\nsafe:\n\tprintf ok >> $(TARGET)\n", "make safe", true},
		{"immediate assignment keeps earlier target", "TARGET := ~/.ssh/authorized_keys\nOUT := $(TARGET)\nTARGET := report.txt\nsafe:\n\tprintf ok >> $(OUT)\n", "make safe", true},
		{"simple append keeps earlier target", "OUT := report.txt\nTARGET := ~/.ssh/authorized_keys\nOUT += $(TARGET)\nTARGET := ordinary.txt\nsafe:\n\tcp report.txt $(OUT)\n", "make safe", true},
		{"parse time shell variable", "TARGET := ~/.ssh/authorized_keys\nX := $(shell printf ok >> $(TARGET))\nsafe:\n\t@true\n", "make safe", true},
		{"parse time simple append", "TARGET := report.txt\nTARGET += $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@true\n", "make safe", true},
		{"selected recursive shell assignment", "TARGET = $(shell printf ok >> ~/.ssh/authorized_keys)\nsafe:\n\t@printf '%s\\n' $(TARGET) > report.txt\n", "make safe", true},
		{"parse time eval variable", "TARGET := ~/.ssh/authorized_keys\n$(eval X := $(TARGET))\nsafe:\n\t@true\n", "make safe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(tc.makefile), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
}
