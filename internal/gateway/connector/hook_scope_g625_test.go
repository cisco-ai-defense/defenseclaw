// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGAP0625ScopedKnownExecutables(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	root := t.TempDir()
	script := filepath.Join(root, "hooks", "hermes-hook.sh")
	managed := shellWord(filepath.Join(root, "hooks", "hookX"))
	forms := []struct {
		name    string
		command string
		want    bool
	}{
		{"subshell keeps parent managed", "HOOK=MANAGED; (HOOK=/bin/true); \"$HOOK\"", true},
		{"subshell keeps parent user", "HOOK=/bin/true; (HOOK=MANAGED); \"$HOOK\"", false},
		{"function declaration keeps parent managed", "HOOK=MANAGED; f() { HOOK=/bin/true; }; \"$HOOK\"", true},
		{"function declaration keeps parent user", "HOOK=/bin/true; f() { HOOK=MANAGED; }; \"$HOOK\"", false},
		{"called function updates parent", "HOOK=MANAGED; f() { HOOK=/bin/true; }; f; \"$HOOK\"", false},
		{"called function executes managed", "f() { MANAGED; }; f", true},
		{"local function value keeps parent managed", "HOOK=MANAGED; f() { local HOOK=/bin/true; }; f; \"$HOOK\"", true},
		{"local function value keeps parent user", "HOOK=/bin/true; f() { local HOOK=MANAGED; }; f; \"$HOOK\"", false},
		{"local function executes managed", "HOOK=/bin/true; f() { local HOOK=MANAGED; \"$HOOK\"; }; f", true},
		{"declare in function keeps parent user", "HOOK=/bin/true; f() { declare HOOK=MANAGED; }; f; \"$HOOK\"", false},
		{"global declaration updates parent", "HOOK=/bin/true; f() { declare -g HOOK=MANAGED; }; f; \"$HOOK\"", true},
		{"command substitution keeps parent managed", "HOOK=MANAGED; VALUE=$(HOOK=/bin/true); \"$HOOK\"", true},
		{"command substitution keeps parent user", "HOOK=/bin/true; VALUE=$(HOOK=MANAGED); \"$HOOK\"", false},
		{"pipeline keeps parent managed", "HOOK=MANAGED; HOOK=/bin/true | /bin/cat; \"$HOOK\"", true},
		{"pipeline keeps parent user", "HOOK=/bin/true; HOOK=MANAGED | /bin/cat; \"$HOOK\"", false},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			command := strings.ReplaceAll(form.command, "MANAGED", managed)
			if got := hookCommandClaimsHookDir(command, script); got != form.want {
				t.Errorf("claim=%v, want=%v", got, form.want)
			}
		})
	}
}

func TestGAP0625ShellCommandTextOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	root := t.TempDir()
	script := filepath.Join(root, "hooks", "hermes-hook.sh")
	managed := shellWord(filepath.Join(root, "hooks", "hookX"))
	forms := []struct {
		name    string
		command string
		want    bool
	}{
		{"login short flag", "bash -lc MANAGED", true},
		{"profile long flag", "bash --noprofile -c MANAGED", true},
		{"environment wrapper", "env -i bash -lc MANAGED", true},
		{"login long flag", "bash --login -c MANAGED", true},
		{"sh login flag", "sh -lc MANAGED", true},
		{"dash login flag", "dash -lc MANAGED", true},
		{"login script", "bash -l MANAGED", true},
		{"login long script", "bash --login MANAGED", true},
		{"user command with managed argument", "bash -lc '/bin/printf %s MANAGED'", false},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			command := strings.ReplaceAll(form.command, "MANAGED", managed)
			if got := hookCommandClaimsHookDir(command, script); got != form.want {
				t.Errorf("claim=%v, want=%v", got, form.want)
			}
		})
	}
}
