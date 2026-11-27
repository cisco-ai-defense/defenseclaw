// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestGAP1078WorldWritableChmodAfterSplitGap pins that a world-writable
// chmod after a call the split cannot flatten keeps the verdict of its plain
// spelling. A world-writable mode is CMD-CHMOD-WORLD on any file, so the
// own-command twin and its neutral both find it; before the fix such a twin
// added nothing and the split spelling was a clean allow where the plain one
// alerts in default and blocks in strict (substrate-1:GAP-1078, SV-LIVE6).
// The calls are only judged, never run, from the account home folder. A
// chmod +x of a git hook after the same split stays as its plain spelling.
func TestGAP1078WorldWritableChmodAfterSplitGap(t *testing.T) {
	installCorrelationHMACForTest(t)
	// The home folder of the account that runs the test. A folder below a
	// temporary one is a fixture folder of a project, where every file is
	// the project's (isDefiniteFixturePath), and both spellings allow.
	account, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home := filepath.ToSlash(account.HomeDir)
	if info, err := os.Stat(home); err != nil || !info.IsDir() || !isRecognizedHomeRoot(strings.ToLower(home)) {
		t.Skipf("the account home %q is not a recognized home root", home)
	}
	cases := []struct {
		name, split, plain string
		world              bool
	}{
		{"cd-gap credentials 777", `f(){ cd /tmp; "$@"; }; f cd && chmod 777 .aws/credentials`, "chmod 777 .aws/credentials", true},
		{"cd-gap netrc 666", `f(){ cd /tmp && "$@"; }; f cd && chmod 666 .netrc`, "chmod 666 .netrc", true},
		{"call-gap home file 777", `f(){ "$@"; }; f make && chmod 777 x.txt`, "chmod 777 x.txt", true},
		{"call-gap git hook +x", `f(){ "$@"; }; f make && chmod +x .git/hooks/pre-commit`, "chmod +x .git/hooks/pre-commit", false},
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(command string) (string, []string) {
			n++
			ev := claudeToolEvent("PreToolUse", "gap1078-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = home
			got := callAgentHookForTest(t, handler, ev)
			return got.Action, got.RuleIDs
		}
		for _, tc := range cases {
			plain, plainRules := decide(tc.plain)
			split, splitRules := decide(tc.split)
			if tc.world {
				if plain == "allow" || !slices.Contains(plainRules, "CMD-CHMOD-WORLD") {
					t.Fatalf("%s %s: plain spelling = %s %v, want a CMD-CHMOD-WORLD finding", pack, tc.name, plain, plainRules)
				}
				if !slices.Contains(splitRules, "CMD-CHMOD-WORLD") {
					t.Errorf("%s %s: split spelling rules = %v, want CMD-CHMOD-WORLD", pack, tc.name, splitRules)
				}
			}
			if split != plain {
				t.Errorf("%s %s: split spelling = %s %v, plain spelling = %s %v", pack, tc.name, split, splitRules, plain, plainRules)
			}
		}
	}
}
