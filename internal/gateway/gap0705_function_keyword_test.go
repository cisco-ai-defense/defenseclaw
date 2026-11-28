// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0705FunctionKeywordIsItsPOSIXDefinition is substrate-1:GAP-0705 (the
// function keyword rows): a definition spelled with the function keyword
// (function f { ...; }, function f() { ...; }) is judged as the same
// definition spelled f() { ...; }, in the default and strict packs. The POSIX
// parse read the keyword form as invalid syntax, so its facts held no path
// and the call was allowed where the f() form alerts or blocks.
func TestGAP0705FunctionKeywordIsItsPOSIXDefinition(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// The gateway takes the account home from os.UserHomeDir, which reads
	// USERPROFILE on a Windows host.
	t.Setenv("USERPROFILE", home)
	posix := []string{
		`f() { cd /tmp; "$@"; }; f cd && rm ~/.aws/credentials`,
		`f() { rm ~/.aws/credentials; }; f`,
		`f() { cp /tmp/x ~/.aws/credentials; }; f`,
		`f() { cd /tmp; "$@"; }; f cd && echo x > ~/.npmrc`,
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0705f-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, cmd := range posix {
			want := verdict(cmd)
			if want == "allow" {
				t.Fatalf("%s: %q = allow, want it judged", pack, cmd)
			}
			for _, keyword := range []string{"function f {", "function f() {"} {
				spelled := strings.Replace(cmd, "f() {", keyword, 1)
				if got := verdict(spelled); got != want {
					t.Errorf("%s: %q = %s, want %s (its f() form)", pack, spelled, got, want)
				}
			}
		}
		for _, control := range []string{`function f { ls; }; f`, `function f { echo hi > notes.txt; }; f`} {
			if got := verdict(control); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, control, got)
			}
		}
	}
}
