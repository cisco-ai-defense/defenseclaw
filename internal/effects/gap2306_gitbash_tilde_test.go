// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// TestGAP2306GitBashUnexpandedTildeIsTheHome (rel-1-0-10:GAP-2306): on a
// Windows host the Git Bash (POSIX) spelling of a leading ~ that the word walk
// did not expand (an option argument or a sed w file) is placed in the active
// home, as placePOSIX places it on a POSIX host and as the walk expands a
// leading ~ word on the same host. Before, it was a dynamic expansion with no
// known target, so a named write to a home member through it reached no set.
// cmd keeps ~ a literal folder (GAP-1191) and a guessed dialect keeps no known
// target.
func TestGAP2306GitBashUnexpandedTildeIsTheHome(t *testing.T) {
	member := strings.Join([]string{".codex", "config.toml"}, "/")
	for _, home := range []string{`C:\Users\alice`, "C:/Users/alice"} {
		o := Options{Flavor: FlavorWindows, Dialect: DialectPOSIX, Home: home, CWD: `C:\work`}
		want, ok, reason := placePath(home+"/"+member, o)
		if !ok {
			t.Fatalf("home %q: abs spelling not placed: %s", home, reason)
		}
		for _, sp := range []string{"~/" + member, `~\` + strings.ReplaceAll(member, "/", `\`)} {
			got, ok, reason := placePath(sp, o)
			if !ok || got != want {
				t.Errorf("home %q Git Bash %q: %q ok=%v (%s), want %q", home, sp, got, ok, reason, want)
			}
		}
		if got, ok, reason := placePath("~", o); !ok || !strings.EqualFold(got, strings.ReplaceAll(home, "/", `\`)) {
			t.Errorf("home %q Git Bash bare ~: %q ok=%v (%s)", home, got, ok, reason)
		}
	}
	o := Options{Flavor: FlavorWindows, Dialect: DialectPOSIX, Home: "/home/alice", CWD: `C:\work`}
	if _, ok, reason := placePath("~/"+member, o); ok || reason != ReasonDynamicExpansion {
		t.Errorf("Git Bash ~ under a non-Windows home: ok=%v (%s), want dynamic", ok, reason)
	}
	o = Options{Flavor: FlavorWindows, Home: `C:\Users\alice`, CWD: `C:\work`}
	if _, ok, reason := placePath("~/"+member, o); ok || reason != ReasonDynamicExpansion {
		t.Errorf("guessed dialect ~: ok=%v (%s), want dynamic", ok, reason)
	}
	o.Dialect = DialectCMD
	if got, ok, _ := placePath("~/"+member, o); !ok || !strings.HasPrefix(strings.ToLower(got), `c:\work\~\`) {
		t.Errorf("cmd ~ is a literal folder: %q ok=%v", got, ok)
	}
}
