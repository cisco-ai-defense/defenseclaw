// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"testing"
)

// DET111 S4-R3, rel-1-0-10:GAP-1678: ~<login> names the account's passwd home.
// The login matches without case (a directory login resolves so, as the
// ~<login> twin of the hook reads it) and a HOME the call assigns moves ~ and
// ~/ but never ~<login>.
func TestDET111R3LoginTildeIsThePasswdHome(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj", Login: "dcku",
		Env: map[string]string{"HOME": "/home/dcku"}}
	for _, tc := range []struct{ command, want string }{
		{`echo k >> ~dcku/.claude/settings.json`, "/home/dcku/.claude/settings.json"},
		{`echo k >> ~DCKU/.claude/settings.json`, "/home/dcku/.claude/settings.json"},
		{`cp proj/notes.txt ~Dcku/.codex/hooks.json`, "/home/dcku/.codex/hooks.json"},
		{`HOME=/tmp/x; echo k >> ~dcku/.claude/settings.json`, "/home/dcku/.claude/settings.json"},
		{`export HOME=/tmp/x; echo k >> ~dcku/.claude/settings.json`, "/home/dcku/.claude/settings.json"},
		// control: ~/ follows the HOME the call set
		{`export HOME=/tmp/x; echo k >> ~/.claude/settings.json`, "/tmp/x/.claude/settings.json"},
	} {
		res := Extract(Call{Surface: SurfaceShell, Command: tc.command}, o)
		var paths []string
		for _, e := range res.Effects {
			if e.Kind == KindWrite || e.Kind == KindAppend {
				paths = append(paths, e.Target.Path)
			}
		}
		if !slices.Contains(paths, tc.want) {
			t.Errorf("%q: write paths %q, want %q", tc.command, paths, tc.want)
		}
	}
}

func TestDET111R3TildeAccountNames(t *testing.T) {
	got := TildeAccountNames("echo k >> ~bob/.x; cp a ~DCKU/b x=~eve/c dd of=~eve/d '~q/z' \"~r\" ~ ~/a ~+ ~- a~b ~../x ~-x ~u@dom.test/y")
	want := []string{"bob", "DCKU", "eve", "q", "r", "u@dom.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("TildeAccountNames = %q, want %q", got, want)
	}
	if got := TildeAccountNames("no tilde here"); got != nil {
		t.Fatalf("no tilde: %q", got)
	}
}
