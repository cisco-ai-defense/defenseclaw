// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"testing"
)

// TestEffectsPwdFunctionRedefinitionAfterUse (GAP-2082, T23 review P3-12): a
// call of a user function, a source or an eval after a static pwd function
// definition may define pwd again, so $(pwd) after it is unknown, not the word
// of the earlier definition. Red at 08e285b2a6: the read target was the Known
// /tmp path (bash reads the home key). The GAP-1043 static order keeps its
// Known target, and so does a call of the pwd function itself.
func TestEffectsPwdFunctionRedefinitionAfterUse(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj",
		Env: map[string]string{"HOME": "/home/dcku"}}
	reads := func(command string) []string {
		var paths []string
		for _, e := range Extract(Call{Surface: SurfaceShell, Command: command}, o).Effects {
			if e.Kind == KindRead && e.TargetState == TargetStateKnown {
				paths = append(paths, e.Target.Path)
			}
		}
		return paths
	}
	const stale = "/tmp/.ssh/id_rsa"
	for _, command := range []string{
		`f() { pwd() { echo /home/dcku; }; }; pwd() { echo /tmp; }; f; cat "$(pwd)/.ssh/id_rsa"`,
		`pwd() { echo /tmp; }; g() { :; }; g; cat "$(pwd)/.ssh/id_rsa"`,
		`pwd() { echo /tmp; }; source ./env.sh; cat "$(pwd)/.ssh/id_rsa"`,
		`pwd() { echo /tmp; }; . ./env.sh; cat "$(pwd)/.ssh/id_rsa"`,
		`pwd() { echo /tmp; }; eval "$SETUP"; cat "$(pwd)/.ssh/id_rsa"`,
	} {
		if got := reads(command); slices.Contains(got, stale) {
			t.Errorf("%q: known read of %s from a pwd definition the call may have replaced (reads %q)", command, stale, got)
		}
	}
	for _, tc := range []struct{ command, want string }{
		{`pwd() { echo /tmp; }; cat "$(pwd)/.ssh/id_rsa"`, stale},
		{`pwd() { echo /tmp; }; pwd; cat "$(pwd)/.ssh/id_rsa"`, stale},
		{`pwd() { echo /a; }; eval "pwd() { echo /tmp; }"; cat "$(pwd)/.ssh/id_rsa"`, stale},
	} {
		if got := reads(tc.command); !slices.Contains(got, tc.want) {
			t.Errorf("%q: known reads %q, want %q", tc.command, got, tc.want)
		}
	}
}
