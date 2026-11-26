// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestDET111LinkEffectsNameTheirEnd (DET111 S1-MECH, GAP-1538): a link has
// two ends, and the decision treats them differently (a link placed at a
// protected file replaces it; a link to it makes an alias the call can write
// through). Each KindLink effect says which end it names: LinkTarget is set
// on the target operand of ln and mklink, and never on the link itself.
func TestDET111LinkEffectsNameTheirEnd(t *testing.T) {
	for _, tc := range []struct {
		name, cmd        string
		o                Options
		target, linkPath string
	}{
		{"ln -s", "ln -s /home/u/.ssh/authorized_keys /home/u/proj/s", Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"},
			"/home/u/.ssh/authorized_keys", "/home/u/proj/s"},
		{"ln hard", "ln /home/u/.ssh/authorized_keys /home/u/proj/notes.txt", Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"},
			"/home/u/.ssh/authorized_keys", "/home/u/proj/notes.txt"},
		{"ln at member", "ln -sf /home/u/dot/authorized_keys /home/u/.ssh/authorized_keys", Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"},
			"/home/u/dot/authorized_keys", "/home/u/.ssh/authorized_keys"},
	} {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: tc.cmd, Workdir: tc.o.CWD}, tc.o)
		var sawTarget, sawLink bool
		for _, e := range r.Effects {
			if e.Kind != KindLink {
				if e.LinkTarget {
					t.Errorf("%s: %s effect on %q marked LinkTarget", tc.name, e.Kind, e.Target.Path)
				}
				continue
			}
			switch e.Target.Path {
			case tc.target:
				sawTarget = true
				if !e.LinkTarget {
					t.Errorf("%s: the link's target %q is not marked LinkTarget\n%s", tc.name, e.Target.Path, fmtRes(r))
				}
			case tc.linkPath:
				sawLink = true
				if e.LinkTarget {
					t.Errorf("%s: the link itself %q is marked LinkTarget\n%s", tc.name, e.Target.Path, fmtRes(r))
				}
			}
		}
		if !sawTarget || !sawLink {
			t.Errorf("%s: link effects target=%v link=%v, want both\n%s", tc.name, sawTarget, sawLink, fmtRes(r))
		}
	}
}
