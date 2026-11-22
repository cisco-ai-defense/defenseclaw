// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestDET111LinkAliasUsedThroughTheCall (DET111 S1-MECH; the P0 alias rows
// of the gap-regression corpus and the T17 dotfiles owner row): a link TO a
// protected member keeps the effect-link row out of the shadow (Proof.LinkTo)
// only when a later command of the call uses the alias: it reads, copies,
// writes or appends the link's own path. A link that is only made, as a
// dotfiles script does with its own authorized_keys, is not.
func TestDET111LinkAliasUsedThroughTheCall(t *testing.T) {
	o := effects.Options{Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"}
	for _, tc := range []struct {
		cmd  string
		used bool
	}{
		{"ln -s ~/.ssh/authorized_keys s && cp -a s notes.txt && echo k >> notes.txt", true},
		{"ln -s ~/.ssh/authorized_keys s && cp -a -t copy s && echo k >> copy/s", true},
		{"ln ~/.ssh/authorized_keys notes.txt && echo k >> notes.txt", true},
		{`L=/bin/ln; "$L" -sf ~/.ssh/authorized_keys v2.txt; echo dummy-key >> v2.txt`, true},
		{"ln -s ~/.ssh/authorized_keys ~/dotfiles/ssh/authorized_keys", false},
		{"ln -s ~/.ssh/authorized_keys s; echo done", false},
	} {
		r := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Tool: "shell", Command: tc.cmd, Workdir: o.CWD}, o)
		got, sawTarget := false, false
		for i, e := range r.Effects {
			if e.Kind == effects.KindLink && e.LinkTarget && e.Target.Path == "/home/u/.ssh/authorized_keys" {
				sawTarget = true
				got = got || effectLinkAliasUsed(r, i)
			}
		}
		if !sawTarget {
			t.Errorf("%q: no link-target effect on authorized_keys", tc.cmd)
			continue
		}
		if got != tc.used {
			t.Errorf("%q: alias used %v, want %v", tc.cmd, got, tc.used)
		}
	}
}
