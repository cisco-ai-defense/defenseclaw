// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// rel-1-0-10:GAP-1553: a Windows path refused only for an 8.3 short
// component is Known once the host expands it (SSH~1 is .ssh), and stays
// unknown when the component does not expand. The native readings are
// TestGAP1553ShortNameTiersNative (internal/gateway, Windows).
func TestDET111R3WindowsShortNameSettles(t *testing.T) {
	const home = `C:\Users\alice`
	long := map[string]string{
		home + `\SSH~1\authorized_keys`: home + `\.ssh\authorized_keys`,
		home + `\.ssh\AUTHOR~1`:         home + `\.ssh\authorized_keys`,
		home + `\PROJEC~1\notes.txt`:    home + `\project\notes.txt`,
	}
	expand := func(p string) (string, bool) { l, ok := long[p]; return l, ok }
	for _, tc := range []struct {
		command, want string
		exact         bool
	}{
		{`Add-Content SSH~1\authorized_keys x`, home + `\.ssh\authorized_keys`, true},
		{`cd .ssh; Add-Content AUTHOR~1 x`, home + `\.ssh\authorized_keys`, true},
		{`Add-Content PROJEC~1\notes.txt x`, home + `\project\notes.txt`, false},
		{`Add-Content SSH~2\authorized_keys x`, "", false},
	} {
		opts := effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: home, CWD: home}
		facts := Project(effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.command}, opts),
			Env{Home: home, Flavor: effects.FlavorWindows, Resolve: func(p string) (string, bool) { return p, true }, ShortPath: expand})
		var got string
		exact := false
		for _, f := range facts {
			if f.GetKind() != string(effects.KindWrite) && f.GetKind() != string(effects.KindAppend) {
				continue
			}
			if f.GetTargetState() == string(effects.TargetStateKnown) {
				got = f.GetTarget().GetPath()
			}
			for _, m := range f.GetTarget().GetProtected() {
				if m.GetSet() == SetSSHAuthorizedKeys && m.GetState() == string(gradeKnown) && m.GetReason() == "exact" {
					exact = true
				}
			}
		}
		if got != tc.want || exact != tc.exact {
			t.Errorf("%q: known target %q exact keys=%v, want %q exact=%v", tc.command, got, exact, tc.want, tc.exact)
		}
	}
}
