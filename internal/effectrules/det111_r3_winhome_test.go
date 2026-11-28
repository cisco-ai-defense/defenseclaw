// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// DET111 S4-R3: a Windows hook call's home spellings (C:\Users\<login>\...,
// %USERPROFILE%\..., $env:USERPROFILE\..., ~\..., Git Bash ~/ and /c/...)
// place under the home as known paths, and the classifier grades them by
// name: an ordinary file is no member of any set, a protected file is known.
// The link resolver reads only paths of the host's own flavor; a Windows path
// on a POSIX host has no link to follow (it graded every such target unknown
// in every set, TRAIN T1 FPR family A). Red at a64bfdb931 (the disk resolver
// cannot read a Windows path, so every plain row is unknown).
func TestDET111R3WindowsHomeSpellingsAreKnownPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX host reading; the Windows host reads its own disk")
	}
	const home = `C:\Users\alice`
	env := map[string]string{"USERPROFILE": home, "HOME": home} // the lane vouches the hook account's home
	o := func(d effects.Dialect) effects.Options {
		return effects.Options{Flavor: effects.FlavorWindows, Dialect: d, Home: home, CWD: home + `\proj`, Env: env}
	}
	ps, cmd, gb := o(effects.DialectPowerShell), o(effects.DialectCMD), o(effects.DialectPOSIX)
	for _, tc := range []struct {
		name, command string
		opts          effects.Options
		protected     bool
	}{
		{"ps written-out home", `Add-Content -Path C:\Users\alice\proj\notes.txt -Value x`, ps, false},
		{"ps ~\\", `Set-Content -Path ~\notes\a.txt -Value y`, ps, false},
		{"ps relative under the home", `Set-Content -Path notes.txt -Value y`, ps, false},
		{"cmd %USERPROFILE%", `type C:\t\a.txt > %USERPROFILE%\notes\a.txt`, cmd, false},
		{"cmd redirect", `echo x > %USERPROFILE%\proj\x.txt`, cmd, false},
		{"cmd written-out home", `echo x > C:\Users\alice\proj\x.txt`, cmd, false},
		{"git bash ~/", `echo x > ~/proj/x.txt`, gb, false},
		{"git bash $HOME", `echo x > $HOME/proj/x.txt`, gb, false},
		{"git bash /c/ mount", `echo x > /c/Users/alice/proj/x.txt`, gb, false},
		{"ps keys", `Add-Content -Path ~\.ssh\authorized_keys -Value k`, ps, true},
		{"ps written-out keys", `Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k`, ps, true},
		{"cmd keys", `echo k >> %USERPROFILE%\.ssh\authorized_keys`, cmd, true},
		{"git bash keys", `echo k >> ~/.ssh/authorized_keys`, gb, true},
	} {
		res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.command}, tc.opts)
		facts := Project(res, Env{Home: home, Flavor: effects.FlavorWindows})
		var writes, grades []string
		known := false
		for _, f := range facts {
			if f.GetKind() != string(effects.KindWrite) && f.GetKind() != string(effects.KindAppend) {
				continue
			}
			writes = append(writes, f.GetTargetState()+" "+f.GetTarget().GetPath())
			for _, m := range f.GetTarget().GetProtected() {
				grades = append(grades, m.GetSet()+"="+m.GetState())
				known = known || m.GetState() == "known"
			}
		}
		switch {
		case len(writes) == 0:
			t.Errorf("%s %q: no write effect", tc.name, tc.command)
		case tc.protected && !known:
			t.Errorf("%s %q: writes %v grades %v, want a known protected member", tc.name, tc.command, writes, grades)
		case !tc.protected && len(grades) != 0:
			t.Errorf("%s %q: writes %v grades %v, want no protected set", tc.name, tc.command, writes, grades)
		case !tc.protected && !strings.HasPrefix(strings.ToLower(writes[0]), `known c:\users\alice\`):
			t.Errorf("%s %q: writes %v, want a known path under the home", tc.name, tc.command, writes)
		}
	}
}

// A path of the other flavor than the host's is its own answer (no disk read).
func TestDET111R3ResolverForFlavor(t *testing.T) {
	old := hostGOOS
	t.Cleanup(func() { hostGOOS = old })
	for _, tc := range []struct {
		goos   string
		flavor effects.Flavor
		path   string
	}{
		{"linux", effects.FlavorWindows, `C:\Users\alice\x`},
		{"darwin", effects.FlavorWindows, `C:\Users\alice\x`},
		{"windows", effects.FlavorPOSIX, `/home/alice/x`},
	} {
		hostGOOS = tc.goos
		if got, ok := resolverForWith(tc.flavor, nil)(tc.path); !ok || got != tc.path {
			t.Errorf("%s host, %s path %q: resolver gave %q %v, want the placed path", tc.goos, tc.flavor, tc.path, got, ok)
		}
	}
}
