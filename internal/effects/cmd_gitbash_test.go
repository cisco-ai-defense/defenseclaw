// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGitBashCmdDoubleSlashC: in Git Bash (POSIX dialect on Windows) cmd //c
// is cmd's /c, because MSYS turns a leading // into /; its body is read like
// cmd /c's (DET111 R1, GAP-1667).
func TestGitBashCmdDoubleSlashC(t *testing.T) {
	o := Options{Flavor: FlavorWindows, Dialect: DialectPOSIX, CWD: `C:\w`, Drive: "C", CaseInsensitive: true}
	for _, src := range []string{`cmd //c "del C:\w\a.txt"`, `cmd //C "del C:\w\a.txt"`, `cmd /c "del C:\w\a.txt"`} {
		r := Extract(Call{Surface: SurfaceShell, Command: src}, o)
		found := false
		for _, e := range r.Effects {
			if e.Kind == KindDelete && e.Target.Key() == `c:\w\a.txt` {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: the cmd body delete is not read:\n%s", src, fmtRes(r))
		}
	}
}
