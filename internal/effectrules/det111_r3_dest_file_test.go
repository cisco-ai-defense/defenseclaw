// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

type destStatInfo struct{ mode fs.FileMode }

func (i destStatInfo) Name() string       { return "x" }
func (i destStatInfo) Size() int64        { return 0 }
func (i destStatInfo) Mode() fs.FileMode  { return i.mode }
func (i destStatInfo) ModTime() time.Time { return time.Time{} }
func (i destStatInfo) IsDir() bool        { return i.mode.IsDir() }
func (i destStatInfo) Sys() any           { return nil }

// rel-1-0-10:GAP-1677/GAP-1678: a cp destination that may be a directory is
// Known when the resolver reads an existing regular file there (cp writes
// that file), and stays unknown for a directory, a missing path, a link the
// resolver could not walk, or the other path flavor.
func TestDET111R3DestFileSettlesCopyTarget(t *testing.T) {
	const home = "/home/alice"
	const dest = home + "/.claude/settings.json"
	walk := func(p string) (string, bool) { return p, true }
	cases := []struct {
		name  string
		rsv   func(string) (string, bool)
		stat  func(string) (os.FileInfo, error)
		known bool
	}{
		{"regular file", walk, func(string) (os.FileInfo, error) { return destStatInfo{0o600}, nil }, true},
		{"directory", walk, func(string) (os.FileInfo, error) { return destStatInfo{fs.ModeDir | 0o700}, nil }, false},
		{"missing", walk, func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }, false},
		{"symlink not walked", walk, func(string) (os.FileInfo, error) { return destStatInfo{fs.ModeSymlink | 0o777}, nil }, false},
		{"resolver refuses", func(string) (string, bool) { return "", false }, func(string) (os.FileInfo, error) { return destStatInfo{0o600}, nil }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostGOOSWas := hostGOOS
			hostGOOS = "linux"
			t.Cleanup(func() { hostGOOS = hostGOOSWas })
			var asked []string
			stat := func(p string) (os.FileInfo, error) { asked = append(asked, p); return tc.stat(p) }
			opts := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: home}
			result := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: "cp proj/notes.txt ~/.claude/settings.json"}, opts)
			facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX, Resolve: tc.rsv, DestStat: stat})
			found := false
			for _, f := range facts {
				if f.GetKind() != string(effects.KindWrite) || f.GetTarget().GetPath() != dest {
					continue
				}
				found = true
				gotKnown := f.GetTargetState() == string(effects.TargetStateKnown) && len(f.GetReasons()) == 0
				if gotKnown != tc.known {
					t.Fatalf("target state %s reasons %v, want known=%v", f.GetTargetState(), f.GetReasons(), tc.known)
				}
				exact := false
				for _, m := range f.GetTarget().GetProtected() {
					if m.GetSet() == SetAgentHookConfig && m.GetState() == string(gradeKnown) && m.GetReason() == "exact" {
						exact = true
					}
				}
				if exact != tc.known {
					t.Fatalf("hook config exact known match = %v, want %v: %v", exact, tc.known, f.GetTarget().GetProtected())
				}
			}
			if !found {
				t.Fatalf("no write to %s in %v", dest, facts)
			}
			if tc.name == "resolver refuses" && len(asked) != 0 {
				t.Fatalf("stat read %v after the resolver refused", asked)
			}
		})
	}
	// A redirection write is Known already; a Windows path on a POSIX host
	// is never read from this file system.
	opts := effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: `C:\Users\alice`, CWD: `C:\Users\alice`}
	result := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: `Copy-Item notes.txt C:\Users\alice\.claude\settings.json`}, opts)
	read := false
	Project(result, Env{Home: `C:\Users\alice`, Flavor: effects.FlavorWindows, Resolve: walk,
		DestStat: func(string) (os.FileInfo, error) { read = true; return destStatInfo{0o600}, nil }})
	if read && hostGOOS != "windows" {
		t.Fatal("a Windows destination was read from the POSIX host file system")
	}
}
