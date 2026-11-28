// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGAP0691GitBashDriveSearchFolder: under a Windows drive home, a
// recursive search of a folder spelled as a Git Bash drive mount (/c/x,
// /cygdrive/c/x), as an operand or as the folder a cd reaches, reads the
// credentials files under it as its drive spelling C:/x does: Git Bash
// hands rg and grep the drive path (substrate-1:GAP-0691, native probe
// TestZZP34BWinProbe rows N1, N2, P06a-P06i: read=false at rel, base and
// head, where the slash and quoted drive spellings read). Before, the walk
// joined /c/x onto the hook folder. The controls read none: a folder with
// no credentials file, and rg without --hidden.
func TestGAP0691GitBashDriveSearchFolder(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Git Bash drive mount names a drive folder on Windows only")
	}
	home := t.TempDir()
	if physical, err := filepath.EvalSymlinks(home); err == nil {
		home = physical
	}
	proj, clean := filepath.Join(home, "proj"), filepath.Join(home, "clean")
	for _, name := range []string{"proj/.env", "proj/sub/.env", "proj/a.go", "clean/a.go"} {
		file := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("KEY=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mount := func(prefix, folder string) string {
		slash := filepath.ToSlash(folder)
		return prefix + strings.ToLower(slash[:1]) + slash[2:]
	}
	for _, row := range []struct {
		id, command string
		read        bool
	}{
		{"N1 rg anchored glob, mount operand", "rg -g '/.env' KEY " + mount("/", proj), true},
		{"N2 rg --hidden, mount operand", "rg --hidden KEY " + mount("/", proj), true},
		{"N3 grep -r, mount operand", "grep -r KEY " + mount("/", proj), true},
		{"N4 cd to a mount, grep -r .", "cd " + mount("/", proj) + " && grep -r KEY .", true},
		{"N5 rg --hidden, cygdrive operand", "rg --hidden KEY " + mount("/cygdrive/", proj), true},
		{"D1 rg --hidden, drive operand", "rg --hidden KEY " + filepath.ToSlash(proj), true},
		{"C1 a folder with no credentials file", "rg --hidden KEY " + mount("/", clean), false},
		{"C2 rg skips hidden files", "rg KEY " + mount("/", proj), false},
	} {
		t.Run(row.id, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: proj, ActiveHome: home, DialectHint: DialectPOSIX})
			if got := len(facts.CredentialPathReads()) > 0; got != row.read {
				t.Fatalf("%s: credentials read = %v, want %v (%v)", row.id, got, row.read, facts.CredentialPathReads())
			}
		})
	}
}

// TestGAP0691GitBashDriveOnlyUnderADriveHome: a drive mount is respelled
// only under a Windows drive home; under a POSIX home /c/x is the folder
// it names (substrate-1:GAP-0691).
func TestGAP0691GitBashDriveOnlyUnderADriveHome(t *testing.T) {
	for _, row := range []struct{ home, value, want string }{
		{"/home/a", "/c/x", "/c/x"},
		{`C:\Users\a`, "/c/x", "C:/x"},
		{"C:/Users/a", "/cygdrive/d/y", "D:/y"},
		{"C:/Users/a", "/tmp/x", "/tmp/x"},
		{"C:/Users/a", "rel/x", "rel/x"},
	} {
		r := &credentialPathResolver{home: row.home}
		if got := r.gitBashDrive(row.value); got != row.want {
			t.Errorf("home %s: gitBashDrive(%s) = %s, want %s", row.home, row.value, got, row.want)
		}
		steps := r.gitBashDriveSteps(workFolder{steps: []string{row.value, ".."}}).steps
		if steps[0] != row.want || steps[1] != ".." {
			t.Errorf("home %s: gitBashDriveSteps(%s) = %v", row.home, row.value, steps)
		}
	}
}
