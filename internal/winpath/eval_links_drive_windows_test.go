// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// freeDriveLetter is a drive letter with nothing behind it, from Y: down.
func freeDriveLetter(t *testing.T) string {
	t.Helper()
	for c := 'Y'; c >= 'M'; c-- {
		if _, err := os.Lstat(string(c) + `:\`); err != nil {
			return string(c) + ":"
		}
	}
	t.Fatal("no free drive letter between M: and Y:")
	return ""
}

func sameFileAs(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	if err != nil {
		t.Fatalf("stat %s: %v", a, err)
	}
	ib, err := os.Stat(b)
	if err != nil {
		t.Fatalf("stat %s: %v", b, err)
	}
	return os.SameFile(ia, ib)
}

// A path on a subst drive keeps its drive letter, as filepath.EvalSymlinks
// kept it, while a junction on the way is still followed: the drive letter
// is spelled back only when the final path lies below the folder the drive
// maps to (rel-1-0-10:GAP-2182, review RV-2182 F2).
func TestEvalLinksKeepsASubstDriveSpelling(t *testing.T) {
	base := t.TempDir()
	mapped := filepath.Join(base, "mapped")
	other := filepath.Join(base, "other")
	for _, d := range []string{filepath.Join(mapped, "sub"), other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{filepath.Join(mapped, "j"): filepath.Join(mapped, "sub"), filepath.Join(mapped, "esc"): other} {
		if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v: %s", err, out)
		}
	}
	letter := freeDriveLetter(t)
	if out, err := exec.Command("subst.exe", letter, mapped).CombinedOutput(); err != nil {
		t.Fatalf("subst %s %s: %v: %s", letter, mapped, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("subst.exe", letter, "/d").Run() })
	wantOther, err := filepath.EvalSymlinks(other)
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		letter + `\sub`:                   letter + `\sub`,
		strings.ToLower(letter) + `\sub\`: letter + `\sub`,
		letter + `\j`:                     letter + `\sub`,
		letter + `\`:                      letter + `\`,
		letter + `\esc`:                   wantOther,
	} {
		got, err := EvalLinks(in)
		if err != nil || !strings.EqualFold(got, want) {
			t.Errorf("EvalLinks(%q) = %q, %v; want %q", in, got, err, want)
			continue
		}
		if !sameFileAs(t, in, got) {
			t.Errorf("EvalLinks(%q) = %q names another file", in, got)
		}
	}
}

// A path on a mapped network drive keeps its drive letter and is not
// respelled as the share (\\server\share\...), so the hook path share gate
// sees the spelling it saw at rel/1.0.10 (review RV-2182 F2). The admin
// share \\localhost\C$ needs an administrator token.
func TestEvalLinksKeepsAMappedDriveSpelling(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the \\\\localhost\\C$ admin share needs an elevated token")
	}
	letter := freeDriveLetter(t)
	if out, err := exec.Command("net.exe", "use", letter, `\\localhost\C$`, "/persistent:no").CombinedOutput(); err != nil {
		t.Fatalf("net use %s: %v: %s", letter, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("net.exe", "use", letter, "/delete", "/y").Run() })
	in := letter + `\Windows\System32`
	got, err := EvalLinks(in)
	if err != nil || !strings.EqualFold(got, in) {
		t.Fatalf("EvalLinks(%q) = %q, %v; want %q", in, got, err, in)
	}
	if !sameFileAs(t, in, got) {
		t.Fatalf("EvalLinks(%q) = %q names another file", in, got)
	}
}

// A bare device name is refused before any open: filepath.Abs turns NUL into
// \\.\NUL, which must not become the UNC path \\?\UNC\.\NUL and cost a
// network lookup (review RV-2182 F3).
func TestExtendedRefusesABareDeviceName(t *testing.T) {
	for _, name := range []string{"NUL", "nul", "CONIN$", "CON"} {
		if got, err := Extended(name); err == nil {
			t.Errorf("Extended(%q) = %q, want an error", name, got)
		}
		start := time.Now()
		if got, err := EvalLinks(name); err == nil {
			t.Errorf("EvalLinks(%q) = %q, want an error", name, got)
		}
		if d := time.Since(start); d > 250*time.Millisecond {
			t.Errorf("EvalLinks(%q) took %v, want a refusal without a network lookup", name, d)
		}
	}
}
