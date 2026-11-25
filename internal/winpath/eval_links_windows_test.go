// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// EvalLinks follows a junction and a symbolic link alike, gives a plain
// folder its own final path, and reports a missing path as not existing
// (rel-1-0-10:GAP-2182).
func TestEvalLinksFollowsJunctionsAndSymbolicLinks(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sub", "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantSub, err := filepath.EvalSymlinks(filepath.Join(outside, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	cases := map[string]string{
		filepath.Join(outside, "sub"):           wantSub,
		filepath.Join(junction, "sub"):          wantSub,
		filepath.Join(junction, "sub", "f.txt"): filepath.Join(wantSub, "f.txt"),
		filepath.Join(junction, "sub") + `\`:    wantSub,
	}
	symlink := filepath.Join(base, "symlink")
	if err := os.Symlink(outside, symlink); err == nil {
		cases[filepath.Join(symlink, "sub")] = wantSub
	} else {
		t.Logf("symbolic link row left out (the account cannot make one): %v", err)
	}
	for in, want := range cases {
		got, err := EvalLinks(in)
		if err != nil || !strings.EqualFold(got, want) {
			t.Errorf("EvalLinks(%q) = %q, %v; want %q", in, got, err, want)
		}
		if strings.HasPrefix(got, `\\?\`) {
			t.Errorf("EvalLinks(%q) = %q keeps the \\\\?\\ prefix", in, got)
		}
	}
	for _, missing := range []string{filepath.Join(junction, "missing"), filepath.Join(base, "missing", "x")} {
		if _, err := EvalLinks(missing); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("EvalLinks(%q) error %v, want fs.ErrNotExist", missing, err)
		}
	}
	dangling := filepath.Join(base, "dangling")
	gone := filepath.Join(base, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", dangling, gone).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if got, err := EvalLinks(dangling); err == nil {
		t.Errorf("EvalLinks of a junction to a removed folder = %q, want an error", got)
	}
}
