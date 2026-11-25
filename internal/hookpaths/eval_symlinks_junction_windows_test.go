// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// EvalSymlinks, the reader every hook path check and the gateway's hook
// config guard resolve a path a hook call names with, follows a junction as
// it follows a symbolic link: a standard user makes a junction without any
// privilege, and a path through one must be judged where it leads
// (rel-1-0-10:GAP-2182).
func TestEvalSymlinksFollowsAJunction(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "home", "link")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(outside, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := EvalSymlinks(filepath.Join(link, "sub"))
	if err != nil || !strings.EqualFold(got, want) {
		t.Fatalf("EvalSymlinks through a junction = %q, %v; want %q", got, err, want)
	}
	// A path that ends at the junction: filepath.EvalSymlinks returns it
	// unresolved, as if it were a plain folder below the home.
	wantLink, err := filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := EvalSymlinks(link); err != nil || !strings.EqualFold(got, wantLink) {
		t.Fatalf("EvalSymlinks of the junction = %q, %v; want %q", got, err, wantLink)
	}
	if _, err := EvalSymlinks(filepath.Join(link, "missing")); !os.IsNotExist(err) {
		t.Fatalf("EvalSymlinks of a missing path through a junction: %v, want a not-exist error", err)
	}
}
