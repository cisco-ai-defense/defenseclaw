// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0443: '..' after a wildcard component that matches a link
// ascends from the link's target, as the kernel walks it; a '..' after a
// real folder and a link that does not resolve are joined by name.
func TestGAP0443GlobDotDotAfterLinkWalksPhysically(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"out", "proj/sub", "home/.ssh", "out/real"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "proj", "sub"), filepath.Join(root, "out", "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "home", ".ssh"), filepath.Join(root, "proj", "keydir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "out", "dangling")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	noDots := func() bool { return false }
	// the pattern as the word spells it: filepath.Join would clean the '..'
	pat := func(parts ...string) string {
		return strings.Join(append([]string{out}, parts...), string(filepath.Separator))
	}
	got, complete, unseen := actionExpandGlob(pat("u*", "..", "keydir", "authorized_keys"), out, false, true, noDots)
	want := filepath.Join(root, "proj", "keydir", "authorized_keys")
	if !complete || unseen || !slices.Equal(got, []string{want}) {
		t.Fatalf("u*/../keydir/authorized_keys = %v complete=%v unseen=%v, want [%s]", got, complete, unseen, want)
	}
	got, _, _ = actionExpandGlob(pat("r*", "..", "x"), out, false, true, noDots)
	if want := filepath.Join(out, "x"); !slices.Equal(got, []string{want}) {
		t.Fatalf("r*/../x = %v, want [%s] (a real folder ascends by name)", got, want)
	}
	got, _, _ = actionExpandGlob(pat("d*", "..", "x"), out, false, true, noDots)
	if want := filepath.Join(out, "x"); !slices.Equal(got, []string{want}) {
		t.Fatalf("d*/../x = %v, want [%s] (an unresolved link is joined by name)", got, want)
	}
}
