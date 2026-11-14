// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A place of the home is private to the account when a directory on the way to
// it has no group or other permission bit; no folder name decides it
// (rel-1-0-10:GAP-0710).
func TestHomeClosedToOthersIsDecidedByPermissionBits(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "open")
	closed := filepath.Join(root, "closed")
	for _, dir := range []string{open, closed} {
		if err := os.MkdirAll(filepath.Join(dir, "public_html"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, home, place string
		want              bool
	}{
		{"home others can open", open, filepath.Join(open, "backup", "k"), false},
		{"a served-looking folder of an open home", open, filepath.Join(open, "public_html", "k"), false},
		{"a folder name proves nothing in a closed home", closed, filepath.Join(closed, "public_html", "k"), true},
		{"a new folder of a closed home", closed, filepath.Join(closed, "new", "k"), true},
		{"a closed folder inside an open home", open, filepath.Join(open, "vault", "k"), true},
		{"a home this host cannot see", filepath.Join(root, "absent"), filepath.Join(root, "absent", "k"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "a closed folder inside an open home" {
				if err := os.Mkdir(filepath.Join(open, "vault"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if got := homeClosedToOthers(test.home, test.place); got != test.want {
				t.Fatalf("homeClosedToOthers(%q) = %v, want %v", test.place, got, test.want)
			}
		})
	}
}
