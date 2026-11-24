// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// GAP-2009: the size of a file the walk cannot open is read relative to the
// held parent folder, so moving that folder away and putting another in its
// place does not change what the walk learns.
func TestGAP2009OpenRefusedReadsTheHeldParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode 000 file")
	}
	for _, tc := range []struct {
		name            string
		heldBig, newBig bool
	}{
		{"held small, swapped in big", false, true},
		{"held big, swapped in small", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			folder := filepath.Join(base, "pdf")
			gap2009File(t, folder, tc.heldBig)
			parent, err := safefile.OpenDirectoryNoFollow(folder)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if err := os.Rename(folder, filepath.Join(base, "moved")); err != nil {
				t.Fatal(err)
			}
			gap2009File(t, folder, tc.newBig)
			_, openErr := safefile.OpenRegularChildNoFollow(parent, "data.bin")
			if openErr == nil {
				t.Fatal("a mode 000 file opened")
			}
			walk := skillHashWalk{limit: maxSkillBytes}
			err = walk.openRefused(parent, "data.bin", openErr)
			if tc.heldBig != errors.Is(err, errSkillTooLarge) {
				t.Fatalf("openRefused = %v; want too large %t (the held folder's file)", err, tc.heldBig)
			}
			if !tc.heldBig && !errors.Is(err, openErr) {
				t.Fatalf("openRefused = %v; want the open error %v", err, openErr)
			}
		})
	}
}

func gap2009File(t *testing.T, folder string, big bool) {
	t.Helper()
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, "data.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if big {
		if err := os.Truncate(path, maxSkillBytes+1024); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}
