// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A box that sets GOTMPDIR (every S7 gate box) keeps t.TempDir there; a test
// that moves its temporary folder must move both (rel-1-0-10:GAP-0423).
func TestSetTempRootMovesTheTestTempDirWithGOTMPDIRSet(t *testing.T) {
	boxTemp, err := os.MkdirTemp("", "gotmpdir-box")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(boxTemp) })
	wanted, err := os.MkdirTemp("", "gotmpdir-wanted")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(wanted) })
	for _, gotmpdir := range []string{boxTemp, ""} {
		t.Run("GOTMPDIR="+filepath.Base(gotmpdir), func(t *testing.T) {
			t.Setenv("GOTMPDIR", gotmpdir)
			SetTempRoot(t, wanted)
			if got := TempRoot(); got != wanted {
				t.Fatalf("TempRoot() = %q, want %q", got, wanted)
			}
			if got := t.TempDir(); !strings.HasPrefix(got, wanted+string(filepath.Separator)) {
				t.Fatalf("t.TempDir() = %q, want a folder in %q", got, wanted)
			}
			if gotmpdir == "" {
				if value, set := os.LookupEnv("GOTMPDIR"); set && value != "" {
					t.Fatalf("GOTMPDIR set to %q; an unset GOTMPDIR stays unset", value)
				}
			}
		})
	}
}
