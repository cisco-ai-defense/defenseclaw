//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A writable folder on the way to the audit database is refused with the folder
// and the one repair named, whichever element of the path it is, and a private
// path opens as before.
func TestAuditDBWritableFolderRefusalNamesTheFolderAndTheRepair(t *testing.T) {
	cases := []struct {
		name   string
		folder func(root string) (ancestor, parent string)
	}{
		{"immediate parent", func(root string) (string, string) {
			parent := filepath.Join(root, "home")
			return parent, parent
		}},
		{"ancestor of the parent", func(root string) (string, string) {
			ancestor := filepath.Join(root, "shared")
			return ancestor, filepath.Join(ancestor, "defenseclaw")
		}},
		{"folder with a quote in its name", func(root string) (string, string) {
			parent := filepath.Join(root, "it's home")
			return parent, parent
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ancestor, parent := tc.folder(t.TempDir())
			if err := os.MkdirAll(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(ancestor, 0o770); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(ancestor, 0o700) //nolint:errcheck
			db, err := openHardenedAuditSQLite(filepath.Join(parent, "audit.db"), auditDBPathHooks{})
			if db != nil {
				_ = db.Close()
			}
			if err == nil {
				t.Fatal("a group-writable folder opened")
			}
			msg := err.Error()
			if !strings.Contains(msg, ancestor) {
				t.Errorf("error %q does not name %s", msg, ancestor)
			}
			if want := "chmod go-w " + auditDBShellQuote(ancestor); !strings.Contains(msg, want) {
				t.Errorf("error %q does not carry %q", msg, want)
			}
			if !strings.HasSuffix(msg, "then run: defenseclaw-gateway restart") {
				t.Errorf("error %q does not end with the restart step", msg)
			}
			if !strings.Contains(msg, "group- or other-writable") {
				t.Errorf("error %q lost the verdict", msg)
			}
		})
	}

	t.Run("private folder opens", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "home")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		db, err := openHardenedAuditSQLite(filepath.Join(parent, "audit.db"), auditDBPathHooks{})
		if err != nil {
			t.Fatalf("a private folder was refused: %v", err)
		}
		_ = db.Close()
	})
}
