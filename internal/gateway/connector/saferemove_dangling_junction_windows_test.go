// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// A junction whose folder is gone is still an entry below parent, and the
// teardown removes it (the link, never what it named), as rel/1.0.10 did. A
// dangling junction that is not below parent is refused and stays
// (rel-1-0-10:GAP-2182, review RV-2182 F1).
func TestSafeRemoveAllRemovesADanglingJunctionBelowParent(t *testing.T) {
	parent := t.TempDir()
	elsewhere := t.TempDir()
	dangling := func(link string) {
		t.Helper()
		gone := filepath.Join(t.TempDir(), "gone")
		if err := os.Mkdir(gone, 0o700); err != nil {
			t.Fatal(err)
		}
		makeGAP2182ConnectorJunction(t, link, gone)
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
	}
	below := filepath.Join(parent, "defenseclaw")
	dangling(below)
	if err := safeRemoveAll(below, parent); err != nil {
		t.Errorf("safeRemoveAll(%s) = %v, want nil", below, err)
	}
	if _, err := os.Lstat(below); !os.IsNotExist(err) {
		t.Errorf("the dangling junction below parent is still there (Lstat: %v)", err)
	}
	outside := filepath.Join(elsewhere, "defenseclaw")
	dangling(outside)
	if err := safeRemoveAll(outside, parent); err == nil {
		t.Errorf("safeRemoveAll(%s, %s) = nil for a dangling junction outside parent, want a refusal", outside, parent)
	}
	if _, err := os.Lstat(outside); err != nil {
		t.Errorf("the dangling junction outside parent was removed (Lstat: %v)", err)
	}
}
