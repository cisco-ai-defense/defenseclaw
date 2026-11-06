// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0483OrdinaryHardLinkBeyondMentionIndex(t *testing.T) {
	// Keep the production 4,096-entry cap: a populated cache is a normal
	// state layout, while the link being tested stays wholly in the project.
	home, cwd := activeStateIndexFixture(t, 4100)
	ordinary := filepath.Join(cwd, "notes")
	alias := filepath.Join(cwd, "notes-alias")
	if err := os.WriteFile(ordinary, []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ordinary, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	got := ProtectedReach(alias, home, NewTargetMemo())
	t.Logf("ordinary hard link grade=%s", got)
	if got != GradeNone {
		t.Errorf("ordinary hard link should remain None in balanced, got %s", got)
	}
}

func TestGAP0483ProtectedHardLinkBeyondMentionIndex(t *testing.T) {
	home, cwd := activeStateIndexFixture(t, 4100)
	protected := filepath.Join(cwd, "state-alias")
	if err := os.Link(filepath.Join(home, ".defenseclaw", "cache", "entry-4099"), protected); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	if grade := ProtectedReach(protected, home, NewTargetMemo()); grade != GradeNamed {
		t.Errorf("protected hard link grade=%s, want Named", grade)
	}
}

func TestGAP0483LinkedStateTreeHardLinkAndOrdinaryTwin(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	state := filepath.Join(home, ".defenseclaw")
	cwd := filepath.Join(root, "project")
	store := filepath.Join(root, "store")
	nested := filepath.Join(root, "nested")
	for _, dir := range []string{state, cwd, store, nested} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(store, filepath.Join(state, "cache")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(nested, filepath.Join(store, "sub")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	protected := filepath.Join(nested, "entry")
	if err := os.WriteFile(protected, nil, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(cwd, "state-alias")
	if err := os.Link(protected, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	ordinary := filepath.Join(cwd, "notes")
	if err := os.WriteFile(ordinary, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ordinaryAlias := filepath.Join(cwd, "notes-alias")
	if err := os.Link(ordinary, ordinaryAlias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	for _, row := range []struct {
		path string
		want Grade
	}{{alias, GradeNamed}, {ordinaryAlias, GradeNone}} {
		if got := ProtectedReach(row.path, home, NewTargetMemo()); got != row.want {
			t.Errorf("linked state reach %s = %s, want %s", filepath.Base(row.path), got, row.want)
		}
	}
}
