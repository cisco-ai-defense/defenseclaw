// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHermesLocksMetadataIsNotAdmittedAsASkill(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	root := filepath.Join(t.TempDir(), "profile", ".hermes", "skills")
	locks := filepath.Join(root, ".locks")
	if err := os.MkdirAll(locks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locks, "install.lock"), []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	if events := w.pendingInstallEvents(locks); len(events) != 0 {
		t.Fatalf("Hermes metadata produced skill admission events: %+v", events)
	}
	for _, event := range w.enumerateTargets() {
		if event.Path == locks {
			t.Fatalf("Hermes metadata was enumerated as a skill: %+v", event)
		}
	}

	// A directory with a SKILL.md is still a skill even if it uses that name.
	if err := os.WriteFile(filepath.Join(locks, "SKILL.md"), []byte("---\nname: lock-review\n---\nreview\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if events := w.pendingInstallEvents(locks); len(events) != 1 || events[0].Path != locks {
		t.Fatalf("actual Hermes skill events = %+v, want the skill", events)
	}
}
