// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0504UnreadableSiblingKeepsReadableSkill(t *testing.T) {
	for _, tc := range []struct{ connector, rootDir string }{
		{"hermes", ".hermes"},
		{"cursor", ".cursor"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Guardrail.Connector = tc.connector
			root := filepath.Join(t.TempDir(), tc.rootDir, "skills")
			category := filepath.Join(root, "category")
			unreadable := filepath.Join(category, "aaa-unreadable")
			skill := filepath.Join(category, "zzz", "listed-skill")
			for _, dir := range []string{unreadable, skill} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: listed-skill\n---\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unreadable, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
			w := New(cfg, []string{root}, nil, store, logger, nil, nil)
			events := w.pendingInstallEvents(category)
			if len(events) != 1 || events[0].Path != skill {
				t.Fatalf("category events = %+v", events)
			}
			targets := w.enumerateTargets()
			if len(targets) != 1 || targets[0].Path != skill {
				t.Fatalf("rescan targets = %+v", targets)
			}
		})
	}
}
