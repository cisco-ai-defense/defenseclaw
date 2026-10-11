// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// GAP-0573: a skill folder whose name ends with a dot was never detected,
// scanned or logged: os.Stat of it looked up the name without the dot.
func TestTrailingDotSkillFolderIsAdmitted(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	path := filepath.Join(skillDir, "epa-s2.")
	if err := os.Mkdir(addressablePath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(addressablePath(path)+`\SKILL.md`, []byte("# epa-s2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	if !w.isDirectChildDir(path) {
		t.Fatal("the trailing-dot folder is not taken for a skill")
	}
	evt := InstallEvent{Type: InstallSkill, Name: "epa-s2.", Path: path, Timestamp: time.Now()}
	snap, err := w.snapshotForEvent(evt)
	if err != nil || snap.ContentHash == "" {
		t.Fatalf("snapshot %+v err %v", snap, err)
	}
	if target, err := w.scanTargetFor(evt); err != nil || !strings.HasPrefix(target, `\\?\`) {
		t.Fatalf("scan target %q, want the extended path that keeps the dot", target)
	}
}

// A trailing-dot or trailing-space asset keeps its exact name through
// quarantine and restore, even beside the normalized name.
func TestTrailingWindowsNameCanBeQuarantinedAndRestored(t *testing.T) {
	for _, name := range []string{"review.", "review "} {
		t.Run(name, func(t *testing.T) {
			cfg, store, logger, skillDir := setupTestEnv(t)
			cfg.Gateway.Watcher.Skill.TakeAction = true
			normal := filepath.Join(skillDir, "review")
			if err := os.Mkdir(normal, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(skillDir, "review") + name[len("review"):]
			if err := os.Mkdir(addressableStandalonePath(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(addressableStandalonePath(path), "SKILL.md"), []byte("# exact\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
			pe := enforce.NewPolicyEngine(store)
			if err := pe.Block("skill", name, "fixture"); err != nil {
				t.Fatal(err)
			}
			if !w.isDirectChildDir(path) || w.classifyEvent(path).Name != name {
				t.Fatal("watcher lost the exact asset name")
			}
			evt := InstallEvent{Type: InstallSkill, Name: name, Path: path, Connector: "claudecode", Timestamp: time.Now()}
			if err := w.quarantineAssetWith(context.Background(), evt, false, "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(addressableStandalonePath(path)); !os.IsNotExist(err) {
				t.Fatalf("source remains: %v", err)
			}
			exact := filepath.Join(cfg.QuarantineDir, "skills", "claudecode", "review") + name[len("review"):]
			if _, err := os.Lstat(addressableStandalonePath(exact)); err != nil {
				t.Fatalf("exact quarantine name missing: %v", err)
			}
			normalized := filepath.Join(cfg.QuarantineDir, "skills", "claudecode", "review")
			if _, err := os.Lstat(normalized); !os.IsNotExist(err) {
				t.Fatalf("quarantine used normalized name: %v", err)
			}
			records, err := store.ListQuarantineRecordsForConnectorExact(context.Background(), "skill", name, "claudecode")
			if err != nil || len(records) != 1 || records[0].TargetName != name ||
				records[0].QuarantinePath != addressableStandalonePath(exact) {
				t.Fatalf("quarantine provenance lost the exact name: records=%v err=%v", records, err)
			}
			if err := w.RestoreQuarantined(context.Background(), "skill", name, "claudecode", ""); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(addressableStandalonePath(path)); err != nil {
				t.Fatalf("exact source was not restored: %v", err)
			}
			if _, err := os.Lstat(normal); err != nil {
				t.Fatalf("normalized sibling changed: %v", err)
			}
			restored, err := store.GetActionForConnector("skill", name, "claudecode")
			if err != nil || restored == nil || !strings.HasPrefix(restored.SourcePath, `\\?\`) {
				t.Fatalf("restored action path = %#v, err = %v", restored, err)
			}
			rejectRestored(w, evt)
			if _, err := os.Lstat(addressableStandalonePath(path)); err != nil {
				t.Fatalf("restored blocked skill was re-quarantined: %v", err)
			}
		})
	}
}
