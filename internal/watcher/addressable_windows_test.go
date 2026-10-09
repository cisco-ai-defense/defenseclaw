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

// A trailing-dot asset must be moved using its addressable Windows path.
func TestTrailingDotSkillCanBeQuarantined(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	path := filepath.Join(skillDir, "review.")
	if err := os.Mkdir(addressablePath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(addressablePath(path), "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallSkill, Name: "review.", Path: path, Timestamp: time.Now()}
	if err := w.quarantineAssetWith(context.Background(), evt, false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(addressablePath(path)); !os.IsNotExist(err) {
		t.Fatalf("source remains: %v", err)
	}
}
