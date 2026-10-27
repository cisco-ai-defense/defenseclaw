// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2118: "defenseclaw skill install" stages a skill in
// <root>/.dclaw-stage-<name>-<random>/<name>. Hermes discovery walks hidden
// folders, so the watcher scanned that private copy under ~/.hermes/skills,
// found it gone and left a fail-closed block on the skill name that kept a
// later admitted install disabled.
func TestHermesSkillInstallStagingIsNotAdmitted(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	cfg.Guardrail.Connector = "hermes"
	root := filepath.Join(home, "skills")
	stage := filepath.Join(root, ".dclaw-stage-fxshare1-x1y2z3")
	staged := filepath.Join(stage, "fxshare1")
	input := filepath.Join(stage, ".dclaw-stage-input-abc", "fxshare1")
	user := filepath.Join(root, "fxshare2")
	for _, dir := range []string{staged, input, user} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		marker := "---\nname: " + filepath.Base(dir) + "\n---\nformat notes\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)

	for _, path := range []string{stage, staged, filepath.Dir(input)} {
		if events := w.pendingInstallEvents(path); len(events) != 0 {
			t.Fatalf("install staging %s produced admission events: %+v", path, events)
		}
	}
	if events := w.pendingInstallEvents(user); len(events) != 1 || !sameWatcherPath(events[0].Path, user) {
		t.Fatalf("user skill events = %+v, want the skill", events)
	}
	names := func() map[string]string {
		got := map[string]string{}
		for _, target := range w.enumerateTargets() {
			if target.Type == InstallSkill {
				got[target.Path] = target.Name
			}
		}
		return got
	}
	got := names()
	if _, ok := got[staged]; ok {
		t.Fatalf("young install staging entered the rescan: %+v", got)
	}
	if _, ok := got[user]; !ok {
		t.Fatalf("user skill missing from the rescan: %+v", got)
	}
	// A staging folder left behind longer than the grace is scanned.
	old := time.Now().Add(-2 * claudeStagingGrace)
	if err := os.Chtimes(stage, old, old); err != nil {
		t.Fatal(err)
	}
	if got := names(); got[staged] != "fxshare1" {
		t.Fatalf("stale install staging was not rescanned: %+v", got)
	}
}

// GAP-2118: a failed scan of a skill folder that is gone is no verdict on
// the name, and a block left earlier for a folder that is gone is lifted by
// a successful scan of the same name at its real place.
func TestScanFailureOfAVanishedSkillLeavesNoBlock(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "skill-scanner"}} }
	gone := filepath.Join(skillDir, "removed-copy")
	evt := InstallEvent{Type: InstallSkill, Name: "fxshare1", Path: gone, Connector: "claudecode", Timestamp: time.Now()}
	if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked {
		t.Fatalf("failed scan of a vanished folder: result %+v, want no block", res)
	}
	if entry, err := store.GetActionForConnector("skill", "fxshare1", "claudecode"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("journal %+v (err %v), want no block for a vanished folder", entry, err)
	}

	// A folder that exists still fails closed.
	present := filepath.Join(skillDir, "fxshare1")
	if err := os.MkdirAll(present, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(present, "SKILL.md"), []byte("---\nname: fxshare1\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := InstallEvent{Type: InstallSkill, Name: "fxshare1", Path: present, Connector: "claudecode", Timestamp: time.Now()}
	if res := w.runAdmission(context.Background(), real); res.Verdict != VerdictBlocked {
		t.Fatalf("failed scan of a present folder: result %+v, want blocked (fail-closed)", res)
	}
	if err := os.MkdirAll(present, 0o700); err != nil { // put back if quarantined
		t.Fatal(err)
	}

	// A block an older build recorded for a staging copy that is gone.
	w.recordScanFailureBlock(InstallEvent{Type: InstallSkill, Name: "fxshare1", Path: gone, Connector: "claudecode"},
		"skill", scanFailureReason+"stat "+gone+": no such file or directory")
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	w.releaseScanFailureBlock(real, "skill")
	if entry, err := store.GetActionForConnector("skill", "fxshare1", "claudecode"); err != nil || (entry != nil && !entry.Actions.IsEmpty()) {
		t.Fatalf("journal %+v (err %v), want the block of the vanished copy lifted", entry, err)
	}
}
