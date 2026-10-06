// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// restoredRescanFixture quarantines a skill, restores it, and returns the
// event for the restored files; keepBlock decides whether the install block
// stays in place across the restore (restore only) or is cleared first
// (unblock, then restore).
func restoredRescanFixture(t *testing.T, keepBlock bool) (*InstallWatcher, *audit.Store, InstallEvent) {
	t.Helper()
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Skill.TakeAction = true
	skillPath := filepath.Join(skillDir, "review-two")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pe := enforce.NewPolicyEngine(store)
	for _, set := range []func(string, string, string) error{pe.Block, pe.Quarantine, pe.Disable} {
		if err := set("skill", "review-two", "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	evt := InstallEvent{
		Type: InstallSkill, Name: "review-two", Path: skillPath,
		Connector: "claudecode", Timestamp: time.Now().UTC(),
	}
	w.quarantineAsset(context.Background(), evt)
	if _, err := os.Lstat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("fixture quarantine left the files in place: %v", err)
	}
	if !keepBlock {
		if err := store.ClearActionField("skill", "review-two", "install"); err != nil {
			t.Fatal(err)
		}
		if err := pe.Enable("skill", "review-two"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.RestoreQuarantined(context.Background(), "skill", "review-two", "claudecode", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(skillPath); err != nil {
		t.Fatalf("restore did not bring the files back: %v", err)
	}
	return w, store, evt
}

func rejectRestored(w *InstallWatcher, evt InstallEvent) {
	out := &policy.AdmissionOutput{
		Verdict: "rejected", InstallAction: "block", FileAction: "quarantine", RuntimeAction: "block",
	}
	w.applyPostScanEnforcement(
		context.Background(), enforce.NewPolicyEngine(w.store), out, evt, "skill",
		&scanner.ScanResult{Scanner: "skill-scanner", Target: evt.Path}, "skill-scanner",
	)
}

// GAP-1971: after unblock + restore, a rejecting re-scan blocks the skill
// again, so its files must go back to quarantine, not stay in the skill folder
// under a "quarantined" record.
func TestRestoreAfterUnblockRescanQuarantinesAgain(t *testing.T) {
	w, store, evt := restoredRescanFixture(t, false)
	rejectRestored(w, evt)

	if _, err := os.Lstat(evt.Path); !os.IsNotExist(err) {
		t.Fatalf("re-blocked skill files stayed in the skill folder: %v", err)
	}
	records, err := store.ListQuarantineRecordsForConnector(context.Background(), "skill", "review-two", "claudecode")
	if err != nil || len(records) != 1 || records[0].State != audit.QuarantineStateActive {
		t.Fatalf("quarantine records = %#v err=%v", records, err)
	}
}

// GAP-0003: the block shorthand (install block, file none, runtime disable)
// blocks and disables the skill but leaves its files in the skill folder; only
// a file action of quarantine moves them.
func TestRescanBlockShorthandKeepsFiles(t *testing.T) {
	w, _, evt := restoredRescanFixture(t, false)
	out := &policy.AdmissionOutput{
		Verdict: "rejected", InstallAction: "block", FileAction: "none", RuntimeAction: "block",
	}
	w.applyPostScanEnforcement(
		context.Background(), enforce.NewPolicyEngine(w.store), out, evt, "skill",
		&scanner.ScanResult{Scanner: "skill-scanner", Target: evt.Path}, "skill-scanner",
	)
	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("block with file none moved the skill files: %v", err)
	}
}

// A restore that kept the install block still keeps the restored files, and
// the record no longer claims they are quarantined.
func TestRestoreWhileBlockedRescanKeepsFilesNotQuarantined(t *testing.T) {
	w, store, evt := restoredRescanFixture(t, true)
	rejectRestored(w, evt)

	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("restored files of a still-blocked skill were moved: %v", err)
	}
	entry, err := store.GetActionForConnector("skill", "review-two", "")
	if err != nil || entry == nil {
		t.Fatalf("action entry = %#v err=%v", entry, err)
	}
	if entry.Actions.File != "" || entry.Actions.Install != "block" {
		t.Fatalf("actions = %#v, want install=block and no file action", entry.Actions)
	}
}

// GAP-1971 (verify run 1): after unblock + restore and the re-scan that
// quarantined the skill again, a delete and re-copy of the same skill is
// caught by the block list and must be quarantined, not kept as "restored".
func TestRestoreAfterUnblockRecopyIsQuarantined(t *testing.T) {
	w, store, evt := restoredRescanFixture(t, false)
	rejectRestored(w, evt)
	if _, err := os.Lstat(evt.Path); !os.IsNotExist(err) {
		t.Fatalf("re-blocked skill files stayed in the skill folder: %v", err)
	}

	if err := os.MkdirAll(evt.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evt.Path, "SKILL.md"), []byte("review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.enforceBlock(context.Background(), evt)

	if _, err := os.Lstat(evt.Path); !os.IsNotExist(err) {
		t.Fatalf("re-copied blocked skill stayed in the skill folder: %v", err)
	}
	records, err := store.ListQuarantineRecordsForConnector(context.Background(), "skill", "review-two", "claudecode")
	if err != nil || len(records) == 0 {
		t.Fatalf("quarantine records = %#v err=%v", records, err)
	}
}

// GAP-1971 (verify run 2): the re-scan blocked the restored skill but its
// quarantine move failed (the folder was deleted meanwhile). A re-copy must
// still be quarantined.
func TestRestoreAfterUnblockFailedRequarantineRecopyIsQuarantined(t *testing.T) {
	w, _, evt := restoredRescanFixture(t, false)
	if err := os.RemoveAll(evt.Path); err != nil {
		t.Fatal(err)
	}
	rejectRestored(w, evt)

	if err := os.MkdirAll(evt.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evt.Path, "SKILL.md"), []byte("review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.enforceBlock(context.Background(), evt)

	if _, err := os.Lstat(evt.Path); !os.IsNotExist(err) {
		t.Fatalf("re-copied blocked skill stayed in the skill folder: %v", err)
	}
}
