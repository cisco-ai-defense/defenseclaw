//go:build !windows

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

// linkedAgentSkills builds ~/.claude -> ~/dotfiles/claude-dir with a clean
// skill "benign" and returns the logical skills root (through the link) and
// the physical one.
func linkedAgentSkills(t *testing.T) (home, logical, physical string) {
	t.Helper()
	home = t.TempDir()
	physical = filepath.Join(home, "dotfiles", "claude-dir", "skills")
	skill := filepath.Join(physical, "benign")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: benign\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(physical), filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return home, filepath.Join(home, ".claude", "skills"), physical
}

// GAP-0906: under a symlinked ~/.claude, a link to an admitted sibling skill
// is inside the watched folders, as it is on a plain root: it is scanned
// through its target and stays.
func TestLinkedAgentRootAdmitsALinkToASiblingSkill(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	_, root, physical := linkedAgentSkills(t)
	link := filepath.Join(root, "alias-ok")
	if err := os.Symlink(filepath.Join(root, "benign"), link); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	scan := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "alias-ok", Path: link, Timestamp: time.Now()})
	if scan.calls == 0 || res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected {
		t.Fatalf("scans=%d verdict=%s reason=%s, want the sibling link scanned and admitted", scan.calls, res.Verdict, res.Reason)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("the admitted link was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(physical, "benign", "SKILL.md")); err != nil {
		t.Fatalf("the sibling skill changed: %v", err)
	}
}

// A link out of the account's watched folders stays refused unread, and the
// link (never its target) is removed although the root is reached through a link.
func TestLinkedAgentRootRemovesALinkOutsideTheWatchedFolders(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	home, root, _ := linkedAgentSkills(t)
	outside := filepath.Join(home, "elsewhere", "private-skill")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias-out")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	scan := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "alias-out", Path: link, Timestamp: time.Now()})
	if scan.calls != 0 || res.Verdict != VerdictBlocked {
		t.Fatalf("scans=%d verdict=%s reason=%s, want an unread refusal", scan.calls, res.Verdict, res.Reason)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the outside link stayed (lstat err %v)", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the link target changed: %v", err)
	}
}

// A flagged skill reached by a link under a symlinked ~/.claude is taken out
// by removing the link itself; the failed removal left a skill the agent kept loading.
func TestLinkedAgentRootRemovesAFlaggedSkillLink(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	_, root, physical := linkedAgentSkills(t)
	link := filepath.Join(root, "alias-bad")
	if err := os.Symlink(filepath.Join(root, "benign"), link); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{{
			ID: "finding", RuleID: "TRUST-IGNORE-PREVIOUS", Severity: scanner.SeverityCritical, Title: "critical finding",
		}}}
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "alias-bad", Path: link, Timestamp: time.Now()})
	if res.Verdict != VerdictRejected {
		t.Fatalf("verdict=%s reason=%s, want the flagged link rejected", res.Verdict, res.Reason)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the flagged link stayed (lstat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(physical, "benign", "SKILL.md")); err != nil {
		t.Fatalf("the link target changed: %v", err)
	}
}
