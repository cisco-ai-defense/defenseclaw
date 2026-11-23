// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSkillFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func mustHashSkill(t *testing.T, root string) string {
	t.Helper()
	hash, status, _ := hashSkillFolder(root, maxSkillBytes)
	if status != SkillContentOK || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hashSkillFolder(%s) = %q, %q", root, hash, status)
	}
	return hash
}

func TestHashSkillFolderCoversEveryFileAndIsPortable(t *testing.T) {
	files := map[string]string{
		"SKILL.md":       "---\nname: pdf\n---\nUse the tool.\n",
		"scripts/run.py": "print('hi')\n",
		"bin/tool":       "\x7fELF\x00\x01\x02",
	}
	first, second := t.TempDir(), t.TempDir()
	writeSkillFiles(t, first, files)
	writeSkillFiles(t, second, files)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(second, "bin", "tool"), old, old); err != nil {
		t.Fatal(err)
	}
	base := mustHashSkill(t, first)
	const fixtureHash = "sha256:6c07b27b069204c825f104dfdb22c2a716934ed5bbbb4049488d0519a7fde7d1"
	if base != fixtureHash {
		t.Fatalf("fixture hash = %s, want %s", base, fixtureHash)
	}
	if got := mustHashSkill(t, second); got != base {
		t.Fatalf("same files in another folder with other times: %s != %s", got, base)
	}

	// Files that change without the skill changing do not move the hash.
	writeSkillFiles(t, second, map[string]string{".DS_Store": "x", ".git/HEAD": "ref", "Thumbs.db": "x"})
	if got := mustHashSkill(t, second); got != base {
		t.Fatal("OS metadata or .git changed the hash")
	}

	for name, change := range map[string]map[string]string{
		"binary byte": {"bin/tool": "\x7fELF\x00\x01\x03"},
		"new script":  {"scripts/extra.sh": "echo"},
		"manifest":    {"SKILL.md": "---\nname: pdf\n---\nUse it.\n"},
	} {
		dir := t.TempDir()
		writeSkillFiles(t, dir, files)
		writeSkillFiles(t, dir, change)
		if mustHashSkill(t, dir) == base {
			t.Fatalf("%s did not change the hash", name)
		}
	}
	renamed := t.TempDir()
	writeSkillFiles(t, renamed, map[string]string{
		"SKILL.md": files["SKILL.md"], "scripts/main.py": files["scripts/run.py"], "bin/tool": files["bin/tool"],
	})
	if mustHashSkill(t, renamed) == base {
		t.Fatal("renaming a file did not change the hash")
	}
}

func TestHashSkillFolderNeverFollowsLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	skill := t.TempDir()
	writeSkillFiles(t, skill, map[string]string{"SKILL.md": "x"})
	if err := os.Symlink(outside, filepath.Join(skill, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(skill, "linked-directory")); err != nil {
		t.Fatal(err)
	}
	base := mustHashSkill(t, skill)
	if err := os.WriteFile(outside, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mustHashSkill(t, skill) != base {
		t.Fatal("the hash read through a link")
	}

	linkedSkill := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(skill, linkedSkill); err != nil {
		t.Fatal(err)
	}
	if hash, status, _ := hashSkillFolder(linkedSkill, maxSkillBytes); hash != "" || status != SkillContentSymlink {
		t.Fatalf("linked skill folder = %q, %q", hash, status)
	}
}

func TestHashSkillFolderLimits(t *testing.T) {
	for name, mkEntry := range map[string]func(string) error{
		"files":         func(path string) error { return os.WriteFile(path, nil, 0o600) },
		"empty folders": func(path string) error { return os.Mkdir(path, 0o700) },
	} {
		many := t.TempDir()
		for i := 0; i <= maxSkillEntries; i++ {
			if err := mkEntry(filepath.Join(many, fmt.Sprintf("e%04d", i))); err != nil {
				t.Fatal(err)
			}
		}
		if _, status, _ := hashSkillFolder(many, maxSkillBytes); status != SkillContentTooLarge {
			t.Fatalf("%d %s: status %q", maxSkillEntries+1, name, status)
		}
	}

	big := t.TempDir()
	file, err := os.Create(filepath.Join(big, "model.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxSkillBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, status, _ := hashSkillFolder(big, maxSkillBytes); status != SkillContentTooLarge {
		t.Fatalf("oversized file: status %q", status)
	}

	if _, status, _ := hashSkillFolder(filepath.Join(big, "missing"), maxSkillBytes); status != SkillContentUnreadable {
		t.Fatalf("missing folder: status %q", status)
	}
}

func TestHashSkillFolderRejectsRegularFileRoot(t *testing.T) {
	root := t.TempDir()
	writeSkillFiles(t, root, map[string]string{"skill.txt": "skill data"})
	if hash, status, read := hashSkillFolder(filepath.Join(root, "skill.txt"), maxSkillBytes); hash != "" || status != SkillContentUnreadable || read != 0 {
		t.Fatalf("file root: hash %q, status %q, read %d", hash, status, read)
	}
}

func TestHashSkillFolderExclusionsHaveSeparateTraversalLimit(t *testing.T) {
	root := t.TempDir()
	for i := range maxSkillEntries {
		writeSkillFiles(t, root, map[string]string{fmt.Sprintf("entry-%d", i): ""})
	}
	base := mustHashSkill(t, root)
	writeSkillFiles(t, root, map[string]string{".DS_Store": "metadata", ".git/HEAD": "ref"})
	if got := mustHashSkill(t, root); got != base {
		t.Fatal("excluded entries changed an exact-limit folder hash")
	}

	root = t.TempDir()
	for i := 0; i <= maxSkillVisitedEntries/5; i++ {
		folder := filepath.Join(root, fmt.Sprintf("folder-%d", i))
		writeSkillFiles(t, folder, map[string]string{
			".DS_Store": "", "Thumbs.db": "", "desktop.ini": "", ".git/HEAD": "",
		})
	}
	if hash, status, read := hashSkillFolder(root, maxSkillBytes); hash != "" || status != SkillContentTooLarge || read != 0 {
		t.Fatalf("metadata-only walk above visit limit: hash %q, status %q, read %d", hash, status, read)
	}
}

func TestHashSkillFolderReadBudget(t *testing.T) {
	root := t.TempDir()
	writeSkillFiles(t, root, map[string]string{"SKILL.md": "abc", "notes.txt": "def"})
	for _, tc := range []struct {
		limit  int64
		read   int64
		status string
	}{
		{limit: -1, status: SkillContentTooLarge},
		{limit: 0, status: SkillContentTooLarge},
		{limit: 5, read: 3, status: SkillContentTooLarge},
		{limit: 6, read: 6, status: SkillContentOK},
	} {
		hash, status, read := hashSkillFolder(root, tc.limit)
		if status != tc.status || read != tc.read || (hash != "") != (status == SkillContentOK) {
			t.Errorf("limit %d: hash %q, status %q, read %d", tc.limit, hash, status, read)
		}
	}
}

func TestDetectSkillsAttachesFactsOncePerFolder(t *testing.T) {
	home := t.TempDir()
	writeSkillFiles(t, filepath.Join(home, ".agents", "skills", "pdf"), map[string]string{
		"SKILL.md": "---\nname: pdf\n---\n",
	})
	catalog := []AISignature{
		{ID: "codex", Vendor: "OpenAI", Category: SignalSupportedConnector, SupportedConnector: "codex", SkillPaths: []string{"~/.agents/skills"}},
		{ID: "cursor", Vendor: "Anysphere", Category: SignalSupportedConnector, SupportedConnector: "cursor", SkillPaths: []string{"~/.agents/skills"}},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)

	var facts []*AISkillFacts
	for _, signal := range svc.detectSkills() {
		for _, ev := range signal.Evidence {
			if ev.Type == "skill_entry" {
				facts = append(facts, ev.Skill)
			}
		}
	}
	if len(facts) != 2 || facts[0] == nil || facts[1] == nil || facts[0] == facts[1] {
		t.Fatalf("want two separate fact rows, got %+v", facts)
	}
	want := AISkillFacts{ContentHash: mustHashSkill(t, filepath.Join(home, ".agents", "skills", "pdf")), ContentStatus: SkillContentOK}
	if *facts[0] != want || *facts[1] != want {
		t.Fatalf("facts = %+v / %+v, want %+v", *facts[0], *facts[1], want)
	}
	if svc.skillFactsSeen != nil {
		t.Fatal("the per-scan cache outlived the scan")
	}

	// A spent scan budget stops reading instead of hashing more user files.
	svc.skillBytesRead = maxSkillScanBytes
	if got := svc.skillFacts(filepath.Join(home, ".agents", "skills", "pdf")); got.ContentStatus != SkillContentTooLarge {
		t.Fatalf("over the scan budget: %+v", got)
	}
}

func TestValidateSkillFactsRejectsForgedFields(t *testing.T) {
	good := AISkillFacts{ContentHash: "sha256:" + strings.Repeat("a", 64), ContentStatus: SkillContentOK}
	if err := validateSkillFacts(good); err != nil {
		t.Fatalf("valid facts: %v", err)
	}
	for name, mutate := range map[string]func(*AISkillFacts){
		"keyed hash":   func(f *AISkillFacts) { f.ContentHash = "hmac-sha256:" + strings.Repeat("a", 64) },
		"short hash":   func(f *AISkillFacts) { f.ContentHash = "sha256:abc" },
		"hash, not ok": func(f *AISkillFacts) { f.ContentStatus = SkillContentTooLarge },
		"status":       func(f *AISkillFacts) { f.ContentStatus = "fine" },
	} {
		facts := good
		mutate(&facts)
		if validateSkillFacts(facts) == nil {
			t.Errorf("%s: accepted %+v", name, facts)
		}
	}
}
