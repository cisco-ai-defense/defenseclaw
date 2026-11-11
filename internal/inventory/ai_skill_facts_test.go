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
	want := AISkillFacts{
		ContentHash: mustHashSkill(t, filepath.Join(home, ".agents", "skills", "pdf")), ContentStatus: SkillContentOK,
		Scope: SkillScopeUser, Location: "~/.agents/skills/pdf",
	}
	if *facts[0] != want || *facts[1] != want {
		t.Fatalf("facts = %+v / %+v, want %+v", *facts[0], *facts[1], want)
	}
	if svc.skillFactsSeen != nil {
		t.Fatal("the per-scan cache outlived the scan")
	}

	// A spent scan budget stops reading instead of hashing more user files.
	svc.skillBytesRead = maxSkillScanBytes
	if got := svc.skillFacts(filepath.Join(home, ".agents", "skills", "pdf"), false); got.ContentStatus != SkillContentTooLarge {
		t.Fatalf("over the scan budget: %+v", got)
	}
}

func TestDetectSkillsSyncedAndManagedFolders(t *testing.T) {
	home, managed := t.TempDir(), t.TempDir()
	skills := filepath.Join(home, ".claude", "skills")
	writeSkillFiles(t, skills, map[string]string{
		"pdf/SKILL.md":                     "---\nname: pdf\n---\n",
		"synced/account-1/review/SKILL.md": "---\nname: review\n---\n",
	})
	writeSkillFiles(t, managed, map[string]string{"policy/SKILL.md": "---\nname: policy\n---\n"})
	writeSkillFiles(t, filepath.Join(home, "work", "app"), map[string]string{".cursor/skills/lint/SKILL.md": "x"})
	catalog := []AISignature{
		// The same folder named twice is scanned once.
		{ID: "claudecode", Category: SignalSupportedConnector, SupportedConnector: "claudecode", SkillPaths: []string{"~/.claude/skills", skills, managed}},
		{ID: "cursor", Category: SignalSupportedConnector, SupportedConnector: "cursor", SkillPaths: []string{"~/.claude/skills", ".cursor/skills"}},
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
		ScanRoots: []string{filepath.Join(home, "work", "app")},
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)

	got := map[string][]string{}
	for _, signal := range svc.detectSkills() {
		for _, ev := range signal.Evidence {
			if strings.Contains(fmt.Sprint(signal.Basenames, ev.Basename), "account-1") {
				t.Fatalf("the synced account id left the endpoint: %v %+v", signal.Basenames, ev)
			}
		}
		for _, ev := range signal.Evidence {
			if ev.Type == "skill_entry" {
				got[signal.SignatureID] = append(got[signal.SignatureID], ev.Basename+"="+ev.Skill.Scope+":"+ev.Skill.Location)
			}
		}
	}
	want := map[string][]string{
		// The account id and a repository's path stay on the endpoint.
		"claudecode": {"pdf=user:~/.claude/skills/pdf", "review=user:~/.claude/skills/synced/review", "policy=managed:"},
		"cursor":     {"pdf=user:~/.claude/skills/pdf", "lint=project:"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("skills = %v, want %v", got, want)
	}
}

func TestValidateSkillFactsRejectsForgedFields(t *testing.T) {
	good := AISkillFacts{ContentHash: "sha256:" + strings.Repeat("a", 64), ContentStatus: SkillContentOK, Scope: SkillScopeUser, Location: "~/.claude/skills/x"}
	if err := validateSkillFacts(good); err != nil {
		t.Fatalf("valid facts: %v", err)
	}
	for name, mutate := range map[string]func(*AISkillFacts){
		"keyed hash":    func(f *AISkillFacts) { f.ContentHash = "hmac-sha256:" + strings.Repeat("a", 64) },
		"short hash":    func(f *AISkillFacts) { f.ContentHash = "sha256:abc" },
		"hash, not ok":  func(f *AISkillFacts) { f.ContentStatus = SkillContentTooLarge },
		"status":        func(f *AISkillFacts) { f.ContentStatus = "fine" },
		"scope":         func(f *AISkillFacts) { f.Scope = "system" },
		"absolute path": func(f *AISkillFacts) { f.Location = "/Users/alice/.claude/skills/x" },
		"control char":  func(f *AISkillFacts) { f.Location = "~/x\n" },
	} {
		facts := good
		mutate(&facts)
		if validateSkillFacts(facts) == nil {
			t.Errorf("%s: accepted %+v", name, facts)
		}
	}
}
