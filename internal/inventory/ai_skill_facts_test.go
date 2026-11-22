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
	hash, status, _, _ := hashSkillFolder(root, maxSkillBytes)
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
	if hash, status, _, _ := hashSkillFolder(linkedSkill, maxSkillBytes); hash != "" || status != SkillContentSymlink {
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
		if _, status, _, _ := hashSkillFolder(many, maxSkillBytes); status != SkillContentTooLarge {
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
	if _, status, _, _ := hashSkillFolder(big, maxSkillBytes); status != SkillContentTooLarge {
		t.Fatalf("oversized file: status %q", status)
	}

	if _, status, _, _ := hashSkillFolder(filepath.Join(big, "missing"), maxSkillBytes); status != SkillContentUnreadable {
		t.Fatalf("missing folder: status %q", status)
	}
}

func TestSkillFrontMatterAuthor(t *testing.T) {
	for manifest, want := range map[string]string{
		"---\nname: a\nauthor: Acme Corp\n---\n":               "Acme Corp",
		"---\nname: a\nauthor: \"Acme # Labs\"\n---\n":         "Acme # Labs",
		"---\nmetadata:\n  author: Jane Doe # owner\n---\n":    "Jane Doe",
		"---\nother:\n  author: not-metadata\n---\n":           "",
		"---\nname: a\n---\nauthor: after the frontmatter\n":   "",
		"no frontmatter\nauthor: x\n":                          "",
		"\ufeff---\r\nauthor: Windows Line Endings\r\n---\r\n": "Windows Line Endings",
		"---\nauthor: bad\x07bell\n---\n":                      "",
		"---\nauthor: " + strings.Repeat("é", 100) + "\n---\n": strings.Repeat("é", maxSkillAuthorBytes/2),
	} {
		if got := parseSkillFrontMatter([]byte(manifest)).author; got != want {
			t.Errorf("author of %q = %q, want %q", manifest, got, want)
		}
	}
}

func TestSkillFrontMatterDescriptionAndVersion(t *testing.T) {
	long := strings.Repeat("word ", 200)
	for _, tc := range []struct {
		manifest, description, version string
	}{
		{"---\nname: a\ndescription: Review a pull request. Use before merge.\nversion: 2.3.0\n---\n", "Review a pull request. Use before merge.", "2.3.0"},
		{"---\nname: a\nmetadata:\n  version: \"1.4\" # pinned\n  description: not top level\n---\n", "", "1.4"},
		{"---\ndescription: >-\n  Folded over\n  two lines.\n\n  And a second paragraph.\nversion: 3\n---\n", "Folded over two lines. And a second paragraph.", "3"},
		{"---\ndescription: |\n  keep # this\n  literal\nname: a\n---\n", "keep # this literal", ""},
		{"---\ndescription: A plain value\n  wrapped onto a second line # not a comment\nname: a\n---\n", "A plain value wrapped onto a second line # not a comment", ""},
		{"---\ndescription: \"A quoted value\n  that wraps\"\n---\n", "A quoted value that wraps", ""},
		{"---\ndescription: first\ndescription: second\n---\n", "first", ""},
		{"---\ndescription:\n  nested: map\n---\n", "", ""},
		{"---\ndescription: tab\there\n---\n", "tab here", ""},
		{"---\ndescription: bad\x07bell\nversion: 1\x1b[0m\n---\n", "", ""},
		{"---\ndescription: " + long + "\n---\n", strings.TrimSpace(long[:maxSkillDescriptionBytes]), ""},
		{"---\nversion: " + strings.Repeat("9", 100) + "\n---\n", "", strings.Repeat("9", maxSkillVersionBytes)},
		{"---\nname: a\n---\ndescription: after the frontmatter\n", "", ""},
		{"\ufeff---\r\ndescription: CRLF\r\n  wrapped\r\nversion: 1.0\r\n---\r\n", "CRLF wrapped", "1.0"},
	} {
		got := parseSkillFrontMatter([]byte(tc.manifest))
		if got.description != tc.description || got.version != tc.version {
			t.Errorf("front matter of %q = (%q, %q), want (%q, %q)", tc.manifest, got.description, got.version, tc.description, tc.version)
		}
	}
}

func TestSkillFrontMatterLongValues(t *testing.T) {
	for _, tc := range []struct {
		name, header, invalidSuffix string
	}{
		{"literal block", "description: |", ""},
		{"folded block", "description: >-", ""},
		{"wrapped plain", "description: é x", ""},
		{"late control", "description: |", "  bad\x07bell\n"},
		{"late invalid UTF-8", "description: é x", "  bad\xfftext\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := []byte("---\n" + tc.header + "\n" + strings.Repeat("  é x\n", 6000) + tc.invalidSuffix +
				"description: ignored duplicate\nmetadata:\n  author: Example Author\n  version: 1.2.3\n---\n")
			want := skillFrontMatter{
				author: "Example Author", version: "1.2.3",
				description: strings.TrimSpace(strings.Repeat("é x ", 200)[:maxSkillDescriptionBytes]),
			}
			if tc.invalidSuffix != "" {
				want.description = ""
			}
			if got := parseSkillFrontMatter(manifest); got != want {
				t.Fatalf("long frontmatter = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSkillFrontMatterLongValueAllocations(t *testing.T) {
	for name, header := range map[string]string{
		"block":   "description: |",
		"wrapped": "description: first",
	} {
		t.Run(name, func(t *testing.T) {
			manifest := []byte("---\n" + header + "\n" + strings.Repeat("  x\n", 16300) + "---\n")
			// A bounded manifest must not allocate a new growing string for
			// each line. Leave room for linear buffering and normalization.
			if allocations := testing.AllocsPerRun(1, func() {
				_ = parseSkillFrontMatter(manifest)
			}); allocations > 128 {
				t.Fatalf("long frontmatter allocated %.0f times, want at most 128", allocations)
			}
		})
	}
}

func BenchmarkSkillFrontMatterLongValue(b *testing.B) {
	for _, tc := range []struct {
		name  string
		lines int
	}{
		{"4KiB", 1024},
		{"64KiB", 16300},
	} {
		b.Run(tc.name, func(b *testing.B) {
			manifest := []byte("---\ndescription: |\n" + strings.Repeat("  x\n", tc.lines) + "---\n")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = parseSkillFrontMatter(manifest)
			}
		})
	}
}

func TestDetectSkillsAttachesFactsOncePerFolder(t *testing.T) {
	home := t.TempDir()
	writeSkillFiles(t, filepath.Join(home, ".agents", "skills", "pdf"), map[string]string{
		"SKILL.md": "---\nname: pdf\ndescription: Fill PDF forms\nversion: 1.2\n---\n",
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
		Scope: SkillScopeUser, Location: "~/.agents/skills/pdf", Description: "Fill PDF forms", Version: "1.2",
		ManifestHash: skillManifestHash([]byte("---\nname: pdf\ndescription: Fill PDF forms\nversion: 1.2\n---\n")), ManifestSize: 59,
	}
	if *facts[0] != want || *facts[1] != want {
		t.Fatalf("facts = %+v / %+v, want %+v", *facts[0], *facts[1], want)
	}
	if svc.skillFactsSeen != nil {
		t.Fatal("the per-scan cache outlived the scan")
	}

	// A spent scan budget stops reading instead of hashing more user files.
	// The folder is new to this scan, so it is not in the hash cache.
	svc.skillHashCache = nil
	svc.skillBytesRead = maxSkillScanBytes
	if got := svc.skillFacts(filepath.Join(home, ".agents", "skills", "pdf"), false); got.ContentStatus != SkillContentTooLarge {
		t.Fatalf("over the scan budget: %+v", got)
	}
}

func TestDetectSkillsSyncedAndManagedFolders(t *testing.T) {
	home, managed := t.TempDir(), t.TempDir()
	// The test folder stands for one an administrator owns.
	adminOwned := skillFolderManaged
	skillFolderManaged = func(path string) bool { return pathBelow(managed, path) || adminOwned(path) }
	t.Cleanup(func() { skillFolderManaged = adminOwned })
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

func TestSkillManifestIsReadBackByHash(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "pdf")
	body := "---\nname: pdf\n---\n" + strings.Repeat("x", maxSkillManifest) // longer than the author read
	writeSkillFiles(t, dir, map[string]string{"skill.md": body})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	facts := svc.skillFacts(dir, false)
	if got, ok := svc.SkillManifest(facts.ManifestHash); !ok || string(got) != body || facts.ManifestHash != skillManifestHash([]byte(body)) {
		t.Fatalf("manifest %q: %v, %d bytes", facts.ManifestHash, ok, len(got))
	}
	writeSkillFiles(t, dir, map[string]string{"skill.md": "edited"})
	if _, ok := svc.SkillManifest(facts.ManifestHash); ok {
		t.Fatal("an edited SKILL.md was returned for the old hash")
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
		"manifest hash": func(f *AISkillFacts) { f.ManifestHash = "md5:abc" },
		"hash, not ok":  func(f *AISkillFacts) { f.ContentStatus = SkillContentTooLarge },
		"status":        func(f *AISkillFacts) { f.ContentStatus = "fine" },
		"scope":         func(f *AISkillFacts) { f.Scope = "system" },
		"absolute path": func(f *AISkillFacts) { f.Location = "/Users/alice/.claude/skills/x" },
		"control char":  func(f *AISkillFacts) { f.Location = "~/x\n" },
		"long author":   func(f *AISkillFacts) { f.Author = strings.Repeat("a", maxSkillAuthorBytes+1) },
		"plugin id":     func(f *AISkillFacts) { f.Plugin = &AISkillPlugin{ID: "../x@y"} },
		"plugin text":   func(f *AISkillFacts) { f.Plugin = &AISkillPlugin{ID: "x@y", Author: "a\x07"} },
	} {
		facts := good
		mutate(&facts)
		if validateSkillFacts(facts) == nil {
			t.Errorf("%s: accepted %+v", name, facts)
		}
	}
}
