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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	svc.skillClock = skillClockAfterTheWrites

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
	skillFolderManaged = func(dir *os.File, path string) bool { return pathBelow(managed, path) || adminOwned(dir, path) }
	adminEntry := skillEntryManaged
	skillEntryManaged = func(opened *os.File, path string) bool { return pathBelow(managed, path) || adminEntry(opened, path) }
	t.Cleanup(func() { skillFolderManaged, skillEntryManaged = adminOwned, adminEntry })
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
	body := "---\nname: pdf\nauthor: Example Team\ndescription: Review release changes\nversion: 2.1\n---\n" + strings.Repeat("x", maxSkillManifest) // longer than the frontmatter read
	writeSkillFiles(t, dir, map[string]string{"skill.md": body})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	facts := svc.skillFacts(dir, false)
	if facts == nil || facts.Author != "Example Team" || facts.Description != "Review release changes" || facts.Version != "2.1" || facts.ManifestSize != int64(len(body)) {
		t.Fatalf("large manifest metadata did not describe the full file: %+v", facts)
	}
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

func TestSkillManifestFullCaptureUsesOnlyTheRootLeaf(t *testing.T) {
	root := t.TempDir()
	body := "---\nname: complete\n---\n" + strings.Repeat("m", maxSkillManifest+17)
	nested := "---\nauthor: nested\n---\n"
	writeSkillFiles(t, root, map[string]string{
		"sKiLl.Md": body, "nested/SKILL.md": nested,
	})
	_, status, manifest, read := hashSkillFolderCapture(root, maxSkillBytes, maxSkillBytes)
	if status != SkillContentOK || string(manifest) != body || read != int64(len(body)+len(nested)) {
		t.Fatalf("full root capture: status %q, retained %d, read %d", status, len(manifest), read)
	}
}

func TestSkillManifestReadbackRejectsUnavailableOrOversizedLeaf(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "readback")
	body := "---\nname: readback\n---\nA complete manifest.\n"
	writeSkillFiles(t, dir, map[string]string{"skill.md": body})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	facts := svc.skillFacts(dir, false)
	if facts.ManifestHash == "" {
		t.Fatal("complete root manifest has no hash")
	}
	path := filepath.Join(dir, "skill.md")
	if err := os.Rename(path, filepath.Join(dir, "renamed.md")); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.SkillManifest(facts.ManifestHash); ok {
		t.Fatal("readback accepted a missing recorded leaf")
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxSkillBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.SkillManifest(facts.ManifestHash); ok {
		t.Fatal("readback accepted a manifest beyond its byte cap")
	}
	writeSkillFiles(t, dir, map[string]string{"skill.md": body})
	if data, ok := svc.SkillManifest(facts.ManifestHash); !ok || string(data) != body {
		t.Fatal("restored matching leaf could not be read back")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.SkillManifest(facts.ManifestHash); ok {
		t.Fatal("readback accepted a directory as a manifest")
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
		{"---\ndescription: A plain value\n  wrapped onto a second line # maintainer comment\nname: a\n---\n", "A plain value wrapped onto a second line", ""},
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

func TestSkillContentHashOptOutPreservesDiscovery(t *testing.T) {
	home := t.TempDir()
	skill := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, skill, map[string]string{"SKILL.md": "Read a PDF.\n"})
	catalog := []AISignature{{ID: "codex", Vendor: "OpenAI", Category: SignalSupportedConnector, SupportedConnector: "codex", SkillPaths: []string{"~/.agents/skills"}}}
	cfg := config.DefaultConfig()
	includeHashes := false
	cfg.AIDiscovery.IncludeSkillContentHashes = &includeHashes
	opts := AIDiscoveryOptionsFromConfig(cfg)
	opts.HomeDir, opts.HomeDirs, opts.DataDir = home, []string{home}, filepath.Join(home, "data")
	svc := NewContinuousDiscoveryServiceWithOptions(opts, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	if facts := svc.skillFacts(skill, false); facts != nil || svc.skillBytesRead != 0 || svc.skillFactsSeen != nil {
		t.Fatalf("disabled skill hashing attempted a read: facts %+v, bytes %d", facts, svc.skillBytesRead)
	}

	assertSkillWithoutFacts := func(signals []AISignal) {
		t.Helper()
		for _, signal := range signals {
			for _, ev := range signal.Evidence {
				if ev.Type == "skill_entry" && ev.Basename == "pdf" {
					if ev.Skill != nil {
						t.Fatalf("disabled skill hashing returned facts: %+v", ev.Skill)
					}
					return
				}
			}
		}
		t.Fatal("disabled hashing hid the discovered skill")
	}
	assertSkillWithoutFacts(svc.detectSkills())

	encoded, err := json.Marshal(UserScanOptionsFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var worker UserScanOptions
	if err := json.Unmarshal(encoded, &worker); err != nil || !worker.DisableSkillContentHashes {
		t.Fatalf("worker opt-out did not survive transport: %v", err)
	}
	assertSkillWithoutFacts(ScanUserHome(t.Context(), home, "test-user", 1000, worker, catalog).Signals)
	if !SandboxScanOptionsFromConfig(cfg).DisableSkillContentHashes {
		t.Fatal("sandbox scanner did not inherit the opt-out")
	}

	// Records from the previous scan can outlive a setting change.
	old := AISignal{Evidence: []AIEvidence{{Type: "skill_entry", Basename: "pdf", Skill: &AISkillFacts{
		ContentHash: mustHashSkill(t, skill), ContentStatus: SkillContentOK,
	}}}}
	assertSkillWithoutFacts([]AISignal{svc.attributeUserScanSignal(old, "1000", "test-user")})
	assertSkillWithoutFacts([]AISignal{svc.attributeSandboxSignal(old, "sandbox-id", "sandbox-name")})
}

func TestSkillFrontMatterKeepsMetadataDepthAndScalarBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, manifest string
		want           skillFrontMatter
	}{
		{"direct metadata", "---\nmetadata:\n  extra:\n    author: Inner\n    version: hidden\n  author: Outer\n  version: 2\n---\n", skillFrontMatter{author: "Outer", version: "2"}},
		{"indented delimiters", "---\ndescription: |\n  Before\n  ---\n  ...\n  After\nversion: 3\n---\n", skillFrontMatter{description: "Before --- ... After", version: "3"}},
		{"plain continuation comments", "---\ndescription: Review changes\n  carefully # maintainer note\n  # an entire comment\n  before release\nversion: 4\n---\n", skillFrontMatter{description: "Review changes carefully before release", version: "4"}},
		{"literal hashes", "---\ndescription: |\n  Keep # literal\nversion: 5\n---\n", skillFrontMatter{description: "Keep # literal", version: "5"}},
		{"quoted hashes", "---\ndescription: \"Keep\n  # quoted\"\n---\n", skillFrontMatter{description: "Keep # quoted"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSkillFrontMatter([]byte(tc.manifest)); got != tc.want {
				t.Fatalf("frontmatter = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSkillManifestIndexPreservesCurrentLookupsAtCapacity(t *testing.T) {
	home := t.TempDir()
	first, second := filepath.Join(home, "first"), filepath.Join(home, "second")
	writeSkillFiles(t, first, map[string]string{"SKILL.md": "first"})
	writeSkillFiles(t, second, map[string]string{"SKILL.md": "second"})
	hash := skillManifestHash([]byte("first"))
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}, skillManifests: map[string]string{hash: filepath.Join(first, "SKILL.md")}}
	for i := 1; i < maxSkillManifestFolders; i++ {
		svc.skillManifests[fmt.Sprintf("old-%d", i)] = "unused"
	}
	facts := svc.skillFacts(first, false)
	if facts.ManifestHash != hash || len(svc.skillManifests) != maxSkillManifestFolders {
		t.Fatal("refreshing a known manifest evicted the full index")
	}
	other := svc.skillFacts(second, false)
	if _, ok := svc.SkillManifest(hash); !ok || len(svc.skillManifests) != maxSkillManifestFolders {
		t.Fatal("a new hash at capacity evicted an existing lookup")
	}
	if _, ok := svc.skillManifests[other.ManifestHash]; ok {
		t.Fatal("manifest index exceeded its cap")
	}
	svc.beginSkillFactsScan()
	if svc.skillManifests != nil {
		t.Fatal("stale manifest paths survived the next scan reset")
	}
	svc.skillFacts(second, false)
	if got, ok := svc.SkillManifest(other.ManifestHash); !ok || string(got) != "second" {
		t.Fatal("next scan did not repopulate the current manifest")
	}
	svc.opts.DisableSkillContentHashes = true
	if _, ok := svc.SkillManifest(other.ManifestHash); ok {
		t.Fatal("disabled hashing allowed lazy body readback")
	}
}

func TestSkillManifestIndexSurvivesScanUntilReadback(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".agents", "skills", "review")
	writeSkillFiles(t, root, map[string]string{"SKILL.md": "first version"})
	svc := &ContinuousDiscoveryService{
		opts:    AIDiscoveryOptions{HomeDir: home},
		catalog: []AISignature{{ID: "codex", SkillPaths: []string{"~/.agents/skills"}}},
	}
	manifestHash := func() string {
		t.Helper()
		for _, signal := range svc.detectSkills() {
			for _, ev := range signal.Evidence {
				if ev.Skill != nil && ev.Skill.ManifestHash != "" {
					return ev.Skill.ManifestHash
				}
			}
		}
		t.Fatal("skill scan did not record a manifest hash")
		return ""
	}
	first := manifestHash()
	if body, ok := svc.SkillManifest(first); !ok || string(body) != "first version" {
		t.Fatal("scan cleanup discarded a manifest before managed readback")
	}
	writeSkillFiles(t, root, map[string]string{"SKILL.md": "second version"})
	second := manifestHash()
	if first == second {
		t.Fatal("changed manifest kept the old hash")
	}
	if _, ok := svc.skillManifests[first]; ok {
		t.Fatal("next scan retained a stale manifest lookup")
	}
	if body, ok := svc.SkillManifest(second); !ok || string(body) != "second version" {
		t.Fatal("next scan did not retain its current manifest")
	}
}
