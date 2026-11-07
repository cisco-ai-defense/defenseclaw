// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeContentFile(t *testing.T, dir, rel, text string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// GAP-0699, GAP-0701: the text of a folder travels in the hook fact within
// bounds, nearest files first, without links, and its digest is recomputed.
func TestReadContentIsBoundedAndSurvivesTheHeader(t *testing.T) {
	dir := t.TempDir()
	writeContentFile(t, dir, "SKILL.md", "# Notes\nordinary\n")
	writeContentFile(t, dir, "deep/a/b/c/d/e.md", "too deep")
	writeContentFile(t, dir, "tool.exe", "binary-ish")
	writeContentFile(t, dir, "big.md", strings.Repeat("x", maxContentFile+10))
	content, ok := ReadContent(ContentSkill, "notes", dir)
	if !ok || len(content.Files) == 0 || content.Files[0].Rel != "SKILL.md" {
		t.Fatalf("content = %+v ok=%v, want SKILL.md first", content, ok)
	}
	if !content.Truncated {
		t.Fatalf("content = %+v, want a truncated flag for the too-deep folder and the file over the bound", content)
	}
	for _, file := range content.Files {
		if file.Rel == "tool.exe" || strings.Contains(file.Rel, "deep") {
			t.Fatalf("content holds %q, outside the bounds", file.Rel)
		}
	}
	got, ok := Decode(Encode(Facts{Contents: []Content{content}}))
	if !ok || len(got.Contents) != 1 || got.Contents[0].Digest != ContentDigest(got.Contents[0].Files) {
		t.Fatalf("round trip = %+v ok=%v, want one content with a recomputed digest", got, ok)
	}
	forged := content
	forged.Digest = strings.Repeat("0", 64)
	if got, _ := Decode(Encode(Facts{Contents: []Content{forged}})); got.Contents[0].Digest == forged.Digest {
		t.Fatal("a claimed digest was kept")
	}
	if _, ok := ReadContent(ContentSkill, "missing", filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing folder read as content")
	}
}

func TestClaudePluginRootsReadTheRegistry(t *testing.T) {
	claude := t.TempDir()
	root := filepath.Join(t.TempDir(), "r109kit")
	writeContentFile(t, claude, "plugins/installed_plugins.json",
		`{"plugins":{"r109kit@r109mkt":[{"installPath":`+jsonQuote(root)+`}],"other@m":{"installPath":"relative"}}}`)
	if got := ClaudePluginRoots(claude, "r109kit"); len(got) != 1 || got[0] != filepath.Clean(root) {
		t.Fatalf("roots = %v, want %s", got, root)
	}
	if got := ClaudePluginRoots(claude, "other"); len(got) != 0 {
		t.Fatalf("a relative install path was accepted: %v", got)
	}
	if got := ClaudePluginNames(claude); len(got) != 2 {
		t.Fatalf("names = %v", got)
	}
}

func jsonQuote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }
