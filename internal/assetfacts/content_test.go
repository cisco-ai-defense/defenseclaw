// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
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

// Ordinary candidate owners of one tool name with tens of KiB of text each
// keep their text, and the encoded header stays within its bound.
func TestEncodeKeepsLargeOrdinaryCandidateOwnerText(t *testing.T) {
	text := strings.Repeat("Count the words in the file the user names and report the number.\n", 500)
	var contents []Content
	for c := 0; c < 8; c++ {
		contents = append(contents, Content{Kind: ContentPlugin, Name: fmt.Sprintf("p_%d", c), Dir: filepath.Join(t.TempDir(), "p"),
			Files: []ContentFile{{Rel: "skills/notes/SKILL.md", Text: text}}})
	}
	value := Encode(Facts{Contents: contents})
	if len(value) == 0 || len(value) > maxHeaderBytes {
		t.Fatalf("encoded header = %d bytes, want 1..%d", len(value), maxHeaderBytes)
	}
	got, ok := Decode(value)
	if !ok || len(got.Contents) != len(contents) {
		t.Fatalf("contents = %d ok=%v, want %d", len(got.Contents), ok, len(contents))
	}
	for _, content := range got.Contents {
		if content.Truncated || len(content.Files) != 1 || content.Files[0].Text != text {
			t.Errorf("content %q lost its text (truncated=%v files=%d)", content.Name, content.Truncated, len(content.Files))
		}
	}
}

// Every candidate owner of one tool name that fits the size budget keeps its
// text, however many there are; one that does not is kept as a truncated
// content without text.
func TestEncodeKeepsTextOfEveryContentWithinTheBudget(t *testing.T) {
	var contents []Content
	for c := 0; c < 12; c++ {
		contents = append(contents, Content{Kind: ContentPlugin, Name: fmt.Sprintf("p_%d", c), Dir: filepath.Join(t.TempDir(), "p"),
			Files: []ContentFile{{Rel: "SKILL.md", Text: "ordinary text"}}})
	}
	got, ok := Decode(Encode(Facts{Contents: contents}))
	if !ok || len(got.Contents) != len(contents) {
		t.Fatalf("contents = %d ok=%v, want %d", len(got.Contents), ok, len(contents))
	}
	for _, content := range got.Contents {
		if content.Truncated || len(content.Files) != 1 {
			t.Errorf("content %q lost its text: %+v", content.Name, content)
		}
	}
}
