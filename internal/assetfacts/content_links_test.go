// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
}

// GAP-0699, GAP-0701: a skill installed as a link is read through, as the
// agent reads it, so its text is judged; a link that leads nowhere readable
// marks the content as not read in full.
func TestReadContentReadsThroughLinksAndMarksTheOthers(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "shared", "np10")
	writeContentFile(t, target, "SKILL.md", "# np10\nshared skill\n")
	linkedDir := filepath.Join(base, "skills", "np10")
	if err := os.MkdirAll(filepath.Dir(linkedDir), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, target, linkedDir)
	content, ok := ReadContent(ContentSkill, "np10", linkedDir)
	if !ok || content.Truncated || len(content.Files) != 1 || content.Files[0].Text != "# np10\nshared skill\n" {
		t.Fatalf("linked folder = %+v ok=%v, want its text read in full", content, ok)
	}
	if content.Dir != filepath.Clean(linkedDir) {
		t.Fatalf("dir = %q, want the path the agent names", content.Dir)
	}

	dir := filepath.Join(base, "skills", "np11")
	writeContentFile(t, dir, "notes.md", "ordinary\n")
	outside := filepath.Join(base, "instructions.md")
	writeContentFile(t, base, "instructions.md", "linked text\n")
	symlinkOrSkip(t, outside, filepath.Join(dir, "SKILL.md"))
	content, _ = ReadContent(ContentSkill, "np11", dir)
	if content.Truncated || len(content.Files) != 2 || content.Files[0].Rel != "SKILL.md" || content.Files[0].Text != "linked text\n" {
		t.Fatalf("linked SKILL.md = %+v, want the linked text read in full", content)
	}

	// A dangling link, or a link to a folder, is not read in full.
	for name, link := range map[string]string{"dangling": filepath.Join(base, "nowhere"), "folder": filepath.Join(base, "shared")} {
		dir := filepath.Join(base, "skills", "np12-"+name)
		writeContentFile(t, dir, "SKILL.md", "# np12\n")
		symlinkOrSkip(t, link, filepath.Join(dir, "extra.md"))
		if content, _ := ReadContent(ContentSkill, "np12", dir); !content.Truncated {
			t.Fatalf("%s link: content = %+v, want it marked not read in full", name, content)
		}
	}
}

// An ordinary large reference file is read in full; one past the bound is
// marked, so a verdict on the part sent is never taken for the whole.
func TestReadContentBoundIsExplicit(t *testing.T) {
	dir := t.TempDir()
	writeContentFile(t, dir, "SKILL.md", "# big\n")
	writeContentFile(t, dir, "reference.md", strings.Repeat("ordinary reference line\n", 1500))
	if content, _ := ReadContent(ContentSkill, "big", dir); content.Truncated || len(content.Files) != 2 {
		t.Fatalf("a 36 KiB reference file was cut: truncated=%v files=%d", content.Truncated, len(content.Files))
	}
	writeContentFile(t, dir, "huge.md", strings.Repeat("a", maxContentFile+1))
	if content, _ := ReadContent(ContentSkill, "big", dir); !content.Truncated {
		t.Fatal("a file past the bound was not marked")
	}
}

// Text that does not fit one header is sent as contents without text, marked
// not read in full, never dropped: dropping them would leave the gateway with
// no fact to refuse on.
func TestEncodeKeepsOversizedContentAsTruncated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "np10")
	// Text that deflates to nothing fits a header; this does not shrink, and
	// it fills the text budget of one claim, and the largest MCP definition
	// adds its digests.
	contents := printableContents(47)
	got, ok := Decode(Encode(Facts{SkillDirs: []string{dir}, Contents: contents, MCP: largestMCPServer()}))
	if !ok || len(got.Contents) != len(contents) || len(got.SkillDirs) != 1 {
		t.Fatalf("oversized contents = %+v ok=%v, want the dirs and every content kept", got, ok)
	}
	for _, content := range got.Contents {
		if !content.Truncated || len(content.Files) != 0 {
			t.Fatalf("content %q = %+v, want it marked truncated without text", content.Name, content)
		}
	}
	small, _ := Decode(Encode(Facts{Contents: contents[:1]}))
	if len(small.Contents) != 1 || len(small.Contents[0].Files) == 0 {
		t.Fatalf("a content that fits lost its text: %+v", small)
	}
}
