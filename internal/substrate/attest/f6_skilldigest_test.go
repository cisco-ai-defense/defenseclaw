// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0164: the build records the content digest of each skill folder it
// admits, the same digest the gateway computes from the files the kit
// attaches; a blocked folder gets none.
func TestBuildRecordsAdmittedSkillDigests(t *testing.T) {
	good := "---\nname: good\n---\nformat code"
	f := newFixture(t,
		tarFile{path: "/home/agent/.claude/skills/good/SKILL.md", mode: 0o644, data: good},
		tarFile{path: "/home/agent/.claude/skills/good/lib/run.sh", mode: 0o644, data: "echo fmt"},
		tarFile{path: "/home/agent/.claude/skills/bad/SKILL.md", mode: 0o644, data: malicious})
	res, err := f.build(t, func(o *BuildOptions) { o.BlockAtOrAbove = FloorNone; o.DryRun = true })
	var report *ScanReport
	var blocked *BuildBlocked
	switch {
	case errors.As(err, &blocked):
		report = blocked.Report
	case err != nil:
		t.Fatal(err)
	default:
		report = res.Report
	}
	want := SkillFolderDigest(map[string][]byte{"SKILL.md": []byte(good), "lib/run.sh": []byte("echo fmt")})
	for _, it := range report.Summary.Items {
		switch it.Name {
		case "good":
			if it.Digest != want {
				t.Errorf("good: digest %q, want %q", it.Digest, want)
			}
		case "bad":
			if it.Verdict == VerdictBlock && it.Digest != "" {
				t.Errorf("a blocked folder has a digest")
			}
		}
	}
}

func TestSkillFolderDigest(t *testing.T) {
	a := SkillFolderDigest(map[string][]byte{"SKILL.md": []byte("x"), "a/b.txt": []byte("y")})
	if a == "" || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("digest %q", a)
	}
	if b := SkillFolderDigest(map[string][]byte{"SKILL.md": []byte("x"), "a/b.txt": []byte("z")}); b == a {
		t.Fatal("content change kept the digest")
	}
	if b := SkillFolderDigest(map[string][]byte{"SKILL.md": []byte("x"), "a/c.txt": []byte("y")}); b == a {
		t.Fatal("rename kept the digest")
	}
	for name, m := range map[string]map[string][]byte{
		"empty": {}, "too deep": {"a/b/c/d/e.txt": []byte("x")}, "climbs": {"../x": []byte("x")}, "absolute": {"/x": []byte("x")},
	} {
		if d := SkillFolderDigest(m); d != "" {
			t.Errorf("%s: %q", name, d)
		}
	}
	many := map[string][]byte{}
	for i := 0; i <= SkillDigestMaxFiles; i++ {
		many[strings.Repeat("f", i+1)] = []byte("x")
	}
	if SkillFolderDigest(many) != "" {
		t.Error("more files than the kit attaches still has a digest")
	}
	// The materialized-folder form equals the map form.
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "a"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "a", "b.txt"), []byte("y"), 0o600)
	if got := localSkillDigest(dir); got != a {
		t.Fatalf("localSkillDigest %q, want %q", got, a)
	}
}
