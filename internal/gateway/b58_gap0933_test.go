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

package gateway

import (
	"strings"
	"testing"
)

// GAP-0933 (RV3-C): skill_archive finds a zip, rar or 7z anywhere in a file
// (a script with a zip appended, a self-extracting archive), the other
// archive and compression formats by their leading bytes, and archive file
// names of binary files (GAP-0981: a text file is not one by its name or a
// short magic); plain files stay clean.
func TestB58SkillArchiveDetection(t *testing.T) {
	dir := "/sandbox/.claude/skills/evil"
	hit := map[string]struct{ name, body string }{
		"prefixed-zip":     {"payload.bin", "#!/bin/sh\nexit 0\nPK\x03\x04rest"},
		"zip-central-only": {"payload.bin", "junk PK\x01\x02 more"},
		"zip-eocd-only":    {"payload.bin", "junk PK\x05\x06 end"},
		"rar":              {"payload.bin", "Rar!\x1a\x07\x00rest"},
		"rar-in-sfx":       {"setup.bin", "MZ....Rar!\x1a\x07\x01\x00rest"},
		"7z-in-sfx":        {"setup.bin", "MZ....7z\xbc\xaf\x27\x1crest"},
		"lz4":              {"data.bin", "\x04\x22\x4d\x18rest"},
		"lzma":             {"data.bin", "\x5d\x00\x00\x80\x00rest"},
		"cpio":             {"data.bin", "070701" + strings.Repeat("0", 104) + "rest"},
		"cpio-binary":      {"data.bin", "070701\xff\x00rest"},
		"ar":               {"data.bin", "!<arch>\nrest"},
		"gzip":             {"data.bin", "\x1f\x8brest"},
		"tar":              {"data.bin", strings.Repeat("\x00", 257) + "ustar\x0000"},
		"ext-tgz":          {"vendor/lib.tgz", "\x00not really"},
		"ext-whl":          {"pkg.whl", "\x00x"},
		"ext-tar.zst":      {"a.tar.zst", "\x00x"},
		"ext-upper":        {"A.ZIP", "\x00x"},
	}
	for name, c := range hit {
		got := skillArchiveFile(dir, []SubstrateAttachedFile{{Path: dir + "/SKILL.md", Content: []byte("---\nname: evil\n---\n")}, {Path: dir + "/" + c.name, Content: []byte(c.body)}})
		if got != c.name {
			t.Errorf("%s: skillArchiveFile = %q, want %q", name, got, c.name)
		}
	}
	clean := map[string]string{
		"SKILL.md":  "---\nname: evil\n---\nUse PK and Rar! and 7z in prose; BZh is a word.",
		"run.sh":    "#!/bin/sh\necho zip",
		"notes.txt": "the archive.zip is downloaded later",
		"bzh.txt":   "BZhello",
		"script.py": "print('070701')",
		"Makefile":  "all:\n\techo ok",
	}
	var files []SubstrateAttachedFile
	for n, b := range clean {
		files = append(files, SubstrateAttachedFile{Path: dir + "/" + n, Content: []byte(b)})
	}
	if got := skillArchiveFile(dir, files); got != "" {
		t.Fatalf("plain files flagged as an archive: %q", got)
	}
}
