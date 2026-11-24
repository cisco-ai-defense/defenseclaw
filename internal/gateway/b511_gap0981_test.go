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
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"image"
	"image/png"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

func b511Zip(t *testing.T, enc bool, members map[string]string) string {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate}
		if enc {
			h.Flags |= 0x1
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(members[n]))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func b511Tar(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(members[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(members[n]))
	}
	w.Close()
	return b.Bytes()
}

func b511Gz(body []byte) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(body)
	w.Close()
	return b.String()
}

func b511PNG() string {
	var b bytes.Buffer
	png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 16, 16)))
	return b.String()
}

// GAP-0981: the name rule and the short magics count only for binary files;
// a whole cpio ASCII header counts for any file.
func TestB511ArchiveTextIsNotAnArchive(t *testing.T) {
	dir := "/sandbox/.claude/skills/s"
	md := SubstrateAttachedFile{Path: dir + "/SKILL.md", Content: []byte("---\nname: s\n---\n")}
	one := func(name, body string) string {
		return skillArchiveFile(dir, []SubstrateAttachedFile{md, {Path: dir + "/" + name, Content: []byte(body)}})
	}
	for name, body := range map[string]string{
		"locales/messages.ar": "greeting = marhaba\n",
		"README.pt.br":        "Leia-me\n",
		"data/dates.csv":      "070701,first release\n080102,second\n",
		"old.csv":             "070707,x\n",
		"notes.zip":           "a text file with a zip name\n",
		"cut.br":              "caf\xc3", // a rune cut at the end of a cut file
	} {
		f := []SubstrateAttachedFile{md, {Path: dir + "/" + name, Content: []byte(body), Truncated: name == "cut.br"}}
		if got := skillArchiveFile(dir, f); got != "" {
			t.Errorf("text %s refused as skill_archive (%q)", name, got)
		}
	}
	cpio := "070701" + strings.Repeat("0", 104) + "TRAILER!!!"
	for name, body := range map[string]string{
		"locales/messages.ar": "\x00\x01binary\xff",
		"README.pt.br":        "\xff\xfe\x00b",
		"data.bin":            "\xc7\x71\x01\x00",
		"x.bin":               "BZh9\x31\x41\x59\x26\x53\x59\xff",
		"y.bin":               "070701\xff\x00",
		"z.cpio-ascii":        cpio,
	} {
		if got := one(name, body); got != name {
			t.Errorf("binary %s: skillArchiveFile = %q, want it refused", name, got)
		}
	}
}

// GAP-0981: a zip format or a tar the skill scanner opens and scans inside is
// not skill_archive when its name and content agree and it holds no archive
// the scanner leaves unopened.
func TestB511ArchiveTheScannerOpens(t *testing.T) {
	dir := "/sandbox/.claude/skills/s"
	md := SubstrateAttachedFile{Path: dir + "/SKILL.md", Content: []byte("---\nname: s\n---\n")}
	tarOK := b511Tar(t, map[string]string{"a.txt": "hello", "inner.zip": "x"})
	tarBad := b511Tar(t, map[string]string{"a.txt": "hello", "payload.7z": "x"})
	tarRar := b511Tar(t, map[string]string{"payload.rar": "x"})
	cases := []struct {
		name, body string
		trunc, hit bool
	}{
		{"tests/fixtures/sample.zip", b511Zip(t, false, map[string]string{"a.txt": "hello"}), false, false},
		{"templates/report.docx", b511Zip(t, false, map[string]string{"word/document.xml": "<w/>", "word/embeddings/Sheet.xlsx": "x"}), false, false},
		{"lib/tool.jar", b511Zip(t, false, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}), false, false},
		{"vendor/src.tar", string(tarOK), false, false},
		{"vendor/src.tar.gz", b511Gz(tarOK), false, false},
		{"vendor/src.tgz", b511Gz(tarOK), false, false},
		{"bad/payload-inside.zip", b511Zip(t, false, map[string]string{"x.7z": "x"}), false, true},
		{"bad/rar-inside.docx", b511Zip(t, false, map[string]string{"word/x.rar": "x"}), false, true},
		{"bad/encrypted.zip", b511Zip(t, true, map[string]string{"a.txt": "hello"}), false, true},
		{"bad/cut.zip", b511Zip(t, false, map[string]string{"a.txt": "hello"}), true, true},
		{"bad/not-a-zip.zip", "\x00\x01\x02binary", false, true},
		{"bad/zip-named-bin.bin", b511Zip(t, false, map[string]string{"a.txt": "hello"}), false, true},
		{"bad/7z-inside.tar", string(tarBad), false, true},
		{"bad/rar-inside.tgz", b511Gz(tarRar), false, true},
		{"bad/not-a-tar.tgz", b511Gz([]byte("plain text, no tar")), false, true},
		{"bad/xz.tar.xz", "\xfd7zXZ\x00rest", false, true},
	}
	for _, c := range cases {
		got := skillArchiveFile(dir, []SubstrateAttachedFile{md, {Path: dir + "/" + c.name, Content: []byte(c.body), Truncated: c.trunc}})
		if (got != "") != c.hit {
			t.Errorf("%s: skillArchiveFile = %q, want refused=%v", c.name, got, c.hit)
		}
	}
}

// b511Scanner records what it scanned and blocks a folder with the marker.
type b511Scanner struct {
	mu   sync.Mutex
	seen map[string][]string
}

func (s *b511Scanner) ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var paths []string
	for _, f := range files {
		paths = append(paths, strings.TrimPrefix(f.Path, dir+"/"))
		if bytes.Contains(f.Content, []byte("B511-BLOCK-MARKER")) {
			return true, "marker found in " + f.Path, nil
		}
	}
	sort.Strings(paths)
	s.seen[dir] = paths
	return false, "", nil
}

func b511Actor() context.Context {
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e11"
	key, _ := sandboxreg.SubstrateKey("eng-web", uid)
	return withSubstrateActor(context.Background(), substrateActor{Atespace: "eng-web", Name: "b511", UID: uid,
		Subject: "actor/eng-web/b511", RegistrationKey: key, verified: substrateVerified})
}

func b511Facts(dir string, files map[string]string) *SubstrateFacts {
	f := &SubstrateFacts{}
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		c := files[rel]
		f.Files = append(f.Files, SubstrateAttachedFile{Role: substrateSkillRoleFile, Path: dir + "/" + rel, Content: []byte(c), Size: int64(len(c))})
	}
	f.Skills = []SubstrateSkillFingerprint{{Path: dir, FP: substrateSkillFolderDigest(dir, f.Files), Attached: true}}
	return f
}

const b511MD = "---\nname: pdf-helper\ndescription: Fill PDF forms\n---\n# PDF helper\nRun scripts/run.py.\n"

// GAP-0981: a plain .gz is unpacked and its payload scanned in its place
// (the parent and rel let it through unscanned), so the benign fixture gets a
// receipt in every tier as it did there.
func TestB511GzipPayloadIsScanned(t *testing.T) {
	big := bytes.Repeat([]byte("a"), skillGzipMax+1)
	cases := []struct {
		name    string
		files   map[string]string
		managed bool
		refused string // a substring of the refusal, "" = passes
		scanned string // a path the scanner must have seen
	}{
		{"managed-gz-fixture", map[string]string{"SKILL.md": b511MD, "tests/data.json.gz": b511Gz([]byte(`{"a":1}`))}, true, "", "tests/data.json"},
		{"managed-gz-payload-blocked", map[string]string{"SKILL.md": b511MD, "tests/data.json.gz": b511Gz([]byte("B511-BLOCK-MARKER"))}, true, "marker found", ""},
		{"managed-gz-of-a-tar", map[string]string{"SKILL.md": b511MD, "data.gz": b511Gz(b511Tar(t, map[string]string{"a": "b"}))}, true, `"data.gz"`, ""},
		{"managed-gz-too-big", map[string]string{"SKILL.md": b511MD, "data.gz": b511Gz(big)}, true, `"data.gz"`, ""},
		{"managed-gz-payload-name-taken", map[string]string{"SKILL.md": b511MD, "data.gz": b511Gz([]byte("x")), "data": "y"}, true, `"data.gz"`, ""},
		{"managed-gz-cut", map[string]string{"SKILL.md": b511MD, "data.gz": b511Gz([]byte("hello world"))[:12]}, true, `"data.gz"`, ""},
		{"oss-gz-fixture", map[string]string{"SKILL.md": b511MD, "tests/data.json.gz": b511Gz([]byte(`{"a":1}`))}, false, "", "tests/data.json"},
		{"oss-gz-payload-blocked", map[string]string{"SKILL.md": b511MD, "tests/data.json.gz": b511Gz([]byte("B511-BLOCK-MARKER"))}, false, "marker found", ""},
	}
	for i, c := range cases {
		sc := &b511Scanner{seen: map[string][]string{}}
		st := &substrateState{}
		st.cfg.Skills = sc
		m := c.managed
		st.cfg.BlockUnscannedSkills = func(string) bool { return m }
		dir := fmt.Sprintf("/home/agent/.claude/skills/g%02d", i)
		ans := st.substrateSkills(b511Actor(), "claudecode", b511Facts(dir, c.files))
		var reasons []string
		for _, q := range ans.Quarantine {
			reasons = append(reasons, q.Reason)
		}
		got := strings.Join(reasons, "; ")
		switch {
		case c.refused == "" && got != "":
			t.Errorf("%s: refused (%s), want it to pass", c.name, got)
		case c.refused != "" && !strings.Contains(got, c.refused):
			t.Errorf("%s: refusal %q, want one naming %s", c.name, got, c.refused)
		}
		if c.scanned != "" {
			seen := strings.Join(sc.seen[dir], ",")
			if !strings.Contains(","+seen+",", ","+c.scanned+",") {
				t.Errorf("%s: scanner saw %q, want %s", c.name, seen, c.scanned)
			}
		}
	}
}

// GAP-0981 (RV5 corpus): no benign folder is refused, OSS or managed, with a
// scanner that finds nothing (the parent 098e044d96: 0/14 both).
func TestB511BenignCorpusNotRefused(t *testing.T) {
	zipOf := func(name, body string) string { return b511Zip(t, false, map[string]string{name: body}) }
	corpus := []struct {
		name  string
		files map[string]string
	}{
		{"plain-skill", map[string]string{"SKILL.md": b511MD, "scripts/run.py": "print('hi')\n"}},
		{"docs-next-to-skill", map[string]string{"SKILL.md": b511MD, "reference.md": "# Ref\n", "docs/guide.md": "guide\n", "examples/form.json": `{"a":1}`}},
		{"plugin-name", map[string]string{"SKILL.md": "---\nname: tools:pdf\ndescription: x\n---\nbody\n"}},
		{"shell-helper", map[string]string{"SKILL.md": b511MD, "lib/helper.sh": "#!/bin/sh\necho ok\n"}},
		{"magic-as-escaped-text", map[string]string{"SKILL.md": b511MD, "scripts/sniff.py": `MAGIC = b"PK\x03\x04"  # zip` + "\n"}},
		{"pk-in-prose", map[string]string{"SKILL.md": b511MD, "notes.md": "zip files begin with PK then 03 04\n"}},
		{"png-asset", map[string]string{"SKILL.md": b511MD, "assets/logo.png": b511PNG()}},
		{"pdf-asset", map[string]string{"SKILL.md": b511MD, "assets/form.pdf": "%PDF-1.4\n1 0 obj << >> endobj\ntrailer\n%%EOF\n"}},
		{"csv-starting-070701", map[string]string{"SKILL.md": b511MD, "data/dates.csv": "070701,first release\n080102,second\n"}},
		{"locale-file-.ar", map[string]string{"SKILL.md": b511MD, "locales/messages.ar": "greeting = marhaba\n"}},
		{"readme-.pt.br", map[string]string{"SKILL.md": b511MD, "README.pt.br": "Leia-me\n"}},
		{"zip-test-fixture", map[string]string{"SKILL.md": b511MD, "tests/fixtures/sample.zip": zipOf("a.txt", "hello")}},
		{"docx-template", map[string]string{"SKILL.md": b511MD, "templates/report.docx": zipOf("word/document.xml", "<w/>")}},
		{"gz-test-fixture", map[string]string{"SKILL.md": b511MD, "tests/data.json.gz": b511Gz([]byte(`{"a":1}`))}},
	}
	for _, managed := range []bool{false, true} {
		for i, c := range corpus {
			st := &substrateState{}
			st.cfg.Skills = &b511Scanner{seen: map[string][]string{}}
			m := managed
			st.cfg.BlockUnscannedSkills = func(string) bool { return m }
			dir := fmt.Sprintf("/home/agent/.claude/skills/c%02d", i)
			ans := st.substrateSkills(b511Actor(), "claudecode", b511Facts(dir, c.files))
			if len(ans.Quarantine) > 0 || len(ans.Scanned) != 1 {
				t.Errorf("managed=%v %s: quarantine %+v, receipts %d (want none refused, one receipt)", managed, c.name, ans.Quarantine, len(ans.Scanned))
			}
		}
	}
}
