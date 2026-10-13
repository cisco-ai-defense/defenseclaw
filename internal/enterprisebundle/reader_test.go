// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// entry is one tar entry of a test archive.
type entry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	link     string
	pax      map[string]string
}

func file(name, body string) entry {
	return entry{name: name, typeflag: tar.TypeReg, mode: 0o644, body: []byte(body)}
}

func dir(name string) entry { return entry{name: name, typeflag: tar.TypeDir, mode: 0o755} }

func archive(t testing.TB, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body)), Linkname: e.link, PAXRecords: e.pax}
		if e.typeflag != tar.TypeReg && e.typeflag != tar.TypeRegA {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tree is a valid bundle tree (no manifest) used across the tests.
func tree() []entry {
	return []entry{
		file(ConfigName, "config_version: 9\n"),
		dir("discovery"),
		dir("discovery/signature-packs"),
		file("discovery/signature-packs/team.json", `{"version":1}`),
		file("discovery/confidence.yaml", "version: 1\n"),
		file("policies/guardrail/strict/rules.yaml", "rules: []\n"),
	}
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Fatalf("error %v: code %q, want %q", err, got, code)
	}
}

func TestReadArchiveAcceptsABundleTree(t *testing.T) {
	entries := append(tree(), file(ManifestName, "{}"), file(SignatureName, "{}"))
	b, err := ReadArchive(bytes.NewReader(archive(t, entries...)))
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Manifest) != "{}" || string(b.Signature) != "{}" {
		t.Fatalf("envelope not captured: %q %q", b.Manifest, b.Signature)
	}
	want := []string{ConfigName, "discovery/confidence.yaml", "discovery/signature-packs/team.json", "policies/guardrail/strict/rules.yaml"}
	if got := b.Paths(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paths %v, want %v", got, want)
	}
}

func TestReadArchiveRefuses(t *testing.T) {
	elf := append([]byte("\x7fELF"), make([]byte, 60)...)
	many := []entry{file(ConfigName, "x")}
	for i := 0; i < MaxEntries; i++ {
		many = append(many, file("policies/guardrail/p/f"+strings.Repeat("0", 3-len(itoa3(i)))+itoa3(i), ""))
	}
	cases := map[string][]entry{
		"traversal":            {file("../config.yaml", "")},
		"traversal inside":     {file("policies/guardrail/../../config.yaml", "")},
		"absolute":             {file("/etc/passwd", "")},
		"backslash":            {file(`policies\guardrail\p\x`, "")},
		"dot segment":          {file("policies/./guardrail/p/x", "")},
		"empty segment":        {file("policies//guardrail/p/x", "")},
		"trailing dot":         {file("policies/guardrail/p./x", "")},
		"device name":          {file("policies/guardrail/nul.txt/x", "")},
		"outside the tree":     {file("notes.txt", "")},
		"secrets dir":          {file("secrets/key", "")},
		"file under policies":  {file("policies/x.yaml", "")},
		"symlink":              {{name: "policies/guardrail/p/x", typeflag: tar.TypeSymlink, link: "/etc/shadow"}},
		"hard link":            {file(ConfigName, ""), {name: "policies/guardrail/p/x", typeflag: tar.TypeLink, link: ConfigName}},
		"char device":          {{name: "policies/guardrail/p/x", typeflag: tar.TypeChar}},
		"fifo":                 {{name: "policies/guardrail/p/x", typeflag: tar.TypeFifo}},
		"global header":        {{name: "pax_global_header", typeflag: tar.TypeXGlobalHeader, pax: map[string]string{"comment": "x"}}},
		"duplicate":            {file(ConfigName, "a"), file(ConfigName, "b")},
		"case collision":       {file(ConfigName, ""), file("Config.yaml", "")},
		"case collision dir":   {file("policies/guardrail/p/x", ""), file("policies/guardrail/P/y", "")},
		"file below a file":    {file("policies/guardrail/p/a", ""), file("policies/guardrail/p/a/x", "")},
		"file named like dir":  {file("policies/guardrail/p/a/x", ""), file("policies/guardrail/p/a", "")},
		"dir named like file":  {file("policies/guardrail/p/a", ""), dir("policies/guardrail/p/a")},
		"executable mode":      {{name: "policies/guardrail/p/x", typeflag: tar.TypeReg, mode: 0o755, body: []byte("x")}},
		"program content":      {{name: "policies/guardrail/p/x", typeflag: tar.TypeReg, mode: 0o644, body: elf}},
		"script content":       {file("policies/guardrail/p/run.yaml", "#!/bin/sh\n")},
		"too many entries":     many,
		"expands too far":      {{name: "policies/guardrail/p/x", typeflag: tar.TypeReg, mode: 0o644, body: make([]byte, MaxExpandedBytes+1)}},
		"manifest too large":   {file(ManifestName, strings.Repeat(" ", MaxManifestBytes+1))},
		"signature too large":  {file(SignatureName, strings.Repeat(" ", MaxSignatureBytes+1))},
		"long path":            {file("policies/guardrail/p/"+strings.Repeat("a", MaxPathBytes), "")},
		"deep path":            {file("policies/guardrail/p/"+strings.Repeat("d/", MaxPathDepth)+"x", "")},
		"bad discovery file":   {file("discovery/signature-packs/team.yaml", "")},
		"discovery nested dir": {file("discovery/signature-packs/a/b.json", "")},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadArchive(bytes.NewReader(archive(t, entries...)))
			want := CodeArchiveInvalid
			if name == "manifest too large" {
				want = CodeManifestInvalid
			}
			wantCode(t, err, want)
		})
	}
}

func itoa3(i int) string {
	return string([]byte{byte('0' + i/100%10), byte('0' + i/10%10), byte('0' + i%10)})
}

func TestReadArchiveRefusesBadStreams(t *testing.T) {
	valid := archive(t, tree()...)
	random := make([]byte, MaxCompressedBytes+1)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	gz := gzip.NewWriter(&second)
	_, _ = gz.Write([]byte("hidden"))
	_ = gz.Close()
	cases := map[string][]byte{
		"not gzip":             []byte("config_version: 9\n"),
		"too large":            random,
		"bytes after gzip":     append(append([]byte{}, valid...), 'x'),
		"second gzip member":   append(append([]byte{}, valid...), second.Bytes()...),
		"truncated":            valid[:len(valid)/2],
		"data after the tar":   gzipped(t, append(tarOnly(t, tree()...), []byte("trailing")...)),
		"not a tar":            gzipped(t, []byte(strings.Repeat("x", 1024))),
		"zero padding is fine": nil,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if data == nil {
				padded := gzipped(t, append(tarOnly(t, tree()...), make([]byte, 10240)...))
				if _, err := ReadArchive(bytes.NewReader(padded)); err != nil {
					t.Fatalf("zero padding refused: %v", err)
				}
				return
			}
			_, err := ReadArchive(bytes.NewReader(data))
			wantCode(t, err, CodeArchiveInvalid)
		})
	}
}

func tarOnly(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeTree writes entries under a new directory and returns it.
func writeTree(t *testing.T, entries ...entry) string {
	t.Helper()
	root := t.TempDir()
	for _, e := range entries {
		full := filepath.Join(root, filepath.FromSlash(e.name))
		if e.typeflag == tar.TypeDir {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, e.body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReadDirMatchesReadArchive(t *testing.T) {
	fromDir, err := ReadDir(writeTree(t, tree()...))
	if err != nil {
		t.Fatal(err)
	}
	fromArchive, err := ReadArchive(bytes.NewReader(archive(t, tree()...)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(fromDir.Paths(), ",") != strings.Join(fromArchive.Paths(), ",") {
		t.Fatalf("dir %v, archive %v", fromDir.Paths(), fromArchive.Paths())
	}
	for name, data := range fromArchive.Files {
		if !bytes.Equal(fromDir.Files[name], data) {
			t.Fatalf("%s differs", name)
		}
	}
}

func TestReadDirRefuses(t *testing.T) {
	t.Run("outside the tree", func(t *testing.T) {
		_, err := ReadDir(writeTree(t, append(tree(), file("notes.txt", ""))...))
		wantCode(t, err, CodeArchiveInvalid)
	})
	t.Run("program", func(t *testing.T) {
		_, err := ReadDir(writeTree(t, append(tree(), file("policies/guardrail/p/x", "#!/bin/sh\n"))...))
		wantCode(t, err, CodeArchiveInvalid)
	})
	t.Run("not a directory", func(t *testing.T) {
		root := writeTree(t, tree()...)
		_, err := ReadDir(filepath.Join(root, ConfigName))
		wantCode(t, err, CodeArchiveInvalid)
	})
	t.Run("link", func(t *testing.T) {
		root := writeTree(t, tree()...)
		target := filepath.Join(t.TempDir(), "outside.yaml")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "policies", "guardrail", "strict", "link.yaml")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := ReadDir(root)
		wantCode(t, err, CodeArchiveInvalid)
	})
	t.Run("linked root", func(t *testing.T) {
		root := writeTree(t, tree()...)
		link := filepath.Join(t.TempDir(), "bundle")
		if err := os.Symlink(root, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := ReadDir(link)
		wantCode(t, err, CodeArchiveInvalid)
	})
	if runtime.GOOS != "windows" {
		t.Run("case collision", func(t *testing.T) {
			root := writeTree(t, append(tree(), file("policies/guardrail/Strict/rules.yaml", ""))...)
			if _, err := os.Stat(filepath.Join(root, "policies/guardrail/strict/rules.yaml")); err != nil {
				t.Skip("case-insensitive file system")
			}
			entries, _ := os.ReadDir(filepath.Join(root, "policies", "guardrail"))
			if len(entries) < 2 {
				t.Skip("case-insensitive file system")
			}
			_, err := ReadDir(root)
			wantCode(t, err, CodeArchiveInvalid)
		})
	}
}
