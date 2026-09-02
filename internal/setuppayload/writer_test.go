// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestRoundTrip writes a trailer + reads it back, asserting each
// payload entry survives byte-identical and the manifest bytes are
// preserved verbatim.
func TestRoundTrip(t *testing.T) {
	prebuilt := []byte("prebuilt setup EXE placeholder bytes\x00\x01\x02")
	entries := []Entry{
		{Name: "defenseclaw.exe", Contents: []byte("gateway binary A")},
		{Name: "DefenseClawEnterprise.psm1", Contents: []byte("Module manifest")},
		{Name: "install-enterprise.ps1", Contents: []byte("$Foo = 'bar'")},
	}
	manifest := []byte(`{"schema_version":1,"version":"0.8.6"}`)

	var buf bytes.Buffer
	buf.Write(prebuilt)
	if err := WriteTrailer(&buf, entries, manifest); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}

	rd := bytes.NewReader(buf.Bytes())
	got, err := Read(rd, int64(buf.Len()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got.Manifest, manifest) {
		t.Errorf("manifest round-trip mismatch: got %q want %q", got.Manifest, manifest)
	}
	if len(got.Entries) != len(entries) {
		t.Fatalf("entry count: got %d want %d", len(got.Entries), len(entries))
	}
	// Verify by name; on-disk order is alphabetical regardless of
	// caller order, so build a map keyed by name. Delete each match
	// as we go and assert the map empties out — otherwise a duplicate
	// returned name whose contents happen to match could paper over
	// a missing name elsewhere in the set.
	wantByName := map[string][]byte{}
	for _, e := range entries {
		wantByName[e.Name] = e.Contents
	}
	for _, got := range got.Entries {
		want, ok := wantByName[got.Name]
		if !ok {
			t.Errorf("unexpected or duplicate entry %q", got.Name)
			continue
		}
		if !bytes.Equal(got.Contents, want) {
			t.Errorf("entry %q content mismatch", got.Name)
		}
		delete(wantByName, got.Name)
	}
	if len(wantByName) != 0 {
		names := make([]string, 0, len(wantByName))
		for n := range wantByName {
			names = append(names, n)
		}
		t.Errorf("expected entries not returned: %v", names)
	}
}

// TestReproducibilityByteIdentical is the spec 001 REQ-07 gate at the
// trailer level. Two writes against the same inputs must produce byte-
// identical outputs regardless of input entry order.
func TestReproducibilityByteIdentical(t *testing.T) {
	orderA := []Entry{
		{Name: "b.exe", Contents: []byte("bbb")},
		{Name: "a.psm1", Contents: []byte("aaa")},
		{Name: "c.ps1", Contents: []byte("ccc")},
	}
	orderB := []Entry{
		// Different caller order — but WriteTrailer sorts internally.
		{Name: "c.ps1", Contents: []byte("ccc")},
		{Name: "a.psm1", Contents: []byte("aaa")},
		{Name: "b.exe", Contents: []byte("bbb")},
	}
	manifest := []byte(`{"schema_version":1}`)

	var bufA, bufB bytes.Buffer
	if err := WriteTrailer(&bufA, orderA, manifest); err != nil {
		t.Fatalf("WriteTrailer A: %v", err)
	}
	if err := WriteTrailer(&bufB, orderB, manifest); err != nil {
		t.Fatalf("WriteTrailer B: %v", err)
	}
	if !bytes.Equal(bufA.Bytes(), bufB.Bytes()) {
		hashA := sha256.Sum256(bufA.Bytes())
		hashB := sha256.Sum256(bufB.Bytes())
		t.Fatalf("trailer not reproducible: sha256(A)=%s sha256(B)=%s",
			hex.EncodeToString(hashA[:]), hex.EncodeToString(hashB[:]))
	}
}

func TestFooterMagicRejected(t *testing.T) {
	// A payload that ends in random bytes must surface ErrTrailerMissing,
	// not a CRC failure or a misleading truncation error.
	buf := bytes.Repeat([]byte{0x42}, 128)
	_, err := Read(bytes.NewReader(buf), int64(len(buf)))
	if !errors.Is(err, ErrTrailerMissing) {
		t.Fatalf("expected ErrTrailerMissing, got %v", err)
	}
}

func TestCRCMismatchRejected(t *testing.T) {
	var buf bytes.Buffer
	entries := []Entry{{Name: "a.txt", Contents: []byte("hello")}}
	if err := WriteTrailer(&buf, entries, []byte(`{}`)); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}
	// Corrupt one byte in the archive region — the CRC will no longer
	// match, and the header's per-entry SHA-256 will also mismatch, so
	// ErrTrailerCorrupt should surface.
	corrupted := buf.Bytes()
	// The archive body is the region before the manifest (2 bytes: `{}`)
	// and the footer (24 bytes). Flip one bit inside the archive.
	if len(corrupted) < 30 {
		t.Fatalf("short buffer: %d", len(corrupted))
	}
	// Byte at index 4 lands well inside the fixed-width name field of
	// entry a.txt (name starts at offset 0 of archive).
	corrupted[4] ^= 0xFF
	_, err := Read(bytes.NewReader(corrupted), int64(len(corrupted)))
	if !errors.Is(err, ErrTrailerCorrupt) {
		t.Fatalf("expected ErrTrailerCorrupt, got %v", err)
	}
}

func TestNameTooLongRejected(t *testing.T) {
	long := strings.Repeat("A", MaxNameLen+1)
	entries := []Entry{{Name: long, Contents: []byte{}}}
	err := WriteTrailer(&bytes.Buffer{}, entries, []byte(`{}`))
	if !errors.Is(err, ErrEntryOversize) {
		t.Fatalf("expected ErrEntryOversize, got %v", err)
	}
}

func TestIllegalNameRejected(t *testing.T) {
	cases := []string{"path/traversal", "..", ".", "colon:name", "\x00null"}
	for _, name := range cases {
		entries := []Entry{{Name: name, Contents: []byte("x")}}
		if err := WriteTrailer(&bytes.Buffer{}, entries, []byte(`{}`)); err == nil {
			t.Errorf("expected error for name %q, got nil", name)
		}
	}
}

func TestDuplicateNameRejected(t *testing.T) {
	entries := []Entry{
		{Name: "a.exe", Contents: []byte("first")},
		{Name: "a.exe", Contents: []byte("second")},
	}
	if err := WriteTrailer(&bytes.Buffer{}, entries, []byte(`{}`)); err == nil {
		t.Fatal("expected duplicate name error, got nil")
	}
}

func TestEmptyEntriesRejected(t *testing.T) {
	if err := WriteTrailer(&bytes.Buffer{}, nil, []byte(`{}`)); err == nil {
		t.Fatal("expected empty-entries error, got nil")
	}
}

func TestAsPayloadFS(t *testing.T) {
	entries := []Entry{
		{Name: "defenseclaw.exe", Contents: []byte("gw")},
		{Name: "install-enterprise.ps1", Contents: []byte("ps")},
	}
	manifest := []byte(`{"version":"0.8.6"}`)

	var buf bytes.Buffer
	if err := WriteTrailer(&buf, entries, manifest); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}
	res, err := Read(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	payloadFS := res.AsPayloadFS()

	// The old loader called fs.ReadFile(payloadFS, "payload/manifest.json") —
	// verify that path resolves.
	gotManifest, err := fs.ReadFile(payloadFS, "payload/manifest.json")
	if err != nil {
		t.Fatalf("fs.ReadFile(manifest.json): %v", err)
	}
	if !bytes.Equal(gotManifest, manifest) {
		t.Errorf("manifest mismatch through fs.FS")
	}
	// And each payload file at its "payload/<name>" path.
	for _, e := range entries {
		got, err := fs.ReadFile(payloadFS, "payload/"+e.Name)
		if err != nil {
			t.Errorf("fs.ReadFile(%s): %v", e.Name, err)
			continue
		}
		if !bytes.Equal(got, e.Contents) {
			t.Errorf("%s content mismatch through fs.FS", e.Name)
		}
	}
}

func TestHasTrailerProbe(t *testing.T) {
	// Empty EXE — no trailer.
	if HasTrailer(bytes.NewReader(nil), 0) {
		t.Error("HasTrailer(empty) = true, want false")
	}
	// Random-tail EXE — no trailer.
	noise := bytes.Repeat([]byte{0x55}, 64)
	if HasTrailer(bytes.NewReader(noise), int64(len(noise))) {
		t.Error("HasTrailer(random) = true, want false")
	}
	// Real trailer — true.
	var buf bytes.Buffer
	entries := []Entry{{Name: "x.txt", Contents: []byte("y")}}
	if err := WriteTrailer(&buf, entries, []byte(`{}`)); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}
	if !HasTrailer(bytes.NewReader(buf.Bytes()), int64(buf.Len())) {
		t.Error("HasTrailer(real) = false, want true")
	}
}
