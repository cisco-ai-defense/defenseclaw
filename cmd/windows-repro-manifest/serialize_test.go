// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMarshalSortedJSONBytestable(t *testing.T) {
	// Same logical value, keys inserted in different Go source orders
	// on repeated calls. The output must be byte-identical because
	// encoding/json sorts map keys alphabetically.
	v1 := map[string]any{
		"version":        "1.2.3",
		"source_commit":  "abc123",
		"schema_version": 1,
		"files": []any{
			map[string]any{"name": "b.exe", "sha256": "22", "size": 20},
			map[string]any{"name": "a.exe", "sha256": "11", "size": 10},
		},
		"distribution_flavor": "managed-enterprise",
	}
	// Different insertion order — same logical map.
	v2 := map[string]any{
		"distribution_flavor": "managed-enterprise",
		"schema_version":      1,
		"source_commit":       "abc123",
		"files": []any{
			map[string]any{"name": "b.exe", "sha256": "22", "size": 20},
			map[string]any{"name": "a.exe", "sha256": "11", "size": 10},
		},
		"version": "1.2.3",
	}
	b1, err := marshalSortedJSON(v1)
	if err != nil {
		t.Fatalf("marshalSortedJSON v1: %v", err)
	}
	b2, err := marshalSortedJSON(v2)
	if err != nil {
		t.Fatalf("marshalSortedJSON v2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("output not byte-stable across map insertion order:\nv1:\n%s\nv2:\n%s", b1, b2)
	}
}

func TestMarshalSortedJSONShape(t *testing.T) {
	got, err := marshalSortedJSON(map[string]any{
		"b": 2,
		"a": 1,
		"nested": map[string]any{
			"z": 3,
			"y": []any{"e", "d"},
		},
	})
	if err != nil {
		t.Fatalf("marshalSortedJSON: %v", err)
	}
	// - Top-level keys sorted (a before b before nested).
	// - Nested map keys sorted (y before z).
	// - Slice order preserved (arrays are ordered semantically).
	// - Two-space indent, LF endings, trailing LF.
	want := "{\n  \"a\": 1,\n  \"b\": 2,\n  \"nested\": {\n    \"y\": [\n      \"e\",\n      \"d\"\n    ],\n    \"z\": 3\n  }\n}\n"
	if string(got) != want {
		t.Fatalf("layout mismatch\ngot:  %q\nwant: %q", got, want)
	}
}

func TestMarshalSortedJSONNoHTMLEscaping(t *testing.T) {
	got, err := marshalSortedJSON(map[string]any{
		"path": "C:\\Users\\alice\\<tools>&<data>",
	})
	if err != nil {
		t.Fatalf("marshalSortedJSON: %v", err)
	}
	// SetEscapeHTML(false) means <, >, & are kept as-is.
	want := "{\n  \"path\": \"C:\\\\Users\\\\alice\\\\<tools>&<data>\"\n}\n"
	if string(got) != want {
		t.Fatalf("html-escape mismatch\ngot:  %q\nwant: %q", got, want)
	}
}

func TestWriteSortedJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	value := map[string]any{
		"schema_version": 1,
		"version":        "0.0.1-test",
	}
	if err := writeSortedJSON(path, value); err != nil {
		t.Fatalf("writeSortedJSON: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := "{\n  \"schema_version\": 1,\n  \"version\": \"0.0.1-test\"\n}\n"
	if string(got) != want {
		t.Fatalf("file contents:\n  got:  %q\n  want: %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// POSIX mode assertion is meaningful on Unix only. Windows does not
	// implement chmod semantics — os.WriteFile there produces a file with
	// the ambient security descriptor, and info.Mode().Perm() returns
	// 0666 for readable/writable files regardless of what we asked for.
	// The byte-stability contract this test cares about is about file
	// CONTENTS, not filesystem ACLs.
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("file mode = %o, want 0644", got)
		}
	}
}
