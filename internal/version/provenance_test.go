// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"sync"
	"testing"
)

func TestSchemaVersionIsSeven(t *testing.T) {
	if SchemaVersion != 7 {
		t.Fatalf("expected SchemaVersion == 7, got %d", SchemaVersion)
	}
}

func TestCurrentDefaultsWhenUnset(t *testing.T) {
	ResetForTesting()
	p := Current()
	if p.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", p.SchemaVersion, SchemaVersion)
	}
	if p.ContentHash != "" {
		t.Errorf("ContentHash = %q, want empty", p.ContentHash)
	}
	if p.Generation != 0 {
		t.Errorf("Generation = %d, want 0", p.Generation)
	}
	if p.BinaryVersion == "" {
		t.Errorf("BinaryVersion must fall back to non-empty value; got empty")
	}
}

func TestSetBinaryVersion(t *testing.T) {
	ResetForTesting()
	SetBinaryVersion("v1.2.3")
	if got := Current().BinaryVersion; got != "v1.2.3" {
		t.Errorf("BinaryVersion = %q, want v1.2.3", got)
	}
	// Trimming
	SetBinaryVersion("  v2.0.0  ")
	if got := Current().BinaryVersion; got != "v2.0.0" {
		t.Errorf("BinaryVersion = %q, want v2.0.0", got)
	}
	// Empty falls back
	SetBinaryVersion("")
	if got := Current().BinaryVersion; got == "" {
		t.Errorf("BinaryVersion must fall back when set empty; got empty")
	}
}

func TestBumpGenerationIsMonotonic(t *testing.T) {
	ResetForTesting()
	const N = 1000
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			BumpGeneration()
		}()
	}
	wg.Wait()
	if got := Current().Generation; got != N {
		t.Errorf("Generation after %d bumps = %d", N, got)
	}
}

func TestSetContentHashStableAcrossKeyOrder(t *testing.T) {
	ResetForTesting()
	a := map[string]any{"b": 2, "a": 1, "c": map[string]any{"y": 1, "x": 2}}
	b := map[string]any{"c": map[string]any{"x": 2, "y": 1}, "a": 1, "b": 2}

	if err := SetContentHashCanonicalJSON(a); err != nil {
		t.Fatal(err)
	}
	h1 := Current().ContentHash

	ResetForTesting()
	if err := SetContentHashCanonicalJSON(b); err != nil {
		t.Fatal(err)
	}
	h2 := Current().ContentHash

	if h1 == "" || h2 == "" {
		t.Fatalf("empty hash: %q %q", h1, h2)
	}
	if h1 != h2 {
		t.Errorf("ContentHash not stable across key order:\n  a -> %s\n  b -> %s", h1, h2)
	}
}

func TestSetContentHashChangesWithContent(t *testing.T) {
	ResetForTesting()
	_ = SetContentHashCanonicalJSON(map[string]any{"k": "v1"})
	h1 := Current().ContentHash
	_ = SetContentHashCanonicalJSON(map[string]any{"k": "v2"})
	h2 := Current().ContentHash
	if h1 == h2 {
		t.Errorf("ContentHash should differ when content changes: %s == %s", h1, h2)
	}
}

func TestSetContentHashEmptyClears(t *testing.T) {
	ResetForTesting()
	SetContentHash([]byte("x"))
	if Current().ContentHash == "" {
		t.Fatal("expected hash to be set")
	}
	SetContentHash(nil)
	if Current().ContentHash != "" {
		t.Errorf("nil input should clear hash, got %q", Current().ContentHash)
	}
}
