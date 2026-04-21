// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func FuzzContentHashCanonicalJSONStable(f *testing.F) {
	version.ResetForTesting()
	f.Add([]byte(`{"z":1,"a":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		version.ResetForTesting()
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil || m == nil {
			t.Skip()
		}
		if err := version.SetContentHashCanonicalJSON(m); err != nil {
			t.Skip()
		}
		h1 := version.Current().ContentHash
		if err := version.SetContentHashCanonicalJSON(m); err != nil {
			t.Fatal(err)
		}
		h2 := version.Current().ContentHash
		if h1 != h2 {
			t.Fatalf("hash drift: %s vs %s", h1, h2)
		}
	})
}

func TestContentHashDifferentInputs(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 10000; i++ {
		version.ResetForTesting()
		m := map[string]any{"i": i}
		if err := version.SetContentHashCanonicalJSON(m); err != nil {
			t.Fatal(err)
		}
		h := version.Current().ContentHash
		if _, ok := seen[h]; ok {
			t.Fatalf("collision at i=%d hash=%s", i, h)
		}
		seen[h] = struct{}{}
	}
}

func TestBumpGenerationConcurrent(t *testing.T) {
	version.ResetForTesting()
	const (
		goroutines = 100
		bumpsEach  = 10
	)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < bumpsEach; i++ {
				version.BumpGeneration()
			}
		}()
	}
	wg.Wait()
	got := version.Current().Generation
	if got != uint64(goroutines*bumpsEach) {
		t.Fatalf("generation = %d, want %d", got, goroutines*bumpsEach)
	}
}

func TestStampProvenanceIdempotentNoGenerationBump(t *testing.T) {
	version.ResetForTesting()
	version.SetBinaryVersion("prov-test")
	if err := version.SetContentHashCanonicalJSON(map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	version.BumpGeneration()
	before := version.Current().Generation

	e := gatewaylog.Event{EventType: gatewaylog.EventLifecycle}
	e.StampProvenance()
	g1 := e.Generation
	e.StampProvenance()
	g2 := e.Generation
	if g1 != g2 {
		t.Fatalf("generation changed across StampProvenance: %d vs %d", g1, g2)
	}
	if version.Current().Generation != before {
		t.Fatalf("global generation bumped: %d vs %d", version.Current().Generation, before)
	}
}
