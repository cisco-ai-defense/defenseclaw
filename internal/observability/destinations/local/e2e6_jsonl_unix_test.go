//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestE2E6ActualBlockedJSONLCountAndBytePressure(t *testing.T) {
	runE2E6ActualLocalAdapterPressure(t, func(t *testing.T) e2e6AdapterFixture {
		t.Helper()
		path := filepath.Join(t.TempDir(), "events.jsonl")
		adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
		if err != nil {
			t.Fatal(err)
		}
		// Hold the real adapter's serialization gate. Its dispatcher can dequeue
		// one item, but no file write can begin until release.
		<-adapter.gate
		var once sync.Once
		return e2e6AdapterFixture{
			adapter: adapter,
			release: func() { once.Do(func() { adapter.gate <- struct{}{} }) },
			output:  func() ([]byte, error) { return os.ReadFile(path) },
			close:   func(ctx context.Context) error { return adapter.Close(ctx) },
		}
	})
}
