// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func newTestLogger(t *testing.T) *Logger {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewLogger(store)
}

func metricValue(t *testing.T, record observability.Record) any {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("metric instrument data is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	return data["value"]
}
