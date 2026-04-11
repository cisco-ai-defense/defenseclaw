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

package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Store.Init: %v", err)
	}
	return store, func() { store.Close() }
}

// --- NetworkEgressEvent.Validate ---

func TestNetworkEgressEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		evt     NetworkEgressEvent
		wantErr bool
	}{
		{
			name:    "valid allowed event",
			evt:     NetworkEgressEvent{Hostname: "api.example.com", PolicyOutcome: "Allowed by pattern: *.example.com"},
			wantErr: false,
		},
		{
			name:    "valid blocked event",
			evt:     NetworkEgressEvent{Hostname: "evil.io", PolicyOutcome: "Denied: not in allowlist", Blocked: true},
			wantErr: false,
		},
		{
			name:    "missing hostname",
			evt:     NetworkEgressEvent{PolicyOutcome: "Allowed by default"},
			wantErr: true,
		},
		{
			name:    "missing policy outcome",
			evt:     NetworkEgressEvent{Hostname: "api.example.com"},
			wantErr: true,
		},
		{
			name:    "whitespace hostname",
			evt:     NetworkEgressEvent{Hostname: "   ", PolicyOutcome: "ok"},
			wantErr: true,
		},
		{
			name:    "whitespace policy outcome",
			evt:     NetworkEgressEvent{Hostname: "api.example.com", PolicyOutcome: "  "},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.evt.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- effectiveSeverity ---

func TestNetworkEgressEvent_effectiveSeverity(t *testing.T) {
	tests := []struct {
		name     string
		evt      NetworkEgressEvent
		wantSev  string
	}{
		{"explicit severity wins", NetworkEgressEvent{Severity: "CRITICAL"}, "CRITICAL"},
		{"blocked defaults HIGH", NetworkEgressEvent{Blocked: true}, "HIGH"},
		{"allowed defaults INFO", NetworkEgressEvent{Blocked: false}, "INFO"},
		{"explicit on blocked wins", NetworkEgressEvent{Blocked: true, Severity: "MEDIUM"}, "MEDIUM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.evt.effectiveSeverity(); got != tt.wantSev {
				t.Errorf("effectiveSeverity() = %q, want %q", got, tt.wantSev)
			}
		})
	}
}

// --- Store: insert / list / query ---

func TestStore_InsertAndListNetworkEgressEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Now().UTC().Truncate(time.Second)

	fixtures := []NetworkEgressRow{
		{
			Timestamp:     base,
			Hostname:      "api.example.com",
			URL:           "https://api.example.com/v1/data",
			HTTPMethod:    "POST",
			Protocol:      "https",
			PolicyOutcome: "Allowed by pattern: *.example.com",
			DecisionCode:  "NETWORK_ALLOW_PATTERN",
			Blocked:       false,
			Severity:      "INFO",
		},
		{
			Timestamp:     base.Add(-time.Minute),
			SessionID:     "sess-abc123",
			Hostname:      "malicious.io",
			URL:           "http://malicious.io/exfil",
			HTTPMethod:    "GET",
			Protocol:      "http",
			PolicyOutcome: "Denied: hostname on deny list",
			DecisionCode:  "NETWORK_DENY_PATTERN",
			Blocked:       true,
			Severity:      "HIGH",
		},
		{
			Timestamp:     base.Add(-2 * time.Minute),
			SessionID:     "sess-abc123",
			Hostname:      "api.example.com",
			PolicyOutcome: "Allowed by default policy",
			DecisionCode:  "NETWORK_DEFAULT_ALLOW",
			Severity:      "INFO",
		},
	}

	for _, e := range fixtures {
		if err := store.InsertNetworkEgressEvent(e); err != nil {
			t.Fatalf("InsertNetworkEgressEvent: %v", err)
		}
	}

	t.Run("list all newest first", func(t *testing.T) {
		rows, err := store.ListNetworkEgressEvents(100, "")
		if err != nil {
			t.Fatalf("ListNetworkEgressEvents: %v", err)
		}
		if len(rows) != 3 {
			t.Errorf("got %d rows, want 3", len(rows))
		}
		if rows[0].Hostname != "api.example.com" || rows[0].HTTPMethod != "POST" {
			t.Errorf("unexpected first row: %+v", rows[0])
		}
	})

	t.Run("filter by hostname", func(t *testing.T) {
		rows, err := store.ListNetworkEgressEvents(100, "api.example.com")
		if err != nil {
			t.Fatalf("ListNetworkEgressEvents: %v", err)
		}
		if len(rows) != 2 {
			t.Errorf("got %d rows, want 2", len(rows))
		}
		for _, r := range rows {
			if r.Hostname != "api.example.com" {
				t.Errorf("unexpected hostname %q in filtered result", r.Hostname)
			}
		}
	})

	t.Run("blocked flag round-trips", func(t *testing.T) {
		rows, err := store.ListNetworkEgressEvents(100, "malicious.io")
		if err != nil || len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d (err=%v)", len(rows), err)
		}
		if !rows[0].Blocked {
			t.Error("expected Blocked=true")
		}
		if rows[0].SessionID != "sess-abc123" {
			t.Errorf("session_id round-trip failed: got %q", rows[0].SessionID)
		}
	})

	t.Run("limit is honoured", func(t *testing.T) {
		rows, err := store.ListNetworkEgressEvents(2, "")
		if err != nil || len(rows) != 2 {
			t.Errorf("got %d rows with limit=2 (err=%v)", len(rows), err)
		}
	})

	t.Run("count blocked", func(t *testing.T) {
		n, err := store.CountBlockedEgress()
		if err != nil {
			t.Fatalf("CountBlockedEgress: %v", err)
		}
		if n != 1 {
			t.Errorf("got %d blocked, want 1", n)
		}
	})
}

func TestStore_QueryNetworkEgressEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	base := time.Now().UTC().Truncate(time.Second)
	boolTrue := true
	boolFalse := false

	fixtures := []NetworkEgressRow{
		{Timestamp: base, Hostname: "a.example.com", SessionID: "s1", PolicyOutcome: "ok", Blocked: false, Severity: "INFO"},
		{Timestamp: base.Add(-time.Minute), Hostname: "b.example.com", SessionID: "s1", PolicyOutcome: "ok", Blocked: false, Severity: "INFO"},
		{Timestamp: base.Add(-2 * time.Minute), Hostname: "evil.io", SessionID: "s2", PolicyOutcome: "denied", Blocked: true, Severity: "HIGH"},
		{Timestamp: base.Add(-3 * time.Minute), Hostname: "a.example.com", SessionID: "s2", PolicyOutcome: "ok", Blocked: false, Severity: "INFO"},
	}
	for _, e := range fixtures {
		if err := store.InsertNetworkEgressEvent(e); err != nil {
			t.Fatalf("InsertNetworkEgressEvent: %v", err)
		}
	}

	tests := []struct {
		name      string
		filter    NetworkEgressFilter
		wantCount int
	}{
		{"no filter returns all", NetworkEgressFilter{}, 4},
		{"hostname filter", NetworkEgressFilter{Hostname: "a.example.com"}, 2},
		{"session filter", NetworkEgressFilter{SessionID: "s1"}, 2},
		{"blocked=true filter", NetworkEgressFilter{Blocked: &boolTrue}, 1},
		{"blocked=false filter", NetworkEgressFilter{Blocked: &boolFalse}, 3},
		{"since filter excludes old", NetworkEgressFilter{Since: base.Add(-90 * time.Second)}, 2},
		{"hostname+session", NetworkEgressFilter{Hostname: "a.example.com", SessionID: "s1"}, 1},
		{"limit 1", NetworkEgressFilter{Limit: 1}, 1},
		{"hostname+blocked=true returns empty", NetworkEgressFilter{Hostname: "a.example.com", Blocked: &boolTrue}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := store.QueryNetworkEgressEvents(tt.filter)
			if err != nil {
				t.Fatalf("QueryNetworkEgressEvents: %v", err)
			}
			if len(rows) != tt.wantCount {
				t.Errorf("got %d rows, want %d", len(rows), tt.wantCount)
			}
		})
	}
}

func TestStore_GetCounts_IncludesBlockedEgress(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	for _, blocked := range []bool{true, true, false} {
		row := NetworkEgressRow{
			Hostname:      "example.com",
			PolicyOutcome: "test",
			Blocked:       blocked,
			Severity:      "INFO",
		}
		if blocked {
			row.Severity = "HIGH"
		}
		if err := store.InsertNetworkEgressEvent(row); err != nil {
			t.Fatalf("InsertNetworkEgressEvent: %v", err)
		}
	}

	counts, err := store.GetCounts()
	if err != nil {
		t.Fatalf("GetCounts: %v", err)
	}
	if counts.BlockedEgressCalls != 2 {
		t.Errorf("BlockedEgressCalls = %d, want 2", counts.BlockedEgressCalls)
	}
}

// --- Logger ---

func TestLogger_LogNetworkEgress(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logger := NewLogger(store)
	ctx := context.Background()

	t.Run("allowed call stored, no alert", func(t *testing.T) {
		evt := NetworkEgressEvent{
			Hostname:      "api.example.com",
			URL:           "https://api.example.com/completions",
			HTTPMethod:    "POST",
			Protocol:      "https",
			PolicyOutcome: "Allowed by pattern: *.example.com",
			DecisionCode:  "NETWORK_ALLOW_PATTERN",
		}
		if err := logger.LogNetworkEgress(ctx, evt); err != nil {
			t.Fatalf("LogNetworkEgress: %v", err)
		}
		rows, err := store.ListNetworkEgressEvents(10, "api.example.com")
		if err != nil || len(rows) != 1 {
			t.Fatalf("expected 1 egress row, got %d (err=%v)", len(rows), err)
		}
		if rows[0].Severity != "INFO" {
			t.Errorf("severity = %q, want INFO", rows[0].Severity)
		}
		alerts, _ := store.ListAlerts(10)
		for _, a := range alerts {
			if a.Action == "network-egress-blocked" {
				t.Error("unexpected blocked alert for allowed egress call")
			}
		}
	})

	t.Run("blocked call stored and raises alert", func(t *testing.T) {
		evt := NetworkEgressEvent{
			Hostname:      "exfil.bad",
			URL:           "http://exfil.bad/upload",
			HTTPMethod:    "PUT",
			Protocol:      "http",
			PolicyOutcome: "Denied: hostname on deny list",
			DecisionCode:  "NETWORK_DENY_PATTERN",
			Blocked:       true,
		}
		if err := logger.LogNetworkEgress(ctx, evt); err != nil {
			t.Fatalf("LogNetworkEgress: %v", err)
		}
		rows, err := store.ListNetworkEgressEvents(10, "exfil.bad")
		if err != nil || len(rows) != 1 {
			t.Fatalf("expected 1 egress row, got %d (err=%v)", len(rows), err)
		}
		if rows[0].Severity != "HIGH" {
			t.Errorf("severity = %q, want HIGH", rows[0].Severity)
		}
		alerts, _ := store.ListAlerts(10)
		var found bool
		for _, a := range alerts {
			if a.Action == "network-egress-blocked" && a.Target == "exfil.bad" {
				found = true
			}
		}
		if !found {
			t.Error("expected a network-egress-blocked alert in audit_events")
		}
	})

	t.Run("validation error propagates", func(t *testing.T) {
		err := logger.LogNetworkEgress(ctx, NetworkEgressEvent{Hostname: "", PolicyOutcome: "x"})
		if err == nil {
			t.Error("expected validation error for empty hostname")
		}
	})

	t.Run("url truncated to 512 bytes", func(t *testing.T) {
		long := "https://api.example.com/" + string(make([]byte, 600))
		if err := logger.LogNetworkEgress(ctx, NetworkEgressEvent{
			Hostname:      "api.example.com",
			URL:           long,
			PolicyOutcome: "Allowed",
		}); err != nil {
			t.Fatalf("LogNetworkEgress: %v", err)
		}
		rows, _ := store.QueryNetworkEgressEvents(NetworkEgressFilter{Hostname: "api.example.com"})
		for _, r := range rows {
			if len(r.URL) > 512 {
				t.Errorf("URL not truncated: len=%d", len(r.URL))
			}
		}
	})

	t.Run("timestamp defaults to now when zero", func(t *testing.T) {
		before := time.Now().UTC().Add(-time.Second)
		if err := logger.LogNetworkEgress(ctx, NetworkEgressEvent{
			Hostname:      "ts.example.com",
			PolicyOutcome: "ok",
		}); err != nil {
			t.Fatalf("LogNetworkEgress: %v", err)
		}
		rows, _ := store.ListNetworkEgressEvents(1, "ts.example.com")
		if len(rows) == 0 {
			t.Fatal("expected 1 row")
		}
		if rows[0].Timestamp.Before(before) {
			t.Errorf("timestamp %v is before expected floor %v", rows[0].Timestamp, before)
		}
	})
}
