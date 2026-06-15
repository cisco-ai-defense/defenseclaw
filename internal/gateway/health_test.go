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
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// connByName indexes a snapshot's per-connector roster by connector name.
func connByName(conns []ConnectorHealth) map[string]ConnectorHealth {
	out := make(map[string]ConnectorHealth, len(conns))
	for _, c := range conns {
		out[c.Name] = c
	}
	return out
}

// TestConnectorCountersAreIsolated verifies that each connector accumulates its
// own counters — the core multi-connector parity guarantee. A tool block on
// codex must never show up under cursor.
func TestConnectorCountersAreIsolated(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", connector.ToolInspectionMode("observe"), connector.SubprocessPolicy("monitor"))
	h.RegisterConnector("cursor", connector.ToolInspectionMode("enforce"), connector.SubprocessPolicy("block"))

	// codex: 3 requests, 1 tool block, 2 inspections.
	h.RecordConnectorRequestFor("codex")
	h.RecordConnectorRequestFor("codex")
	h.RecordConnectorRequestFor("codex")
	h.RecordToolBlockFor("codex")
	h.RecordToolInspectionFor("codex")
	h.RecordToolInspectionFor("codex")

	// cursor: 1 request, 0 tool blocks.
	h.RecordConnectorRequestFor("cursor")

	snap := h.Snapshot()
	if len(snap.Connectors) != 2 {
		t.Fatalf("expected 2 connectors in roster, got %d", len(snap.Connectors))
	}
	byName := connByName(snap.Connectors)

	codex, ok := byName["codex"]
	if !ok {
		t.Fatalf("codex missing from roster: %+v", snap.Connectors)
	}
	if codex.Requests != 3 || codex.ToolBlocks != 1 || codex.ToolInspections != 2 {
		t.Errorf("codex counters wrong: requests=%d toolBlocks=%d inspections=%d",
			codex.Requests, codex.ToolBlocks, codex.ToolInspections)
	}

	cursor, ok := byName["cursor"]
	if !ok {
		t.Fatalf("cursor missing from roster: %+v", snap.Connectors)
	}
	if cursor.Requests != 1 || cursor.ToolBlocks != 0 || cursor.ToolInspections != 0 {
		t.Errorf("cursor counters bled from codex: requests=%d toolBlocks=%d inspections=%d",
			cursor.Requests, cursor.ToolBlocks, cursor.ToolInspections)
	}

	// Static fields are per-connector too.
	if codex.ToolInspectionMode != connector.ToolInspectionMode("observe") {
		t.Errorf("codex mode = %q, want observe", codex.ToolInspectionMode)
	}
	if cursor.ToolInspectionMode != connector.ToolInspectionMode("enforce") {
		t.Errorf("cursor mode = %q, want enforce", cursor.ToolInspectionMode)
	}
}

// TestSetConnectorMarksPrimary confirms the back-compat singular Connector
// tracks whichever connector was set via SetConnector, while every registered
// connector still appears in the Connectors roster.
func TestSetConnectorMarksPrimary(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", "", "")
	h.SetConnector("cursor", "", "") // cursor is primary

	snap := h.Snapshot()
	if snap.Connector == nil {
		t.Fatal("expected singular Connector to be set")
	}
	if snap.Connector.Name != "cursor" {
		t.Errorf("primary = %q, want cursor", snap.Connector.Name)
	}
	if len(snap.Connectors) != 2 {
		t.Errorf("expected both connectors in roster, got %d", len(snap.Connectors))
	}
}

// TestRecordForUnregisteredConnectorLazyCreates ensures a hook firing for a
// connector that has not been registered yet still records its counts (counts
// must never be silently dropped).
func TestRecordForUnregisteredConnectorLazyCreates(t *testing.T) {
	h := NewSidecarHealth()
	h.RecordConnectorRequestFor("ghost")

	snap := h.Snapshot()
	byName := connByName(snap.Connectors)
	ghost, ok := byName["ghost"]
	if !ok {
		t.Fatalf("ghost connector not lazily created: %+v", snap.Connectors)
	}
	if ghost.Requests != 1 {
		t.Errorf("ghost requests = %d, want 1", ghost.Requests)
	}
}

// TestConnectorNameNormalization confirms names are matched case-insensitively
// and trimmed so "Codex", " codex " and "codex" all hit the same bucket.
func TestConnectorNameNormalization(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("Codex", "", "")
	h.RecordConnectorRequestFor(" codex ")
	h.RecordConnectorRequestFor("CODEX")

	snap := h.Snapshot()
	if len(snap.Connectors) != 1 {
		t.Fatalf("expected names to collapse to 1 bucket, got %d: %+v", len(snap.Connectors), snap.Connectors)
	}
	if snap.Connectors[0].Requests != 2 {
		t.Errorf("requests = %d, want 2", snap.Connectors[0].Requests)
	}
}

// TestConcurrentConnectorCounters drives concurrent increments across two
// connectors. Run with -race to assert the per-connector hot path is free of
// data races, and check totals to confirm no increments are lost.
func TestConcurrentConnectorCounters(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", "", "")
	h.RegisterConnector("cursor", "", "")

	const perConn = 1000
	var wg sync.WaitGroup
	for _, name := range []string{"codex", "cursor"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perConn; i++ {
				h.RecordConnectorRequestFor(name)
			}
		}()
	}
	wg.Wait()

	byName := connByName(h.Snapshot().Connectors)
	if byName["codex"].Requests != perConn {
		t.Errorf("codex requests = %d, want %d", byName["codex"].Requests, perConn)
	}
	if byName["cursor"].Requests != perConn {
		t.Errorf("cursor requests = %d, want %d", byName["cursor"].Requests, perConn)
	}
}
