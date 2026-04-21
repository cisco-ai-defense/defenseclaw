// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestAlertsRefresh_IngestsScanFindingFromGatewayJSONL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	gw := filepath.Join(dir, "gateway.jsonl")
	line := `{"ts":"2026-04-20T12:00:00Z","event_type":"scan_finding","severity":"HIGH","scan_finding":{"scan_id":"sid1","scanner":"skill-scanner","target":"t.py","rule_id":"R9","line_number":3,"title":"x"}}` + "\n"
	if err := os.WriteFile(gw, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	p := NewAlertsPanel(store, dir)
	p.Refresh()
	p.expanded["sid1"] = true
	p.rebuildFlat()
	p.applyFilter()

	found := false
	for _, row := range p.filtered {
		if row.Event == nil {
			continue
		}
		if row.Kind == alertFlatScanFinding && row.Event.Action == "scan-finding" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a scan_finding flat row after expand + Refresh")
	}
}
