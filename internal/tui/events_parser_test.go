// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
)

func TestParseGatewayEvent_Scan(t *testing.T) {
	line := `{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"HIGH","scan":{"scan_id":"s1","scanner":"skill-scanner","target":"/x","verdict":"warn","duration_ms":42,"severity_max":"HIGH"}}`
	ev, err := ParseGatewayEvent(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventType != GatewayEventScan || ev.Scan == nil || ev.Scan.ScanID != "s1" {
		t.Fatalf("scan parse mismatch: %#v", ev.Scan)
	}
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parseVerdictRow failed")
	}
	out := renderVerdictLine(row)
	if !strings.Contains(out, "skill-scanner") || !strings.Contains(out, "s1") {
		t.Fatalf("render: %q", out)
	}
}

func TestParseGatewayEvent_ScanFinding(t *testing.T) {
	line := `{"ts":"2026-04-20T12:00:01Z","event_type":"scan_finding","severity":"CRITICAL","scan_finding":{"scan_id":"s1","scanner":"skill-scanner","target":"f.py","rule_id":"R42","line_number":7,"title":"bad"}}`
	ev, err := ParseGatewayEvent(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventType != GatewayEventScanFinding || ev.ScanFinding == nil || ev.ScanFinding.RuleID != "R42" {
		t.Fatalf("finding parse mismatch")
	}
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parseVerdictRow failed")
	}
	out := renderVerdictLine(row)
	if !strings.Contains(out, "R42") || !strings.Contains(out, "7") {
		t.Fatalf("render: %q", out)
	}
}

func TestParseGatewayEvent_Activity(t *testing.T) {
	line := `{"ts":"2026-04-20T12:00:02Z","event_type":"activity","severity":"INFO","activity":{"actor":"alice","action":"config-update","target_type":"config","target_id":"cfg","version_from":"v1","version_to":"v2"}}`
	ev, err := ParseGatewayEvent(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventType != GatewayEventActivity || ev.Activity == nil || ev.Activity.Actor != "alice" {
		t.Fatalf("activity parse mismatch")
	}
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parseVerdictRow failed")
	}
	out := renderVerdictLine(row)
	if !strings.Contains(out, "alice") || !strings.Contains(out, "config-update") {
		t.Fatalf("render: %q", out)
	}
}
