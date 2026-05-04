// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

// TestEventStampProvenance verifies the envelope picks up the
// process-wide provenance snapshot. The writer relies on this
// behaviour to keep every tier consistent, so breaking it silently
// would split dashboards across schema versions.
func TestEventStampProvenance(t *testing.T) {
	version.ResetForTesting()
	version.SetBinaryVersion("1.2.3-test")
	if err := version.SetContentHashCanonicalJSON(map[string]any{"k": "v"}); err != nil {
		t.Fatalf("SetContentHashCanonicalJSON: %v", err)
	}
	version.BumpGeneration()
	version.BumpGeneration()

	e := Event{EventType: EventLifecycle}
	e.StampProvenance()

	if e.SchemaVersion != version.SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", e.SchemaVersion, version.SchemaVersion)
	}
	if e.BinaryVersion != "1.2.3-test" {
		t.Fatalf("binary_version = %q", e.BinaryVersion)
	}
	if e.ContentHash == "" {
		t.Fatal("content_hash empty")
	}
	if e.Generation != 2 {
		t.Fatalf("generation = %d, want 2", e.Generation)
	}
}

// TestEventStampProvenanceOverwrites ensures the stamper is
// authoritative. Once called, it MUST overwrite anything callers
// pre-populated so a stale cached value from a worker goroutine
// can't sneak past a provenance bump at the writer choke point.
func TestEventStampProvenanceOverwrites(t *testing.T) {
	version.ResetForTesting()
	version.SetBinaryVersion("9.9.9")

	e := Event{
		EventType:     EventLifecycle,
		SchemaVersion: 1,
		BinaryVersion: "old",
		Generation:    42,
		ContentHash:   "deadbeef",
	}
	e.StampProvenance()

	if e.SchemaVersion != version.SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", e.SchemaVersion, version.SchemaVersion)
	}
	if e.BinaryVersion != "9.9.9" {
		t.Fatalf("binary_version = %q", e.BinaryVersion)
	}
	if e.Generation != 0 {
		t.Fatalf("generation = %d, want 0 after reset", e.Generation)
	}
}

func TestStampAgentWatchContext(t *testing.T) {
	SetAgentWatchContext(AgentWatchContext{
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-1",
		Environment:     "prod",
		DeploymentMode:  "managed",
		DiscoverySource: "registry",
	})
	t.Cleanup(func() { SetAgentWatchContext(AgentWatchContext{}) })

	e := Event{EventType: EventLifecycle}
	StampAgentWatchContext(&e)

	if e.TenantID != "tenant-a" {
		t.Fatalf("tenant_id=%q, want tenant-a", e.TenantID)
	}
	if e.WorkspaceID != "workspace-1" {
		t.Fatalf("workspace_id=%q, want workspace-1", e.WorkspaceID)
	}
	if e.Environment != "prod" {
		t.Fatalf("environment=%q, want prod", e.Environment)
	}
	if e.DeploymentMode != "managed" {
		t.Fatalf("deployment_mode=%q, want managed", e.DeploymentMode)
	}
	if e.DiscoverySource != "registry" {
		t.Fatalf("discovery_source=%q, want registry", e.DiscoverySource)
	}

	pinned := Event{TenantID: "caller-tenant"}
	StampAgentWatchContext(&pinned)
	if pinned.TenantID != "caller-tenant" {
		t.Fatalf("caller-supplied tenant_id was overwritten: %q", pinned.TenantID)
	}
}

// TestEventMarshalOmitsEmptyPayloads pins the contract that each
// event type only carries its own payload; downstream consumers
// dispatch on event_type and shouldn't have to tolerate cross-talk.
func TestEventMarshalOmitsEmptyPayloads(t *testing.T) {
	e := Event{
		Timestamp: time.Unix(0, 0).UTC(),
		EventType: EventScan,
		Severity:  SeverityInfo,
		Scan: &ScanPayload{
			ScanID:  "scan-1",
			Scanner: "skill",
			Target:  "demo.skill",
			Verdict: "clean",
		},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)

	// Note: "verdict" appears both as a top-level payload key and
	// inside ScanPayload; we only check for top-level collisions
	// by matching the key prefix at the expected position.
	for _, banned := range []string{
		`,"verdict":{`, `,"judge":{`, `,"lifecycle":{`,
		`,"error":{`, `,"diagnostic":{`, `,"scan_finding":{`, `,"activity":{`,
		`,"llm_prompt":{`, `,"llm_response":{`, `,"tool_invocation":{`,
	} {
		if strings.Contains(s, banned) {
			t.Errorf("marshalled event should not carry %s for EventScan: %s", banned, s)
		}
	}
	if !strings.Contains(s, `"scan":`) {
		t.Errorf("scan payload missing: %s", s)
	}
}

// TestEventScanFindingPayload pins the per-finding fanout shape so
// SIEM consumers can rely on rule_id + severity + scan_id always
// being present in the payload.
func TestEventScanFindingPayload(t *testing.T) {
	e := Event{
		EventType: EventScanFinding,
		ScanFinding: &ScanFindingPayload{
			ScanID:   "scan-1",
			Scanner:  "mcp",
			Target:   "https://api.example.com",
			RuleID:   "MCP-0001",
			Severity: SeverityCritical,
		},
	}
	b, _ := json.Marshal(e)
	got := string(b)
	for _, want := range []string{
		`"event_type":"scan_finding"`,
		`"scan_id":"scan-1"`,
		`"rule_id":"MCP-0001"`,
		`"severity":"CRITICAL"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

// TestActivityPayloadDiff captures that the diff structure is
// preserved on the wire. Auditors rely on the DiffEntry shape for
// mutation replay — if we accidentally drop/rename fields they
// can't reconstruct before/after state from the log alone.
func TestActivityPayloadDiff(t *testing.T) {
	e := Event{
		EventType: EventActivity,
		Activity: &ActivityPayload{
			Actor:      "cli:alice",
			Action:     "policy-reload",
			TargetType: "policy",
			TargetID:   "default",
			Diff: []DiffEntry{
				{Path: "actions.skill.critical", Op: "replace", Before: "warn", After: "block"},
			},
		},
	}
	b, _ := json.Marshal(e)
	got := string(b)
	for _, want := range []string{
		`"event_type":"activity"`,
		`"actor":"cli:alice"`,
		`"op":"replace"`,
		`"before":"warn"`,
		`"after":"block"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

// TestWriterStampsProvenance verifies the writer choke point stamps
// provenance. Callers should never have to remember to stamp; the
// writer is the sole authority.
func TestWriterStampsProvenance(t *testing.T) {
	version.ResetForTesting()
	version.SetBinaryVersion("7.0.0")

	w, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var seen Event
	w.WithFanout(func(e Event) { seen = e })
	w.Emit(Event{EventType: EventLifecycle})

	if seen.SchemaVersion != version.SchemaVersion {
		t.Fatalf("writer did not stamp schema_version: %+v", seen)
	}
	if seen.BinaryVersion != "7.0.0" {
		t.Fatalf("writer did not stamp binary_version: %+v", seen)
	}
}
