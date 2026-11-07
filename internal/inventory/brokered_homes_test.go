// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path"
	"path/filepath"
	"testing"
	"time"
)

// The allowlist is the catalog's home-relative agent paths and nothing a
// variable, glob, absolute path or parent step could widen.
func TestBrokeredHomeAllowlistIsTheCatalogsHomePaths(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	allow := NewBrokeredHomeAllowlist(catalog)
	for rel, want := range map[string]brokeredAllowance{
		".claude.json":          {MCPShapes: []string{mcpShapeClaudeState}},
		".mcp.json":             {MCPShapes: []string{mcpShapeDotMCP}},
		".claude/settings.json": {},
		"CLAUDE.md":             {},
		".claude/skills":        {Children: true},
	} {
		got, ok := allow[rel]
		if !ok || got.Children != want.Children || len(got.MCPShapes) != len(want.MCPShapes) ||
			(len(want.MCPShapes) > 0 && got.MCPShapes[0] != want.MCPShapes[0]) {
			t.Fatalf("allow[%s] = %+v (present %v), want %+v", rel, got, ok, want)
		}
	}
	for rel := range allow {
		if path.IsAbs(rel) || path.Clean(rel) != rel || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
			t.Fatalf("allowlist path %q is not a clean relative path", rel)
		}
	}
	for _, candidate := range []string{"$CODEX_HOME/skills", "/etc/codex/skills", "~", "~/../etc/shadow", "a/*/b", `..\x`} {
		if rel, ok := brokeredRelativePath(candidate); ok {
			t.Fatalf("brokeredRelativePath(%q) = %q", candidate, rel)
		}
	}
}

// The gateway bounds the helper's answer: a foreign schema or account is
// refused and a path outside the allowlist is dropped.
func TestBrokeredHomeReportValidation(t *testing.T) {
	allow := BrokeredHomeAllowlist{"CLAUDE.md": {}, ".claude/skills": {Children: true}}
	valid := func() BrokeredHomeReport {
		return BrokeredHomeReport{Version: BrokeredHomeReportVersion, Homes: []BrokeredHome{{
			Home: "/sessions/cwk-v1", UID: 1005, User: "cwk-v1",
			Entries: []BrokeredHomeEntry{{Path: "CLAUDE.md"}, {Path: "../../etc/shadow"}},
		}}}
	}
	report := valid()
	if dropped, err := validateBrokeredHomeReport(&report, allow); err != nil || dropped != 1 || len(report.Homes[0].Entries) != 1 {
		t.Fatalf("dropped %d err %v entries %+v", dropped, err, report.Homes[0].Entries)
	}
	for name, mutate := range map[string]func(*BrokeredHomeReport){
		"version": func(r *BrokeredHomeReport) { r.Version = 2 },
		"root":    func(r *BrokeredHomeReport) { r.Homes[0].UID = 0 },
		"home":    func(r *BrokeredHomeReport) { r.Homes[0].Home = "sessions/../x" },
		"user":    func(r *BrokeredHomeReport) { r.Homes[0].User = "a/b" },
		"child name": func(r *BrokeredHomeReport) {
			r.Homes[0].Entries = []BrokeredHomeEntry{{Path: ".claude/skills", Dir: true, Children: []BrokeredHomeChild{{Name: "../x"}}}}
		},
		"server name": func(r *BrokeredHomeReport) {
			r.Homes[0].Entries = []BrokeredHomeEntry{{Path: "CLAUDE.md", MCP: []BrokeredMCPConfig{{Shape: mcpShapeDotMCP, Servers: []string{"x/../y"}}}}}
		},
		"coverage reason": func(r *BrokeredHomeReport) {
			r.Homes[0].Entries = []BrokeredHomeEntry{{Path: "CLAUDE.md", MCP: []BrokeredMCPConfig{{Shape: mcpShapeDotMCP, Partial: "env=KEY"}}}}
		},
	} {
		report := valid()
		mutate(&report)
		if _, err := validateBrokeredHomeReport(&report, allow); err == nil {
			t.Fatalf("%s: accepted %+v", name, report)
		}
	}
}

// A scan whose helper read failed keeps the helper's signals rather than
// reporting them gone; a scan that read the homes and found them missing
// reports them gone.
func TestFailedBrokeredReadKeepsHelperSignals(t *testing.T) {
	service := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{Mode: "passive"},
		store: NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	brokered := AISignal{Fingerprint: "sha256:brokered", SignatureID: "claudecode", Category: SignalSupportedConnector,
		Detector: "config", Source: AISourceSensorHelper, UserID: "1005", UserName: "cwk-v1"}
	stats := func(unavailable bool) scanStats {
		return scanStats{DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}, BrokeredHomesUnavailable: unavailable}
	}
	load := func() aiStateFile {
		prev, err := service.store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return prev
	}
	service.classifyAndPersist("full-1", "test", time.Now(), []AISignal{brokered}, stats(false), load(), true)
	kept := service.classifyAndPersist("full-2", "test", time.Now(), nil, stats(true), load(), true)
	if kept.Summary.GoneSignals != 0 || kept.Summary.ActiveSignals != 1 {
		t.Fatalf("helper down: gone %d active %d", kept.Summary.GoneSignals, kept.Summary.ActiveSignals)
	}
	gone := service.classifyAndPersist("full-3", "test", time.Now(), nil, stats(false), load(), true)
	if gone.Summary.GoneSignals != 1 {
		t.Fatalf("helper up, signal absent: gone %d", gone.Summary.GoneSignals)
	}
}
