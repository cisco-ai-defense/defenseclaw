// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestInventoryStoreInitMigrates is a smoke test for the schema
// migration framework: opening a fresh DB must run the v1 migration
// and end at SchemaVersion()==1. Running a second open must be a
// no-op (no extra migrations applied).
func TestInventoryStoreInitMigrates(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.db")
	st, err := NewInventoryStore(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	v, err := st.SchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != len(inventoryMigrations) {
		t.Errorf("schema version = %d, want %d", v, len(inventoryMigrations))
	}
	st.Close()
	// Reopen: idempotent, same version.
	st2, err := NewInventoryStore(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if v2, _ := st2.SchemaVersion(); v2 != v {
		t.Errorf("reopen schema version = %d, want %d", v2, v)
	}
}

// TestInventoryStoreRecordScanRoundTrip writes one scan, reads back
// the locations + history, and asserts the rolled-up view contains
// the right counts. This is the integration test for the SQL ↔ Go
// boundary; we keep it tight enough to run in <1s.
func TestInventoryStoreRecordScanRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	now := time.Now().UTC()
	scanned := now.Add(-time.Minute)

	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID:        "scan-1",
			ScannedAt:     scanned,
			DurationMs:    42,
			Source:        "sidecar",
			PrivacyMode:   "balanced",
			Result:        "ok",
			TotalSignals:  2,
			ActiveSignals: 2,
			FilesScanned:  4,
		},
		Signals: []AISignal{
			{
				Fingerprint: "fp-1",
				SignalID:    "sig-1",
				SignatureID: "ai-sdks",
				Name:        "openai",
				Vendor:      "OpenAI",
				Product:     "openai",
				Category:    SignalPackageDependency,
				Detector:    "package_manifest",
				State:       AIStateNew,
				Confidence:  0.85,
				Component: &AIComponent{
					Ecosystem: "pypi",
					Name:      "openai",
					Version:   "1.45.0",
					Framework: "openai-python",
				},
				LastSeen: scanned,
				Evidence: []AIEvidence{{
					Type:      "package",
					Basename:  "package.json",
					Quality:   1.0,
					MatchKind: MatchKindExact,
				}},
			},
			{
				Fingerprint: "fp-2",
				SignalID:    "sig-2",
				SignatureID: "ai-sdks",
				Name:        "openai",
				Vendor:      "OpenAI",
				Product:     "openai",
				Category:    SignalActiveProcess,
				Detector:    "process",
				State:       AIStateNew,
				Confidence:  0.85,
				Component: &AIComponent{
					Ecosystem: "pypi",
					Name:      "openai",
				},
				LastSeen:     scanned,
				LastActiveAt: &scanned,
				Evidence: []AIEvidence{{
					Type:      "process",
					Quality:   1.0,
					MatchKind: MatchKindExact,
				}},
			},
		},
	}
	if err := st.RecordScan(context.Background(), report, ConfidenceParams{Policy: policy}); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	// Locations: should return one row per evidence row across the
	// two signals -> 2 rows. RawPath stays empty because we passed
	// includeRawPaths=false.
	locs, err := st.ListComponentLocations(context.Background(), "pypi", "openai", false)
	if err != nil {
		t.Fatalf("list locations: %v", err)
	}
	if len(locs) != 2 {
		t.Errorf("locations count = %d, want 2", len(locs))
	}
	for _, loc := range locs {
		if loc.RawPath != "" {
			t.Errorf("RawPath should be empty when includeRawPaths=false, got %q", loc.RawPath)
		}
	}

	// History: should contain the one snapshot we wrote.
	hist, err := st.ComponentHistory(context.Background(), "pypi", "openai", 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history count = %d, want 1", len(hist))
	}
	h := hist[0]
	if h.IdentityScore <= 0 || h.IdentityScore > 1 {
		t.Errorf("identity score out of range: %v", h.IdentityScore)
	}
	if h.PresenceScore <= 0 || h.PresenceScore > 1 {
		t.Errorf("presence score out of range: %v", h.PresenceScore)
	}
	if h.IdentityBand == "" || h.PresenceBand == "" {
		t.Errorf("bands must be non-empty; got %+v", h)
	}
}

// TestAIComponentsViewCaseInsensitiveJoin pins the v2 migration:
// ai_signals stores the original ecosystem casing (e.g. "PyPI")
// while ai_confidence_snapshots normalises to lowercase. The v1
// view JOIN compared raw columns and silently dropped the score
// columns whenever those didn't match. The v2 view rebuilds the
// JOIN with LOWER() on both sides; this test would flake on the
// pre-fix view because identity_score / presence_score would land
// as NULL.
func TestAIComponentsViewCaseInsensitiveJoin(t *testing.T) {
	dir := t.TempDir()
	st, err := NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	scanned := time.Now().UTC().Add(-time.Minute)
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID:        "scan-mixed-case",
			ScannedAt:     scanned,
			DurationMs:    1,
			Source:        "sidecar",
			PrivacyMode:   "balanced",
			Result:        "ok",
			TotalSignals:  1,
			ActiveSignals: 1,
			FilesScanned:  1,
		},
		Signals: []AISignal{{
			Fingerprint: "fp-mixed",
			SignalID:    "sig-mixed",
			SignatureID: "ai-sdks",
			Name:        "openai",
			Vendor:      "OpenAI",
			Product:     "openai",
			Category:    SignalPackageDependency,
			Detector:    "package_manifest",
			State:       AIStateNew,
			Confidence:  0.85,
			Component: &AIComponent{
				// Mixed-case ecosystem to exercise the JOIN.
				Ecosystem: "PyPI",
				Name:      "OpenAI",
				Version:   "1.45.0",
			},
			LastSeen: scanned,
			Evidence: []AIEvidence{{
				Type: "package", Quality: 1.0, MatchKind: MatchKindExact,
			}},
		}},
	}
	if err := st.RecordScan(context.Background(), report, ConfidenceParams{Policy: policy}); err != nil {
		t.Fatalf("record scan: %v", err)
	}

	row := st.db.QueryRow(`SELECT identity_score, presence_score FROM ai_components_v
		WHERE LOWER(ecosystem) = 'pypi' AND LOWER(name) = 'openai'`)
	var idScore, prScore *float64
	if err := row.Scan(&idScore, &prScore); err != nil {
		t.Fatalf("scan view row: %v", err)
	}
	if idScore == nil || *idScore <= 0 {
		t.Errorf("identity_score = %v; pre-v2 case mismatch returned NULL", idScore)
	}
	if prScore == nil || *prScore <= 0 {
		t.Errorf("presence_score = %v; pre-v2 case mismatch returned NULL", prScore)
	}
}

// TestInventoryStoreNilSafe verifies the helper functions are
// no-ops when the store is nil. The discovery service relies on this
// for the degraded-mode fallback (DB open failed -> invStore nil).
func TestInventoryStoreNilSafe(t *testing.T) {
	var st *InventoryStore
	if err := st.RecordScan(context.Background(), AIDiscoveryReport{}, ConfidenceParams{}); err != nil {
		t.Errorf("nil RecordScan should be no-op, got: %v", err)
	}
	locs, err := st.ListComponentLocations(context.Background(), "pypi", "openai", false)
	if err != nil || locs != nil {
		t.Errorf("nil ListComponentLocations should be no-op, got %v / %v", locs, err)
	}
	hist, err := st.ComponentHistory(context.Background(), "pypi", "openai", 10)
	if err != nil || hist != nil {
		t.Errorf("nil ComponentHistory should be no-op, got %v / %v", hist, err)
	}
	n, err := st.PruneScansBefore(context.Background(), time.Now())
	if err != nil || n != 0 {
		t.Errorf("nil Prune should be no-op, got %d / %v", n, err)
	}
}
