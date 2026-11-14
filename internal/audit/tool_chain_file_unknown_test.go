// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// secretReadProjection is step (1 read, 2 upload) of
// chain.secret_read_then_egress with join identity digest.
func secretReadProjection(t *testing.T, step int, status actionfacts.ParseStatus, digest string) guardrail.ToolChainProjection {
	t.Helper()
	bit, ok := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, step)
	index, okIndex := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	if !ok || !okIndex {
		t.Fatal("chain.secret_read_then_egress is not in the catalog")
	}
	projection := guardrail.ToolChainProjection{ParseStatus: status, DetectionStepMask: bit}
	projection.EnforcementJoinDigests[index] = digest
	return projection
}

// observeSecretReadChain records a read with readDigest and then an upload
// of an exact file in one session; it returns the upload's input and fresh
// result.
func observeSecretReadChain(t *testing.T, fixture *toolChainFixture, session string, readDigest string) (ToolChainObserveInput, ToolChainObserveResult) {
	t.Helper()
	const exact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	read := fixture.seed(t, session, correlationDigest(session+"-read"))
	read.Projection = secretReadProjection(t, 1, actionfacts.StatusPartial, readDigest)
	if _, err := fixture.chain.Observe(t.Context(), read); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	upload := fixture.seed(t, session, correlationDigest(session+"-upload"))
	upload.Projection = secretReadProjection(t, 2, actionfacts.StatusComplete, exact)
	result, err := fixture.chain.Observe(t.Context(), upload)
	if err != nil {
		t.Fatal(err)
	}
	return upload, result
}

// The chain state stores which detected chains joined only through the
// file-unknown marker and returns it on a fresh observe and on a replay; a
// resolved read stores it clear.
func TestToolChainStateStoresFileUnknownJoinMask(t *testing.T) {
	bit, _ := guardrail.ToolChainResultMask(guardrail.ToolChainSecretReadThenEgress)
	for _, row := range []struct {
		name, readDigest string
		wantFileUnknown  bool
	}{
		{"unresolved read (marker)", guardrail.ToolChainFileUnknownDigest, true},
		{"resolved read (exact file)", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fixture := newToolChainFixture(t, ":memory:")
			upload, fresh := observeSecretReadChain(t, fixture, "s-"+row.name, row.readDigest)
			replay, err := fixture.chain.Observe(t.Context(), upload)
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []ToolChainObserveResult{fresh, replay} {
				if got.DetectedMask&bit == 0 || (got.FileUnknownJoinMask&bit != 0) != row.wantFileUnknown {
					t.Fatalf("%s result: detected %#x file-unknown %#x, want file-unknown %t",
						got.Status, got.DetectedMask, got.FileUnknownJoinMask, row.wantFileUnknown)
				}
			}
			if fresh.Status != ToolChainObserveFresh || replay.Status != ToolChainObserveReplay {
				t.Fatalf("statuses %s, %s", fresh.Status, replay.Status)
			}
			var stored uint32
			if err := fixture.store.db.QueryRow(`SELECT file_unknown_chain_mask FROM guardrail_chain_events
				WHERE semantic_event_id=?`, string(upload.SemanticEventID)).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != fresh.FileUnknownJoinMask {
				t.Fatalf("stored mask %#x, result %#x", stored, fresh.FileUnknownJoinMask)
			}
		})
	}
}

// Fail-safe upgrade: a chain event written before file_unknown_chain_mask
// existed reads as resolved. The test writes a marker-only chain, turns the
// database back into the previous format (the column dropped, the last
// migration not applied), reopens it as an upgrade does, and replays the
// upload: the chain is still detected and its mask is clear, so the Agent
// Substrate disposition keeps refusing it.
func TestToolChainStateOldFormatEventReadsAsResolved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if migrations[len(migrations)-1].description !=
		"guardrails: store which detected chains joined only through the file-unknown marker" {
		t.Fatal("the file-unknown mask is no longer the last migration; move this test's downgrade step")
	}
	fixture := newToolChainFixture(t, path)
	upload, fresh := observeSecretReadChain(t, fixture, "s-old", guardrail.ToolChainFileUnknownDigest)
	bit, _ := guardrail.ToolChainResultMask(guardrail.ToolChainSecretReadThenEgress)
	if fresh.FileUnknownJoinMask&bit == 0 {
		t.Fatalf("setup: marker-only chain not marked: %+v", fresh)
	}
	for _, statement := range []string{
		`ALTER TABLE guardrail_chain_events DROP COLUMN file_unknown_chain_mask`,
		fmt.Sprintf(`DELETE FROM schema_version WHERE version=%d`, len(migrations)),
	} {
		if _, err := fixture.store.db.Exec(statement); err != nil {
			t.Fatalf("downgrade %q: %v", statement, err)
		}
	}
	if ok, err := fixture.store.hasColumn("guardrail_chain_events", "file_unknown_chain_mask"); err != nil || ok {
		t.Fatalf("downgrade left the column: ok=%v err=%v", ok, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if version, err := store.SchemaVersion(); err != nil || version != len(migrations) {
		t.Fatalf("schema version=%d want=%d err=%v", version, len(migrations), err)
	}
	chain, err := store.ToolChainRepository()
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.now
	chain.now = func() time.Time { return now }
	replay, err := chain.Observe(t.Context(), upload)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Status != ToolChainObserveReplay || replay.DetectedMask&bit == 0 || replay.FileUnknownJoinMask != 0 {
		t.Fatalf("old-format record: %+v, want a replay that detects the chain with a clear file-unknown mask", replay)
	}
}
