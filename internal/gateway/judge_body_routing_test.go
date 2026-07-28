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
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestSidecar_WiresJudgeBodyStore reproduces the exact wiring NewSidecar
// performs when retain_judge_bodies is on: it opens a dedicated
// JudgeBodyStore, wraps it in judgeBodyStoreInserter, hands that to
// NewJudgeStore, and drives a single PersistJudgeEvent through the
// queue. The post-condition is that the row lands in judge_bodies.db
// and *not* in audit.db — which is the entire point of the Phase 4
// split: audit_events / activity_events writers on audit.db must
// never share a write lock with judge body INSERTs.
func TestSidecar_WiresJudgeBodyStore(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.db")
	bodiesPath := filepath.Join(dir, "judge_bodies.db")

	auditStore, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	if err := auditStore.Init(); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}

	bodyStore, err := openAuthoritativeJudgeBodyStore(t.Context(), bodiesPath, auditStore)
	if err != nil {
		t.Fatalf("openAuthoritativeJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = bodyStore.Close() })

	// auditLogger is what NewSidecar passes for the redacted audit
	// fan-out. We don't drive the fan-out here (no Writer wired)
	// but the JudgeStore needs a non-nil logger to keep the fan-out
	// code path nominal.
	auditLogger := audit.NewLogger(auditStore)
	t.Cleanup(func() { auditLogger.Close() })

	js := NewJudgeStore(&judgeBodyStoreInserter{s: bodyStore}, auditLogger, 0 /* default queue depth */)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// PersistJudgeEvent accepts tool/policy/destination metadata as
	// explicit args; request/trace/session IDs are pulled from
	// context. We stamp them via the Set*Context helpers so the
	// queued job carries the same identifiers a real proxy hop
	// would.
	ctx = ContextWithRequestID(ctx, "req-routing-1")
	ctx = ContextWithTraceID(ctx, "trace-routing-1")
	ctx = ContextWithSessionID(ctx, "session-routing-1")

	if err := js.PersistJudgeEvent(ctx, gatewaylog.DirectionPrompt, gatewaylog.JudgePayload{
		Kind:        "injection",
		Model:       "gpt-4o-mini",
		Action:      "warn",
		Severity:    "medium",
		LatencyMs:   17,
		RawResponse: `{"verdict":"warn","reason":"looks like a credential"}`,
	}, "Bash", "tool-routing-1", "policy-routing-1", "destination-routing-1"); err != nil {
		t.Fatalf("PersistJudgeEvent: %v", err)
	}

	if err := js.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	bodies, err := bodyStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses(judge_bodies.db): %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("judge_bodies.db: want 1 row, got %d", len(bodies))
	}
	if got := bodies[0].RequestID; got != "req-routing-1" {
		t.Errorf("judge_bodies.db row RequestID: want req-routing-1, got %q", got)
	}

	// The critical Phase 4 assertion: audit.db's judge_responses
	// table stays empty. The redacted audit_events row goes through
	// audit.Logger.LogEvent (we exercise that in other tests); the
	// raw body must never end up in audit.db once the split is
	// wired correctly. If a future refactor accidentally routes
	// the body insert back through audit.Store, this assertion
	// catches it.
	auditBodies, err := auditStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses(audit.db): %v", err)
	}
	if len(auditBodies) != 0 {
		t.Fatalf("audit.db judge_responses must remain empty after Phase 4 split; got %d rows", len(auditBodies))
	}
}

func TestOpenAuthoritativeJudgeBodyStore_CutoverFailureNeverFallsBack(t *testing.T) {
	dir := t.TempDir()
	legacy, err := audit.NewStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = legacy.Close() })
	if err := legacy.Init(); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}
	legacyRow := audit.JudgeResponse{
		ID: "stable-id", Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		Kind: "pii", Raw: "legacy body",
	}
	if err := legacy.InsertJudgeResponse(legacyRow); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	targetPath := filepath.Join(dir, "judge_bodies.db")
	seed, err := audit.NewJudgeBodyStore(targetPath)
	if err != nil {
		t.Fatalf("audit.NewJudgeBodyStore(seed): %v", err)
	}
	conflict := legacyRow
	conflict.Raw = "conflicting target body"
	if err := seed.InsertJudgeResponse(conflict); err != nil {
		t.Fatalf("seed target conflict: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed target: %v", err)
	}

	store, err := openAuthoritativeJudgeBodyStore(t.Context(), targetPath, legacy)
	if err == nil {
		if store != nil {
			_ = store.Close()
		}
		t.Fatal("openAuthoritativeJudgeBodyStore conflict = nil, want startup failure")
	}
	if store != nil {
		t.Fatal("failed cutover returned a writable store")
	}
	// A failed cutover leaves the pre-upgrade writer active; critically, the
	// gateway helper does not construct an audit.Store-backed JudgeStore.
	if err := legacy.InsertJudgeResponse(audit.JudgeResponse{
		ID: "pre-cutover", Kind: "pii", Raw: "still legacy",
	}); err != nil {
		t.Fatalf("legacy writer after failed cutover: %v", err)
	}
}
