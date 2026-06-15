// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// TestSQLiteContention_BurstJudgeBodiesNoBusy is the end-to-end
// regression test for the SQLite write-lock remediation. It fires 500
// concurrent judge-body persists through the production wiring
// (JudgeBodyStore + async JudgeStore queue + audit.Logger fan-out)
// and asserts the contracts every phase exists to uphold:
//
//   - zero SQLITE_BUSY counter increments (Phase 1 pool + pragma
//     hygiene, Phase 2 retry wrapper)
//   - zero judge persist drops (Phase 3 async queue depth tuned high
//     enough to absorb the burst)
//   - all 500 rows present in judge_bodies.db (Phase 4 split DB)
//
// Pre-PR (on main) this same harness reproduced "database is locked"
// errors and dropped rows under the same load; post-PR every assertion
// should pass.
func TestSQLiteContention_BurstJudgeBodiesNoBusy(t *testing.T) {
	if testing.Short() {
		t.Skip("burst test takes seconds; skip under -short")
	}

	const totalJudges = 500

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.db")
	bodiesPath := filepath.Join(dir, "judge_bodies.db")

	auditStore, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	if err := auditStore.Init(); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })

	bodyStore, err := audit.NewJudgeBodyStore(bodiesPath)
	if err != nil {
		t.Fatalf("audit.NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = bodyStore.Close() })

	// Wire up a real telemetry provider so we can inspect the
	// SQLite-busy counter and the judge-persist drop counter at the
	// end of the run. The ManualReader lets us pull the snapshot
	// without standing up an exporter.
	reader := sdkmetric.NewManualReader()
	tp, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("telemetry.NewProviderForTest: %v", err)
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// Install the test provider as the global so the package-level
	// helpers in internal/telemetry/global_provider.go
	// (RecordSQLiteBusy, RecordJudgePersistDrop, …) emit into the
	// ManualReader we control. The cleanup restores whatever was
	// installed before so we don't leak state into other e2e tests.
	prev := telemetry.InstallGlobalForTest(tp)
	t.Cleanup(func() { telemetry.InstallGlobalForTest(prev) })

	auditLogger := audit.NewLogger(auditStore)
	auditLogger.SetOTelProvider(tp)
	t.Cleanup(func() { auditLogger.Close() })

	// Queue depth bigger than totalJudges so the burst NEVER drops on
	// the producer side. Phase 3 also flushes in 32-row batches so
	// the worker sees roughly totalJudges / 32 transactions, which
	// is the multiplier we want amortizing fsync cost.
	js := gateway.NewJudgeStoreFromBodyStore(bodyStore, auditLogger, totalJudges*2)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, totalJudges)
	for i := 0; i < totalJudges; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rctx := gateway.ContextWithRequestID(ctx, "req-burst-"+strconv.Itoa(idx))
			rctx = gateway.ContextWithTraceID(rctx, "trace-burst-"+strconv.Itoa(idx))
			rctx = gateway.ContextWithSessionID(rctx, "sess-burst-"+strconv.Itoa(idx))
			err := js.PersistJudgeEvent(rctx, gatewaylog.DirectionPrompt, gatewaylog.JudgePayload{
				Kind:        "injection",
				Model:       "gpt-4o-mini",
				Action:      "warn",
				Severity:    "medium",
				LatencyMs:   12,
				RawResponse: `{"verdict":"warn","reason":"burst-` + strconv.Itoa(idx) + `"}`,
			}, "Bash", "tool-burst-"+strconv.Itoa(idx), "policy-burst", "destination-burst")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("PersistJudgeEvent under burst: %v", err)
		}
	}
	enqueueElapsed := time.Since(start)

	// Phase 3 graceful drain: every queued row must hit disk before
	// Shutdown returns (within the 5s shutdown timeout the queue
	// honors internally). If this fails the worker did not drain.
	if err := js.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	totalElapsed := time.Since(start)

	rows, err := bodyStore.ListJudgeResponses(totalJudges + 5)
	if err != nil {
		t.Fatalf("ListJudgeResponses(judge_bodies.db): %v", err)
	}
	if len(rows) != totalJudges {
		t.Fatalf("judge_bodies.db: want %d rows, got %d (enqueue=%s total=%s)",
			totalJudges, len(rows), enqueueElapsed, totalElapsed)
	}

	// Pull the metric snapshot — both counters MUST be zero for the
	// remediation to be considered complete. If either is non-zero
	// the suite reports the exact value so we can compare against
	// pre-PR baselines.
	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("metric reader.Collect: %v", err)
	}
	if got := sumInt64Counter(rm, "defenseclaw.sqlite.busy_retries"); got != 0 {
		t.Errorf("defenseclaw.sqlite.busy_retries: want 0 under burst (Phase 1/2 broken if non-zero), got %d", got)
	}
	if got := sumInt64Counter(rm, "defenseclaw.judge.persist.drops"); got != 0 {
		t.Errorf("defenseclaw.judge.persist.drops: want 0 with queueDepth=%d (Phase 3 broken if non-zero), got %d", totalJudges*2, got)
	}

	// Phase 4 contract: judge bodies must never land in audit.db.
	auditBodies, err := auditStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses(audit.db): %v", err)
	}
	if len(auditBodies) != 0 {
		t.Fatalf("audit.db judge_responses must remain empty after Phase 4 split; got %d rows", len(auditBodies))
	}

	t.Logf("burst persisted %d judges in %s (enqueue=%s)",
		totalJudges, totalElapsed, enqueueElapsed)
}

// sumInt64Counter is provided by v7_test_helpers.go.
