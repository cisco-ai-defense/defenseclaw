// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

type gap0370BatchEmitter struct {
	audit.RuntimeV8Emitter
	sizes []int
}

func (emitter *gap0370BatchEmitter) EmitRuntimeV8AtomicLogBatch(
	ctx context.Context, operations []audit.RuntimeV8LogOperation,
) ([]audit.RuntimeV8EmitOutcome, error) {
	emitter.sizes = append(emitter.sizes, len(operations))
	atomicRuntime, ok := emitter.RuntimeV8Emitter.(interface {
		EmitRuntimeV8AtomicLogBatch(context.Context, []audit.RuntimeV8LogOperation) ([]audit.RuntimeV8EmitOutcome, error)
	})
	if !ok {
		return nil, fmt.Errorf("atomic runtime unavailable")
	}
	return atomicRuntime.EmitRuntimeV8AtomicLogBatch(ctx, operations)
}

func TestGAP0370ReporterCommitsBoundedMarkerGroups(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints}
	emitter := &gap0370BatchEmitter{RuntimeV8Emitter: runtime}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(emitter)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Now().UTC()
	for i := range 65 {
		appendHookFailures(t, logDir, blockedHookLine(now.Format(time.RFC3339), "PreToolUse", "s", fmt.Sprintf("toolu_batch_%d", i)))
	}
	appendHookFailures(t, logDir, `{"ts":"`+now.Format(time.RFC3339)+`","connector":"claudecode","event":"PreToolUse","outcome":"diagnostic","session_id":"s","call_id":"toolu_benign","tool_id":"toolu_benign"}`+"\n")
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	if len(emitter.sizes) != 3 || emitter.sizes[0] != 32 || emitter.sizes[1] != 32 || emitter.sizes[2] != 1 {
		t.Fatalf("marker group sizes = %v, want 32, 32, 1", emitter.sizes)
	}
	events, err := fixture.store.ListEvents(200)
	if err != nil {
		t.Fatal(err)
	}
	blocked := map[string]bool{}
	for _, event := range events {
		if event.Action == string(audit.ActionGuardrailBlock) {
			blocked[event.ToolID] = true
		}
	}
	for i := range 65 {
		if !blocked[fmt.Sprintf("toolu_batch_%d", i)] {
			t.Fatalf("missing marker %d", i)
		}
	}
	if blocked["toolu_benign"] {
		t.Fatal("diagnostic control received a block marker")
	}
}

func TestGAP0370ReporterWakesOnAppend(t *testing.T) {
	previousInterval := hookFailOpenReportInterval
	hookFailOpenReportInterval = time.Hour
	t.Cleanup(func() { hookFailOpenReportInterval = previousInterval })
	store, logger := testStoreAndLogger(t)
	dataDir := t.TempDir()
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, hookFailuresFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: dataDir}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.watchHookFailureCalls(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// Give the watcher time to register before the first append.
	time.Sleep(100 * time.Millisecond)
	appendHookFailures(t, logDir, blockedHookLine(time.Now().UTC().Format(time.RFC3339), "PreToolUse", "s", "toolu_live_append"))
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := store.ListEvents(100)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Action == string(audit.ActionGuardrailBlock) && event.ToolID == "toolu_live_append" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("appended marker was not reported before the fallback poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
