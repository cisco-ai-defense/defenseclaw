// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"go.opentelemetry.io/otel"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestAdmissionSpan_GoldenTree(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	ctx := context.Background()
	ctx, parent := otel.Tracer("defenseclaw").Start(ctx, "http/server")

	ctx, child := enforce.StartAdmissionDecideSpan(ctx, "skill", "x", "pid")
	enforce.EndAdmissionDecideSpan(child, "allowed", "ok", "pid", nil)

	parent.End()

	spans := exp.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("expected spans, got %d", len(spans))
	}
	var sawAdmission bool
	for _, s := range spans {
		if s.Name == "defenseclaw.admission.decide" {
			sawAdmission = true
		}
	}
	if !sawAdmission {
		t.Fatalf("spans: %#v", spans)
	}
}

func TestPolicyFilePoll_BumpsGeneration(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.PolicyDir = filepath.Join(cfg.DataDir, "policies")
	if err := os.MkdirAll(cfg.PolicyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	blockPath := filepath.Join(cfg.DataDir, "block_list.yaml")
	if err := os.WriteFile(blockPath, []byte(`- target_type: skill
  target_name: a
  reason: t
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w.pollPolicyFilesOnce(ctx)
	gen1 := version.Current().Generation
	if err := os.WriteFile(blockPath, []byte(`- target_type: skill
  target_name: b
  reason: t
`), 0o600); err != nil {
		t.Fatal(err)
	}
	w.pollPolicyFilesOnce(ctx)
	gen2 := version.Current().Generation
	if gen2 <= gen1 {
		t.Fatalf("generation did not bump: %d -> %d", gen1, gen2)
	}
}

func TestQuarantineStress_ConcurrentMoves(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "q")
	se := enforce.NewSkillEnforcer(qdir)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			skill := filepath.Join(tmp, fmt.Sprintf("skill-%d", i))
			if err := os.MkdirAll(filepath.Join(skill, "inner"), 0o700); err != nil {
				return
			}
			_, _ = se.Quarantine(skill)
		}(i)
	}
	wg.Wait()
}

func TestRecordQuarantineAction_WithProvider(t *testing.T) {
	rdr := sdkmetric.NewManualReader()
	p, err := telemetry.NewProviderForTest(rdr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordQuarantineAction(ctx, "move_in", "ok")
	p.RecordQuarantineAction(ctx, "move_in", "error")
	_ = time.Now()
}
