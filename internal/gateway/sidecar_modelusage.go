// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

// modelUsageDBName is the local usage aggregate, next to the audit database.
const modelUsageDBName = "model_usage.db"

// modelUsageDBDir keeps the database in its own folder, so the folder (not
// data_dir) is what the SQLite permissions are applied to.
const modelUsageDBDir = "model_usage"

// modelUsageRuntime is the process-owned model usage engine and its local
// store. Both are created once and are inert until observability.tokenomics
// turns them on; a config reload only calls Apply, never rebuilds them.
type modelUsageRuntime struct {
	engine *modelusage.Engine
	store  *modelusage.Store
}

// modelUsage returns the sidecar usage runtime, creating the inert one on
// first use. The proxy takes ModelUsageRecorder() as its recorder.
func (s *Sidecar) modelUsage() *modelUsageRuntime {
	if rt := s.modelUsageRT.Load(); rt != nil {
		return rt
	}
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	store := modelusage.NewStore(filepath.Join(dataDir, modelUsageDBDir, modelUsageDBName))
	sink := newModelUsageV8Sink(
		func() sidecarRuntimeEmitter { return s.observabilityV8Emitter() },
		func() hookLifecycleMetricV8Runtime {
			r, _ := s.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
			return r
		},
	)
	rt := &modelUsageRuntime{engine: modelusage.NewEngine(sink, store), store: store}
	if s.modelUsageRT.CompareAndSwap(nil, rt) {
		processModelUsage.Store(rt.engine)
		return rt
	}
	return s.modelUsageRT.Load()
}

// ModelUsageRecorder is the recorder the guardrail proxy, the route-only
// listener and the judge call sites record through. It is never nil.
func (s *Sidecar) ModelUsageRecorder() modelusage.Recorder { return s.modelUsage().engine }

// applyModelUsage installs observability.tokenomics and observability.pricing
// from a validated config. It is hot: called at start and on every reload.
func (s *Sidecar) applyModelUsage(cfg *config.Config) {
	if s == nil || cfg == nil {
		return
	}
	rt := s.modelUsage()
	tok, price := cfg.Observability.Tokenomics, cfg.Observability.Pricing
	wantStore := tok.Enabled && tok.LocalStore.Enabled
	if err := rt.store.Configure(wantStore, tok.UsageRetentionDays()); err != nil {
		fmt.Fprintf(os.Stderr, "[modelusage] local usage store unavailable: %v\n", err)
	}
	rt.engine.Apply(tok, price)
}

// stopModelUsage flushes and stops the engine and the store.
func (s *Sidecar) stopModelUsage() {
	if s == nil {
		return
	}
	if rt := s.modelUsageRT.Load(); rt != nil {
		rt.engine.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		_ = rt.store.Configure(false, 0)
	}
}
