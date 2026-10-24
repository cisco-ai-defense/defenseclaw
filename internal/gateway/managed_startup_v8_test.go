// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed (standalone enterprise) gateway upgraded from 1.0.2 boots from a
// config_version 8 file with an observability v8 block and rule-pack assets.
// Its own startup reconcile of those on-disk bytes must report ready (rc.6
// crash-looped here with "config reload refused"), while a later unsigned
// edit of config.yaml is still refused and leaves the generation in place.
func TestManagedGatewayStartsFromV8ObservabilityConfig(t *testing.T) {
	clearGenerationBuildError()
	t.Cleanup(clearGenerationBuildError)
	// The published generation is process-wide; later tests (the provider
	// registry reads it) must not see this managed one.
	previousGeneration := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(previousGeneration) })
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	previousTrust := managedPolicyTreeTrust
	managedPolicyTreeTrust = func(*config.Config, string) error { return nil }
	t.Cleanup(func() { managedPolicyTreeTrust = previousTrust })
	v8Config := func(retentionDays int) []byte {
		return []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\npolicy_dir: %q\n"+
			"observability:\n  local:\n    retention_days: %d\n",
			fixture.dataDir, filepath.Join(fixture.dataDir, "policies"), retentionDays))
	}
	raw := v8Config(30)
	if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// The gateway boots a v8 file through the read-only v9 migration, as
	// the reload loader does.
	initial, err := loadRuntimeConfigCandidate(fixture.configPath, raw)
	if err != nil {
		t.Fatal(err)
	}
	initial = withEnterpriseProfile(initial, managed.ProfileStandalone)
	if err := config.ApplyRuntimeV8DataDirDefaultsFromBytes(initial, fixture.configPath, raw, fixture.dataDir); err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap: bound=%t err=%v", bound, err)
	}
	rulePacks, err := preflightSidecarRulePacks(initial)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := newGuardrailProfileSet(initial, rulePacks.cache, true)
	if err != nil {
		t.Fatal(err)
	}
	live, err := buildGeneration(t.Context(), generationInputs{
		cfg: cloneConfig(initial), raw: raw, rulePacks: rulePacks, profiles: profiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	live.N = 1
	fixture.sidecar.publishGeneration(live)
	mgr := newConfigManagerWithSnapshot(fixture.configPath, initial, nil, fixture.sidecar.health,
		fixture.sidecar.observabilityV8ActivePlanDigest(), fixture.sidecar.applyConfigReloadSnapshot)
	mgr.bindInitialObservabilityV8Plan(fixture.sidecar.observabilityV8ActivePlan())
	loader := mgr.loadSnapshot
	mgr.loadSnapshot = func(path string, raw []byte) (*config.Config, error) {
		candidate, err := loader(path, raw)
		if err == nil {
			candidate = withEnterpriseProfile(candidate, managed.ProfileStandalone)
		}
		return candidate, err
	}
	fixture.sidecar.configMgr = mgr
	fixture.sidecar.watchGenerationAssets()
	if mgr.assetDirs == nil && mgr.assetFiles == nil {
		t.Fatal("rule-pack asset watches are not attached; the startup reconcile would not take the asset path")
	}
	mgr.setStartupSource(fixture.configPath, raw)
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	select {
	case err := <-ready:
		if err != nil {
			cancel()
			<-done
			t.Fatalf("managed gateway startup from a v8 observability config: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("managed gateway startup did not report readiness")
	}
	if !bytes.Equal(mgr.appliedRaw, raw) || mgr.rejected || hasRejection() || fixture.sidecar.Generation() != live {
		cancel()
		<-done
		t.Fatal("startup did not keep the boot generation as the applied one")
	}
	if got := fixture.sidecar.health.Snapshot().Config; got.State != StateRunning || got.LastError != "" {
		cancel()
		<-done
		t.Fatalf("startup config health = %+v", got)
	}
	cancel()
	<-done

	// An unsigned edit that bypasses the bundle is still refused.
	if err := os.WriteFile(fixture.configPath, v8Config(7), 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.Reload(t.Context(), "fsnotify")
	if err == nil || !strings.Contains(err.Error(), "signed") {
		t.Fatalf("unsigned config edit = %v, want signed-bundle refusal", err)
	}
	if fixture.sidecar.Generation() != live || !mgr.rejected {
		t.Fatal("unsigned config edit changed the generation or did not set the rejection")
	}
}
