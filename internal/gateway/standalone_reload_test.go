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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The first boot after upgrade can still have config_version 8 on disk. The
// boot loader and the watcher must agree on its effective configuration, and
// the startup asset reconciliation must recognize the exact disk snapshot.
func TestStandaloneStartupReconcilesUnmigratedV8File(t *testing.T) {
	clearGenerationBuildError()
	t.Cleanup(clearGenerationBuildError)
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	previousTrust := managedPolicyTreeTrust
	managedPolicyTreeTrust = func(*config.Config, string) error { return nil }
	t.Cleanup(func() { managedPolicyTreeTrust = previousTrust })
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\npolicy_dir: %q\nskill_actions:\n  medium:\n    install: block\n    file: quarantine\n    runtime: disable\nobservability: {}\n",
		fixture.dataDir, filepath.Join(fixture.dataDir, "policies")))
	if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := config.MigrateV8InMemory(fixture.configPath, raw, guardrail.RulePackDigest)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8FromBytes(fixture.configPath, migrated)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := config.ParseCompileObservabilityV8(fixture.configPath, migrated,
		config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir})
	if err != nil {
		t.Fatal(err)
	}
	initial = withEnterpriseProfile(initial, managed.ProfileStandalone)
	initial.DataDir = compiled.DataDir
	initial.AuditDB = compiled.Plan.Snapshot().Local.Path
	initial.JudgeBodiesDB = compiled.Plan.Snapshot().Local.JudgeBodiesPath
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap unmigrated v8 file: bound=%t err=%v", bound, err)
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
	mgr.setStartupSource(fixture.sidecar.bootConfigSourceName, fixture.sidecar.bootConfigSource)
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	select {
	case err := <-ready:
		cancel()
		<-done
		if err != nil {
			t.Fatalf("managed startup asset reconcile from v8 file: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("managed startup from v8 file did not report readiness")
	}
	if mgr.rejected || !bytes.Equal(mgr.appliedRaw, raw) || fixture.sidecar.Generation() != live {
		t.Fatalf("startup rejected or lost v8 disk snapshot: rejected=%t applied=%q", mgr.rejected, mgr.appliedRaw)
	}
}

// A standalone gateway starts its config watcher with asset watches attached.
// Readiness and later no-op events must prove the published generation again;
// an unsigned asset edit must leave that generation in place and name the asset.
func TestStandaloneConfigManagerStartupAndAssetEventsProveGeneration(t *testing.T) {
	clearGenerationBuildError()
	t.Cleanup(clearGenerationBuildError)
	fixture := newSidecarV8BootstrapFixture(t, config.ConfigVersionV9, "")
	previousTrust := managedPolicyTreeTrust
	managedPolicyTreeTrust = func(*config.Config, string) error { return nil }
	t.Cleanup(func() { managedPolicyTreeTrust = previousTrust })
	pack := filepath.Join(fixture.dataDir, "signature-pack.json")
	originalPack := []byte(`{"version":1,"signatures":[]}`)
	if err := os.WriteFile(pack, originalPack, 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\npolicy_dir: %q\nai_discovery:\n  signature_packs: [%q]\nobservability: {}\n",
		fixture.dataDir, filepath.Join(fixture.dataDir, "policies"), pack))
	if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
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
	mgr.setStartupSource(fixture.configPath, raw)
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	select {
	case err := <-ready:
		cancel()
		<-done
		if err != nil {
			t.Fatalf("standalone startup with unchanged assets: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("standalone startup did not report readiness")
	}
	if !bytes.Equal(mgr.appliedRaw, raw) || mgr.rejected || mgr.gen.Load() != 0 || fixture.sidecar.Generation() != live {
		t.Fatal("startup did not preserve the applied standalone generation")
	}
	if err := os.WriteFile(pack, originalPack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(t.Context(), "asset_watch"); err != nil {
		t.Fatalf("unchanged asset event: %v", err)
	}
	if got := fixture.sidecar.health.Snapshot().Config; got.State != StateRunning || got.LastError != "" || hasRejection() {
		t.Fatalf("unchanged asset event health = %+v", got)
	}
	if err := os.WriteFile(pack, []byte(`{"version":1, "signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.ReloadAssets(t.Context(), "asset_watch")
	if err == nil || !strings.Contains(err.Error(), "signature_pack:") || !strings.Contains(err.Error(), "signed policy bundle") {
		t.Fatalf("unsigned signature pack edit = %v, want named asset refusal", err)
	}
	if fixture.sidecar.Generation() != live || mgr.gen.Load() != 0 || !mgr.rejected || !hasRejection() {
		t.Fatal("unsigned asset edit changed the generation or did not set rejection")
	}
	if err := os.WriteFile(pack, originalPack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(t.Context(), "asset_watch"); err != nil {
		t.Fatalf("restored asset: %v", err)
	}
	if fixture.sidecar.Generation() != live || mgr.gen.Load() != 0 || mgr.rejected || hasRejection() {
		t.Fatal("restored asset did not clear the error without a generation swap")
	}
}

// A repaired config may clear a standing reload error only when rebuilding it
// proves that the running generation is still the same. Neither the repair
// nor a later asset event grants permission to apply an unsigned generation.
func TestStandaloneConfigManagerRestoredConfigClearsRejection(t *testing.T) {
	for _, rejection := range []string{"invalid YAML", "unsigned edit"} {
		for _, restoreWithAssets := range []bool{false, true} {
			name := fmt.Sprintf("%s/assets=%t", rejection, restoreWithAssets)
			t.Run(name, func(t *testing.T) {
				clearGenerationBuildError()
				t.Cleanup(clearGenerationBuildError)
				dir := t.TempDir()
				path := filepath.Join(dir, "config.yaml")
				asset := filepath.Join(dir, "asset.rego")
				if err := os.WriteFile(asset, []byte("package original"), 0o600); err != nil {
					t.Fatal(err)
				}
				writeConfigForManagerTest(t, path, dir, "observe")
				good, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				initial, err := config.LoadRuntimeV8File(path)
				if err != nil {
					t.Fatal(err)
				}
				initial = withEnterpriseProfile(initial, managed.ProfileStandalone)
				health := NewSidecarHealth()
				applyCalls := 0
				mgr := newConfigManagerWithSnapshot(path, initial, nil, health, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
					applyCalls++
					if !slices.Equal(diff.Changed, []string{configDiffAssets}) {
						t.Fatalf("recovery diff = %+v, want assets-only rebuild", diff)
					}
					contents, err := os.ReadFile(asset)
					if err != nil {
						return err
					}
					if string(contents) != "package original" {
						return fmt.Errorf("config reload refused: referenced asset %s differs; apply a new signed policy bundle", asset)
					}
					return errGenerationUnchanged
				})
				mgr.assetFiles = func() []string { return []string{asset} }
				loader := mgr.loadSnapshot
				mgr.loadSnapshot = func(path string, raw []byte) (*config.Config, error) {
					candidate, err := loader(path, raw)
					if err == nil {
						candidate = withEnterpriseProfile(candidate, managed.ProfileStandalone)
					}
					return candidate, err
				}
				// Boot and hot reload both use the in-memory migration for v8.
				// Seed the applied snapshot through that same path so Windows
				// does not compare v8 path defaults against migrated v9 defaults.
				applied, source, err := mgr.loadStableCandidate(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				mgr.current.Store(cloneConfig(applied))
				mgr.bindInitialObservabilityV8Plan(source.compiledV8.Plan)
				mgr.appliedRaw = good
				mgr.appliedGenerationKnown = true
				bad := []byte("openshell: [invalid\n")
				if rejection == "unsigned edit" {
					bad = append(append([]byte(nil), good...), []byte("\ngateway:\n  api_port: 19080\n")...)
				}
				if err := os.WriteFile(path, bad, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := mgr.Reload(t.Context(), "watch"); err == nil {
					t.Fatal("unsigned or invalid edit was accepted")
				}
				if !mgr.rejected || health.Snapshot().Config.State != StateError || !hasRejection() {
					t.Fatalf("rejection not reported: manager=%t health=%+v", mgr.rejected, health.Snapshot().Config)
				}
				if err := os.WriteFile(path, good, 0o600); err != nil {
					t.Fatal(err)
				}
				if restoreWithAssets {
					err = mgr.ReloadAssets(t.Context(), "asset_watch")
				} else {
					err = mgr.Reload(t.Context(), "watch")
				}
				if err != nil || mgr.rejected || hasRejection() || applyCalls != 1 || mgr.gen.Load() != 0 {
					t.Fatalf("restored config: err=%v rejected=%t reload_error=%t rebuilds=%d generation=%d", err, mgr.rejected, hasRejection(), applyCalls, mgr.gen.Load())
				}
				if got := health.Snapshot().Config; got.State != StateRunning || got.LastError != "" {
					t.Fatalf("restored config health = %+v", got)
				}
				if err := mgr.ReloadAssets(t.Context(), "unchanged_asset_watch"); err != nil {
					t.Fatalf("unchanged later asset event = %v", err)
				}
				if err := os.WriteFile(asset, []byte("package changed"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := mgr.ReloadAssets(t.Context(), "unsigned_asset_watch"); err == nil || !strings.Contains(err.Error(), asset) {
					t.Fatalf("unreceipted changed asset event = %v, want named refusal", err)
				}
				if applyCalls != 3 {
					t.Fatalf("expected recovery, unchanged proof and changed refusal; rebuilds=%d", applyCalls)
				}
			})
		}
	}
}

func TestStandaloneConfigManagerRecoveryNeverPublishesChangedAsset(t *testing.T) {
	clearGenerationBuildError()
	t.Cleanup(clearGenerationBuildError)
	fixture := newSidecarV8BootstrapFixture(t, config.ConfigVersionV9, "")
	previousTrust := managedPolicyTreeTrust
	managedPolicyTreeTrust = func(*config.Config, string) error { return nil } // TempDir is not root-owned.
	t.Cleanup(func() { managedPolicyTreeTrust = previousTrust })
	pack := filepath.Join(fixture.dataDir, "signature-pack.json")
	originalPack := []byte(`{"version":1,"signatures":[]}`)
	if err := os.WriteFile(pack, originalPack, 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\npolicy_dir: %q\nai_discovery:\n  signature_packs: [%q]\nobservability: {}\n",
		fixture.dataDir, filepath.Join(fixture.dataDir, "policies"), pack))
	if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
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
	mgr.appliedRaw = raw
	mgr.appliedGenerationKnown = true
	if err := os.WriteFile(fixture.configPath, []byte("openshell: [invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "watch"); err == nil {
		t.Fatal("invalid candidate was accepted")
	}
	if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, []byte(`{"version":1, "signatures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "restore"); err == nil || !strings.Contains(err.Error(), "referenced assets differ") {
		t.Fatalf("restored config with unreceipted asset = %v, want asset mismatch refusal", err)
	}
	if fixture.sidecar.Generation() != live || mgr.gen.Load() != 0 || !mgr.rejected {
		t.Fatal("unreceipted asset changed the published generation or cleared the rejection")
	}
	if err := os.WriteFile(pack, originalPack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ReloadAssets(t.Context(), "asset_restored"); err != nil {
		t.Fatalf("restored asset: %v", err)
	}
	if fixture.sidecar.Generation() != live || mgr.gen.Load() != 0 || mgr.rejected || hasRejection() {
		t.Fatalf("restored asset changed the generation or left health rejected: gen=%d rejected=%t error=%t", mgr.gen.Load(), mgr.rejected, hasRejection())
	}
	if got := fixture.sidecar.health.Snapshot().Config; got.State != StateRunning || got.LastError != "" {
		t.Fatalf("restored asset health = %+v", got)
	}
}

func withEnterpriseProfile(cfg *config.Config, profile string) *config.Config {
	next := cloneConfig(cfg)
	next.DeploymentMode = managed.DeploymentModeManagedEnterprise
	next.Enterprise.Profile = profile
	return next
}

func TestDiffConfigsSeesStandaloneEnterpriseChanges(t *testing.T) {
	base := withEnterpriseProfile(config.DefaultConfig(), managed.ProfileStandalone)
	for _, test := range []struct {
		name        string
		mutate      func(*config.Config)
		wantChanged string
		wantRestart bool
		listsHot    bool
	}{
		{
			name: "ai defense enabled",
			mutate: func(c *config.Config) {
				c.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
			},
			wantChanged: "enterprise.inspection",
		},
		{
			name:        "egress proxy",
			mutate:      func(c *config.Config) { c.Enterprise.Network.HTTPSProxy = "http://proxy.corp:3128" },
			wantChanged: "enterprise.network",
			wantRestart: true,
		},
		{
			name:        "enrollment",
			mutate:      func(c *config.Config) { c.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny },
			wantChanged: "enterprise",
			wantRestart: true,
		},
		{
			// GAP-0716: on Windows who is enrolled reloads in place.
			name:        "exclude_users on windows",
			mutate:      func(c *config.Config) { c.Enterprise.Enrollment.ExcludeUsers = []string{"dcw-eo5"} },
			wantChanged: "enterprise.enrollment",
			listsHot:    true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := standaloneEnrollmentListsHot
			standaloneEnrollmentListsHot = test.listsHot
			t.Cleanup(func() { standaloneEnrollmentListsHot = previous })
			next := cloneConfig(base)
			test.mutate(next)
			diff := diffConfigs(base, next)
			if !slices.Equal(diff.Changed, []string{test.wantChanged}) {
				t.Fatalf("changed = %v, want [%s]", diff.Changed, test.wantChanged)
			}
			if got := slices.Contains(diff.RestartRequired, test.wantChanged); got != test.wantRestart {
				t.Fatalf("restart required = %v, want %s restart=%t", diff.RestartRequired, test.wantChanged, test.wantRestart)
			}
			if test.wantChanged == "enterprise.inspection" && !inspectorNeedsRebuild(base, next) {
				t.Fatalf("%s must rebuild the standalone AI Defense client", test.wantChanged)
			}
		})
	}
}

func standaloneDiffTestConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise = config.EnterpriseConfig{
		Profile: managed.ProfileStandalone,
		Inspection: config.EnterpriseInspectionConfig{AIDefense: config.EnterpriseAIDefenseConfig{
			Enabled: true, Credential: "ai-defense-api-key",
		}},
		Enrollment: config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"svc-release"}},
		MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
			"codex": {AllowedHooks: []string{}},
		}},
		Network: config.EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128"},
	}
	return cfg
}

// A clone of a config with a full enterprise block diffs as unchanged.
func TestDiffConfigsSeesNoEnterpriseChangeAcrossAClone(t *testing.T) {
	oldCfg := standaloneDiffTestConfig()
	if diff := diffConfigs(oldCfg, cloneConfig(oldCfg)); len(diff.Changed) != 0 {
		t.Fatalf("an unchanged enterprise block diffed as changed: %v", diff.Changed)
	}
	secureClient := config.DefaultConfig()
	secureClient.DeploymentMode = managed.DeploymentModeManagedEnterprise
	secureClient.Enterprise.Profile = managed.ProfileSecureClient
	if diff := diffConfigs(secureClient, cloneConfig(secureClient)); len(diff.Changed) != 0 || len(diff.RestartRequired) != 0 {
		t.Fatalf("an unchanged Secure Client config diffed as %+v", diff)
	}
}

func TestDiffConfigsLeavesSecureClientEnterpriseUntouched(t *testing.T) {
	// A Secure Client deployment carries no enterprise block; nothing about
	// its diff, restart set or inspector rebuild may change.
	base := withEnterpriseProfile(config.DefaultConfig(), "")
	next := cloneConfig(base)
	next.Enterprise.Inspection.AIDefense.Enabled = true
	next.Enterprise.Network.HTTPSProxy = "http://proxy.corp:3128"
	diff := diffConfigs(base, next)
	if len(diff.Changed) != 0 || len(diff.RestartRequired) != 0 {
		t.Fatalf("Secure Client diff = %+v, want empty", diff)
	}
	if inspectorNeedsRebuild(base, next) {
		t.Fatal("Secure Client inspector rebuild must depend on cisco_ai_defense only")
	}
}

func TestStandaloneReloadRebuildsTheAIDefenseClient(t *testing.T) {
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)

	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nobservability: {}\n", fixture.dataDir))
	loaded, err := config.LoadRuntimeV8CandidateFromBytes(fixture.configPath, raw)
	if err != nil {
		t.Fatalf("load reload fixture: %v", err)
	}
	oldCfg := withEnterpriseProfile(loaded, managed.ProfileStandalone)
	fixture.sidecar.publishConfig(oldCfg)
	fixture.sidecar.router = routerWithDefaultRulePack(t)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		fixture.configPath, raw, config.ObservabilityV8CompileOptions{DefaultDataDir: fixture.dataDir},
	)
	if err != nil {
		t.Fatalf("compile observability plan: %v", err)
	}
	// Local-only standalone: the local engine is all there is.
	fixture.sidecar.pickInspector(context.Background())
	if available, _ := fixture.sidecar.inspectionAvailability(); !available {
		t.Fatal("precondition: local-only standalone inspection is available")
	}

	next := cloneConfig(oldCfg)
	next.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	diff := diffConfigs(oldCfg, next)
	if len(diff.RestartRequired) != 0 {
		t.Fatalf("enabling standalone AI Defense must be hot, restart required = %v", diff.RestartRequired)
	}
	if err := fixture.sidecar.applyConfigReloadSnapshot(
		context.Background(), oldCfg, next, diff,
		configReloadSource{sourceName: fixture.configPath, raw: raw, compiledV8: compiled},
	); err != nil {
		t.Fatalf("apply standalone AI Defense reload: %v", err)
	}
	available, reason := fixture.sidecar.inspectionAvailability()
	if available || !strings.Contains(reason, "ai-defense-api-key") {
		t.Fatalf("reload did not rebuild the AI Defense client: available=%t reason=%q", available, reason)
	}
}

func TestConfigManagerReloadRefusesUnbundledEnterpriseOnlyStandaloneChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	loaded, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	initial := withEnterpriseProfile(loaded, managed.ProfileStandalone)
	calls := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, _ ConfigDiff, _ configReloadSource) error {
		calls++
		return nil
	})
	// An enterprise-only candidate used to reload as "no change". The
	// standalone manager now requires its signed bundle generation too.
	mgr.loadSnapshot = func(path string, raw []byte) (*config.Config, error) {
		cfg, err := config.LoadRuntimeV8CandidateFromBytes(path, raw)
		if err != nil {
			return nil, err
		}
		cfg = withEnterpriseProfile(cfg, managed.ProfileStandalone)
		cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
		return cfg, nil
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil || !strings.Contains(err.Error(), "signed policy bundle") {
		t.Fatalf("unbundled enterprise-only reload = %v, want signed-bundle refusal", err)
	}
	if calls != 0 || mgr.Current().Enterprise.Inspection.AIDefense.Enabled {
		t.Fatalf("unbundled enterprise-only change applied: calls=%d current=%+v", calls, mgr.Current().Enterprise.Inspection.AIDefense)
	}
}

func TestConfigManagerReloadProfileGuard(t *testing.T) {
	for _, test := range []struct {
		name        string
		fromProfile string // "-" = unmanaged
		toProfile   string
		wantGuard   bool
	}{
		{name: "unmanaged to standalone", fromProfile: "-", toProfile: managed.ProfileStandalone},
		{name: "secure client to standalone", fromProfile: managed.ProfileSecureClient, toProfile: managed.ProfileStandalone, wantGuard: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatalf("initial load: %v", err)
			}
			if test.fromProfile != "-" {
				initial = withEnterpriseProfile(initial, test.fromProfile)
			}
			var applied *ConfigDiff
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
				applied = &diff
				return nil
			})
			mgr.loadSnapshot = func(path string, raw []byte) (*config.Config, error) {
				cfg, err := config.LoadRuntimeV8CandidateFromBytes(path, raw)
				if err != nil {
					return nil, err
				}
				cfg = withEnterpriseProfile(cfg, test.toProfile)
				// A Secure Client candidate needs its managed AI Defense
				// destination to compile the telemetry plan.
				cfg.CiscoAIDefense.Endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
				return cfg, nil
			}
			err = mgr.Reload(context.Background(), "test")
			guarded := err != nil && strings.Contains(err.Error(), "cannot change the enterprise profile")
			if guarded != test.wantGuard {
				t.Fatalf("reload error = %v, want profile guard %t", err, test.wantGuard)
			}
			if test.wantGuard {
				if applied != nil {
					t.Fatalf("a rejected profile change reached apply: %+v", *applied)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "signed policy bundle") {
				t.Fatalf("unmanaged to managed reload = %v, want signed-bundle refusal", err)
			}
			if applied != nil {
				t.Fatalf("unbundled managed candidate reached apply: %+v", *applied)
			}
		})
	}
}
