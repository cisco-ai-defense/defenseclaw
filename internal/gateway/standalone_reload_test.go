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
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

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
	} {
		t.Run(test.name, func(t *testing.T) {
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

func TestConfigManagerReloadAppliesEnterpriseOnlyStandaloneChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	loaded, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	initial := withEnterpriseProfile(loaded, managed.ProfileStandalone)
	var applied ConfigDiff
	calls := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
		calls++
		applied = diff
		return nil
	})
	// The candidate differs from the running config only in its enterprise
	// block, which used to reload as "no change".
	mgr.loadSnapshot = func(path string, raw []byte) (*config.Config, error) {
		cfg, err := config.LoadRuntimeV8CandidateFromBytes(path, raw)
		if err != nil {
			return nil, err
		}
		cfg = withEnterpriseProfile(cfg, managed.ProfileStandalone)
		cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
		return cfg, nil
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if calls != 1 || !slices.Contains(applied.Changed, "enterprise.inspection") {
		t.Fatalf("enterprise-only change was not applied: calls=%d diff=%+v", calls, applied)
	}
	if !mgr.Current().Enterprise.Inspection.AIDefense.Enabled {
		t.Fatal("the running snapshot kept the old enterprise block")
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
			if err != nil {
				t.Fatalf("unmanaged to managed reload = %v, want the candidate handed to apply", err)
			}
			if applied == nil || !slices.Contains(applied.RestartRequired, "deployment_mode") {
				t.Fatalf("unmanaged to managed must reach apply as a deployment_mode restart, got %+v", applied)
			}
		})
	}
}
