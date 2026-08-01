// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func TestEnterpriseHookLifecycleModeMatrixIsOptIn(t *testing.T) {
	hookConnector := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	proxyConnector := &bootStubConnector{stubConnector: stubConnector{name: "openclaw"}}

	tests := []struct {
		name             string
		mode             string
		guardianOwnsHook bool
	}{
		{name: "legacy default", mode: ""},
		{name: "unmanaged BYOD", mode: string(config.DeploymentModeUnmanagedBYOD)},
		{name: "CI/CD", mode: string(config.DeploymentModeCICD)},
		{name: "sandboxed", mode: string(config.DeploymentModeSandboxed)},
		{name: "server", mode: string(config.DeploymentModeServer)},
		{name: "SaaS", mode: string(config.DeploymentModeSaaS)},
		{
			name:             "managed enterprise",
			mode:             string(config.DeploymentModeManagedEnterprise),
			guardianOwnsHook: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{DeploymentMode: tc.mode}
			if got := managedEnterpriseGuardianOwnsConnectorLifecycle(cfg, hookConnector); got != tc.guardianOwnsHook {
				t.Fatalf(
					"managedEnterpriseGuardianOwnsConnectorLifecycle(mode=%q, hook connector) = %v, want %v",
					tc.mode,
					got,
					tc.guardianOwnsHook,
				)
			}
			wantManager := "gateway"
			if tc.guardianOwnsHook {
				wantManager = "enterprise_hook_guardian"
			}
			if got := lifecycleManagerForConnector(cfg, hookConnector); got != wantManager {
				t.Fatalf("lifecycleManagerForConnector(mode=%q) = %q, want %q", tc.mode, got, wantManager)
			}

			// Enterprise hardening applies only to hook-native lifecycle
			// surfaces. Proxy connectors remain owned by the gateway in every
			// deployment mode.
			if managedEnterpriseGuardianOwnsConnectorLifecycle(cfg, proxyConnector) {
				t.Fatalf("mode=%q transferred a proxy connector to the hook guardian", tc.mode)
			}
		})
	}
}

func TestApplicationProtectionModeMatrixPreservesUnmanagedBaselineRepair(t *testing.T) {
	tests := []struct {
		name            string
		mode            string
		wantSetupCalls  int
		wantGuardianOwn bool
	}{
		{name: "legacy default", mode: "", wantSetupCalls: 1},
		{name: "unmanaged BYOD", mode: string(config.DeploymentModeUnmanagedBYOD), wantSetupCalls: 1},
		{name: "CI/CD", mode: string(config.DeploymentModeCICD), wantSetupCalls: 1},
		{name: "sandboxed", mode: string(config.DeploymentModeSandboxed), wantSetupCalls: 1},
		{name: "server", mode: string(config.DeploymentModeServer), wantSetupCalls: 1},
		{name: "SaaS", mode: string(config.DeploymentModeSaaS), wantSetupCalls: 1},
		{
			name:            "managed enterprise",
			mode:            string(config.DeploymentModeManagedEnterprise),
			wantSetupCalls:  0,
			wantGuardianOwn: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hookConfigPath := filepath.Join(dir, "codex", "config.toml")

			// A previously active connector with a deleted native config is the
			// baseline automatic-repair path. Outside managed_enterprise the
			// gateway must continue to call Setup even though first-time setup
			// would skip a missing native config.
			if err := saveApplicationProtectionState(dir, applicationProtectionState{
				Version: 1,
				Active: []applicationProtectionActiveRow{{
					Connector:   "codex",
					Source:      "automatic",
					ActivatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
				}},
			}); err != nil {
				t.Fatalf("seed application protection state: %v", err)
			}
			if _, err := os.Stat(hookConfigPath); !os.IsNotExist(err) {
				t.Fatalf("deleted-hook fixture unexpectedly exists: %v", err)
			}

			cfg := &config.Config{
				DataDir:               dir,
				DeploymentMode:        tc.mode,
				ApplicationProtection: enabledApplicationProtectionConfig(),
				Guardrail: config.GuardrailConfig{
					HookSelfHeal: true,
				},
			}
			sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
			registry := connector.NewRegistry()
			conn := &appProtectionHookStub{
				bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
				hookConfigPath:    hookConfigPath,
			}
			registry.RegisterBuiltin(conn)
			controller := newApplicationProtectionController(
				sidecar,
				registry,
				"hook-token",
				"127.0.0.1:4000",
				"127.0.0.1:18970",
				"master-token",
			)

			now := time.Now().UTC()
			controller.OnDiscoveryReport(context.Background(), inventory.AIDiscoveryReport{
				Summary: inventory.AIDiscoverySummary{ScannedAt: now},
				Signals: []inventory.AISignal{{
					Category:           inventory.SignalSupportedConnector,
					SupportedConnector: "codex",
					Name:               "Codex",
					Confidence:         0.95,
					State:              "active",
					LastSeen:           now,
				}},
			})

			if conn.setupCalls != tc.wantSetupCalls {
				t.Fatalf(
					"mode=%q automatic repair Setup calls = %d, want %d",
					tc.mode,
					conn.setupCalls,
					tc.wantSetupCalls,
				)
			}
			if tc.wantGuardianOwn {
				snapshot := sidecar.health.Snapshot()
				if snapshot.ApplicationProtection.State != StateDisabled {
					t.Fatalf(
						"managed application protection state = %s, want %s",
						snapshot.ApplicationProtection.State,
						StateDisabled,
					)
				}
			}
		})
	}
}
