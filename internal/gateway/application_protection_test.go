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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func TestApplicationProtectionControllerActivatesHookConnector(t *testing.T) {
	dir := t.TempDir()
	hookConfigPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(hookConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir hook config dir: %v", err)
	}
	if err := os.WriteFile(hookConfigPath, []byte("model_provider = \"openai\"\n"), 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	cfg := &config.Config{
		DataDir:               dir,
		ApplicationProtection: config.DefaultApplicationProtectionConfig(),
		Guardrail:             config.GuardrailConfig{HookSelfHeal: false},
	}
	health := NewSidecarHealth()
	sidecar := &Sidecar{cfg: cfg, health: health}
	registry := connector.NewRegistry()
	conn := &appProtectionHookStub{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		hookConfigPath:    hookConfigPath,
	}
	registry.RegisterBuiltin(conn)
	controller := newApplicationProtectionController(sidecar, registry, "tok", "127.0.0.1:4000", "127.0.0.1:18970", "master")

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

	if conn.setupCalls != 1 {
		t.Fatalf("setupCalls = %d, want 1", conn.setupCalls)
	}
	snap := health.Snapshot()
	byName := connByName(snap.Connectors)
	codex, ok := byName["codex"]
	if !ok {
		t.Fatalf("codex missing from health connectors: %+v", snap.Connectors)
	}
	if codex.Source != "automatic" {
		t.Errorf("codex Source = %q, want automatic", codex.Source)
	}
	state := loadApplicationProtectionState(dir)
	if len(state.Active) != 1 || state.Active[0].Connector != "codex" {
		t.Fatalf("state.Active = %+v, want codex", state.Active)
	}
	if state.Active[0].Source != "automatic" {
		t.Errorf("state active source = %q, want automatic", state.Active[0].Source)
	}
}

func TestApplicationProtectionControllerSkipsMissingHookConfig(t *testing.T) {
	dir := t.TempDir()
	hookConfigPath := filepath.Join(dir, "codex", "config.toml")
	cfg := &config.Config{
		DataDir:               dir,
		ApplicationProtection: config.DefaultApplicationProtectionConfig(),
		Guardrail:             config.GuardrailConfig{HookSelfHeal: false},
	}
	sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	registry := connector.NewRegistry()
	conn := &appProtectionHookStub{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		hookConfigPath:    hookConfigPath,
	}
	registry.RegisterBuiltin(conn)
	controller := newApplicationProtectionController(sidecar, registry, "tok", "127.0.0.1:4000", "127.0.0.1:18970", "master")

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

	if conn.setupCalls != 0 {
		t.Fatalf("setupCalls = %d, want 0 when hook config is missing", conn.setupCalls)
	}
	state := loadApplicationProtectionState(dir)
	if len(state.Active) != 0 {
		t.Fatalf("state.Active = %+v, want none", state.Active)
	}
	if len(state.Skipped) != 1 {
		t.Fatalf("state.Skipped = %+v, want one missing-hook-config skip", state.Skipped)
	}
	if got := state.Skipped[0].Reason; got != "hook_config_missing" {
		t.Errorf("skip reason = %q, want hook_config_missing", got)
	}
}

func TestApplicationProtectionControllerSkipsUnverifiedHookContractInActionMode(t *testing.T) {
	dir := t.TempDir()
	hookConfigPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(hookConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir hook config dir: %v", err)
	}
	if err := os.WriteFile(hookConfigPath, []byte("model_provider = \"openai\"\n"), 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	cfg := &config.Config{
		DataDir:               dir,
		ApplicationProtection: config.DefaultApplicationProtectionConfig(),
		Guardrail: config.GuardrailConfig{
			Mode:         "action",
			HookSelfHeal: false,
		},
	}
	sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	registry := connector.NewRegistry()
	conn := &appProtectionHookStub{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		hookConfigPath:    hookConfigPath,
	}
	registry.RegisterBuiltin(conn)
	controller := newApplicationProtectionController(sidecar, registry, "tok", "127.0.0.1:4000", "127.0.0.1:18970", "master")

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

	if conn.setupCalls != 0 {
		t.Fatalf("setupCalls = %d, want 0 for unverified action-mode hook contract", conn.setupCalls)
	}
	if conn.teardownCalls != 0 {
		t.Fatalf("teardownCalls = %d, want 0 before setup has been allowed", conn.teardownCalls)
	}
	state := loadApplicationProtectionState(dir)
	if len(state.Active) != 0 {
		t.Fatalf("state.Active = %+v, want none", state.Active)
	}
	if len(state.Skipped) != 1 {
		t.Fatalf("state.Skipped = %+v, want one hook-contract skip", state.Skipped)
	}
	if got := state.Skipped[0].Reason; got != "hook_contract_unverified" {
		t.Errorf("skip reason = %q, want hook_contract_unverified", got)
	}
	if len(state.LastErrors) != 0 {
		t.Fatalf("state.LastErrors = %+v, want none for policy preflight skip", state.LastErrors)
	}
}

func TestApplicationProtectionControllerRepairsPreviouslyActiveWithoutHookConfig(t *testing.T) {
	dir := t.TempDir()
	hookConfigPath := filepath.Join(dir, "codex", "config.toml")
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
	cfg := &config.Config{
		DataDir:               dir,
		ApplicationProtection: config.DefaultApplicationProtectionConfig(),
		Guardrail:             config.GuardrailConfig{HookSelfHeal: false},
	}
	sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	registry := connector.NewRegistry()
	conn := &appProtectionHookStub{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		hookConfigPath:    hookConfigPath,
	}
	registry.RegisterBuiltin(conn)
	controller := newApplicationProtectionController(sidecar, registry, "tok", "127.0.0.1:4000", "127.0.0.1:18970", "master")

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

	if conn.setupCalls != 1 {
		t.Fatalf("setupCalls = %d, want 1 for previously active connector repair", conn.setupCalls)
	}
	state := loadApplicationProtectionState(dir)
	if len(state.Active) != 1 || state.Active[0].Connector != "codex" {
		t.Fatalf("state.Active = %+v, want codex retained", state.Active)
	}
	if len(state.Skipped) != 0 {
		t.Fatalf("state.Skipped = %+v, want no missing-hook-config skip for repair", state.Skipped)
	}
}

func TestApplicationProtectionControllerSkipsProxyConnector(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:               dir,
		ApplicationProtection: config.DefaultApplicationProtectionConfig(),
		Guardrail:             config.GuardrailConfig{HookSelfHeal: false},
	}
	sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	controller := newApplicationProtectionController(sidecar, connector.NewDefaultRegistry(), "tok", "127.0.0.1:4000", "127.0.0.1:18970", "master")

	now := time.Now().UTC()
	controller.OnDiscoveryReport(context.Background(), inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{ScannedAt: now},
		Signals: []inventory.AISignal{{
			Category:           inventory.SignalSupportedConnector,
			SupportedConnector: "openclaw",
			Name:               "OpenClaw",
			Confidence:         0.99,
			State:              "active",
			LastSeen:           now,
		}},
	})

	state := loadApplicationProtectionState(dir)
	if len(state.Active) != 0 {
		t.Fatalf("state.Active = %+v, want none", state.Active)
	}
	if len(state.Skipped) != 1 {
		t.Fatalf("state.Skipped = %+v, want one proxy skip", state.Skipped)
	}
	if got := state.Skipped[0].Reason; got != "proxy_connector_setup_only" {
		t.Errorf("skip reason = %q, want proxy_connector_setup_only", got)
	}
}

type appProtectionHookStub struct {
	bootStubConnector
	hookConfigPath string
}

func (s *appProtectionHookStub) HookScriptNames(connector.SetupOpts) []string {
	return []string{s.Name() + "-hook.sh"}
}

func (s *appProtectionHookStub) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{
		CanBlock:   true,
		Scope:      "user",
		ConfigPath: s.hookConfigPath,
	}
}
