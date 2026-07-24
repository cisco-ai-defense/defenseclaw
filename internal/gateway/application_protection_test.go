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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func enabledApplicationProtectionConfig() config.ApplicationProtectionConfig {
	appProtection := config.DefaultApplicationProtectionConfig()
	appProtection.Enabled = true
	return appProtection
}

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
		ApplicationProtection: enabledApplicationProtectionConfig(),
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
		ApplicationProtection: enabledApplicationProtectionConfig(),
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

func TestApplicationProtectionControllerManagedEnterpriseDoesNotWriteUserHooks(t *testing.T) {
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
		DeploymentMode:        "managed_enterprise",
		ApplicationProtection: enabledApplicationProtectionConfig(),
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

	if conn.setupCalls != 0 {
		t.Fatalf("setupCalls = %d, want 0 in managed_enterprise without guardian", conn.setupCalls)
	}
	snap := health.Snapshot()
	if snap.ApplicationProtection.State != StateDisabled {
		t.Fatalf("application protection state = %s, want disabled", snap.ApplicationProtection.State)
	}
	if !strings.Contains(snap.ApplicationProtection.LastError, "guardian") {
		t.Fatalf("application protection error = %q, want guardian hint", snap.ApplicationProtection.LastError)
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
		ApplicationProtection: enabledApplicationProtectionConfig(),
		Guardrail: config.GuardrailConfig{
			HookSelfHeal: false,
		},
	}
	cfg.ApplicationProtection.Guardrail.Mode = "action"
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
		ApplicationProtection: enabledApplicationProtectionConfig(),
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
		ApplicationProtection: enabledApplicationProtectionConfig(),
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
	wantReason := "proxy_connector_setup_only"
	if runtime.GOOS == "windows" {
		wantReason = "unsupported_os"
	}
	if got := state.Skipped[0].Reason; got != wantReason {
		t.Errorf("skip reason = %q, want %s", got, wantReason)
	}
}

func TestApplicationProtectionHookStubPublishesOwnedRegistration(t *testing.T) {
	dir := t.TempDir()
	hookConfigPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(hookConfigPath), 0o700); err != nil {
		t.Fatalf("mkdir hook config dir: %v", err)
	}
	const originalConfig = "model_provider = \"openai\"\n"
	if err := os.WriteFile(hookConfigPath, []byte(originalConfig), 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	conn := &appProtectionHookStub{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		hookConfigPath:    hookConfigPath,
	}
	opts := connector.SetupOpts{DataDir: dir}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("successful fake setup did not publish its owned registration")
	}
	raw, err := os.ReadFile(hookConfigPath)
	if err != nil {
		t.Fatalf("read hook config: %v", err)
	}
	if !strings.HasPrefix(string(raw), originalConfig) {
		t.Fatalf("fake setup did not preserve existing config: %q", raw)
	}
}

type appProtectionHookStub struct {
	bootStubConnector
	hookConfigPath string
}

const appProtectionHookReference = "defenseclaw-app-protection-test-hook"

func (s *appProtectionHookStub) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if err := s.bootStubConnector.Setup(ctx, opts); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.hookConfigPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.hookConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("\ncommand = \"" + appProtectionHookReference + "\"\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *appProtectionHookStub) HookScriptNames(connector.SetupOpts) []string {
	return []string{s.Name() + "-hook.sh"}
}

func (*appProtectionHookStub) HookConfigReferenceNeedles(connector.SetupOpts) []string {
	return []string{appProtectionHookReference}
}

func (s *appProtectionHookStub) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{
		CanBlock:   true,
		Scope:      "user",
		ConfigPath: s.hookConfigPath,
	}
}
