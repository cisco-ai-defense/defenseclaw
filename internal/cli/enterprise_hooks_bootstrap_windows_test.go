//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

func TestWindowsEnterpriseHooksBootstrapIgnoresRuntimeDotEnvAndPlugins(t *testing.T) {
	originalRuntimeGOOS := enterpriseHooksRuntimeGOOS
	originalLoader := enterpriseHooksWindowsConfigLoader
	originalFullPreRun := enterpriseHooksFullRootPersistentPreRun
	originalPluginFactory := enterpriseHooksPluginRegistryFactory
	originalCertifiedFactory := enterpriseHooksCertifiedRegistryFactory
	originalCfg := cfg
	originalAuditStore, originalAuditLog := auditStore, auditLog
	t.Cleanup(func() {
		enterpriseHooksRuntimeGOOS = originalRuntimeGOOS
		enterpriseHooksWindowsConfigLoader = originalLoader
		enterpriseHooksFullRootPersistentPreRun = originalFullPreRun
		enterpriseHooksPluginRegistryFactory = originalPluginFactory
		enterpriseHooksCertifiedRegistryFactory = originalCertifiedFactory
		cfg = originalCfg
		auditStore, auditLog = originalAuditStore, originalAuditLog
	})

	runtimeDir := t.TempDir()
	maliciousCodexHome := filepath.Join(runtimeDir, "attacker-codex-home")
	if err := os.WriteFile(filepath.Join(runtimeDir, ".env"), []byte(
		"CODEX_HOME="+maliciousCodexHome+"\n"+
			"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1\n"+
			"OTEL_EXPORTER_OTLP_ENDPOINT=http://attacker.invalid\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", runtimeDir)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)

	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	fullPreRunCalled := false
	enterpriseHooksFullRootPersistentPreRun = func(*cobra.Command, []string) error {
		fullPreRunCalled = true
		return nil
	}
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) {
		for _, name := range []string{
			"CODEX_HOME",
			"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
			"OTEL_EXPORTER_OTLP_ENDPOINT",
		} {
			if got := os.Getenv(name); got != "" {
				t.Fatalf("%s mutated from runtime .env before protected config load: %q", name, got)
			}
		}
		return &config.Config{
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			DataDir:        runtimeDir,
		}, nil
	}
	pluginLoaderCalled := false
	enterpriseHooksPluginRegistryFactory = func() *connector.Registry {
		pluginLoaderCalled = true
		return connector.NewDefaultRegistry()
	}
	enterpriseHooksCertifiedRegistryFactory = newWindowsEnterpriseCertifiedConnectorRegistry
	auditStore, auditLog = nil, nil

	if err := enterpriseHooksNativePersistentPreRun(&cobra.Command{}, nil); err != nil {
		t.Fatalf("minimal Windows enterprise pre-run: %v", err)
	}
	if fullPreRunCalled {
		t.Fatal("full root pre-run initialized dotenv/audit/telemetry for LocalSystem guardian")
	}
	for _, name := range []string{
		"CODEX_HOME",
		"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
	} {
		if got := os.Getenv(name); got != "" {
			t.Fatalf("%s mutated from service-writable runtime .env: %q", name, got)
		}
	}
	if auditStore != nil || auditLog != nil {
		t.Fatal("minimal guardian bootstrap initialized audit state")
	}

	registry := newEnterpriseHooksConnectorRegistry()
	if pluginLoaderCalled {
		t.Fatal("managed Windows guardian invoked runtime plugin registry factory")
	}
	for _, name := range []string{"codex", "claudecode"} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("certified connector %q is missing", name)
		}
	}
	if _, ok := registry.Get("openclaw"); ok {
		t.Fatal("uncertified built-in connector entered native Windows guardian registry")
	}
}

func TestWindowsEnterpriseHooksBootstrapUsesFullPreRunOutsideManagedMode(t *testing.T) {
	originalRuntimeGOOS := enterpriseHooksRuntimeGOOS
	originalLoader := enterpriseHooksWindowsConfigLoader
	originalFullPreRun := enterpriseHooksFullRootPersistentPreRun
	originalCfg := cfg
	t.Cleanup(func() {
		enterpriseHooksRuntimeGOOS = originalRuntimeGOOS
		enterpriseHooksWindowsConfigLoader = originalLoader
		enterpriseHooksFullRootPersistentPreRun = originalFullPreRun
		cfg = originalCfg
	})

	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) {
		t.Fatal("normal Windows bootstrap read protected config before historical full pre-run")
		return nil, nil
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	fullConfig := &config.Config{DeploymentMode: string(config.DeploymentModeUnmanagedBYOD), DataDir: t.TempDir()}
	fullPreRunCalls := 0
	enterpriseHooksFullRootPersistentPreRun = func(gotCommand *cobra.Command, gotArgs []string) error {
		fullPreRunCalls++
		cfg = fullConfig
		return nil
	}

	if err := enterpriseHooksNativePersistentPreRun(&cobra.Command{}, []string{"status"}); err != nil {
		t.Fatalf("normal Windows pre-run: %v", err)
	}
	if fullPreRunCalls != 1 {
		t.Fatalf("full root pre-run calls = %d, want 1", fullPreRunCalls)
	}
	if cfg != fullConfig {
		t.Fatal("normal Windows mode retained minimal guardian config instead of full pre-run config")
	}
}
