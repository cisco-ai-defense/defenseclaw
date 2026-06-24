// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestInstallCodexTargetsExplicitUserHome(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	result, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.Connector != "codex" {
		t.Fatalf("connector = %q, want codex", result.Connector)
	}
	if result.DataDir != filepath.Join(home, ".defenseclaw") {
		t.Fatalf("data dir = %q, want default under user home", result.DataDir)
	}
	if len(result.HookConfigPaths) != 1 || result.HookConfigPaths[0] != codexConfig {
		t.Fatalf("hook config paths = %v, want %s", result.HookConfigPaths, codexConfig)
	}
	data, err := os.ReadFile(codexConfig)
	if err != nil {
		t.Fatalf("read codex config: %v", err)
	}
	if !strings.Contains(string(data), filepath.Join(home, ".defenseclaw", "hooks", "codex-hook.sh")) {
		t.Fatalf("codex config does not reference per-user hook script:\n%s", string(data))
	}
	if _, err := os.Stat(filepath.Join(home, ".defenseclaw", "hook_contract_lock.json")); err != nil {
		t.Fatalf("hook contract lock missing: %v", err)
	}
}

func TestInstallRefusesMissingHookConfig(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "hook config file missing") {
		t.Fatalf("Install error = %v, want hook config missing", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".defenseclaw")); !os.IsNotExist(statErr) {
		t.Fatalf("data dir exists after refused install: %v", statErr)
	}
}

func TestInstallRefusesHookConfigSymlinkOutsideHome(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.Symlink(outside, codexConfig); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "outside user home") {
		t.Fatalf("Install error = %v, want outside user home symlink refusal", err)
	}
}

func TestInstallRefusesProxyConnector(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "openclaw",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "setup-only") {
		t.Fatalf("Install error = %v, want proxy setup-only refusal", err)
	}
}

func TestInstallRefusesRootTarget(t *testing.T) {
	home := t.TempDir()
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      0,
		OwnerGID:      0,
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to target uid 0") {
		t.Fatalf("Install error = %v, want uid 0 refusal", err)
	}
}

func TestLoadManifestValidatesEnabledTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
targets:
  - user: alice
    connector: codex
    agent_version: "codex-cli 0.142.0"
  - enabled: false
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.Version != 1 {
		t.Fatalf("version = %d, want default 1", manifest.Version)
	}
	if len(manifest.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(manifest.Targets))
	}
	if !manifest.Targets[0].IsEnabled() {
		t.Fatal("first target should be enabled by default")
	}
	if manifest.Targets[1].IsEnabled() {
		t.Fatal("second target should be disabled")
	}
}

func TestLoadManifestRejectsIncompleteEnabledTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user: alice
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "requires connector") {
		t.Fatalf("LoadManifest error = %v, want connector validation", err)
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("enterprise hook installer refuses uid 0 targets")
	}
}
