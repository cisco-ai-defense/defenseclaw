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
	home := newTestHome(t)
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
	home := newTestHome(t)
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "hook config") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Install error = %v, want hook config missing", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".defenseclaw")); !os.IsNotExist(statErr) {
		t.Fatalf("data dir exists after refused install: %v", statErr)
	}
}

func TestInstallRepairsMissingHookConfigWhenPreviouslyProtected(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)

	result, err := Install(context.Background(), InstallOptions{
		ConnectorName:                "codex",
		UserHome:                     home,
		OwnerUID:                     os.Getuid(),
		OwnerGID:                     os.Getgid(),
		APIAddr:                      "127.0.0.1:18970",
		APIToken:                     "test-token",
		AgentVersion:                 "codex-cli 0.142.0",
		GuardrailMode:                "action",
		AllowMissingHookConfigRepair: true,
		Registry:                     connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Install repair missing config: %v", err)
	}
	if result.Connector != "codex" {
		t.Fatalf("result.Connector = %q, want codex", result.Connector)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read repaired config: %v", err)
	}
	if !strings.Contains(string(data), "defenseclaw") || !strings.Contains(string(data), "codex-hook.sh") {
		t.Fatalf("repaired config missing DefenseClaw hook:\n%s", string(data))
	}
}

func TestInstallRefusesHookConfigSymlinkOutsideHome(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
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
	if err == nil || !strings.Contains(err.Error(), "refusing symlink hook config") {
		t.Fatalf("Install error = %v, want symlink hook config refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "model = \"gpt-5\"\n" {
		t.Fatalf("outside symlink target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesHookConfigSymlinkInsideHome(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	realConfig := filepath.Join(home, "real-config.toml")
	if err := os.WriteFile(realConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write real target: %v", err)
	}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.Symlink(realConfig, codexConfig); err != nil {
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
	if err == nil || !strings.Contains(err.Error(), "refusing symlink hook config") {
		t.Fatalf("Install error = %v, want symlink hook config refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".defenseclaw")); !os.IsNotExist(statErr) {
		t.Fatalf("data dir exists after refused symlink install: %v", statErr)
	}
}

func TestInstallRefusesHookConfigSymlinkParent(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	realDir := filepath.Join(home, "real-codex")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Symlink(realDir, filepath.Join(home, ".codex")); err != nil {
		t.Fatalf("symlink parent: %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "refusing symlink in hook config path") {
		t.Fatalf("Install error = %v, want symlink parent refusal", err)
	}
}

func TestInstallRefusesDataDirSymlink(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	realData := filepath.Join(home, "real-defenseclaw")
	if err := os.MkdirAll(realData, 0o700); err != nil {
		t.Fatalf("mkdir real data: %v", err)
	}
	if err := os.Symlink(realData, filepath.Join(home, ".defenseclaw")); err != nil {
		t.Fatalf("symlink data dir: %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "refusing symlink in data dir path") {
		t.Fatalf("Install error = %v, want data dir symlink refusal", err)
	}
	if entries, readErr := os.ReadDir(realData); readErr != nil || len(entries) != 0 {
		t.Fatalf("real data dir changed: entries=%v err=%v", entries, readErr)
	}
}

func TestInstallRefusesExistingHookScriptSymlinkBeforeSetup(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatalf("mkdir hook dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\necho outside\n"), 0o700); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(hookDir, "codex-hook.sh")); err != nil {
		t.Fatalf("symlink hook script: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		AgentVersion:  "codex-cli 0.142.0",
		GuardrailMode: "action",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
		t.Fatalf("Install error = %v, want symlink footprint file refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "#!/bin/sh\necho outside\n" {
		t.Fatalf("outside hook target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesExistingHookTokenSymlinkBeforeSetup(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatalf("mkdir hook dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside-token")
	if err := os.WriteFile(outside, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatalf("write outside token target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(hookDir, ".token")); err != nil {
		t.Fatalf("symlink hook token: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		AgentVersion:  "codex-cli 0.142.0",
		GuardrailMode: "action",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
		t.Fatalf("Install error = %v, want symlink token sidecar refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "sentinel\n" {
		t.Fatalf("outside token target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesHomeOwnerMismatch(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid() + 1,
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "user home") || !strings.Contains(err.Error(), "does not match target uid") {
		t.Fatalf("Install error = %v, want home owner mismatch", err)
	}
}

func TestHardenInstallFootprintRefusesCreatedDirOutsideHome(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatalf("chmod outside dir: %v", err)
	}

	err := hardenInstallFootprint(os.Getuid(), os.Getgid(), home, dataDir, connector.AgentPaths{
		CreatedDirs: []string{outside},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing created dir outside user home") {
		t.Fatalf("hardenInstallFootprint error = %v, want outside created dir refusal", err)
	}
}

func TestInstallRefusesProxyConnector(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
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
	home := newTestHome(t)
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

func newTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod test home: %v", err)
	}
	return home
}
