// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func requireEnterpriseHookInstaller(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian internals are unsupported on native Windows; early rejection is covered separately")
	}
}

func TestInstallRejectsNativeWindowsBeforeSideEffects(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows rejection contract")
	}
	scope := t.TempDir()
	sentinel := filepath.Join(scope, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Install(context.Background(), InstallOptions{UserHome: filepath.Join(scope, "home")})
	if err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("Install error = %v, want unsupported-on-Windows rejection", err)
	}
	if got, readErr := os.ReadFile(sentinel); readErr != nil || string(got) != "unchanged" {
		t.Fatalf("sentinel changed: data=%q err=%v", got, readErr)
	}
}

func TestInstallCodexTargetsExplicitUserHome(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	otlpToken := strings.Repeat("d", 64)
	result, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		OTLPPathToken: otlpToken,
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
	if !strings.Contains(string(data), "/otlp/codex/"+otlpToken+"/v1/") {
		t.Fatalf("codex config does not reference supplied service OTLP token:\n%s", string(data))
	}
	userOTLPToken, err := connector.OTLPPathTokenFilePath(filepath.Join(home, ".defenseclaw"), connector.OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(userOTLPToken); !os.IsNotExist(err) {
		t.Fatalf("managed install minted a per-user OTLP token sidecar: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".defenseclaw", "hook_contract_lock.json")); err != nil {
		t.Fatalf("hook contract lock missing: %v", err)
	}
}

func TestInstallOmnigentPolicyModuleThroughGuardian(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	configPath := filepath.Join(home, ".omnigent", "config.yaml")
	sitePackages := filepath.Join(home, ".local", "lib", "python", "site-packages")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("mkdir OmniGent config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("server: https://example.test\npolicy_modules: []\n"), 0o600); err != nil {
		t.Fatalf("write OmniGent config: %v", err)
	}

	previousConfig := connector.OmnigentConfigPathOverride
	previousSite := connector.OmnigentSitePackagesPathOverride
	connector.OmnigentConfigPathOverride = configPath
	connector.OmnigentSitePackagesPathOverride = sitePackages
	t.Cleanup(func() {
		connector.OmnigentConfigPathOverride = previousConfig
		connector.OmnigentSitePackagesPathOverride = previousSite
	})

	result, err := Install(context.Background(), InstallOptions{
		ConnectorName: "omnigent",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "omnigent-scoped-token",
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "omnigent 0.1.0",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Install OmniGent: %v", err)
	}
	if result.Connector != "omnigent" {
		t.Fatalf("connector = %q, want omnigent", result.Connector)
	}
	if len(result.HookConfigPaths) != 1 || result.HookConfigPaths[0] != configPath {
		t.Fatalf("hook config paths = %v, want %s", result.HookConfigPaths, configPath)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read OmniGent config: %v", err)
	}
	if !strings.Contains(string(configData), "defenseclaw_omnigent_policy.defenseclaw_policy") {
		t.Fatalf("OmniGent config does not reference DefenseClaw policy module:\n%s", configData)
	}
}

func TestInstallMultipleConnectorsKeepsScopedHookTokens(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	claudeConfig := filepath.Join(home, ".claude", "settings.json")
	for _, path := range []string{codexConfig, claudeConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir connector config dir: %v", err)
		}
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.WriteFile(claudeConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write Claude Code config: %v", err)
	}

	registry := connector.NewDefaultRegistry()
	for _, opts := range []InstallOptions{
		{
			ConnectorName: "codex",
			APIToken:      "codex-token",
			AgentVersion:  "codex-cli 0.142.0",
		},
		{
			ConnectorName: "claudecode",
			APIToken:      "claude-token",
			AgentVersion:  "2.1.187 (Claude Code)",
		},
	} {
		opts.UserHome = home
		opts.OwnerUID = os.Getuid()
		opts.OwnerGID = os.Getgid()
		opts.APIAddr = "127.0.0.1:18970"
		opts.ProxyAddr = "127.0.0.1:4000"
		opts.GuardrailMode = "action"
		opts.HookFailMode = "closed"
		opts.Registry = registry
		if _, err := Install(context.Background(), opts); err != nil {
			t.Fatalf("Install(%s): %v", opts.ConnectorName, err)
		}
	}

	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	otherToken := map[string]string{
		"codex":      ".hook-claudecode.token",
		"claudecode": ".hook-codex.token",
	}
	for _, tc := range []struct {
		connector string
		script    string
		token     string
	}{
		{connector: "codex", script: "codex-hook.sh", token: "codex-token"},
		{connector: "claudecode", script: "claude-code-hook.sh", token: "claude-token"},
	} {
		tokenName := ".hook-" + tc.connector + ".token"
		tokenData, err := os.ReadFile(filepath.Join(hookDir, tokenName))
		if err != nil {
			t.Fatalf("read %s token: %v", tc.connector, err)
		}
		wantToken := tc.token
		if got := strings.TrimSpace(string(tokenData)); got != wantToken {
			t.Fatalf("%s token sidecar = %q, want %q", tc.connector, got, wantToken)
		}
		scriptData, err := os.ReadFile(filepath.Join(hookDir, tc.script))
		if err != nil {
			t.Fatalf("read %s script: %v", tc.connector, err)
		}
		scriptText := string(scriptData)
		if !strings.Contains(scriptText, "${HOOK_DIR}/"+tokenName) {
			t.Fatalf("%s script does not reference %s", tc.connector, tokenName)
		}
		if strings.Contains(scriptText, "${HOOK_DIR}/.token") {
			t.Fatalf("%s script still references legacy shared token", tc.connector)
		}
		if strings.Contains(scriptText, otherToken[tc.connector]) {
			t.Fatalf("%s script references another connector token", tc.connector)
		}
	}
	if _, err := os.Lstat(filepath.Join(hookDir, ".token")); !os.IsNotExist(err) {
		t.Fatalf("shared legacy token exists after scoped installs: %v", err)
	}
}

func TestInstallAuthorizedRepairNormalizesWritableArtifacts(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	opts := InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "codex-token",
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      connector.NewDefaultRegistry(),
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("initial Install: %v", err)
	}
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	modes := map[string]os.FileMode{
		codexConfig:                                 0o600,
		filepath.Join(hookDir, "codex-hook.sh"):     0o700,
		filepath.Join(hookDir, ".hook-codex.token"): 0o600,
	}
	for path := range modes {
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatalf("widen %s: %v", path, err)
		}
	}
	opts.AllowMissingHookConfigRepair = true
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair Install: %v", err)
	}
	for path, want := range modes {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode %s = %04o, want %04o", path, got, want)
		}
	}
}

func TestInstallMultipleConnectorsNoOpRepairPreservesModificationTimes(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	claudeConfig := filepath.Join(home, ".claude", "settings.json")
	for _, path := range []string{codexConfig, claudeConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir connector config dir: %v", err)
		}
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.WriteFile(claudeConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write Claude Code config: %v", err)
	}

	registry := connector.NewDefaultRegistry()
	options := []InstallOptions{
		{ConnectorName: "codex", APIToken: "codex-token", AgentVersion: "codex-cli 0.142.0"},
		{ConnectorName: "claudecode", APIToken: "claude-token", AgentVersion: "2.1.187 (Claude Code)"},
	}
	installAll := func(allowRepair bool) {
		t.Helper()
		for i := range options {
			opts := options[i]
			opts.UserHome = home
			opts.OwnerUID = os.Getuid()
			opts.OwnerGID = os.Getgid()
			opts.APIAddr = "127.0.0.1:18970"
			opts.ProxyAddr = "127.0.0.1:4000"
			opts.GuardrailMode = "action"
			opts.HookFailMode = "closed"
			opts.Registry = registry
			opts.AllowMissingHookConfigRepair = allowRepair
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatalf("Install(%s): %v", opts.ConnectorName, err)
			}
		}
	}
	installAll(false)
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	paths := []string{
		codexConfig,
		claudeConfig,
		filepath.Join(hookDir, ".hook-codex.token"),
		filepath.Join(hookDir, ".hook-claudecode.token"),
		filepath.Join(hookDir, "codex-hook.sh"),
		filepath.Join(hookDir, "claude-code-hook.sh"),
		filepath.Join(home, ".defenseclaw", "hook_contract_lock.json"),
		filepath.Join(home, ".defenseclaw", "connector_backups", "codex", "config.toml.json"),
		filepath.Join(home, ".defenseclaw", "connector_backups", "claudecode", "settings.json.json"),
	}
	modTimes := make(map[string]int64, len(paths))
	oldTime := time.Unix(1, 0)
	for _, path := range paths {
		if err := os.Chtimes(path, oldTime, oldTime); err != nil {
			t.Fatalf("age no-op repair fixture %s: %v", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat before no-op repair %s: %v", path, err)
		}
		modTimes[path] = info.ModTime().UnixNano()
	}
	installAll(true)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat after no-op repair %s: %v", path, err)
		}
		if got := info.ModTime().UnixNano(); got != modTimes[path] {
			t.Fatalf("no-op repair rewrote %s: mtime before=%d after=%d", path, modTimes[path], got)
		}
	}
}

func TestWatchDirsIncludesHookConfigAndRuntimeDirs(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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

	dirs, err := WatchDirs(InstallOptions{
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
		t.Fatalf("WatchDirs: %v", err)
	}
	for _, want := range []string{filepath.Join(home, ".codex"), filepath.Join(home, ".defenseclaw"), hookDir} {
		if !sliceContains(dirs, want) {
			t.Fatalf("WatchDirs = %v, missing %s", dirs, want)
		}
	}
}

func TestInstallRefusesMissingHookConfig(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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

func TestInstallRepairsHookConfigSymlinkWhenPreviouslyProtected(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	outside := filepath.Join(t.TempDir(), "outside.toml")
	if err := os.WriteFile(outside, []byte("outside = true\n"), 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.Symlink(outside, codexConfig); err != nil {
		t.Fatalf("symlink codex config: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
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
		t.Fatalf("Install repair symlink config: %v", err)
	}
	info, err := os.Lstat(codexConfig)
	if err != nil {
		t.Fatalf("lstat repaired config: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("codex config is still a symlink")
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "outside = true\n" {
		t.Fatalf("outside target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesHookConfigSymlinkOutsideHome(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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

func TestInstallRepairsExistingHookScriptSymlinkWhenPreviouslyProtected(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	hookPath := filepath.Join(hookDir, "codex-hook.sh")
	if err := os.Symlink(outside, hookPath); err != nil {
		t.Fatalf("symlink hook script: %v", err)
	}

	_, err := Install(context.Background(), InstallOptions{
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
		t.Fatalf("Install repair hook script symlink: %v", err)
	}
	info, err := os.Lstat(hookPath)
	if err != nil {
		t.Fatalf("lstat repaired hook script: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("hook script is still a symlink")
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "#!/bin/sh\necho outside\n" {
		t.Fatalf("outside symlink target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesExistingHookTokenSymlinkBeforeSetup(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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

func TestInstallRefusesExistingHookHelperSymlinkBeforeSetup(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	outside := filepath.Join(t.TempDir(), "outside-hardening.sh")
	if err := os.WriteFile(outside, []byte("# helper\n"), 0o600); err != nil {
		t.Fatalf("write outside helper target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(hookDir, "_hardening.sh")); err != nil {
		t.Fatalf("symlink hook helper: %v", err)
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
		t.Fatalf("Install error = %v, want hook helper symlink refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "# helper\n" {
		t.Fatalf("outside helper target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesExistingGeneratedExecutableSymlinkBeforeSetup(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside-notify.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\necho outside\n"), 0o700); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "notify-bridge.sh")); err != nil {
		t.Fatalf("symlink notify bridge: %v", err)
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
		t.Fatalf("Install error = %v, want generated executable symlink refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "#!/bin/sh\necho outside\n" {
		t.Fatalf("outside notify target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestValidateInstallFootprintRefusesGeneratedFileSymlinkBeforeSetup(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	generatedPath := filepath.Join(dataDir, "policies", "defenseclaw-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(generatedPath), 0o700); err != nil {
		t.Fatalf("mkdir generated file dir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside-policy.yaml")
	if err := os.WriteFile(outside, []byte("sentinel: true\n"), 0o600); err != nil {
		t.Fatalf("write outside policy target: %v", err)
	}
	if err := os.Symlink(outside, generatedPath); err != nil {
		t.Fatalf("symlink policy: %v", err)
	}

	err := validateInstallFootprintBeforeSetup(home, dataDir, os.Getuid(), "codex", connector.AgentPaths{
		GeneratedFiles: []string{generatedPath},
	}, false)
	if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
		t.Fatalf("validateInstallFootprintBeforeSetup error = %v, want generated file symlink refusal", err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "sentinel: true\n" {
		t.Fatalf("outside policy target changed: data=%q err=%v", string(got), readErr)
	}
}

func TestInstallRefusesHomeOwnerMismatch(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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

	err := hardenInstallFootprint(os.Getuid(), os.Getgid(), home, dataDir, "codex", connector.AgentPaths{
		CreatedDirs: []string{outside},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing created dir outside user home") {
		t.Fatalf("hardenInstallFootprint error = %v, want outside created dir refusal", err)
	}
}

func TestInstallRefusesProxyConnector(t *testing.T) {
	requireEnterpriseHookInstaller(t)
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
	requireEnterpriseHookInstaller(t)
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

func sliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
