// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/windows"
)

// packagedWindowsHookBinaryAtUninstallRoot is a test-only strict resolver for
// exercising uninstall-trash layout validation without adding an otherwise
// unused production wrapper around the two production primitives.
func packagedWindowsHookBinaryAtUninstallRoot(executable, expectedRoot string) string {
	physicalRoot := packagedWindowsUninstallPhysicalRoot(executable, expectedRoot)
	if physicalRoot == "" {
		return ""
	}
	return packagedWindowsHookBinaryAtLayout(executable, physicalRoot, expectedRoot, false)
}

func TestCanonicalNativeWindowsInstallRootIgnoresConnectorEnvironmentOverrides(t *testing.T) {
	want := canonicalNativeWindowsInstallRoot()
	if strings.TrimSpace(want) == "" {
		t.Fatal("token-bound native install root is empty before environment overrides")
	}
	foreignProfile := t.TempDir()
	for name, value := range map[string]string{
		"USERPROFILE":  foreignProfile,
		"HOME":         foreignProfile,
		"LOCALAPPDATA": filepath.Join(foreignProfile, "AppData", "Local"),
		"APPDATA":      filepath.Join(foreignProfile, "AppData", "Roaming"),
	} {
		t.Setenv(name, value)
	}
	got := canonicalNativeWindowsInstallRoot()
	if !sameWindowsInstallPath(got, want) {
		t.Fatalf("token-bound native install root changed with connector environment: got %q, want %q", got, want)
	}
}

const stableHookUninstallTransactionID = "0123456789abcdef0123456789abcdef"

func stageRelocatedNativeInstallForTest(t *testing.T, suffix string) (string, string, string) {
	t.Helper()
	parent := t.TempDir()
	declaredRoot := filepath.Join(parent, "DefenseClaw")
	physicalRoot := declaredRoot + suffix
	commandDir := filepath.Join(physicalRoot, "bin")
	installerDir := filepath.Join(physicalRoot, "installer")
	if err := os.MkdirAll(commandDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(commandDir, windowsGatewayBinaryName)
	hook := filepath.Join(commandDir, windowsHookBinaryName)
	for _, path := range []string{gateway, hook} {
		if err := os.WriteFile(path, []byte("MZ-test-native-binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := nativeWindowsInstallState{
		SchemaVersion: 1,
		InstallKind:   "native-windows-exe",
		InstallScope:  "user",
		InstallRoot:   declaredRoot,
		CommandDir:    filepath.Join(declaredRoot, "bin"),
		Runtime:       filepath.Join(declaredRoot, "runtime", "python"),
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installerDir, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return declaredRoot, gateway, hook
}

func TestPackagedWindowsHookBinaryRecognizesOnlyOwnedUninstallTree(t *testing.T) {
	declaredRoot, gateway, hook := stageRelocatedNativeInstallForTest(
		t,
		".uninstall."+stableHookUninstallTransactionID,
	)
	if got := packagedWindowsHookBinaryAtUninstallRoot(gateway, declaredRoot); !sameWindowsInstallPath(got, hook) {
		t.Fatalf("owned uninstall hook = %q, want %q", got, hook)
	}
	logicalHook := filepath.Join(declaredRoot, "bin", windowsHookBinaryName)
	if got := packagedWindowsHookBinaryForRoot(gateway, declaredRoot); !sameWindowsInstallPath(got, logicalHook) {
		t.Fatalf("owned uninstall command = %q, want original installed sibling %q", got, logicalHook)
	}

	for _, suffix := range []string{
		".uninstall.short",
		".uninstall.0123456789ABCDEF0123456789ABCDEF",
		".uninstall.0123456789abcdef0123456789abcdeg",
		".backup." + stableHookUninstallTransactionID,
	} {
		t.Run(suffix, func(t *testing.T) {
			root, candidate, _ := stageRelocatedNativeInstallForTest(t, suffix)
			if got := packagedWindowsHookBinaryAtUninstallRoot(candidate, root); got != "" {
				t.Fatalf("unsafe transaction suffix accepted: %q", got)
			}
		})
	}
}

func TestPackagedWindowsHookBinaryRejectsRelocatedTreeWithForeignState(t *testing.T) {
	declaredRoot, gateway, _ := stageRelocatedNativeInstallForTest(
		t,
		".uninstall."+stableHookUninstallTransactionID,
	)
	statePath := filepath.Join(filepath.Dir(filepath.Dir(gateway)), "installer", "install-state.json")
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state nativeWindowsInstallState
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	state.InstallRoot = filepath.Join(t.TempDir(), "foreign")
	body, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := packagedWindowsHookBinaryAtUninstallRoot(gateway, declaredRoot); got != "" {
		t.Fatalf("foreign install state accepted: %q", got)
	}
}

func TestPackagedWindowsRunningGatewayUsesExactInstalledSiblingWhileImageIsLocked(t *testing.T) {
	root, gateway, hook := stageRelocatedNativeInstallForTest(t, "")
	gatewayPointer, err := windows.UTF16PtrFromString(gateway)
	if err != nil {
		t.Fatal(err)
	}
	gatewayHandle, err := windows.CreateFile(
		gatewayPointer,
		windows.GENERIC_READ,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("lock packaged gateway image: %v", err)
	}
	defer windows.CloseHandle(gatewayHandle)

	hookPointer, err := windows.UTF16PtrFromString(hook)
	if err != nil {
		t.Fatal(err)
	}
	hookHandle, err := windows.CreateFile(
		hookPointer,
		windows.GENERIC_READ,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("lock packaged hook image: %v", err)
	}
	if got := packagedWindowsHookBinaryAtRoot(gateway, root); got != "" {
		t.Fatalf("non-running strict resolver accepted a sharing-locked gateway: %q", got)
	}

	released := make(chan error, 1)
	go func() {
		time.Sleep(250 * time.Millisecond)
		released <- windows.CloseHandle(hookHandle)
	}()
	if got := packagedWindowsHookBinaryForRoot(gateway, root); !sameWindowsInstallPath(got, hook) {
		t.Fatalf("running packaged resolver = %q, want exact installed sibling %q", got, hook)
	}
	if err := <-released; err != nil {
		t.Fatalf("release packaged hook image: %v", err)
	}
}

func TestMaintenanceTeardownRecognizesCanonicalHookWithoutInstalledLayout(t *testing.T) {
	canonical := canonicalNativeWindowsHookBinary()
	if strings.TrimSpace(canonical) == "" {
		t.Fatal("canonical native installed hook path is empty")
	}
	defenseclawHookBinaryOverride = `C:\repository-build\defenseclaw-hook.exe`
	t.Cleanup(func() { defenseclawHookBinaryOverride = "" })

	owned := windowsNativePowerShellHookCommandForBinary("codex", canonical)
	if !isNativeHookCommand(owned) {
		t.Fatalf("maintenance teardown did not recognize canonical encoded hook command %q", owned)
	}
	if !isDefenseClawHookExecutable(canonical) {
		t.Fatalf("maintenance teardown did not recognize canonical hook executable %q", canonical)
	}
	structured := map[string]interface{}{
		"command": canonical,
		"args":    []interface{}{"hook", "--connector", "claudecode"},
	}
	if !structuredNativeExecHookReferences(structured, []string{nativeHookFlag + "claudecode"}) {
		t.Fatalf("maintenance teardown did not recognize canonical structured hook %#v", structured)
	}
	foreign := windowsNativePowerShellHookCommandForBinary("codex", `C:\foreign\defenseclaw-hook.exe`)
	if isNativeHookCommand(foreign) {
		t.Fatalf("maintenance teardown accepted foreign encoded hook command %q", foreign)
	}
	structured["command"] = `C:\foreign\defenseclaw-hook.exe`
	if structuredNativeExecHookReferences(structured, []string{nativeHookFlag + "claudecode"}) {
		t.Fatalf("maintenance teardown accepted foreign structured hook %#v", structured)
	}
	if got, want := windowsNativePowerShellHookCommand("codex"), windowsNativePowerShellHookCommandForBinary("codex", defenseclawHookBinaryOverride); got != want {
		t.Fatalf("command generation unexpectedly switched to canonical maintenance ownership path: %q", got)
	}
}

func TestManagedHookExecutableRejectsRelativeOwnedBasename(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, windowsHookBinaryName)
	defenseclawHookBinaryOverride = owned
	t.Cleanup(func() { defenseclawHookBinaryOverride = "" })
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	if isDefenseClawManagedHookExecutable(windowsHookBinaryName) {
		t.Fatalf("managed executable predicate accepted relative PATH command %q", windowsHookBinaryName)
	}
}

func TestMaintenanceCodexTeardownPreservesDriftWithoutInstalledLayout(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-user-choice\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = "" })
	originalInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "maintenance teardown test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = originalInspector })

	canonical := canonicalNativeWindowsHookBinary()
	defenseclawHookBinaryOverride = canonical
	t.Cleanup(func() { defenseclawHookBinaryOverride = "" })
	opts := SetupOpts{
		DataDir:   filepath.Join(root, "data"),
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "maintenance-test-token",
	}
	conn := NewCodexConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("seed canonical Codex hook: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("setup hooks have unexpected type %T", cfg["hooks"])
	}
	hooks["UserMaintenance"] = []interface{}{map[string]interface{}{
		"hooks": []interface{}{map[string]interface{}{
			"type":    "command",
			"command": "user-maintenance-policy.exe",
			"timeout": int64(7),
		}},
	}}
	drifted, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, drifted, 0o600); err != nil {
		t.Fatal(err)
	}

	// A maintenance gateway has no packaged install layout, and this override
	// simulates its ordinary repository/legacy fallback. Teardown must still
	// recognize the exact canonical installed command already stored in Codex
	// config even when that installed executable is now missing.
	defenseclawHookBinaryOverride = `C:\maintenance-temp\defenseclaw-hook.exe`
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("maintenance Codex teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("maintenance Codex verify clean: %v", err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restored), "user-maintenance-policy.exe") ||
		!strings.Contains(string(restored), "gpt-user-choice") {
		t.Fatalf("maintenance teardown discarded unrelated Codex drift:\n%s", restored)
	}
}

func TestMaintenanceClaudeTeardownPreservesForeignHookWithoutInstalledLayout(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configHome := filepath.Join(root, "claude")
	if err := os.MkdirAll(configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configHome, "settings.json")
	original := `{"existingKey":"user-value","hooks":{"Notification":[{"hooks":[{"type":"command","command":"user-notification.exe"}]}]}}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", configHome)

	canonical := canonicalNativeWindowsHookBinary()
	if strings.TrimSpace(canonical) == "" {
		t.Fatal("canonical native installed hook path is empty")
	}
	defenseclawHookBinaryOverride = canonical
	t.Cleanup(func() { defenseclawHookBinaryOverride = "" })
	opts := SetupOpts{
		DataDir:   filepath.Join(root, "data"),
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
		APIToken:  "maintenance-test-token",
	}
	conn := NewClaudeCodeConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("seed canonical Claude hooks: %v", err)
	}

	// Simulate the Setup-owned maintenance gateway after the installed payload
	// disappeared. Its own fallback path must not determine hook ownership.
	defenseclawHookBinaryOverride = `C:\maintenance-temp\defenseclaw-hook.exe`
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("maintenance Claude teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("maintenance Claude verify clean: %v", err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(restored))
	if strings.Contains(lower, "defenseclaw") {
		t.Fatalf("owned Claude state survived maintenance teardown:\n%s", restored)
	}
	for _, want := range []string{"user-value", "user-notification.exe"} {
		if !strings.Contains(string(restored), want) {
			t.Fatalf("unrelated Claude setting %q was not preserved:\n%s", want, restored)
		}
	}
}
