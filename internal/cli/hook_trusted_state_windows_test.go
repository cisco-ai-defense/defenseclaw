// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func stageTrustedNativeHookForTest(t *testing.T, failMode string) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Defense Claw")
	commandDir := filepath.Join(root, "bin")
	dataRoot := filepath.Join(t.TempDir(), "trusted-data")
	installerDir := filepath.Join(root, "installer")
	for _, dir := range []string{commandDir, filepath.Join(dataRoot, "hooks"), installerDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(commandDir, nativeHookLauncherName)
	if err := os.WriteFile(executable, []byte("test launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := nativeHookInstallState{
		SchemaVersion: 1,
		InstallKind:   "native-windows-exe",
		InstallScope:  "user",
		InstallRoot:   root,
		CommandDir:    commandDir,
		DataRoot:      dataRoot,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installerDir, "install-state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar := map[string]interface{}{
		"version":      2,
		"gateway_addr": "127.0.0.1:18971",
		"fail_modes":   map[string]string{"claudecode": failMode},
	}
	data, err = json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "hooks", ".hookcfg"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previous })
	return executable, dataRoot
}

func TestBuildHookOptionsPackagedWindowsIgnoresLooseningProjectEnv(t *testing.T) {
	_, trustedHome := stageTrustedNativeHookForTest(t, "closed")
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(t.TempDir(), "missing-attacker-home"))
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "127.0.0.1:44444")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "project-controlled-token")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "999999999")

	opts := buildHookOptions("claudecode", "PreToolUse", "", "")
	if opts.Home != trustedHome || opts.HookDir != filepath.Join(trustedHome, "hooks") {
		t.Fatalf("hook roots came from inherited environment: Home=%q HookDir=%q", opts.Home, opts.HookDir)
	}
	if opts.APIAddr != "127.0.0.1:18971" {
		t.Fatalf("APIAddr=%q, want trusted sidecar address", opts.APIAddr)
	}
	if opts.FailMode != "closed" {
		t.Fatalf("FailMode=%q, project environment loosened trusted policy", opts.FailMode)
	}
	if opts.Token != "" {
		t.Fatalf("Token=%q, inherited generic token must be ignored", opts.Token)
	}
	if opts.MaxBody != 0 {
		t.Fatalf("MaxBody=%d, inherited environment raised the protected cap", opts.MaxBody)
	}
}

func TestBuildHookOptionsPackagedWindowsAllowsTighteningProjectEnv(t *testing.T) {
	_, trustedHome := stageTrustedNativeHookForTest(t, "open")
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(t.TempDir(), "attacker-home"))
	t.Setenv("DEFENSECLAW_FAIL_MODE", "closed")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "true")
	t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "4096")

	opts := buildHookOptions("claudecode", "PreToolUse", "", "")
	if opts.Home != trustedHome || opts.FailMode != "closed" || !opts.StrictAvailability || opts.MaxBody != 4096 {
		t.Fatalf("tightening environment was not honored safely: %+v", opts)
	}
}

func TestTrustedNativeHookHomeRejectsStateBoundToAnotherInstall(t *testing.T) {
	executable, _ := stageTrustedNativeHookForTest(t, "closed")
	statePath := filepath.Join(filepath.Dir(filepath.Dir(executable)), "installer", "install-state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state nativeHookInstallState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state.CommandDir = filepath.Join(t.TempDir(), "other-bin")
	data, _ = json.Marshal(state)
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if home, ok := trustedNativeHookHome(); !ok || sameWindowsHookPath(home, state.DataRoot) {
		t.Fatalf("mismatched installer state did not fall back safely: home=%q native=%v", home, ok)
	}
}
