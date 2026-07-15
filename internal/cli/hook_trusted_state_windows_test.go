// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stubEnterpriseManagedRuntimeResolver(t *testing.T, resolve func(string) (string, bool, error)) {
	t.Helper()
	previous := enterpriseManagedRuntimeResolver
	enterpriseManagedRuntimeResolver = resolve
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	nativeEnterpriseHookRuntimeSnapshot.prepared = false
	nativeEnterpriseHookRuntimeSnapshot.executable = ""
	nativeEnterpriseHookRuntimeSnapshot.home = ""
	nativeEnterpriseHookRuntimeSnapshot.registered = false
	nativeEnterpriseHookRuntimeSnapshot.err = nil
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
	t.Cleanup(func() {
		enterpriseManagedRuntimeResolver = previous
		nativeEnterpriseHookRuntimeSnapshot.Lock()
		nativeEnterpriseHookRuntimeSnapshot.prepared = false
		nativeEnterpriseHookRuntimeSnapshot.executable = ""
		nativeEnterpriseHookRuntimeSnapshot.home = ""
		nativeEnterpriseHookRuntimeSnapshot.registered = false
		nativeEnterpriseHookRuntimeSnapshot.err = nil
		nativeEnterpriseHookRuntimeSnapshot.Unlock()
	})
}

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

func TestBuildHookOptionsEnterpriseManagedUsesInvokingUserRuntime(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	userRuntime := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(userRuntime, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecar, _ := json.Marshal(map[string]interface{}{
		"version":      2,
		"gateway_addr": "127.0.0.1:18977",
		"fail_modes":   map[string]string{"claudecode": "closed"},
	})
	if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	stubEnterpriseManagedRuntimeResolver(t, func(string) (string, bool, error) {
		return userRuntime, true, nil
	})
	if enterpriseManagedHookRuntimeNoop() {
		t.Fatal("registered enterprise runtime was treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "", true)
	if opts.Home != userRuntime || opts.HookDir != hookDir || opts.APIAddr != "127.0.0.1:18977" || opts.FailMode != "closed" {
		t.Fatalf("enterprise runtime options = %+v", opts)
	}
}

func TestBuildHookOptionsEnterpriseManagedFailsClosedOnOwnershipError(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	userRuntime := filepath.Join(t.TempDir(), ".defenseclaw")
	stubEnterpriseManagedRuntimeResolver(t, func(string) (string, bool, error) {
		return userRuntime, false, errors.New("tampered managed ownership state")
	})
	if enterpriseManagedHookRuntimeNoop() {
		t.Fatal("invalid enterprise runtime was allowed to no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
	if opts.Home != userRuntime || opts.FailMode != "closed" || !opts.StrictAvailability {
		t.Fatalf("invalid managed runtime did not fail closed: %+v", opts)
	}
}

func TestEnterpriseManagedHookRuntimeNoopsForUnregisteredSID(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	stubEnterpriseManagedRuntimeResolver(t, func(string) (string, bool, error) {
		return filepath.Join(t.TempDir(), ".defenseclaw"), false, nil
	})
	if !enterpriseManagedHookRuntimeNoop() {
		t.Fatal("valid unregistered SID did not no-op")
	}
}

func TestNativeHookRuntimeUnrecognizedEnterpriseInvocationResolvesFailClosedRuntime(t *testing.T) {
	executable := filepath.Join(t.TempDir(), nativeHookLauncherName)
	if err := os.WriteFile(executable, []byte("test launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousExecutable := hookExecutableOverride
	previousArgs := os.Args
	hookExecutableOverride = executable
	os.Args = []string{executable, "hook", "--connector", "claudecode", "--enterprise-managed"}
	t.Cleanup(func() {
		hookExecutableOverride = previousExecutable
		os.Args = previousArgs
	})

	called := false
	stubEnterpriseManagedRuntimeResolver(t, func(got string) (string, bool, error) {
		called = true
		if !sameWindowsHookPath(got, executable) {
			t.Fatalf("resolver executable = %q, want %q", got, executable)
		}
		return filepath.Join(t.TempDir(), ".defenseclaw"), false, errors.New("untrusted enterprise runtime")
	})
	if NativeHookRuntimeNoop() {
		t.Fatal("unrecognized enterprise invocation was allowed to exit as a permissive no-op")
	}
	if !called || !enterpriseManagedHookRuntimeForceClosed() {
		t.Fatalf("enterprise runtime resolver called=%v forceClosed=%v", called, enterpriseManagedHookRuntimeForceClosed())
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

func TestTrustedNativeHookHomeUsesPowerShellInstallState(t *testing.T) {
	commandDir := filepath.Join(t.TempDir(), ".local", "bin")
	dataRoot := filepath.Join(t.TempDir(), "custom-defenseclaw-home")
	for _, dir := range []string{commandDir, dataRoot} {
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
		InstallKind:   "powershell-windows",
		InstallScope:  "user",
		InstallRoot:   commandDir,
		CommandDir:    commandDir,
		DataRoot:      dataRoot,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(commandDir, powerShellHookStateName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previous })

	home, ok := trustedNativeHookHome()
	if !ok || !sameWindowsHookPath(home, dataRoot) {
		t.Fatalf("PowerShell state resolved home=%q native=%v, want %q", home, ok, dataRoot)
	}
}
