// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

func stubEnterpriseManagedRuntimeResolver(
	t *testing.T,
	resolve func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error),
) {
	t.Helper()
	previous := enterpriseManagedRuntimeResolver
	enterpriseManagedRuntimeResolver = resolve
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	nativeEnterpriseHookRuntimeSnapshot.prepared = false
	nativeEnterpriseHookRuntimeSnapshot.executable = ""
	nativeEnterpriseHookRuntimeSnapshot.connector = ""
	nativeEnterpriseHookRuntimeSnapshot.home = ""
	nativeEnterpriseHookRuntimeSnapshot.policyActive = false
	nativeEnterpriseHookRuntimeSnapshot.registered = false
	nativeEnterpriseHookRuntimeSnapshot.gatewayAddr = ""
	nativeEnterpriseHookRuntimeSnapshot.gatewayServiceName = ""
	nativeEnterpriseHookRuntimeSnapshot.scopedToken = ""
	nativeEnterpriseHookRuntimeSnapshot.generationID = ""
	nativeEnterpriseHookRuntimeSnapshot.failMode = ""
	nativeEnterpriseHookRuntimeSnapshot.err = nil
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
	t.Cleanup(func() {
		enterpriseManagedRuntimeResolver = previous
		nativeEnterpriseHookRuntimeSnapshot.Lock()
		nativeEnterpriseHookRuntimeSnapshot.prepared = false
		nativeEnterpriseHookRuntimeSnapshot.executable = ""
		nativeEnterpriseHookRuntimeSnapshot.connector = ""
		nativeEnterpriseHookRuntimeSnapshot.home = ""
		nativeEnterpriseHookRuntimeSnapshot.policyActive = false
		nativeEnterpriseHookRuntimeSnapshot.registered = false
		nativeEnterpriseHookRuntimeSnapshot.gatewayAddr = ""
		nativeEnterpriseHookRuntimeSnapshot.gatewayServiceName = ""
		nativeEnterpriseHookRuntimeSnapshot.scopedToken = ""
		nativeEnterpriseHookRuntimeSnapshot.generationID = ""
		nativeEnterpriseHookRuntimeSnapshot.failMode = ""
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
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:          "claudecode",
			DataDir:            userRuntime,
			PolicyActive:       true,
			Registered:         true,
			GatewayAddr:        "127.0.0.1:18977",
			GatewayServiceName: "DefenseClawGateway",
			ScopedToken:        "authenticated-generation-token",
			GenerationID:       "0123456789abcdef0123456789abcdef",
		}, nil
	})
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("registered enterprise runtime was treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "", true)
	if opts.Home != userRuntime || opts.HookDir != hookDir ||
		opts.APIAddr != "127.0.0.1:18977" ||
		opts.ManagedGatewayServiceName != "DefenseClawGateway" ||
		opts.AuthenticatedManagedToken == nil ||
		*opts.AuthenticatedManagedToken != "authenticated-generation-token" ||
		opts.FailMode != "closed" {
		t.Fatalf("enterprise runtime options = %+v", opts)
	}
}

func TestBuildHookOptionsEnterpriseManagedRejectsIncompleteAuthenticatedGeneration(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	for _, tc := range []struct {
		name         string
		scopedToken  string
		generationID string
	}{
		{
			name:         "empty token",
			generationID: "0123456789abcdef0123456789abcdef",
		},
		{
			name:        "missing generation",
			scopedToken: "authenticated-generation-token",
		},
		{
			name:         "noncanonical generation",
			scopedToken:  "authenticated-generation-token",
			generationID: "0123456789ABCDEF0123456789ABCDEF",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
				return enterprisehooks.WindowsManagedHookRuntime{
					Connector:          "codex",
					DataDir:            filepath.Join(t.TempDir(), ".defenseclaw"),
					PolicyActive:       true,
					Registered:         true,
					GatewayAddr:        "127.0.0.1:18977",
					GatewayServiceName: "DefenseClawGateway",
					ScopedToken:        tc.scopedToken,
					GenerationID:       tc.generationID,
				}, nil
			})
			if enterpriseManagedHookRuntimeNoop("codex") {
				t.Fatal("incomplete authenticated generation was treated as a no-op")
			}
			opts := buildHookOptionsForRuntime("codex", "BeforeAgent", "", "open", true)
			if opts.ManagedRuntimeFailure != "enterprise_managed_runtime_state_invalid" ||
				opts.AuthenticatedManagedToken != nil ||
				opts.FailMode != "closed" || !opts.StrictAvailability {
				t.Fatalf("incomplete authenticated generation did not fail closed: %+v", opts)
			}
		})
	}
}

func TestBuildHookOptionsEnterpriseManagedWithoutPreflightCannotReadLegacyRuntime(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		t.Fatal("managed resolver must not be called from the options builder")
		return enterprisehooks.WindowsManagedHookRuntime{}, nil
	})

	opts := buildHookOptionsForRuntime("codex", "BeforeAgent", "", "open", true)
	if opts.ManagedRuntimeFailure != "enterprise_managed_runtime_state_invalid" ||
		opts.AuthenticatedManagedToken != nil || opts.APIAddr != "127.0.0.1:1" ||
		opts.FailMode != "closed" || !opts.StrictAvailability {
		t.Fatalf("managed options without authenticated preflight did not fail closed: %+v", opts)
	}
}

func TestBuildHookOptionsEnterpriseManagedFailsClosedOnOwnershipError(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "open")
	userRuntime := filepath.Join(t.TempDir(), ".defenseclaw")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:    "claudecode",
			DataDir:      userRuntime,
			PolicyActive: true,
		}, errors.New("tampered managed ownership state")
	})
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("invalid enterprise runtime was allowed to no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
	if opts.Home != "" || opts.HookDir != "" ||
		opts.FailMode != "closed" || !opts.StrictAvailability {
		t.Fatalf("invalid managed runtime did not fail closed: %+v", opts)
	}
}

func TestManagedSIDUnregisteredReasonMatchesEnterpriseHooks(t *testing.T) {
	if hookexec.ManagedSIDUnregisteredReason != enterprisehooks.WindowsManagedSIDUnregisteredReason {
		t.Fatalf("hookexec reason %q != enterprisehooks reason %q",
			hookexec.ManagedSIDUnregisteredReason, enterprisehooks.WindowsManagedSIDUnregisteredReason)
	}
}

// An account that is not enrolled yet takes the managed open default;
// strict availability in the agent's environment still closes it.
func TestEnterpriseManagedHookRuntimeFailsOpenForUnregisteredSID(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:    "claudecode",
			DataDir:      filepath.Join(t.TempDir(), ".defenseclaw"),
			PolicyActive: true,
		}, fmt.Errorf("%w: connector claudecode current SID S-1-5-21-1 is absent", enterprisehooks.ErrWindowsManagedSIDUnregistered)
	})
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("unregistered SID was incorrectly treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
	if opts.FailMode != "open" || opts.StrictAvailability || !opts.ManagedEnterprise ||
		opts.ManagedRuntimeFailure != enterprisehooks.WindowsManagedSIDUnregisteredReason {
		t.Fatalf("unregistered managed SID did not take the open default: %+v", opts)
	}
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "1")
	if opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true); !opts.StrictAvailability {
		t.Fatalf("strict availability override was lost for an unregistered SID: %+v", opts)
	}
}

// Only the typed sentinel selects the unregistered outcome. A resolver error
// that merely carries the reason text, for example in a target-owned path,
// stays an invalid runtime and fails closed.
func TestEnterpriseManagedHookRuntimeUnregisteredTextWithoutSentinelFailsClosed(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
				Connector:    "claudecode",
				DataDir:      filepath.Join(t.TempDir(), ".defenseclaw"),
				PolicyActive: true,
			}, fmt.Errorf("open C:\\Users\\x\\.defenseclaw\\%s: access denied",
				enterprisehooks.WindowsManagedSIDUnregisteredReason)
	})
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("invalid runtime was incorrectly treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
	if opts.ManagedRuntimeFailure != "enterprise_managed_runtime_state_invalid" ||
		opts.FailMode != "closed" || !opts.StrictAvailability {
		t.Fatalf("reason text without the sentinel did not fail closed: %+v", opts)
	}
}

func TestRecognizedPerUserLauncherWithCachedManagedArgsNoopsAfterTombstone(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{Connector: "codex"}, nil
	})
	nativeHookRuntimeSnapshot.Lock()
	oldPrepared := nativeHookRuntimeSnapshot.prepared
	oldExecutable := nativeHookRuntimeSnapshot.executable
	oldState := nativeHookRuntimeSnapshot.state
	oldRecognized := nativeHookRuntimeSnapshot.recognized
	oldErr := nativeHookRuntimeSnapshot.err
	nativeHookRuntimeSnapshot.prepared = true
	nativeHookRuntimeSnapshot.recognized = true
	nativeHookRuntimeSnapshot.err = nil
	nativeHookRuntimeSnapshot.state = hookruntime.State{Status: hookruntime.StatusDisabled}
	nativeHookRuntimeSnapshot.Unlock()
	t.Cleanup(func() {
		nativeHookRuntimeSnapshot.Lock()
		nativeHookRuntimeSnapshot.prepared = oldPrepared
		nativeHookRuntimeSnapshot.executable = oldExecutable
		nativeHookRuntimeSnapshot.state = oldState
		nativeHookRuntimeSnapshot.recognized = oldRecognized
		nativeHookRuntimeSnapshot.err = oldErr
		nativeHookRuntimeSnapshot.Unlock()
	})

	if !enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("recognized per-user launcher with clean absent policy plus trusted disabled state did not no-op")
	}
}

func TestRetainedActiveRuntimeFailsAsUnregisteredBeforeGatewayLookup(t *testing.T) {
	executable, dataRoot := stageTrustedNativeHookForTest(t, "closed")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{Connector: "claudecode"}, nil
	})
	nativeHookRuntimeSnapshot.Lock()
	oldPrepared := nativeHookRuntimeSnapshot.prepared
	oldExecutable := nativeHookRuntimeSnapshot.executable
	oldState := nativeHookRuntimeSnapshot.state
	oldRecognized := nativeHookRuntimeSnapshot.recognized
	oldErr := nativeHookRuntimeSnapshot.err
	nativeHookRuntimeSnapshot.prepared = true
	nativeHookRuntimeSnapshot.executable = executable
	nativeHookRuntimeSnapshot.recognized = true
	nativeHookRuntimeSnapshot.err = nil
	nativeHookRuntimeSnapshot.state = hookruntime.State{
		Status:   hookruntime.StatusActive,
		DataRoot: dataRoot,
	}
	nativeHookRuntimeSnapshot.Unlock()
	t.Cleanup(func() {
		nativeHookRuntimeSnapshot.Lock()
		nativeHookRuntimeSnapshot.prepared = oldPrepared
		nativeHookRuntimeSnapshot.executable = oldExecutable
		nativeHookRuntimeSnapshot.state = oldState
		nativeHookRuntimeSnapshot.recognized = oldRecognized
		nativeHookRuntimeSnapshot.err = oldErr
		nativeHookRuntimeSnapshot.Unlock()
	})

	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("de-enrolled active runtime was incorrectly treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
	if opts.ManagedRuntimeFailure != enterprisehooks.WindowsManagedSIDUnregisteredReason ||
		opts.APIAddr != "" || opts.FailMode != "open" {
		t.Fatalf("de-enrolled runtime was not stopped before gateway lookup: %+v", opts)
	}
}

func TestEnterpriseProgramFilesCommandDoesNotClaimPerUserTombstoneNoop(t *testing.T) {
	installRoot := filepath.Join(t.TempDir(), "Program Files", "Cisco", "DefenseClaw")
	executable := filepath.Join(installRoot, "bin", nativeHookLauncherName)
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("enterprise hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldOverride := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = oldOverride })

	_, recognized, err := hookruntime.ReadTrustedForExecutable(executable)
	if recognized {
		t.Fatalf("managed-enterprise Program Files command was mistaken for the stable per-user launcher: %v", err)
	}
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{Connector: "codex"}, nil
	})
	nativeHookRuntimeSnapshot.Lock()
	nativeHookRuntimeSnapshot.prepared = true
	nativeHookRuntimeSnapshot.executable = executable
	nativeHookRuntimeSnapshot.state = hookruntime.State{}
	nativeHookRuntimeSnapshot.recognized = false
	nativeHookRuntimeSnapshot.err = nil
	nativeHookRuntimeSnapshot.Unlock()
	t.Cleanup(func() {
		nativeHookRuntimeSnapshot.Lock()
		nativeHookRuntimeSnapshot.prepared = false
		nativeHookRuntimeSnapshot.executable = ""
		nativeHookRuntimeSnapshot.state = hookruntime.State{}
		nativeHookRuntimeSnapshot.recognized = false
		nativeHookRuntimeSnapshot.err = nil
		nativeHookRuntimeSnapshot.Unlock()
	})

	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("managed-enterprise Program Files command incorrectly inherited the per-user tombstone no-op")
	}
}

func TestCodexManagedActiveMissingStateFailsClosed(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{
			Connector:    "codex",
			PolicyActive: true,
		}, errors.New("active Codex machine requirements are missing protected managed runtime state")
	})
	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("active Codex policy with missing state was incorrectly treated as a no-op")
	}
	opts := buildHookOptionsForRuntime("codex", "BeforeAgent", "", "open", true)
	if opts.ManagedRuntimeFailure != "enterprise_managed_runtime_state_invalid" ||
		opts.FailMode != "closed" || !opts.StrictAvailability {
		t.Fatalf("active Codex state damage did not fail closed: %+v", opts)
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

func TestManagedRuntimeDriftReasonMatchesEnterpriseHooks(t *testing.T) {
	if hookexec.ManagedRuntimeDriftReason != enterprisehooks.WindowsManagedRuntimeDriftReason {
		t.Fatalf("hookexec reason %q != enterprisehooks reason %q",
			hookexec.ManagedRuntimeDriftReason, enterprisehooks.WindowsManagedRuntimeDriftReason)
	}
}

// Drifted runtime state follows the configured mode the resolver recovered
// from authenticated state, closed when none was recovered; a boundary stays
// closed and strict whatever mode the runtime reports.
func TestEnterpriseManagedHookRuntimeFailureClassSelectsDelivery(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	cause := errors.New("enterprise hooks: managed runtime generation directory is untrusted")
	for _, tc := range []struct {
		name       string
		err        error
		failMode   string
		strictEnv  string
		wantReason string
		wantMode   string
		wantStrict bool
	}{
		{
			name:       "drift open",
			err:        fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, cause),
			failMode:   "open",
			wantReason: enterprisehooks.WindowsManagedRuntimeDriftReason,
			wantMode:   "open",
		},
		{
			name:       "drift closed",
			err:        fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, cause),
			failMode:   "closed",
			wantReason: enterprisehooks.WindowsManagedRuntimeDriftReason,
			wantMode:   "closed",
		},
		{
			name:       "drift with no recovered mode",
			err:        fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, cause),
			wantReason: enterprisehooks.WindowsManagedRuntimeDriftReason,
			wantMode:   "closed",
		},
		{
			name:       "drift open under strict availability",
			err:        fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, cause),
			failMode:   "open",
			strictEnv:  "1",
			wantReason: enterprisehooks.WindowsManagedRuntimeDriftReason,
			wantMode:   "open",
			wantStrict: true,
		},
		{
			name:       "boundary",
			err:        fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeBoundary, cause),
			failMode:   "open",
			wantReason: "enterprise_managed_runtime_state_invalid",
			wantMode:   "closed",
			wantStrict: true,
		},
		{
			name: "boundary wrapping drift",
			err: fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeBoundary,
				fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, cause)),
			failMode:   "open",
			wantReason: "enterprise_managed_runtime_state_invalid",
			wantMode:   "closed",
			wantStrict: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", tc.strictEnv)
			stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
				return enterprisehooks.WindowsManagedHookRuntime{
					Connector:    "claudecode",
					DataDir:      filepath.Join(t.TempDir(), ".defenseclaw"),
					PolicyActive: true,
					FailMode:     tc.failMode,
				}, tc.err
			})
			if enterpriseManagedHookRuntimeNoop("claudecode") {
				t.Fatal("failed managed runtime was treated as a no-op")
			}
			opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
			if opts.ManagedRuntimeFailure != tc.wantReason ||
				opts.FailMode != tc.wantMode ||
				opts.StrictAvailability != tc.wantStrict ||
				!opts.ManagedEnterprise ||
				opts.AuthenticatedManagedToken != nil {
				t.Fatalf("delivery = %+v, want reason=%q mode=%q strict=%t",
					opts, tc.wantReason, tc.wantMode, tc.wantStrict)
			}
		})
	}
}
