// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// Revoking a user whose connector has no machine directory (it never ran,
// or an uninstall already retired it) must not create the directory and
// its lock file; with an enrollment present, the SID is still revoked.
func TestRevokeWindowsPerUserManagedRegistrationCreatesNothingWithoutItsDirectory(t *testing.T) {
	h := newPerUserManagedHarness(t)
	const name = "devin"
	directory := filepath.Join(h.base, windowsPerUserManagedRuntimeParent, name)
	if err := revokeWindowsPerUserManagedRegistration(name, h.target, h.dataDir, h.hookExecutable); err != nil {
		t.Fatalf("revoke without a directory: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revocation created %s: %v", directory, err)
	}

	if err := updateWindowsPerUserManagedEnrollment(name, h.hookExecutable,
		func(current []windowsPerUserManagedEnrollmentTarget) []windowsPerUserManagedEnrollmentTarget {
			return append(current, windowsPerUserManagedEnrollmentTarget{SID: h.target.String(), DataDir: h.dataDir})
		}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := revokeWindowsPerUserManagedRegistration(name, h.target, h.dataDir, h.hookExecutable); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, exists, err := readWindowsPerUserManagedEnrollment(name); err != nil || exists {
		t.Fatalf("enrollment survived revocation: exists=%t err=%v", exists, err)
	}
}

// Removal renders the connector's hook command with the same hook binary
// install used, so a registration that names the binary (Hermes' direct
// hook) is recognized and removed rather than left behind. The fixture user
// has no DefenseClaw data directory (a user may delete it); the
// registration is still removed and there is no hook contract to clear.
func TestRemoveWindowsGenericManagedRuntimeTearsDownWithTheInstalledHookBinary(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	var captured []connector.SetupOpts
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{configPath: fixture.config, teardownOpts: &captured})
	opts := fixture.opts
	opts.Registry = registry
	if err := removeWindowsGenericManagedRuntime(context.Background(), opts); err != nil {
		t.Fatalf("remove: %v", err)
	}
	want, err := windowsEnterpriseHookExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 || !captured[0].ManagedEnterprise ||
		!sameWindowsEnterprisePath(captured[0].HookExecutable, want) {
		t.Fatalf("teardown options = %+v, want managed teardown with hook executable %s", captured, want)
	}
}

// Runtime-only removal must reach the registered user-file cleanup while
// impersonating the target account. Other connectors must leave Copilot's
// VS Code Local files alone.
func TestRemoveWindowsRuntimeOnlyManagedRuntimeDispatchesCopilotVSCodeCleanup(t *testing.T) {
	h := newPerUserManagedHarness(t)
	home := newWindowsTargetOwnedTestHome(t, h.target)
	previousHook := windowsEnterpriseHookExecutable
	previousImpersonation := windowsEnterpriseTargetImpersonation
	windowsCopilotVSCodeUser.Lock()
	previousCopilot := windowsCopilotVSCodeUser.apply
	windowsCopilotVSCodeUser.Unlock()
	t.Cleanup(func() {
		windowsEnterpriseHookExecutable = previousHook
		windowsEnterpriseTargetImpersonation = previousImpersonation
		SetWindowsCopilotVSCodeUser(previousCopilot)
	})
	windowsEnterpriseHookExecutable = func() (string, error) { return h.hookExecutable, nil }
	impersonations := 0
	inImpersonation := false
	windowsEnterpriseTargetImpersonation = func(sid *windows.SID, gotHome string, fn func() error) error {
		if !sid.Equals(h.target) || gotHome != home {
			t.Fatalf("removal impersonation = %s %s, want %s %s", sid, gotHome, h.target, home)
		}
		impersonations++
		inImpersonation = true
		defer func() { inImpersonation = false }()
		return runWindowsTestThreadImpersonatedAsSelf(fn)
	}
	type cleanupCall struct {
		home           string
		verify, remove bool
	}
	var calls []cleanupCall
	SetWindowsCopilotVSCodeUser(func(gotHome string, verify, remove bool) error {
		if !inImpersonation {
			t.Fatal("Copilot user-file cleanup ran outside target impersonation")
		}
		calls = append(calls, cleanupCall{gotHome, verify, remove})
		return nil
	})

	opts := InstallOptions{OwnerSID: h.target.String(), UserHome: home}
	for _, conn := range []connector.Connector{connector.NewOpenCodeConnector(), connector.NewCopilotConnector()} {
		if err := removeWindowsRuntimeOnlyManagedRuntime(context.Background(), opts, conn); err != nil {
			t.Fatalf("remove %s: %v", conn.Name(), err)
		}
		if conn.Name() == "opencode" && len(calls) != 0 {
			t.Fatalf("OpenCode removal invoked Copilot cleanup: %+v", calls)
		}
	}
	if impersonations != 2 {
		t.Fatalf("runtime removals used impersonation %d times, want 2", impersonations)
	}
	if len(calls) != 1 || calls[0] != (cleanupCall{home: home, verify: false, remove: true}) {
		t.Fatalf("Copilot removal callbacks = %+v, want one removal for %s", calls, home)
	}
	SetWindowsCopilotVSCodeUser(nil)
	if err := removeWindowsRuntimeOnlyManagedRuntime(context.Background(), opts, connector.NewCopilotConnector()); err == nil {
		t.Fatal("Copilot removal succeeded without the registered user-file callback")
	}
}

func newWindowsCopilotUserHooksFixture(t *testing.T) (home, dataDir, hooks string) {
	t.Helper()
	target := currentWindowsTestSID(t)
	home = filepath.Join(t.TempDir(), "home")
	dataDir = filepath.Join(home, ".defenseclaw")
	for _, path := range []string{home, dataDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setWindowsTestPathExactOwner(t, home, target)
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatalf("protect home: %v", err)
	}
	copilotHome := filepath.Join(home, ".copilot")
	t.Setenv("COPILOT_HOME", copilotHome)
	previousHooks, previousWorkspace := connector.CopilotHooksPathOverride, connector.CopilotWorkspaceDirOverride
	connector.CopilotHooksPathOverride, connector.CopilotWorkspaceDirOverride = "", ""
	t.Cleanup(func() {
		connector.CopilotHooksPathOverride, connector.CopilotWorkspaceDirOverride = previousHooks, previousWorkspace
	})
	return home, dataDir, filepath.Join(copilotHome, "hooks", "defenseclaw.json")
}

// A Copilot user hook file DefenseClaw wrote (an earlier per-user setup) is
// DefenseClaw's own registration: removal takes out its entries and keeps
// the user's handler. A user without the file gets nothing written.
func TestRemoveWindowsRuntimeOnlyUserRegistrationRemovesOnlyDefenseClawCopilotHooks(t *testing.T) {
	target := currentWindowsTestSID(t)
	home, dataDir, hooks := newWindowsCopilotUserHooksFixture(t)
	hookExecutable := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	conn := connector.NewCopilotConnector()

	if err := removeWindowsRuntimeOnlyUserRegistration(context.Background(), conn, home, dataDir, hookExecutable, target); err != nil {
		t.Fatalf("removal for a user without Copilot hooks: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(hooks)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removal created Copilot hook state for a user without it: %v", err)
	}

	setup := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	if err := connector.WithUserHomeDir(home, func() error { return conn.Setup(context.Background(), setup) }); err != nil {
		t.Fatalf("setup: %v", err)
	}
	var document map[string]any
	body, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatalf("setup did not write %s: %v", hooks, err)
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	events, _ := document["hooks"].(map[string]any)
	list, _ := events["preToolUse"].([]any)
	events["preToolUse"] = append(list, map[string]any{"type": "command", "powershell": "C:\\Tools\\operator-review.ps1"})
	body, _ = json.Marshal(document)
	if err := os.WriteFile(hooks, body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(filepath.Dir(hooks)), filepath.Dir(hooks)} {
		setWindowsTestPathExactOwner(t, path, target)
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect %s: %v", path, err)
		}
	}
	setWindowsTestPathExactOwner(t, hooks, target)
	if err := setWindowsUserPathProtection(hooks, target, false); err != nil {
		t.Fatalf("protect %s: %v", hooks, err)
	}

	if err := removeWindowsRuntimeOnlyUserRegistration(context.Background(), conn, home, dataDir, hookExecutable, target); err != nil {
		t.Fatalf("removal: %v", err)
	}
	kept, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatalf("removal deleted the user's handler with the file: %v", err)
	}
	if !strings.Contains(string(kept), "operator-review.ps1") || strings.Contains(string(kept), "copilot-hook") {
		t.Fatalf("removal left %s", kept)
	}
}
