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
