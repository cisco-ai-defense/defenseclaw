// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/spf13/cobra"
)

// GAP-1968: the readiness-notes plumbing at command level. A target check
// that meets an account file the Windows migration cannot finish adds a note
// while `enterprise hooks readiness` runs (the note set is stored), and fails
// its row otherwise. Readiness then passes with the note under warnings,
// `enterprise hooks verify` fails and names the file, and the set is cleared
// after readiness so a later verify in the same process still fails.
func TestEnterpriseHooksReadinessReportsANoteThatVerifyFails(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousPublic, previousRegistration := enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier
	previousSession, previousDeferredSession := enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable
	previousRelease, previousChange := enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange
	previousSecureClient := enterpriseHookReconcileSecureClient
	previousCleanup := enterpriseForeignHookCleanup
	previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
	previousStandaloneUnix := enterprisehooks.StandaloneUnix()
	previousJSON := enterpriseHookJSON
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = previousPublic, previousRegistration
		enterpriseHookReconcileSessionAvailable, enterpriseHookReconcileDeferredSessionAvailable = previousSession, previousDeferredSession
		enterpriseHookReconcileTargetRelease, enterpriseHookReconcileTargetFailModeChange = previousRelease, previousChange
		enterpriseHookReconcileSecureClient = previousSecureClient
		enterpriseForeignHookCleanup = previousCleanup
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
		enterprisehooks.SetStandaloneUnix(previousStandaloneUnix)
		enterpriseHookJSON = previousJSON
		enterpriseHookReadinessNotes.Store(nil)
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	enterprisehooks.SetStandaloneUnix(true)
	enterpriseHookReconcileSecureClient = func() bool { return false }
	enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "", false, nil }
	enterpriseHookReconcileTargetFailModeChange = func(enterprisehooks.InstallOptions) (string, string, error) { return "", "", nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	home := filepath.Join(scope, "Alice")
	for _, dir := range []string{dataDir, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	alice := "S-1-5-21-1-2-3-1017"
	manifestPath := filepath.Join(scope, "targets.yaml")
	manifestBody := fmt.Sprintf("version: 1\ntargets:\n  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: codex\n    enabled: true\n    deferred: true\n",
		home, os.Getuid(), os.Getgid(), alice)
	if err := os.WriteFile(manifestPath, []byte(manifestBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	if _, err := connector.EnsureHookAPIToken(dataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if otlpScope, ok := connector.OTLPPathTokenScopeForConnector("codex"); ok {
		if _, err := connector.EnsureOTLPPathToken(dataDir, otlpScope); err != nil {
			t.Fatal(err)
		}
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
	enterpriseHookReconcileDeferredSessionAvailable = enterpriseHookReconcileSessionAvailable
	const fileNote = `C:\Users\Alice\.claude\settings.json cannot be migrated: it starts with a byte order mark`
	ok := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	// The target check as windowsCopilotVSCodeUser runs it: a note while
	// readiness runs, the row's error otherwise.
	check := func(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if notes := enterpriseHookReadinessNotes.Load(); notes != nil {
			notes.add(fileNote)
			return ok(ctx, opts)
		}
		return enterprisehooks.InstallResult{}, errors.New(fileNote)
	}
	enterpriseHookReconcileInstaller, enterpriseHookReconcileVerifier = ok, ok
	if run, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil || run.StateErr != nil || run.Failures != 0 {
		t.Fatalf("guardian pass: run=%+v err=%v", run, err)
	}
	enterpriseHookLivePublicVerifier, enterpriseHookLiveRegistrationVerifier = check, check

	run := func(registrationOnly bool) (map[string]any, error) {
		t.Helper()
		enterpriseHookJSON = true
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		err := runEnterpriseHooksVerifyWithScope(cmd, registrationOnly)
		payload := map[string]any{}
		if decodeErr := json.Unmarshal(out.Bytes(), &payload); decodeErr != nil {
			t.Fatalf("registrationOnly=%t: output %q is not one JSON object: %v", registrationOnly, out.String(), decodeErr)
		}
		return payload, err
	}
	hasNote := func(payload map[string]any) bool {
		warnings, _ := payload["warnings"].([]any)
		for _, warning := range warnings {
			if text, _ := warning.(string); strings.Contains(text, "settings.json cannot be migrated") {
				return true
			}
		}
		return false
	}

	readiness, err := run(true)
	if err != nil || readiness["ok"] != true || !hasNote(readiness) {
		t.Fatalf("readiness: err=%v payload=%v, want ok with the settings note under warnings", err, readiness)
	}
	if enterpriseHookReadinessNotes.Load() != nil {
		t.Fatal("the readiness note set outlived the readiness run")
	}
	verify, err := run(false)
	if err == nil || verify["ok"] != false || hasNote(verify) {
		t.Fatalf("verify after readiness: err=%v payload=%v, want a failed row naming the file, not a warning", err, verify)
	}
	if !strings.Contains(fmt.Sprint(verify["results"]), "settings.json cannot be migrated") {
		t.Fatalf("verify results %v do not name the file", verify["results"])
	}
}
