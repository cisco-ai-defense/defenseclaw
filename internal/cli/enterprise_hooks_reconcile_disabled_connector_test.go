// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2373: on a standalone managed deployment the reconcile row of a
// connector the loaded config no longer enables (an administrator's
// guardrail.connectors.opencode.enabled: false, before the enumerator drops
// the row) is failed for this pass, never verified or repaired: the repair
// took the per-user route and left a per-user OpenCode plugin that blocked
// every tool call. Enabled connectors and other deployments are unchanged.
func TestEnterpriseHookReconcileConnectorPublishedRefusesADisabledConnector(t *testing.T) {
	disabled := false
	standalone := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	standalone.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":    {Mode: "observe"},
		"opencode": {Mode: "action", Enabled: &disabled},
	}
	err := enterpriseHookReconcileConnectorPublished(standalone, "opencode")
	if err == nil || !strings.Contains(err.Error(), `connector "opencode" is not enabled`) ||
		!strings.Contains(err.Error(), "enumerator removes the row") {
		t.Fatalf("disabled opencode: err=%v, want the not-enabled row error", err)
	}
	if err := enterpriseHookReconcileConnectorPublished(standalone, "codex"); err != nil {
		t.Fatalf("enabled codex: %v", err)
	}
	enabled := true
	standalone.Guardrail.Connectors["opencode"] = config.PerConnectorGuardrailConfig{Mode: "action", Enabled: &enabled}
	if err := enterpriseHookReconcileConnectorPublished(standalone, "opencode"); err != nil {
		t.Fatalf("re-enabled opencode: %v", err)
	}
	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	secureClient.Enterprise.Profile = managed.ProfileSecureClient
	secureClient.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"opencode": {Enabled: &disabled}}
	if err := enterpriseHookReconcileConnectorPublished(secureClient, "opencode"); err != nil {
		t.Fatalf("Secure Client is unchanged: %v", err)
	}
	if err := enterpriseHookReconcileConnectorPublished(&config.Config{}, "opencode"); err != nil {
		t.Fatalf("per-user config is unchanged: %v", err)
	}
}

func TestEnterpriseHookReconcileNeverRepairsARowOfADisabledConnector(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	previousEnabled := enterpriseHookReconcileConnectorEnabled
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
		enterpriseHookReconcileConnectorEnabled = previousEnabled
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	home := filepath.Join(scope, "home")
	for _, dir := range []string{dataDir, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	const sid = "S-1-5-21-1-2-3-1001"
	versions := map[string]string{"codex": "0.200.0", "opencode": "1.18.34"}
	manifest := "version: 1\ntargets:\n"
	protected := []enterpriseHookReconcileRow{}
	for _, name := range []string{"codex", "opencode"} {
		manifest += fmt.Sprintf("  - user_home: %q\n", home)
		if runtime.GOOS == "windows" {
			manifest += fmt.Sprintf("    agent_version: %s\n", versions[name])
		} else {
			manifest += fmt.Sprintf("    uid: %d\n    gid: %d\n", os.Getuid(), os.Getgid())
		}
		manifest += fmt.Sprintf("    sid: %s\n    connector: %s\n", sid, name)
		protected = append(protected, enterpriseHookReconcileRow{UserHome: home, SID: sid, Connector: name, OK: true})
	}
	manifestPath := filepath.Join(scope, "targets.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	if err := writeEnterpriseHookGuardianState(dataDir, manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}
	// The loaded config has withdrawn opencode; targets.yaml still lists it.
	enterpriseHookReconcileConnectorEnabled = func(name string) error {
		if name == "opencode" {
			return errors.New(`enterprise hooks reconcile: connector "opencode" is not enabled by this computer's DefenseClaw configuration`)
		}
		return nil
	}
	verified, installs := []string{}, []string{}
	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		verified = append(verified, opts.ConnectorName)
		if opts.ConnectorName == "opencode" {
			// Machine policy withdrawn: the per-user plugin route finds no plugin.
			return enterprisehooks.InstallResult{}, errors.New("opencode plugin is missing")
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		installs = append(installs, opts.ConnectorName)
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(installs) != 0 || strings.Join(verified, ",") != "codex" {
		t.Fatalf("verified=%v installs=%v, want only codex verified and nothing installed for the disabled opencode row", verified, installs)
	}
	if run.Failures != 1 || run.Repairs != 0 {
		t.Fatalf("run=%+v, want the one opencode row failed and no repair", run)
	}
	for _, row := range run.Rows {
		switch row.Connector {
		case "codex":
			if !row.OK {
				t.Fatalf("codex row %+v, want ok", row)
			}
		case "opencode":
			if row.OK || !strings.Contains(row.Error, "is not enabled") {
				t.Fatalf("opencode row %+v, want the not-enabled error", row)
			}
		}
	}
}
