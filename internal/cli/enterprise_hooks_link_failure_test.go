// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0879. A link at one connector's vendor folder fails that connector's
// targets by name and does not stop the pass: the other connectors are revoked
// and applied, and the manifest is activated, so a later uninstall can adopt it.
// A failure that is not a link still fails the pass.
func TestEnterpriseHookReconcileFailsOnlyTheLinkedConnectorsRows(t *testing.T) {
	for _, shape := range []string{"link at the Codex folder", "a failure that is no link", "a link that appears after the pre-pass"} {
		t.Run(shape, func(t *testing.T) {
			stubEarlierReleaseClosedMachineRegistration(t)
			restoreEnterpriseHooksLifecycleTestState(t)
			stubEnterpriseHookAuthorizationTrustForTempDir(t)
			stubEnterpriseHookTokenSources(t)
			awaitingSignInTestPlatformSetup(t)
			previousSecureClient := enterpriseHookReconcileSecureClient
			previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
			previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
			previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
			previousRelease, previousDeferredSession := enterpriseHookReconcileTargetRelease, enterpriseHookReconcileDeferredSessionAvailable
			previousStage, previousSync := enterpriseHookReconcileStageDeferredPolicies, enterpriseHookReconcileSyncEnrollments
			previousStateTrust, previousManifestTrust := enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck
			previousOwnership := enterpriseHookAuthorizationOwnershipSetter
			t.Cleanup(func() {
				enterpriseHookReconcileSecureClient = previousSecureClient
				enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
				enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
				enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
				enterpriseHookReconcileTargetRelease, enterpriseHookReconcileDeferredSessionAvailable = previousRelease, previousDeferredSession
				enterpriseHookReconcileStageDeferredPolicies, enterpriseHookReconcileSyncEnrollments = previousStage, previousSync
				enterpriseHookGuardianStateFileTrustCheck, enterpriseHookManifestFileTrustCheck = previousStateTrust, previousManifestTrust
				enterpriseHookAuthorizationOwnershipSetter = previousOwnership
			})
			enterpriseHookReconcileSecureClient = func() bool { return false }
			enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
				return enterprisepolicy.CleanupResult{}, nil
			}
			enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
			enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
			enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }

			scope := t.TempDir()
			dataDir := filepath.Join(scope, "runtime")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
			type account struct{ name, sid string }
			alice := account{"EntraAlice", "S-1-12-1-1-2-3-1001"}
			bob := account{"EntraBob", "S-1-12-1-1-2-3-1002"}
			stale := account{"EntraGone", "S-1-12-1-1-2-3-1009"}
			homes := map[string]string{}
			for _, a := range []account{alice, bob, stale} {
				homes[a.sid] = filepath.Join(scope, a.name)
				if err := os.MkdirAll(homes[a.sid], 0o700); err != nil {
					t.Fatal(err)
				}
			}
			manifestPath := filepath.Join(scope, "targets.yaml")
			var body strings.Builder
			body.WriteString("version: 1\ntargets:\n")
			for _, a := range []account{alice, bob} {
				for _, connectorName := range []string{"claudecode", "codex"} {
					body.WriteString(awaitingSignInManifestTarget(homes[a.sid], a.sid, connectorName))
				}
			}
			if err := os.WriteFile(manifestPath, []byte(body.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := enterprisehooks.LoadManifestWithSHA256(manifestPath); err != nil {
				t.Fatal(err)
			}
			cfg = &config.Config{DataDir: dataDir, DeploymentMode: "local"}
			enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"

			// The account that left the manifest still holds a Claude Code enrollment: stale.
			store := awaitingSignInEnrollmentStore{}
			store.enroll("claudecode", stale.sid)
			enterpriseHookReconcileVerifier = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
				return enterprisehooks.InstallResult{}, errors.New("not installed yet")
			}
			enterpriseHookReconcileTargetRelease = func(enterprisehooks.InstallOptions) (string, bool, error) { return "1.0.9", true, nil }
			available := func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }
			enterpriseHookReconcileSessionAvailable = available
			enterpriseHookReconcileDeferredSessionAvailable = available
			var installed []string
			enterpriseHookReconcileInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
				installed = append(installed, opts.OwnerSID+"/"+opts.ConnectorName)
				store.enroll(opts.ConnectorName, opts.OwnerSID)
				return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
			}
			enterpriseHookReconcileStageDeferredPolicies = func(enterprisehooks.Manifest, []enterprisehooks.ManifestTarget, string) error { return nil }
			const link = `C:\ProgramData\OpenAI\Codex`
			enterpriseHookReconcileSyncEnrollments = func(m enterprisehooks.Manifest, _ string, publishExact bool) error {
				desired := awaitingSignInDesiredEnrollment(t, m)
				for connectorName, sids := range store {
					for sid := range sids {
						if !desired[connectorName][sid] {
							delete(sids, sid)
						}
					}
				}
				if shape == "a failure that is no link" {
					return errors.New("ensure configured Codex machine requirements: access is denied")
				}
				if shape == "a link that appears after the pre-pass" && !publishExact {
					return nil
				}
				return &enterpriseHookConnectorLinkFailures{Failures: []enterpriseHookConnectorLinkFailure{
					{Connector: "codex", Link: link, Cause: errors.New("ensure configured Codex machine requirements: a link sits at " + link)},
				}}
			}

			// The streak tracker is process-wide: start this row with none.
			previousHealth := enterpriseHookTargetHealth
			enterpriseHookTargetHealth = &enterpriseHookTargetHealthTracker{}
			t.Cleanup(func() { enterpriseHookTargetHealth = previousHealth })
			var skips int
			previousReport := managed.ReportResilienceEvent
			managed.ReportResilienceEvent = func(marker string, _ map[string]string) {
				if marker == managed.MarkerSkip {
					skips++
				}
			}
			t.Cleanup(func() { managed.ReportResilienceEvent = previousReport })
			run, err := runEnterpriseHookReconcileOnce(context.Background())
			if shape == "a link that appears after the pre-pass" {
				// No row was failed for the link, so the publish failure must keep the pass failed.
				if err != nil || run.StateErr == nil || !strings.Contains(run.StateErr.Error(), "publish exact protected enrollment set") || run.Failures != 0 {
					t.Fatalf("a link after the pre-pass must keep the pass failed: err=%v stateErr=%v failures=%d", err, run.StateErr, run.Failures)
				}
				return
			}
			if shape == "a failure that is no link" {
				if err == nil || !strings.Contains(err.Error(), "revoke stale protected enrollments") || len(run.Rows) != 0 || len(installed) != 0 {
					t.Fatalf("a failure that is no link must still fail the pass before any row: err=%v rows=%d installed=%v", err, len(run.Rows), installed)
				}
				return
			}
			if err != nil || run.StateErr != nil {
				t.Fatalf("a link at the Codex folder failed the pass: err=%v stateErr=%v", err, run.StateErr)
			}
			// Codex rows fail with the link text; Claude Code rows are applied.
			if run.Failures != 2 || len(run.Rows) != 4 {
				t.Fatalf("failures=%d rows=%d, want 2 failed Codex rows of 4", run.Failures, len(run.Rows))
			}
			wantText := fmt.Sprintf(enterpriseHookVendorFolderLinkRow, "Codex", "Codex", link)
			for _, row := range run.Rows {
				switch row.Connector {
				case "codex":
					if row.OK || row.Error != wantText {
						t.Fatalf("Codex row of %s: ok=%v error=%q, want a failure with %q", row.SID, row.OK, row.Error, wantText)
					}
				case "claudecode":
					if !row.OK || row.Error != "" {
						t.Fatalf("Claude Code row of %s: ok=%v error=%q, want it applied", row.SID, row.OK, row.Error)
					}
				}
			}
			if strings.Join(installed, ",") == "" || strings.Contains(strings.Join(installed, ","), "/codex") {
				t.Fatalf("installed %v: Claude Code must be applied and nothing written for Codex", installed)
			}
			if store["claudecode"][strings.ToUpper(stale.sid)] {
				t.Fatalf("the stale Claude Code enrollment survived the pass: %v", store.sorted("claudecode"))
			}
			// The failed rows are logged once per streak, not on every pass.
			if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil || skips != 2 {
				t.Fatalf("a second pass with the same failed rows logged %d skip lines in total, want 2 (one per row, once)", skips)
			}
			state, exists, err := loadEnterpriseHookGuardianState(dataDir)
			if err != nil || !exists || state.Manifest != manifestPath || state.FailureCount != 2 || state.SuccessCount != 2 || state.TargetCount != 4 {
				t.Fatalf("the pass did not record the manifest with the Codex rows failed: exists=%v err=%v state=%+v", exists, err, state)
			}
		})
	}
}

// The failed row of a linked connector is the text the Setup adoption gate
// matches (GuardianMachineFolderLinkPattern in DefenseClawEnterprise.psm1). The
// text comes from the Go format string, and the pattern from the module, so
// neither can drift from the other without this test failing.
func TestEnterpriseHookVendorFolderLinkRowMatchesTheAdoptionGatePattern(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Skipf("the module is not beside the source tree: %v", err)
	}
	start := strings.Index(string(module), "$script:GuardianMachineFolderLinkPattern = [regex]::new(")
	if start < 0 {
		t.Fatal("GuardianMachineFolderLinkPattern is not in the module")
	}
	literal := regexp.MustCompile(`(?s)\[regex\]::new\(\s*'(.*?)'\)`).FindStringSubmatch(string(module)[start:])
	if literal == nil {
		t.Fatal("cannot read the pattern literal")
	}
	pattern := regexp.MustCompile(strings.ReplaceAll(strings.ReplaceAll(literal[1], "(?<path>", "(?P<path>"), "''", "'"))
	for _, tc := range []struct{ connector, link string }{
		{"codex", `C:\ProgramData\OpenAI\Codex`},
		{"codex", `C:\ProgramData\OpenAI`},
		{"cursor", `C:\ProgramData\Cursor`},
		{"claudecode", `C:\Program Files\ClaudeCode\managed-settings.d`},
	} {
		text := enterpriseHookConnectorLinkFailure{Connector: tc.connector, Link: tc.link, Cause: errors.New("x")}.rowError()
		found := pattern.FindStringSubmatch(text)
		if found == nil || found[pattern.SubexpIndex("path")] != tc.link {
			t.Fatalf("the failed row %q is not matched by the adoption gate pattern (captured %v)", text, found)
		}
	}
}

func TestClassifyEnterpriseHookConnectorErrors(t *testing.T) {
	linkOf := func(links map[string]string) func(string) string {
		return func(connectorName string) string { return links[connectorName] }
	}
	codex := errors.New("codex step failed")
	other := errors.New("claude step failed")
	if err := classifyEnterpriseHookConnectorErrors(linkOf(nil), nil, nil); err != nil {
		t.Fatalf("no failure: %v", err)
	}
	// Only a link: a typed failure the pass survives.
	err := classifyEnterpriseHookConnectorErrors(linkOf(map[string]string{"codex": `C:\ProgramData\OpenAI\Codex`}),
		[]enterpriseHookConnectorStepError{{Connector: "codex", Err: codex}}, nil)
	failures := enterpriseHookLinkFailures(err)
	if failures == nil || len(failures.Failures) != 1 || !errors.Is(err, codex) {
		t.Fatalf("a link alone: %v", err)
	}
	// A link next to a failure that is no link: a plain pass failure naming both.
	err = classifyEnterpriseHookConnectorErrors(linkOf(map[string]string{"codex": `C:\ProgramData\OpenAI\Codex`}),
		[]enterpriseHookConnectorStepError{{Connector: "claudecode", Err: other}, {Connector: "codex", Err: codex}}, nil)
	if enterpriseHookLinkFailures(err) != nil || !errors.Is(err, other) || !errors.Is(err, codex) {
		t.Fatalf("a link next to another failure must fail the pass: %v", err)
	}
	// A pass-level error is never a link failure.
	pass := errors.New("resolve the layout")
	err = classifyEnterpriseHookConnectorErrors(linkOf(map[string]string{"codex": `C:\ProgramData\OpenAI\Codex`}),
		[]enterpriseHookConnectorStepError{{Connector: "codex", Err: codex}}, pass)
	if enterpriseHookLinkFailures(err) != nil || !errors.Is(err, pass) {
		t.Fatalf("a pass-level error: %v", err)
	}
}

// The guardian log line of a link failure names the link and the fix for every
// connector, not only Codex.
func TestEnterpriseHookLinkCauseLineCarriesTheFixForEveryConnector(t *testing.T) {
	for connectorName, link := range map[string]string{
		"codex":      `C:\ProgramData\OpenAI\Codex`,
		"cursor":     `C:\ProgramData\Cursor`,
		"claudecode": `C:\Program Files\ClaudeCode\managed-settings.d`,
	} {
		line := enterpriseHookConnectorLinkFailure{Connector: connectorName, Link: link, Cause: errors.New("access is denied")}.causeLine()
		for _, want := range []string{connectorName, link, `cmd /c rmdir "` + link + `"`, "access is denied"} {
			if !strings.Contains(line, want) {
				t.Fatalf("%s: the log line lacks %q: %s", connectorName, want, line)
			}
		}
		if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
			t.Fatalf("%s: not exactly one line: %q", connectorName, line)
		}
	}
}
