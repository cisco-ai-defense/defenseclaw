//go:build windows

package cli

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2056. The guardian publishes the Codex targets for the hook image it
// resolves, and that publication verifies the requirements against that
// image. Requirements an earlier image of this install published are read as
// active (GAP-0751), so the guardian has to publish them again for its image
// first. Before the fix it did not: a standalone rollback restored 1.0.10's
// requirements (bin\hooks\6081ba06f39a5eb8) while the transaction's guard was
// still the hook at bin\defenseclaw-hook.exe, every guardian pass failed with
// "windows_managed_dir ... does not match protected managed directory", and
// the rollback stayed pending with the gateway stopped.
func TestWindowsGuardianRepublishesCodexRequirementsOfAnotherHookImage(t *testing.T) {
	const bin = `C:\Program Files\Cisco\DefenseClaw\bin`
	transition := bin + `\defenseclaw-hook.exe`
	restored := bin + `\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
	upgraded := bin + `\hooks\0f1e2d3c4b5a6978\defenseclaw-hook.exe`
	cases := []struct {
		name          string
		recorded      string
		resolved      string
		wantReconcile int
	}{
		{name: "rollback: restored requirements name the prior launch folder, the guard is the hook", recorded: restored, resolved: transition, wantReconcile: 1},
		{name: "rollback: the restored hook is back, requirements name the guard", recorded: transition, resolved: restored, wantReconcile: 1},
		{name: "upgrade: requirements name the old launch folder", recorded: restored, resolved: upgraded, wantReconcile: 1},
		{name: "steady state: requirements name the resolved image", recorded: restored, resolved: restored, wantReconcile: 0},
		{name: "steady state: spelling differs only in case", recorded: restored, resolved: `c:\program files\cisco\defenseclaw\bin\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`, wantReconcile: 0},
	}
	for _, tc := range cases {
		for _, publishExact := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/publishExact=%v", tc.name, publishExact), func(t *testing.T) {
				previousCfg := cfg
				previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
				previousClaudeEnsurer, previousCursorEnsurer := enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer
				previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
				previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
				previousCodexReconciler, previousCodexRemover := enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexRequirementsRemover
				previousCodexPublisher, previousFolder := enterpriseHookCodexTargetsPublisher, enterpriseHookCodexFolderEnsurer
				previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
				t.Cleanup(func() {
					cfg = previousCfg
					enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
					enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer = previousClaudeEnsurer, previousCursorEnsurer
					enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
					enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
					enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexRequirementsRemover = previousCodexReconciler, previousCodexRemover
					enterpriseHookCodexTargetsPublisher, enterpriseHookCodexFolderEnsurer = previousCodexPublisher, previousFolder
					enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
				})
				cfg = &config.Config{
					DeploymentMode: managed.DeploymentModeManagedEnterprise,
					Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
					Guardrail:      config.GuardrailConfig{Connector: "codex"},
				}
				// published is the image the requirements on disk name; the
				// reconcile publishes them for the image it is given.
				published := tc.recorded
				reconciled := 0
				enterpriseHookCodexFolderEnsurer = func() (enterprisehooks.WindowsCodexMachineFolderEnsure, error) {
					return enterprisehooks.WindowsCodexMachineFolderEnsure{Folder: `C:\ProgramData\OpenAI\Codex`}, nil
				}
				enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
					return connector.WindowsCodexMachineRequirementsOptions{HookBinary: tc.resolved, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
				}
				enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
					return connector.WindowsCodexManagedRuntimeRegistry{Active: true, HookExecutable: published, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
				}
				enterpriseHookCodexRequirementsReconciler = func(opts connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
					if !opts.CodexTargetEnabled {
						t.Fatal("the republish did not enable the configured Codex machine guard")
					}
					reconciled++
					published = opts.HookBinary
					return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
				}
				// The real publication verifies the requirements against the
				// image it publishes for (verifyWindowsCodexMachineRequirementsLocked).
				enterpriseHookCodexTargetsPublisher = func(opts connector.WindowsCodexMachineRequirementsOptions, _ []connector.WindowsCodexManagedRuntimeTarget) error {
					if !sameWindowsEnterprisePathCLI(published, opts.HookBinary) {
						return fmt.Errorf("hooks.windows_managed_dir=%q does not match protected managed directory %q",
							filepath.Dir(published), filepath.Dir(opts.HookBinary))
					}
					return nil
				}
				enterpriseHookCodexRequirementsRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
					t.Fatal("a configured Codex connector must not have its requirements removed")
					return connector.WindowsCodexMachineRequirementsReport{}, nil
				}
				enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, false, nil }
				enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
					return nil, false, nil
				}
				enterpriseHookClaudePolicyEnsurer = func(connector.SetupOpts) error { return nil }
				enterpriseHookCursorPolicyEnsurer = func(connector.SetupOpts) error { return nil }
				enterpriseHookClaudePolicyTargetsPublisher = func([]string) error { return nil }
				enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
				enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
				enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }

				if err := syncEnterpriseHookManagedMachineEnrollments(enterprisehooks.Manifest{}, "127.0.0.1:32109", publishExact); err != nil {
					t.Fatalf("guardian pass failed (reconcile x%d): %v", reconciled, err)
				}
				if reconciled != tc.wantReconcile {
					t.Fatalf("reconcile x%d, want x%d", reconciled, tc.wantReconcile)
				}
				if !sameWindowsEnterprisePathCLI(published, tc.resolved) {
					t.Fatalf("requirements name %s after the pass, want the resolved image %s", published, tc.resolved)
				}
			})
		}
	}
}
