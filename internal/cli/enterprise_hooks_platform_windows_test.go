//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A configured machine-policy connector stays active with no enrolled SIDs.
// The same state occurs on a fresh install and after the final account is cut
// off; the guardian must publish an empty registry, not remove its hook.
func TestWindowsConfiguredMachinePolicySurvivesEmptyEnrollment(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		t.Run(name, func(t *testing.T) {
			previousCfg := cfg
			previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
			previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
			previousCodexRemover, previousCodexPublisher := enterpriseHookCodexRequirementsRemover, enterpriseHookCodexTargetsPublisher
			previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
			previousClaudeDeactivator, previousCursorDeactivator := enterpriseHookClaudePolicyDeactivator, enterpriseHookCursorPolicyDeactivator
			previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
			t.Cleanup(func() {
				cfg = previousCfg
				enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
				enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
				enterpriseHookCodexRequirementsRemover, enterpriseHookCodexTargetsPublisher = previousCodexRemover, previousCodexPublisher
				enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
				enterpriseHookClaudePolicyDeactivator, enterpriseHookCursorPolicyDeactivator = previousClaudeDeactivator, previousCursorDeactivator
				enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
			})
			cfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
				Guardrail:      config.GuardrailConfig{Connector: name},
			}
			active := true
			enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, name == "claudecode" && active, nil }
			enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
				return nil, name == "cursor" && active, nil
			}
			enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				return connector.WindowsCodexMachineRequirementsOptions{HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return connector.WindowsCodexManagedRuntimeRegistry{Active: name == "codex" && active, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			var removedCodex bool
			var removedOther bool
			enterpriseHookClaudePolicyDeactivator = func() error { removedOther, active = true, false; return nil }
			enterpriseHookCursorPolicyDeactivator = func() error { removedOther, active = true, false; return nil }
			enterpriseHookCodexRequirementsRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
				removedCodex = true
				active = false
				return connector.WindowsCodexMachineRequirementsReport{OK: true, SafeToRemoveBinary: true}, nil
			}
			enterpriseHookClaudePolicyTargetsPublisher = func([]string) error { return nil }
			enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
			enterpriseHookCodexTargetsPublisher = func(connector.WindowsCodexMachineRequirementsOptions, []connector.WindowsCodexManagedRuntimeTarget) error {
				return nil
			}
			enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
			enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }

			manifest := enterprisehooks.Manifest{}
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", false); err != nil {
				t.Fatal(err)
			}
			if removedCodex {
				t.Fatal("empty Codex enrollment removed configured machine requirements")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("configured %s policy with zero targets failed verify: %v", name, err)
			}
			cfg.Guardrail.Connector = "copilot"
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", true); err != nil {
				t.Fatal(err)
			}
			if active || (!removedCodex && !removedOther) {
				t.Fatal("removing the connector from admin config did not remove its machine hook")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("removed %s policy failed verify: %v", name, err)
			}
		})
	}
}

// Upgrading an older standalone install can start with no machine policy at
// all for a configured connector. Reconcile must restore its guard before it
// publishes the still-empty enrollment registry.
func TestWindowsConfiguredMachinePolicyRepairsLegacyEmptyEnrollment(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		t.Run(name, func(t *testing.T) {
			previousCfg := cfg
			previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
			previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
			previousCodexReconciler, previousCodexPublisher := enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher
			previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
			previousClaudeEnsurer, previousCursorEnsurer := enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer
			previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
			t.Cleanup(func() {
				cfg = previousCfg
				enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
				enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
				enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher = previousCodexReconciler, previousCodexPublisher
				enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
				enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer = previousClaudeEnsurer, previousCursorEnsurer
				enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
			})
			cfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
				Guardrail:      config.GuardrailConfig{Connector: name},
			}
			active := false
			ensured := false
			enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, name == "claudecode" && active, nil }
			enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
				return nil, name == "cursor" && active, nil
			}
			enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				return connector.WindowsCodexMachineRequirementsOptions{HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return connector.WindowsCodexManagedRuntimeRegistry{Active: name == "codex" && active, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookClaudePolicyEnsurer = func(connector.SetupOpts) error { active, ensured = true, true; return nil }
			enterpriseHookCursorPolicyEnsurer = func(connector.SetupOpts) error { active, ensured = true, true; return nil }
			enterpriseHookCodexRequirementsReconciler = func(opts connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
				if !opts.CodexTargetEnabled {
					t.Fatal("Codex repair did not enable the configured machine guard")
				}
				active, ensured = true, true
				return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
			}
			enterpriseHookClaudePolicyTargetsPublisher = func([]string) error { return nil }
			enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
			enterpriseHookCodexTargetsPublisher = func(connector.WindowsCodexMachineRequirementsOptions, []connector.WindowsCodexManagedRuntimeTarget) error {
				return nil
			}
			enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
			enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
			manifest := enterprisehooks.Manifest{}
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", true); err != nil {
				t.Fatal(err)
			}
			if !ensured || !active {
				t.Fatal("legacy empty enrollment did not restore the configured machine guard")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("restored empty policy failed verify: %v", err)
			}
		})
	}
}

// The guard x enrollment x repair table for every configured machine-policy
// connector. A guard is absent (nothing installed yet, or an earlier release's
// zero-target state), present, or damaged: its machine-owned record survives
// while an artifact it owns is missing or changed. Repair installs an absent
// guard, rebuilds a damaged one from its record, keeps a present one, and
// never publishes a target set smaller than the record through pre-sync or
// exact publication. Each damaged row names the artifact; the real-artifact
// rebuilds are TestWindowsClaudeMachineGuardArtifactRepairTable,
// TestWindowsCodexMachineGuardArtifactRepairTable and
// TestWindowsCursorMachineGuardRebuildsEveryOwnedArtifact.
func TestWindowsMachineGuardRepairStateTable(t *testing.T) {
	const sid = "S-1-5-21-111-222-333-1001"
	const home = `C:\Users\alice`
	const hookBinary = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	guards := map[string][]string{
		"claudecode": {"absent", "present", "drop-in missing", "drop-in changed"},
		"codex":      {"absent", "present", "requirements missing", "requirements changed", "registry missing"},
		"cursor": {
			"absent", "present", "hooks.json missing", "hooks.json changed",
			"adapter missing", "adapter changed", "hooks.json and adapter missing",
		},
	}
	for _, connectorName := range []string{"claudecode", "codex", "cursor"} {
		for _, guard := range guards[connectorName] {
			for _, enrolled := range []bool{false, true} {
				name := connectorName + "/guard=" + guard + "/enrollment=" + map[bool]string{false: "empty", true: "Alice"}[enrolled]
				t.Run(name, func(t *testing.T) {
					previousCfg := cfg
					previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
					previousClaudeEnsurer, previousClaudeIdentity := enterpriseHookClaudePolicyEnsurer, enterpriseHookClaudePolicyIdentityVerifier
					previousClaudeRestorer := enterpriseHookClaudePolicyRestorer
					previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
					previousCursorEnsurer, previousCursorRestorer := enterpriseHookCursorPolicyEnsurer, enterpriseHookCursorPolicyRestorer
					previousCursorIdentity := enterpriseHookCursorPolicyIdentityVerifier
					previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
					previousCodexReconciler, previousCodexPublisher := enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher
					previousCodexRemover := enterpriseHookCodexRequirementsRemover
					t.Cleanup(func() {
						cfg = previousCfg
						enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
						enterpriseHookClaudePolicyEnsurer, enterpriseHookClaudePolicyIdentityVerifier = previousClaudeEnsurer, previousClaudeIdentity
						enterpriseHookClaudePolicyRestorer = previousClaudeRestorer
						enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
						enterpriseHookCursorPolicyEnsurer, enterpriseHookCursorPolicyRestorer = previousCursorEnsurer, previousCursorRestorer
						enterpriseHookCursorPolicyIdentityVerifier = previousCursorIdentity
						enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
						enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher = previousCodexReconciler, previousCodexPublisher
						enterpriseHookCodexRequirementsRemover = previousCodexRemover
					})
					cfg = &config.Config{
						DeploymentMode: managed.DeploymentModeManagedEnterprise,
						Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
						Guardrail:      config.GuardrailConfig{Connector: connectorName},
					}
					manifest := enterprisehooks.Manifest{}
					if enrolled {
						manifest.Targets = []enterprisehooks.ManifestTarget{{SID: sid, UserHome: home, Connector: connectorName}}
					}
					absent := guard == "absent"
					damaged := !absent && guard != "present"
					wantEnsures, wantRestores, wantReconciles := 0, 0, 0
					switch {
					case connectorName == "codex" && guard != "present":
						wantReconciles = 1
					case absent:
						wantEnsures = 1
					case damaged:
						wantRestores = 1
					}
					active := guard == "present"
					// The machine-owned record keeps Alice through damage. An
					// absent guard has no record; per-target installation
					// enrolls Alice before exact publication.
					recordAlice := enrolled && !absent
					var targets []string
					if recordAlice {
						targets = []string{sid}
					}
					var minimum []string
					if recordAlice && guard != "registry missing" {
						// Losing the Codex registry loses the record itself;
						// exact publication restores Alice from the manifest
						// and she stays refused until then.
						minimum = []string{sid}
					}
					published := 0
					publish := func(next []string) {
						published++
						for _, want := range minimum {
							if !slices.Contains(next, want) {
								t.Fatalf("published %v, dropping the record's %s", next, want)
							}
						}
						targets = append([]string(nil), next...)
					}
					ensures, restores, reconciles := 0, 0, 0
					damageErr := errors.New(guard + "; the machine-owned record remains")

					enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) {
						if connectorName != "claudecode" {
							return nil, false, nil
						}
						if damaged {
							return nil, false, damageErr
						}
						return append([]string(nil), targets...), active, nil
					}
					enterpriseHookClaudePolicyRestorer = func() (bool, error) {
						if connectorName != "claudecode" || !damaged {
							t.Fatal("Claude drop-in restore called without a damaged guard")
						}
						restores++
						damaged, active = false, true
						return true, nil
					}
					enterpriseHookClaudePolicyEnsurer = func(opts connector.SetupOpts) error {
						if connectorName != "claudecode" || opts.ManagedTargetSID != "" {
							t.Fatalf("unexpected Claude ensurer call: %+v", opts)
						}
						if damaged && guard == "drop-in changed" {
							// The install path refuses a drop-in changed
							// outside DefenseClaw.
							return errors.New("Claude Code managed policy was changed outside DefenseClaw")
						}
						// Missing-policy recovery restores the record's
						// enrollment.
						ensures++
						damaged, active = false, true
						return nil
					}
					enterpriseHookClaudePolicyTargetsPublisher = func(next []string) error {
						if connectorName == "claudecode" {
							publish(next)
						}
						return nil
					}

					enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
						return connector.WindowsCodexMachineRequirementsOptions{
							HookBinary:  hookBinary,
							GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway",
						}, nil
					}
					codexTargets := func() []connector.WindowsCodexManagedRuntimeTarget {
						result := []connector.WindowsCodexManagedRuntimeTarget{}
						for _, target := range targets {
							result = append(result, connector.WindowsCodexManagedRuntimeTarget{SID: target, DataDir: filepath.Join(home, ".defenseclaw")})
						}
						return result
					}
					enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
						if connectorName != "codex" {
							return connector.WindowsCodexManagedRuntimeRegistry{}, nil
						}
						if damaged {
							return connector.WindowsCodexManagedRuntimeRegistry{}, damageErr
						}
						return connector.WindowsCodexManagedRuntimeRegistry{
							Active: active, Targets: codexTargets(),
							GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway",
						}, nil
					}
					enterpriseHookCodexRequirementsReconciler = func(opts connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
						if connectorName != "codex" || !opts.CodexTargetEnabled {
							t.Fatalf("unexpected Codex reconcile: %+v", opts)
						}
						reconciles++
						if guard == "registry missing" {
							targets = nil
						}
						damaged, active = false, true
						return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
					}
					enterpriseHookCodexTargetsPublisher = func(_ connector.WindowsCodexMachineRequirementsOptions, next []connector.WindowsCodexManagedRuntimeTarget) error {
						if connectorName == "codex" {
							sids := []string{}
							for _, target := range next {
								sids = append(sids, target.SID)
							}
							publish(sids)
						}
						return nil
					}
					enterpriseHookCodexRequirementsRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
						t.Fatal("repair removed a configured Codex guard")
						return connector.WindowsCodexMachineRequirementsReport{}, nil
					}

					cursorTargets := func() []enterprisehooks.WindowsCursorManagedRuntimeTarget {
						result := []enterprisehooks.WindowsCursorManagedRuntimeTarget{}
						for _, target := range targets {
							result = append(result, enterprisehooks.WindowsCursorManagedRuntimeTarget{SID: target, DataDir: filepath.Join(home, ".defenseclaw")})
						}
						return result
					}
					enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
						if connectorName != "cursor" {
							return nil, false, nil
						}
						if damaged {
							return nil, true, damageErr
						}
						return cursorTargets(), active, nil
					}
					enterpriseHookCursorPolicyRestorer = func(binary string) (bool, error) {
						if connectorName != "cursor" || !damaged || binary != hookBinary {
							t.Fatal("Cursor rebuild called without a damaged guard")
						}
						restores++
						damaged, active = false, true
						return true, nil
					}
					enterpriseHookCursorPolicyEnsurer = func(opts connector.SetupOpts) error {
						if connectorName != "cursor" || opts.ManagedTargetSID != "" || damaged {
							t.Fatalf("unexpected Cursor ensurer call: %+v", opts)
						}
						ensures++
						active = true
						return nil
					}
					enterpriseHookCursorPolicyTargetsPublisher = func(next []enterprisehooks.WindowsCursorManagedRuntimeTarget) error {
						if connectorName == "cursor" {
							sids := []string{}
							for _, target := range next {
								sids = append(sids, target.SID)
							}
							publish(sids)
						}
						return nil
					}
					enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
					enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }

					for _, exact := range []bool{false, true} {
						if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", exact); err != nil {
							t.Fatalf("repair (exact=%t): %v", exact, err)
						}
						if exact && enrolled && !slices.Contains(targets, sid) {
							t.Fatalf("exact publication left %v, want Alice enrolled", targets)
						}
						// Until exact publication an account the record lacks
						// stays refused, and verify reports the difference.
						if !exact && enrolled && len(minimum) == 0 {
							continue
						}
						if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
							t.Fatalf("verify repaired guard (exact=%t): %v", exact, err)
						}
					}
					if !active || ensures != wantEnsures || restores != wantRestores || reconciles != wantReconciles || published != 2 {
						t.Fatalf("repair action: active=%t ensures=%d restores=%d reconciles=%d publications=%d; want ensures=%d restores=%d reconciles=%d publications=2",
							active, ensures, restores, reconciles, published, wantEnsures, wantRestores, wantReconciles)
					}
				})
			}
		}
	}
}

func TestWindowsCursorGuardRepairRefusesUnverifiedPublication(t *testing.T) {
	for _, test := range []struct {
		name             string
		initialReadError bool
		ensuredReadError bool
	}{
		{name: "ensure returned without an active guard"},
		{name: "ensured guard could not be read", ensuredReadError: true},
		{name: "damaged adapter could not be authenticated", initialReadError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			previousCfg := cfg
			previousClaudeReader := enterpriseHookClaudePolicyTargetsReader
			previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
			previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
			previousCursorEnsurer, previousCursorRestorer := enterpriseHookCursorPolicyEnsurer, enterpriseHookCursorPolicyRestorer
			t.Cleanup(func() {
				cfg = previousCfg
				enterpriseHookClaudePolicyTargetsReader = previousClaudeReader
				enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
				enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
				enterpriseHookCursorPolicyEnsurer, enterpriseHookCursorPolicyRestorer = previousCursorEnsurer, previousCursorRestorer
			})
			cfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
				Guardrail:      config.GuardrailConfig{Connector: "cursor"},
			}
			enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, false, nil }
			enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				return connector.WindowsCodexMachineRequirementsOptions{
					HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
				}, nil
			}
			enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return connector.WindowsCodexManagedRuntimeRegistry{}, nil
			}
			reads := 0
			enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
				reads++
				if test.initialReadError || (test.ensuredReadError && reads > 1) {
					return nil, false, errors.New("Cursor ownership could not be authenticated")
				}
				return nil, false, nil
			}
			enterpriseHookCursorPolicyRestorer = func(string) (bool, error) {
				return false, errors.New("Cursor adapter recovery refused untrusted state")
			}
			enterpriseHookCursorPolicyEnsurer = func(connector.SetupOpts) error { return nil }
			published := false
			enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error {
				published = true
				return nil
			}
			if err := syncEnterpriseHookManagedMachineEnrollments(enterprisehooks.Manifest{}, "127.0.0.1:32109", false); err == nil {
				t.Fatal("repair accepted a missing or untrusted Cursor guard")
			}
			if published {
				t.Fatal("repair published enrollment without an authenticated Cursor guard")
			}
		})
	}
}

func TestWindowsClaudeDeletedPolicyReconcileRetainsEnrolledTargets(t *testing.T) {
	const aliceSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	previousCfg := cfg
	previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
	previousClaudeEnsurer := enterpriseHookClaudePolicyEnsurer
	previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
	previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
		enterpriseHookClaudePolicyEnsurer = previousClaudeEnsurer
		enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
		enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
	})
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Connector: "claudecode"},
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		SID: aliceSID, UserHome: `C:\Users\alice`, Connector: "claudecode",
	}}}
	policyPresent := false
	ensures := 0
	published := 0
	enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) {
		if !policyPresent {
			return nil, false, errors.New("ownership metadata is incomplete")
		}
		return []string{aliceSID}, true, nil
	}
	enterpriseHookClaudePolicyEnsurer = func(opts connector.SetupOpts) error {
		if opts.ManagedTargetSID != "" {
			t.Fatalf("machine-policy repair enrolled a new SID: %s", opts.ManagedTargetSID)
		}
		ensures++
		policyPresent = true
		return nil
	}
	// The drift restore finds no rendering of the record; the ensure's
	// missing-policy recovery restores the guard instead.
	previousClaudeRestorer := enterpriseHookClaudePolicyRestorer
	t.Cleanup(func() { enterpriseHookClaudePolicyRestorer = previousClaudeRestorer })
	enterpriseHookClaudePolicyRestorer = func() (bool, error) { return false, nil }
	enterpriseHookClaudePolicyTargetsPublisher = func(targets []string) error {
		published++
		if len(targets) != 1 || targets[0] != aliceSID {
			t.Fatalf("reconcile published %v, want Alice retained", targets)
		}
		return nil
	}
	enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		return connector.WindowsCodexMachineRequirementsOptions{
			HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		}, nil
	}
	enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
		return connector.WindowsCodexManagedRuntimeRegistry{}, nil
	}
	enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
		return nil, false, nil
	}
	enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
	for _, publishExact := range []bool{false, true} {
		if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", publishExact); err != nil {
			t.Fatalf("reconcile publication (exact=%t): %v", publishExact, err)
		}
	}
	if ensures != 1 || published != 2 {
		t.Fatalf("reconcile ensured policy %d times and published targets %d times", ensures, published)
	}
}

func TestDeferredTargetSessionAvailabilityDowngradesOnlyTypedAbsence(t *testing.T) {
	previous := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previous
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:      "S-1-5-21-1-2-3-1001",
		UserHome: `C:\Users\alice`,
	}
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return nil
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	available, err := enterpriseHookDeferredTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("typed absence = available %t err %v, want false/nil", available, err)
	}

	sentinel := errors.New("WTS token query denied")
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return sentinel
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, sentinel) {
		t.Fatalf("ordinary WTS failure = available %t err %v, want hard error", available, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	selectorErr := errors.New("selected runtime lacks protected authorization")
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return selectorErr
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, selectorErr) {
		t.Fatalf("stale runtime = available %t err %v, want hard error", available, err)
	}

	available, err = enterpriseHookTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("protected-runtime session absence = available %t err %v, want false/nil", available, err)
	}
}

func TestDeferredPendingRaceRechecksSessionAndSelectorState(t *testing.T) {
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:       "S-1-5-21-1-2-3-1001",
		UserHome:  `C:\Users\alice`,
		Connector: "codex",
		Deferred:  true,
	}
	original := &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return original }
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error { return nil }

	pending, err := enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if err != nil || !pending {
		t.Fatalf("stable absence = pending %t err %v, want true/nil", pending, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return nil }
	pending, err = enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if pending || !errors.Is(err, original) {
		t.Fatalf("session reappeared = pending %t err %v, want original hard error", pending, err)
	}
}

func TestExpandEnterpriseHookProfileImagePathUsesTrustedSystemDrive(t *testing.T) {
	previous := enterpriseHookWindowsSystemDirectory
	t.Cleanup(func() { enterpriseHookWindowsSystemDirectory = previous })
	enterpriseHookWindowsSystemDirectory = func() (string, error) {
		return `D:\Windows\System32`, nil
	}
	t.Setenv("SystemDrive", `Z:`)

	got, err := expandEnterpriseHookProfileImagePath(`%SystemDrive%\Users\managed`)
	if err != nil {
		t.Fatalf("expand ProfileImagePath: %v", err)
	}
	want := filepath.Clean(`D:\Users\managed`)
	if filepath.Clean(got) != want {
		t.Fatalf("expanded ProfileImagePath = %q, want %q", got, want)
	}
}

func TestExpandEnterpriseHookProfileImagePathRejectsOtherVariables(t *testing.T) {
	if _, err := expandEnterpriseHookProfileImagePath(`%USERPROFILE%\managed`); err == nil {
		t.Fatal("ProfileImagePath with user-controlled expansion was accepted")
	}
}

func TestWindowsEnterpriseDesiredEnrollmentsResolvesLocalUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		User:      current.Username,
		Connector: "codex",
	}}}

	_, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve desired enrollments: %v", err)
	}
	if len(codex) != 1 {
		t.Fatalf("Codex enrollment count = %d, want 1", len(codex))
	}
	if !strings.EqualFold(codex[0].SID, current.Uid) {
		t.Fatalf("Codex enrollment SID = %q, want %q", codex[0].SID, current.Uid)
	}
	wantDataDir := filepath.Join(filepath.Clean(current.HomeDir), ".defenseclaw")
	if !sameWindowsEnterprisePathCLI(codex[0].DataDir, wantDataDir) {
		t.Fatalf("Codex enrollment data dir = %q, want %q", codex[0].DataDir, wantDataDir)
	}
}

func TestWindowsEnterpriseDesiredEnrollmentsAcceptEntraIDForAllConnectors(t *testing.T) {
	const entraSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	home := filepath.Clean(`C:\Users\entra-user`)
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
		{SID: entraSID, UserHome: home, Connector: "claudecode"},
		{SID: entraSID, UserHome: home, Connector: "codex"},
		{SID: entraSID, UserHome: home, Connector: "cursor"},
	}}

	claude, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve Claude Code and Codex enrollments: %v", err)
	}
	if len(claude) != 1 || claude[0] != entraSID {
		t.Fatalf("Claude Code enrollments = %v, want %s", claude, entraSID)
	}
	if len(codex) != 1 || codex[0].SID != entraSID ||
		!sameWindowsEnterprisePathCLI(codex[0].DataDir, filepath.Join(home, ".defenseclaw")) {
		t.Fatalf("Codex enrollments = %+v, want Microsoft Entra ID target", codex)
	}
	cursor, err := windowsEnterpriseDesiredCursorEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve Cursor enrollments: %v", err)
	}
	if len(cursor) != 1 || cursor[0].SID != entraSID ||
		!sameWindowsEnterprisePathCLI(cursor[0].DataDir, filepath.Join(home, ".defenseclaw")) {
		t.Fatalf("Cursor enrollments = %+v, want Microsoft Entra ID target", cursor)
	}
}

func TestManagedEnrollmentIdentityRejectsStaleDeploymentWithSameSID(t *testing.T) {
	previousClaude := enterpriseHookClaudePolicyIdentityVerifier
	previousCursor := enterpriseHookCursorPolicyIdentityVerifier
	t.Cleanup(func() {
		enterpriseHookClaudePolicyIdentityVerifier = previousClaude
		enterpriseHookCursorPolicyIdentityVerifier = previousCursor
	})
	opts := connector.WindowsCodexMachineRequirementsOptions{
		HookBinary:         `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:32109",
		GatewayServiceName: "DefenseClawGateway",
	}
	current := connector.WindowsCodexManagedRuntimeRegistry{
		Active:             true,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		Targets: []connector.WindowsCodexManagedRuntimeTarget{{
			SID:     "S-1-5-21-1-2-3-1001",
			DataDir: `C:\Users\alice\.defenseclaw`,
		}},
	}
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err != nil {
		t.Fatalf("exact identity: %v", err)
	}

	staleClaude := errors.New("stale Claude gateway identity")
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return staleClaude }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleClaude) {
		t.Fatalf("stale Claude identity error = %v, want %v", err, staleClaude)
	}

	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	staleCursor := errors.New("stale Cursor gateway identity")
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return staleCursor }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleCursor) {
		t.Fatalf("stale Cursor identity error = %v, want %v", err, staleCursor)
	}

	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	current.GatewayServiceName = "DefenseClawGateway_Old"
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err == nil {
		t.Fatal("stale Codex gateway identity was accepted because the SID set matched")
	}
}

// GAP-0929 review: a guardian notice of a row that carries only the SID
// names the account as "user (SID)", like the other Windows notices, not by
// the SID alone.
func TestWindowsGuardianNoticeNamesTheAccountOfASIDOnlyRow(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	got := enterpriseHookNoticeAccount(enterpriseHookReconcileRow{SID: current.Uid})
	name := current.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	if !strings.HasSuffix(got, " ("+current.Uid+")") || !strings.Contains(strings.ToLower(got), strings.ToLower(name)) {
		t.Fatalf("notice account = %q, want the name of %s (%s)", got, current.Username, current.Uid)
	}
	if got := enterpriseHookNoticeAccount(enterpriseHookReconcileRow{User: "dcw-std1", SID: current.Uid}); got != "dcw-std1 ("+current.Uid+")" {
		t.Fatalf("named row = %q", got)
	}
}
