//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestWindowsEnterprisePowerShellArgsLifecycleParity(t *testing.T) {
	opts := &windowsEnterpriseLifecycleOptions{
		gatewayBinary:                  `C:\stage\defenseclaw-gateway.exe`,
		hookBinary:                     `C:\stage\defenseclaw-hook.exe`,
		cliBinary:                      `C:\stage\defenseclaw.exe`,
		configPath:                     `C:\stage\config.yaml`,
		manifestPath:                   `C:\stage\targets.yaml`,
		installRoot:                    `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`,
		stateRoot:                      `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`,
		gatewayServiceName:             "DefenseClawGateway",
		guardianServiceName:            "DefenseClawHookGuardian",
		certificationCodexHome:         `C:\certification\codex-home`,
		codexTrustedHookLauncherBinary: `C:\stage\codex-fixed.exe`,
		attestAgentApplicationControl:  true,
		attestClaudeEffectivePolicy:    true,
		attestCodexTrustedHookLauncher: true,
		noStart:                        true,
		allowUnsigned:                  true,
		jsonOutput:                     true,
	}
	got := windowsEnterprisePowerShellArgs("upgrade", opts)
	want := []string{
		"-Action", "Upgrade",
		"-GatewayBinary", opts.gatewayBinary,
		"-HookBinary", opts.hookBinary,
		"-CLIBinary", opts.cliBinary,
		"-Config", opts.configPath,
		"-Manifest", opts.manifestPath,
		"-InstallRoot", opts.installRoot,
		"-StateRoot", opts.stateRoot,
		"-GatewayServiceName", opts.gatewayServiceName,
		"-GuardianServiceName", opts.guardianServiceName,
		"-CertificationCodexHome", opts.certificationCodexHome,
		"-AttestAgentApplicationControl",
		"-AttestClaudeEffectivePolicy",
		"-AttestCodexTrustedHookLauncher",
		"-CodexTrustedHookLauncherBinary", opts.codexTrustedHookLauncherBinary,
		"-NoStart",
		"-AllowUnsigned",
		"-Json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("windowsEnterprisePowerShellArgs = %#v, want %#v", got, want)
	}
}

func TestWindowsEnterpriseLifecycleSecurityOptionsAreActionScoped(t *testing.T) {
	for _, action := range []string{"reconcile", "status", "verify", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			opts := &windowsEnterpriseLifecycleOptions{attestAgentApplicationControl: true}
			if err := validateWindowsEnterpriseLifecycleSecurityOptions(nil, action, opts); err == nil ||
				!strings.Contains(err.Error(), "only with install, upgrade, or repair") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
	for _, action := range []string{"install", "upgrade", "repair"} {
		t.Run(action, func(t *testing.T) {
			opts := &windowsEnterpriseLifecycleOptions{
				attestAgentApplicationControl:  true,
				attestClaudeEffectivePolicy:    true,
				attestCodexTrustedHookLauncher: true,
				codexTrustedHookLauncherBinary: `C:\approved\codex-fixed.exe`,
			}
			if err := validateWindowsEnterpriseLifecycleSecurityOptions(nil, action, opts); err != nil {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestWindowsEnterpriseLifecycleCodexLauncherAttestationIsPaired(t *testing.T) {
	tests := []windowsEnterpriseLifecycleOptions{
		{attestCodexTrustedHookLauncher: true},
		{codexTrustedHookLauncherBinary: `C:\approved\codex-fixed.exe`},
	}
	for _, opts := range tests {
		if err := validateWindowsEnterpriseLifecycleSecurityOptions(nil, "repair", &opts); err == nil ||
			!strings.Contains(err.Error(), "must be supplied together") {
			t.Fatalf("validation error = %v", err)
		}
	}
}

func TestWindowsEnterpriseLifecycleCertificationModeMatrix(t *testing.T) {
	const certificationHome = `C:\Users\cert\.codex-defenseclaw-cert-0123456789`
	tests := []struct {
		name        string
		action      string
		opts        windowsEnterpriseLifecycleOptions
		wantErr     bool
		errContains string
	}{
		{
			name:   "signed production",
			action: "install",
			opts: windowsEnterpriseLifecycleOptions{
				attestAgentApplicationControl:  true,
				attestCodexTrustedHookLauncher: true,
				codexTrustedHookLauncherBinary: `C:\approved\codex-fixed.exe`,
			},
		},
		{
			name:   "full unsigned certification",
			action: "install",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:                  true,
				certificationCodexHome:         certificationHome,
				attestAgentApplicationControl:  true,
				attestCodexTrustedHookLauncher: true,
				codexTrustedHookLauncherBinary: `C:\approved\codex-fixed.exe`,
			},
		},
		{
			name:   "core unsigned certification",
			action: "repair",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:              true,
				certificationCodexHome:     certificationHome,
				coreHardeningCertification: true,
			},
		},
		{
			name:   "unsigned preinstall status",
			action: "status",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:          true,
				certificationCodexHome: certificationHome,
			},
		},
		{
			name:   "unsigned verify",
			action: "verify",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:          true,
				certificationCodexHome: certificationHome,
			},
		},
		{
			name:   "unsigned reconcile",
			action: "reconcile",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:          true,
				certificationCodexHome: certificationHome,
			},
		},
		{
			name:   "unsigned uninstall",
			action: "uninstall",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:          true,
				certificationCodexHome: certificationHome,
			},
		},
		{
			name:        "unsigned lacks scope home",
			action:      "install",
			opts:        windowsEnterpriseLifecycleOptions{allowUnsigned: true},
			wantErr:     true,
			errContains: "requires --certification-codex-home",
		},
		{
			name:        "scope home without unsigned",
			action:      "install",
			opts:        windowsEnterpriseLifecycleOptions{certificationCodexHome: certificationHome},
			wantErr:     true,
			errContains: "valid only with --allow-unsigned",
		},
		{
			name:   "core lacks explicit unsigned",
			action: "repair",
			opts: windowsEnterpriseLifecycleOptions{
				certificationCodexHome:     certificationHome,
				coreHardeningCertification: true,
			},
			wantErr:     true,
			errContains: "valid only with --allow-unsigned",
		},
		{
			name:   "core rejects production attestation",
			action: "repair",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:                 true,
				certificationCodexHome:        certificationHome,
				coreHardeningCertification:    true,
				attestAgentApplicationControl: true,
			},
			wantErr:     true,
			errContains: "cannot be combined",
		},
		{
			name:   "core flag is mutation scoped",
			action: "status",
			opts: windowsEnterpriseLifecycleOptions{
				allowUnsigned:              true,
				certificationCodexHome:     certificationHome,
				coreHardeningCertification: true,
			},
			wantErr:     true,
			errContains: "only with install, upgrade, or repair",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWindowsEnterpriseLifecycleSecurityOptions(
				nil,
				test.action,
				&test.opts,
			)
			if !test.wantErr {
				if err != nil {
					t.Fatalf("validation error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.errContains) {
				t.Fatalf("validation error = %v, want substring %q", err, test.errContains)
			}
		})
	}
}

func TestWindowsEnterprisePowerShellArgsCoreCertificationIsExplicit(t *testing.T) {
	opts := &windowsEnterpriseLifecycleOptions{
		allowUnsigned:              true,
		certificationCodexHome:     `C:\Users\cert\.codex-defenseclaw-cert-0123456789`,
		coreHardeningCertification: true,
	}
	got := windowsEnterprisePowerShellArgs("repair", opts)
	want := []string{
		"-Action", "Repair",
		"-CertificationCodexHome", opts.certificationCodexHome,
		"-CoreHardeningCertification",
		"-AllowUnsigned",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("core certification args = %#v, want %#v", got, want)
	}
}

func TestWindowsEnterprisePowerShellArgsUnsignedReadOnlyScopeIsExplicit(t *testing.T) {
	opts := &windowsEnterpriseLifecycleOptions{
		allowUnsigned:          true,
		certificationCodexHome: `C:\Users\cert\.codex-defenseclaw-cert-0123456789`,
	}
	got := windowsEnterprisePowerShellArgs("status", opts)
	want := []string{
		"-Action", "Status",
		"-CertificationCodexHome", opts.certificationCodexHome,
		"-AllowUnsigned",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unsigned status args = %#v, want %#v", got, want)
	}
}

func TestWindowsEnterprisePowerShellArgsPurgeIsExplicit(t *testing.T) {
	got := windowsEnterprisePowerShellArgs("uninstall", &windowsEnterpriseLifecycleOptions{purge: true})
	if !reflect.DeepEqual(got, []string{"-Action", "Uninstall", "-Purge"}) {
		t.Fatalf("uninstall args = %#v", got)
	}
	got = windowsEnterprisePowerShellArgs("status", &windowsEnterpriseLifecycleOptions{})
	if !reflect.DeepEqual(got, []string{"-Action", "Status"}) {
		t.Fatalf("status args = %#v", got)
	}
}

func TestWindowsEnterpriseSelfUninstallCallerRequiresExactInstalledLayout(t *testing.T) {
	const processID = 4242
	installer := `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\libexec\install-enterprise.ps1`
	executable := `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw.exe`
	got, ok := windowsEnterpriseSelfUninstallCaller(
		"uninstall",
		installer,
		executable,
		processID,
	)
	if !ok || got != processID {
		t.Fatalf("exact installed self caller = (%d, %t), want (%d, true)", got, ok, processID)
	}

	tests := []struct {
		name       string
		action     string
		installer  string
		executable string
		processID  int
	}{
		{
			name:       "non-uninstall action",
			action:     "repair",
			installer:  installer,
			executable: executable,
			processID:  processID,
		},
		{
			name:       "external source CLI",
			action:     "uninstall",
			installer:  installer,
			executable: `C:\stage\defenseclaw.exe`,
			processID:  processID,
		},
		{
			name:       "near-prefix install root",
			action:     "uninstall",
			installer:  installer,
			executable: `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw2\bin\defenseclaw.exe`,
			processID:  processID,
		},
		{
			name:       "wrong installer directory",
			action:     "uninstall",
			installer:  `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\libexec2\install-enterprise.ps1`,
			executable: executable,
			processID:  processID,
		},
		{
			name:       "wrong installer name",
			action:     "uninstall",
			installer:  `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\libexec\other.ps1`,
			executable: executable,
			processID:  processID,
		},
		{
			name:       "zero process ID",
			action:     "uninstall",
			installer:  installer,
			executable: executable,
			processID:  0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, ok := windowsEnterpriseSelfUninstallCaller(
				test.action,
				test.installer,
				test.executable,
				test.processID,
			); ok || got != 0 {
				t.Fatalf("self caller = (%d, %t), want (0, false)", got, ok)
			}
		})
	}
}

func TestWindowsEnterpriseSelfUpgradeRequiresExternalReleaseCLI(t *testing.T) {
	root := t.TempDir()
	explicitInstallRoot := filepath.Join(root, "explicit-install")
	defaultProgramFiles := filepath.Join(root, "default-program-files")
	defaultInstallRoot := filepath.Join(defaultProgramFiles, "Cisco", "DefenseClaw")
	explicitInstalledCLI := filepath.Join(
		explicitInstallRoot,
		"bin",
		"defenseclaw.exe",
	)
	defaultInstalledCLI := filepath.Join(
		defaultInstallRoot,
		"bin",
		"defenseclaw.exe",
	)
	replacement := filepath.Join(root, "release", "defenseclaw.exe")
	aliasCLI := filepath.Join(root, "stage", "defenseclaw.exe")
	for _, directory := range []string{
		filepath.Dir(explicitInstalledCLI),
		filepath.Dir(defaultInstalledCLI),
		filepath.Dir(replacement),
		filepath.Dir(aliasCLI),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", directory, err)
		}
	}
	for _, path := range []string{
		explicitInstalledCLI,
		defaultInstalledCLI,
		replacement,
	} {
		if err := os.WriteFile(path, []byte("MZ fixture"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	if err := os.Link(explicitInstalledCLI, aliasCLI); err != nil {
		t.Fatalf("create installed CLI hard-link alias: %v", err)
	}

	originalProgramFilesResolver := windowsEnterpriseProgramFilesResolver
	windowsEnterpriseProgramFilesResolver = func() (string, error) {
		return defaultProgramFiles, nil
	}
	t.Cleanup(func() {
		windowsEnterpriseProgramFilesResolver = originalProgramFilesResolver
	})

	tests := []struct {
		name        string
		action      string
		installRoot string
		executable  string
		cliBinary   string
		conflict    bool
	}{
		{
			name:        "explicit installed root exact path",
			action:      "upgrade",
			installRoot: explicitInstallRoot,
			executable:  explicitInstalledCLI,
			cliBinary:   replacement,
			conflict:    true,
		},
		{
			name:       "default installed root exact path",
			action:     "upgrade",
			executable: defaultInstalledCLI,
			cliBinary:  replacement,
			conflict:   true,
		},
		{
			name:        "explicit installed root file identity alias",
			action:      "upgrade",
			installRoot: explicitInstallRoot,
			executable:  aliasCLI,
			cliBinary:   replacement,
			conflict:    true,
		},
		{
			name:        "external release CLI explicit root",
			action:      "upgrade",
			installRoot: explicitInstallRoot,
			executable:  replacement,
			cliBinary:   replacement,
		},
		{
			name:       "external release CLI default root",
			action:     "upgrade",
			executable: replacement,
			cliBinary:  replacement,
		},
		{
			name:        "gateway and hook only",
			action:      "upgrade",
			installRoot: explicitInstallRoot,
			executable:  explicitInstalledCLI,
		},
		{
			name:        "repair may reassert identical CLI",
			action:      "repair",
			installRoot: explicitInstallRoot,
			executable:  explicitInstalledCLI,
			cliBinary:   explicitInstalledCLI,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conflict, err := windowsEnterpriseSelfUpgradeConflict(
				test.action,
				test.installRoot,
				test.executable,
				test.cliBinary,
			)
			if err != nil {
				t.Fatalf("windowsEnterpriseSelfUpgradeConflict: %v", err)
			}
			if conflict != test.conflict {
				t.Fatalf("conflict = %t, want %t", conflict, test.conflict)
			}
		})
	}
}

func TestWindowsEnterpriseSelfUpgradeResolutionErrorsFailClosed(t *testing.T) {
	originalProgramFilesResolver := windowsEnterpriseProgramFilesResolver
	t.Cleanup(func() {
		windowsEnterpriseProgramFilesResolver = originalProgramFilesResolver
	})

	if conflict, err := windowsEnterpriseSelfUpgradeConflict(
		"upgrade",
		`..\..\Program Files\Cisco\Cisco Secure Client\DefenseClaw`,
		`C:\stage\defenseclaw.exe`,
		`C:\release\defenseclaw.exe`,
	); err == nil || conflict ||
		!strings.Contains(err.Error(), "install root must be an absolute path") {
		t.Fatalf("relative explicit root = (%t, %v), want fail-closed error", conflict, err)
	}

	windowsEnterpriseProgramFilesResolver = func() (string, error) {
		return `..\Program Files`, nil
	}
	if conflict, err := windowsEnterpriseSelfUpgradeConflict(
		"upgrade",
		"",
		`C:\stage\defenseclaw.exe`,
		`C:\release\defenseclaw.exe`,
	); err == nil || conflict ||
		!strings.Contains(err.Error(), "not an absolute path") {
		t.Fatalf("relative default root = (%t, %v), want fail-closed error", conflict, err)
	}

	windowsEnterpriseProgramFilesResolver = func() (string, error) {
		return "", errors.New("known-folder unavailable")
	}
	if conflict, err := windowsEnterpriseSelfUpgradeConflict(
		"upgrade",
		"",
		`C:\stage\defenseclaw.exe`,
		`C:\release\defenseclaw.exe`,
	); err == nil || conflict ||
		!strings.Contains(err.Error(), "trusted default Windows Program Files") {
		t.Fatalf("default-root resolution = (%t, %v), want fail-closed error", conflict, err)
	}

	if conflict, err := windowsEnterpriseSelfUpgradeConflict(
		"upgrade",
		t.TempDir(),
		"",
		`C:\release\defenseclaw.exe`,
	); err == nil || conflict ||
		!strings.Contains(err.Error(), "executable path is empty") {
		t.Fatalf("executable resolution = (%t, %v), want fail-closed error", conflict, err)
	}
}

func TestRunWindowsEnterpriseLifecycleSelfUpgradeConflictStopsBeforeRunnerAndEmitsJSON(
	t *testing.T,
) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	originalExecutableResolver := windowsEnterpriseExecutableResolver
	originalProgramFilesResolver := windowsEnterpriseProgramFilesResolver
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
		windowsEnterpriseExecutableResolver = originalExecutableResolver
		windowsEnterpriseProgramFilesResolver = originalProgramFilesResolver
	})

	root := t.TempDir()
	explicitInstallRoot := filepath.Join(root, "explicit-install")
	defaultProgramFiles := filepath.Join(root, "default-program-files")
	defaultInstallRoot := filepath.Join(defaultProgramFiles, "Cisco", "DefenseClaw")
	externalInstaller := filepath.Join(root, "release", "install-enterprise.ps1")
	replacement := filepath.Join(root, "release", "defenseclaw.exe")
	windowsEnterpriseScriptFinder = func(string) (string, error) {
		return externalInstaller, nil
	}
	windowsEnterpriseProgramFilesResolver = func() (string, error) {
		return defaultProgramFiles, nil
	}

	for _, test := range []struct {
		name        string
		installRoot string
		executable  string
	}{
		{
			name:        "external installer explicit installed root",
			installRoot: explicitInstallRoot,
			executable: filepath.Join(
				explicitInstallRoot,
				"bin",
				"defenseclaw.exe",
			),
		},
		{
			name: "external installer default installed root",
			executable: filepath.Join(
				defaultInstallRoot,
				"bin",
				"defenseclaw.exe",
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runnerCalled := false
			windowsEnterpriseCommandRunner = func(
				context.Context,
				*cobra.Command,
				string,
				[]string,
			) error {
				runnerCalled = true
				return nil
			}
			windowsEnterpriseExecutableResolver = func() (string, error) {
				return test.executable, nil
			}
			var output strings.Builder
			cmd := &cobra.Command{}
			cmd.SetOut(&output)
			err := runWindowsEnterpriseLifecycle(
				context.Background(),
				cmd,
				"upgrade",
				&windowsEnterpriseLifecycleOptions{
					installRoot: test.installRoot,
					cliBinary:   replacement,
					jsonOutput:  true,
				},
			)
			if err == nil ||
				!strings.Contains(err.Error(), "cannot replace its own running image") {
				t.Fatalf("runWindowsEnterpriseLifecycle error = %v", err)
			}
			if runnerCalled {
				t.Fatal("PowerShell runner was called after self-upgrade conflict")
			}
			assertWindowsEnterprisePreflightFailureJSON(
				t,
				output.String(),
				"upgrade",
				"cannot replace its own running image",
			)
		})
	}
}

func TestRunWindowsEnterpriseLifecycleResolutionErrorsFailClosedJSON(t *testing.T) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	originalExecutableResolver := windowsEnterpriseExecutableResolver
	originalProgramFilesResolver := windowsEnterpriseProgramFilesResolver
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
		windowsEnterpriseExecutableResolver = originalExecutableResolver
		windowsEnterpriseProgramFilesResolver = originalProgramFilesResolver
	})

	windowsEnterpriseScriptFinder = func(string) (string, error) {
		return `C:\external\install-enterprise.ps1`, nil
	}
	for _, test := range []struct {
		name          string
		action        string
		installRoot   string
		executable    func() (string, error)
		programFiles  func() (string, error)
		errorContains string
	}{
		{
			name:        "relative explicit install root",
			installRoot: `..\..\Program Files\Cisco\Cisco Secure Client\DefenseClaw`,
			executable: func() (string, error) {
				return `C:\release\defenseclaw.exe`, nil
			},
			programFiles: func() (string, error) {
				return `C:\Program Files`, nil
			},
			errorContains: "install root must be an absolute path",
		},
		{
			name: "running executable resolution",
			executable: func() (string, error) {
				return "", errors.New("executable unavailable")
			},
			programFiles: func() (string, error) {
				return `C:\Program Files`, nil
			},
			errorContains: "resolve the running Windows enterprise CLI executable",
		},
		{
			name:   "uninstall executable resolution",
			action: "uninstall",
			executable: func() (string, error) {
				return "", errors.New("executable unavailable")
			},
			programFiles: func() (string, error) {
				return `C:\Program Files`, nil
			},
			errorContains: "resolve the running Windows enterprise CLI executable",
		},
		{
			name: "default root resolution",
			executable: func() (string, error) {
				return `C:\release\defenseclaw.exe`, nil
			},
			programFiles: func() (string, error) {
				return "", errors.New("known-folder unavailable")
			},
			errorContains: "trusted default Windows Program Files",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			action := test.action
			if action == "" {
				action = "upgrade"
			}
			cliBinary := `C:\release\defenseclaw.exe`
			if action == "uninstall" {
				cliBinary = ""
			}
			runnerCalled := false
			windowsEnterpriseCommandRunner = func(
				context.Context,
				*cobra.Command,
				string,
				[]string,
			) error {
				runnerCalled = true
				return nil
			}
			windowsEnterpriseExecutableResolver = test.executable
			windowsEnterpriseProgramFilesResolver = test.programFiles
			var output strings.Builder
			cmd := &cobra.Command{}
			cmd.SetOut(&output)
			err := runWindowsEnterpriseLifecycle(
				context.Background(),
				cmd,
				action,
				&windowsEnterpriseLifecycleOptions{
					installRoot: test.installRoot,
					cliBinary:   cliBinary,
					jsonOutput:  true,
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.errorContains) {
				t.Fatalf("runWindowsEnterpriseLifecycle error = %v", err)
			}
			if runnerCalled {
				t.Fatal("PowerShell runner was called after resolution failure")
			}
			assertWindowsEnterprisePreflightFailureJSON(
				t,
				output.String(),
				action,
				test.errorContains,
			)
		})
	}
}

func TestRunWindowsEnterpriseLifecyclePreflightAndRunnerJSONBoundaries(t *testing.T) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	originalExecutableResolver := windowsEnterpriseExecutableResolver
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
		windowsEnterpriseExecutableResolver = originalExecutableResolver
	})

	t.Run("option validation emits one document", func(t *testing.T) {
		runnerCalled := false
		windowsEnterpriseCommandRunner = func(
			context.Context,
			*cobra.Command,
			string,
			[]string,
		) error {
			runnerCalled = true
			return nil
		}
		var output strings.Builder
		cmd := &cobra.Command{}
		cmd.SetOut(&output)
		err := runWindowsEnterpriseLifecycle(
			context.Background(),
			cmd,
			"status",
			&windowsEnterpriseLifecycleOptions{
				purge:      true,
				jsonOutput: true,
			},
		)
		if err == nil {
			t.Fatal("invalid purge preflight returned nil")
		}
		if runnerCalled {
			t.Fatal("PowerShell runner was called after option validation failure")
		}
		assertWindowsEnterprisePreflightFailureJSON(
			t,
			output.String(),
			"status",
			"--purge is valid only",
		)
	})

	t.Run("script resolution emits one document", func(t *testing.T) {
		scriptErr := errors.New("trusted installer unavailable")
		windowsEnterpriseScriptFinder = func(string) (string, error) {
			return "", scriptErr
		}
		var output strings.Builder
		cmd := &cobra.Command{}
		cmd.SetOut(&output)
		err := runWindowsEnterpriseLifecycle(
			context.Background(),
			cmd,
			"status",
			&windowsEnterpriseLifecycleOptions{jsonOutput: true},
		)
		if !errors.Is(err, scriptErr) {
			t.Fatalf("script resolution error = %v", err)
		}
		assertWindowsEnterprisePreflightFailureJSON(
			t,
			output.String(),
			"status",
			scriptErr.Error(),
		)
	})

	t.Run("runner failure does not emit a second document", func(t *testing.T) {
		runnerErr := errors.New("PowerShell reported failure")
		windowsEnterpriseScriptFinder = func(string) (string, error) {
			return `C:\trusted\install-enterprise.ps1`, nil
		}
		windowsEnterpriseExecutableResolver = func() (string, error) {
			return `C:\release\defenseclaw.exe`, nil
		}
		windowsEnterpriseCommandRunner = func(
			context.Context,
			*cobra.Command,
			string,
			[]string,
		) error {
			return runnerErr
		}
		var output strings.Builder
		cmd := &cobra.Command{}
		cmd.SetOut(&output)
		err := runWindowsEnterpriseLifecycle(
			context.Background(),
			cmd,
			"status",
			&windowsEnterpriseLifecycleOptions{jsonOutput: true},
		)
		if !errors.Is(err, runnerErr) {
			t.Fatalf("runner error = %v", err)
		}
		if output.Len() != 0 {
			t.Fatalf("Go preflight double-emitted runner JSON: %q", output.String())
		}
	})
}

func TestWindowsEnterpriseInstallerFailureDiagnosticPreservesCausalJSON(t *testing.T) {
	body := []byte(`{"schema_version":1,"ok":false,"action":"repair","error":"guardian activation failed\npolicy incomplete","errors":["guardian activation failed"]}`)
	action, detail, ok := windowsEnterpriseInstallerFailureDiagnostic(body, false)
	if !ok || action != "repair" ||
		detail != "guardian activation failed policy incomplete" {
		t.Fatalf("diagnostic = (%q, %q, %t)", action, detail, ok)
	}
	legacy := append([]byte{0xef, 0xbb, 0xbf}, body...)
	if action, detail, ok := windowsEnterpriseInstallerFailureDiagnostic(
		legacy,
		false,
	); !ok || action != "repair" || detail == "" {
		t.Fatalf("PowerShell 5.1 BOM diagnostic = (%q, %q, %t)", action, detail, ok)
	}
	errorsOnly := []byte(`{"schema_version":1,"ok":false,"action":"repair","errors":["readiness timeout"]}`)
	if _, detail, ok := windowsEnterpriseInstallerFailureDiagnostic(
		errorsOnly,
		false,
	); !ok || detail != "readiness timeout" {
		t.Fatalf("errors-only diagnostic = (%q, %t)", detail, ok)
	}
	for name, test := range map[string]struct {
		body      []byte
		truncated bool
	}{
		"success report": {
			body: []byte(`{"schema_version":1,"ok":true,"action":"repair","error":"unexpected"}`),
		},
		"non-json prefix": {
			body: []byte("warning\n" + string(body)),
		},
		"truncated": {
			body:      body,
			truncated: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := windowsEnterpriseInstallerFailureDiagnostic(
				test.body,
				test.truncated,
			); ok {
				t.Fatal("untrusted installer output was promoted to a public diagnostic")
			}
		})
	}
}

func assertWindowsEnterprisePreflightFailureJSON(
	t *testing.T,
	output string,
	action string,
	errorContains string,
) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("preflight output is not exactly one JSON document: %v\n%s", err, output)
	}
	for _, field := range []string{"schema_version", "action", "ok", "error", "errors"} {
		if _, ok := raw[field]; !ok {
			t.Fatalf("preflight JSON is missing %q: %s", field, output)
		}
	}
	if len(raw) != 5 {
		t.Fatalf("preflight JSON fields = %v, want exact five-field contract", raw)
	}
	var report windowsEnterpriseLifecyclePreflightFailure
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode preflight report: %v", err)
	}
	if report.SchemaVersion != 1 ||
		report.Action != action ||
		report.OK ||
		!strings.Contains(report.Error, errorContains) ||
		len(report.Errors) != 1 ||
		report.Errors[0] != report.Error {
		t.Fatalf("unexpected preflight report: %#v", report)
	}
}

func TestFindWindowsEnterpriseInstallerExplicitRegularFile(t *testing.T) {
	originalValidator := windowsEnterpriseTrustValidator
	windowsEnterpriseTrustValidator = func(string) error { return nil }
	t.Cleanup(func() { windowsEnterpriseTrustValidator = originalValidator })

	path := filepath.Join(t.TempDir(), "install-enterprise.ps1")
	if err := os.WriteFile(path, []byte("# fixture"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := findWindowsEnterpriseInstaller(path)
	if err != nil {
		t.Fatalf("findWindowsEnterpriseInstaller: %v", err)
	}
	want, _ := filepath.Abs(path)
	if got != filepath.Clean(want) {
		t.Fatalf("installer = %q, want %q", got, want)
	}
}

func TestFindWindowsEnterpriseInstallerRejectsDirectoryAndSymlink(t *testing.T) {
	root := t.TempDir()
	if _, err := findWindowsEnterpriseInstaller(root); err == nil {
		t.Fatal("directory accepted as enterprise installer")
	}

	target := filepath.Join(root, "real.ps1")
	link := filepath.Join(root, "link.ps1")
	if err := os.WriteFile(target, []byte("# fixture"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink creation unavailable: %v", err)
	}
	if _, err := findWindowsEnterpriseInstaller(link); err == nil {
		t.Fatal("symlink accepted as enterprise installer")
	}
}

func TestFindWindowsEnterpriseInstallerRejectsUserControlledScriptAndModule(t *testing.T) {
	root := t.TempDir()
	installer := filepath.Join(root, "install-enterprise.ps1")
	module := filepath.Join(root, "DefenseClawEnterprise.psm1")
	for _, path := range []string{installer, module} {
		if err := os.WriteFile(path, []byte("# fixture"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", path, err)
		}
	}
	if _, err := findWindowsEnterpriseInstaller(installer); err == nil {
		t.Fatal("user-controlled installer and adjacent module were accepted")
	}
}

func TestFindWindowsEnterpriseInstallerDoesNotFallBackToCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "packaging", "windows")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "install-enterprise.ps1"), []byte("# fixture"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	t.Setenv(windowsEnterpriseInstallerEnv, "")
	if _, err := findWindowsEnterpriseInstaller(""); err == nil {
		t.Fatal("current-directory installer fallback was accepted")
	}
}

func TestFindWindowsPowerShellIgnoresPathAndSystemRootPoisoning(t *testing.T) {
	shadow := filepath.Join(t.TempDir(), "powershell.exe")
	if err := os.WriteFile(shadow, []byte("not powershell"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", filepath.Dir(shadow))
	t.Setenv("SystemRoot", filepath.Dir(shadow))
	got, err := findWindowsPowerShell()
	if err != nil {
		t.Fatalf("findWindowsPowerShell: %v", err)
	}
	if strings.EqualFold(got, shadow) {
		t.Fatalf("findWindowsPowerShell selected PATH shadow %q", got)
	}
	if filepath.Base(got) != "powershell.exe" {
		t.Fatalf("findWindowsPowerShell = %q", got)
	}
}

func TestTrustedWindowsEnterpriseEnvironmentOverwritesPoisonedOSPaths(t *testing.T) {
	poison := filepath.Join(t.TempDir(), "poison")
	for _, key := range []string{
		"SystemRoot",
		"windir",
		"ProgramFiles",
		"ProgramData",
		"PSModulePath",
		"PATH",
		"ComSpec",
		"TEMP",
		"TMP",
		"LOCALAPPDATA",
		"APPDATA",
		"USERPROFILE",
		"HOME",
		"HOMEDRIVE",
		"HOMEPATH",
		"COR_ENABLE_PROFILING",
		"COR_PROFILER",
		"COR_PROFILER_PATH",
		"CORECLR_ENABLE_PROFILING",
		"COMPlus_ReadyToRun",
		"DOTNET_STARTUP_HOOKS",
		"PSExecutionPolicyPreference",
		"__COMPAT_LAYER",
		"DEFENSECLAW_CALLER_SECRET",
	} {
		t.Setenv(key, poison)
	}
	trustedTemp := t.TempDir()
	environment, err := trustedWindowsEnterpriseEnvironment(trustedTemp)
	if err != nil {
		t.Fatalf("trustedWindowsEnterpriseEnvironment: %v", err)
	}
	values := make(map[string]string)
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found {
			values[strings.ToLower(key)] = value
		}
	}
	for _, key := range []string{
		"systemroot",
		"windir",
		"programfiles",
		"programdata",
		"psmodulepath",
		"path",
		"comspec",
		"temp",
		"tmp",
		"localappdata",
		"appdata",
		"userprofile",
		"home",
		"homedrive",
		"homepath",
	} {
		if strings.EqualFold(values[key], poison) || strings.TrimSpace(values[key]) == "" {
			t.Fatalf("%s remained poisoned: %q", key, values[key])
		}
	}
	if !strings.EqualFold(values["temp"], trustedTemp) ||
		!strings.EqualFold(values["tmp"], trustedTemp) ||
		!strings.EqualFold(values["localappdata"], trustedTemp) ||
		!strings.EqualFold(values["appdata"], trustedTemp) ||
		!strings.EqualFold(values["userprofile"], trustedTemp) ||
		!strings.EqualFold(values["home"], trustedTemp) {
		t.Fatalf(
			"trusted writable homes were not pinned: TEMP=%q TMP=%q LOCALAPPDATA=%q APPDATA=%q USERPROFILE=%q HOME=%q want %q",
			values["temp"],
			values["tmp"],
			values["localappdata"],
			values["appdata"],
			values["userprofile"],
			values["home"],
			trustedTemp,
		)
	}
	for _, key := range []string{
		"cor_enable_profiling",
		"cor_profiler",
		"cor_profiler_path",
		"coreclr_enable_profiling",
		"complus_readytorun",
		"dotnet_startup_hooks",
		"psexecutionpolicypreference",
		"__compat_layer",
		"defenseclaw_caller_secret",
	} {
		if _, inherited := values[key]; inherited {
			t.Fatalf("privileged child inherited caller-controlled variable %s", key)
		}
	}
}

func TestPrepareWindowsEnterprisePowerShellTempUsesCurrentUserKnownFolderWithoutElevation(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("non-elevated branch requires a limited process token")
	}
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatalf("resolve token-bound LocalAppData: %v", err)
	}
	poison := filepath.Join(t.TempDir(), "caller-controlled-temp")
	t.Setenv("TEMP", poison)
	t.Setenv("TMP", poison)
	t.Setenv("LOCALAPPDATA", poison)

	got, cleanup, err := prepareWindowsEnterprisePowerShellTemp()
	if err != nil {
		t.Fatalf("prepareWindowsEnterprisePowerShellTemp: %v", err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("cleanup non-elevated temp selection: %v", err)
		}
	})
	want := filepath.Join(localAppData, "Temp")
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		t.Fatalf("selected temp = %q, want current-user known folder %q", got, want)
	}
	if strings.EqualFold(filepath.Clean(got), filepath.Clean(poison)) {
		t.Fatalf("selected caller-controlled TEMP %q", got)
	}
}

func TestPrepareWindowsEnterprisePowerShellTempOpsNonElevatedHasNoPrivilegedSideEffects(t *testing.T) {
	const userTemp = `C:\Users\limited\AppData\Local\Temp`
	unexpected := func(string) error {
		t.Fatal("non-elevated temp selection invoked a privileged operation")
		return nil
	}
	path, cleanup, err := prepareWindowsEnterprisePowerShellTempWithOps(
		windowsEnterprisePowerShellTempOps{
			isElevated: func() bool { return false },
			userTemp:   func() (string, error) { return userTemp, nil },
			elevatedTempRoot: func() (string, error) {
				t.Fatal("non-elevated temp selection resolved ProgramData")
				return "", nil
			},
			randomRead: func([]byte) (int, error) {
				t.Fatal("non-elevated temp selection generated a privileged capability")
				return 0, nil
			},
			createDirectory: func(*uint16, *windows.SecurityAttributes) error {
				t.Fatal("non-elevated temp selection created a privileged directory")
				return nil
			},
			validate:  unexpected,
			remove:    unexpected,
			removeAll: unexpected,
		},
	)
	if err != nil {
		t.Fatalf("prepareWindowsEnterprisePowerShellTempWithOps: %v", err)
	}
	if path != userTemp {
		t.Fatalf("selected temp = %q, want %q", path, userTemp)
	}
	if cleanup == nil {
		t.Fatal("non-elevated temp selection returned no cleanup")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("non-elevated cleanup: %v", err)
	}
}

func TestPrepareWindowsEnterprisePowerShellTempOpsCreatesExactProtectedCapability(t *testing.T) {
	var (
		createdPath       string
		createdDescriptor string
		validatePaths     []string
		removedPath       string
	)
	ops := windowsEnterprisePowerShellTempOps{
		isElevated:       func() bool { return true },
		elevatedTempRoot: func() (string, error) { return `C:\ProgramData`, nil },
		randomRead: func(buffer []byte) (int, error) {
			for index := range buffer {
				buffer[index] = byte(index)
			}
			return len(buffer), nil
		},
		createDirectory: func(
			path *uint16,
			attributes *windows.SecurityAttributes,
		) error {
			createdPath = windows.UTF16PtrToString(path)
			if attributes == nil {
				t.Fatal("CreateDirectory received no SecurityAttributes")
			}
			if attributes.Length != uint32(unsafe.Sizeof(windows.SecurityAttributes{})) {
				t.Fatalf("SecurityAttributes.Length = %d", attributes.Length)
			}
			if attributes.SecurityDescriptor == nil {
				t.Fatal("CreateDirectory received no security descriptor")
			}
			createdDescriptor = attributes.SecurityDescriptor.String()
			return nil
		},
		validate: func(path string) error {
			validatePaths = append(validatePaths, path)
			return nil
		},
		remove: func(path string) error {
			t.Fatalf("successful preparation unexpectedly removed empty path %q", path)
			return nil
		},
		removeAll: func(path string) error {
			removedPath = path
			return nil
		},
	}

	path, cleanup, err := prepareWindowsEnterprisePowerShellTempWithOps(ops)
	if err != nil {
		t.Fatalf("prepareWindowsEnterprisePowerShellTempWithOps: %v", err)
	}
	want := `C:\ProgramData\DefenseClaw-PowerShell-000102030405060708090a0b0c0d0e0f`
	wantCreatePath, err := winpath.Extended(want)
	if err != nil {
		t.Fatalf("extend expected CreateDirectory path: %v", err)
	}
	if path != want || createdPath != wantCreatePath {
		t.Fatalf(
			"protected temp = %q, CreateDirectory path = %q, want %q / %q",
			path,
			createdPath,
			want,
			wantCreatePath,
		)
	}
	expectedDescriptor, err := windows.SecurityDescriptorFromString(windowsEnterpriseTempSDDL)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	if createdDescriptor != expectedDescriptor.String() {
		t.Fatalf("created descriptor = %q, want %q", createdDescriptor, expectedDescriptor.String())
	}
	if !reflect.DeepEqual(validatePaths, []string{want}) {
		t.Fatalf("initial validation paths = %#v", validatePaths)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup protected capability: %v", err)
	}
	if !reflect.DeepEqual(validatePaths, []string{want, want}) {
		t.Fatalf("validation paths after cleanup = %#v", validatePaths)
	}
	if removedPath != want {
		t.Fatalf("RemoveAll path = %q, want %q", removedPath, want)
	}
}

func TestWindowsEnterpriseExactDescriptorMatchIgnoresOnlyAutoInherited(t *testing.T) {
	expected, err := windows.SecurityDescriptorFromString(windowsEnterpriseTempSDDL)
	if err != nil {
		t.Fatalf("build expected descriptor: %v", err)
	}
	autoInheritedSDDL := strings.Replace(windowsEnterpriseTempSDDL, "D:P", "D:PAI", 1)
	autoInherited, err := windows.SecurityDescriptorFromString(autoInheritedSDDL)
	if err != nil {
		t.Fatalf("build auto-inherited descriptor: %v", err)
	}
	matches, err := windowsEnterpriseExactDescriptorMatch(autoInherited, expected)
	if err != nil {
		t.Fatalf("compare auto-inherited descriptor: %v", err)
	}
	if !matches {
		t.Fatal("benign AutoInherited metadata caused an exact-DACL mismatch")
	}

	hostile, err := windows.SecurityDescriptorFromString(
		autoInheritedSDDL + "(A;OICI;GR;;;BU)",
	)
	if err != nil {
		t.Fatalf("build hostile descriptor: %v", err)
	}
	matches, err = windowsEnterpriseExactDescriptorMatch(hostile, expected)
	if err != nil {
		t.Fatalf("compare hostile descriptor: %v", err)
	}
	if matches {
		t.Fatal("descriptor comparison accepted an extra ACE")
	}
}

func TestPrepareWindowsEnterprisePowerShellTempOpsCleanupRefusesValidationDrift(t *testing.T) {
	validateCalls := 0
	removeAllCalled := false
	ops := deterministicWindowsEnterpriseTempOps(t)
	ops.validate = func(string) error {
		validateCalls++
		if validateCalls == 1 {
			return nil
		}
		return errors.New("reparse or descriptor drift")
	}
	ops.removeAll = func(string) error {
		removeAllCalled = true
		return nil
	}
	_, cleanup, err := prepareWindowsEnterprisePowerShellTempWithOps(ops)
	if err != nil {
		t.Fatalf("prepareWindowsEnterprisePowerShellTempWithOps: %v", err)
	}
	if err := cleanup(); err == nil ||
		!strings.Contains(err.Error(), "refusing unsafe temp cleanup") {
		t.Fatalf("cleanup validation error = %v", err)
	}
	if removeAllCalled {
		t.Fatal("cleanup followed validation drift with RemoveAll")
	}
}

func TestPrepareWindowsEnterprisePowerShellTempOpsRetriesOnlyCollisions(t *testing.T) {
	ops := deterministicWindowsEnterpriseTempOps(t)
	var created []string
	ops.randomRead = func(buffer []byte) (int, error) {
		for index := range buffer {
			buffer[index] = byte(len(created) + 1)
		}
		return len(buffer), nil
	}
	ops.createDirectory = func(path *uint16, _ *windows.SecurityAttributes) error {
		created = append(created, windows.UTF16PtrToString(path))
		if len(created) < 4 {
			return windows.ERROR_ALREADY_EXISTS
		}
		return nil
	}
	path, cleanup, err := prepareWindowsEnterprisePowerShellTempWithOps(ops)
	if err != nil {
		t.Fatalf("prepare after collisions: %v", err)
	}
	if len(created) != 4 {
		t.Fatalf("CreateDirectory attempts = %d, want 4", len(created))
	}
	for index := 1; index < len(created); index++ {
		if created[index] == created[index-1] {
			t.Fatalf("collision retry reused capability path %q", created[index])
		}
	}
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		t.Fatalf("extend selected path: %v", err)
	}
	if extendedPath != created[len(created)-1] {
		t.Fatalf("selected path = %q (%q), want final created path %q", path, extendedPath, created[len(created)-1])
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup collision result: %v", err)
	}

	exhausted := deterministicWindowsEnterpriseTempOps(t)
	attempts := 0
	exhausted.createDirectory = func(*uint16, *windows.SecurityAttributes) error {
		attempts++
		return windows.ERROR_ALREADY_EXISTS
	}
	path, cleanup, err = prepareWindowsEnterprisePowerShellTempWithOps(exhausted)
	if err == nil || !strings.Contains(err.Error(), "random path collisions exhausted") {
		t.Fatalf("collision exhaustion error = %v", err)
	}
	if path != "" || cleanup != nil || attempts != 4 {
		t.Fatalf("collision exhaustion path=%q cleanupNil=%t attempts=%d", path, cleanup == nil, attempts)
	}
}

func TestPrepareWindowsEnterprisePowerShellTempOpsFailureCleanupIsExact(t *testing.T) {
	ops := deterministicWindowsEnterpriseTempOps(t)
	ops.createDirectory = func(*uint16, *windows.SecurityAttributes) error {
		return windows.ERROR_ACCESS_DENIED
	}
	path, cleanup, err := prepareWindowsEnterprisePowerShellTempWithOps(ops)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("non-collision create error = %v", err)
	}
	if path != "" || cleanup != nil {
		t.Fatalf("create failure returned path=%q cleanupNil=%t", path, cleanup == nil)
	}

	validationFailure := deterministicWindowsEnterpriseTempOps(t)
	var removed string
	validationFailure.validate = func(string) error {
		return errors.New("exact descriptor rejected")
	}
	validationFailure.remove = func(path string) error {
		removed = path
		return nil
	}
	path, cleanup, err = prepareWindowsEnterprisePowerShellTempWithOps(validationFailure)
	if err == nil || !strings.Contains(err.Error(), "exact descriptor rejected") {
		t.Fatalf("initial validation error = %v", err)
	}
	want := `C:\ProgramData\DefenseClaw-PowerShell-000102030405060708090a0b0c0d0e0f`
	if path != "" || cleanup != nil || removed != want {
		t.Fatalf("validation failure path=%q cleanupNil=%t removed=%q want=%q", path, cleanup == nil, removed, want)
	}
}

func deterministicWindowsEnterpriseTempOps(t *testing.T) windowsEnterprisePowerShellTempOps {
	t.Helper()
	return windowsEnterprisePowerShellTempOps{
		isElevated:       func() bool { return true },
		elevatedTempRoot: func() (string, error) { return `C:\ProgramData`, nil },
		randomRead: func(buffer []byte) (int, error) {
			for index := range buffer {
				buffer[index] = byte(index)
			}
			return len(buffer), nil
		},
		createDirectory: func(*uint16, *windows.SecurityAttributes) error { return nil },
		validate:        func(string) error { return nil },
		remove:          func(string) error { return nil },
		removeAll:       func(string) error { return nil },
	}
}

func TestPrepareWindowsEnterprisePowerShellTempElevatedDescriptorAndCleanupRefusal(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("protected ProgramData temp creation requires an elevated process token")
	}
	path, cleanup, err := prepareWindowsEnterprisePowerShellTemp()
	if err != nil {
		t.Fatalf("prepareWindowsEnterprisePowerShellTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(path)
	})

	programData, err := trustedWindowsEnterpriseProgramData()
	if err != nil {
		t.Fatalf("resolve ProgramData: %v", err)
	}
	wantParent := filepath.Clean(programData)
	if !strings.EqualFold(filepath.Dir(path), wantParent) {
		t.Fatalf("protected temp parent = %q, want %q", filepath.Dir(path), wantParent)
	}
	name := strings.TrimPrefix(filepath.Base(path), "DefenseClaw-PowerShell-")
	if len(name) != 32 {
		t.Fatalf("protected temp capability name = %q, want 128-bit lowercase hex", filepath.Base(path))
	}
	for _, character := range name {
		if !strings.ContainsRune("0123456789abcdef", character) {
			t.Fatalf("protected temp capability name contains non-hex character %q", character)
		}
	}
	if err := validateWindowsEnterprisePowerShellTemp(path); err != nil {
		t.Fatalf("validate freshly created protected temp: %v", err)
	}

	hostileDescriptor, err := windows.SecurityDescriptorFromString(
		"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;BU)",
	)
	if err != nil {
		t.Fatalf("build hostile descriptor: %v", err)
	}
	hostileDACL, _, err := hostileDescriptor.DACL()
	if err != nil {
		t.Fatalf("read hostile descriptor DACL: %v", err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatalf("encode protected temp path: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		hostileDACL,
		nil,
	); err != nil {
		t.Fatalf("tamper protected temp DACL: %v", err)
	}
	if err := validateWindowsEnterprisePowerShellTemp(path); err == nil ||
		!strings.Contains(err.Error(), "descriptor mismatch") {
		t.Fatalf("descriptor tamper validation error = %v", err)
	}
	if err := cleanup(); err == nil ||
		!strings.Contains(err.Error(), "refusing unsafe temp cleanup") {
		t.Fatalf("cleanup after descriptor tamper error = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("cleanup removed rejected protected temp: %v", err)
	}

	expectedDescriptor, err := windows.SecurityDescriptorFromString(windowsEnterpriseTempSDDL)
	if err != nil {
		t.Fatalf("build expected descriptor: %v", err)
	}
	expectedDACL, _, err := expectedDescriptor.DACL()
	if err != nil {
		t.Fatalf("read expected descriptor DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		expectedDACL,
		nil,
	); err != nil {
		t.Fatalf("restore protected temp DACL: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup restored protected temp: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("protected temp survived cleanup: %v", err)
	}
}

func TestTrustedWindowsEnterpriseChildDropsLoaderEnvAndHostileCWD(t *testing.T) {
	hostile := t.TempDir()
	for _, key := range []string{
		"COR_ENABLE_PROFILING",
		"COR_PROFILER",
		"COR_PROFILER_PATH",
		"CORECLR_ENABLE_PROFILING",
		"COMPlus_ReadyToRun",
		"DOTNET_STARTUP_HOOKS",
		"PSExecutionPolicyPreference",
		"__COMPAT_LAYER",
	} {
		t.Setenv(key, filepath.Join(hostile, key+".dll"))
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(hostile); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	powerShell, err := findWindowsPowerShell()
	if err != nil {
		t.Fatalf("findWindowsPowerShell: %v", err)
	}
	environment, err := trustedWindowsEnterpriseEnvironment(t.TempDir())
	if err != nil {
		t.Fatalf("trustedWindowsEnterpriseEnvironment: %v", err)
	}
	workingDirectory, err := trustedWindowsEnterpriseWorkingDirectory()
	if err != nil {
		t.Fatalf("trustedWindowsEnterpriseWorkingDirectory: %v", err)
	}
	script := `Add-Type -TypeDefinition 'public static class DefenseClawTrustedChildProbe { public static int Value() { return 1; } }' -ErrorAction Stop;
[pscustomobject]@{
cwd=(Get-Location).Path;
cor=$env:COR_ENABLE_PROFILING;
profiler=$env:COR_PROFILER_PATH;
coreclr=$env:CORECLR_ENABLE_PROFILING;
complus=$env:COMPlus_ReadyToRun;
startup=$env:DOTNET_STARTUP_HOOKS;
policy=$env:PSExecutionPolicyPreference;
compat=$env:__COMPAT_LAYER
}|ConvertTo-Json -Compress`
	child := exec.Command(
		powerShell,
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	)
	child.Env = environment
	child.Dir = workingDirectory
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("trusted child: %v\n%s", err, output)
	}
	var report map[string]any
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode child report: %v\n%s", err, output)
	}
	if !strings.EqualFold(
		filepath.Clean(report["cwd"].(string)),
		filepath.Clean(workingDirectory),
	) {
		t.Fatalf("child cwd = %q, want %q", report["cwd"], workingDirectory)
	}
	for _, key := range []string{
		"cor",
		"profiler",
		"coreclr",
		"complus",
		"startup",
		"policy",
		"compat",
	} {
		value, present := report[key]
		if present && value != nil && strings.TrimSpace(value.(string)) != "" {
			t.Fatalf("trusted child inherited %s=%q", key, value)
		}
	}
}

func TestSetTemporaryEnvironmentRestoresUnsetAndExistingValues(t *testing.T) {
	const (
		existing = "DEFENSECLAW_TEST_EXISTING"
		unset    = "DEFENSECLAW_TEST_UNSET"
	)
	t.Setenv(existing, "before")
	_ = os.Unsetenv(unset)
	restore := setTemporaryEnvironment(map[string]string{
		existing: "during",
		unset:    "created",
	})
	if got := os.Getenv(existing); got != "during" {
		t.Fatalf("existing during = %q", got)
	}
	if got := os.Getenv(unset); got != "created" {
		t.Fatalf("unset during = %q", got)
	}
	restore()
	if got := os.Getenv(existing); got != "before" {
		t.Fatalf("existing restored = %q", got)
	}
	if _, ok := os.LookupEnv(unset); ok {
		t.Fatal("previously unset environment variable remained set")
	}
}
