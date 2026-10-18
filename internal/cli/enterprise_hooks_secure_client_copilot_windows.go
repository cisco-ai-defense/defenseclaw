// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// On the Secure Client profile the guardian manages GitHub Copilot, the
// Copilot CLI and the GitHub Copilot app that runs the same CLI, the way the
// standalone guardian does: it publishes DefenseClaw's policy.d drop-in before
// every reconcile, and each enrolled user gets a per-user runtime
// (enterprisehooks). Copilot is the only per-user connector Secure Client
// manages, and only through its CLI policy hooks.

// windowsSecureClientCopilotPolicyOptions resolves the Secure Client GitHub
// Copilot policy: the drop-in runs hookBinary (this deployment's own
// launcher when empty), and DefenseClaw's ownership records live in the
// Secure Client lifecycle folder, which only administrators can write.
func windowsSecureClientCopilotPolicyOptions(hookBinary string) (enterprisepolicy.Options, error) {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		return enterprisepolicy.Options{}, err
	}
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return enterprisepolicy.Options{}, err
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return enterprisepolicy.Options{}, err
	}
	if strings.TrimSpace(hookBinary) == "" {
		if hookBinary, err = windowsSecureClientHookBinary(roots); err != nil {
			return enterprisepolicy.Options{}, err
		}
	}
	return enterprisepolicy.Options{
		GOOS:                 "windows",
		WindowsProgramFiles:  programFiles,
		WindowsProgramData:   programData,
		HookBinary:           filepath.Clean(hookBinary),
		StateDir:             filepath.Join(roots.LifecycleDir, "machine-policy"),
		CopilotCLIPolicyOnly: true,
	}, nil
}

// windowsSecureClientHookBinary is the hook launcher beside this process's
// binary, which must sit in the bin folder of a Secure Client install root
// (production or a run-scoped certification root).
func windowsSecureClientHookBinary(roots winpath.EnterpriseRoots) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve the running executable: %w", err)
	}
	bin := filepath.Dir(filepath.Clean(executable))
	if !strings.EqualFold(filepath.Base(bin), "bin") ||
		winpath.ValidateEnterpriseInstallRoot(roots, filepath.Dir(bin)) != nil {
		return "", fmt.Errorf("the GitHub Copilot machine policy is published only by an installed Secure Client DefenseClaw, not %s", executable)
	}
	return filepath.Join(bin, nativeHookLauncherName), nil
}

// Replaceable in tests.
var (
	enterpriseHookSecureClientCopilotOptions = windowsSecureClientCopilotPolicyOptions
	enterpriseHookSecureClientCopilotPublish = enterprisepolicy.PublishWindowsSecureClientCopilot
)

// enterpriseHookSecureClientPlatformPrepare publishes the Secure Client
// GitHub Copilot drop-in before the reconcile installs any Copilot row, or
// removes the one this deployment published once Copilot is no longer an
// enabled connector. Failure is reported, not fatal: Copilot rows fail their
// own verification while the drop-in is not in force.
func enterpriseHookSecureClientPlatformPrepare(stderr io.Writer) {
	enabled := slices.Contains(enterprisehooks.EffectiveWindowsHookConnectors(cfg), "copilot")
	opts, err := enterpriseHookSecureClientCopilotOptions("")
	if err == nil {
		windowsStandaloneGoOwnedPolicyMu.Lock()
		_, err = enterpriseHookSecureClientCopilotPublish(opts, enabled)
		windowsStandaloneGoOwnedPolicyMu.Unlock()
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: GitHub Copilot machine policy (Windows Secure Client): %v\n", err)
	}
}

// removeWindowsSecureClientCopilotWiring revokes every Copilot enrollment and
// removes the drop-in this deployment recorded. Managed-hook teardown and a
// rolled-back first install call it; the selectors and DefenseClaw's folder
// in Copilot's machine folder go in their own steps.
func removeWindowsSecureClientCopilotWiring(hookBinary string) error {
	if err := enterprisehooks.RemoveWindowsPerUserManagedEnrollments(
		hookBinary,
		enterprisehooks.WindowsProfilePerUserConnectorNames(),
	); err != nil {
		return err
	}
	opts, err := windowsSecureClientCopilotPolicyOptions(hookBinary)
	if err != nil {
		return err
	}
	_, err = enterprisepolicy.RemoveWindowsSecureClientCopilot(opts)
	return err
}

// rollbackWindowsSecureClientFirstInstallFootprint runs when a rolled-back
// first Secure Client install retires its lifecycle journal: the guardian may
// already have enrolled Copilot users and published the drop-in. It removes
// them, the Copilot runtime selector and DefenseClaw's folder in Copilot's
// machine folder, and returns each leftover.
func rollbackWindowsSecureClientFirstInstallFootprint(ctx windowsManagedHooksLifecycleContext) []string {
	var leftovers []string
	if err := removeWindowsSecureClientCopilotWiring(ctx.opts.HookBinary); err != nil {
		leftovers = append(leftovers, fmt.Sprintf("GitHub Copilot enrollment and machine policy: %v", err))
	}
	if err := enterprisehooks.RemoveWindowsPerUserRuntimeSelectors(); err != nil {
		leftovers = append(leftovers, fmt.Sprintf("GitHub Copilot runtime selector: %v", err))
	}
	kept, err := enterprisehooks.RemoveWindowsSecureClientPerUserRuntimeDirectories()
	if err != nil {
		leftovers = append(leftovers, fmt.Sprintf("GitHub Copilot runtime folder: %v", err))
	}
	return append(leftovers, kept...)
}
