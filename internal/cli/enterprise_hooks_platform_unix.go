//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

var enterpriseHookSIDProfilePath = func(string) (string, error) {
	return "", fmt.Errorf("SID-only targets are supported only on native Windows")
}

func enterpriseHookDeferredTargetSessionAvailable(
	enterprisehooks.ManifestTarget,
) (bool, error) {
	return false, fmt.Errorf("deferred enterprise hook targets are supported only on native Windows")
}

// enterpriseHookRemovedAccountRow is the Windows standalone deleted-account
// check; no unix row is excused.
var enterpriseHookRemovedAccountRow = func(enterpriseHookReconcileRow) bool { return false }

// enterpriseHookManifestCatchUpAllowed is the Windows standalone
// manifest catch-up check (enterpriseHookManifestActivationIssue); unix
// status keeps the exact manifest binding.
var enterpriseHookManifestCatchUpAllowed = func() bool { return false }

func enterpriseHookTargetSessionAvailable(enterprisehooks.ManifestTarget) (bool, error) {
	return true, nil
}

func stageEnterpriseHookDeferredManagedPolicies(
	enterprisehooks.Manifest,
	[]enterprisehooks.ManifestTarget,
	string,
) error {
	return nil
}

func syncEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
	bool,
) error {
	return nil
}

func verifyEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
) error {
	return nil
}

func enterpriseHooksNativePlatformPreflight() error { return nil }

// enterpriseHooksNativeMutationIdentityPreflight is a no-op except for the
// standalone profile, whose guardian must be root with CAP_SETUID and
// CAP_SETGID to start per-user workers.
func enterpriseHooksNativeMutationIdentityPreflight() error {
	return enterpriseHookStandaloneMutationPreflight()
}

func enterpriseHooksNativePersistentPreRun(cmd *cobra.Command, args []string) error {
	// The per-user worker and scrub run without the daemon bootstrap and
	// must never be pointed at the managed deployment.
	bootstrap := cmd == nil || cmd.Annotations["defenseclaw.skip-daemon-bootstrap"] != "true"
	if bootstrap {
		if err := refuseEnterpriseHooksForStandardUserOnManagedHost(cmd); err != nil {
			return err
		}
		var warn io.Writer = os.Stderr
		if cmd != nil {
			warn = cmd.ErrOrStderr()
		}
		applyManagedStandaloneAdminEnv(warn)
	}
	var err error
	if cmd == enterpriseHooksStatusCmd {
		err = enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
	} else {
		err = enterpriseHooksFullRootPersistentPreRun(cmd, args)
	}
	if err == nil {
		if bootstrap {
			applyStandaloneHookGuardianDefaults(cmd)
		}
		configureEnterpriseHooksStandaloneUnix(cmd.Context())
	}
	return err
}

// refuseEnterpriseHooksForStandardUserOnManagedHost tells a standard user
// on a standalone managed host that the enterprise hooks commands read the
// administrator-owned deployment, instead of failing on a per-user config
// the managed deployment never creates ("read v8 config
// /home/<user>/.defenseclaw/config.yaml: no such file"). A caller that
// names a config keeps the ordinary path and its errors.
func refuseEnterpriseHooksForStandardUserOnManagedHost(cmd *cobra.Command) error {
	if strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" {
		return nil
	}
	layout, descriptor, err := managedStandaloneAdminDeployment()
	if err != nil {
		return nil
	}
	uid := managedHostCallerUID()
	if uid == 0 || (descriptor.ServiceUID >= 0 && uid == descriptor.ServiceUID) {
		return nil
	}
	command := "enterprise hooks"
	if cmd != nil {
		command = strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()))
	}
	return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s); "+
		"`%s` reads the administrator-owned deployment, so an administrator runs it: `sudo %s %s`",
		layout.DescriptorPath, command, managedHostGatewayCommand(), command)
}

// applyStandaloneHookGuardianDefaults fills in the guardian paths of this
// OS's standalone layout for a standalone deployment's config when the
// caller left them unset: the manifest (the flag default is the Linux
// path, and enumerate has none) and the guardian authorization directory
// (the data-dir-derived default differs from the layout on macOS). The
// services pass both explicitly, so their behavior is unchanged; the Secure
// Client profile is never standalone.
func applyStandaloneHookGuardianDefaults(cmd *cobra.Command) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return
	}
	applyStandaloneHookGuardianLayout(cmd, layout)
}

func applyStandaloneHookGuardianLayout(cmd *cobra.Command, layout managed.StandaloneLayout) {
	if cmd == nil || cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	if flag := cmd.Flags().Lookup("manifest"); flag != nil && !flag.Changed {
		_ = cmd.Flags().Set("manifest", layout.ManifestPath)
	}
	if strings.TrimSpace(os.Getenv(managed.HookGuardianAuthorizationDirEnv)) == "" &&
		filepath.Clean(strings.TrimSpace(cfg.DataDir)) == filepath.Clean(layout.DataDir) {
		_ = os.Setenv(managed.HookGuardianAuthorizationDirEnv, layout.GuardianAuthDir)
	}
}

// enterpriseHookMachinePolicyContract is Windows-only: Unix machine policy
// is not rendered per row.
func enterpriseHookMachinePolicyContract(enterprisehooks.Manifest) string {
	return ""
}

// enterpriseHookInstallMachinePolicyContract is Windows-only, like
// enterpriseHookMachinePolicyContract.
func enterpriseHookInstallMachinePolicyContract(string) (string, error) {
	return "", nil
}
