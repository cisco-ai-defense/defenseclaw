//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var enterpriseHookSIDProfilePath = windowsEnterpriseHookSIDProfilePath

var enterpriseHookWindowsSystemDirectory = windows.GetSystemDirectory

func syncEnterpriseHookManagedEnrollments(
	manifest enterprisehooks.Manifest,
	apiAddr string,
	publishExact bool,
) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	desiredClaude, desiredCodex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		return err
	}
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		if publishExact || len(desiredClaude) == 0 {
			return err
		}
		// The active global command remains fail-closed while protected state
		// is incomplete. Let the narrow per-target secure Install path attempt
		// its ownership-bound repair; final exact publication below will still
		// reject any unrepaired damage.
		currentClaude = nil
		claudeActive = false
	}
	if publishExact {
		if claudeActive || len(desiredClaude) > 0 {
			if err := enterprisehooks.PublishWindowsClaudeManagedPolicyTargets(desiredClaude); err != nil {
				return err
			}
		}
	} else if claudeActive {
		desired := make(map[string]struct{}, len(desiredClaude))
		for _, sid := range desiredClaude {
			desired[sid] = struct{}{}
		}
		retained := make([]string, 0, len(currentClaude))
		for _, sid := range currentClaude {
			if _, ok := desired[sid]; ok {
				retained = append(retained, sid)
			}
		}
		if err := enterprisehooks.PublishWindowsClaudeManagedPolicyTargets(retained); err != nil {
			return err
		}
	}

	codexOpts, err := resolveWindowsCodexRequirementsLayout("reconcile")
	if err != nil {
		return err
	}
	currentCodex, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(
		codexOpts.HookBinary,
	)
	if err != nil {
		if publishExact || len(desiredCodex) == 0 {
			return err
		}
		// As above, defer only to the trusted machine-policy reconciler. The
		// target stays unregistered/fail-closed until final exact publication.
		return nil
	}
	if len(desiredCodex) == 0 {
		if currentCodex.Active {
			report, err := connector.RemoveWindowsCodexMachineRequirements(codexOpts)
			if err != nil {
				return err
			}
			if !report.OK || !report.SafeToRemoveBinary ||
				report.SurvivingOwnedPathReferences != 0 {
				return fmt.Errorf("Codex machine requirements removal was not reference-clean")
			}
		}
		return nil
	}
	if publishExact {
		if !currentCodex.Active {
			return fmt.Errorf("Codex managed policy is absent after target runtime installation")
		}
		return connector.PublishWindowsCodexManagedRuntimeTargets(codexOpts, desiredCodex)
	}
	if !currentCodex.Active {
		return nil
	}
	desired := make(map[string]string, len(desiredCodex))
	for _, target := range desiredCodex {
		desired[strings.ToUpper(target.SID)] = target.DataDir
	}
	retained := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(currentCodex.Targets))
	for _, target := range currentCodex.Targets {
		dataDir, ok := desired[strings.ToUpper(target.SID)]
		if ok && sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			retained = append(retained, target)
		}
	}
	return connector.PublishWindowsCodexManagedRuntimeTargets(codexOpts, retained)
}

func windowsEnterpriseDesiredEnrollments(
	manifest enterprisehooks.Manifest,
) ([]string, []connector.WindowsCodexManagedRuntimeTarget, error) {
	desiredClaude := make([]string, 0, len(manifest.Targets))
	desiredCodex := make([]connector.WindowsCodexManagedRuntimeTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		resolved, err := resolveEnterpriseHookTargetValues(
			target.User,
			target.UserHome,
			intPtrValue(target.UID),
			intPtrValue(target.GID),
			target.SID,
			target.DataDir,
		)
		if err != nil {
			return nil, nil, err
		}
		sid, err := windows.StringToSid(strings.TrimSpace(resolved.sid))
		if err != nil || sid == nil {
			return nil, nil, fmt.Errorf("invalid Windows enrollment SID %q", resolved.sid)
		}
		switch strings.ToLower(strings.TrimSpace(target.Connector)) {
		case "claudecode":
			desiredClaude = append(desiredClaude, sid.String())
		case "codex":
			dataDir := filepath.Join(filepath.Clean(resolved.home), ".defenseclaw")
			if configured := strings.TrimSpace(target.DataDir); configured != "" {
				configured, err = filepath.Abs(configured)
				if err != nil {
					return nil, nil, err
				}
				configured = filepath.Clean(configured)
				if !sameWindowsEnterprisePathCLI(configured, dataDir) {
					return nil, nil, fmt.Errorf(
						"Codex target %s data_dir does not equal canonical %s",
						sid,
						dataDir,
					)
				}
			}
			desiredCodex = append(desiredCodex, connector.WindowsCodexManagedRuntimeTarget{
				SID:     sid.String(),
				DataDir: dataDir,
			})
		}
	}
	sort.Strings(desiredClaude)
	sort.Slice(desiredCodex, func(i, j int) bool {
		return desiredCodex[i].SID < desiredCodex[j].SID
	})
	return desiredClaude, desiredCodex, nil
}

func verifyEnterpriseHookManagedEnrollments(
	manifest enterprisehooks.Manifest,
	_ string,
) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	desiredClaude, desiredCodex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		return err
	}
	currentClaude, claudeActive, err := enterprisehooks.ReadWindowsClaudeManagedPolicyTargets()
	if err != nil {
		return err
	}
	if claudeActive != (len(desiredClaude) > 0) ||
		!equalWindowsEnterpriseStringSet(currentClaude, desiredClaude) {
		return fmt.Errorf("Claude protected SID enrollment does not match the enabled manifest")
	}

	codexOpts, err := resolveWindowsCodexRequirementsLayout("verify")
	if err != nil {
		return err
	}
	currentCodex, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(
		codexOpts.HookBinary,
	)
	if err != nil {
		return err
	}
	if currentCodex.Active != (len(desiredCodex) > 0) ||
		len(currentCodex.Targets) != len(desiredCodex) {
		return fmt.Errorf("Codex protected SID enrollment does not match the enabled manifest")
	}
	for index := range desiredCodex {
		if !strings.EqualFold(currentCodex.Targets[index].SID, desiredCodex[index].SID) ||
			!sameWindowsEnterprisePathCLI(
				currentCodex.Targets[index].DataDir,
				desiredCodex[index].DataDir,
			) {
			return fmt.Errorf("Codex protected SID enrollment does not match the enabled manifest")
		}
	}
	return nil
}

func equalWindowsEnterpriseStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) {
	// The guardian must never promote service-writable runtime state into its
	// administrator-owned configuration. In particular this intentionally
	// skips rootPersistentPreRunE's runtime .env load and runtime migration.
	return config.LoadFromFile(config.ConfigPath())
}

func enterpriseHooksNativePersistentPreRun(cmd *cobra.Command, args []string) error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		if cmd == enterpriseHooksStatusCmd {
			return enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
		}
		return enterpriseHooksFullRootPersistentPreRun(cmd, args)
	}
	if versionJSON {
		return nil
	}
	// The administrator-installed SCM deployment-mode pin is the trust-safe
	// mode probe. Outside that explicitly enabled mode, delegate immediately
	// so normal Windows startup retains its historical dotenv/config order and
	// performs no preliminary protected-config I/O.
	if !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		if cmd == enterpriseHooksStatusCmd {
			return enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
		}
		return enterpriseHooksFullRootPersistentPreRun(cmd, args)
	}
	loaded, err := enterpriseHooksWindowsConfigLoader()
	if err != nil {
		return fmt.Errorf(
			"failed to load protected enterprise config (the guardian ignores runtime .env and requires administrator-provisioned configuration and non-secret service pins): %w",
			err,
		)
	}
	if !managed.IsManagedEnterprise(loaded.DeploymentMode) {
		return fmt.Errorf(
			"failed to load protected enterprise config: immutable %s enables managed enterprise mode but the protected config resolved deployment_mode=%q",
			managed.DeploymentModeEnv,
			loaded.DeploymentMode,
		)
	}
	cfg = loaded
	version.SetBinaryVersion(appVersion)
	return nil
}

func enterpriseHooksNativePlatformPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
}

func windowsEnterpriseHookSIDProfilePath(rawSID string) (string, error) {
	sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
	if err != nil {
		return "", fmt.Errorf("parse SID: %w", err)
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(),
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	profile, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valueType == registry.EXPAND_SZ {
		profile, err = expandEnterpriseHookProfileImagePath(profile)
		if err != nil {
			return "", err
		}
	}
	profile = strings.TrimSpace(profile)
	if profile == "" || !filepath.IsAbs(profile) {
		return "", fmt.Errorf("profile path is empty or not absolute")
	}
	return filepath.Clean(profile), nil
}

func expandEnterpriseHookProfileImagePath(profile string) (string, error) {
	const systemDrive = `%SystemDrive%`
	profile = strings.TrimSpace(profile)
	if len(profile) < len(systemDrive) || !strings.EqualFold(profile[:len(systemDrive)], systemDrive) {
		if strings.Contains(profile, "%") {
			return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
		}
		return profile, nil
	}
	systemDirectory, err := enterpriseHookWindowsSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Windows system drive: %w", err)
	}
	drive := filepath.VolumeName(filepath.Clean(systemDirectory))
	if drive == "" {
		return "", fmt.Errorf("resolve trusted Windows system drive from %q", systemDirectory)
	}
	expanded := drive + profile[len(systemDrive):]
	if strings.Contains(expanded, "%") {
		return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
	}
	return expanded, nil
}

func enterpriseHooksNativeMutationIdentityPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("managed enterprise hook mutations require LocalSystem on native Windows: inspect process identity: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("managed enterprise hook mutations require the LocalSystem guardian on native Windows")
	}
	return nil
}
