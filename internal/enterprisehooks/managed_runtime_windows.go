// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const WindowsManagedSIDUnregisteredReason = "enterprise_managed_sid_unregistered"

// WindowsManagedHookRuntime is the administrator-authorized runtime selected
// for the current process token. PolicyActive distinguishes a clean
// post-uninstall absence from a damaged or unregistered active global policy.
type WindowsManagedHookRuntime struct {
	Connector          string
	DataDir            string
	PolicyActive       bool
	Registered         bool
	GatewayAddr        string
	GatewayServiceName string
}

// ResolveWindowsManagedHookRuntime performs connector-aware machine-policy
// resolution before any target-owned configuration is trusted.
func ResolveWindowsManagedHookRuntime(
	hookExecutable string,
	connectorName string,
) (WindowsManagedHookRuntime, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	switch name {
	case "claudecode":
		return resolveWindowsClaudeManagedHookRuntime(hookExecutable)
	case "codex":
		return resolveWindowsCodexManagedHookRuntime(hookExecutable)
	case "cursor":
		return resolveWindowsCursorManagedHookRuntime(hookExecutable)
	default:
		return WindowsManagedHookRuntime{}, fmt.Errorf(
			"enterprise hooks: unsupported Windows managed connector %q",
			connectorName,
		)
	}
}

func resolveWindowsCursorManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsCursorManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "cursor",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.active {
		return result, nil
	}
	result.PolicyActive = true
	result.GatewayAddr = target.gatewayAddr
	result.GatewayServiceName = target.gatewayServiceName
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"enterprise hooks: invoking hook executable %s does not match active Cursor policy executable %s",
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%s: connector cursor current SID %s is absent from the protected target set",
			WindowsManagedSIDUnregisteredReason,
			sid,
		)
	}
	if err := validateWindowsCursorManagedRuntime(target); err != nil {
		return result, err
	}
	result.Registered = true
	return result, nil
}

func validateWindowsCursorManagedRuntime(
	target windowsCursorManagedPolicyTarget,
) error {
	if target.targetSID == nil {
		return errors.New("enterprise hooks: Cursor managed runtime target SID is required")
	}
	if err := windowsEnterpriseHookTrustCheck(target.hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed hook executable trust check failed: %w", err)
	}
	hookDir := filepath.Join(target.dataDir, "hooks")
	tokenPath, err := connector.HookTokenFilePath(hookDir, "cursor")
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{target.dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.lock"), false},
		{filepath.Join(hookDir, ".hookcfg.cursor"), false},
		{tokenPath, false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json"), false},
		{filepath.Join(target.dataDir, "hook_contract_lock.json.lock"), false},
	} {
		if err := validateWindowsUserPathElement(
			item.path,
			target.targetSID,
			item.dir,
			item.dir,
			true,
		); err != nil {
			return fmt.Errorf("enterprise hooks: Cursor managed runtime trust check failed for %s: %w", item.path, err)
		}
		if !item.dir {
			info, err := os.Lstat(item.path)
			if err != nil {
				return err
			}
			if info.Size() > windowsEnterpriseUserFileMaxBytes {
				return fmt.Errorf("enterprise hooks: Cursor runtime file exceeds the bounded size: %s", item.path)
			}
		}
	}
	if err := connector.ValidateManagedNativeHookRuntime(
		target.dataDir,
		target.gatewayAddr,
		"cursor",
	); err != nil {
		return fmt.Errorf("enterprise hooks: Cursor managed runtime sidecars are invalid: %w", err)
	}
	_, hooksPath, adapterPath, _, _, _, err := windowsCursorManagedPaths()
	if err != nil {
		return err
	}
	lock, err := connector.LoadHookContractLockEntryForMode(target.dataDir, "cursor", true)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load Cursor managed hook contract: %w", err)
	}
	if lock.Connector != "cursor" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], hooksPath) ||
		len(lock.Locations.HookScriptPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookScriptPaths[0], adapterPath) ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "closed") {
		return errors.New("enterprise hooks: Cursor managed hook contract does not identify the active enterprise adapter")
	}
	return nil
}

func resolveWindowsClaudeManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	target, err := resolveWindowsClaudeManagedPolicyTarget()
	result := WindowsManagedHookRuntime{
		Connector: "claudecode",
		DataDir:   target.dataDir,
	}
	if err != nil {
		return result, err
	}
	if !target.policyExists {
		return result, nil
	}
	result.PolicyActive = true
	result.GatewayAddr = target.gatewayAddr
	result.GatewayServiceName = target.gatewayServiceName
	gatewayAddr, gatewayErr := connector.NormalizeWindowsManagedGatewayAddr(target.gatewayAddr)
	if gatewayErr != nil || gatewayAddr != target.gatewayAddr {
		return result, errors.New("enterprise hooks: active Claude policy has no valid protected gateway address")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(target.gatewayServiceName); err != nil {
		return result, err
	}
	if !sameWindowsEnterprisePath(target.hookExecutable, hookExecutable) {
		return result, fmt.Errorf(
			"enterprise hooks: invoking hook executable %s does not match active managed policy executable %s",
			hookExecutable,
			target.hookExecutable,
		)
	}
	if !target.registered {
		sid := "<unknown>"
		if target.targetSID != nil {
			sid = target.targetSID.String()
		}
		return result, fmt.Errorf(
			"%s: connector claudecode current SID %s is absent from the protected target set",
			WindowsManagedSIDUnregisteredReason,
			sid,
		)
	}
	if err := validateWindowsClaudeManagedRuntime(target); err != nil {
		return result, err
	}
	result.Registered = true
	return result, nil
}

func resolveWindowsCodexManagedHookRuntime(
	hookExecutable string,
) (WindowsManagedHookRuntime, error) {
	result := WindowsManagedHookRuntime{
		Connector: "codex",
	}
	registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(hookExecutable)
	if err != nil {
		result.PolicyActive = true
		return result, fmt.Errorf("enterprise hooks: resolve protected Codex runtime state: %w", err)
	}
	if !registry.Active {
		return result, nil
	}
	result.PolicyActive = true
	result.GatewayAddr = registry.GatewayAddr
	result.GatewayServiceName = registry.GatewayServiceName
	targets := registry.Targets
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return result, fmt.Errorf("enterprise hooks: resolve current Windows hook SID: %w", err)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return result, errors.New("enterprise hooks: current Windows hook token has no user SID")
	}
	currentSID := tokenUser.User.Sid
	var selected *connector.WindowsCodexManagedRuntimeTarget
	for index := range targets {
		if strings.EqualFold(targets[index].SID, currentSID.String()) {
			selected = &targets[index]
			break
		}
	}
	if selected == nil {
		return result, fmt.Errorf(
			"%s: connector codex current SID %s is absent from the protected target set",
			WindowsManagedSIDUnregisteredReason,
			currentSID,
		)
	}
	result.DataDir = selected.DataDir
	if err := validateWindowsCodexManagedRuntime(
		selected.DataDir,
		currentSID,
		hookExecutable,
	); err != nil {
		return result, err
	}
	result.Registered = true
	return result, nil
}

func validateWindowsCodexManagedRuntime(
	dataDir string,
	targetSID *windows.SID,
	hookExecutable string,
) error {
	if targetSID == nil {
		return errors.New("enterprise hooks: Codex managed runtime target SID is required")
	}
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed hook executable trust check failed: %w", err)
	}
	if !strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
		return fmt.Errorf("enterprise hooks: Codex managed data directory is noncanonical: %s", dataDir)
	}
	home := filepath.Dir(dataDir)
	validatedHome, validatedSID, err := validateWindowsEnterpriseHome(home, targetSID.String())
	if err != nil {
		return err
	}
	if !sameWindowsEnterprisePath(validatedHome, home) ||
		!validatedSID.Equals(targetSID) {
		return errors.New("enterprise hooks: Codex managed runtime identity changed during validation")
	}
	hookDir := filepath.Join(dataDir, "hooks")
	tokenPath, err := connector.HookTokenFilePath(hookDir, "codex")
	if err != nil {
		return err
	}
	requirementsPath, err := windowsCodexMachineRequirementsPath()
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		dir  bool
	}{
		{dataDir, true},
		{hookDir, true},
		{filepath.Join(hookDir, ".hookcfg"), false},
		{filepath.Join(hookDir, ".hookcfg.lock"), false},
		{filepath.Join(hookDir, ".hookcfg.codex"), false},
		{tokenPath, false},
		{filepath.Join(dataDir, "hook_contract_lock.json"), false},
		{filepath.Join(dataDir, "hook_contract_lock.json.lock"), false},
	} {
		if err := validateWindowsUserPathElement(
			item.path,
			targetSID,
			item.dir,
			item.dir,
			true,
		); err != nil {
			return fmt.Errorf(
				"enterprise hooks: Codex managed runtime trust check failed for %s: %w",
				item.path,
				err,
			)
		}
		if !item.dir {
			info, err := os.Lstat(item.path)
			if err != nil {
				return fmt.Errorf("enterprise hooks: inspect Codex managed runtime %s: %w", item.path, err)
			}
			if info.Size() > windowsEnterpriseUserFileMaxBytes {
				return fmt.Errorf(
					"enterprise hooks: Codex managed runtime %s exceeds %d-byte limit",
					item.path,
					windowsEnterpriseUserFileMaxBytes,
				)
			}
		}
	}
	if err := connector.ValidateManagedHookRuntimeState(dataDir, "codex", "closed"); err != nil {
		return fmt.Errorf("enterprise hooks: Codex managed runtime sidecars are invalid: %w", err)
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		dataDir,
		"codex",
		true,
	)
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: load Codex managed hook contract: %w",
			err,
		)
	}
	if lock.Connector != "codex" ||
		len(lock.Locations.HookConfigPaths) != 1 ||
		!sameWindowsEnterprisePath(lock.Locations.HookConfigPaths[0], requirementsPath) ||
		len(lock.Locations.HookScriptPaths) != 0 ||
		!strings.EqualFold(strings.TrimSpace(lock.HookFailMode), "closed") {
		return errors.New("enterprise hooks: Codex managed hook contract lock does not identify the active machine requirements")
	}
	return nil
}

func windowsCodexMachineRequirementsPath() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve trusted ProgramData: %w", err)
	}
	return filepath.Join(programData, "OpenAI", "Codex", "requirements.toml"), nil
}
