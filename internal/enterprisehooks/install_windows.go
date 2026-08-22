//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	windowsEnterpriseAdministratorCheck = requireWindowsEnterpriseAdministrator
	windowsEnterpriseHookExecutable     = defaultWindowsEnterpriseHookExecutable
	windowsEnterpriseHookTrustCheck     = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "enterprise hook executable")
	}
	windowsEnterpriseTargetImpersonation    = withWindowsEnterpriseTargetImpersonation
	windowsEnterpriseConnectorCertification = certifyWindowsEnterpriseConnector
)

func platformInstall(ctx context.Context, opts InstallOptions) (InstallResult, bool, error) {
	if err := requireWindowsEnterpriseManagedAgentVersion(
		opts.ConnectorName,
		opts.AgentVersion,
	); err != nil {
		return InstallResult{}, true, err
	}
	var result InstallResult
	var err error
	switch strings.ToLower(strings.TrimSpace(opts.ConnectorName)) {
	case "claudecode":
		result, err = installWindowsClaudeManagedResult(ctx, opts)
	case "codex":
		result, err = installWindowsCodexManagedResult(ctx, opts)
	case "cursor":
		result, err = installWindowsCursorManagedResult(ctx, opts)
	default:
		result, err = installWindowsGenericManagedResult(ctx, opts)
	}
	return result, true, err
}

// windowsEnterpriseHookFailMode is the authoritative managed-native hook
// policy used by rendering, lock publication, and verification. The protected
// Windows deployment never permits Codex or Claude hooks to inherit a
// fail-open normal-mode setting.
func windowsEnterpriseHookFailMode(connectorName, configured string) string {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "codex", "claudecode", "cursor":
		return "closed"
	default:
		return strings.TrimSpace(configured)
	}
}

func platformVerify(ctx context.Context, opts InstallOptions) (InstallResult, bool, error) {
	if err := requireWindowsEnterpriseManagedAgentVersion(
		opts.ConnectorName,
		opts.AgentVersion,
	); err != nil {
		return InstallResult{}, true, err
	}
	var result InstallResult
	var err error
	switch strings.ToLower(strings.TrimSpace(opts.ConnectorName)) {
	case "claudecode":
		result, err = verifyWindowsClaudeManagedResult(ctx, opts)
	case "codex":
		result, err = verifyWindowsCodexManagedResult(ctx, opts)
	case "cursor":
		result, err = verifyWindowsCursorManagedResult(ctx, opts)
	default:
		result, err = verifyWindowsGenericManagedResult(ctx, opts)
	}
	return result, true, err
}

func requireWindowsEnterpriseManagedAgentVersion(connectorName, raw string) error {
	if err := requireWindowsEnterpriseAgentVersion(raw); err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	minimum := ""
	switch name {
	case "codex":
		minimum = "0.131.0"
	case "claudecode":
		minimum = "2.1.152"
	case "cursor":
		minimum = "1.7.0"
	default:
		return nil
	}
	normalized := connector.NormalizeAgentVersion(name, raw)
	if normalized == "" {
		return fmt.Errorf(
			"enterprise hooks: connector %s agent_version %q is malformed",
			name,
			raw,
		)
	}
	if compareWindowsEnterpriseVersion(normalized, minimum) < 0 {
		return fmt.Errorf(
			"enterprise hooks: connector %s agent_version %s is below the Windows enterprise minimum %s",
			name,
			normalized,
			minimum,
		)
	}
	return nil
}

func compareWindowsEnterpriseVersion(left, right string) int {
	parse := func(value string) [3]int {
		var result [3]int
		parts := strings.Split(value, ".")
		for index := 0; index < len(parts) && index < len(result); index++ {
			_, _ = fmt.Sscanf(parts[index], "%d", &result[index])
		}
		return result
	}
	leftTuple := parse(left)
	rightTuple := parse(right)
	for index := range leftTuple {
		if leftTuple[index] < rightTuple[index] {
			return -1
		}
		if leftTuple[index] > rightTuple[index] {
			return 1
		}
	}
	return 0
}

func installWindowsClaudeManagedResult(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	return installWindowsClaudeManagedResultSecure(ctx, opts)
}

func verifyWindowsClaudeManagedResult(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name != "claudecode" {
		if name == "" {
			return InstallResult{}, fmt.Errorf("enterprise hooks: connector is required")
		}
		return InstallResult{}, fmt.Errorf("enterprise hooks: native Windows managed policy currently supports only claudecode, got %q", name)
	}
	reg := opts.Registry
	if reg == nil {
		reg = newWindowsEnterpriseConnectorRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if err := windowsEnterpriseConnectorCertification(name, conn); err != nil {
		return InstallResult{}, err
	}
	provider, ok := conn.(connector.ManagedHookPolicyProvider)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not expose a managed policy contract", name)
	}
	home, targetSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return InstallResult{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return InstallResult{}, err
	}
	if err := validateWindowsUserPathPrefix(home, dataDir, targetSID, false); err != nil {
		return InstallResult{}, err
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return InstallResult{}, err
	}
	if !filepath.IsAbs(hookExecutable) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable is not absolute: %s", hookExecutable)
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed hook executable trust check failed: %w", err)
	}

	setupOpts := connector.SetupOpts{
		DataDir:            dataDir,
		ProxyAddr:          strings.TrimSpace(opts.ProxyAddr),
		APIAddr:            strings.TrimSpace(opts.APIAddr),
		APIToken:           strings.TrimSpace(opts.APIToken),
		HookAPIToken:       strings.TrimSpace(opts.APIToken),
		HookAPITokenScoped: true,
		OTLPPathToken:      strings.TrimSpace(opts.OTLPPathToken),
		Interactive:        false,
		ManagedEnterprise:  true,
		WorkspaceDir:       strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:       windowsEnterpriseHookFailMode(name, opts.HookFailMode),
		HILTEnabled:        opts.HILTEnabled,
		AgentVersion:       strings.TrimSpace(opts.AgentVersion),
		HookContractID:     strings.TrimSpace(opts.HookContractID),
		HookExecutable:     hookExecutable,
	}
	if err := validateWindowsEnterpriseImpersonationSetup(setupOpts); err != nil {
		return InstallResult{}, err
	}
	if setupOpts.APIAddr == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: API address is required")
	}
	if setupOpts.HookAPIToken == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector-scoped hook token is required")
	}
	if err := requireWindowsEnterpriseAgentVersion(setupOpts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	if setupOpts.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}
	if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
		return InstallResult{}, err
	}

	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return InstallResult{}, err
	}
	policySnapshot, err := snapshotWindowsManagedFile(policyPath)
	if err != nil {
		return InstallResult{}, err
	}
	statePath := filepath.Join(filepath.Dir(policyPath), windowsClaudeManagedStateFile)
	stateSnapshot, err := snapshotWindowsManagedFile(statePath)
	if err != nil {
		return InstallResult{}, err
	}
	state, err := validateExistingWindowsManagedPolicyOwnership(policySnapshot, stateSnapshot)
	if err != nil {
		return InstallResult{}, err
	}
	if !policySnapshot.existed {
		return InstallResult{}, fmt.Errorf("enterprise hooks: Claude Code managed policy is missing: %s", policyPath)
	}
	registered := false
	for _, sid := range state.TargetSIDs {
		if strings.EqualFold(strings.TrimSpace(sid), targetSID.String()) {
			registered = true
			break
		}
	}
	if !registered {
		return InstallResult{}, fmt.Errorf("enterprise hooks: target SID %s is not registered in the Claude Code managed policy", targetSID)
	}
	if !sameWindowsEnterprisePath(state.HookExecutable, hookExecutable) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: managed policy executable %s does not match trusted hook executable %s", state.HookExecutable, hookExecutable)
	}
	expectedPolicy, err := provider.ManagedHookPolicy(setupOpts)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: build canonical Claude Code managed policy: %w", err)
	}
	if !bytes.Equal(policySnapshot.data, expectedPolicy) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: Claude Code managed policy differs from the canonical DefenseClaw hook matrix")
	}
	if err := provider.VerifyManagedHookPolicy(policySnapshot.data, setupOpts); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: verify Claude Code managed policy: %w", err)
	}

	lock, err := verifyWindowsClaudeUserRuntimeReadOnly(home, dataDir, policyPath, targetSID, setupOpts, conn)
	if err != nil {
		return InstallResult{}, err
	}
	_ = ctx
	hookScripts := []string{}
	if scriptProvider, ok := conn.(connector.HookScriptProvider); ok {
		hookScripts = scriptProvider.HookScripts(setupOpts)
	}
	return InstallResult{
		Connector:       conn.Name(),
		UserHome:        home,
		DataDir:         dataDir,
		HookConfigPaths: []string{policyPath},
		HookScripts:     sortedUnique(hookScripts),
		AgentVersion:    lock.RawAgentVersion,
		HookContractID:  lock.ContractID,
	}, nil
}

type windowsGenericManagedTarget struct {
	home           string
	dataDir        string
	hookExecutable string
	sid            *windows.SID
	conn           connector.Connector
	setup          connector.SetupOpts
}

func resolveWindowsGenericManagedTarget(opts InstallOptions) (windowsGenericManagedTarget, error) {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	if name == "claudecode" {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: Claude Code uses the native Windows administrator policy path")
	}
	reg := opts.Registry
	if reg == nil {
		reg = newWindowsEnterpriseConnectorRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if err := windowsEnterpriseConnectorCertification(name, conn); err != nil {
		return windowsGenericManagedTarget{}, err
	}
	if connector.IsProxyConnector(conn.Name()) {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only; per-user hook install is not supported", conn.Name())
	}
	if !connector.OwnsManagedHookRuntime(conn) {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: connector %q does not own a managed hook runtime", conn.Name())
	}
	// Cursor remains hidden from the general native-Windows setup surface
	// until its release matrix is certified. This enterprise-only lifecycle is
	// separately gated by the concrete built-in registry and the protected
	// machine-policy implementation below.
	if name != "cursor" && !connector.ConnectorSupportedOnHostOS(conn.Name()) {
		support := connector.ConnectorSupportOnHostOS(conn.Name())
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: connector %q is not supported on native Windows: %s", conn.Name(), support.Reason)
	}
	home, targetSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return windowsGenericManagedTarget{}, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return windowsGenericManagedTarget{}, err
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return windowsGenericManagedTarget{}, err
	}
	if !filepath.IsAbs(hookExecutable) {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: managed hook executable is not absolute: %s", hookExecutable)
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: managed hook executable trust check failed: %w", err)
	}
	renderedExecutable := connector.NativeHookExecutable()
	if !sameWindowsEnterprisePath(renderedExecutable, hookExecutable) {
		return windowsGenericManagedTarget{}, fmt.Errorf(
			"enterprise hooks: connector runtime would use non-authoritative hook executable %s instead of trusted sibling %s",
			renderedExecutable,
			hookExecutable,
		)
	}
	setup := connector.SetupOpts{
		DataDir:            dataDir,
		ProxyAddr:          strings.TrimSpace(opts.ProxyAddr),
		APIAddr:            strings.TrimSpace(opts.APIAddr),
		APIToken:           strings.TrimSpace(opts.APIToken),
		HookAPIToken:       strings.TrimSpace(opts.APIToken),
		HookAPITokenScoped: true,
		OTLPPathToken:      strings.TrimSpace(opts.OTLPPathToken),
		Interactive:        false,
		ManagedEnterprise:  true,
		WorkspaceDir:       strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:       windowsEnterpriseHookFailMode(name, opts.HookFailMode),
		HILTEnabled:        opts.HILTEnabled,
		AgentVersion:       strings.TrimSpace(opts.AgentVersion),
		HookContractID:     strings.TrimSpace(opts.HookContractID),
		HookExecutable:     hookExecutable,
	}
	if err := validateWindowsEnterpriseImpersonationSetup(setup); err != nil {
		return windowsGenericManagedTarget{}, err
	}
	if setup.APIAddr == "" {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: API address is required")
	}
	if setup.HookAPIToken == "" {
		return windowsGenericManagedTarget{}, fmt.Errorf("enterprise hooks: connector-scoped hook token is required")
	}
	if err := requireWindowsEnterpriseAgentVersion(setup.AgentVersion); err != nil {
		return windowsGenericManagedTarget{}, err
	}
	if setup.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setup.AgentVersion)
		setup.HookContractID = resolution.Contract.ContractID
	}
	if err := validateHookContract(opts.GuardrailMode, conn, setup); err != nil {
		return windowsGenericManagedTarget{}, err
	}
	return windowsGenericManagedTarget{
		home:           home,
		dataDir:        dataDir,
		hookExecutable: hookExecutable,
		sid:            targetSID,
		conn:           conn,
		setup:          setup,
	}, nil
}

func installWindowsGenericManagedResult(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	var result InstallResult
	err = connector.WithUserHomeDir(target.home, func() error {
		configPaths := connector.HookConfigPathsForConnector(target.conn, target.setup)
		footprint := connector.AgentPaths{}
		if provider, ok := target.conn.(connector.AgentPathProvider); ok {
			footprint = provider.AgentPaths(target.setup)
		}
		// SECURITY INVARIANT: callbacks in this block run with only the target
		// user's thread token. Windows CreateProcess does not automatically use
		// that impersonation token, so a child could otherwise inherit the
		// guardian's LocalSystem process token. Only the certified built-in,
		// filesystem-only connector contract with process-launching options
		// disabled may cross this boundary.
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			if _, verifiedSID, err := validateWindowsEnterpriseHome(target.home, target.sid.String()); err != nil {
				return err
			} else if !verifiedSID.Equals(target.sid) {
				return fmt.Errorf("enterprise hooks: target profile SID changed before impersonated setup")
			}
			if err := prepareWindowsGenericFootprint(target, configPaths, footprint, opts.AllowMissingHookConfigRepair); err != nil {
				return err
			}
			target.conn.SetCredentials(target.setup.APIToken, opts.MasterKey)
			if err := target.conn.Setup(ctx, target.setup); err != nil {
				return fmt.Errorf("enterprise hooks: connector %s setup failed under target SID %s: %w", target.conn.Name(), target.sid, err)
			}
			rollback := func(cause error) error {
				if teardownErr := target.conn.Teardown(ctx, target.setup); teardownErr != nil {
					return fmt.Errorf("%v (target-SID rollback failed: %v)", cause, teardownErr)
				}
				return cause
			}
			present, err := connector.OwnedHooksPresentContext(ctx, target.conn, target.setup)
			if err != nil {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", target.conn.Name(), err))
			}
			if !present {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: owned hook command not present", target.conn.Name()))
			}
			lockEntry, err := connector.NewHookContractLockEntryForMode(
				target.setup,
				target.conn,
				version.Current().BinaryVersion,
				true,
			)
			if err != nil {
				return rollback(fmt.Errorf(
					"enterprise hooks: digest managed hook runtime: %w",
					err,
				))
			}
			if err := connector.SaveHookContractLockEntryForMode(target.dataDir, lockEntry, true); err != nil {
				return rollback(fmt.Errorf("enterprise hooks: save hook contract lock: %w", err))
			}
			if err := hardenWindowsGenericFootprint(target, configPaths, footprint); err != nil {
				return rollback(err)
			}
			if err := verifyWindowsGenericManagedTarget(ctx, target, configPaths, footprint); err != nil {
				return rollback(err)
			}
			cleanupWindowsGenericFootprintQuarantines(target, configPaths, footprint)
			result = InstallResult{
				Connector:       target.conn.Name(),
				UserHome:        target.home,
				DataDir:         target.dataDir,
				HookConfigPaths: sortedUnique(configPaths),
				HookScripts:     sortedUnique(footprint.HookScripts),
				BackupFiles:     sortedUnique(footprint.BackupFiles),
				CreatedDirs:     sortedUnique(append([]string{target.dataDir, filepath.Join(target.dataDir, "hooks")}, footprint.CreatedDirs...)),
				AgentVersion:    target.setup.AgentVersion,
				HookContractID:  lockEntry.ContractID,
			}
			return nil
		})
	})
	if err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

func verifyWindowsGenericManagedResult(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return InstallResult{}, err
	}
	if err := requireWindowsEnterpriseAgentVersion(opts.AgentVersion); err != nil {
		return InstallResult{}, err
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return InstallResult{}, err
	}
	var result InstallResult
	err = connector.WithUserHomeDir(target.home, func() error {
		configPaths := connector.HookConfigPathsForConnector(target.conn, target.setup)
		footprint := connector.AgentPaths{}
		if provider, ok := target.conn.(connector.AgentPathProvider); ok {
			footprint = provider.AgentPaths(target.setup)
		}
		if err := prepareWindowsGenericFootprint(target, configPaths, footprint, false); err != nil {
			return err
		}
		if err := verifyWindowsGenericManagedTarget(ctx, target, configPaths, footprint); err != nil {
			return err
		}
		lock, err := connector.LoadHookContractLockEntryForMode(
			target.dataDir,
			target.conn.Name(),
			true,
		)
		if err != nil {
			return fmt.Errorf("enterprise hooks: load managed hook contract: %w", err)
		}
		result = InstallResult{
			Connector:       target.conn.Name(),
			UserHome:        target.home,
			DataDir:         target.dataDir,
			HookConfigPaths: sortedUnique(configPaths),
			HookScripts:     sortedUnique(footprint.HookScripts),
			BackupFiles:     sortedUnique(footprint.BackupFiles),
			CreatedDirs:     sortedUnique(append([]string{target.dataDir, filepath.Join(target.dataDir, "hooks")}, footprint.CreatedDirs...)),
			AgentVersion:    lock.RawAgentVersion,
			HookContractID:  lock.ContractID,
		}
		return nil
	})
	if err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

func prepareWindowsGenericFootprint(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths, allowRepair bool) error {
	if err := prepareWindowsGenericPath(target.home, target.dataDir, target.sid, true, false, allowRepair, "data dir"); err != nil {
		return err
	}
	for _, path := range configPaths {
		if err := prepareWindowsGenericPath(target.home, path, target.sid, false, !allowRepair, allowRepair, "hook config"); err != nil {
			return err
		}
	}
	for _, path := range sortedUnique(append([]string{filepath.Join(target.dataDir, "hooks")}, footprint.CreatedDirs...)) {
		if err := prepareWindowsGenericPath(target.home, path, target.sid, true, false, allowRepair, "footprint directory"); err != nil {
			return err
		}
	}
	files, err := windowsGenericManagedFilePaths(target, configPaths, footprint)
	if err != nil {
		return err
	}
	for _, path := range sortedUnique(files) {
		if err := prepareWindowsGenericPath(target.home, path, target.sid, false, false, allowRepair, "footprint file"); err != nil {
			return err
		}
	}
	return nil
}

func windowsGenericManagedFilePaths(
	target windowsGenericManagedTarget,
	configPaths []string,
	footprint connector.AgentPaths,
) ([]string, error) {
	files := append([]string{}, configPaths...)
	files = append(files, footprint.PatchedFiles...)
	files = append(files, footprint.BackupFiles...)
	files = append(files, footprint.HookScripts...)
	files = append(files, footprint.GeneratedFiles...)
	files = append(files, footprint.GeneratedExecutables...)
	sidecars, err := hookSidecarFiles(target.dataDir, target.conn.Name())
	if err != nil {
		return nil, err
	}
	files = append(files, sidecars...)
	contractPath := filepath.Join(target.dataDir, "hook_contract_lock.json")
	files = append(files, contractPath)

	// Every target-controlled sibling opened by withFileLockMode is part of
	// the managed footprint. Preflight quarantines authorized wrong-type or
	// reparse obstructions before connector code opens them; hardening and
	// verification then enforce the same exact-SID/type/DACL contract.
	for _, lockedPath := range configPaths {
		files = append(files, lockedPath+".lock")
	}
	files = append(
		files,
		filepath.Join(target.dataDir, "hooks", ".hookcfg.lock"),
		contractPath+".lock",
	)
	return sortedUnique(files), nil
}

func prepareWindowsGenericPath(home, raw string, target *windows.SID, wantDir, required, allowRepair bool, label string) error {
	path := strings.TrimSpace(raw)
	if path == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve %s %s: %w", label, path, err)
	}
	path = filepath.Clean(abs)
	if !pathInside(home, path) {
		return fmt.Errorf("enterprise hooks: refusing %s outside user home: %s", label, path)
	}
	if err := prepareWindowsGenericHomeProtection(home, target, allowRepair, label); err != nil {
		return err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil {
		return err
	}
	current := filepath.Clean(home)
	parts := strings.Split(rel, string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		final := index == len(parts)-1
		elementWantsDir := !final || wantDir
		info, statErr := os.Lstat(current)
		if statErr != nil && allowRepair && errors.Is(statErr, windows.ERROR_ACCESS_DENIED) {
			if err := repairWindowsTargetOwnedPathDACL(home, current, target, elementWantsDir); err != nil {
				return fmt.Errorf("enterprise hooks: repair inaccessible %s %s: %w", label, current, err)
			}
			info, statErr = os.Lstat(current)
		}
		if errors.Is(statErr, os.ErrNotExist) {
			if final && required {
				return fmt.Errorf("enterprise hooks: %s is missing: %s", label, current)
			}
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, current, statErr)
		}
		ptr, err := winpath.UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if err != nil {
			return err
		}
		reparse := info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
		if reparse {
			if !allowRepair {
				return fmt.Errorf("enterprise hooks: refusing reparse point in %s path: %s", label, current)
			}
			elementWantsDir := !final || wantDir
			if err := quarantineWindowsTargetOwnedObstruction(home, current, target, elementWantsDir, label); err != nil {
				return err
			}
			return nil
		}
		if info.Mode().IsRegular() && info.Size() > windowsEnterpriseUserFileMaxBytes {
			if !allowRepair {
				return fmt.Errorf(
					"enterprise hooks: refusing oversized %s %s: %d bytes exceeds %d-byte managed limit",
					label,
					current,
					info.Size(),
					windowsEnterpriseUserFileMaxBytes,
				)
			}
			if err := quarantineWindowsTargetOwnedObstruction(
				home,
				current,
				target,
				elementWantsDir,
				label,
			); err != nil {
				return err
			}
			return nil
		}
		if elementWantsDir && !info.IsDir() {
			if !allowRepair {
				return fmt.Errorf("enterprise hooks: %s path element is not a directory: %s", label, current)
			}
			if err := quarantineWindowsTargetOwnedObstruction(home, current, target, true, label); err != nil {
				return err
			}
			return nil
		}
		if !elementWantsDir && !info.Mode().IsRegular() {
			if !allowRepair {
				return fmt.Errorf("enterprise hooks: %s is not a regular file: %s", label, current)
			}
			if err := quarantineWindowsTargetOwnedObstruction(home, current, target, false, label); err != nil {
				return err
			}
			return nil
		}
		if err := validateWindowsUserPathElement(current, target, elementWantsDir, elementWantsDir, true); err != nil {
			if errors.Is(err, errWindowsManagedHardlink) {
				if !allowRepair {
					return fmt.Errorf("enterprise hooks: %s trust check failed: %w", label, err)
				}
				if !final || elementWantsDir {
					return fmt.Errorf("enterprise hooks: refusing hard-linked non-file path element in %s path: %s", label, current)
				}
				if err := quarantineWindowsTargetOwnedObstruction(home, current, target, false, label); err != nil {
					return err
				}
				return nil
			}
			// A freshly created descendant inherits the directory's target/SY/BA
			// ACEs but is not yet protected. Because it is still target-owned
			// and has no inherited OWNER RIGHTS ACE, the impersonated target can
			// canonicalize it without invoking LocalSystem repair privileges.
			if repairErr := repairWindowsTargetOwnedPathDACLNoFollow(home, current, target, elementWantsDir); repairErr == nil {
				if err := validateWindowsUserPathElement(current, target, elementWantsDir, elementWantsDir, true); err != nil {
					return fmt.Errorf("enterprise hooks: target-repaired %s trust check failed: %w", label, err)
				}
				continue
			}
			if !allowRepair {
				return fmt.Errorf("enterprise hooks: %s trust check failed: %w", label, err)
			}
			if err := repairWindowsTargetOwnedPathDACL(home, current, target, elementWantsDir); err != nil {
				return fmt.Errorf("enterprise hooks: repair %s protection for %s: %w", label, current, err)
			}
			if err := validateWindowsUserPathElement(current, target, elementWantsDir, elementWantsDir, true); err != nil {
				return fmt.Errorf("enterprise hooks: repaired %s trust check failed: %w", label, err)
			}
		}
	}
	return nil
}

func prepareWindowsGenericHomeProtection(home string, target *windows.SID, allowRepair bool, label string) error {
	_ = allowRepair // profile-root DACLs are never canonicalized
	if err := validateWindowsEnterpriseHomeAnchor(home, target); err != nil {
		return fmt.Errorf("enterprise hooks: target home anchor check failed for %s: %w", label, err)
	}
	return nil
}

const windowsManagedObstructionQuarantineSuffix = ".defenseclaw-quarantine"
const windowsEnterpriseUserFileMaxBytes int64 = 4 << 20
const windowsEnterpriseTokenMaxBytes int64 = 64 << 10

var errWindowsManagedHardlink = errors.New("managed regular file has more than one hard link")

func windowsManagedObstructionQuarantinePath(path string) string {
	return path + windowsManagedObstructionQuarantineSuffix
}

func quarantineWindowsTargetOwnedObstruction(home, path string, target *windows.SID, recreateDirectory bool, label string) error {
	owner, err := windowsPathOwnerNoFollow(path)
	if err != nil || owner == nil || !owner.Equals(target) {
		return fmt.Errorf("enterprise hooks: refusing foreign-owned obstruction in %s path %s", label, path)
	}
	quarantine := windowsManagedObstructionQuarantinePath(path)
	if err := removeWindowsTargetOwnedQuarantine(quarantine, target, false); err != nil {
		return fmt.Errorf(
			"enterprise hooks: bounded obstruction quarantine for %s is unavailable: %w",
			path,
			err,
		)
	}
	if err := os.Rename(path, quarantine); err != nil {
		return fmt.Errorf("enterprise hooks: quarantine target-owned obstruction %s: %w", path, err)
	}
	if !recreateDirectory {
		return nil
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		_ = os.Rename(quarantine, path)
		return fmt.Errorf("enterprise hooks: recreate canonical directory %s: %w", path, err)
	}
	if err := repairWindowsTargetOwnedPathDACLNoFollow(home, path, target, true); err != nil {
		_ = os.Remove(path)
		_ = os.Rename(quarantine, path)
		return fmt.Errorf("enterprise hooks: protect recreated canonical directory %s: %w", path, err)
	}
	if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
		_ = os.Remove(path)
		_ = os.Rename(quarantine, path)
		return fmt.Errorf("enterprise hooks: verify recreated canonical directory %s: %w", path, err)
	}
	return nil
}

// removeWindowsTargetOwnedQuarantine purges the one bounded quarantine slot by
// handle. The implementation opens every child relative to an already-open
// parent with FILE_OPEN_REPARSE_POINT, so junctions are deleted as links and
// are never traversed. All deletion remains under the impersonated target
// token; LocalSystem is not allowed to recursively delete user-controlled
// paths with its process identity.
func removeWindowsTargetOwnedQuarantine(path string, target *windows.SID, allowNonEmpty bool) error {
	// allowNonEmpty is retained for the private call contract, but a non-empty
	// target-owned slot must now be recycled: leaving it in place lets a target
	// user permanently suppress every later repair.
	_ = allowNonEmpty
	return purgeWindowsTargetOwnedQuarantine(path, target)
}

func cleanupWindowsManagedObstructionQuarantine(path string, target *windows.SID) {
	_ = removeWindowsTargetOwnedQuarantine(windowsManagedObstructionQuarantinePath(path), target, true)
}

func cleanupWindowsGenericFootprintQuarantines(
	target windowsGenericManagedTarget,
	configPaths []string,
	footprint connector.AgentPaths,
) {
	paths := []string{target.dataDir, filepath.Join(target.dataDir, "hooks")}
	paths = append(paths, configPaths...)
	paths = append(paths, footprint.CreatedDirs...)
	paths = append(paths, footprint.PatchedFiles...)
	paths = append(paths, footprint.BackupFiles...)
	paths = append(paths, footprint.HookScripts...)
	paths = append(paths, footprint.GeneratedFiles...)
	paths = append(paths, footprint.GeneratedExecutables...)
	if files, err := windowsGenericManagedFilePaths(target, configPaths, footprint); err == nil {
		paths = append(paths, files...)
	}
	for _, path := range sortedUnique(paths) {
		cleanupWindowsManagedObstructionQuarantine(path, target.sid)
	}
}

func hardenWindowsGenericFootprint(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) error {
	dirs := append([]string{target.dataDir, filepath.Join(target.dataDir, "hooks")}, footprint.CreatedDirs...)
	for _, path := range sortedUnique(dirs) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := prepareWindowsGenericPath(target.home, path, target.sid, true, true, true, "installed directory"); err != nil {
			return err
		}
	}
	files, err := windowsGenericManagedFilePaths(target, configPaths, footprint)
	if err != nil {
		return err
	}
	for _, path := range sortedUnique(files) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := prepareWindowsGenericPath(target.home, path, target.sid, false, true, true, "installed file"); err != nil {
			return err
		}
	}
	return nil
}

func verifyWindowsGenericManagedTarget(ctx context.Context, target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) error {
	if err := prepareWindowsGenericFootprint(target, configPaths, footprint, false); err != nil {
		return err
	}
	present, err := connector.OwnedHooksPresentContext(ctx, target.conn, target.setup)
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", target.conn.Name(), err)
	}
	if !present {
		return fmt.Errorf("enterprise hooks: connector %s hook verification failed: canonical hook matrix is absent", target.conn.Name())
	}
	if err := connector.ValidateManagedHookRuntimeState(target.dataDir, target.conn.Name(), target.setup.HookFailMode); err != nil {
		return fmt.Errorf("enterprise hooks: connector %s runtime sidecars are invalid: %w", target.conn.Name(), err)
	}
	tokenPath, err := connector.HookTokenFilePath(filepath.Join(target.dataDir, "hooks"), target.conn.Name())
	if err != nil {
		return err
	}
	tokenData, err := connector.ReadManagedHookRuntimeFile(
		tokenPath,
		"managed connector-scoped token",
		windowsEnterpriseTokenMaxBytes,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read per-user connector-scoped token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(tokenData))), []byte(target.setup.HookAPIToken)) != 1 {
		return fmt.Errorf("enterprise hooks: per-user connector-scoped token does not match the protected service token")
	}
	lock, err := connector.LoadHookContractLockEntryForMode(
		target.dataDir,
		target.conn.Name(),
		true,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load managed hook contract: %w", err)
	}
	if lock.Connector != target.conn.Name() {
		return fmt.Errorf("enterprise hooks: connector %s hook contract lock is missing", target.conn.Name())
	}
	current, err := connector.NewHookContractLockEntryForMode(
		target.setup,
		target.conn,
		version.Current().BinaryVersion,
		true,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: digest managed hook runtime: %w", err)
	}
	if connector.HookContractLockDrifted(lock, current) {
		return fmt.Errorf("enterprise hooks: connector %s hook contract drift detected", target.conn.Name())
	}
	if strings.TrimSpace(lock.HookFailMode) != strings.TrimSpace(current.HookFailMode) {
		return fmt.Errorf("enterprise hooks: connector %s fail mode %q does not match configured mode %q", target.conn.Name(), lock.HookFailMode, current.HookFailMode)
	}
	return nil
}

func platformWatchDirs(opts InstallOptions) ([]string, bool, error) {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "codex" {
		target, err := resolveWindowsGenericManagedTarget(opts)
		if err != nil {
			return nil, true, err
		}
		machineOpts, err := windowsCodexRequirementsOptionsResolver(
			target.hookExecutable,
			target.setup.APIAddr,
		)
		if err != nil {
			return nil, true, err
		}
		userDirs := []string{
			target.home,
			target.dataDir,
			filepath.Join(target.dataDir, "hooks"),
		}
		for _, dir := range userDirs {
			if err := prepareWindowsGenericPath(
				target.home,
				dir,
				target.sid,
				true,
				false,
				false,
				"Codex watch directory",
			); err != nil {
				return nil, true, err
			}
		}
		return sortedUnique(append(userDirs,
			filepath.Dir(machineOpts.RequirementsPath),
			filepath.Dir(machineOpts.OwnershipPath),
		)), true, nil
	}
	if name == "cursor" {
		target, err := resolveWindowsGenericManagedTarget(opts)
		if err != nil {
			return nil, true, err
		}
		root, _, _, _, _, _, err := windowsCursorManagedPaths()
		if err != nil {
			return nil, true, err
		}
		userDirs := []string{
			target.home,
			target.dataDir,
			filepath.Join(target.dataDir, "hooks"),
		}
		for _, dir := range userDirs {
			if err := prepareWindowsGenericPath(
				target.home,
				dir,
				target.sid,
				true,
				false,
				false,
				"Cursor watch directory",
			); err != nil {
				return nil, true, err
			}
		}
		return sortedUnique(append(userDirs, root)), true, nil
	}
	if name != "claudecode" {
		target, err := resolveWindowsGenericManagedTarget(opts)
		if err != nil {
			return nil, true, err
		}
		dirs := map[string]struct{}{target.home: {}, target.dataDir: {}, filepath.Join(target.dataDir, "hooks"): {}}
		err = connector.WithUserHomeDir(target.home, func() error {
			for _, path := range connector.HookConfigPathsForConnector(target.conn, target.setup) {
				dirs[filepath.Dir(filepath.Clean(path))] = struct{}{}
			}
			if provider, ok := target.conn.(connector.AgentPathProvider); ok {
				footprint := provider.AgentPaths(target.setup)
				for _, path := range append(append(append(append([]string{}, footprint.PatchedFiles...), footprint.BackupFiles...), footprint.HookScripts...), footprint.GeneratedFiles...) {
					dirs[filepath.Dir(filepath.Clean(path))] = struct{}{}
				}
				for _, path := range footprint.CreatedDirs {
					dirs[filepath.Clean(path)] = struct{}{}
				}
			}
			return nil
		})
		if err != nil {
			return nil, true, err
		}
		out := make([]string, 0, len(dirs))
		for dir := range dirs {
			if err := prepareWindowsGenericPath(target.home, dir, target.sid, true, false, false, "watch directory"); err == nil {
				out = append(out, dir)
			}
		}
		return sortedUnique(out), true, nil
	}
	home, sid, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
	if err != nil {
		return nil, true, err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
	if err != nil {
		return nil, true, err
	}
	if err := validateWindowsUserPathPrefix(home, dataDir, sid, true); err != nil {
		return nil, true, err
	}
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return nil, true, err
	}
	return sortedUnique([]string{home, dataDir, filepath.Join(dataDir, "hooks"), filepath.Dir(policyPath)}), true, nil
}

func platformWatchOwnedFiles(opts InstallOptions) (WatchOwnership, bool, error) {
	if !strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "cursor") {
		return WatchOwnership{}, false, nil
	}
	target, err := resolveWindowsGenericManagedTarget(opts)
	if err != nil {
		return WatchOwnership{}, true, err
	}
	_, hooksPath, adapterPath, statePath, receiptPath, _, err := windowsCursorManagedPaths()
	if err != nil {
		return WatchOwnership{}, true, err
	}
	hookDir := filepath.Join(target.dataDir, "hooks")
	return WatchOwnership{
		SharedWriter: []string{hooksPath},
		ExclusiveWriter: sortedUnique([]string{
			adapterPath,
			statePath,
			receiptPath,
			filepath.Join(hookDir, ".hookcfg.cursor"),
			filepath.Join(hookDir, ".hook-cursor.token"),
			filepath.Join(target.dataDir, "hook_contract_lock.json"),
			filepath.Join(target.dataDir, "hook_contract_lock.json.lock"),
		}),
	}, true, nil
}

func resolveWindowsEnterpriseDataDir(home, raw string) (string, error) {
	canonical, err := filepath.Abs(filepath.Join(home, ".defenseclaw"))
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve canonical data dir: %w", err)
	}
	canonical = filepath.Clean(canonical)
	configured := strings.TrimSpace(raw)
	if configured == "" {
		return canonical, nil
	}
	configured, err = filepath.Abs(configured)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	configured = filepath.Clean(configured)
	if !sameWindowsEnterprisePath(configured, canonical) {
		return "", fmt.Errorf("enterprise hooks: native Windows managed runtime must use canonical per-user data dir %s, got %s", canonical, configured)
	}
	return canonical, nil
}

func platformRemoveManagedPolicy(ctx context.Context, opts InstallOptions) error {
	if err := windowsEnterpriseAdministratorCheck(); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "claudecode") {
		var targetSID *windows.SID
		var err error
		if strings.TrimSpace(opts.UserHome) != "" {
			_, targetSID, err = validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
		} else {
			targetSID, err = validateWindowsEnterpriseTargetSID(opts.OwnerSID)
		}
		if err != nil {
			return err
		}
		return removeWindowsClaudeManagedPolicyTarget(targetSID)
	}
	if strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "codex") {
		if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
			return err
		}
		targetSID, err := validateWindowsEnterpriseTargetSID(opts.OwnerSID)
		if err != nil {
			return err
		}
		hookExecutable, err := windowsEnterpriseHookExecutable()
		if err != nil {
			return err
		}
		machineOpts, err := windowsCodexRequirementsOptionsResolver(
			filepath.Clean(hookExecutable),
			strings.TrimSpace(opts.APIAddr),
		)
		if err != nil {
			return err
		}
		_ = ctx
		return connector.RemoveWindowsCodexManagedRuntimeTarget(
			machineOpts,
			targetSID.String(),
		)
	}
	if strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "cursor") {
		if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
			return err
		}
		targetSID, err := validateWindowsEnterpriseTargetSID(opts.OwnerSID)
		if err != nil {
			return err
		}
		return removeWindowsCursorManagedPolicyTarget(targetSID)
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	return removeWindowsGenericManagedRuntime(ctx, opts)
}

func removeWindowsGenericManagedRuntime(ctx context.Context, opts InstallOptions) error {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return fmt.Errorf("enterprise hooks: connector is required")
	}
	reg := opts.Registry
	if reg == nil {
		reg = newWindowsEnterpriseConnectorRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if err := windowsEnterpriseConnectorCertification(name, conn); err != nil {
		return err
	}
	if connector.IsProxyConnector(conn.Name()) || !connector.OwnsManagedHookRuntime(conn) {
		return fmt.Errorf("enterprise hooks: connector %q does not own a removable managed hook runtime", conn.Name())
	}
	targetSID, err := validateWindowsEnterpriseTargetSID(opts.OwnerSID)
	if err != nil {
		return err
	}
	return windowsEnterpriseTargetImpersonation(targetSID, opts.UserHome, func() error {
		home, verifiedSID, err := validateWindowsEnterpriseHome(opts.UserHome, opts.OwnerSID)
		if err != nil {
			return err
		}
		if !verifiedSID.Equals(targetSID) {
			return fmt.Errorf("enterprise hooks: target profile SID changed before impersonated removal")
		}
		dataDir, err := resolveWindowsEnterpriseDataDir(home, opts.DataDir)
		if err != nil {
			return err
		}
		setup := connector.SetupOpts{
			DataDir:           dataDir,
			ManagedEnterprise: true,
		}
		if err := validateWindowsEnterpriseImpersonationSetup(setup); err != nil {
			return err
		}
		return connector.WithUserHomeDir(home, func() error {
			configPaths := connector.HookConfigPathsForConnector(conn, setup)
			footprint := connector.AgentPaths{}
			if provider, ok := conn.(connector.AgentPathProvider); ok {
				footprint = provider.AgentPaths(setup)
			}
			target := windowsGenericManagedTarget{
				home:    home,
				dataDir: dataDir,
				sid:     targetSID,
				conn:    conn,
				setup:   setup,
			}
			if err := validateWindowsGenericRemovalFootprint(target, configPaths, footprint); err != nil {
				return err
			}
			if err := conn.Teardown(ctx, setup); err != nil {
				return fmt.Errorf(
					"enterprise hooks: connector %s teardown failed under target SID %s: %w",
					conn.Name(),
					targetSID,
					err,
				)
			}
			if err := connector.ClearHookContractLockEntryForMode(dataDir, conn.Name(), true); err != nil {
				return fmt.Errorf("enterprise hooks: clear connector %s hook contract lock: %w", conn.Name(), err)
			}
			return nil
		})
	})
}

func validateWindowsGenericRemovalFootprint(
	target windowsGenericManagedTarget,
	configPaths []string,
	footprint connector.AgentPaths,
) error {
	for _, path := range sortedUnique(append([]string{target.dataDir, filepath.Join(target.dataDir, "hooks")}, footprint.CreatedDirs...)) {
		if err := prepareWindowsGenericPath(target.home, path, target.sid, true, false, false, "removal directory"); err != nil {
			return err
		}
	}
	files, err := windowsGenericManagedFilePaths(target, configPaths, footprint)
	if err != nil {
		return err
	}
	for _, path := range sortedUnique(files) {
		if err := prepareWindowsGenericPath(target.home, path, target.sid, false, false, false, "removal file"); err != nil {
			return err
		}
	}
	return nil
}

func requireWindowsEnterpriseAdministrator() error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks: native Windows managed policy install requires an elevated administrator or LocalSystem token")
}

func newWindowsEnterpriseConnectorRegistry() *connector.Registry {
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewCodexConnector())
	registry.RegisterBuiltin(connector.NewClaudeCodeConnector())
	registry.RegisterBuiltin(connector.NewCursorConnector())
	return registry
}

// certifyWindowsEnterpriseConnector is deliberately a concrete-type allowlist,
// not a name or capability check. A plugin can claim "codex" while running
// arbitrary code from Setup, Teardown, or an optional provider callback.
func certifyWindowsEnterpriseConnector(name string, conn connector.Connector) error {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "codex":
		if _, ok := conn.(*connector.CodexConnector); !ok {
			return fmt.Errorf("enterprise hooks: connector %q is not the certified built-in Windows implementation", name)
		}
	case "claudecode":
		if _, ok := conn.(*connector.ClaudeCodeConnector); !ok {
			return fmt.Errorf("enterprise hooks: connector %q is not the certified built-in Windows implementation", name)
		}
	case "cursor":
		if !connector.IsBuiltinCursorConnector(conn) {
			return fmt.Errorf("enterprise hooks: connector %q is not the certified built-in Windows implementation", name)
		}
	default:
		return fmt.Errorf("enterprise hooks: connector %q is not certified for native Windows enterprise callbacks", name)
	}
	return nil
}

func validateWindowsEnterpriseImpersonationSetup(setup connector.SetupOpts) error {
	if !setup.ManagedEnterprise {
		return fmt.Errorf("enterprise hooks: Windows enterprise connector callback is missing managed mode")
	}
	if strings.TrimSpace(setup.AgentExecutable) != "" {
		return fmt.Errorf("enterprise hooks: Windows enterprise connector callbacks may not launch a target-user agent executable")
	}
	if setup.InstallCodeGuard {
		return fmt.Errorf("enterprise hooks: Windows enterprise connector callbacks may not install CodeGuard plugins")
	}
	if setup.Interactive {
		return fmt.Errorf("enterprise hooks: Windows enterprise connector callbacks may not be interactive")
	}
	return nil
}

func requireWindowsEnterpriseAgentVersion(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("enterprise hooks: native Windows managed target requires explicit agent_version")
	}
	return nil
}

func defaultWindowsEnterpriseHookExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve gateway executable: %w", err)
	}
	path := filepath.Join(filepath.Dir(executable), "defenseclaw-hook.exe")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect sibling native hook executable %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("enterprise hooks: native hook executable is not a regular file: %s", path)
	}
	return filepath.Clean(path), nil
}

func validateWindowsEnterpriseHome(raw, rawSID string) (string, *windows.SID, error) {
	home := strings.TrimSpace(raw)
	if home == "" {
		return "", nil, fmt.Errorf("enterprise hooks: user home is required")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: resolve user home: %w", err)
	}
	home = filepath.Clean(abs)
	info, err := os.Lstat(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: inspect user home %s: %w", home, err)
	}
	if !info.IsDir() {
		return "", nil, fmt.Errorf("enterprise hooks: user home is not a directory: %s", home)
	}
	owner, err := windowsPathOwner(home)
	if err != nil {
		return "", nil, fmt.Errorf("enterprise hooks: inspect user home owner: %w", err)
	}
	target := owner
	if strings.TrimSpace(rawSID) != "" {
		target, err = windows.StringToSid(strings.TrimSpace(rawSID))
		if err != nil {
			return "", nil, fmt.Errorf("enterprise hooks: parse target user SID: %w", err)
		}
	}
	if target == nil || windowsEnterpriseSystemIdentity(target) {
		return "", nil, fmt.Errorf("enterprise hooks: refusing non-interactive target SID %s", windowsSIDString(target))
	}
	if err := validateWindowsEnterpriseHomeAnchor(home, target); err != nil {
		return "", nil, err
	}
	return home, target, nil
}

// validateWindowsEnterpriseHomeAnchor treats the profile root as an identity
// and no-reparse anchor only. Its DACL is owned by Windows/profile-management
// policy and may legitimately contain inherited AppContainer, OneDrive, or
// enterprise principals. The guardian canonicalizes only exact managed
// descendants; it must never replace the whole profile DACL.
func validateWindowsEnterpriseHomeAnchor(home string, target *windows.SID) error {
	if err := validateWindowsEnterpriseProfileVolume(home); err != nil {
		return err
	}
	info, err := os.Lstat(home)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect user home anchor %s: %w", home, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: user home anchor is not a regular directory: %s", home)
	}
	ptr, err := winpath.UTF16Ptr(home)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect user home anchor attributes: %w", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("enterprise hooks: user home anchor is a reparse point: %s", home)
	}
	owner, err := windowsPathOwnerNoFollow(home)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect user home anchor owner: %w", err)
	}
	if !windowsEnterpriseProfileAnchorOwner(owner, target) {
		return fmt.Errorf(
			"enterprise hooks: user home anchor owner SID %s is not target or a trusted profile-management principal for target SID %s",
			windowsSIDString(owner),
			windowsSIDString(target),
		)
	}
	return rejectWindowsReparseChain(home)
}

func windowsEnterpriseProfileAnchorOwner(owner, target *windows.SID) bool {
	return owner != nil && target != nil && (owner.Equals(target) || windowsEnterpriseAdminIdentity(owner))
}

func validateWindowsEnterpriseProfileVolume(home string) error {
	identity, err := winpath.ValidateFixedNTFSMountedPath(home)
	if err != nil {
		return fmt.Errorf("enterprise hooks: user home is not on a trusted mount-manager NTFS drive: %w", err)
	}
	volume := strings.TrimSuffix(identity.DriveRoot, `\`)
	extended, err := winpath.Extended(home)
	if err != nil {
		return err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open user home volume anchor: %w", err)
	}
	defer windows.CloseHandle(handle)
	fileSystem := make([]uint16, 32)
	if err := windows.GetVolumeInformationByHandle(
		handle,
		nil,
		0,
		nil,
		nil,
		nil,
		&fileSystem[0],
		uint32(len(fileSystem)),
	); err != nil {
		return fmt.Errorf("enterprise hooks: inspect user home filesystem: %w", err)
	}
	if name := windows.UTF16ToString(fileSystem); !strings.EqualFold(name, "NTFS") {
		return fmt.Errorf("enterprise hooks: user home filesystem %q is not NTFS", name)
	}
	finalBuffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &finalBuffer[0], uint32(len(finalBuffer)), 0)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve final user home volume path: %w", err)
	}
	if n == 0 || n >= uint32(len(finalBuffer)) {
		return fmt.Errorf("enterprise hooks: final user home volume path exceeds bounded buffer")
	}
	finalPath := windows.UTF16ToString(finalBuffer[:n])
	finalPath = strings.TrimPrefix(finalPath, `\\?\`)
	if strings.HasPrefix(finalPath, `UNC\`) ||
		!strings.EqualFold(filepath.VolumeName(finalPath), volume) {
		return fmt.Errorf("enterprise hooks: user home drive is mapped, substituted, or resolves to another volume: %s", home)
	}
	return nil
}

func validateWindowsEnterpriseTargetSID(raw string) (*windows.SID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("enterprise hooks: target user SID is required when the user profile is unavailable")
	}
	sid, err := windows.StringToSid(raw)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse target user SID: %w", err)
	}
	if windowsEnterpriseSystemIdentity(sid) {
		return nil, fmt.Errorf("enterprise hooks: refusing non-interactive target SID %s", windowsSIDString(sid))
	}
	return sid, nil
}

func validateWindowsUserPathPrefix(home, path string, target *windows.SID, allowMissing bool) error {
	if err := validateWindowsEnterpriseProfileVolume(home); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	if !pathInside(home, abs) {
		return fmt.Errorf("enterprise hooks: refusing path outside user home: %s", abs)
	}
	rel, err := filepath.Rel(home, abs)
	if err != nil {
		return err
	}
	current := filepath.Clean(home)
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if _, err := os.Lstat(current); err != nil {
			if errors.Is(err, os.ErrNotExist) && allowMissing {
				return nil
			}
			return fmt.Errorf("enterprise hooks: inspect user path %s: %w", current, err)
		}
		if err := validateWindowsUserPathElement(current, target, true, true, false); err != nil {
			return err
		}
	}
	return nil
}

func validateWindowsUserPathElement(path string, target *windows.SID, wantDir, protectChildren, requireTargetOwner bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("enterprise hooks: symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("enterprise hooks: expected directory: %s", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: expected regular file: %s", path)
	}
	if !wantDir {
		if err := validateWindowsRegularFileSingleLink(path); err != nil {
			return err
		}
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows security descriptor for %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if requireTargetOwner {
		if owner == nil || !owner.Equals(target) {
			return fmt.Errorf("enterprise hooks: owner SID %s does not match target SID %s on %s", windowsSIDString(owner), windowsSIDString(target), path)
		}
	} else if owner == nil || (!owner.Equals(target) && !windowsEnterpriseAdminIdentity(owner)) {
		return fmt.Errorf("enterprise hooks: foreign owner SID %s on %s", windowsSIDString(owner), path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: null or unreadable Windows DACL on %s", path)
	}
	if requireTargetOwner {
		return validateWindowsUserPathProtectionACL(path, sd, dacl, target, wantDir)
	}
	return rejectWindowsUserRuntimeWriteACEs(path, dacl, target, wantDir, protectChildren)
}

func validateWindowsRegularFileSingleLink(path string) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open managed regular file without following %s: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("enterprise hooks: inspect managed regular file link count %s: %w", path, err)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf(
			"enterprise hooks: %w (%s has %d links)",
			errWindowsManagedHardlink,
			path,
			info.NumberOfLinks,
		)
	}
	return nil
}

type windowsUserPathCanonicalACE struct {
	sid         *windows.SID
	mask        windows.ACCESS_MASK
	inheritance uint32
}

type windowsUserPathAppliedACE struct {
	sid   *windows.SID
	mask  windows.ACCESS_MASK
	flags uint8
}

func windowsUserPathCanonicalACEs(target *windows.SID, directory bool) ([]windowsUserPathCanonicalACE, error) {
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	targetMask := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.GENERIC_WRITE |
			windows.GENERIC_EXECUTE |
			windows.DELETE,
	)
	if directory {
		targetMask |= fileDeleteChild
	}
	return []windowsUserPathCanonicalACE{
		// Any OWNER RIGHTS ACE suppresses the owner's implicit WRITE_DAC.
		// Keeping only READ_CONTROL prevents an owner from granting itself
		// WRITE_OWNER and transferring a managed object to an enabled group.
		// It is deliberately not inherited: a newly created target-owned child
		// needs its one-time implicit WRITE_DAC so the impersonated target can
		// apply the protected canonical child DACL immediately.
		{sid: ownerRights, mask: windows.READ_CONTROL, inheritance: windows.NO_INHERITANCE},
		{sid: target, mask: targetMask, inheritance: inheritance},
		{sid: system, mask: windows.GENERIC_ALL, inheritance: inheritance},
		{sid: administrators, mask: windows.GENERIC_ALL, inheritance: inheritance},
	}, nil
}

func windowsUserPathAppliedCanonicalACEs(target *windows.SID, directory bool) ([]windowsUserPathAppliedACE, error) {
	canonical, err := windowsUserPathCanonicalACEs(target, directory)
	if err != nil {
		return nil, err
	}
	out := make([]windowsUserPathAppliedACE, 0, len(canonical)*2)
	for _, item := range canonical {
		out = append(out, windowsUserPathAppliedACE{
			sid:  item.sid,
			mask: mapWindowsUserPathGenericMask(item.mask),
		})
		if item.inheritance != windows.NO_INHERITANCE {
			out = append(out, windowsUserPathAppliedACE{
				sid:   item.sid,
				mask:  item.mask,
				flags: uint8(item.inheritance) | windows.INHERIT_ONLY_ACE,
			})
		}
	}
	return out, nil
}

func mapWindowsUserPathGenericMask(mask windows.ACCESS_MASK) windows.ACCESS_MASK {
	mapped := mask
	if mask&windows.GENERIC_ALL != 0 {
		mapped &^= windows.GENERIC_ALL
		mapped |= windows.ACCESS_MASK(0x001f01ff) // FILE_ALL_ACCESS
	}
	if mask&windows.GENERIC_READ != 0 {
		mapped &^= windows.GENERIC_READ
		mapped |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		mapped &^= windows.GENERIC_WRITE
		mapped |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		mapped &^= windows.GENERIC_EXECUTE
		mapped |= windows.FILE_GENERIC_EXECUTE
	}
	return mapped
}

func validateWindowsUserPathProtectionACL(
	path string,
	sd *windows.SECURITY_DESCRIPTOR,
	dacl *windows.ACL,
	target *windows.SID,
	directory bool,
) error {
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows DACL control for %s: %w", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("enterprise hooks: managed Windows DACL is not protected on %s", path)
	}
	expected, err := windowsUserPathAppliedCanonicalACEs(target, directory)
	if err != nil {
		return err
	}
	if int(dacl.AceCount) != len(expected) {
		return fmt.Errorf(
			"enterprise hooks: managed Windows DACL on %s has %d ACEs, expected %d",
			path,
			dacl.AceCount,
			len(expected),
		)
	}
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect Windows ACE %d for %s: %w", index, path, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("enterprise hooks: managed Windows DACL on %s contains non-canonical ACE type at index %d", path, index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		match := -1
		for candidate, want := range expected {
			if seen[candidate] {
				continue
			}
			if sid.Equals(want.sid) &&
				ace.Mask == want.mask &&
				ace.Header.AceFlags == want.flags {
				match = candidate
				break
			}
		}
		if match < 0 {
			return fmt.Errorf(
				"enterprise hooks: managed Windows DACL on %s contains unexpected or duplicate ACE for principal %s (mask 0x%x, inheritance 0x%x)",
				path,
				windowsSIDString(sid),
				uint32(ace.Mask),
				uint32(ace.Header.AceFlags),
			)
		}
		seen[match] = true
	}
	return nil
}

func rejectWindowsUserRuntimeWriteACEs(path string, dacl *windows.ACL, target *windows.SID, wantDir, protectChildren bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
		accessDeniedObjectACEType          = 0x6
		accessDeniedCallbackACEType        = 0xA
		accessDeniedCallbackObjectACEType  = 0xC
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect Windows ACE %d for %s: %w", index, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inherits := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!protectChildren || !wantDir || !inherits) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE,
			accessDeniedObjectACEType,
			accessDeniedCallbackACEType,
			accessDeniedCallbackObjectACEType:
			return fmt.Errorf(
				"enterprise hooks: deny ACE type 0x%x with mask 0x%x can suppress managed access on %s",
				ace.Header.AceType,
				uint32(ace.Mask),
				path,
			)
		}
		if !windowsEnterpriseWriteLikeAccess(ace.Mask, protectChildren) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("enterprise hooks: unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) || (inheritOnly && sid.IsWellKnown(windows.WinCreatorOwnerSid)) {
			continue
		}
		if !sid.Equals(target) && !windowsEnterpriseAdminIdentity(sid) {
			return fmt.Errorf("enterprise hooks: untrusted Windows principal %s has write-like access mask 0x%x on %s", windowsSIDString(sid), uint32(ace.Mask), path)
		}
	}
	return nil
}

func windowsEnterpriseWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafeMask := windows.ACCESS_MASK(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
	if protectChildren {
		unsafeMask |= fileDeleteChild
	}
	return mask&unsafeMask != 0
}

func windowsEnterpriseSystemIdentity(sid *windows.SID) bool {
	if sid == nil {
		return true
	}
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalServiceSid) || sid.IsWellKnown(windows.WinNetworkServiceSid)
}

func windowsEnterpriseAdminIdentity(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

func windowsPathOwner(path string) (*windows.SID, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func windowsPathOwnerNoFollow(path string) (*windows.SID, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func rejectWindowsReparseChain(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		ptr, err := winpath.UTF16Ptr(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(ptr)
		if err == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("enterprise hooks: reparse point in path: %s", current)
		}
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func windowsSIDString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

type windowsRuntimeFileSnapshot struct {
	path    string
	existed bool
	data    []byte
}

func windowsClaudeRuntimePaths(opts connector.SetupOpts, conn connector.Connector) []string {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	paths := []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.claudecode"),
		filepath.Join(hookDir, ".hookcfg.lock"),
		filepath.Join(hookDir, ".hook-claudecode.token"),
		filepath.Join(hookDir, "_hardening.sh"),
		filepath.Join(opts.DataDir, "hook_contract_lock.json"),
		filepath.Join(opts.DataDir, "hook_contract_lock.json.lock"),
	}
	if provider, ok := conn.(connector.HookScriptProvider); ok {
		paths = append(paths, provider.HookScripts(opts)...)
	}
	return sortedUnique(paths)
}

func snapshotWindowsRuntimeFiles(paths []string) ([]windowsRuntimeFileSnapshot, error) {
	snapshots := make([]windowsRuntimeFileSnapshot, 0, len(paths))
	for _, path := range paths {
		snapshot := windowsRuntimeFileSnapshot{path: path}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: snapshot runtime file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Size() > windowsEnterpriseUserFileMaxBytes {
			return nil, fmt.Errorf("enterprise hooks: refusing unsafe runtime file during snapshot: %s", path)
		}
		data, err := readWindowsRuntimeSnapshotFile(path, info)
		if err != nil {
			return nil, err
		}
		snapshot.existed = true
		snapshot.data = data
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func readWindowsRuntimeSnapshotFile(path string, expected os.FileInfo) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("enterprise hooks: runtime snapshot file changed identity before open: %s", path)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		return nil, err
	}
	if handleInfo.NumberOfLinks != 1 {
		return nil, fmt.Errorf(
			"enterprise hooks: %w (%s has %d links during snapshot)",
			errWindowsManagedHardlink,
			path,
			handleInfo.NumberOfLinks,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsEnterpriseUserFileMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > windowsEnterpriseUserFileMaxBytes {
		return nil, fmt.Errorf("enterprise hooks: runtime snapshot file exceeds %d-byte limit: %s", windowsEnterpriseUserFileMaxBytes, path)
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("enterprise hooks: runtime snapshot file changed identity during read: %s", path)
	}
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		return nil, err
	}
	if handleInfo.NumberOfLinks != 1 {
		return nil, fmt.Errorf(
			"enterprise hooks: %w (%s gained links during snapshot)",
			errWindowsManagedHardlink,
			path,
		)
	}
	return data, nil
}

func restoreWindowsRuntimeFiles(
	home string,
	target *windows.SID,
	snapshots []windowsRuntimeFileSnapshot,
) error {
	var failures []string
	for _, snapshot := range snapshots {
		if err := prepareWindowsGenericPath(
			home,
			filepath.Dir(snapshot.path),
			target,
			true,
			true,
			true,
			"runtime rollback parent",
		); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
			continue
		}
		if err := prepareWindowsGenericPath(
			home,
			snapshot.path,
			target,
			false,
			false,
			true,
			"runtime rollback file",
		); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
			continue
		}
		if snapshot.existed {
			if err := writeWindowsRuntimeRollbackFile(snapshot.path, snapshot.data); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
				continue
			}
			if err := prepareWindowsGenericPath(
				home,
				snapshot.path,
				target,
				false,
				true,
				true,
				"restored runtime rollback file",
			); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
			}
			cleanupWindowsManagedObstructionQuarantine(snapshot.path, target)
			continue
		}
		if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Sprintf("%s: %v", snapshot.path, err))
		}
		cleanupWindowsManagedObstructionQuarantine(snapshot.path, target)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func writeWindowsRuntimeRollbackFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".defenseclaw-rollback-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	removeTemp := true
	defer func() {
		_ = file.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := safefile.ReplaceFile(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func hardenWindowsUserRuntime(home, dataDir string, paths []string, target *windows.SID) error {
	if err := prepareWindowsGenericPath(home, dataDir, target, true, true, true, "per-user data directory"); err != nil {
		return err
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := prepareWindowsGenericPath(home, hookDir, target, true, true, true, "per-user hook directory"); err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := prepareWindowsGenericPath(home, path, target, false, true, true, "runtime file"); err != nil {
			return err
		}
	}
	return nil
}

func setWindowsUserPathProtection(path string, target *windows.SID, directory bool) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	owner, err := windowsPathOwnerNoFollow(path)
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(target) {
		return fmt.Errorf(
			"enterprise hooks: refusing to canonicalize wrong-owner path %s (owner %s, target %s)",
			path,
			windowsSIDString(owner),
			windowsSIDString(target),
		)
	}
	if !directory {
		if err := validateWindowsRegularFileSingleLink(path); err != nil {
			return err
		}
	}
	if err := validateWindowsUserPathElement(path, target, directory, directory, true); err == nil {
		return nil
	}
	acl, err := windowsUserPathProtectionACL(target, directory)
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func windowsUserPathProtectionACL(target *windows.SID, directory bool) (*windows.ACL, error) {
	canonical, err := windowsUserPathCanonicalACEs(target, directory)
	if err != nil {
		return nil, err
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(canonical))
	for _, item := range canonical {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: item.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       item.inheritance,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(item.sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, err
	}
	return acl, nil
}

func verifyWindowsUserRuntime(paths []string, target *windows.SID) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
			return fmt.Errorf("enterprise hooks: runtime verification failed: %w", err)
		}
	}
	return nil
}

func removeEmptyWindowsDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("enterprise hooks: rollback directory is not empty: %s", path)
	}
	return os.Remove(path)
}
